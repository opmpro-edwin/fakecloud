//! Task-role credentials at the ECS agent's link-local address.
//!
//! On ECS, a task with a `taskRoleArn` gets
//! `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/<id>`, and the
//! agent answers `http://169.254.170.2` inside the task's network. The AWS
//! SDKs resolve the relative URI against that fixed base, and they only accept
//! a plain-HTTP `AWS_CONTAINER_CREDENTIALS_FULL_URI` on a loopback or ECS/EKS
//! link-local host, so pointing a full URI at fakecloud on
//! `host.docker.internal` is refused by every SDK credential chain.
//!
//! fakecloud reproduces the agent's address instead. Before a container
//! starts, its network namespace gets a NAT rule (nftables, or iptables when
//! that's what the helper image has) that sends `169.254.170.2:80` to
//! fakecloud's own listener, which serves the agent's `/v2/credentials/<id>`
//! surface to requests addressed to that host. Nothing listens on port 80
//! inside the task, so the app keeps every port to itself.
//!
//! - Docker / Podman: a small holder container (the analogue of the agent's
//!   pause container) owns the namespace. It carries the container's network
//!   flags (network, published ports, host alias, `net.*` sysctls), installs
//!   the rule with `NET_ADMIN`, and stays up; the app container joins it with
//!   `--network container:<holder>`. Because the rule is in place before the
//!   app starts, there is no window where the app can race it.
//! - Kubernetes: the Pod's own sandbox owns the namespace, so a first
//!   initContainer with `NET_ADMIN` installs the rule and exits before any
//!   task container runs.
//!
//! Fail-safe: when the holder / initContainer can't do its job (no helper
//! image -- including a helper build or pull that outran its budget --
//! `NET_ADMIN` refused, no NAT support), the task still runs with
//! `AWS_CONTAINER_CREDENTIALS_FULL_URI` pointing at fakecloud, which
//! `curl`-style clients can still use.

use std::time::Duration;

use super::{ContainerPlan, EcsRuntime, CLI_CALL_TIMEOUT, CONTAINER_RUN_TIMEOUT};

/// Overrides the helper image (Docker, Podman and Kubernetes). It must have
/// `sh`, `getent`, `awk` and either `nft` or `iptables`.
pub(crate) const HELPER_IMAGE_ENV: &str = "FAKECLOUD_ECS_CREDS_HELPER_IMAGE";

/// Base image of the helper fakecloud builds locally for Docker / Podman, and
/// the default Kubernetes helper (which installs `nftables` at start).
pub(crate) const HELPER_BASE_IMAGE: &str = "public.ecr.aws/docker/library/alpine:3.20";

/// Repository of the locally built Docker / Podman helper image.
const HELPER_LOCAL_REPO: &str = "fakecloud-ecs-creds-helper";

/// The locally built helper: the base image plus `nftables`.
fn helper_dockerfile() -> String {
    format!("FROM {HELPER_BASE_IMAGE}\nRUN apk add --no-cache nftables\n")
}

/// Line the setup script prints once the NAT rule is in place.
pub(crate) const READY_MARKER: &str = "FAKECLOUD_ECS_CREDS_READY";

/// Name of the Kubernetes initContainer that installs the rule.
pub(crate) const K8S_INIT_CONTAINER: &str = "fakecloud-ecs-creds";

/// Installs the `169.254.170.2:80` -> `$1:$2` NAT rule in the current network
/// namespace. `$3` is `hold` to keep running afterwards (the Docker holder
/// owns the namespace) or `once` to exit (the Kubernetes initContainer).
/// Without `nft`/`iptables` on an Alpine image it installs `nftables` first.
/// It tries `nft`, then `iptables` if `nft` is missing or its rule is refused.
///
/// The optional `$4`..`$6` give the namespace its VPC (see `vpc_net`, nft
/// only): DNS (UDP and TCP 53) to the addresses in `$5` goes to `$1:$4`, and
/// with `$6` = `lb` TCP connections follow the `lb` map, which fakecloud
/// fills with the load balancer addresses afterwards.
pub(crate) const SETUP_SCRIPT: &str = r#"set -eu
host="$1"; port="$2"; mode="$3"
dns_port="${4:-}"; dns_addrs="${5:-}"; lb="${6:-}"
have() { command -v "$1" >/dev/null 2>&1; }
if ! have nft && ! have iptables && have apk; then
  apk add --no-cache -q nftables >/dev/null
fi
ip=$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1}')
if [ -z "$ip" ]; then
  echo "fakecloud-ecs-creds: cannot resolve $host" >&2
  exit 1
fi
nl='
'
vpc=""; lbmap=""
if [ -n "$dns_port" ]; then
  for proto in udp tcp; do
    vpc="$vpc  ip daddr { $dns_addrs } $proto dport 53 dnat to $ip:$dns_port$nl"
  done
fi
if [ "$lb" = lb ]; then
  lbmap=" map lb {$nl  type ipv4_addr . inet_service : ipv4_addr . inet_service$nl }$nl"
  vpc="$vpc  meta l4proto tcp dnat ip to ip daddr . tcp dport map @lb$nl"
fi
# nft first; iptables when nft is missing or the kernel refuses its rule.
# Both are idempotent: a re-run in the same namespace replaces the rule.
if have nft && printf 'table ip fakecloud_ecs_creds\ndelete table ip fakecloud_ecs_creds\ntable ip fakecloud_ecs_creds {\n%s chain output {\n  type nat hook output priority -100; policy accept;\n  ip daddr 169.254.170.2 tcp dport 80 dnat to %s:%s\n%s }\n}\n' "$lbmap" "$ip" "$port" "$vpc" | nft -f -; then
  :
elif have iptables && rule="-d 169.254.170.2/32 -p tcp --dport 80 -j DNAT --to-destination $ip:$port" \
  && { iptables -t nat -C OUTPUT $rule 2>/dev/null || iptables -t nat -A OUTPUT $rule; }; then
  [ -z "$vpc" ] || echo "fakecloud-ecs-creds: no nft; VPC DNS and load balancer addresses are not routed" >&2
else
  echo "fakecloud-ecs-creds: could not install the NAT rule with nft or iptables" >&2
  exit 1
fi
echo "FAKECLOUD_ECS_CREDS_READY 169.254.170.2:80 -> $ip:$port"
[ "$mode" = hold ] || exit 0
trap 'exit 0' TERM INT
while :; do sleep 3600 & wait $!; done
"#;

/// How long a failed helper-image resolution is remembered before a task
/// tries again.
pub(crate) const HELPER_RETRY_AFTER: Duration = Duration::from_secs(300);

/// The resolved helper image, or the last failure to resolve it.
#[derive(Debug, Clone)]
pub(crate) enum HelperImage {
    Ready(String),
    Failed {
        error: String,
        at: std::time::Instant,
    },
}

/// How long a holder may take to install its rule.
const HOLDER_READY_TIMEOUT: Duration = Duration::from_secs(60);

/// Budget for one `build` of the local helper. The build is
/// `apk add nftables` on a base image that is already pulled, which takes a
/// few seconds (tens on a slow Podman host); the CLI has no deadline of its
/// own, so a package mirror that stalls mid-download would otherwise hold
/// every task-role launch in `PENDING` forever. Ninety seconds is many times
/// a healthy build and short enough that a retry -- a fresh connection, often
/// to a different CDN edge -- still fits in [`HELPER_BUILD_BUDGET`].
const HELPER_BUILD_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(90);

/// Budget for every attempt of the helper build together, backoff included.
/// Tasks that need the helper wait on the first one's build, so this bounds
/// how long a stalled mirror can hold any task-role launch before it falls
/// back to the full credentials URI.
const HELPER_BUILD_BUDGET: Duration = Duration::from_secs(240);

/// The helper build's limits; tests shrink them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BuildLimits {
    pub(crate) attempts: u32,
    pub(crate) attempt_timeout: Duration,
    pub(crate) budget: Duration,
    pub(crate) retry_delay: Duration,
}

const BUILD_LIMITS: BuildLimits = BuildLimits {
    attempts: 3,
    attempt_timeout: HELPER_BUILD_ATTEMPT_TIMEOUT,
    budget: HELPER_BUILD_BUDGET,
    retry_delay: Duration::from_secs(2),
};

/// The agent's relative credentials URI for a task.
pub(crate) fn relative_uri(task_id: &str) -> String {
    format!("/v2/credentials/{task_id}")
}

/// Env var carrying the per-task credentials authorization token. The AWS
/// SDKs' container credential providers send its value as the
/// `Authorization` header on every credentials request (relative and full
/// URI alike).
pub const AUTHORIZATION_TOKEN_ENV: &str = "AWS_CONTAINER_AUTHORIZATION_TOKEN";

/// The authorization token injected as [`AUTHORIZATION_TOKEN_ENV`] into task
/// `task_id`'s containers that get the full credentials URI. Under
/// `--iam strict` that endpoint only hands out a task's role credentials to a
/// request presenting it, so knowing (or guessing) a task ID is not enough.
///
/// Derived as HMAC-SHA256 of the task ID under a key drawn at random once per
/// process: stable for the life of the task without storing anything, and
/// unforgeable without the key. Tasks never outlive the process (a restart
/// stops every restored task), so a fresh key per run loses nothing.
pub fn task_credentials_token(task_id: &str) -> String {
    use hmac::{Hmac, Mac};
    use rand::RngCore;
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    let key = KEY.get_or_init(|| {
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        k
    });
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(task_id.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The credentials env vars a task container gets: the agent's relative URI
/// when `169.254.170.2` reaches fakecloud inside the container, else the full
/// URI of fakecloud's endpoint at `fakecloud_base` (no trailing slash) plus
/// the task's [`AUTHORIZATION_TOKEN_ENV`], which the full-URI endpoint
/// requires under `--iam strict`. As on ECS, the relative URI comes with no
/// token: only the task's own network reaches the agent address.
pub(crate) fn credentials_env(
    task_id: &str,
    link_local: bool,
    fakecloud_base: &str,
) -> Vec<(String, String)> {
    if link_local {
        vec![(
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI".into(),
            relative_uri(task_id),
        )]
    } else {
        vec![
            (
                "AWS_CONTAINER_CREDENTIALS_FULL_URI".into(),
                format!("{fakecloud_base}/_fakecloud/ecs/creds/{task_id}"),
            ),
            (
                AUTHORIZATION_TOKEN_ENV.into(),
                task_credentials_token(task_id),
            ),
        ]
    }
}

/// The operator's helper image override, if set.
pub(crate) fn helper_image_override() -> Option<String> {
    std::env::var(HELPER_IMAGE_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Tag of the locally built helper, keyed on its Dockerfile so a change to it
/// builds a fresh image instead of reusing a stale one.
pub(crate) fn local_helper_tag() -> String {
    // FNV-1a: stable across builds and platforms, unlike `DefaultHasher`.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in helper_dockerfile().bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{HELPER_LOCAL_REPO}:{:012x}", hash & 0xffff_ffff_ffff)
}

/// Docker name of the holder owning `container`'s network namespace. The
/// `fakecloud-` prefix can't collide with task containers, whose names start
/// with the (hex) task ID.
pub(crate) fn holder_name(task_id: &str, container: &str) -> String {
    format!("fakecloud-ecs-netns-{task_id}-{container}")
}

/// Whether a `--sysctl` name is network-namespaced, so it belongs on whichever
/// container owns the namespace.
pub(crate) fn is_net_sysctl(name: &str) -> bool {
    name.starts_with("net.")
}

/// Whether the task uses the `none` network mode: no network at all, only a
/// loopback interface.
pub(crate) fn is_none_network(plan: &ContainerPlan) -> bool {
    plan.network_mode.as_deref() == Some("none")
}

/// Whether a container gets a namespace holder routing `169.254.170.2` (and,
/// with VPC networking, the VPC's DNS server and load balancer addresses; see
/// `vpc_net`). Task-role containers need one, every container does under VPC
/// networking, and a `none`-mode container has no network to route over: as
/// on ECS, it gets the relative URI with nothing answering it.
pub(crate) fn wants_netns_holder(plan: &ContainerPlan) -> bool {
    (plan.has_task_role || super::vpc_net::enabled()) && !is_none_network(plan)
}

/// The network flags of the container that owns a task container's network
/// namespace: the container itself, or its holder. `alias` is the task
/// container's own name, kept resolvable on the per-task network when a holder
/// owns the endpoint.
pub(crate) fn namespace_network_argv(
    plan: &ContainerPlan,
    task_id: &str,
    add_host_arg: Option<&str>,
    awsvpc_network_ready: bool,
    alias: Option<&str>,
) -> Vec<String> {
    let mut argv = Vec::new();
    // `none`: loopback only. No host alias, no published ports.
    if is_none_network(plan) {
        argv.push("--network".into());
        argv.push("none".into());
        return argv;
    }
    // Inject `--add-host host.docker.internal:<ip>` only for docker;
    // podman provides `host.containers.internal` natively and rejects
    // the host-gateway mapping (issue #1539).
    if let Some(arg) = add_host_arg {
        argv.push("--add-host".into());
        argv.push(arg.to_string());
    }
    let use_awsvpc_network = plan.network_mode.as_deref() == Some("awsvpc") && awsvpc_network_ready;
    if use_awsvpc_network {
        argv.push("--network".into());
        argv.push(format!("fakecloud-ecs-{task_id}"));
        if let Some(alias) = alias {
            argv.push("--network-alias".into());
            argv.push(alias.to_string());
        }
    }
    // `awsvpc` puts the container on a per-task ENI whose private IP is not
    // routable from fakecloud locally, and its ports are not host ports
    // (every task binds its own containerPort). Publish each container port
    // on an ephemeral host port instead: the runtime reads it back and routes
    // load balancer traffic for `<ENI IP>:<containerPort>` there (see `eni`),
    // without two tasks competing for one host port.
    // Bridge / host / default network modes publish `hostPort:containerPort`:
    // `host` is emulated on a bridge whose published ports are the host ports
    // the task binds (never the host's own namespace, which a task-role holder
    // would otherwise have to NAT in). If the awsvpc per-task network creation
    // failed and we fell back to bridge, the task's declared mapping applies.
    for pm in &plan.port_mappings {
        argv.push("--publish".into());
        let spec = if use_awsvpc_network {
            format!("{}/{}", pm.container_port, pm.protocol)
        } else {
            format!("{}:{}/{}", pm.host_port, pm.container_port, pm.protocol)
        };
        argv.push(fakecloud_core::container_net::publish_spec(&spec));
    }
    argv
}

/// `docker run` argv for the holder of `plan`'s network namespace. With
/// `vpc_dns` the namespace resolves through the VPC's DNS server and the
/// setup script routes it and the load balancer addresses (see `vpc_net`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_holder_argv(
    plan: &ContainerPlan,
    task_id: &str,
    add_host_arg: Option<&str>,
    awsvpc_network_ready: bool,
    helper_image: &str,
    fakecloud_host: &str,
    fakecloud_port: u16,
    vpc_dns: Option<&super::vpc_net::VpcDns>,
) -> Vec<String> {
    let app_name = format!("{}-{}", task_id, plan.container_name);
    let mut argv: Vec<String> = vec![
        "run".into(),
        "-d".into(),
        "--name".into(),
        holder_name(task_id, &plan.container_name),
        "--label".into(),
        format!("fakecloud-ecs-task={task_id}"),
        "--label".into(),
        format!("fakecloud-ecs-netns-for={}", plan.container_name),
        // Reaped with the task's containers after an ungraceful restart.
        "--label".into(),
        super::fakecloud_instance_label(),
        "--cap-add".into(),
        "NET_ADMIN".into(),
    ];
    // The VPC resolver replaces the engine's, which is what resolves
    // `host.docker.internal` on Docker Desktop when fakecloud runs in a
    // container (no `--add-host` then): pin the alias in the namespace's
    // hosts file instead, so the setup script and the app still resolve it.
    let pinned_alias = add_host_arg
        .is_none()
        .then(|| fakecloud_core::vpc_netns::pinned_host_alias(vpc_dns.is_some(), fakecloud_host))
        .flatten();
    argv.extend(namespace_network_argv(
        plan,
        task_id,
        add_host_arg.or(pinned_alias.as_deref()),
        awsvpc_network_ready,
        Some(&app_name),
    ));
    if let Some(lp) = plan.linux_parameters.as_ref() {
        for sys in lp.sysctls.iter().filter(|s| is_net_sysctl(&s.name)) {
            argv.push("--sysctl".into());
            argv.push(format!("{}={}", sys.name, sys.value));
        }
    }
    // The namespace's resolv.conf (or, on a per-task network, the engine's
    // embedded DNS, which forwards from inside the namespace) names the VPC
    // DNS server; the setup script sends it to fakecloud.
    if let Some(vpc) = vpc_dns {
        argv.push("--dns".into());
        argv.push(vpc.server.to_string());
    }
    argv.extend([
        "--entrypoint".into(),
        "sh".into(),
        helper_image.to_string(),
        "-c".into(),
        SETUP_SCRIPT.to_string(),
        "fakecloud-ecs-creds".into(),
        fakecloud_host.to_string(),
        fakecloud_port.to_string(),
        "hold".into(),
    ]);
    if let Some(vpc) = vpc_dns {
        argv.extend(vpc.script_args());
    }
    argv
}

impl EcsRuntime {
    /// The helper image for namespace holders: the operator's override, or a
    /// locally built Alpine + nftables image (built once per host and reused).
    pub(crate) async fn ensure_creds_helper_image(&self) -> Result<String, String> {
        self.ensure_creds_helper_image_with(BUILD_LIMITS).await
    }

    /// [`Self::ensure_creds_helper_image`] with explicit build limits. The
    /// lock is held across the whole resolution, so concurrent first tasks
    /// make one build (or pull) and share its outcome instead of racing
    /// builds of the same tag.
    pub(crate) async fn ensure_creds_helper_image_with(
        &self,
        limits: BuildLimits,
    ) -> Result<String, String> {
        // Fast path, the common case of every launch after the first: check a
        // resolved image without holding the lock, so launches don't queue
        // behind each other's `image inspect`.
        let ready = match self.creds_helper_image.lock().await.as_ref() {
            Some(HelperImage::Ready(image)) => Some(image.clone()),
            _ => None,
        };
        if let Some(image) = ready {
            if self.image_present(&image).await {
                return Ok(image);
            }
        }
        // Slow path, under the lock for the whole resolution so concurrent
        // launches share one build. Everything is re-checked: another launch
        // may have resolved (or failed) while this one waited.
        let mut cached = self.creds_helper_image.lock().await;
        match cached.as_ref() {
            // Re-check: the image can be pruned while fakecloud runs, and a
            // holder `run` would then try to pull the local-only tag.
            Some(HelperImage::Ready(image)) if self.image_present(image).await => {
                return Ok(image.clone());
            }
            // Don't make every task-role launch repeat a build/pull that just
            // failed (with its retries and backoff) before falling back.
            Some(HelperImage::Failed { error, at }) if at.elapsed() < HELPER_RETRY_AFTER => {
                return Err(error.clone());
            }
            _ => {}
        }
        let resolved = match helper_image_override() {
            Some(image) => fakecloud_core::container_image::ensure_image_within(
                &self.cli,
                self.docker_config_path().as_deref(),
                &image,
                limits.budget,
            )
            .await
            .map(|_| image),
            None => {
                let tag = local_helper_tag();
                if self.image_present(&tag).await {
                    Ok(tag)
                } else {
                    self.build_local_helper(&tag, limits).await.map(|()| tag)
                }
            }
        };
        *cached = Some(match &resolved {
            Ok(image) => HelperImage::Ready(image.clone()),
            Err(error) => HelperImage::Failed {
                error: error.clone(),
                at: std::time::Instant::now(),
            },
        });
        resolved
    }

    async fn image_present(&self, tag: &str) -> bool {
        self.cli_output(["image", "inspect", tag], CLI_CALL_TIMEOUT)
            .await
            .is_ok_and(|o| o.status.success())
    }

    async fn build_local_helper(&self, tag: &str, limits: BuildLimits) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + limits.budget;
        // Pull the base with the shared retry so a registry 429 doesn't fail
        // the build's implicit pull.
        // Bounded by the build's own budget: the base is small, so a pull that
        // outlives it has stalled.
        fakecloud_core::container_image::ensure_image_within(
            &self.cli,
            None,
            HELPER_BASE_IMAGE,
            deadline.saturating_duration_since(tokio::time::Instant::now()),
        )
        .await?;
        let dir = tempfile::tempdir().map_err(|e| format!("helper build dir: {e}"))?;
        std::fs::write(dir.path().join("Dockerfile"), helper_dockerfile())
            .map_err(|e| format!("helper Dockerfile: {e}"))?;
        let mut last_err = String::new();
        for attempt in 0..limits.attempts {
            if attempt > 0 {
                tokio::time::sleep(limits.retry_delay * attempt).await;
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let timeout = limits.attempt_timeout.min(remaining);
            let mut args: Vec<std::ffi::OsString> = ["build", "-q", "-t", tag]
                .into_iter()
                .map(Into::into)
                .collect();
            args.push(dir.path().into());
            match self.cli_output(&args, timeout).await {
                Ok(out) if out.status.success() => {
                    tracing::info!(image = %tag, "built ECS task-credentials helper image");
                    return Ok(());
                }
                Ok(out) => last_err = String::from_utf8_lossy(&out.stderr).trim().to_string(),
                // Timed out (killed) or could not run: either way the next
                // attempt starts from scratch.
                Err(e) => last_err = e,
            }
            tracing::warn!(
                image = %tag,
                attempt = attempt + 1,
                error = %last_err,
                "ECS task-credentials helper build failed"
            );
        }
        Err(format!("building {tag}: {last_err}"))
    }

    /// Start the holder for `plan`'s network namespace and wait for its NAT
    /// rule. Returns the holder's container ID. On failure the holder is
    /// removed and the error says why.
    pub(crate) async fn start_netns_holder(
        &self,
        plan: &ContainerPlan,
        task_id: &str,
        awsvpc_network_ready: bool,
        helper_image: &str,
        vpc_dns: Option<&super::vpc_net::VpcDns>,
    ) -> Result<String, String> {
        let name = holder_name(task_id, &plan.container_name);
        // A holder left by an earlier attempt of this task would block the name.
        let _ = self.cli_output(["rm", "-f", &name], CLI_CALL_TIMEOUT).await;
        let argv = build_holder_argv(
            plan,
            task_id,
            self.net.add_host_arg.as_deref(),
            awsvpc_network_ready,
            helper_image,
            &self.net.host_alias,
            self.server_port,
            vpc_dns,
        );
        let out = match self.cli_output(&argv, CONTAINER_RUN_TIMEOUT).await {
            Ok(out) if out.status.success() => out,
            failed => {
                // A timed-out `run` may still have created the holder.
                let _ = self.cli_output(["rm", "-f", &name], CLI_CALL_TIMEOUT).await;
                return Err(match failed {
                    Ok(out) => String::from_utf8_lossy(&out.stderr).trim().to_string(),
                    Err(e) => e,
                });
            }
        };
        let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if let Err(e) = self.wait_for_holder_ready(&id).await {
            let _ = self.cli_output(["rm", "-f", &id], CLI_CALL_TIMEOUT).await;
            return Err(e);
        }
        // Load balancer addresses route before the task's container starts.
        if vpc_dns.is_some() {
            super::vpc_net::attach_holder(self.container_cli(), &id, &self.net.host_alias).await;
        }
        self.netns_holders
            .write()
            .entry(task_id.to_string())
            .or_default()
            .push(id.clone());
        Ok(id)
    }

    async fn wait_for_holder_ready(&self, id: &str) -> Result<(), String> {
        let deadline = std::time::Instant::now() + HOLDER_READY_TIMEOUT;
        let mut poll = Duration::from_millis(100);
        // Each call gets what is left of the readiness budget (plus a
        // moment, so the last poll can still run), never the CLI default:
        // a wedged daemon must not stretch the wait past its deadline.
        let call_budget = || {
            deadline
                .saturating_duration_since(std::time::Instant::now())
                .min(CLI_CALL_TIMEOUT)
                + Duration::from_secs(1)
        };
        loop {
            let logs = self.cli_output(["logs", id], call_budget()).await?;
            let stdout = String::from_utf8_lossy(&logs.stdout);
            let stderr = String::from_utf8_lossy(&logs.stderr);
            if stdout.contains(READY_MARKER) {
                return Ok(());
            }
            let running = self
                .cli_output(["inspect", "-f", "{{.State.Running}}", id], call_budget())
                .await
                .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
                .unwrap_or(false);
            if !running {
                return Err(format!(
                    "holder exited before installing the NAT rule; stdout: {:?}; stderr: {:?}",
                    stdout.trim(),
                    stderr.trim()
                ));
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "holder did not install the NAT rule within {}s",
                    HOLDER_READY_TIMEOUT.as_secs()
                ));
            }
            tokio::time::sleep(poll).await;
            // The rule normally lands within a few polls; back off for a
            // slow first start instead of shelling out every 100ms.
            poll = (poll * 2).min(Duration::from_secs(1));
        }
    }

    /// Remove every namespace holder of `task_id`. Call after the task's
    /// containers are gone (they share the holders' namespaces) and before
    /// its per-task network is removed (the holders are attached to it).
    pub(crate) async fn remove_netns_holders(&self, task_id: &str) {
        let ids = self.netns_holders.write().remove(task_id);
        super::vpc_net::detach_holders(ids.as_deref().unwrap_or_default());
        for id in ids.into_iter().flatten() {
            let _ = self.cli_output(["rm", "-f", &id], CLI_CALL_TIMEOUT).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{LinuxParameters, PortMapping, Sysctl};

    fn plan(network_mode: Option<&str>) -> ContainerPlan {
        let mut p = crate::runtime::tests_support::minimal_plan();
        p.container_name = "web".into();
        p.has_task_role = true;
        p.network_mode = network_mode.map(String::from);
        p.port_mappings = vec![PortMapping {
            container_port: 80,
            host_port: 8080,
            protocol: "tcp".into(),
        }];
        p
    }

    #[test]
    fn credentials_env_prefers_the_agents_relative_uri() {
        assert_eq!(
            credentials_env("abc", true, "http://host.docker.internal:4566"),
            vec![(
                "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI".to_string(),
                "/v2/credentials/abc".to_string()
            )]
        );
        assert_eq!(
            credentials_env("abc", false, "http://host.docker.internal:4566"),
            vec![
                (
                    "AWS_CONTAINER_CREDENTIALS_FULL_URI".to_string(),
                    "http://host.docker.internal:4566/_fakecloud/ecs/creds/abc".to_string()
                ),
                (
                    "AWS_CONTAINER_AUTHORIZATION_TOKEN".to_string(),
                    task_credentials_token("abc")
                ),
            ]
        );
    }

    #[test]
    fn task_credentials_token_is_stable_per_task_and_distinct_across_tasks() {
        let a = task_credentials_token("task-a");
        assert_eq!(a, task_credentials_token("task-a"));
        assert_ne!(a, task_credentials_token("task-b"));
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn holder_owns_the_namespace_flags_and_runs_the_setup_script() {
        let mut p = plan(None);
        p.linux_parameters = Some(LinuxParameters {
            sysctls: vec![
                Sysctl {
                    name: "net.core.somaxconn".into(),
                    value: "1024".into(),
                },
                Sysctl {
                    name: "kernel.shm_rmid_forced".into(),
                    value: "1".into(),
                },
            ],
            ..LinuxParameters::default()
        });
        let argv = build_holder_argv(
            &p,
            "t1",
            Some("host.docker.internal:host-gateway"),
            false,
            "helper:1",
            "host.docker.internal",
            4566,
            None,
        );
        let joined = argv.join(" ");
        assert!(joined.starts_with("run -d --name fakecloud-ecs-netns-t1-web "));
        assert!(joined.contains("--cap-add NET_ADMIN"), "{joined}");
        assert!(
            joined.contains("--add-host host.docker.internal:host-gateway"),
            "{joined}"
        );
        assert!(joined.contains("--publish 8080:80/tcp"), "{joined}");
        assert!(joined.contains("--label fakecloud-ecs-task=t1"), "{joined}");
        assert!(
            joined.contains(&format!(
                "--label {}",
                crate::runtime::fakecloud_instance_label()
            )),
            "{joined}"
        );
        // Only the network-namespaced sysctl moves to the holder.
        assert!(joined.contains("--sysctl net.core.somaxconn=1024"));
        assert!(!joined.contains("kernel.shm_rmid_forced"));
        // Not on a per-task network, so no alias.
        assert!(!joined.contains("--network"), "{joined}");
        assert_eq!(
            argv[argv.len() - 9..],
            [
                "--entrypoint",
                "sh",
                "helper:1",
                "-c",
                SETUP_SCRIPT,
                "fakecloud-ecs-creds",
                "host.docker.internal",
                "4566",
                "hold",
            ]
        );
    }

    #[test]
    fn awsvpc_holder_joins_the_task_network_under_the_containers_name() {
        let argv = build_holder_argv(
            &plan(Some("awsvpc")),
            "t1",
            None,
            true,
            "helper:1",
            "host.containers.internal",
            4566,
            None,
        );
        let joined = argv.join(" ");
        assert!(
            joined.contains("--network fakecloud-ecs-t1 --network-alias t1-web"),
            "{joined}"
        );
        // The holder owns the namespace, so it publishes the awsvpc port on
        // an ephemeral host port (never the declared hostPort), and podman
        // needs no --add-host.
        assert!(joined.contains("--publish 80/tcp"), "{joined}");
        assert!(!joined.contains("8080:80"), "{joined}");
        assert!(!joined.contains("--add-host"), "{joined}");
    }

    /// The setup script really installs the rule: run it under `sh` with
    /// fake `nft` / `iptables` / `getent` on `PATH` and check which tool got
    /// the rule, including the iptables fallback when nft refuses it.
    #[test]
    fn setup_script_falls_back_to_iptables_when_nft_refuses_the_rule() {
        use std::os::unix::fs::PermissionsExt;
        let run = |nft_ok: Option<bool>| {
            let dir = tempfile::tempdir().unwrap();
            let log = dir.path().join("calls");
            let tool = |name: &str, body: &str| {
                let path = dir.path().join(name);
                std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            };
            let log_s = log.display().to_string();
            // PATH is only this directory: the fakes plus the two real
            // utilities the script needs, so a real nft/iptables on the
            // machine is never reached (the "no nft" case really has none).
            for util in ["awk", "cat"] {
                let real = ["/usr/bin", "/bin"]
                    .iter()
                    .map(|d| std::path::Path::new(d).join(util))
                    .find(|p| p.exists())
                    .unwrap_or_else(|| panic!("{util} not found"));
                std::os::unix::fs::symlink(real, dir.path().join(util)).unwrap();
            }
            tool("getent", "echo '10.1.2.3 STREAM host'");
            // `-C` (check) finds no rule, so the script appends one.
            tool(
                "iptables",
                &format!("case \"$3\" in -C) exit 1;; esac; echo \"iptables $*\" >> {log_s}"),
            );
            match nft_ok {
                Some(true) => tool("nft", &format!("cat >/dev/null; echo nft >> {log_s}")),
                Some(false) => tool("nft", "cat >/dev/null; exit 1"),
                None => {}
            }
            let path = dir.path().display().to_string();
            let out = std::process::Command::new("/bin/sh")
                .args(["-c", SETUP_SCRIPT, "t", "host", "4566", "once"])
                .env("PATH", path)
                .output()
                .unwrap();
            let calls = std::fs::read_to_string(&log).unwrap_or_default();
            (
                out.status.success(),
                String::from_utf8_lossy(&out.stdout).into_owned(),
                calls,
            )
        };
        let (ok, stdout, calls) = run(Some(true));
        assert!(ok && stdout.contains(READY_MARKER), "{stdout}");
        assert_eq!(calls.trim(), "nft");
        // nft gets a ruleset that replaces any earlier copy of the table, so
        // a re-run in the same namespace doesn't fail on "already exists".
        assert!(SETUP_SCRIPT.contains("delete table ip fakecloud_ecs_creds"));
        let (ok, stdout, calls) = run(Some(false));
        assert!(ok && stdout.contains("-> 10.1.2.3:4566"), "{stdout}");
        assert!(
            calls.contains("iptables -t nat -A OUTPUT -d 169.254.170.2/32 -p tcp --dport 80 -j DNAT --to-destination 10.1.2.3:4566"),
            "{calls}"
        );
        let (ok, _, calls) = run(None);
        assert!(ok && calls.starts_with("iptables"), "{calls}");
    }

    /// With the VPC arguments the nft ruleset also sends DNS for the VPC
    /// resolver addresses to fakecloud's DNS port and declares the load
    /// balancer map; the holder gets the VPC DNS server as its resolver.
    #[test]
    fn setup_script_routes_vpc_dns_and_load_balancer_addresses() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let ruleset = dir.path().join("ruleset");
        let tool = |name: &str, body: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        for util in ["awk", "cat"] {
            let real = ["/usr/bin", "/bin"]
                .iter()
                .map(|d| std::path::Path::new(d).join(util))
                .find(|p| p.exists())
                .unwrap_or_else(|| panic!("{util} not found"));
            std::os::unix::fs::symlink(real, dir.path().join(util)).unwrap();
        }
        tool("getent", "echo '10.1.2.3 STREAM host'");
        tool("nft", &format!("cat > {}", ruleset.display()));
        let vpc = super::super::vpc_net::VpcDns {
            server: std::net::Ipv4Addr::new(10, 40, 0, 2),
            port: 15353,
        };
        let mut args = vec![
            "-c".to_string(),
            SETUP_SCRIPT.to_string(),
            "t".to_string(),
            "host".to_string(),
            "4566".to_string(),
            "once".to_string(),
        ];
        args.extend(vpc.script_args());
        let out = std::process::Command::new("/bin/sh")
            .args(&args)
            .env("PATH", dir.path())
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let rules = std::fs::read_to_string(&ruleset).unwrap();
        for line in [
            "ip daddr 169.254.170.2 tcp dport 80 dnat to 10.1.2.3:4566",
            "ip daddr { 10.40.0.2, 169.254.169.253 } udp dport 53 dnat to 10.1.2.3:15353",
            "ip daddr { 10.40.0.2, 169.254.169.253 } tcp dport 53 dnat to 10.1.2.3:15353",
            "type ipv4_addr . inet_service : ipv4_addr . inet_service",
            "meta l4proto tcp dnat ip to ip daddr . tcp dport map @lb",
        ] {
            assert!(rules.contains(line), "{line} missing from:\n{rules}");
        }
        // Without them the ruleset is the credentials rule alone.
        let out = std::process::Command::new("/bin/sh")
            .args(&args[..6])
            .env("PATH", dir.path())
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let rules = std::fs::read_to_string(&ruleset).unwrap();
        assert!(
            !rules.contains("dport 53") && !rules.contains("map"),
            "{rules}"
        );

        let argv = build_holder_argv(
            &plan(Some("awsvpc")),
            "t1",
            None,
            true,
            "helper:1",
            "host.docker.internal",
            4566,
            Some(&vpc),
        );
        let joined = argv.join(" ");
        assert!(
            joined.contains("--dns 10.40.0.2 --entrypoint sh"),
            "{joined}"
        );
        assert!(
            joined.ends_with("hold 15353 10.40.0.2, 169.254.169.253 lb"),
            "{joined}"
        );
        // No `--add-host` from the runtime (a containerized fakecloud on
        // Docker Desktop): the alias is pinned, since the VPC resolver
        // replaces the engine's.
        assert!(
            joined.contains("--add-host host.docker.internal:host-gateway"),
            "{joined}"
        );
        let podman = build_holder_argv(
            &plan(Some("awsvpc")),
            "t1",
            None,
            true,
            "helper:1",
            "host.containers.internal",
            4566,
            Some(&vpc),
        )
        .join(" ");
        assert!(!podman.contains("--add-host"), "{podman}");
    }

    #[test]
    fn setup_script_installs_the_nat_rule_for_the_agents_address() {
        assert!(SETUP_SCRIPT.contains("ip daddr 169.254.170.2 tcp dport 80 dnat to"));
        assert!(SETUP_SCRIPT.contains("-d 169.254.170.2/32 -p tcp --dport 80 -j DNAT"));
        assert!(SETUP_SCRIPT.contains(READY_MARKER));
        assert!(helper_dockerfile().contains(HELPER_BASE_IMAGE));
        assert!(helper_dockerfile().contains("nftables"));
    }

    #[test]
    fn local_helper_tag_is_stable_and_content_keyed() {
        let tag = local_helper_tag();
        assert_eq!(tag, local_helper_tag());
        let (repo, digest) = tag.split_once(':').unwrap();
        assert_eq!(repo, HELPER_LOCAL_REPO);
        assert_eq!(digest.len(), 12);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn a_failed_helper_image_is_not_retried_by_every_task() {
        let rt = EcsRuntime::bare_for_tests();
        *rt.creds_helper_image.lock().await = Some(HelperImage::Failed {
            error: "pull failed".into(),
            at: std::time::Instant::now(),
        });
        // Within the retry window the failure is returned without touching
        // the (absent) container CLI.
        assert_eq!(
            rt.ensure_creds_helper_image().await,
            Err("pull failed".to_string())
        );
    }

    #[tokio::test]
    async fn a_cached_helper_image_that_is_gone_is_resolved_again() {
        // No container CLI: the cached image can't be found, so the runtime
        // tries to resolve it again (and remembers that failure) instead of
        // handing out a tag the holder `run` would fail to pull.
        let rt = EcsRuntime::bare_for_tests();
        *rt.creds_helper_image.lock().await = Some(HelperImage::Ready("helper:1".into()));
        assert!(rt.ensure_creds_helper_image().await.is_err());
        assert!(matches!(
            *rt.creds_helper_image.lock().await,
            Some(HelperImage::Failed { .. })
        ));
    }

    /// A stand-in container CLI for the helper build. The base image is always
    /// present; the helper tag is present once a build succeeded. `build`
    /// either never finishes (`hang`, recording the pid of the process it is
    /// stuck in) or succeeds after a moment (`ok`). Every call but the warmup
    /// is appended to `calls.log`.
    struct FakeBuildCli {
        dir: tempfile::TempDir,
    }

    impl FakeBuildCli {
        fn new(build: &str) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let body = match build {
                "hang" => r#"sleep 1000 & echo $! >> "$d/pids"; wait"#,
                "ok" => r#"sleep 0.3; touch "$d/built""#,
                other => panic!("unknown build mode {other}"),
            };
            let script = format!(
                r#"#!/bin/sh
d="{dir}"
[ "$1" = warmup ] && exit 0
echo "$*" >> "$d/calls.log"
case "$1" in
  image)
    case "$3" in
      {repo}:*) [ -f "$d/built" ] ;;
      *) exit 0 ;;
    esac ;;
  build) {body} ;;
  *) exit 2 ;;
esac
"#,
                dir = dir.path().display(),
                repo = HELPER_LOCAL_REPO,
            );
            fakecloud_core::test_support::write_executable(&dir.path().join("cli"), &script);
            Self { dir }
        }

        fn runtime(&self) -> EcsRuntime {
            let mut rt = EcsRuntime::bare_for_tests();
            rt.cli = self.dir.path().join("cli").display().to_string();
            rt
        }

        fn builds(&self) -> usize {
            std::fs::read_to_string(self.dir.path().join("calls.log"))
                .unwrap_or_default()
                .lines()
                .filter(|l| l.starts_with("build "))
                .count()
        }

        fn build_pids(&self) -> Vec<u32> {
            std::fs::read_to_string(self.dir.path().join("pids"))
                .unwrap_or_default()
                .lines()
                .map(|l| l.trim().parse().unwrap())
                .collect()
        }
    }

    fn limits(attempts: u32, attempt_timeout: Duration, budget: Duration) -> BuildLimits {
        BuildLimits {
            attempts,
            attempt_timeout,
            budget,
            retry_delay: Duration::from_millis(10),
        }
    }

    /// A build stuck on a stalled package mirror used to hold every
    /// task-role launch in PENDING forever. Each attempt is now killed at its
    /// timeout -- with the process it was stuck in -- and the failure is
    /// returned and remembered, so the next task falls back at once instead
    /// of waiting out the build again.
    #[tokio::test]
    async fn a_build_that_never_finishes_is_killed_and_its_failure_returned() {
        let cli = FakeBuildCli::new("hang");
        let rt = cli.runtime();
        let start = std::time::Instant::now();
        let err = rt
            .ensure_creds_helper_image_with(limits(
                2,
                Duration::from_millis(300),
                Duration::from_secs(20),
            ))
            .await
            .expect_err("a hung build must fail");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "took {:?}",
            start.elapsed()
        );
        assert!(
            err.starts_with(&format!("building {}", local_helper_tag())),
            "{err}"
        );
        assert!(err.contains("build did not finish within 0.3s"), "{err}");
        assert_eq!(cli.builds(), 2, "every attempt runs, each one bounded");
        let pids = cli.build_pids();
        assert_eq!(pids.len(), 2);
        for pid in pids {
            assert!(
                fakecloud_core::test_support::pid_gone(pid),
                "build process {pid} survived its timeout"
            );
        }
        assert!(matches!(
            *rt.creds_helper_image.lock().await,
            Some(HelperImage::Failed { .. })
        ));
        assert_eq!(rt.ensure_creds_helper_image().await, Err(err));
        assert_eq!(cli.builds(), 2, "the remembered failure builds nothing");
    }

    /// The overall budget caps the attempts too: a retry never starts after
    /// it, and the last attempt only gets what is left of it.
    #[tokio::test]
    async fn the_build_budget_caps_every_attempt_together() {
        let cli = FakeBuildCli::new("hang");
        let rt = cli.runtime();
        let start = std::time::Instant::now();
        let err = rt
            .ensure_creds_helper_image_with(limits(
                5,
                Duration::from_secs(60),
                Duration::from_millis(400),
            ))
            .await
            .expect_err("a hung build must fail");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "took {:?}",
            start.elapsed()
        );
        assert!(err.contains("did not finish within"), "{err}");
        assert_eq!(cli.builds(), 1);
    }

    /// Tasks starting together share the first one's build instead of racing
    /// builds of the same tag.
    #[tokio::test]
    async fn concurrent_tasks_share_a_single_helper_build() {
        let cli = FakeBuildCli::new("ok");
        let rt = std::sync::Arc::new(cli.runtime());
        let lim = limits(3, Duration::from_secs(30), Duration::from_secs(60));
        let tasks: Vec<_> = (0..4)
            .map(|_| {
                let rt = rt.clone();
                tokio::spawn(async move { rt.ensure_creds_helper_image_with(lim).await })
            })
            .collect();
        for t in tasks {
            assert_eq!(t.await.unwrap(), Ok(local_helper_tag()));
        }
        assert_eq!(cli.builds(), 1);
    }

    #[test]
    fn none_network_mode_has_no_network_and_no_holder() {
        let p = plan(Some("none"));
        // Loopback only: no host alias, no published ports, whatever the
        // runtime and the task definition say.
        assert_eq!(
            namespace_network_argv(
                &p,
                "t1",
                Some("host.docker.internal:host-gateway"),
                true,
                None
            ),
            ["--network", "none"]
        );
        assert!(!wants_netns_holder(&p));
        // Every other mode with a task role gets a holder; without a role
        // none does.
        for mode in [None, Some("bridge"), Some("host"), Some("awsvpc")] {
            assert!(wants_netns_holder(&plan(mode)), "{mode:?}");
            let mut roleless = plan(mode);
            roleless.has_task_role = false;
            assert!(!wants_netns_holder(&roleless), "{mode:?}");
        }
    }

    #[test]
    fn only_net_sysctls_are_namespace_scoped() {
        assert!(is_net_sysctl("net.ipv4.ip_forward"));
        assert!(!is_net_sysctl("kernel.msgmax"));
    }
}
