//! Backing-container runtime for EC2 instances.
//!
//! `RunInstances` spins a real container per instance; the instance
//! lifecycle (`Start`/`Stop`/`Reboot`/`Terminate`) maps onto the container
//! lifecycle, and `DescribeInstances` reports the container's real private
//! IP. The container can run either as a local Docker/Podman container (the
//! default) or as a native Kubernetes Pod (`FAKECLOUD_EC2_BACKEND=k8s` or the
//! global `FAKECLOUD_CONTAINER_BACKEND=k8s`).
//!
//! Operations are keyed by **instance id**, not the backend handle: a
//! Kubernetes Pod can't be stopped and restarted in place, so `Stop` deletes
//! the Pod and `Start`/`Reboot` recreate it. The runtime therefore keeps,
//! per instance, the handle plus enough of the original request (image,
//! user-data) to recreate the backing container deterministically.
//!
//! The runtime is strictly additive: when no container backend is available
//! the control plane keeps its metadata-faithful behaviour (synthesized IPs,
//! state transitions) so every API call still succeeds. Real container
//! backing is best-effort fidelity layered on top.

pub mod firewall;
mod imds;
pub(crate) mod instance_env;
mod k8s;
pub mod netpolicy;
pub(crate) mod vpc;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use parking_lot::RwLock;

use firewall::{
    render_bridge_ruleset, render_ruleset, resolve_enforcement_mode, EnforcementMode,
    InstanceRules, SubnetFirewall,
};

/// Default base image an instance's container runs. AMIs don't map to a
/// concrete OS image, so we boot a real Amazon Linux container by default
/// (overridable via `FAKECLOUD_EC2_DEFAULT_IMAGE`, e.g. to a lighter image
/// in CI). The container is kept alive with `tail -f /dev/null` — EC2
/// instances are long-running hosts, not one-shot tasks. `tail` is used
/// rather than `sleep infinity` so any base image works (busybox `sleep`
/// rejects `infinity`).
const DEFAULT_IMAGE_ENV: &str = "FAKECLOUD_EC2_DEFAULT_IMAGE";
const DEFAULT_IMAGE: &str = "amazonlinux:2023";

/// Budget for a container CLI call that copies files into a container.
const CLI_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("container failed to start: {0}")]
    ContainerStartFailed(String),
}

/// Error initializing the Kubernetes backend at startup. Surfaced to the
/// operator so a misconfigured cluster fails fast rather than silently
/// falling back to Docker.
#[derive(Debug, thiserror::Error)]
pub enum BackendInitError {
    #[error(transparent)]
    Env(#[from] fakecloud_k8s::K8sEnvError),
    #[error(transparent)]
    PodConfig(#[from] fakecloud_k8s::K8sPodConfigError),
    #[error("failed to connect to the Kubernetes cluster: {0}")]
    Connect(String),
}

/// A running instance's backing container.
#[derive(Debug, Clone)]
pub struct RunningInstance {
    /// Backend-specific handle: a Docker container id, or a Pod name.
    pub container_id: String,
    /// The instance's private IP — the container's address on the daemon
    /// network (Docker) or the Pod IP (k8s).
    pub private_ip: String,
    /// Name of the backing daemon network the container was attached to
    /// (`fakecloud-subnet-<id>`), or `None` when it ran on the default bridge
    /// (no network spec, or creation failed and we fell back). Surfaced for
    /// introspection (#1745 phase 5).
    pub network: Option<String>,
}

/// The L3 placement of an instance's backing container: which subnet it lands
/// in, whether that subnet is private, and the addresses that place it in its
/// VPC (see [`vpc`]).
///
/// Per-subnet networks give the isolation #1745 wants for free: two instances
/// in the same subnet share a bridge and can talk; instances in different
/// subnets / VPCs land on different bridges and cannot route to each other.
#[derive(Debug, Clone, Default)]
pub struct InstanceNetwork {
    /// The EC2 subnet id the instance launched into.
    pub subnet_id: String,
    /// True when the subnet has no `0.0.0.0/0 -> igw` route (private). Its
    /// backing network is `--internal` (no NAT to host/internet) only when
    /// `FAKECLOUD_EC2_ISOLATE_PRIVATE_SUBNETS` asks for it.
    pub internal: bool,
    /// The subnet's CIDR block: the backing network's address range.
    pub cidr_block: Option<String>,
    /// The CIDR block of the subnet's VPC, whose base plus two is the VPC's
    /// DNS server.
    pub vpc_cidr_block: Option<String>,
    /// The private IP EC2 gave the instance, which its container gets on the
    /// subnet's network.
    pub private_ip: Option<String>,
}

/// The daemon network name backing an EC2 subnet. Stable per subnet so every
/// instance in the subnet attaches to the same bridge.
pub fn subnet_network_name(subnet_id: &str) -> String {
    format!("fakecloud-subnet-{subnet_id}")
}

/// How this runtime isolates instance traffic, surfaced by the
/// `/_fakecloud/ec2/instance-networks` introspection endpoint so users can
/// answer "why can't X reach Y" — which backend, which SG-enforcement
/// mechanism, and whether it's actually active vs degraded to metadata-only.
#[derive(Debug, Clone)]
pub struct NetworkIsolationSummary {
    /// `docker` | `podman` | `kubernetes`.
    pub backend: &'static str,
    /// `nftables` (Docker host firewall) | `networkpolicy` (k8s) | `disabled`.
    pub sg_enforcement: &'static str,
    /// Whether security-group rules are actually enforced. False means rules
    /// are tracked but not applied (no `CAP_NET_ADMIN`, or a CNI that ignores
    /// NetworkPolicy) — phase-2 L3 isolation still holds.
    pub enforced: bool,
}

/// What the runtime remembers per instance so it can drive the backing
/// container's lifecycle and recreate it (k8s `Start`/`Reboot`).
#[derive(Debug, Clone)]
struct InstanceRecord {
    /// Docker container id, or Pod name.
    handle: String,
    /// Resolved base image, captured at `RunInstances` so a recreate is
    /// identical even if `FAKECLOUD_EC2_DEFAULT_IMAGE` later changes.
    image: String,
    /// Base64 user-data to re-run on recreate, if any.
    user_data: Option<String>,
    /// The instance's tags, captured at `RunInstances`. Reserved
    /// `fakecloud-k8s/*` entries drive per-instance Pod scheduling and must
    /// survive a k8s `Start`/`Reboot` recreate, so they're stored here
    /// rather than re-read from the control plane.
    tags: BTreeMap<String, String>,
    /// The instance's subnet placement, captured at `RunInstances` so a k8s
    /// `Start`/`Reboot` recreate re-applies the same network and phase-5
    /// introspection can report the backing network. `None` in metadata-only
    /// network mode.
    network: Option<InstanceNetwork>,
    /// The backing container's current private IP (refreshed on start and
    /// k8s recreate), which load balancer forwarders connect to. Empty while
    /// unknown (mid-reboot, or a failed inspect): re-read on demand.
    private_ip: String,
    /// Whether the backing container should be running (false once stopped).
    running: bool,
    /// The account and region the instance runs in, captured at `RunInstances`
    /// so a Docker recreate mounts the same data and EBS volumes.
    account_id: String,
    region: String,
    /// The EBS volumes attached to the instance, each mounted in its container
    /// at its device name when mounting is on.
    volumes: Vec<AttachedVolume>,
    /// The attached volumes changed while the instance was stopped: its
    /// container is recreated, not restarted, when it starts.
    remount: bool,
}

/// What an instance boots with: its user-data (base64, as `RunInstances`
/// received it), tags, subnet placement, region and attached EBS volumes.
#[derive(Debug, Clone, Copy)]
pub struct Boot<'a> {
    pub user_data: Option<&'a str>,
    pub tags: &'a BTreeMap<String, String>,
    pub network: Option<&'a InstanceNetwork>,
    pub region: &'a str,
    pub volumes: &'a [AttachedVolume],
}

/// An EBS volume attached to an instance: its container mounts the volume's
/// backing container volume at the attachment's device name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachedVolume {
    pub volume_id: String,
    pub device: String,
}

/// The selected backing-container backend.
#[derive(Debug, Clone)]
enum InstanceBackend {
    Docker(DockerInstances),
    K8s(k8s::K8sInstances),
}

/// Host firewall enforcement for security groups + NACLs (#1745 phase 3).
///
/// The network-driver abstraction the issue asks for: today there is one real
/// driver (nftables) plus the degraded no-op, selected once at construction.
/// Branching on podman vs docker isn't needed explicitly — rootless podman
/// can't touch the host firewall, so the `nft list ruleset` capability probe
/// already degrades it; rootful podman with netavark passes the same probe.
#[derive(Debug, Clone)]
pub struct FirewallEnforcer {
    mode: EnforcementMode,
}

impl FirewallEnforcer {
    /// Resolve the enforcement mode from `FAKECLOUD_EC2_SG_ENFORCEMENT` and an
    /// `nft` capability probe, warning once when enforcement was requested but
    /// can't be backed (so the operator knows it degraded, not silently).
    fn detect() -> Self {
        let requested = std::env::var("FAKECLOUD_EC2_SG_ENFORCEMENT").ok();
        let mode = resolve_enforcement_mode(
            requested.as_deref(),
            firewall::host_shares_daemon_netns(),
            firewall::nft_available,
        );
        if requested.is_some() && mode == EnforcementMode::Disabled {
            tracing::warn!(
                "EC2 security-group enforcement was requested but it can't take effect here \
                 (needs nftables + CAP_NET_ADMIN on a native-Linux host whose daemon shares this \
                 network namespace — Docker Desktop / podman-machine run the daemon in a VM); \
                 falling back to metadata-only (phase-2 L3 isolation stays active, security-group \
                 rules are tracked but not enforced)"
            );
        } else if mode == EnforcementMode::Nftables {
            tracing::info!("EC2 security-group enforcement active via nftables");
        }
        Self { mode }
    }

    /// Disabled enforcer (k8s backend, or no container runtime).
    fn disabled() -> Self {
        Self {
            mode: EnforcementMode::Disabled,
        }
    }

    pub fn mode(&self) -> EnforcementMode {
        self.mode
    }

    pub fn enabled(&self) -> bool {
        self.mode != EnforcementMode::Disabled
    }

    /// Atomically swap in the rendered ruleset via `nft -f -`. No-op when
    /// disabled. Best-effort: a failed apply logs and leaves the previous
    /// ruleset in place rather than erroring the originating API call.
    async fn reconcile(&self, subnets: &[SubnetFirewall]) {
        if self.mode == EnforcementMode::Disabled {
            return;
        }
        // Instances in the same subnet share one Linux bridge; their traffic is
        // L2-switched and only traverses the `forward` chain (where our SG rules
        // live) when bridge netfilter is enabled. Without this, same-subnet SG
        // rules silently filter nothing — exactly what the real-packet E2E
        // caught. Needs CAP_NET_ADMIN (which the enforcer holds) and the
        // `modprobe`/`sysctl` binaries (shipped via kmod/procps in the image).
        // Warn rather than swallow the error: a missing binary or a failed call
        // means enforcement degrades to filtering nothing, and the operator who
        // opted in deserves to know (bug-audit 2026-06-20, 0.B1).
        match tokio::process::Command::new("modprobe")
            .arg("br_netfilter")
            .output()
            .await
        {
            Ok(o) if o.status.success() => {}
            Ok(o) => tracing::warn!(
                stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                "modprobe br_netfilter failed; same-subnet security-group enforcement may filter nothing"
            ),
            Err(e) => tracing::warn!(
                error = %e,
                "could not run modprobe (is kmod installed?); same-subnet security-group enforcement may filter nothing"
            ),
        }
        match tokio::process::Command::new("sysctl")
            .args(["-w", "net.bridge.bridge-nf-call-iptables=1"])
            .output()
            .await
        {
            Ok(o) if o.status.success() => {}
            Ok(o) => tracing::warn!(
                stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                "sysctl bridge-nf-call-iptables=1 failed; same-subnet security-group enforcement may filter nothing"
            ),
            Err(e) => tracing::warn!(
                error = %e,
                "could not run sysctl (is procps installed?); same-subnet security-group enforcement may filter nothing"
            ),
        }
        use tokio::io::AsyncWriteExt;
        // Load a rendered ruleset via `nft -f -`. `required=false` marks the
        // best-effort same-subnet bridge table: a kernel without
        // `nf_conntrack_bridge` rejects its `ct state` line, and since the inet
        // table is applied independently first, that rejection is logged at
        // debug (degraded same-subnet enforcement) rather than warn.
        async fn load_nft(label: &str, ruleset: &str, subnets: usize, required: bool) {
            let mut child = match tokio::process::Command::new("nft")
                .args(["-f", "-"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, table = label, "failed to spawn nft; security-group ruleset not applied");
                    return;
                }
            };
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(ruleset.as_bytes()).await;
                let _ = stdin.shutdown().await;
            }
            match child.wait_with_output().await {
                Ok(out) if out.status.success() => {
                    tracing::debug!(
                        subnets,
                        table = label,
                        "applied EC2 security-group nft ruleset"
                    );
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    let stderr = stderr.trim();
                    if required {
                        tracing::warn!(table = label, stderr = %stderr, "nft rejected the security-group ruleset; leaving the previous ruleset in place");
                    } else {
                        tracing::debug!(table = label, stderr = %stderr, "bridge-family SG ruleset not applied (kernel may lack nf_conntrack_bridge); same-subnet enforcement degraded to inet table only");
                    }
                }
                Err(e) => tracing::warn!(error = %e, table = label, "nft apply failed"),
            }
        }
        let n = subnets.len();
        // inet: cross-subnet routed enforcement (required). bridge: same-subnet
        // L2 enforcement that the inet forward hook misses for bridged frames.
        load_nft("inet fakecloud_ec2", &render_ruleset(subnets), n, true).await;
        load_nft(
            "bridge fakecloud_ec2_l2",
            &render_bridge_ruleset(subnets),
            n,
            false,
        )
        .await;
    }
}

#[derive(Debug, Clone)]
pub struct Ec2Runtime {
    backend: InstanceBackend,
    /// Per-instance backing records, keyed by EC2 instance id, so the
    /// lifecycle operations and reset/shutdown teardown work without
    /// consulting service state.
    instances: Arc<RwLock<HashMap<String, InstanceRecord>>>,
    /// Host firewall enforcer for security groups + NACLs.
    firewall: FirewallEnforcer,
    /// Serializes firewall reconciles. Reconcile is fired from many concurrent
    /// background tasks (per SG/NACL/lifecycle event); without this, two
    /// reconciles built from divergent state could interleave so the k8s
    /// apply+prune of one deletes a policy the other just applied (bug-hunt
    /// 2026-06-18 finding 4.3). Holding it across the whole reconcile makes the
    /// last-started reconcile the last-applied for both backends.
    reconcile_lock: Arc<tokio::sync::Mutex<()>>,
    /// Per-instance lifecycle locks. Every container-lifecycle task (boot,
    /// start, stop, terminate, reboot, recovery) holds its instance's lock
    /// across the runtime call and the state reconcile that follows, and
    /// re-reads the instance's desired state once it holds it. So a stop
    /// decided against a `stopped` row can never land on a container a later
    /// StartInstances just started: that start waits, then sees the row it
    /// is asked to converge to.
    lifecycle_locks: Arc<parking_lot::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
}

impl Ec2Runtime {
    /// Construct the Docker/Podman backend. Returns `None` when no container
    /// CLI is available — callers then run in metadata-only mode.
    /// `server_port` is fakecloud's bound port, which instance IMDS proxies
    /// forward to.
    pub fn new(server_port: u16) -> Option<Self> {
        let cli = fakecloud_core::container_net::detect_container_cli()?;
        let podman = fakecloud_core::container_net::is_podman(&cli);
        let net = fakecloud_core::container_net::HostNetworking::detect(&cli);
        Some(Self {
            backend: InstanceBackend::Docker(DockerInstances {
                cli,
                podman,
                instance_id: format!("fakecloud-{}", std::process::id()),
                net,
                server_port,
                helper_image: Arc::new(tokio::sync::Mutex::new(None)),
                forwarders: Arc::new(parking_lot::Mutex::new(HashMap::new())),
                forward_locks: Arc::new(parking_lot::Mutex::new(HashMap::new())),
                forwarders_changed: Arc::new(ChangeHook::default()),
                vpc_sidecars: Arc::new(parking_lot::Mutex::new(HashMap::new())),
                engine_socket: Arc::new(std::sync::OnceLock::new()),
            }),
            instances: Arc::new(RwLock::new(HashMap::new())),
            firewall: FirewallEnforcer::detect(),
            reconcile_lock: Arc::new(tokio::sync::Mutex::new(())),
            lifecycle_locks: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        })
    }

    /// Construct the Kubernetes backend. `server_port` is fakecloud's bound
    /// port (used when `FAKECLOUD_K8S_SELF_URL` omits one). Fails fast on
    /// misconfiguration — never silently degrades to Docker.
    pub async fn new_k8s(server_port: u16) -> Result<Self, BackendInitError> {
        let backend = k8s::K8sInstances::from_env(server_port).await?;
        Ok(Self {
            backend: InstanceBackend::K8s(backend),
            instances: Arc::new(RwLock::new(HashMap::new())),
            // k8s isolation is a NetworkPolicy concern (phase 4), not host nft.
            firewall: FirewallEnforcer::disabled(),
            reconcile_lock: Arc::new(tokio::sync::Mutex::new(())),
            lifecycle_locks: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        })
    }

    /// The firewall enforcer, so the control plane can skip building the model
    /// when enforcement is disabled and report the mode for introspection.
    pub fn firewall(&self) -> &FirewallEnforcer {
        &self.firewall
    }

    /// Re-render and atomically apply the security-group/NACL ruleset for the
    /// given per-subnet model. No-op (cheap) when enforcement is disabled.
    /// Serialized against other reconciles (finding 4.3).
    /// `build` derives the model and runs under the lock, so a model built
    /// from older state can never be applied after a newer one.
    pub async fn reconcile_firewall(&self, build: impl FnOnce() -> Vec<SubnetFirewall>) {
        let _guard = self.reconcile_lock.lock().await;
        let subnets = build();
        self.firewall.reconcile(&subnets).await;
    }

    /// Whether this runtime backs network isolation with real enforcement —
    /// host nftables (Docker, opt-in) or k8s NetworkPolicy. Lets the control
    /// plane skip building the firewall model entirely when neither applies.
    pub fn network_isolation_enforced(&self) -> bool {
        self.firewall.enabled() || self.is_k8s()
    }

    /// True for the Kubernetes backend (isolation via NetworkPolicy).
    pub fn is_k8s(&self) -> bool {
        matches!(self.backend, InstanceBackend::K8s(_))
    }

    /// Apply one NetworkPolicy per instance for the k8s backend. No-op on the
    /// Docker backend (which uses nftables instead). Serialized against other
    /// reconciles so a concurrent apply+prune can't delete a just-applied
    /// policy (finding 4.3).
    pub async fn reconcile_network_policies(&self, build: impl FnOnce() -> Vec<InstanceRules>) {
        if let InstanceBackend::K8s(k) = &self.backend {
            let _guard = self.reconcile_lock.lock().await;
            let rules = build();
            k.reconcile_network_policies(&rules).await;
        }
    }

    /// A snapshot of how this runtime isolates instance traffic, for the
    /// `/_fakecloud/ec2/instance-networks` introspection endpoint (#1745 ph5).
    pub fn network_isolation_summary(&self) -> NetworkIsolationSummary {
        match &self.backend {
            InstanceBackend::Docker(d) => NetworkIsolationSummary {
                backend: if d.podman { "podman" } else { "docker" },
                sg_enforcement: match self.firewall.mode() {
                    EnforcementMode::Nftables => "nftables",
                    EnforcementMode::Disabled => "disabled",
                },
                enforced: self.firewall.enabled(),
            },
            InstanceBackend::K8s(k) => NetworkIsolationSummary {
                backend: "kubernetes",
                sg_enforcement: "networkpolicy",
                // NetworkPolicies are always created; "enforced" reflects
                // whether the detected CNI actually applies them.
                enforced: k.cni_enforces(),
            },
        }
    }

    /// Name of the active backend, for logging.
    pub fn cli_name(&self) -> &str {
        match &self.backend {
            InstanceBackend::Docker(d) => &d.cli,
            InstanceBackend::K8s(_) => "kubernetes",
        }
    }

    /// Boot a container for an instance. `user_data` is the base64-encoded
    /// user-data as received on the wire (RunInstances `UserData`), run at
    /// boot the way cloud-init would, if present. `region` is the instance's
    /// region.
    pub async fn run_instance(
        &self,
        account_id: &str,
        instance_id: &str,
        boot: &Boot<'_>,
    ) -> Result<RunningInstance, RuntimeError> {
        let Boot {
            user_data,
            tags,
            network,
            region,
            volumes,
        } = *boot;
        let image = default_image();
        let running = match &self.backend {
            // Docker attaches the container to the subnet's per-VPC bridge for
            // L3 isolation. k8s pods share a flat network; isolation there is a
            // NetworkPolicy concern handled separately (#1745 phase 4).
            InstanceBackend::Docker(d) => {
                let launch = DockerLaunch {
                    account_id,
                    instance_id,
                    image: &image,
                    user_data,
                    tags,
                    network,
                    region,
                    volumes,
                };
                d.run_instance(&launch).await?
            }
            InstanceBackend::K8s(k) => {
                if ebs_mounts_enabled() && !volumes.is_empty() {
                    tracing::warn!(instance = %instance_id, "the Kubernetes backend does not mount attached EBS volumes");
                }
                k.spawn_pod(instance_id, &image, user_data, tags).await?
            }
        };
        self.instances.write().insert(
            instance_id.to_string(),
            InstanceRecord {
                handle: running.container_id.clone(),
                image,
                user_data: user_data.map(str::to_string),
                tags: tags.clone(),
                network: network.cloned(),
                private_ip: running.private_ip.clone(),
                running: true,
                account_id: account_id.to_string(),
                region: region.to_string(),
                volumes: volumes.to_vec(),
                remount: false,
            },
        );
        self.spawn_imds(instance_id, &running.container_id);
        Ok(running)
    }

    /// Mount `volumes`, the EBS volumes now attached to the instance, in its
    /// container (maps to `AttachVolume` and `DetachVolume`). Docker cannot
    /// change a container's mounts, so a running instance's container is
    /// recreated on the same root data volume, private IP and user-data -- to
    /// the instance, a reboot -- and its new handle and IP are returned; a
    /// stopped one is recreated when it next starts. With mounting off, or on
    /// the Kubernetes backend, the container is left as it is.
    pub async fn set_volumes(
        &self,
        instance_id: &str,
        volumes: Vec<AttachedVolume>,
    ) -> Option<RunningInstance> {
        let InstanceBackend::Docker(d) = &self.backend else {
            return None;
        };
        let record = {
            let mut instances = self.instances.write();
            let record = instances.get_mut(instance_id)?;
            if record.volumes == volumes {
                return None;
            }
            record.volumes = volumes;
            if !ebs_mounts_enabled() {
                return None;
            }
            if !record.running {
                record.remount = true;
                return None;
            }
            record.clone()
        };
        self.recreate(d, instance_id, &record).await
    }

    /// Remove the container volume backing EBS volume `volume_id` (maps to
    /// `DeleteVolume`, and to a `DeleteOnTermination` volume going with its
    /// instance). A no-op with mounting off: no such volume was made.
    pub async fn delete_volume(&self, account_id: &str, volume_id: &str) {
        let InstanceBackend::Docker(d) = &self.backend else {
            return;
        };
        if !ebs_mounts_enabled() {
            return;
        }
        let name = ebs_volume_name(
            fakecloud_core::data_volume::current_scope().tag(),
            account_id,
            volume_id,
        );
        fakecloud_core::data_volume::remove_volume(&d.cli, &name).await;
    }

    /// Replace a Docker-backed instance's container with one booted from its
    /// record, whose mounts changed. The old container goes first, so the new
    /// one takes its private IP.
    async fn recreate(
        &self,
        d: &DockerInstances,
        instance_id: &str,
        record: &InstanceRecord,
    ) -> Option<RunningInstance> {
        self.update_ip(instance_id, "");
        d.remove_sidecars(instance_id).await;
        d.remove(&record.handle).await;
        let launch = DockerLaunch {
            account_id: &record.account_id,
            instance_id,
            image: &record.image,
            user_data: record.user_data.as_deref(),
            tags: &record.tags,
            network: record.network.as_ref(),
            region: &record.region,
            volumes: &record.volumes,
        };
        match d.run_instance(&launch).await {
            Ok(running) => {
                if let Some(r) = self.instances.write().get_mut(instance_id) {
                    r.handle.clone_from(&running.container_id);
                    r.private_ip.clone_from(&running.private_ip);
                    r.running = true;
                    r.remount = false;
                }
                self.spawn_imds(instance_id, &running.container_id);
                Some(running)
            }
            Err(error) => {
                tracing::warn!(instance = %instance_id, %error, "could not recreate the instance's container with its EBS volumes");
                if let Some(r) = self.instances.write().get_mut(instance_id) {
                    r.running = false;
                    r.remount = true;
                }
                None
            }
        }
    }

    /// Stop an instance's backing container (maps to `StopInstances`).
    /// Docker stops the container in place; k8s deletes the Pod (recreated
    /// on the next `Start`).
    pub async fn stop_instance(&self, instance_id: &str) {
        let Some(handle) = self.handle_of(instance_id) else {
            return;
        };
        // A stopped instance has no address: nothing may be forwarded to the
        // IP it held, which the daemon can hand to another container.
        if let Some(record) = self.instances.write().get_mut(instance_id) {
            record.private_ip.clear();
            record.running = false;
        }
        match &self.backend {
            InstanceBackend::Docker(d) => {
                d.stop(&handle).await;
                // The namespace the sidecar joined and the IP the forwarders
                // target are gone with the container's network.
                d.remove_sidecars(instance_id).await;
            }
            InstanceBackend::K8s(k) => k.delete_pod(&handle).await,
        }
    }

    /// Start a previously-stopped instance (maps to `StartInstances`).
    /// Returns the running container's (possibly new) handle and private IP.
    /// Docker starts the existing container; k8s recreates the Pod under a new
    /// unique name, so the handle changes — callers should persist it.
    pub async fn start_instance(&self, instance_id: &str) -> Option<RunningInstance> {
        let record = self.instances.read().get(instance_id)?.clone();
        match &self.backend {
            // Its EBS volumes changed while it was stopped: a container that
            // mounts them takes the old one's place.
            InstanceBackend::Docker(d) if record.remount => {
                self.recreate(d, instance_id, &record).await
            }
            InstanceBackend::Docker(d) => {
                // Same container; only the IP may change. The subnet network the
                // container was created on persists across stop/start.
                let private_ip = d.start(&record.handle).await?;
                // A started container has a fresh network namespace: give it
                // IMDS again.
                d.remove_sidecars(instance_id).await;
                self.update_ip(instance_id, &private_ip);
                self.spawn_imds(instance_id, &record.handle);
                Some(RunningInstance {
                    container_id: record.handle,
                    private_ip,
                    network: record
                        .network
                        .as_ref()
                        .map(|n| subnet_network_name(&n.subnet_id)),
                })
            }
            InstanceBackend::K8s(k) => {
                let running = k
                    .spawn_pod(
                        instance_id,
                        &record.image,
                        record.user_data.as_deref(),
                        &record.tags,
                    )
                    .await
                    .ok()?;
                self.update_handle(instance_id, &running.container_id);
                self.update_ip(instance_id, &running.private_ip);
                Some(running)
            }
        }
    }

    /// Restart an instance's backing container (maps to `RebootInstances`).
    /// Docker restarts in place; k8s deletes and recreates the Pod under a new
    /// name. Returns the running container's handle + IP when it changed (k8s),
    /// so callers can persist the new handle; `None` when nothing to update.
    pub async fn reboot_instance(&self, instance_id: &str) -> Option<RunningInstance> {
        let record = self.instances.read().get(instance_id).cloned()?;
        match &self.backend {
            InstanceBackend::Docker(d) => {
                self.update_ip(instance_id, "");
                d.reboot(&record.handle).await;
                // The restart replaced the network namespace the sidecar had
                // joined; the IP can change with it.
                d.remove_sidecars(instance_id).await;
                if let Some(ip) = d.inspect_ip(&record.handle).await {
                    self.update_ip(instance_id, &ip);
                }
                self.spawn_imds(instance_id, &record.handle);
                None
            }
            InstanceBackend::K8s(k) => {
                self.update_ip(instance_id, "");
                k.delete_pod(&record.handle).await;
                let running = k
                    .spawn_pod(
                        instance_id,
                        &record.image,
                        record.user_data.as_deref(),
                        &record.tags,
                    )
                    .await
                    .ok()?;
                self.update_handle(instance_id, &running.container_id);
                self.update_ip(instance_id, &running.private_ip);
                Some(running)
            }
        }
    }

    /// Serialize lifecycle work on one instance; see `lifecycle_locks`.
    pub async fn lock_lifecycle(&self, instance_id: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = self
            .lifecycle_locks
            .lock()
            .entry(instance_id.to_string())
            .or_default()
            .clone();
        lock.lock_owned().await
    }

    /// Remove an instance's backing container and its durable root-disk
    /// volume (maps to `TerminateInstances`). The volume is removed by the
    /// instance's account and id even when no runtime record exists: a boot
    /// that failed after creating it, or an instance recovered from disk as
    /// `stopped`, has a volume but no record. Instance ids are unique, so this
    /// never reaches another instance's volume.
    pub async fn terminate_instance(&self, account_id: &str, instance_id: &str) {
        let record = self.instances.write().remove(instance_id);
        // Terminated is final, so its lifecycle lock is never needed again; a
        // late task for the id creates a fresh one and only ever reaps.
        self.lifecycle_locks.lock().remove(instance_id);
        match &self.backend {
            InstanceBackend::Docker(d) => {
                d.remove_sidecars(instance_id).await;
                if let Some(record) = record {
                    d.remove(&record.handle).await;
                }
                // Terminate = volume gone, matching a deleted EBS root volume.
                // No-op when volumes are disabled.
                d.remove_data_volume(account_id, instance_id).await;
            }
            InstanceBackend::K8s(k) => {
                if let Some(record) = record {
                    k.delete_pod(&record.handle).await;
                }
            }
        }
    }

    /// Tear down every container this runtime spawned (used on reset and
    /// shutdown). The Docker backend leans on the shared reaper for any
    /// container it loses track of.
    pub async fn stop_all(&self) {
        let records: Vec<(String, InstanceRecord)> = {
            let mut instances = self.instances.write();
            instances.drain().collect()
        };
        for (instance_id, record) in records {
            match &self.backend {
                InstanceBackend::Docker(d) => {
                    d.remove_sidecars(&instance_id).await;
                    d.remove(&record.handle).await
                }
                InstanceBackend::K8s(k) => k.delete_pod(&record.handle).await,
            }
        }
    }

    /// Tear down the given `(account, instance_id)`s for a reset: their
    /// containers and data volumes. Instance ids are unique per instance, so
    /// this never reaches an instance launched after the reset. Covers stopped
    /// instances recovered from disk too, which have no runtime record but
    /// still have a volume.
    ///
    /// An instance with a lifecycle task in flight (a boot pulling its image,
    /// a reboot recreating its Pod) is torn down once that task lets go, on a
    /// task of its own: waiting for it here would hold the reset response for
    /// as long as an image pull takes. The task removes what the in-flight one
    /// leaves, so nothing outlives the reset either way.
    pub async fn remove_instances(&self, instances: Vec<(String, String)>) {
        for (account_id, instance_id) in instances {
            let lock = self
                .lifecycle_locks
                .lock()
                .entry(instance_id.clone())
                .or_default()
                .clone();
            match lock.clone().try_lock_owned() {
                Ok(guard) => {
                    self.remove_instance_locked(&account_id, &instance_id, guard)
                        .await
                }
                Err(_) => {
                    let rt = self.clone();
                    tokio::spawn(async move {
                        let guard = lock.lock_owned().await;
                        rt.remove_instance_locked(&account_id, &instance_id, guard)
                            .await;
                    });
                }
            }
        }
    }

    /// Remove one reset instance's container and data volume while holding
    /// its lifecycle lock.
    async fn remove_instance_locked(
        &self,
        account_id: &str,
        instance_id: &str,
        lifecycle: tokio::sync::OwnedMutexGuard<()>,
    ) {
        let record = self.instances.write().remove(instance_id);
        if let InstanceBackend::Docker(d) = &self.backend {
            d.remove_sidecars(instance_id).await;
        }
        if let Some(record) = record {
            match &self.backend {
                InstanceBackend::Docker(d) => d.remove(&record.handle).await,
                InstanceBackend::K8s(k) => k.delete_pod(&record.handle).await,
            }
        }
        if let InstanceBackend::Docker(d) = &self.backend {
            d.remove_data_volume(account_id, instance_id).await;
        }
        drop(lifecycle);
        self.lifecycle_locks.lock().remove(instance_id);
    }

    /// Sweep instance Pods orphaned by a previous fakecloud process (k8s
    /// only; the Docker backend relies on the shared reaper).
    pub async fn reap_stale(&self) {
        if let InstanceBackend::K8s(k) = &self.backend {
            k.reap_stale().await;
        }
    }

    /// The backing container's console log — its combined stdout/stderr, which
    /// includes anything user-data printed at boot (maps to `GetConsoleOutput`).
    /// `None` for an unbacked instance or when logs can't be read.
    pub async fn console_output(&self, instance_id: &str) -> Option<Vec<u8>> {
        let handle = self.handle_of(instance_id)?;
        match &self.backend {
            InstanceBackend::Docker(d) => d.logs(&handle).await,
            InstanceBackend::K8s(k) => k.logs(&handle).await,
        }
    }

    /// Whether the runtime holds an in-memory backing record for this instance.
    /// After a fakecloud restart the registry is rebuilt only for instances that
    /// persisted as `running`/`pending` (see `recover_persisted_containers`), so
    /// an instance that persisted as `stopped` has no record here. `StartInstances`
    /// uses this to distinguish "reattach the existing container" (`start_instance`)
    /// from "the registry was lost across a restart, boot a fresh container"
    /// (`run_instance`) — without it, starting a stopped-then-restarted instance
    /// flips it to `running` with no backing container (the EC2 analogue of the
    /// RDS restart-recovery bug).
    pub fn is_registered(&self, instance_id: &str) -> bool {
        self.instances.read().contains_key(instance_id)
    }

    fn handle_of(&self, instance_id: &str) -> Option<String> {
        self.instances
            .read()
            .get(instance_id)
            .map(|r| r.handle.clone())
    }

    /// Give a Docker-backed instance IMDS (and, with `--dns`, its VPC's DNS
    /// and load balancer routes) in the background. The sidecar (and, the
    /// first time, the helper image build) can take tens of seconds, and the
    /// caller holds the instance's lifecycle lock -- which a reset, stop or
    /// terminate waits on -- so it never runs inline. The task re-checks that
    /// the instance is still this running container before and after
    /// starting the sidecar, so a stop / terminate that lands meanwhile never
    /// leaves a sidecar behind.
    fn spawn_imds(&self, instance_id: &str, handle: &str) {
        let InstanceBackend::Docker(d) = &self.backend else {
            return;
        };
        let d = d.clone();
        let instances = self.instances.clone();
        let id = instance_id.to_string();
        let handle = handle.to_string();
        let vpc_dns = {
            let instances = self.instances.read();
            vpc::vpc_dns(instances.get(instance_id).and_then(|r| r.network.as_ref()))
        };
        tokio::spawn(async move {
            let current = {
                let (instances, id, handle) = (instances.clone(), id.clone(), handle.clone());
                move || {
                    instances
                        .read()
                        .get(&id)
                        .is_some_and(|r| r.running && r.handle == handle)
                }
            };
            d.start_imds(&id, &handle, vpc_dns.as_ref(), current).await;
        });
    }

    fn update_handle(&self, instance_id: &str, handle: &str) {
        if let Some(record) = self.instances.write().get_mut(instance_id) {
            record.handle = handle.to_string();
        }
    }

    fn update_ip(&self, instance_id: &str, ip: &str) {
        if let Some(record) = self.instances.write().get_mut(instance_id) {
            record.private_ip = ip.to_string();
            if !ip.is_empty() {
                record.running = true;
            }
        }
    }

    /// The resolver the ELBv2 data plane uses to reach `i-...` targets:
    /// install it with [`fakecloud_core::dataplane::set_instance_resolver`].
    pub fn endpoint_resolver(&self) -> Arc<dyn fakecloud_core::dataplane::InstanceResolver> {
        Arc::new(InstanceEndpoints(self.clone()))
    }

    /// Where `port` of a running instance is reachable from fakecloud: a
    /// forwarder's published host port (Docker), or the Pod IP (k8s, which
    /// the data plane reaches in-cluster). `None` for an unbacked instance.
    async fn instance_endpoint(
        &self,
        instance_id: &str,
        port: u16,
        source_groups: Vec<String>,
    ) -> Option<fakecloud_core::dataplane::Endpoint> {
        let record = self.instances.read().get(instance_id).cloned()?;
        // Stopped: nothing to reach (its old IP may belong to another
        // container now).
        if !record.running {
            return None;
        }
        match &self.backend {
            InstanceBackend::Docker(d) => {
                // Running with no known address (a reboot whose inspect
                // failed): read it again rather than staying unreachable.
                let ip = if record.private_ip.is_empty() {
                    let ip = d.inspect_ip(&record.handle).await?;
                    self.update_ip(instance_id, &ip);
                    ip
                } else {
                    record.private_ip.clone()
                };
                let instances = self.instances.clone();
                let id = instance_id.to_string();
                let current_ip = move || {
                    instances
                        .read()
                        .get(&id)
                        .filter(|r| r.running)
                        .map(|r| r.private_ip.clone())
                };
                d.forward(
                    instance_id,
                    &ip,
                    record.network.as_ref(),
                    port,
                    source_groups,
                    current_ip,
                )
                .await
            }
            InstanceBackend::K8s(_) => (!record.private_ip.is_empty())
                .then(|| fakecloud_core::dataplane::Endpoint::new(record.private_ip, port)),
        }
    }

    /// `(security group, address)` pairs to treat as members of the group
    /// when expanding referenced-group rules: the load balancer forwarders'
    /// subnet addresses under the load balancer's groups. Empty on k8s.
    pub fn extra_group_members(&self) -> Vec<(String, String)> {
        match &self.backend {
            InstanceBackend::Docker(d) => d.forwarder_group_members(),
            InstanceBackend::K8s(_) => Vec::new(),
        }
    }

    /// Install the hook run when the extra group members change (the control
    /// plane re-renders the firewall). First call wins.
    pub fn set_group_members_hook(
        &self,
        hook: impl Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
            + Send
            + Sync
            + 'static,
    ) {
        if let InstanceBackend::Docker(d) = &self.backend {
            let _ = d.forwarders_changed.0.set(Arc::new(hook));
        }
    }
}

/// [`fakecloud_core::dataplane::InstanceResolver`] over the EC2 runtime.
struct InstanceEndpoints(Ec2Runtime);

impl fakecloud_core::dataplane::InstanceResolver for InstanceEndpoints {
    fn resolve(
        &self,
        _account_id: &str,
        instance_id: &str,
        port: u16,
        source_groups: Vec<String>,
    ) -> fakecloud_core::dataplane::ResolveFuture {
        // Instance ids are globally unique, so the id alone picks the record.
        let rt = self.0.clone();
        let instance_id = instance_id.to_string();
        Box::pin(async move {
            rt.instance_endpoint(&instance_id, port, source_groups)
                .await
        })
    }
}

fn default_image() -> String {
    std::env::var(DEFAULT_IMAGE_ENV).unwrap_or_else(|_| DEFAULT_IMAGE.to_string())
}

/// The in-instance directory backed by the durable data volume. Defaults to
/// `/var/lib/fakecloud/ec2`; override with `FAKECLOUD_EC2_INSTANCE_DATA_DIR`
/// to capture whichever path the instance's workload writes its long-lived
/// state to. This is fakecloud's persistent-instance-data convention rather
/// than a full root-filesystem snapshot: data written here survives restart
/// and stop/start; the rest of the container's ephemeral filesystem does not.
fn instance_data_dir() -> String {
    std::env::var("FAKECLOUD_EC2_INSTANCE_DATA_DIR")
        .unwrap_or_else(|_| "/var/lib/fakecloud/ec2".to_string())
}

/// Whether EC2 instance data should survive a container being recreated via a
/// durable named volume. The server defaults `FAKECLOUD_PERSIST_EC2_VOLUMES`
/// on in persistent mode (volumes scoped to the data dir); unset means off, as
/// in memory mode, where an explicit opt-in gets process-scoped volumes.
fn ec2_volumes_enabled() -> bool {
    std::env::var("FAKECLOUD_PERSIST_EC2_VOLUMES")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes"))
        .unwrap_or(false)
}

/// Whether an EBS volume attached to an instance is mounted in its container,
/// at the attachment's device name (`FAKECLOUD_EC2_MOUNT_VOLUMES`, off unless
/// set). The instance then sees the volume as a directory there, not a block
/// device, already formatted. Docker cannot add a mount to a running
/// container, so attaching or detaching a volume recreates a running
/// instance's container: to the instance, a reboot.
fn ebs_mounts_enabled() -> bool {
    std::env::var("FAKECLOUD_EC2_MOUNT_VOLUMES")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes"))
        .unwrap_or(false)
}

/// Docker volume name backing an EBS volume in a volume scope: stable across
/// restarts of a data dir, so a volume keeps its contents whichever instance
/// it is attached to.
fn ebs_volume_name(scope_tag: &str, account_id: &str, volume_id: &str) -> String {
    fakecloud_core::data_volume::scoped_volume_name("ebs", scope_tag, &[account_id, volume_id])
}

/// Docker volume name for an instance's data dir in a volume scope
/// (`fakecloud_core::data_volume`): stable for the same data dir across
/// restarts, so the recovered container reattaches it, and distinct for any
/// other data dir or memory-mode process.
fn scoped_data_volume_name(scope_tag: &str, account_id: &str, instance_id: &str) -> String {
    fakecloud_core::data_volume::scoped_volume_name("ec2", scope_tag, &[account_id, instance_id])
}

/// The unscoped name builds before #2630 gave an instance's data volume.
fn legacy_data_volume_name(account_id: &str, instance_id: &str) -> String {
    fakecloud_core::data_volume::legacy_volume_name("ec2", &[account_id, instance_id])
}

/// Pick the volume to mount: the scoped one once it exists, else a legacy one
/// left by a pre-scoping build for this (randomly-id'd) instance, else a new
/// scoped one.
fn choose_data_volume(
    scoped: String,
    legacy: String,
    scoped_exists: bool,
    legacy_exists: bool,
) -> String {
    if !scoped_exists && legacy_exists {
        legacy
    } else {
        scoped
    }
}

/// Keep-alive command + user-data wrapper for a base image. Shared by both
/// backends so they boot identical containers. When `user_data` (base64) is
/// present it is decoded and run as a root shell script, backgrounded so a
/// slow script never blocks readiness, then the container tails forever.
fn boot_command(user_data: Option<&str>) -> Vec<String> {
    match user_data.filter(|s| !s.is_empty()) {
        Some(b64) => {
            // Wait (bounded) for the IMDS proxy, so a boot script that reads
            // `169.254.169.254` first thing finds it, as cloud-init would.
            let script = format!(
                "(i=0; while [ ! -e {ready} ] && [ $i -lt {wait} ]; do sleep 1; i=$((i+1)); done; \
                 printf %s '{b64}' | base64 -d | sh) & exec tail -f /dev/null",
                ready = imds::READY_FILE,
                wait = imds::BOOT_WAIT_SECS,
            );
            vec!["sh".to_string(), "-c".to_string(), script]
        }
        None => vec![
            "tail".to_string(),
            "-f".to_string(),
            "/dev/null".to_string(),
        ],
    }
}

/// Docker/Podman backend: shells out to the container CLI.
#[derive(Debug, Clone)]
struct DockerInstances {
    cli: String,
    /// Whether `cli` drives Podman, probed once at construction (by engine,
    /// so the `podman-docker` shim counts) for the introspection summary.
    podman: bool,
    instance_id: String,
    /// Container-to-host networking: the host alias instances (and their IMDS
    /// proxy) reach fakecloud at, and the address fakecloud reaches published
    /// ports at.
    net: fakecloud_core::container_net::HostNetworking,
    /// fakecloud's bound port.
    server_port: u16,
    /// The IMDS / forwarder helper image (see [`imds`]), or its last failure.
    helper_image: Arc<tokio::sync::Mutex<Option<imds::HelperImage>>>,
    /// Live load balancer forwarders: `(instance, port)` -> the forwarder's
    /// container, published host port and the instance IP it targets.
    forwarders: Arc<parking_lot::Mutex<HashMap<(String, u16), Forwarder>>>,
    /// Per-`(instance, port)` locks serializing forwarder creation.
    forward_locks: Arc<parking_lot::Mutex<HashMap<(String, u16), ForwardLock>>>,
    /// Called when forwarders' security-group membership changes.
    forwarders_changed: Arc<ChangeHook>,
    /// Instance id -> its IMDS sidecar's container id, for sidecars whose
    /// load balancer map [`fakecloud_core::vpc_netns`] keeps current.
    vpc_sidecars: Arc<parking_lot::Mutex<HashMap<String, String>>>,
    /// The host engine socket mounted into instances tagged for it, resolved
    /// on first use (see [`instance_env`]).
    engine_socket: Arc<std::sync::OnceLock<String>>,
}

/// What one instance container is started with (Docker / Podman).
struct DockerLaunch<'a> {
    account_id: &'a str,
    instance_id: &'a str,
    image: &'a str,
    user_data: Option<&'a str>,
    tags: &'a BTreeMap<String, String>,
    network: Option<&'a InstanceNetwork>,
    region: &'a str,
    volumes: &'a [AttachedVolume],
}

/// Files an instance container gets before it starts.
struct InstanceFiles<'a> {
    /// The extra CA's PEM, for the trust bundle.
    extra_ca: Option<&'a str>,
    /// The sourceable AWS SDK environment.
    aws_env: Option<String>,
}

impl InstanceFiles<'_> {
    fn any(&self) -> bool {
        self.extra_ca.is_some() || self.aws_env.is_some()
    }
}

/// The daemon network backing a subnet.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SubnetBacking {
    name: String,
    /// Whether the network's range is the subnet's CIDR block, so instances
    /// can be given their EC2 private IPs on it.
    addressed: bool,
}

/// What became of a `network create`.
enum NetworkCreate {
    Created,
    Exists,
    Failed(String),
}

/// A forwarder publishing one instance port on the host (see [`imds`]).
#[derive(Debug, Clone)]
struct Forwarder {
    container: String,
    host_port: u16,
    target_ip: String,
    /// The forwarder's address on the instance's subnet network -- where the
    /// forwarded traffic comes from as the instance sees it.
    subnet_ip: Option<String>,
    /// Security groups of the load balancer(s) the forwarder carries traffic
    /// for (sorted).
    source_groups: Vec<String>,
}

/// Hook the control plane installs to re-render the firewall (set once).
#[derive(Default)]
struct ChangeHook(std::sync::OnceLock<HookFn>);

/// The hook itself: returns the re-render to await.
type HookFn =
    Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>;

impl std::fmt::Debug for ChangeHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangeHook")
            .field("set", &self.0.get().is_some())
            .finish()
    }
}

/// Serializes forwarder creation for one `(instance, port)`.
type ForwardLock = Arc<tokio::sync::Mutex<()>>;

/// The subnets of a `network inspect` document: Docker's `IPAM.Config[].Subnet`
/// and Podman's `subnets[].subnet`, in canonical form.
fn network_subnets(inspect: &serde_json::Value) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![inspect];
    while let Some(v) = stack.pop() {
        match v {
            serde_json::Value::Array(items) => stack.extend(items),
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    match v.as_str() {
                        Some(subnet) if k.eq_ignore_ascii_case("subnet") => {
                            if let Some(c) = vpc::Cidr::parse(subnet) {
                                found.push(c.canonical());
                            }
                        }
                        _ => stack.push(v),
                    }
                }
            }
            _ => {}
        }
    }
    found
}

/// `inspect` template printing a container's IP on network `name`.
fn network_ip_template(name: &str) -> String {
    format!("{{{{with index .NetworkSettings.Networks \"{name}\"}}}}{{{{.IPAddress}}}}{{{{end}}}}")
}

impl DockerInstances {
    async fn run_instance(
        &self,
        launch: &DockerLaunch<'_>,
    ) -> Result<RunningInstance, RuntimeError> {
        let instance_id = launch.instance_id;
        // Ensure the subnet's bridge exists and attach to it for L3 isolation.
        // Network creation is best-effort: on failure we fall back to the
        // default bridge so the instance still boots (no regression vs today).
        let backing = match launch.network {
            Some(net) => self.ensure_subnet_network(net).await,
            None => None,
        };
        // The instance's EC2 private IP, on a network that carries its
        // subnet's range (see `vpc`).
        let pinned_ip = launch
            .network
            .zip(backing.as_ref())
            .and_then(|(net, b)| vpc::pinned_ip(net, b.addressed));
        let vpc_dns = vpc::vpc_dns(launch.network);
        let extra_ca = instance_env::extra_ca();
        let aws_env = instance_env::aws_env(&self.net.host_alias, self.server_port, launch.region);
        let files = InstanceFiles {
            extra_ca: extra_ca.as_deref(),
            aws_env: aws_env.as_ref().map(instance_env::AwsEnv::file),
        };

        let mut args: Vec<String> = vec![
            "run".to_string(),
            "-d".to_string(),
            "--label".to_string(),
            format!("fakecloud-ec2={instance_id}"),
            "--label".to_string(),
            format!("fakecloud-instance={}", self.instance_id),
        ];
        // Optionally back the instance's writable data directory with a durable
        // named volume keyed on the data dir + account + instance id, so the
        // filesystem state an instance writes there survives a fakecloud
        // restart (the recovery path recreates the container, which reattaches
        // the same volume) and a stop/start (Docker reuses the same container,
        // so the volume persists regardless). Default-on in persistent storage
        // mode, off in memory mode, `FAKECLOUD_PERSIST_EC2_VOLUMES` overrides.
        // The volume is dropped on TerminateInstances. See
        // [`scoped_data_volume_name`] / [`instance_data_dir`].
        if ec2_volumes_enabled() {
            let volume = self
                .resolve_data_volume(launch.account_id, instance_id)
                .await?;
            fakecloud_core::data_volume::ensure_volume(
                &self.cli,
                &volume,
                fakecloud_core::data_volume::current_scope(),
                &[format!("fakecloud-ec2={instance_id}")],
            )
            .await;
            args.push("-v".to_string());
            args.push(format!("{volume}:{}", instance_data_dir()));
        }
        // Its attached EBS volumes, each at its device name.
        if ebs_mounts_enabled() {
            let scope = fakecloud_core::data_volume::current_scope();
            for attached in launch.volumes {
                let volume = ebs_volume_name(scope.tag(), launch.account_id, &attached.volume_id);
                fakecloud_core::data_volume::ensure_volume(
                    &self.cli,
                    &volume,
                    scope,
                    &[format!("fakecloud-ebs={}", attached.volume_id)],
                )
                .await;
                args.push("-v".to_string());
                args.push(format!("{volume}:{}", attached.device));
            }
        }
        // The subnet network and the instance's address on it, the host alias
        // (which resolves inside the instance and its IMDS sidecar, which
        // shares its /etc/hosts, so workloads can reach fakecloud), and the
        // VPC resolver.
        args.extend(vpc::instance_network_argv(
            backing.as_ref().map(|b| b.name.as_str()),
            pinned_ip,
            self.net.add_host_arg.as_deref(),
            &self.net.host_alias,
            vpc_dns.as_ref(),
        ));
        args.extend(imds::readiness_tmpfs_args());
        // IMDS answers at 169.254.169.254 through the sidecar; without a
        // helper image, point SDKs at fakecloud's per-instance IMDS instead.
        // Decided from what is already known, never by building the image
        // here (see `Ec2Runtime::spawn_imds`).
        if self.helper_known_failed() {
            let (k, v) =
                imds::metadata_endpoint_env(&self.net.host_alias, self.server_port, instance_id);
            args.push("-e".to_string());
            args.push(format!("{k}={v}"));
        }
        if let Some(env) = &aws_env {
            args.extend(env.args());
        }
        if extra_ca.is_some() {
            args.extend(instance_env::ssl_cert_file_env());
        }
        if instance_env::wants_host_engine(launch.tags) {
            args.extend(instance_env::engine_socket_mount(
                &self.host_engine_socket().await,
            ));
        }
        args.push(launch.image.to_string());
        args.extend(boot_command(launch.user_data));

        // `run` pulls a missing image itself but gives up on the first
        // throttled pull; make it available first, retrying transient
        // registry failures.
        fakecloud_core::container_image::ensure_image(&self.cli, None, launch.image)
            .await
            .map_err(RuntimeError::ContainerStartFailed)?;

        let mut started = self
            .start_instance_container(instance_id, &args, &files)
            .await;
        // The address is held by a container EC2 does not know about (one
        // that is still going away, or a forwarder the daemon gave it): the
        // instance takes an address the daemon picks instead, which is what
        // DescribeInstances then reports.
        if let (Err(error), Some(ip)) = (&started, pinned_ip) {
            if vpc::address_taken(error) {
                tracing::warn!(
                    instance = %instance_id,
                    %ip,
                    "the instance's private IP is held by another container; it gets another address in its subnet"
                );
                if let Some(at) = args.iter().position(|a| a == "--ip") {
                    args.drain(at..at + 2);
                }
                started = self
                    .start_instance_container(instance_id, &args, &files)
                    .await;
            }
        }
        let container_id = started.map_err(RuntimeError::ContainerStartFailed)?;
        let private_ip = self
            .inspect_ip(&container_id)
            .await
            .unwrap_or_else(|| "10.0.0.1".to_string());

        Ok(RunningInstance {
            container_id,
            private_ip,
            network: backing.map(|b| b.name),
        })
    }

    /// Start an instance container from its `run -d` argv and return its id.
    /// With `files` to put in it, it is created, given them (see
    /// [`instance_env`]), then started, so they are there before user-data
    /// runs. A container left created but not started is removed.
    async fn start_instance_container(
        &self,
        instance_id: &str,
        args: &[String],
        files: &InstanceFiles<'_>,
    ) -> Result<String, String> {
        let create = files
            .any()
            .then(|| fakecloud_core::ca_bundle::create_argv(args))
            .flatten();
        let Some(create) = create else {
            let out = tokio::process::Command::new(&self.cli)
                .args(args)
                .output()
                .await
                .map_err(|e| e.to_string())?;
            if out.status.success() {
                return Ok(String::from_utf8_lossy(&out.stdout).trim().to_string());
            }
            self.remove_unstarted(instance_id).await;
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        };
        let created = tokio::process::Command::new(&self.cli)
            .args(&create)
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if !created.status.success() {
            return Err(String::from_utf8_lossy(&created.stderr).trim().to_string());
        }
        let id = String::from_utf8_lossy(&created.stdout).trim().to_string();
        if let Some(ca) = files.extra_ca {
            if let Err(error) = fakecloud_core::ca_bundle::copy_into(
                &self.cli,
                &id,
                ca,
                instance_env::BUNDLE_DIR,
                CLI_TIMEOUT,
            )
            .await
            {
                tracing::warn!(instance = %instance_id, %error, "could not give the instance container its CA bundle");
            }
        }
        if let Some(env) = &files.aws_env {
            if let Err(error) = self
                .copy_file_into(
                    &id,
                    instance_env::AWS_ENV_DIR,
                    instance_env::AWS_ENV_FILE,
                    env,
                )
                .await
            {
                tracing::warn!(instance = %instance_id, %error, "could not write {} in the instance", instance_env::AWS_ENV_PATH);
            }
        }
        let out = tokio::process::Command::new(&self.cli)
            .args(["start", &id])
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            return Ok(id);
        }
        self.remove(&id).await;
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }

    /// Put `contents` in created container `id` as `<dir>/<name>`, readable
    /// by every user, creating `dir` when the image has none.
    async fn copy_file_into(
        &self,
        id: &str,
        dir: &str,
        name: &str,
        contents: &str,
    ) -> Result<(), String> {
        let staged = tempfile::tempdir().map_err(|e| format!("staging dir: {e}"))?;
        let staged_dir = staged.path().join("dir");
        std::fs::create_dir(&staged_dir).map_err(|e| format!("staging dir: {e}"))?;
        let file = staged_dir.join(name);
        std::fs::write(&file, contents).map_err(|e| format!("staging file: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&staged_dir, std::fs::Permissions::from_mode(0o755));
            let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644));
        }
        let out = fakecloud_core::container_net::output_within(
            tokio::process::Command::new(&self.cli)
                .arg("cp")
                // `<dir>/.`: the directory's contents, into `dir` whether or
                // not the image already has it.
                .arg(staged_dir.join("."))
                .arg(format!("{id}:{dir}")),
            CLI_TIMEOUT,
        )
        .await
        .map_err(|e| format!("{} cp {e}", self.cli))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    /// Remove an instance's containers that were created but never started
    /// (a `run` whose start failed leaves one behind).
    async fn remove_unstarted(&self, instance_id: &str) {
        let ps = tokio::process::Command::new(&self.cli)
            .args([
                "ps",
                "-aq",
                "--filter",
                &format!("label=fakecloud-ec2={instance_id}"),
                "--filter",
                "status=created",
            ])
            .output()
            .await;
        if let Ok(out) = ps {
            for id in String::from_utf8_lossy(&out.stdout).split_whitespace() {
                self.remove(id).await;
            }
        }
    }

    /// The host engine socket for instances tagged for it, resolved once.
    async fn host_engine_socket(&self) -> String {
        if let Some(socket) = self.engine_socket.get() {
            return socket.clone();
        }
        let (cli, podman) = (self.cli.clone(), self.podman);
        let socket =
            tokio::task::spawn_blocking(move || instance_env::host_engine_socket(&cli, podman))
                .await
                .unwrap_or_else(|_| "/var/run/docker.sock".to_string());
        self.engine_socket.get_or_init(|| socket).clone()
    }

    /// The helper image for IMDS sidecars and forwarders: the operator's
    /// override, or a locally built Alpine + nftables + nginx + socat image
    /// (built once per host and reused). `None` when it can't be had; a failure
    /// is remembered for [`imds::HELPER_RETRY_AFTER`].
    async fn ensure_helper_image(&self) -> Option<String> {
        let mut cached = self.helper_image.lock().await;
        match cached.as_ref() {
            Some(imds::HelperImage::Ready(image)) if self.image_present(image).await => {
                return Some(image.clone());
            }
            Some(imds::HelperImage::Failed { at, .. })
                if at.elapsed() < imds::HELPER_RETRY_AFTER =>
            {
                return None;
            }
            _ => {}
        }
        let resolved = match imds::helper_image_override() {
            Some(image) => fakecloud_core::container_image::ensure_image(&self.cli, None, &image)
                .await
                .map(|_| image),
            None => {
                let tag = imds::local_helper_tag();
                if self.image_present(&tag).await {
                    Ok(tag)
                } else {
                    self.build_local_helper(&tag).await.map(|()| tag)
                }
            }
        };
        *cached = Some(match &resolved {
            Ok(image) => imds::HelperImage::Ready(image.clone()),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "EC2 helper image unavailable; instances get AWS_EC2_METADATA_SERVICE_ENDPOINT \
                     instead of 169.254.169.254, and load balancers cannot reach instance ports"
                );
                imds::HelperImage::Failed {
                    at: std::time::Instant::now(),
                }
            }
        });
        resolved.ok()
    }

    /// Whether resolving the helper image failed recently, without waiting:
    /// a resolution in progress, or none yet, counts as "not failed".
    fn helper_known_failed(&self) -> bool {
        self.helper_image.try_lock().is_ok_and(|cached| {
            matches!(
                cached.as_ref(),
                Some(imds::HelperImage::Failed { at }) if at.elapsed() < imds::HELPER_RETRY_AFTER
            )
        })
    }

    async fn image_present(&self, tag: &str) -> bool {
        tokio::process::Command::new(&self.cli)
            .args(["image", "inspect", tag])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .is_ok_and(|s| s.success())
    }

    async fn build_local_helper(&self, tag: &str) -> Result<(), String> {
        // Pull the base with the shared retry so a registry 429 doesn't fail
        // the build's implicit pull.
        fakecloud_core::container_image::ensure_image(&self.cli, None, imds::HELPER_BASE_IMAGE)
            .await?;
        let dir = tempfile::tempdir().map_err(|e| format!("helper build dir: {e}"))?;
        std::fs::write(dir.path().join("Dockerfile"), imds::helper_dockerfile())
            .map_err(|e| format!("helper Dockerfile: {e}"))?;
        let mut last_err = String::new();
        for attempt in 0..3u64 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(2 * attempt)).await;
            }
            let out = tokio::process::Command::new(&self.cli)
                .args(["build", "-q", "-t", tag])
                .arg(dir.path())
                .output()
                .await
                .map_err(|e| format!("{} build: {e}", self.cli))?;
            if out.status.success() {
                tracing::info!(image = %tag, "built EC2 helper image");
                return Ok(());
            }
            last_err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        }
        Err(format!("building {tag}: {last_err}"))
    }

    /// Give a running instance container IMDS at `169.254.169.254` (and,
    /// with `vpc_dns`, its VPC's DNS server and load balancer routes): start
    /// its sidecar, wait for the rules, then release the boot (user-data
    /// waits on [`imds::READY_FILE`]). Best-effort: on failure the boot is
    /// released anyway and the instance runs without link-local IMDS.
    ///
    /// `still_current` says whether the instance is still this running
    /// container.
    async fn start_imds(
        &self,
        instance_id: &str,
        container_id: &str,
        vpc_dns: Option<&fakecloud_core::vpc_netns::VpcDns>,
        still_current: impl Fn() -> bool,
    ) {
        let Some(helper) = self.ensure_helper_image().await else {
            self.mark_boot_ready(container_id).await;
            return;
        };
        if !still_current() {
            return;
        }
        let name = imds::sidecar_name(instance_id);
        let _ = tokio::process::Command::new(&self.cli)
            .args(["rm", "-f", &name])
            .output()
            .await;
        let argv = imds::sidecar_argv(
            instance_id,
            container_id,
            &self.instance_id,
            &helper,
            &self.net.host_alias,
            self.server_port,
            vpc_dns,
        );
        let result = match tokio::process::Command::new(&self.cli)
            .args(&argv)
            .output()
            .await
        {
            Ok(out) if out.status.success() => {
                let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
                self.wait_for_sidecar(&id).await.map(|()| id)
            }
            Ok(out) => Err(String::from_utf8_lossy(&out.stderr).trim().to_string()),
            Err(e) => Err(e.to_string()),
        };
        if result.is_ok() && !still_current() {
            // Stopped / terminated while the sidecar came up.
            let _ = tokio::process::Command::new(&self.cli)
                .args(["rm", "-f", &name])
                .output()
                .await;
            return;
        }
        // Load balancer addresses route before user-data runs, and follow
        // load balancers created later.
        if let (Ok(sidecar), Some(_)) = (&result, vpc_dns) {
            fakecloud_core::vpc_netns::attach(
                &self.cli,
                sidecar,
                &self.net.host_alias,
                imds::NFT_TABLE,
            )
            .await;
            let replaced = self
                .vpc_sidecars
                .lock()
                .insert(instance_id.to_string(), sidecar.clone());
            fakecloud_core::vpc_netns::detach(replaced.as_slice());
            if !still_current() {
                // Stopped / terminated while the map was filled: its teardown
                // may have looked for the sidecar before it was recorded.
                self.remove_vpc_sidecar(instance_id);
                let _ = tokio::process::Command::new(&self.cli)
                    .args(["rm", "-f", &name])
                    .output()
                    .await;
                return;
            }
        }
        if let Err(error) = result {
            tracing::warn!(
                instance = %instance_id,
                error = %error,
                "could not route 169.254.169.254 to fakecloud IMDS inside the instance"
            );
            let _ = tokio::process::Command::new(&self.cli)
                .args(["rm", "-f", &name])
                .output()
                .await;
        }
        self.mark_boot_ready(container_id).await;
    }

    async fn wait_for_sidecar(&self, id: &str) -> Result<(), String> {
        let deadline = std::time::Instant::now() + imds::SIDECAR_READY_TIMEOUT;
        let mut poll = std::time::Duration::from_millis(100);
        loop {
            let logs = tokio::process::Command::new(&self.cli)
                .args(["logs", id])
                .output()
                .await
                .map_err(|e| e.to_string())?;
            let stdout = String::from_utf8_lossy(&logs.stdout);
            if stdout.contains(imds::READY_MARKER) {
                return Ok(());
            }
            let running = tokio::process::Command::new(&self.cli)
                .args(["inspect", "-f", "{{.State.Running}}", id])
                .output()
                .await
                .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
                .unwrap_or(false);
            if !running {
                return Err(format!(
                    "IMDS sidecar exited during setup; stderr: {:?}",
                    String::from_utf8_lossy(&logs.stderr).trim()
                ));
            }
            if std::time::Instant::now() >= deadline {
                return Err("IMDS sidecar did not become ready in time".into());
            }
            tokio::time::sleep(poll).await;
            poll = (poll * 2).min(std::time::Duration::from_secs(1));
        }
    }

    /// Release a boot waiting on IMDS (see [`boot_command`]).
    async fn mark_boot_ready(&self, container_id: &str) {
        let script = format!("mkdir -p {} && : > {}", imds::READY_DIR, imds::READY_FILE);
        let _ = tokio::process::Command::new(&self.cli)
            .args(["exec", container_id, "sh", "-c", &script])
            .output()
            .await;
    }

    /// Stop keeping the load balancer map of an instance's sidecar.
    fn remove_vpc_sidecar(&self, instance_id: &str) {
        let tracked = self.vpc_sidecars.lock().remove(instance_id);
        fakecloud_core::vpc_netns::detach(tracked.as_slice());
    }

    /// Remove an instance's IMDS sidecar and load balancer forwarders --
    /// tracked ones, and any a concurrent [`Self::forward`] is still starting
    /// (found by label).
    async fn remove_sidecars(&self, instance_id: &str) {
        self.remove_vpc_sidecar(instance_id);
        let mut names = vec![imds::sidecar_name(instance_id)];
        self.forward_locks
            .lock()
            .retain(|(id, _), l| id != instance_id || Arc::strong_count(l) > 1);
        let had_forwarders = {
            let mut fwd = self.forwarders.lock();
            let before = fwd.len();
            fwd.retain(|(id, _), f| {
                if id == instance_id {
                    names.push(f.container.clone());
                    false
                } else {
                    true
                }
            });
            before != fwd.len()
        };
        let ps = tokio::time::timeout(
            fakecloud_core::container_net::CLI_PROBE_TIMEOUT,
            tokio::process::Command::new(&self.cli)
                .args([
                    "ps",
                    "-aq",
                    "--filter",
                    &format!("label=fakecloud-ec2-fwd={instance_id}"),
                ])
                .kill_on_drop(true)
                .output(),
        )
        .await;
        if let Ok(Ok(out)) = ps {
            if out.status.success() {
                names.extend(
                    String::from_utf8_lossy(&out.stdout)
                        .split_whitespace()
                        .map(str::to_string),
                );
            }
        }
        for name in names {
            let _ = tokio::process::Command::new(&self.cli)
                .args(["rm", "-f", &name])
                .output()
                .await;
        }
        if had_forwarders {
            self.forwarders_changed().await;
        }
    }

    /// Tell the control plane the forwarders' security-group membership
    /// changed and wait for the firewall to be re-rendered with them.
    async fn forwarders_changed(&self) {
        let hook = self.forwarders_changed.0.get().cloned();
        if let Some(hook) = hook {
            hook().await;
        }
    }

    /// `(security group, forwarder IP on its subnet network)` for every live
    /// forwarder: a forwarder carries the load balancer's traffic, so it is a
    /// member of the load balancer's security groups when an instance's rules
    /// reference them.
    fn forwarder_group_members(&self) -> Vec<(String, String)> {
        self.forwarders
            .lock()
            .values()
            .filter_map(|f| f.subnet_ip.as_ref().map(|ip| (ip, &f.source_groups)))
            .flat_map(|(ip, groups)| groups.iter().map(move |g| (g.clone(), ip.clone())))
            .collect()
    }

    /// The host endpoint serving `port` of a running instance at
    /// `instance_ip`, starting a forwarder for it on first use (or when the
    /// instance's IP changed). Serialized per `(instance, port)`, so
    /// concurrent callers (the data plane and the health prober) never race
    /// to create the same forwarder.
    ///
    /// `current_ip` reads the instance's address as it is now: checked under
    /// the lock once the forwarder is up, so a stop / reboot that landed
    /// meanwhile drops this forwarder (and never a newer one).
    async fn forward(
        &self,
        instance_id: &str,
        instance_ip: &str,
        network: Option<&InstanceNetwork>,
        port: u16,
        source_groups: Vec<String>,
        current_ip: impl Fn() -> Option<String>,
    ) -> Option<fakecloud_core::dataplane::Endpoint> {
        let key = (instance_id.to_string(), port);
        let lock = self
            .forward_locks
            .lock()
            .entry(key.clone())
            .or_default()
            .clone();
        let _serial = lock.lock().await;
        let mut source_groups = source_groups;
        source_groups.sort();
        source_groups.dedup();
        let cached = self.forwarders.lock().get(&key).cloned();
        if let Some(f) = cached {
            if f.target_ip == instance_ip {
                // Several load balancers can share a target: the forwarder
                // stands in for all of them, so their groups accumulate.
                let grew = self.forwarders.lock().get_mut(&key).is_some_and(|entry| {
                    let before = entry.source_groups.len();
                    entry.source_groups.extend(source_groups);
                    entry.source_groups.sort();
                    entry.source_groups.dedup();
                    entry.source_groups.len() != before
                });
                if grew && f.subnet_ip.is_some() {
                    self.forwarders_changed().await;
                }
                return Some(fakecloud_core::dataplane::Endpoint::new(
                    self.net.sibling_host.clone(),
                    f.host_port,
                ));
            }
        }
        let helper = self.ensure_helper_image().await?;
        let name = imds::forwarder_name(instance_id, port);
        let _ = tokio::process::Command::new(&self.cli)
            .args(["rm", "-f", &name])
            .output()
            .await;
        let argv = imds::forwarder_argv(instance_id, port, instance_ip, &self.instance_id, &helper);
        let out = tokio::process::Command::new(&self.cli)
            .args(&argv)
            .output()
            .await
            .ok()?;
        if !out.status.success() {
            tracing::warn!(
                instance = %instance_id,
                port,
                error = %String::from_utf8_lossy(&out.stderr).trim(),
                "could not start a load balancer forwarder for the instance"
            );
            return None;
        }
        let container = String::from_utf8_lossy(&out.stdout).trim().to_string();
        // Reach the instance over its subnet network (the forwarder sits on
        // the default bridge so its port can be published), and learn the
        // address its traffic arrives from there.
        let mut subnet_ip = None;
        if let Some(net) = network {
            let net_name = subnet_network_name(&net.subnet_id);
            let _ = tokio::process::Command::new(&self.cli)
                .args(["network", "connect", &net_name, &container])
                .output()
                .await;
            subnet_ip = tokio::process::Command::new(&self.cli)
                .args(["inspect", "-f", &network_ip_template(&net_name), &container])
                .output()
                .await
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|ip| !ip.is_empty() && ip != "<no value>");
        }
        let spec = format!("{port}/tcp");
        let host_port = tokio::process::Command::new(&self.cli)
            .args(["port", &container, &spec])
            .output()
            .await
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| {
                fakecloud_core::container_net::parse_published_port(&String::from_utf8_lossy(
                    &o.stdout,
                ))
            });
        let Some(host_port) = host_port else {
            let _ = tokio::process::Command::new(&self.cli)
                .args(["rm", "-f", &container])
                .output()
                .await;
            return None;
        };
        // A stop / reboot landed while the forwarder was starting: it
        // targets an address the instance no longer has.
        if current_ip().as_deref() != Some(instance_ip) {
            let _ = tokio::process::Command::new(&self.cli)
                .args(["rm", "-f", &container])
                .output()
                .await;
            return None;
        }
        let has_groups = !source_groups.is_empty() && subnet_ip.is_some();
        self.forwarders.lock().insert(
            key,
            Forwarder {
                container,
                host_port,
                target_ip: instance_ip.to_string(),
                subnet_ip,
                source_groups,
            },
        );
        // With security groups enforced, the first request must not race
        // the rule admitting the forwarder.
        if has_groups {
            self.forwarders_changed().await;
        }
        Some(fakecloud_core::dataplane::Endpoint::new(
            self.net.sibling_host.clone(),
            host_port,
        ))
    }

    /// Create (idempotently) the daemon network backing a subnet, or `None`
    /// if that failed (caller falls back to the default bridge). The network
    /// carries the shared `fakecloud-instance` ownership label so the startup
    /// reaper prunes it after an ungraceful restart, plus a
    /// `fakecloud-subnet=<id>` label for introspection. Its range is the
    /// subnet's CIDR block when the daemon allows it (see [`vpc`]).
    async fn ensure_subnet_network(&self, net: &InstanceNetwork) -> Option<SubnetBacking> {
        let name = subnet_network_name(&net.subnet_id);
        let isolate = vpc::isolate_private_subnets();
        let cidr = vpc::subnet_cidr(net);
        if cidr.is_some() {
            let argv = vpc::network_create_argv(&name, net, &self.instance_id, true, isolate);
            match self.create_network(&argv).await {
                NetworkCreate::Created => {
                    return Some(SubnetBacking {
                        name,
                        addressed: true,
                    })
                }
                // Another instance in the subnet created it, or an earlier
                // run did without the range.
                NetworkCreate::Exists => {
                    let addressed = self.network_has_range(&name, cidr.as_ref()).await;
                    return Some(SubnetBacking { name, addressed });
                }
                NetworkCreate::Failed(error) => tracing::warn!(
                    subnet = %net.subnet_id,
                    network = %name,
                    %error,
                    "the subnet's network cannot have the subnet's CIDR block (another network \
                     overlaps it?); its instances get addresses the engine picks"
                ),
            }
        }
        let argv = vpc::network_create_argv(&name, net, &self.instance_id, false, isolate);
        match self.create_network(&argv).await {
            NetworkCreate::Created => Some(SubnetBacking {
                name,
                addressed: false,
            }),
            NetworkCreate::Exists => {
                let addressed = self.network_has_range(&name, cidr.as_ref()).await;
                Some(SubnetBacking { name, addressed })
            }
            NetworkCreate::Failed(error) => {
                tracing::warn!(
                    subnet = %net.subnet_id,
                    network = %name,
                    %error,
                    "subnet network creation failed; falling back to default bridge"
                );
                None
            }
        }
    }

    async fn create_network(&self, argv: &[String]) -> NetworkCreate {
        match tokio::process::Command::new(&self.cli)
            .args(argv)
            .output()
            .await
        {
            Ok(out) if out.status.success() => NetworkCreate::Created,
            Ok(out) => {
                let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
                if vpc::already_exists(&err) {
                    NetworkCreate::Exists
                } else {
                    NetworkCreate::Failed(err)
                }
            }
            Err(e) => NetworkCreate::Failed(e.to_string()),
        }
    }

    /// Whether existing network `name`'s range is `cidr`.
    async fn network_has_range(&self, name: &str, cidr: Option<&vpc::Cidr>) -> bool {
        let Some(cidr) = cidr else {
            return false;
        };
        let out = tokio::process::Command::new(&self.cli)
            .args(["network", "inspect", name])
            .output()
            .await;
        out.ok()
            .filter(|o| o.status.success())
            .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok())
            .is_some_and(|v| network_subnets(&v).contains(&cidr.canonical()))
    }

    /// Read the container's private IP from `inspect`. Returns `None` if the
    /// container has no address (e.g. host networking) — the caller falls
    /// back to a synthesized IP.
    async fn inspect_ip(&self, container_id: &str) -> Option<String> {
        let output = tokio::process::Command::new(&self.cli)
            .args([
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                container_id,
            ])
            .output()
            .await
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if ip.is_empty() {
            None
        } else {
            Some(ip)
        }
    }

    async fn stop(&self, container_id: &str) {
        let _ = tokio::process::Command::new(&self.cli)
            .args(["stop", container_id])
            .output()
            .await;
    }

    async fn start(&self, container_id: &str) -> Option<String> {
        let started = tokio::process::Command::new(&self.cli)
            .args(["start", container_id])
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !started {
            return None;
        }
        self.inspect_ip(container_id).await
    }

    async fn reboot(&self, container_id: &str) {
        let _ = tokio::process::Command::new(&self.cli)
            .args(["restart", container_id])
            .output()
            .await;
    }

    async fn remove(&self, container_id: &str) {
        let _ = tokio::process::Command::new(&self.cli)
            .args(["rm", "-f", container_id])
            .output()
            .await;
    }

    /// Remove the durable data volume for an instance (called on
    /// `TerminateInstances`) so a later instance reusing the same id starts
    /// clean rather than inheriting the terminated instance's filesystem. A
    /// no-op when volume persistence is disabled (no such volume was created).
    async fn remove_data_volume(&self, account_id: &str, instance_id: &str) {
        if !ec2_volumes_enabled() {
            return;
        }
        // Instance ids are random, so a legacy volume named after this id can
        // only be this instance's own (adopted by `resolve_data_volume`).
        for name in [
            scoped_data_volume_name(
                fakecloud_core::data_volume::current_scope().tag(),
                account_id,
                instance_id,
            ),
            legacy_data_volume_name(account_id, instance_id),
        ] {
            fakecloud_core::data_volume::remove_volume(&self.cli, &name).await;
        }
    }

    /// The data volume an instance mounts. Instance ids are random, so the
    /// unscoped name a build before data-dir scoping gave this instance can
    /// only belong to it: an instance restored from such a data dir keeps
    /// that legacy volume, unless its scoped one already exists. Fails when
    /// the daemon can't list its volumes: guessing "absent" would mount an
    /// empty scoped volume that from then on shadows the legacy data.
    async fn resolve_data_volume(
        &self,
        account_id: &str,
        instance_id: &str,
    ) -> Result<String, RuntimeError> {
        let scoped = scoped_data_volume_name(
            fakecloud_core::data_volume::current_scope().tag(),
            account_id,
            instance_id,
        );
        let legacy = legacy_data_volume_name(account_id, instance_id);
        let existing = fakecloud_core::data_volume::list_volumes(&self.cli)
            .await
            .ok_or_else(|| {
                RuntimeError::ContainerStartFailed(
                    "could not list container volumes to find the instance's data volume"
                        .to_string(),
                )
            })?;
        let scoped_exists = existing.contains(&scoped);
        let legacy_exists = existing.contains(&legacy);
        Ok(choose_data_volume(
            scoped,
            legacy,
            scoped_exists,
            legacy_exists,
        ))
    }

    /// The container's combined stdout+stderr (`docker logs`). `None` if the
    /// command fails; an empty log is `Some(vec![])`.
    async fn logs(&self, container_id: &str) -> Option<Vec<u8>> {
        let output = tokio::process::Command::new(&self.cli)
            .args(["logs", container_id])
            .output()
            .await
            .ok()?;
        if !output.status.success() {
            return None;
        }
        // `docker logs` writes the container's stdout to ours and its stderr to
        // ours; concatenate so the console output carries both streams.
        let mut buf = output.stdout;
        buf.extend_from_slice(&output.stderr);
        Some(buf)
    }
}

#[cfg(test)]
mod volume_tests {
    use super::*;

    #[test]
    fn data_volume_name_is_scoped_stable_and_sanitized() {
        assert_eq!(
            scoped_data_volume_name("d0123456789ab", "123456789012", "i-0abc123"),
            "fakecloud-ec2-data-d0123456789ab-123456789012-i-0abc123"
        );
        // Two data dirs never share a volume.
        assert_ne!(
            scoped_data_volume_name("d0123456789ab", "123456789012", "i-0abc123"),
            scoped_data_volume_name("dba9876543210", "123456789012", "i-0abc123")
        );
        // Characters outside Docker's volume-name set become '-'.
        assert_eq!(
            scoped_data_volume_name("d0", "1234/5678", "i-0abc:1"),
            "fakecloud-ec2-data-d0-1234-5678-i-0abc-1"
        );
        // The legacy name is exactly what pre-scoping builds created.
        assert_eq!(
            legacy_data_volume_name("123456789012", "i-0abc123"),
            "fakecloud-ec2-data-123456789012-i-0abc123"
        );
    }

    #[test]
    fn distinct_instances_get_distinct_volumes() {
        // Two instances in the same account never share a data volume, so
        // terminating one cannot wipe another's filesystem.
        assert_ne!(
            scoped_data_volume_name("d0", "123456789012", "i-aaaa"),
            scoped_data_volume_name("d0", "123456789012", "i-bbbb")
        );
    }

    #[test]
    fn legacy_volume_kept_only_until_a_scoped_one_exists() {
        let pick = |s, l| choose_data_volume("scoped".into(), "legacy".into(), s, l);
        // Fresh instance: a new scoped volume.
        assert_eq!(pick(false, false), "scoped");
        // Instance restored from a pre-scoping data dir: keep its data.
        assert_eq!(pick(false, true), "legacy");
        // The scoped volume always wins once it exists.
        assert_eq!(pick(true, false), "scoped");
        assert_eq!(pick(true, true), "scoped");
    }
}

#[cfg(test)]
mod reachability_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A Docker-backend runtime driving `cli` (a fake CLI script).
    fn runtime_with_cli(cli: &str) -> Ec2Runtime {
        Ec2Runtime {
            backend: InstanceBackend::Docker(DockerInstances {
                cli: cli.to_string(),
                podman: false,
                instance_id: "fakecloud-test".into(),
                net: fakecloud_core::container_net::HostNetworking {
                    host_alias: "host.docker.internal".into(),
                    add_host_arg: None,
                    sibling_host: "127.0.0.1".into(),
                },
                server_port: 4566,
                helper_image: Arc::new(tokio::sync::Mutex::new(None)),
                forwarders: Arc::new(parking_lot::Mutex::new(HashMap::new())),
                forward_locks: Arc::new(parking_lot::Mutex::new(HashMap::new())),
                forwarders_changed: Arc::new(ChangeHook::default()),
                vpc_sidecars: Arc::new(parking_lot::Mutex::new(HashMap::new())),
                engine_socket: Arc::new(std::sync::OnceLock::new()),
            }),
            instances: Arc::new(RwLock::new(HashMap::new())),
            firewall: FirewallEnforcer::disabled(),
            reconcile_lock: Arc::new(tokio::sync::Mutex::new(())),
            lifecycle_locks: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        }
    }

    fn record(ip: &str, network: Option<InstanceNetwork>) -> InstanceRecord {
        InstanceRecord {
            handle: "cid-instance".into(),
            image: "busybox".into(),
            user_data: None,
            tags: BTreeMap::new(),
            network,
            private_ip: ip.into(),
            running: true,
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
            volumes: Vec::new(),
            remount: false,
        }
    }

    /// A fake container CLI logging every call. `run` answers with a
    /// container id after a short delay (so concurrent callers overlap),
    /// `port` with a published port, `inspect` with a subnet address, and
    /// everything else succeeds.
    fn fake_cli(dir: &std::path::Path) -> (String, std::path::PathBuf) {
        let log = dir.join("calls");
        let script = dir.join("fakecli");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\necho \"$*\" >> {log}\ncase \"$1\" in\n  run) sleep 0.3; echo cid-fwd ;;\n  port) echo 0.0.0.0:49999 ;;\n  inspect) echo 172.30.0.9 ;;\n  ps) ;;\nesac\nexit 0\n",
                log = log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        wait_executable(&script);
        (script.display().to_string(), log)
    }

    /// Wait until a freshly written script can be exec'd. Another test
    /// thread forking while the script was open for writing leaves its child
    /// holding the write fd until that child execs, and exec meanwhile fails
    /// with `ETXTBSY`; the runtime would read that as a failed CLI call.
    fn wait_executable(script: &std::path::Path) {
        for _ in 0..200 {
            match std::process::Command::new(script).arg("noop").output() {
                Err(e) if e.raw_os_error() == Some(libc_etxtbsy()) => {
                    std::thread::sleep(std::time::Duration::from_millis(5))
                }
                _ => return,
            }
        }
    }

    fn libc_etxtbsy() -> i32 {
        26 // ETXTBSY on Linux and macOS
    }

    fn calls(log: &std::path::Path, verb: &str) -> usize {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .filter(|l| l.starts_with(&format!("{verb} ")))
            .count()
    }

    /// The instance container runs of `log`: those of image `busybox`, which
    /// the sidecars and forwarders don't run.
    fn instance_runs(log: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .filter(|l| l.starts_with("run ") && l.contains(" busybox "))
            .map(str::to_string)
            .collect()
    }

    #[tokio::test]
    async fn attached_volumes_are_mounted_by_recreating_the_container() {
        std::env::set_var("FAKECLOUD_EC2_MOUNT_VOLUMES", "1");
        let dir = tempfile::tempdir().unwrap();
        let (cli, log) = fake_cli(dir.path());
        let rt = runtime_with_cli(&cli);
        rt.instances
            .write()
            .insert("i-vol".into(), record("172.30.0.5", None));
        let sdf = vec![AttachedVolume {
            volume_id: "vol-1".into(),
            device: "/dev/sdf".into(),
        }];

        // Running: its container goes and one mounting the volume at its
        // device takes its place.
        let running = rt
            .set_volumes("i-vol", sdf.clone())
            .await
            .expect("recreated");
        let calls = std::fs::read_to_string(&log).unwrap();
        assert!(calls.contains("rm -f cid-instance"), "{calls}");
        let runs = instance_runs(&log);
        assert_eq!(runs.len(), 1, "{calls}");
        assert!(
            runs[0].contains("-123456789012-vol-1:/dev/sdf "),
            "{}",
            runs[0]
        );
        assert_eq!(rt.instances.read()["i-vol"].handle, running.container_id);

        // The same volumes again: nothing to do.
        assert!(rt.set_volumes("i-vol", sdf).await.is_none());
        assert_eq!(instance_runs(&log).len(), 1);

        // Stopped: the change waits for the next start, which recreates it
        // without the volume.
        rt.stop_instance("i-vol").await;
        assert!(rt.set_volumes("i-vol", Vec::new()).await.is_none());
        assert!(rt.instances.read()["i-vol"].remount);
        assert_eq!(instance_runs(&log).len(), 1);
        rt.start_instance("i-vol").await.expect("started");
        let runs = instance_runs(&log);
        assert_eq!(runs.len(), 2);
        assert!(!runs[1].contains("vol-1"), "{}", runs[1]);
        assert!(!rt.instances.read()["i-vol"].remount);
    }

    #[tokio::test]
    async fn concurrent_resolves_start_one_forwarder() {
        let dir = tempfile::tempdir().unwrap();
        let (cli, log) = fake_cli(dir.path());
        let rt = runtime_with_cli(&cli);
        rt.instances
            .write()
            .insert("i-abc".into(), record("172.30.0.5", None));
        let resolver = rt.endpoint_resolver();
        let (a, b) = tokio::join!(
            resolver.resolve("123456789012", "i-abc", 8080, Vec::new()),
            resolver.resolve("123456789012", "i-abc", 8080, Vec::new()),
        );
        let want = fakecloud_core::dataplane::Endpoint::new("127.0.0.1", 49999);
        assert_eq!(a.as_ref(), Some(&want));
        assert_eq!(b.as_ref(), Some(&want));
        // The data plane and the prober racing must not both rm/run the
        // same forwarder name.
        assert_eq!(calls(&log, "run"), 1, "{:?}", std::fs::read_to_string(&log));
    }

    #[tokio::test]
    async fn stopped_instance_is_never_forwarded_to() {
        let dir = tempfile::tempdir().unwrap();
        let (cli, log) = fake_cli(dir.path());
        let rt = runtime_with_cli(&cli);
        // A stopped instance's address is cleared: the daemon may already
        // have handed its old IP to another container.
        let mut stopped = record("172.30.0.4", None);
        stopped.running = false;
        rt.instances.write().insert("i-stopped".into(), stopped);
        let ep = rt
            .endpoint_resolver()
            .resolve("123456789012", "i-stopped", 80, Vec::new())
            .await;
        assert_eq!(ep, None);
        assert_eq!(calls(&log, "run"), 0);
        // Stopping a running instance clears its address before anything
        // else, and drops its forwarders.
        rt.instances
            .write()
            .insert("i-run".into(), record("172.30.0.6", None));
        assert!(rt
            .endpoint_resolver()
            .resolve("123456789012", "i-run", 80, Vec::new())
            .await
            .is_some());
        rt.stop_instance("i-run").await;
        assert_eq!(rt.instances.read()["i-run"].private_ip, "");
        assert!(rt.extra_group_members().is_empty());
        assert!(rt
            .endpoint_resolver()
            .resolve("123456789012", "i-run", 80, Vec::new())
            .await
            .is_none());
    }

    #[tokio::test]
    async fn forwarders_stand_in_for_the_load_balancer_security_groups() {
        let dir = tempfile::tempdir().unwrap();
        let (cli, _log) = fake_cli(dir.path());
        let rt = runtime_with_cli(&cli);
        let changed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = changed.clone();
        rt.set_group_members_hook(move || {
            let c = c.clone();
            Box::pin(async move {
                // The re-render takes a while; the endpoint must not be
                // handed out before it lands.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        });
        rt.instances.write().insert(
            "i-sg".into(),
            record(
                "172.30.0.7",
                Some(InstanceNetwork {
                    subnet_id: "subnet-1".into(),
                    ..InstanceNetwork::default()
                }),
            ),
        );
        rt.endpoint_resolver()
            .resolve(
                "123456789012",
                "i-sg",
                80,
                vec!["sg-alb".into(), "sg-alb".into()],
            )
            .await
            .expect("forwarded");
        // The forwarder's subnet address joins the load balancer's group, and
        // the firewall re-render finished before the endpoint was returned.
        assert_eq!(
            rt.extra_group_members(),
            vec![("sg-alb".to_string(), "172.30.0.9".to_string())]
        );
        assert_eq!(changed.load(std::sync::atomic::Ordering::SeqCst), 1);

        // A second load balancer sharing the target adds its group; the
        // first's stays (no flip-flop), and a repeat changes nothing.
        let resolver = rt.endpoint_resolver();
        resolver
            .resolve("123456789012", "i-sg", 80, vec!["sg-nlb".into()])
            .await
            .expect("forwarded");
        let mut members = rt.extra_group_members();
        members.sort();
        assert_eq!(
            members,
            vec![
                ("sg-alb".to_string(), "172.30.0.9".to_string()),
                ("sg-nlb".to_string(), "172.30.0.9".to_string()),
            ]
        );
        assert_eq!(changed.load(std::sync::atomic::Ordering::SeqCst), 2);
        for _ in 0..3 {
            resolver
                .resolve("123456789012", "i-sg", 80, vec!["sg-alb".into()])
                .await
                .expect("forwarded");
        }
        assert_eq!(changed.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn running_instance_with_unknown_address_is_reinspected() {
        // A reboot whose inspect failed leaves the address unknown; the next
        // resolve reads it again instead of leaving the instance unreachable.
        let dir = tempfile::tempdir().unwrap();
        let (cli, log) = fake_cli(dir.path());
        let rt = runtime_with_cli(&cli);
        rt.instances
            .write()
            .insert("i-reboot".into(), record("", None));
        let ep = rt
            .endpoint_resolver()
            .resolve("123456789012", "i-reboot", 80, Vec::new())
            .await;
        assert!(ep.is_some());
        assert_eq!(rt.instances.read()["i-reboot"].private_ip, "172.30.0.9");
        assert!(std::fs::read_to_string(&log)
            .unwrap()
            .contains("run -d --name fakecloud-ec2-fwd-i-reboot-80"));
    }

    #[tokio::test]
    async fn stop_during_forwarder_start_drops_only_that_forwarder() {
        let dir = tempfile::tempdir().unwrap();
        let (cli, _log) = fake_cli(dir.path());
        let rt = runtime_with_cli(&cli);
        rt.instances
            .write()
            .insert("i-race".into(), record("172.30.0.8", None));
        let resolver = rt.endpoint_resolver();
        let pending = tokio::spawn(async move {
            resolver
                .resolve("123456789012", "i-race", 80, Vec::new())
                .await
        });
        // The fake `run` takes 300ms; stop lands while it is in flight.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        rt.stop_instance("i-race").await;
        assert_eq!(pending.await.unwrap(), None);
        assert!(rt.with_docker(|d| d.forwarders.lock().is_empty()).unwrap());
    }

    #[tokio::test]
    async fn boot_does_not_wait_on_the_imds_helper() {
        // The helper image build and sidecar setup are slow (tens of seconds
        // on a cold CI runner). They must not run inside `run_instance`,
        // whose caller holds the instance's lifecycle lock -- a reset or
        // terminate right after RunInstances waits on that lock.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("calls");
        let script = dir.path().join("slowcli");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\necho \"$*\" >> {log}\ncase \"$1 $2 $3\" in\n  \"image inspect fakecloud-ec2-helper\"*) sleep 30; exit 1 ;;\nesac\ncase \"$1\" in\n  build) sleep 30 ;;\n  run) echo cid-instance ;;\n  inspect) echo 172.30.0.11 ;;\nesac\nexit 0\n",
                log = log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        wait_executable(&script);
        let rt = runtime_with_cli(&script.display().to_string());
        let started = std::time::Instant::now();
        let running = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            rt.run_instance(
                "123456789012",
                "i-fast",
                &Boot {
                    user_data: None,
                    tags: &BTreeMap::new(),
                    network: None,
                    region: "us-east-1",
                    volumes: &[],
                },
            ),
        )
        .await
        .expect("run_instance waited on the IMDS helper")
        .expect("run_instance");
        assert_eq!(running.private_ip, "172.30.0.11");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        // Terminating right away doesn't wait on the background setup either.
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            rt.terminate_instance("123456789012", "i-fast"),
        )
        .await
        .expect("terminate waited on the IMDS helper");
    }

    /// A reset must not wait for an instance's in-flight lifecycle task (a
    /// boot pulling a large image holds the lock for as long as the pull
    /// takes): `remove_instances` returns at once, and the teardown --
    /// container, IMDS sidecar and forwarders included -- happens once the
    /// task lets go.
    #[tokio::test]
    async fn reset_does_not_wait_for_an_in_flight_boot() {
        let dir = tempfile::tempdir().unwrap();
        let (cli, log) = fake_cli(dir.path());
        let rt = runtime_with_cli(&cli);
        rt.instances
            .write()
            .insert("i-booting".into(), record("172.30.0.5", None));
        // The boot task holds the lifecycle lock while its image pulls.
        let boot = rt.lock_lifecycle("i-booting").await;

        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            rt.remove_instances(vec![("123456789012".into(), "i-booting".into())]),
        )
        .await
        .expect("reset waited on the in-flight boot");
        assert!(rt.is_registered("i-booting"), "torn down under the boot");

        // The boot finishes: the deferred teardown removes what it left.
        drop(boot);
        let mut done = false;
        for _ in 0..100 {
            let calls = std::fs::read_to_string(&log).unwrap_or_default();
            done = !rt.is_registered("i-booting")
                && calls.contains("rm -f cid-instance")
                && calls.contains("rm -f fakecloud-ec2-imds-i-booting");
            if done {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            done,
            "deferred teardown incomplete: {:?}",
            std::fs::read_to_string(&log)
        );
    }

    impl Ec2Runtime {
        fn with_docker<T>(&self, f: impl FnOnce(&DockerInstances) -> T) -> Option<T> {
            match &self.backend {
                InstanceBackend::Docker(d) => Some(f(d)),
                InstanceBackend::K8s(_) => None,
            }
        }
    }

    /// An instance is given its EC2 private IP on a subnet network that
    /// carries the subnet's range; when another container holds that
    /// address, it boots with one the engine picks and reports that one.
    #[tokio::test]
    async fn an_instance_whose_address_is_taken_takes_another() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("calls");
        let script = dir.path().join("fakecli");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\necho \"$*\" >> {log}\ncase \"$1\" in\n  run) case \"$*\" in\n    *fakecloud-ec2-imds*) exit 1 ;;\n    *\"--ip \"*) echo 'Error response from daemon: Address already in use' >&2; exit 125 ;;\n  esac; echo cid-new ;;\n  inspect) echo 10.40.4.130 ;;\nesac\nexit 0\n",
                log = log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        wait_executable(&script);
        let rt = runtime_with_cli(&script.display().to_string());
        let net = InstanceNetwork {
            subnet_id: "subnet-1".into(),
            internal: true,
            cidr_block: Some("10.40.4.0/24".into()),
            vpc_cidr_block: Some("10.40.0.0/16".into()),
            private_ip: Some("10.40.4.4".into()),
        };
        let running = rt
            .run_instance(
                "123456789012",
                "i-taken",
                &Boot {
                    user_data: None,
                    tags: &BTreeMap::new(),
                    network: Some(&net),
                    region: "us-east-1",
                    volumes: &[],
                },
            )
            .await
            .expect("run_instance");
        assert_eq!(running.private_ip, "10.40.4.130");
        assert_eq!(
            running.network.as_deref(),
            Some("fakecloud-subnet-subnet-1")
        );
        let calls = std::fs::read_to_string(&log).unwrap();
        assert!(
            calls.contains(
                "network create --subnet 10.40.4.0/24 --gateway 10.40.4.1 --ip-range 10.40.4.128/25"
            ),
            "{calls}"
        );
        let runs: Vec<&str> = calls
            .lines()
            .filter(|l| l.starts_with("run -d --label fakecloud-ec2=i-taken"))
            .collect();
        assert_eq!(runs.len(), 2, "{calls}");
        assert!(
            runs[0].contains("--network fakecloud-subnet-subnet-1 --ip 10.40.4.4"),
            "{calls}"
        );
        assert!(!runs[1].contains("--ip "), "{calls}");
        // What the failed `run` left created is removed first.
        assert!(
            calls.contains("ps -aq --filter label=fakecloud-ec2=i-taken --filter status=created"),
            "{calls}"
        );
        rt.terminate_instance("123456789012", "i-taken").await;
    }

    #[test]
    fn network_subnets_reads_docker_and_podman_inspect_output() {
        let docker = serde_json::json!([{
            "Name": "fakecloud-subnet-1",
            "IPAM": {"Config": [{"Subnet": "10.40.4.0/24", "IPRange": "10.40.4.128/25", "Gateway": "10.40.4.1"}]}
        }]);
        assert_eq!(network_subnets(&docker), ["10.40.4.0/24"]);
        let podman = serde_json::json!([{
            "name": "fakecloud-subnet-1",
            "subnets": [{"subnet": "10.40.4.0/24", "gateway": "10.40.4.1"}]
        }]);
        assert_eq!(network_subnets(&podman), ["10.40.4.0/24"]);
        assert!(network_subnets(&serde_json::json!([{"IPAM": {"Config": []}}])).is_empty());
    }

    #[test]
    fn network_ip_template_targets_the_named_network() {
        assert_eq!(
            network_ip_template("fakecloud-subnet-1"),
            "{{with index .NetworkSettings.Networks \"fakecloud-subnet-1\"}}{{.IPAddress}}{{end}}"
        );
    }
}
