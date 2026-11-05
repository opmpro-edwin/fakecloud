//! A workload's network namespace as the inside of its VPC (Docker / Podman).
//!
//! The ECS runtime (in a task container's namespace holder) and the EC2
//! runtime (in an instance's IMDS sidecar) both turn a container's network
//! namespace into the inside of a VPC with NAT rules, from the facts in
//! [`crate::vpc_network`]:
//!
//! - the namespace resolves through the VPC's DNS server, and DNS (UDP and
//!   TCP 53) to that address or to `169.254.169.253` goes to fakecloud's DNS
//!   listener. Names in no hosted zone are forwarded upstream by fakecloud, so
//!   internet names still resolve;
//! - a TCP connection to a load balancer address on a listener port goes where
//!   [`crate::vpc_network::lb_routes`] says: the configured frontend
//!   (`FAKECLOUD_ELBV2_FRONTEND_HTTPS` / `_HTTP`) or fakecloud's own ALB data
//!   plane. Nothing else is rewritten.
//!
//! The rules are installed by each runtime's own setup script; this module
//! holds what the two share: the resolver a namespace gets ([`VpcDns`]) and
//! the load balancer map. Load balancer addresses come from EC2's ordinary
//! allocator and a load balancer can be created, deleted or given a listener
//! at any time, so the routes are a map in the namespace's nftables table that
//! fakecloud keeps current: the runtime fills it once the rules are in place
//! ([`attach`]) and, while the container lives, it is rewritten (`docker exec
//! ... nft`) whenever the routes change. The check is an in-process comparison
//! once a second; a container is only exec'd into when its routes changed.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;
use std::sync::OnceLock;
use std::time::Duration;

use crate::vpc_network::{self, LbRoute, LINK_LOCAL_DNS_SERVER};

/// How often the load balancer routes are compared with what each namespace
/// has.
const REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// Budget for one `exec` that rewrites a namespace's map.
const EXEC_TIMEOUT: Duration = Duration::from_secs(60);

/// The VPC resolver a namespace gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpcDns {
    /// The VPC CIDR base plus two, else the link-local resolver address.
    pub server: Ipv4Addr,
    /// fakecloud's DNS listener port.
    pub port: u16,
}

impl VpcDns {
    /// The resolver of a VPC with CIDR block `vpc_cidr`, when fakecloud runs
    /// its DNS resolver (`--dns`). Without a known VPC the namespace still
    /// gets the link-local resolver.
    pub fn for_vpc(vpc_cidr: Option<&str>) -> Option<Self> {
        let port = vpc_network::dns_port()?;
        Some(Self::with_port(vpc_cidr, port))
    }

    /// [`Self::for_vpc`] with the DNS port given.
    pub fn with_port(vpc_cidr: Option<&str>, port: u16) -> Self {
        let server = vpc_cidr
            .and_then(vpc_network::dns_server_of_cidr)
            .unwrap_or(LINK_LOCAL_DNS_SERVER);
        Self { server, port }
    }

    /// The setup scripts' VPC arguments: DNS port, the resolver addresses
    /// (an nftables set body), and `lb` to create the load balancer map.
    pub fn script_args(&self) -> [String; 3] {
        let addresses = if self.server == LINK_LOCAL_DNS_SERVER {
            self.server.to_string()
        } else {
            format!("{}, {LINK_LOCAL_DNS_SERVER}", self.server)
        };
        [self.port.to_string(), addresses, "lb".to_string()]
    }
}

/// Docker's host alias. Podman's (`host.containers.internal`) is written to
/// the hosts file by podman itself.
const DOCKER_HOST_ALIAS: &str = "host.docker.internal";

/// The `--add-host` value that pins fakecloud's host alias in a namespace
/// whose runtime adds no alias of its own. The VPC resolver replaces the
/// engine's, and the engine's is what resolves `host.docker.internal` on
/// Docker Desktop when fakecloud runs in a container (no `--add-host` then):
/// without the pin, neither the setup script nor the workload could resolve
/// fakecloud.
pub fn pinned_host_alias(vpc_dns: bool, fakecloud_host: &str) -> Option<String> {
    (vpc_dns && fakecloud_host == DOCKER_HOST_ALIAS)
        .then(|| format!("{DOCKER_HOST_ALIAS}:host-gateway"))
}

/// A frontend host name or IPv4 literal that is safe to put in the script.
fn safe_host(host: &str) -> bool {
    !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// The script that replaces the `lb` map of nftables table `ip <table>` with
/// `routes`. A route with no target host goes to fakecloud at
/// `fakecloud_host`. Each host is resolved inside the namespace, as the setup
/// scripts resolve fakecloud's; the whole map is swapped in one nftables
/// transaction.
pub fn lb_map_script(routes: &[LbRoute], fakecloud_host: &str, table: &str) -> String {
    let mut hosts: Vec<&str> = Vec::new();
    let mut elements: Vec<String> = Vec::new();
    for route in routes {
        let host = route.target_host.as_deref().unwrap_or(fakecloud_host);
        if !safe_host(host) {
            tracing::warn!(%host, "skipping a load balancer frontend with an unusable host name");
            continue;
        }
        let index = match hosts.iter().position(|h| *h == host) {
            Some(i) => i,
            None => {
                hosts.push(host);
                hosts.len() - 1
            }
        };
        elements.push(format!(
            "{} . {} : $h{index} . {}",
            route.address, route.port, route.target_port
        ));
    }
    let mut script =
        String::from("set -eu\nr() { getent ahostsv4 \"$1\" | awk 'NR==1{print $1}'; }\n");
    for (i, host) in hosts.iter().enumerate() {
        script.push_str(&format!(
            "h{i}=$(r '{host}')\n[ -n \"$h{i}\" ] || {{ echo \"cannot resolve {host}\" >&2; exit 1; }}\n"
        ));
    }
    script.push_str(&format!("nft -f - <<EOF\nflush map ip {table} lb\n"));
    if !elements.is_empty() {
        script.push_str(&format!(
            "add element ip {table} lb {{ {} }}\n",
            elements.join(", ")
        ));
    }
    script.push_str("EOF\n");
    script
}

fn fingerprint(script: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    script.hash(&mut hasher);
    hasher.finish()
}

/// A running container whose namespace's load balancer map fakecloud keeps
/// current.
struct Tracked {
    cli: String,
    fakecloud_host: String,
    table: &'static str,
    /// Fingerprint of the map script last run in it. A script that failed is
    /// not retried until the routes change again, so a container that cannot
    /// take the map (an iptables-only helper image) is not exec'd into every
    /// second.
    attempted: u64,
}

impl Tracked {
    fn script(&self, routes: &[LbRoute]) -> String {
        lb_map_script(routes, &self.fakecloud_host, self.table)
    }
}

fn tracked() -> &'static parking_lot::Mutex<HashMap<String, Tracked>> {
    static TRACKED: OnceLock<parking_lot::Mutex<HashMap<String, Tracked>>> = OnceLock::new();
    TRACKED.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

/// What became of an attempt to update a namespace's map.
enum Applied {
    Done,
    /// The container is gone (or stopped): stop tracking it.
    Gone,
    Failed(String),
}

async fn apply(cli: &str, container: &str, script: &str) -> Applied {
    let out = crate::container_net::output_within(
        tokio::process::Command::new(cli).args(["exec", container, "sh", "-c", script]),
        EXEC_TIMEOUT,
    )
    .await;
    match out {
        Ok(out) if out.status.success() => Applied::Done,
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let lower = err.to_ascii_lowercase();
            if lower.contains("no such container")
                || lower.contains("no container with")
                || lower.contains("is not running")
            {
                Applied::Gone
            } else {
                Applied::Failed(err)
            }
        }
        Err(e) => Applied::Failed(format!("{cli} exec {e}")),
    }
}

/// Fill the load balancer map of `container`, whose namespace just got its
/// rules in nftables table `ip <table>`, and keep it current while the
/// container lives. `fakecloud_host` is the name fakecloud is reached at from
/// inside the namespace.
pub async fn attach(cli: &str, container: &str, fakecloud_host: &str, table: &'static str) {
    let entry = Tracked {
        cli: cli.to_string(),
        fakecloud_host: fakecloud_host.to_string(),
        table,
        attempted: 0,
    };
    let script = entry.script(&vpc_network::lb_routes());
    match apply(cli, container, &script).await {
        Applied::Done => {}
        Applied::Gone => return,
        Applied::Failed(error) => {
            tracing::warn!(%container, %error, "could not route load balancer addresses in a VPC namespace");
        }
    }
    tracked().lock().insert(
        container.to_string(),
        Tracked {
            attempted: fingerprint(&script),
            ..entry
        },
    );
    ensure_refresher();
}

/// Stop keeping the maps of containers that are being removed.
pub fn detach(ids: &[String]) {
    let mut tracked = tracked().lock();
    for id in ids {
        tracked.remove(id);
    }
}

fn ensure_refresher() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        tokio::spawn(async {
            let mut tick = tokio::time::interval(REFRESH_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                refresh().await;
            }
        });
    });
}

/// Update every namespace whose routes changed since it was last updated.
async fn refresh() {
    let routes = vpc_network::lb_routes();
    let stale: Vec<(String, String, String)> = tracked()
        .lock()
        .iter()
        .filter_map(|(id, t)| {
            let script = t.script(&routes);
            (t.attempted != fingerprint(&script)).then(|| (id.clone(), t.cli.clone(), script))
        })
        .collect();
    for (id, cli, script) in stale {
        let outcome = apply(&cli, &id, &script).await;
        let mut tracked = tracked().lock();
        match outcome {
            Applied::Gone => {
                tracked.remove(&id);
            }
            Applied::Done => {
                if let Some(t) = tracked.get_mut(&id) {
                    t.attempted = fingerprint(&script);
                }
            }
            Applied::Failed(error) => {
                tracing::warn!(container = %id, %error, "could not update load balancer routes in a VPC namespace");
                if let Some(t) = tracked.get_mut(&id) {
                    t.attempted = fingerprint(&script);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(address: [u8; 4], port: u16, host: Option<&str>, target_port: u16) -> LbRoute {
        LbRoute {
            address: Ipv4Addr::from(address),
            port,
            target_host: host.map(str::to_string),
            target_port,
        }
    }

    #[test]
    fn script_args_name_both_resolver_addresses_once() {
        let vpc = VpcDns::with_port(Some("10.40.0.0/16"), 15353);
        assert_eq!(vpc.server, Ipv4Addr::new(10, 40, 0, 2));
        assert_eq!(
            vpc.script_args(),
            [
                "15353".to_string(),
                "10.40.0.2, 169.254.169.253".to_string(),
                "lb".to_string()
            ]
        );
        // No VPC: only the link-local resolver.
        let link_local = VpcDns::with_port(None, 53);
        assert_eq!(link_local.server, LINK_LOCAL_DNS_SERVER);
        assert_eq!(link_local.script_args()[1], "169.254.169.253");
    }

    #[test]
    fn lb_map_script_resolves_each_frontend_once_and_swaps_the_map() {
        let script = lb_map_script(
            &[
                route([10, 40, 4, 10], 443, Some("host.docker.internal"), 24443),
                route([10, 40, 5, 10], 443, Some("host.docker.internal"), 24443),
                route([10, 40, 4, 10], 80, None, 41000),
                route([10, 40, 4, 11], 80, Some("bad host;rm -rf /"), 80),
            ],
            "fakecloud.internal",
            "fakecloud_ecs_creds",
        );
        assert_eq!(script.matches("getent").count(), 1, "{script}");
        assert!(
            script.contains("h0=$(r 'host.docker.internal')"),
            "{script}"
        );
        assert!(script.contains("h1=$(r 'fakecloud.internal')"), "{script}");
        assert!(!script.contains("bad host"), "{script}");
        assert!(script.contains(
            "add element ip fakecloud_ecs_creds lb { 10.40.4.10 . 443 : $h0 . 24443, 10.40.5.10 . 443 : $h0 . 24443, 10.40.4.10 . 80 : $h1 . 41000 }"
        ), "{script}");
        // No routes: the map is only emptied.
        let empty = lb_map_script(&[], "fakecloud.internal", "fakecloud_ec2_imds");
        assert!(
            empty.contains("flush map ip fakecloud_ec2_imds lb\nEOF"),
            "{empty}"
        );
        assert!(!empty.contains("add element"), "{empty}");
    }

    /// The map script really runs: under `sh` with fake `getent` and `nft`,
    /// nft gets the flush and the elements with the resolved frontend.
    #[cfg(unix)]
    #[test]
    fn lb_map_script_feeds_nft_the_resolved_elements() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("nft-input");
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
        tool("getent", "echo '192.168.65.254 STREAM host'");
        tool("nft", &format!("cat > {}", log.display()));
        let script = lb_map_script(
            &[route([10, 40, 4, 10], 443, Some("edge"), 24443)],
            "fakecloud",
            "fakecloud_ecs_creds",
        );
        let out = std::process::Command::new("/bin/sh")
            .args(["-c", &script])
            .env("PATH", dir.path())
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "flush map ip fakecloud_ecs_creds lb\nadd element ip fakecloud_ecs_creds lb { 10.40.4.10 . 443 : 192.168.65.254 . 24443 }\n"
        );
    }
}
