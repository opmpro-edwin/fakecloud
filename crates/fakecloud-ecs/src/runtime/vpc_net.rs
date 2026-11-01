//! A task's network namespace as the inside of its VPC (Docker / Podman).
//!
//! On AWS a task resolves names through the VPC's DNS server (the VPC CIDR
//! base plus two, and `169.254.169.253`), which answers the private hosted
//! zones and the load balancers' names, and it reaches an internal ALB at the
//! private IPs of the ALB's network interfaces. When fakecloud runs its DNS
//! resolver (`--dns`), each task container's namespace holder (see
//! `task_creds`) reproduces both with NAT rules in the namespace:
//!
//! - the holder is started with the VPC DNS server as its resolver, and DNS
//!   (UDP and TCP 53) to that address or to `169.254.169.253` goes to
//!   fakecloud's DNS listener. Names in no hosted zone are forwarded upstream
//!   by fakecloud, so internet names still resolve;
//! - a TCP connection to an ALB address on a listener port goes where
//!   `fakecloud_core::vpc_network::lb_routes` says: the configured frontend
//!   (`FAKECLOUD_ELBV2_FRONTEND_HTTPS` / `_HTTP`) or fakecloud's own ALB data
//!   plane. Nothing else is rewritten, so task-to-task traffic is untouched.
//!
//! ALB addresses come from EC2's ordinary allocator and an ALB can be created,
//! deleted or given a listener at any time, so the routes are a map in the
//! holder's nftables table that fakecloud keeps current: it fills the map
//! before the task's container starts and, while the holder lives, rewrites it
//! (`docker exec ... nft`) whenever the routes change. The check is an
//! in-process comparison once a second; a holder is only exec'd into when its
//! routes changed.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;
use std::sync::OnceLock;
use std::time::Duration;

use fakecloud_core::vpc_network::{self, LbRoute, LINK_LOCAL_DNS_SERVER};

use super::config::ContainerCli;
use super::CLI_CALL_TIMEOUT;

/// How often the load balancer routes are compared with what each holder has.
const REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// Whether tasks get VPC networking: fakecloud runs its DNS resolver.
pub(crate) fn enabled() -> bool {
    vpc_network::dns_port().is_some()
}

/// The VPC resolver a task's namespace gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VpcDns {
    /// The VPC CIDR base plus two for the task's subnet, else the link-local
    /// resolver address.
    pub(crate) server: Ipv4Addr,
    /// fakecloud's DNS listener port.
    pub(crate) port: u16,
}

impl VpcDns {
    /// The setup script's VPC arguments: DNS port, the resolver addresses
    /// (an nftables set body), and `lb` to create the load balancer map.
    pub(crate) fn script_args(&self) -> [String; 3] {
        let addresses = if self.server == LINK_LOCAL_DNS_SERVER {
            self.server.to_string()
        } else {
            format!("{}, {LINK_LOCAL_DNS_SERVER}", self.server)
        };
        [self.port.to_string(), addresses, "lb".to_string()]
    }
}

/// The VPC resolver for task `task_id`, when tasks get VPC networking.
pub(crate) fn task_vpc_dns(
    state: &crate::state::SharedEcsState,
    account_id: &str,
    task_id: &str,
) -> Option<VpcDns> {
    let port = vpc_network::dns_port()?;
    let subnet = {
        let accounts = state.read();
        accounts.get(account_id).and_then(|st| {
            st.tasks
                .get(task_id)
                .and_then(|task| super::eni::task_subnet(st, task))
        })
    };
    let server = subnet
        .and_then(|s| vpc_network::vpc_dns_server(account_id, &s))
        .unwrap_or(LINK_LOCAL_DNS_SERVER);
    Some(VpcDns { server, port })
}

/// A frontend host name or IPv4 literal that is safe to put in the script.
fn safe_host(host: &str) -> bool {
    !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// The script that replaces a holder's load balancer map with `routes`. A
/// route with no target host goes to fakecloud at `fakecloud_host`. Each host
/// is resolved inside the holder, as the credentials rule's host is; the
/// whole map is swapped in one nftables transaction.
pub(crate) fn lb_map_script(routes: &[LbRoute], fakecloud_host: &str) -> String {
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
    script.push_str("nft -f - <<EOF\nflush map ip fakecloud_ecs_creds lb\n");
    if !elements.is_empty() {
        script.push_str(&format!(
            "add element ip fakecloud_ecs_creds lb {{ {} }}\n",
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

/// A running holder whose load balancer map fakecloud keeps current.
struct Holder {
    cli: ContainerCli,
    fakecloud_host: String,
    /// Fingerprint of the map script last run in it. A script that failed is
    /// not retried until the routes change again, so a holder that cannot
    /// take the map (an iptables-only helper image) is not exec'd into every
    /// second.
    attempted: u64,
}

fn holders() -> &'static parking_lot::Mutex<HashMap<String, Holder>> {
    static HOLDERS: OnceLock<parking_lot::Mutex<HashMap<String, Holder>>> = OnceLock::new();
    HOLDERS.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

/// What became of an attempt to update a holder's map.
enum Applied {
    Done,
    /// The holder is gone (or stopped): stop tracking it.
    Gone,
    Failed(String),
}

async fn apply(cli: &ContainerCli, holder: &str, script: &str) -> Applied {
    match cli
        .output(["exec", holder, "sh", "-c", script], CLI_CALL_TIMEOUT)
        .await
    {
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
        Err(e) => Applied::Failed(e),
    }
}

/// Fill the load balancer map of a holder that just installed its rules,
/// and keep it current while the holder lives.
pub(crate) async fn attach_holder(cli: ContainerCli, holder: &str, fakecloud_host: &str) {
    let script = lb_map_script(&vpc_network::lb_routes(), fakecloud_host);
    match apply(&cli, holder, &script).await {
        Applied::Done => {}
        Applied::Gone => return,
        Applied::Failed(error) => {
            tracing::warn!(%holder, %error, "could not route load balancer addresses in the task's namespace");
        }
    }
    holders().lock().insert(
        holder.to_string(),
        Holder {
            cli,
            fakecloud_host: fakecloud_host.to_string(),
            attempted: fingerprint(&script),
        },
    );
    ensure_refresher();
}

/// Stop keeping the maps of holders that are being removed.
pub(crate) fn detach_holders(ids: &[String]) {
    let mut holders = holders().lock();
    for id in ids {
        holders.remove(id);
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

/// Update every holder whose routes changed since it was last updated.
async fn refresh() {
    let routes = vpc_network::lb_routes();
    let stale: Vec<(String, ContainerCli, String)> = holders()
        .lock()
        .iter()
        .filter_map(|(id, h)| {
            let script = lb_map_script(&routes, &h.fakecloud_host);
            (h.attempted != fingerprint(&script)).then(|| (id.clone(), h.cli.clone(), script))
        })
        .collect();
    for (id, cli, script) in stale {
        let outcome = apply(&cli, &id, &script).await;
        let mut holders = holders().lock();
        match outcome {
            Applied::Gone => {
                holders.remove(&id);
            }
            Applied::Done => {
                if let Some(h) = holders.get_mut(&id) {
                    h.attempted = fingerprint(&script);
                }
            }
            Applied::Failed(error) => {
                tracing::warn!(holder = %id, %error, "could not update load balancer routes in a task's namespace");
                if let Some(h) = holders.get_mut(&id) {
                    h.attempted = fingerprint(&script);
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
        let vpc = VpcDns {
            server: Ipv4Addr::new(10, 40, 0, 2),
            port: 15353,
        };
        assert_eq!(
            vpc.script_args(),
            [
                "15353".to_string(),
                "10.40.0.2, 169.254.169.253".to_string(),
                "lb".to_string()
            ]
        );
        let link_local = VpcDns {
            server: LINK_LOCAL_DNS_SERVER,
            port: 53,
        };
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
        let empty = lb_map_script(&[], "fakecloud.internal");
        assert!(
            empty.contains("flush map ip fakecloud_ecs_creds lb\nEOF"),
            "{empty}"
        );
        assert!(!empty.contains("add element"), "{empty}");
    }

    /// The map script really runs: under `sh` with fake `getent` and `nft`,
    /// nft gets the flush and the elements with the resolved frontend.
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
