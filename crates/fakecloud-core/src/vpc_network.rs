//! What a task's network namespace needs to behave like the inside of a VPC:
//! the Amazon-provided DNS server and the private addresses of load
//! balancers.
//!
//! In a VPC a workload resolves names through the VPC's DNS server (the VPC
//! CIDR's base address plus two, also reachable at `169.254.169.253`), which
//! serves the private hosted zones and the load balancers' names, and it
//! reaches an internal load balancer at the private IPs of the load
//! balancer's network interfaces. Locally the ECS runtime reproduces both in a
//! task's network namespace with NAT rules: DNS for those addresses goes to
//! fakecloud's resolver (`--dns`), and a connection to a load balancer
//! address and listener port goes to a frontend that serves that listener.
//!
//! The services that own the facts register them here, so the ECS runtime
//! needs no dependency on EC2 or ELBv2: the server records the DNS port and a
//! VPC directory (backed by EC2), ELBv2 records where each load balancer
//! address and listener port is served.

use std::net::Ipv4Addr;
use std::sync::{Arc, OnceLock};

use parking_lot::RwLock;

/// The Route 53 Resolver's link-local address, which every VPC answers on in
/// addition to the CIDR base plus two.
pub const LINK_LOCAL_DNS_SERVER: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 253);

fn dns_port_cell() -> &'static RwLock<Option<u16>> {
    static PORT: OnceLock<RwLock<Option<u16>>> = OnceLock::new();
    PORT.get_or_init(|| RwLock::new(None))
}

/// Record fakecloud's DNS listener port (`--dns`), which containers reach at
/// the host alias; `None` when the resolver is off.
pub fn set_dns_port(port: Option<u16>) {
    *dns_port_cell().write() = port;
}

/// fakecloud's DNS listener port, when `--dns` is on.
pub fn dns_port() -> Option<u16> {
    *dns_port_cell().read()
}

/// Where subnets and VPCs are, from outside the EC2 crate.
pub trait VpcDirectory: Send + Sync {
    /// The CIDR block of the VPC that `subnet_id` belongs to in `account_id`.
    fn subnet_vpc_cidr(&self, account_id: &str, subnet_id: &str) -> Option<String>;
}

fn directory() -> &'static RwLock<Option<Arc<dyn VpcDirectory>>> {
    static DIRECTORY: OnceLock<RwLock<Option<Arc<dyn VpcDirectory>>>> = OnceLock::new();
    DIRECTORY.get_or_init(|| RwLock::new(None))
}

/// Install the VPC directory (one per process; a later call replaces it).
pub fn set_vpc_directory(dir: Arc<dyn VpcDirectory>) {
    *directory().write() = Some(dir);
}

/// The base-plus-two address of a CIDR block (`10.40.0.0/16` -> `10.40.0.2`).
pub fn dns_server_of_cidr(cidr: &str) -> Option<Ipv4Addr> {
    let (addr, len) = cidr.trim().split_once('/')?;
    let addr: Ipv4Addr = addr.parse().ok()?;
    let len: u32 = len.parse().ok()?;
    if len > 30 {
        return None;
    }
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    Some(Ipv4Addr::from((u32::from(addr) & mask) + 2))
}

/// The VPC DNS server (VPC CIDR base plus two) for a workload in
/// `subnet_id`, when the VPC directory knows the subnet.
pub fn vpc_dns_server(account_id: &str, subnet_id: &str) -> Option<Ipv4Addr> {
    let dir = directory().read().clone()?;
    dns_server_of_cidr(&dir.subnet_vpc_cidr(account_id, subnet_id)?)
}

/// Where a connection to a load balancer address and listener port goes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LbRoute {
    /// The load balancer's private address in a subnet.
    pub address: Ipv4Addr,
    /// The listener port.
    pub port: u16,
    /// The frontend host, resolved inside the task's namespace. `None` means
    /// fakecloud itself, at the host alias the task reaches it on.
    pub target_host: Option<String>,
    pub target_port: u16,
}

/// The load balancer routes currently in effect.
pub trait LbRouteSource: Send + Sync {
    fn routes(&self) -> Vec<LbRoute>;
}

fn route_source() -> &'static RwLock<Option<Arc<dyn LbRouteSource>>> {
    static SOURCE: OnceLock<RwLock<Option<Arc<dyn LbRouteSource>>>> = OnceLock::new();
    SOURCE.get_or_init(|| RwLock::new(None))
}

/// Install the load balancer route source (ELBv2; one per process).
pub fn set_lb_route_source(source: Arc<dyn LbRouteSource>) {
    *route_source().write() = Some(source);
}

/// Every load balancer route, sorted and without duplicates.
pub fn lb_routes() -> Vec<LbRoute> {
    let Some(source) = route_source().read().clone() else {
        return Vec::new();
    };
    let mut routes = source.routes();
    routes.sort();
    routes.dedup();
    routes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_server_is_the_cidr_base_plus_two() {
        assert_eq!(
            dns_server_of_cidr("10.40.0.0/16"),
            Some(Ipv4Addr::new(10, 40, 0, 2))
        );
        // A host address inside the block still names the block.
        assert_eq!(
            dns_server_of_cidr("172.31.7.9/16"),
            Some(Ipv4Addr::new(172, 31, 0, 2))
        );
        assert_eq!(dns_server_of_cidr("10.0.0.0/31"), None);
        assert_eq!(dns_server_of_cidr("garbage"), None);
    }

    struct Directory;
    impl VpcDirectory for Directory {
        fn subnet_vpc_cidr(&self, account_id: &str, subnet_id: &str) -> Option<String> {
            (account_id == "123456789012" && subnet_id == "subnet-a")
                .then(|| "10.40.0.0/16".to_string())
        }
    }

    #[test]
    fn vpc_dns_server_comes_from_the_directory() {
        set_vpc_directory(Arc::new(Directory));
        assert_eq!(
            vpc_dns_server("123456789012", "subnet-a"),
            Some(Ipv4Addr::new(10, 40, 0, 2))
        );
        assert_eq!(vpc_dns_server("123456789012", "subnet-b"), None);
    }
}
