//! An instance container's place in its VPC (Docker / Podman).
//!
//! **Addresses.** Each subnet is backed by one daemon network
//! (`fakecloud-subnet-<id>`) whose address range is the subnet's CIDR block,
//! with the bridge at the base plus one (the VPC router's address on AWS). An
//! instance's container is given the private IP EC2 allocated to it, so the
//! address DescribeInstances reports, IMDS's `local-ipv4` and the one other
//! instances and security-group rules see are the same. The daemon hands out
//! addresses of its own (load balancer forwarders) only from the upper half of
//! the range ([`ip_range`]), away from EC2's allocator, which starts at the
//! bottom. When the daemon refuses the range (another network already uses
//! an overlapping one, as two VPCs with the same CIDR would), the subnet
//! falls back to a range the daemon picks and instances report the address
//! the daemon gave them.
//!
//! **Egress.** fakecloud has no NAT gateways or NAT instances, so, as for ECS
//! tasks, a private subnet's network reaches the internet through the
//! daemon's NAT like a public one. `FAKECLOUD_EC2_ISOLATE_PRIVATE_SUBNETS=1`
//! puts private subnets (no `0.0.0.0/0 -> igw` route) on `--internal`
//! networks instead, which also cuts them off from fakecloud itself: no IMDS,
//! VPC DNS or AWS endpoint there.
//!
//! **DNS and load balancers.** When fakecloud runs its DNS resolver (`--dns`),
//! the instance resolves through its VPC's DNS server and reaches load
//! balancers at their private addresses, exactly as ECS tasks do (see
//! [`fakecloud_core::vpc_netns`]): the container is started with the VPC
//! resolver as its DNS server, and the IMDS sidecar, which shares the
//! instance's network namespace, installs the NAT rules and carries the load
//! balancer map.

use std::net::Ipv4Addr;

use fakecloud_core::vpc_netns::VpcDns;

use super::InstanceNetwork;

/// Opt-in: private subnets get `--internal` networks with no egress.
const ISOLATE_PRIVATE_SUBNETS_ENV: &str = "FAKECLOUD_EC2_ISOLATE_PRIVATE_SUBNETS";

/// Whether private subnets are cut off from everything outside them.
pub(crate) fn isolate_private_subnets() -> bool {
    std::env::var(ISOLATE_PRIVATE_SUBNETS_ENV)
        .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes"))
        .unwrap_or(false)
}

/// A parsed IPv4 CIDR block: network address and prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cidr {
    network: u32,
    len: u32,
}

impl Cidr {
    pub(crate) fn parse(cidr: &str) -> Option<Self> {
        let (addr, len) = cidr.trim().split_once('/')?;
        let addr: Ipv4Addr = addr.parse().ok()?;
        let len: u32 = len.parse().ok()?;
        if len > 32 {
            return None;
        }
        Some(Self {
            network: u32::from(addr) & mask(len),
            len,
        })
    }

    fn size(&self) -> u64 {
        1u64 << (32 - self.len)
    }

    fn at(&self, offset: u64) -> Ipv4Addr {
        Ipv4Addr::from(self.network.wrapping_add(offset as u32))
    }

    /// The block in canonical form (`10.40.4.7/24` -> `10.40.4.0/24`).
    pub(crate) fn canonical(&self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.network), self.len)
    }

    /// Whether `ip` is an address EC2 hands out in this block: inside it and
    /// not one of the five AWS reserves (the network address, the next three
    /// and the broadcast address).
    pub(crate) fn assignable(&self, ip: &str) -> bool {
        let Ok(ip) = ip.parse::<Ipv4Addr>() else {
            return false;
        };
        let ip = u32::from(ip);
        if ip & mask(self.len) != self.network {
            return false;
        }
        let offset = u64::from(ip - self.network);
        offset >= 4 && offset < self.size() - 1
    }
}

fn mask(len: u32) -> u32 {
    if len == 0 {
        0
    } else {
        u32::MAX << (32 - len)
    }
}

/// The gateway and the range the daemon allocates from on its own for a
/// subnet's network: the base plus one (the VPC router), and the upper half of
/// the block. `None` for a block too small to hold an instance (AWS subnets
/// are /16 to /28) or too large to be one.
pub(crate) fn ip_range(cidr: &Cidr) -> Option<(Ipv4Addr, String)> {
    if !(16..=28).contains(&cidr.len) {
        return None;
    }
    let half = cidr.size() / 2;
    Some((cidr.at(1), format!("{}/{}", cidr.at(half), cidr.len + 1)))
}

/// `network create` argv for a subnet's backing network. `addressed` gives it
/// the subnet's CIDR block (see [`ip_range`]); without it the daemon picks a
/// range. `isolate` is [`isolate_private_subnets`].
pub(crate) fn network_create_argv(
    name: &str,
    net: &InstanceNetwork,
    owner: &str,
    addressed: bool,
    isolate: bool,
) -> Vec<String> {
    let mut argv = vec!["network".to_string(), "create".to_string()];
    if net.internal && isolate {
        argv.push("--internal".to_string());
    }
    if addressed {
        if let Some((cidr, (gateway, range))) =
            subnet_cidr(net).and_then(|c| Some((c, ip_range(&c)?)))
        {
            argv.extend([
                "--subnet".to_string(),
                cidr.canonical(),
                "--gateway".to_string(),
                gateway.to_string(),
                "--ip-range".to_string(),
                range,
            ]);
        }
    }
    argv.extend([
        "--label".to_string(),
        format!("fakecloud-subnet={}", net.subnet_id),
        "--label".to_string(),
        format!("fakecloud-instance={owner}"),
        name.to_string(),
    ]);
    argv
}

/// The subnet's CIDR block, when it can back a network.
pub(crate) fn subnet_cidr(net: &InstanceNetwork) -> Option<Cidr> {
    net.cidr_block
        .as_deref()
        .and_then(Cidr::parse)
        .filter(|c| ip_range(c).is_some())
}

/// Whether a failed `network create` failed because the network exists.
pub(crate) fn already_exists(stderr: &str) -> bool {
    stderr.contains("already exists")
}

/// Whether a failed `run` / `start` failed because the requested address is
/// held by another container (Docker: "Address already in use"; Podman:
/// "requested ip address ... is already allocated").
pub(crate) fn address_taken(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("address already in use") || lower.contains("already allocated")
}

/// The address to pin on the instance container, when its subnet network
/// carries the subnet's CIDR block: the instance's EC2 private IP, if it is
/// one EC2 could have handed out there.
pub(crate) fn pinned_ip(net: &InstanceNetwork, addressed: bool) -> Option<&str> {
    let cidr = subnet_cidr(net).filter(|_| addressed)?;
    net.private_ip.as_deref().filter(|ip| cidr.assignable(ip))
}

/// The VPC resolver an instance in `net` gets, when fakecloud runs its DNS
/// resolver. An instance in no known subnet still gets the link-local one.
pub(crate) fn vpc_dns(net: Option<&InstanceNetwork>) -> Option<VpcDns> {
    VpcDns::for_vpc(net.and_then(|n| n.vpc_cidr_block.as_deref()))
}

/// The network flags of an instance container: its subnet network and
/// address, the host alias, and the VPC resolver.
pub(crate) fn instance_network_argv(
    network: Option<&str>,
    ip: Option<&str>,
    add_host_arg: Option<&str>,
    fakecloud_host: &str,
    vpc_dns: Option<&VpcDns>,
) -> Vec<String> {
    let mut argv = Vec::new();
    if let Some(name) = network {
        argv.extend(["--network".to_string(), name.to_string()]);
        if let Some(ip) = ip {
            argv.extend(["--ip".to_string(), ip.to_string()]);
        }
    }
    // The VPC resolver replaces the engine's, which is what resolves the host
    // alias on Docker Desktop when fakecloud runs in a container: pin it.
    let alias = add_host_arg.map(str::to_string).or_else(|| {
        fakecloud_core::vpc_netns::pinned_host_alias(vpc_dns.is_some(), fakecloud_host)
    });
    if let Some(alias) = alias {
        argv.extend(["--add-host".to_string(), alias]);
    }
    if let Some(vpc) = vpc_dns {
        argv.extend(["--dns".to_string(), vpc.server.to_string()]);
    }
    argv
}

/// The region of an Availability Zone (`ap-southeast-1a` ->
/// `ap-southeast-1`, `us-west-2-lax-1a` -> `us-west-2`): the parts up to and
/// including the first that starts with a digit, cut to its digits.
pub(crate) fn region_of_az(az: &str) -> String {
    let mut parts = Vec::new();
    for part in az.split('-') {
        let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            parts.push(part.to_string());
        } else {
            parts.push(digits);
            return parts.join("-");
        }
    }
    az.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(cidr: Option<&str>, ip: Option<&str>) -> InstanceNetwork {
        InstanceNetwork {
            subnet_id: "subnet-1".into(),
            internal: true,
            cidr_block: cidr.map(str::to_string),
            vpc_cidr_block: Some("10.40.0.0/16".into()),
            private_ip: ip.map(str::to_string),
        }
    }

    #[test]
    fn a_subnet_network_carries_the_subnet_range_with_the_daemon_in_the_upper_half() {
        let argv = network_create_argv(
            "fakecloud-subnet-1",
            &net(Some("10.40.4.0/24"), None),
            "fakecloud-7",
            true,
            false,
        )
        .join(" ");
        assert_eq!(
            argv,
            "network create --subnet 10.40.4.0/24 --gateway 10.40.4.1 --ip-range 10.40.4.128/25 \
             --label fakecloud-subnet=subnet-1 --label fakecloud-instance=fakecloud-7 \
             fakecloud-subnet-1"
        );
        // A private subnet is not `--internal` unless isolation is asked for,
        // and a public one never is.
        assert!(!argv.contains("--internal"));
        let isolated = network_create_argv(
            "fakecloud-subnet-1",
            &net(Some("10.40.4.0/24"), None),
            "fakecloud-7",
            true,
            true,
        );
        assert_eq!(isolated[2], "--internal");
        let mut public = net(Some("10.40.4.0/24"), None);
        public.internal = false;
        assert!(
            !network_create_argv("n", &public, "o", true, true).contains(&"--internal".to_string())
        );
        // The fallback leaves the range to the daemon.
        let plain = network_create_argv(
            "fakecloud-subnet-1",
            &net(Some("10.40.4.0/24"), None),
            "fakecloud-7",
            false,
            false,
        )
        .join(" ");
        assert!(!plain.contains("--subnet"), "{plain}");
        // A /28 still has room: the daemon gets .8 to .15.
        let small = Cidr::parse("10.40.9.16/28").unwrap();
        assert_eq!(
            ip_range(&small),
            Some((Ipv4Addr::new(10, 40, 9, 17), "10.40.9.24/29".to_string()))
        );
        // Blocks no AWS subnet has are left to the daemon.
        assert!(ip_range(&Cidr::parse("10.0.0.0/30").unwrap()).is_none());
        assert!(ip_range(&Cidr::parse("10.0.0.0/8").unwrap()).is_none());
        assert!(
            network_create_argv("n", &net(Some("garbage"), None), "o", true, false)
                .iter()
                .all(|a| a != "--subnet")
        );
    }

    #[test]
    fn only_an_address_ec2_could_hand_out_is_pinned() {
        let addressed = |ip| pinned_ip(&net(Some("10.40.4.0/24"), Some(ip)), true).is_some();
        assert!(addressed("10.40.4.4"));
        assert!(addressed("10.40.4.254"));
        // Reserved, outside the block, or not an address.
        for ip in [
            "10.40.4.0",
            "10.40.4.1",
            "10.40.4.3",
            "10.40.4.255",
            "10.40.5.9",
            "x",
        ] {
            assert!(!addressed(ip), "{ip}");
        }
        // Nothing is pinned on a network the daemon addressed itself.
        assert_eq!(
            pinned_ip(&net(Some("10.40.4.0/24"), Some("10.40.4.4")), false),
            None
        );
        assert_eq!(pinned_ip(&net(None, Some("10.40.4.4")), true), None);
    }

    #[test]
    fn instance_network_flags_pin_the_alias_only_under_the_vpc_resolver() {
        let vpc = VpcDns::with_port(Some("10.40.0.0/16"), 15353);
        let argv = instance_network_argv(
            Some("fakecloud-subnet-1"),
            Some("10.40.4.4"),
            None,
            "host.docker.internal",
            Some(&vpc),
        )
        .join(" ");
        assert_eq!(
            argv,
            "--network fakecloud-subnet-1 --ip 10.40.4.4 \
             --add-host host.docker.internal:host-gateway --dns 10.40.0.2"
        );
        // Without the VPC resolver the engine's DNS keeps resolving the alias.
        let plain = instance_network_argv(
            Some("fakecloud-subnet-1"),
            None,
            None,
            "host.docker.internal",
            None,
        );
        assert_eq!(plain, ["--network", "fakecloud-subnet-1"]);
        // The runtime's own mapping always wins; podman needs none.
        let linux = instance_network_argv(
            None,
            None,
            Some("host.docker.internal:172.17.0.1"),
            "host.docker.internal",
            Some(&vpc),
        )
        .join(" ");
        assert_eq!(
            linux,
            "--add-host host.docker.internal:172.17.0.1 --dns 10.40.0.2"
        );
        let podman =
            instance_network_argv(None, None, None, "host.containers.internal", Some(&vpc));
        assert_eq!(podman, ["--dns", "10.40.0.2"]);
    }

    #[test]
    fn engine_errors_are_told_apart() {
        assert!(already_exists(
            "Error response from daemon: network with name fakecloud-subnet-1 already exists"
        ));
        assert!(!already_exists(
            "Error response from daemon: Pool overlaps with other one on this address space"
        ));
        assert!(address_taken(
            "Error response from daemon: Address already in use"
        ));
        assert!(address_taken(
            "Error: requested ip address 10.40.4.4 is already allocated to container ID abc"
        ));
        assert!(!address_taken("no such image"));
    }

    #[test]
    fn region_comes_from_the_availability_zone() {
        assert_eq!(region_of_az("ap-southeast-1a"), "ap-southeast-1");
        assert_eq!(region_of_az("us-gov-west-1b"), "us-gov-west-1");
        assert_eq!(region_of_az("us-west-2-lax-1a"), "us-west-2");
        assert_eq!(region_of_az("weird"), "weird");
    }
}
