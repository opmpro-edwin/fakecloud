//! A task's network namespace as the inside of its VPC (Docker / Podman).
//!
//! On AWS a task resolves names through the VPC's DNS server (the VPC CIDR
//! base plus two, and `169.254.169.253`), which answers the private hosted
//! zones and the load balancers' names, and it reaches an internal ALB at the
//! private IPs of the ALB's network interfaces. When fakecloud runs its DNS
//! resolver (`--dns`), each task container's namespace holder (see
//! `task_creds`) reproduces both with NAT rules in the namespace, the way
//! [`fakecloud_core::vpc_netns`] describes: the holder is started with the VPC
//! DNS server as its resolver, its setup script sends DNS for the resolver
//! addresses to fakecloud, and the load balancer map in its nftables table is
//! kept current by `vpc_netns`. Nothing else is rewritten, so task-to-task
//! traffic is untouched.

use fakecloud_core::vpc_netns;
use fakecloud_core::vpc_network::{self, LINK_LOCAL_DNS_SERVER};

pub(crate) use fakecloud_core::vpc_netns::VpcDns;

use super::config::ContainerCli;

/// The holder's nftables table, which carries the load balancer map.
pub(crate) const NFT_TABLE: &str = "fakecloud_ecs_creds";

/// Whether tasks get VPC networking: fakecloud runs its DNS resolver.
pub(crate) fn enabled() -> bool {
    vpc_network::dns_port().is_some()
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

/// Fill the load balancer map of a holder that just installed its rules,
/// and keep it current while the holder lives.
pub(crate) async fn attach_holder(cli: ContainerCli, holder: &str, fakecloud_host: &str) {
    vpc_netns::attach(cli.program(), holder, fakecloud_host, NFT_TABLE).await;
}

/// Stop keeping the maps of holders that are being removed.
pub(crate) fn detach_holders(ids: &[String]) {
    vpc_netns::detach(ids);
}
