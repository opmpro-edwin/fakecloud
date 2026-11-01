//! The private addresses of Application Load Balancers.
//!
//! On AWS an ALB has a requester-managed network interface in each of its
//! subnets (description `ELB app/<name>/<id>`, visible in
//! DescribeNetworkInterfaces); its DNS name resolves to those interfaces'
//! private IPs, and so does a Route 53 alias record that points at it. Clients
//! in the VPC connect to those IPs.
//!
//! fakecloud creates the same interfaces through EC2's own allocator, so an
//! ALB address never collides with a task ENI or any other interface in the
//! subnet, and it answers the ALB's DNS name with their IPs (see
//! [`dns_records`]). An internet-facing ALB gets private addresses too
//! (locally there are no public ones); its DNS name resolves to them.
//!
//! Inside an ECS task's network namespace a connection to an ALB address on a
//! listener port is sent to a frontend serving that listener (see [`Routes`]):
//! the `FAKECLOUD_ELBV2_FRONTEND_HTTPS` / `FAKECLOUD_ELBV2_FRONTEND_HTTP`
//! endpoint when set (a TLS edge that picks the ALB by SNI / Host), else
//! fakecloud's own in-process data plane for the ALB, which serves plain
//! HTTP.

use std::net::Ipv4Addr;

use fakecloud_core::vpc_network::{LbRoute, LbRouteSource};
use fakecloud_ec2::vpc_lookup::{self, ServiceEni};
use fakecloud_ec2::SharedEc2State;
use serde::{Deserialize, Serialize};

use crate::state::{LoadBalancer, SharedElbv2State};

/// Env var naming the frontend for HTTPS (and TLS) listeners, `host:port`.
pub const FRONTEND_HTTPS_ENV: &str = "FAKECLOUD_ELBV2_FRONTEND_HTTPS";
/// Env var naming the frontend for HTTP listeners, `host:port`.
pub const FRONTEND_HTTP_ENV: &str = "FAKECLOUD_ELBV2_FRONTEND_HTTP";

/// One network interface of a load balancer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LbInterface {
    pub subnet_id: String,
    pub network_interface_id: String,
    pub private_ip: String,
}

/// Whether `lb` gets network interfaces (Application Load Balancers).
fn wants_interfaces(lb: &LoadBalancer) -> bool {
    lb.lb_type == "application"
}

/// The description AWS gives a load balancer's interfaces:
/// `ELB app/<name>/<id>` (the resource part of the ARN after `loadbalancer/`).
pub fn interface_description(lb_arn: &str) -> String {
    let resource = lb_arn
        .split_once(":loadbalancer/")
        .map(|(_, r)| r)
        .unwrap_or(lb_arn);
    format!("ELB {resource}")
}

/// Bring the network interfaces of load balancer `arn` in line with its
/// subnets and security groups: one interface per subnet (created by EC2),
/// none for a subnet it left, the load balancer's groups on each. Returns
/// whether EC2 state changed. A load balancer that is gone has its
/// interfaces released by [`release_interfaces`] instead.
pub fn sync_interfaces(
    elbv2: &SharedElbv2State,
    ec2: &SharedEc2State,
    account_id: &str,
    arn: &str,
) -> bool {
    // ELBv2 is read, then EC2 written, then ELBv2 written: never both at once.
    let Some((subnets, groups, interfaces)) = elbv2.read().get(account_id).and_then(|st| {
        let lb = st
            .load_balancers
            .get(arn)
            .filter(|lb| wants_interfaces(lb))?;
        Some((
            lb.availability_zones
                .iter()
                .map(|z| z.subnet_id.clone())
                .collect::<Vec<_>>(),
            lb.security_groups.clone(),
            lb.interfaces.clone(),
        ))
    }) else {
        return false;
    };
    let description = interface_description(arn);
    let mut changed = false;
    let mut kept: Vec<LbInterface> = Vec::new();
    {
        let mut accounts = ec2.write();
        let state = accounts.get_or_create(account_id);
        for iface in interfaces {
            let exists = state
                .network_interfaces
                .contains_key(&iface.network_interface_id);
            if subnets.contains(&iface.subnet_id) && exists {
                if let Some(eni) = state
                    .network_interfaces
                    .get_mut(&iface.network_interface_id)
                {
                    if eni.group_ids != groups {
                        eni.group_ids = groups.clone();
                        changed = true;
                    }
                }
                kept.push(iface);
            } else {
                vpc_lookup::delete_service_eni(state, &iface.network_interface_id);
                changed |= exists;
            }
        }
        for subnet in &subnets {
            if kept.iter().any(|i| &i.subnet_id == subnet) || !state.subnets.contains_key(subnet) {
                continue;
            }
            match vpc_lookup::create_service_eni(
                state,
                ServiceEni {
                    subnet_id: subnet,
                    group_ids: groups.clone(),
                    description: description.clone(),
                    private_ip: None,
                },
            ) {
                Ok((eni_id, ip)) => {
                    kept.push(LbInterface {
                        subnet_id: subnet.clone(),
                        network_interface_id: eni_id,
                        private_ip: ip,
                    });
                    changed = true;
                }
                Err(error) => tracing::warn!(
                    load_balancer = %arn,
                    %subnet,
                    ?error,
                    "could not give the load balancer an address in the subnet"
                ),
            }
        }
    }
    kept.sort_by(|a, b| {
        subnets
            .iter()
            .position(|s| s == &a.subnet_id)
            .cmp(&subnets.iter().position(|s| s == &b.subnet_id))
    });
    let mut accounts = elbv2.write();
    match accounts
        .get_mut(account_id)
        .and_then(|st| st.load_balancers.get_mut(arn))
    {
        Some(lb) => lb.interfaces = kept,
        // Deleted meanwhile: give back what was just created.
        None => {
            drop(accounts);
            release_interfaces(ec2, account_id, &kept);
        }
    }
    changed
}

/// Delete the network interfaces of a deleted load balancer.
pub fn release_interfaces(ec2: &SharedEc2State, account_id: &str, interfaces: &[LbInterface]) {
    if interfaces.is_empty() {
        return;
    }
    let mut accounts = ec2.write();
    let state = accounts.get_or_create(account_id);
    for iface in interfaces {
        vpc_lookup::delete_service_eni(state, &iface.network_interface_id);
    }
}

/// Give every load balancer restored from a snapshot the interfaces it is
/// missing (snapshots taken before load balancers had addresses, or an EC2
/// snapshot that lost them). Returns how many load balancers changed.
pub fn restore_interfaces(elbv2: &SharedElbv2State, ec2: &SharedEc2State) -> usize {
    let lbs: Vec<(String, String)> = elbv2
        .read()
        .iter()
        .flat_map(|(account, st)| {
            st.load_balancers
                .values()
                .filter(|lb| wants_interfaces(lb))
                .map(|lb| (account.clone(), lb.arn.clone()))
                .collect::<Vec<_>>()
        })
        .collect();
    lbs.into_iter()
        .filter(|(account, arn)| sync_interfaces(elbv2, ec2, account, arn))
        .count()
}

/// Strip the `dualstack.` prefix Route 53 alias targets often carry.
fn lb_name_of(dns_name: &str) -> String {
    let name = dns_name.trim().trim_end_matches('.').to_ascii_lowercase();
    name.strip_prefix("dualstack.")
        .map(str::to_string)
        .unwrap_or(name)
}

/// The DNS answer for load balancer DNS name `name` (with or without the
/// `dualstack.` prefix and trailing dot): its addresses for `A`, nothing for
/// other types (fakecloud gives load balancers no IPv6 addresses). `None`
/// when no load balancer has that name.
pub fn dns_records(state: &SharedElbv2State, name: &str, rtype: &str) -> Option<Vec<String>> {
    let wanted = lb_name_of(name);
    let accounts = state.read();
    let lb = accounts.iter().find_map(|(_, st)| {
        st.load_balancers
            .values()
            .find(|lb| lb.dns_name.to_ascii_lowercase() == wanted)
    })?;
    Some(if rtype.eq_ignore_ascii_case("A") {
        lb.interfaces.iter().map(|i| i.private_ip.clone()).collect()
    } else {
        Vec::new()
    })
}

/// A `host:port` frontend from an env var value.
fn parse_frontend(value: &str) -> Option<(String, u16)> {
    let (host, port) = value.trim().rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port.parse().ok()?))
}

fn frontend_from_env(var: &str) -> Option<(String, u16)> {
    let value = std::env::var(var).ok()?;
    let parsed = parse_frontend(&value);
    if parsed.is_none() {
        tracing::warn!(%var, %value, "ignoring a load balancer frontend that is not host:port");
    }
    parsed
}

/// Where tasks' connections to load balancer addresses go: one route per
/// ALB address and listener port.
pub struct Routes {
    state: SharedElbv2State,
}

impl Routes {
    pub fn new(state: SharedElbv2State) -> Self {
        Self { state }
    }
}

/// The routes of `lb`'s listeners given the configured frontends: HTTPS and
/// TLS listeners go to `https`, HTTP listeners to `http`; without a frontend
/// they go to fakecloud's own data plane for the ALB (`None` host), when it
/// is bound.
fn lb_routes(
    lb: &LoadBalancer,
    listeners: &[(u16, String)],
    https: Option<&(String, u16)>,
    http: Option<&(String, u16)>,
) -> Vec<LbRoute> {
    if lb.state_code != "active" {
        return Vec::new();
    }
    let addresses: Vec<Ipv4Addr> = lb
        .interfaces
        .iter()
        .filter_map(|i| i.private_ip.parse().ok())
        .collect();
    let mut routes = Vec::new();
    for (port, protocol) in listeners {
        let frontend =
            if protocol.eq_ignore_ascii_case("HTTPS") || protocol.eq_ignore_ascii_case("TLS") {
                https
            } else {
                http
            };
        let (target_host, target_port) = match (frontend, lb.bound_port) {
            (Some((host, port)), _) => (Some(host.clone()), *port),
            (None, Some(bound)) => (None, bound),
            (None, None) => continue,
        };
        for address in &addresses {
            routes.push(LbRoute {
                address: *address,
                port: *port,
                target_host: target_host.clone(),
                target_port,
            });
        }
    }
    routes
}

impl Routes {
    /// The routes with the given HTTPS and HTTP frontends.
    pub(crate) fn routes_with(
        &self,
        https: Option<&(String, u16)>,
        http: Option<&(String, u16)>,
    ) -> Vec<LbRoute> {
        let accounts = self.state.read();
        let mut out = Vec::new();
        for (_, st) in accounts.iter() {
            for lb in st.load_balancers.values().filter(|lb| wants_interfaces(lb)) {
                let listeners: Vec<(u16, String)> = st
                    .listeners
                    .values()
                    .filter(|l| l.load_balancer_arn == lb.arn)
                    .filter_map(|l| {
                        Some((
                            u16::try_from(l.port?).ok()?,
                            l.protocol.clone().unwrap_or_else(|| "HTTP".to_string()),
                        ))
                    })
                    .collect();
                out.extend(lb_routes(lb, &listeners, https, http));
            }
        }
        out
    }
}

/// A frontend's host and port.
type Frontend = (String, u16);

/// The configured frontends (HTTPS, HTTP), read once.
fn frontends() -> &'static (Option<Frontend>, Option<Frontend>) {
    static FRONTENDS: std::sync::OnceLock<(Option<Frontend>, Option<Frontend>)> =
        std::sync::OnceLock::new();
    FRONTENDS.get_or_init(|| {
        (
            frontend_from_env(FRONTEND_HTTPS_ENV),
            frontend_from_env(FRONTEND_HTTP_ENV),
        )
    })
}

impl LbRouteSource for Routes {
    fn routes(&self) -> Vec<LbRoute> {
        let (https, http) = frontends();
        self.routes_with(https.as_ref(), http.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_description_is_elb_plus_the_arn_resource() {
        assert_eq!(
            interface_description(
                "arn:aws:elasticloadbalancing:ap-southeast-1:111122223333:loadbalancer/app/alb-internal/fd21de949b4d449a"
            ),
            "ELB app/alb-internal/fd21de949b4d449a"
        );
    }

    #[test]
    fn frontends_parse_as_host_port() {
        assert_eq!(
            parse_frontend("host.docker.internal:24443"),
            Some(("host.docker.internal".to_string(), 24443))
        );
        assert_eq!(parse_frontend("[::1]:443"), Some(("::1".to_string(), 443)));
        assert_eq!(parse_frontend("no-port"), None);
        assert_eq!(parse_frontend(":443"), None);
        assert_eq!(
            lb_name_of("DualStack.internal-a-1.elb.amazonaws.com."),
            "internal-a-1.elb.amazonaws.com"
        );
    }
}
