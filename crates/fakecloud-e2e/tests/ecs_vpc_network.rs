//! With `--dns`, an ECS task's network namespace behaves like the inside of
//! its VPC: it resolves through the VPC's DNS server (Route 53 private zones,
//! alias records to load balancers, load balancer names, internet names), and
//! a connection to an ALB's private address on a listener port reaches that
//! listener, including for an ALB created after the task started.
//!
//! The HTTPS listener goes to a frontend named by
//! `FAKECLOUD_ELBV2_FRONTEND_HTTPS` (here a plain HTTP server owned by the
//! test, which echoes the Host header it got); the HTTP listener falls back to
//! fakecloud's own ALB data plane, which listens on the host's loopback and is
//! only reachable from containers where the host alias reaches it (Docker
//! Desktop, OrbStack, Podman machine on macOS).

mod helpers;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aws_sdk_ecs::types::{
    AwsVpcConfiguration, ContainerDefinition, KeyValuePair, NetworkConfiguration, NetworkMode,
};
use aws_sdk_elasticloadbalancingv2::types::{
    Action, ActionTypeEnum, Certificate, FixedResponseActionConfig, LoadBalancerSchemeEnum,
    ProtocolEnum,
};
use aws_sdk_route53::types::{
    AliasTarget, Change, ChangeAction, ChangeBatch, HostedZoneConfig, ResourceRecordSet, RrType,
    Vpc, VpcRegion,
};
use helpers::TestServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn docker_available() -> bool {
    std::process::Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn require_docker_or_skip(test: &str) -> bool {
    if docker_available() {
        return true;
    }
    if std::env::var("CI").is_ok() {
        panic!("docker is required for {test} in CI");
    }
    eprintln!("skipping {test}: docker is not available");
    false
}

async fn free_udp_port() -> u16 {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
    sock.local_addr().unwrap().port()
}

/// What the task told the test through the frontend.
#[derive(Default)]
struct Signals {
    /// The task finished its first checks (`GET /ready`).
    ready: AtomicBool,
    /// The test created the late ALB (`GET /go` answers 200).
    go: AtomicBool,
}

/// A plain HTTP server on all interfaces answering `frontend host=<Host>`,
/// plus the `/ready` and `/go` signals between the task and the test (the
/// task's logs are only captured once it stops).
async fn spawn_frontend(signals: Arc<Signals>) -> u16 {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else {
                return;
            };
            let signals = signals.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = conn.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = request.split_whitespace().nth(1).unwrap_or("/");
                let status = match path {
                    "/ready" => {
                        signals.ready.store(true, Ordering::SeqCst);
                        "200 OK"
                    }
                    "/go" if !signals.go.load(Ordering::SeqCst) => "503 Service Unavailable",
                    _ => "200 OK",
                };
                let host = request
                    .lines()
                    .find_map(|l| {
                        l.strip_prefix("Host: ")
                            .or_else(|| l.strip_prefix("host: "))
                    })
                    .unwrap_or("-")
                    .trim()
                    .to_string();
                let body = format!("frontend host={host}\n");
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = conn.write_all(resp.as_bytes()).await;
            });
        }
    });
    port
}

struct Alb {
    arn: String,
    dns_name: String,
    zone_id: String,
}

async fn create_alb(server: &TestServer, name: &str, subnets: &[&str]) -> Alb {
    let elb = server.elbv2_client().await;
    let mut create = elb
        .create_load_balancer()
        .name(name)
        .scheme(LoadBalancerSchemeEnum::Internal);
    for s in subnets {
        create = create.subnets(*s);
    }
    let lb = create
        .send()
        .await
        .expect("create load balancer")
        .load_balancers()[0]
        .clone();
    let alb = Alb {
        arn: lb.load_balancer_arn().unwrap().to_string(),
        dns_name: lb.dns_name().unwrap().to_string(),
        zone_id: lb.canonical_hosted_zone_id().unwrap().to_string(),
    };
    // HTTPS -> the configured frontend; HTTP -> fakecloud's data plane.
    elb.create_listener()
        .load_balancer_arn(&alb.arn)
        .protocol(ProtocolEnum::Https)
        .port(443)
        .certificates(
            Certificate::builder()
                .certificate_arn("arn:aws:acm:us-east-1:123456789012:certificate/edge")
                .build(),
        )
        .default_actions(fixed_response(&format!("{name}-https")))
        .send()
        .await
        .expect("create https listener");
    elb.create_listener()
        .load_balancer_arn(&alb.arn)
        .protocol(ProtocolEnum::Http)
        .port(80)
        .default_actions(fixed_response(&format!("{name}-dataplane-ok")))
        .send()
        .await
        .expect("create http listener");
    alb
}

fn fixed_response(body: &str) -> Action {
    Action::builder()
        .r#type(ActionTypeEnum::FixedResponse)
        .fixed_response_config(
            FixedResponseActionConfig::builder()
                .status_code("200")
                .content_type("text/plain")
                .message_body(body)
                .build(),
        )
        .build()
}

async fn alias(server: &TestServer, zone: &str, name: &str, alb: &Alb) {
    server
        .route53_client()
        .await
        .change_resource_record_sets()
        .hosted_zone_id(zone)
        .change_batch(
            ChangeBatch::builder()
                .changes(
                    Change::builder()
                        .action(ChangeAction::Upsert)
                        .resource_record_set(
                            ResourceRecordSet::builder()
                                .name(name)
                                .r#type(RrType::A)
                                .alias_target(
                                    AliasTarget::builder()
                                        .hosted_zone_id(&alb.zone_id)
                                        .dns_name(format!("dualstack.{}", alb.dns_name))
                                        .evaluate_target_health(false)
                                        .build()
                                        .unwrap(),
                                )
                                .build()
                                .unwrap(),
                        )
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("create alias record");
}

/// The private IPs of an ALB's network interfaces, from EC2.
async fn alb_ips(server: &TestServer, alb: &Alb) -> Vec<String> {
    let resource = alb.arn.split_once(":loadbalancer/").unwrap().1;
    let enis = server
        .ec2_client()
        .await
        .describe_network_interfaces()
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name("description")
                .values(format!("ELB {resource}"))
                .build(),
        )
        .send()
        .await
        .expect("describe network interfaces");
    let mut ips: Vec<String> = enis
        .network_interfaces()
        .iter()
        .map(|e| {
            assert_eq!(e.requester_managed(), Some(true));
            e.private_ip_address().unwrap().to_string()
        })
        .collect();
    ips.sort();
    ips
}

const PROBE: &str = r#"
echo "RESOLV=[$(grep '^nameserver' /etc/resolv.conf | tr '\n' ' ')]"
echo "ALIAS=[$(nslookup app.int.example.test 2>/dev/null | awk '$1 == "Address:" && $2 !~ /:/ {print $2}' | sort | tr '\n' ' ')]"
echo "LBNAME=[$(nslookup "$ALB_DNS" 169.254.169.253 2>/dev/null | awk '$1 == "Address:" && $2 !~ /:/ {print $2}' | sort | tr '\n' ' ')]"
echo "VPCDNS=[$(nslookup app.int.example.test "$VPC_DNS" 2>/dev/null | awk '$1 == "Address:" && $2 !~ /:/ {print $2}' | sort | tr '\n' ' ')]"
nslookup example.com >/dev/null 2>&1 && echo INTERNET_RESOLVES
echo "BY_NAME=[$(wget -qO- http://app.int.example.test:443/ 2>&1)]"
for ip in $ALB_IPS; do echo "BY_IP $ip=[$(wget -qO- http://$ip:443/ 2>&1)]"; done
echo "DATAPLANE=[$(wget -qO- http://app.int.example.test/ 2>&1)]"
signal="http://host.docker.internal:$FRONTEND"
wget -qO- "$signal/ready" >/dev/null 2>&1
i=0
until wget -qO- "$signal/go" >/dev/null 2>&1 || [ $i -ge 180 ]; do i=$((i+1)); sleep 1; done
i=0
while [ $i -lt 30 ]; do
  out=$(wget -qO- http://late.int.example.test:443/ 2>/dev/null) && { echo "LATE=[$out]"; break; }
  i=$((i+1)); sleep 1
done
echo DONE
"#;

#[tokio::test]
async fn task_resolves_aliases_to_albs_and_reaches_their_listeners() {
    if !require_docker_or_skip("task_resolves_aliases_to_albs_and_reaches_their_listeners") {
        return;
    }
    let signals = Arc::new(Signals::default());
    let frontend = spawn_frontend(signals.clone()).await;
    let dns_port = free_udp_port().await;
    let frontend_env = format!("host.docker.internal:{frontend}");
    let server = TestServer::start_full(
        &[("FAKECLOUD_ELBV2_FRONTEND_HTTPS", frontend_env.as_str())],
        &["--dns", "--dns-addr", &format!("0.0.0.0:{dns_port}")],
    )
    .await;

    // A VPC with two subnets, an internal ALB in both, a private zone with an
    // alias record to it.
    let ec2 = server.ec2_client().await;
    let vpc = ec2
        .create_vpc()
        .cidr_block("10.40.0.0/16")
        .send()
        .await
        .unwrap()
        .vpc()
        .unwrap()
        .vpc_id()
        .unwrap()
        .to_string();
    let mut subnets = Vec::new();
    for (cidr, az) in [
        ("10.40.4.0/24", "us-east-1a"),
        ("10.40.5.0/24", "us-east-1b"),
    ] {
        subnets.push(
            ec2.create_subnet()
                .vpc_id(&vpc)
                .cidr_block(cidr)
                .availability_zone(az)
                .send()
                .await
                .unwrap()
                .subnet()
                .unwrap()
                .subnet_id()
                .unwrap()
                .to_string(),
        );
    }
    let alb = create_alb(&server, "app", &[&subnets[0], &subnets[1]]).await;
    assert!(
        alb.dns_name.starts_with("internal-app-"),
        "{}",
        alb.dns_name
    );
    let ips = alb_ips(&server, &alb).await;
    assert_eq!(ips.len(), 2, "{ips:?}");
    assert!(
        ips[0].starts_with("10.40.4.") && ips[1].starts_with("10.40.5."),
        "{ips:?}"
    );

    let zone = server
        .route53_client()
        .await
        .create_hosted_zone()
        .name("int.example.test")
        .caller_reference("vpc-network")
        .hosted_zone_config(HostedZoneConfig::builder().private_zone(true).build())
        .vpc(
            Vpc::builder()
                .vpc_id(&vpc)
                .vpc_region(VpcRegion::UsEast1)
                .build(),
        )
        .send()
        .await
        .unwrap()
        .hosted_zone()
        .unwrap()
        .id()
        .to_string();
    alias(&server, &zone, "app.int.example.test", &alb).await;

    // The introspection resolver answers the alias with the ALB's addresses.
    let resolved: serde_json::Value = reqwest::Client::new()
        .get(format!(
            "{}/_fakecloud/dns/resolve?name=app.int.example.test&type=A",
            server.endpoint()
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut answered: Vec<String> = resolved["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["value"].as_str().unwrap().to_string())
        .collect();
    answered.sort();
    assert_eq!(answered, ips, "{resolved}");

    // An awsvpc task in the first subnet.
    let ecs = server.ecs_client().await;
    ecs.create_cluster()
        .cluster_name("vpc-net")
        .send()
        .await
        .unwrap();
    let env = |name: &str, value: &str| KeyValuePair::builder().name(name).value(value).build();
    ecs.register_task_definition()
        .family("vpc-net")
        .network_mode(NetworkMode::Awsvpc)
        .container_definitions(
            ContainerDefinition::builder()
                .name("probe")
                .image("public.ecr.aws/docker/library/alpine:3.20")
                .essential(true)
                .command("sh")
                .command("-c")
                .command(PROBE)
                .environment(env("ALB_DNS", &alb.dns_name))
                .environment(env("ALB_IPS", &ips.join(" ")))
                .environment(env("VPC_DNS", "10.40.0.2"))
                .environment(env("FRONTEND", &frontend.to_string()))
                .build(),
        )
        .send()
        .await
        .unwrap();
    let task_arn = ecs
        .run_task()
        .cluster("vpc-net")
        .task_definition("vpc-net")
        .network_configuration(
            NetworkConfiguration::builder()
                .awsvpc_configuration(
                    AwsVpcConfiguration::builder()
                        .subnets(&subnets[0])
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap()
        .tasks()[0]
        .task_arn()
        .unwrap()
        .to_string();
    let task_id = task_arn.rsplit('/').next().unwrap().to_string();
    let logs = || async {
        let v: serde_json::Value = reqwest::Client::new()
            .get(format!(
                "{}/_fakecloud/ecs/tasks/{task_id}/logs",
                server.endpoint()
            ))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        v["logs"].as_str().unwrap_or_default().to_string()
    };

    // An ALB created after the task started is routed too: the task asks
    // for it once its first checks are done, and only then looks it up.
    let ready = helpers::wait_until(Duration::from_secs(300), || async {
        signals.ready.load(Ordering::SeqCst).then_some(())
    })
    .await;
    if ready.is_none() {
        let task = ecs
            .describe_tasks()
            .cluster("vpc-net")
            .tasks(&task_arn)
            .send()
            .await
            .unwrap()
            .tasks()[0]
            .clone();
        panic!(
            "task never got to the late ALB: {} logs: {}",
            helpers::ecs_task_summary(&task),
            logs().await
        );
    }
    let late = create_alb(&server, "late", &[&subnets[0]]).await;
    alias(&server, &zone, "late.int.example.test", &late).await;
    signals.go.store(true, Ordering::SeqCst);

    let done = helpers::wait_until(Duration::from_secs(120), || async {
        let l = logs().await;
        l.contains("DONE").then_some(l)
    })
    .await;
    let logs = done.unwrap_or_else(|| panic!("task never finished"));

    // DNS goes to the VPC resolver (Docker's embedded DNS on the per-task
    // network forwards to it from inside the namespace).
    assert!(
        logs.contains("RESOLV=[nameserver 127.0.0.11 ]")
            || logs.contains("RESOLV=[nameserver 10.40.0.2 ]"),
        "{logs}"
    );
    let ip_list = format!("[{} ]", ips.join(" "));
    assert!(logs.contains(&format!("ALIAS={ip_list}")), "{logs}");
    assert!(logs.contains(&format!("LBNAME={ip_list}")), "{logs}");
    assert!(logs.contains(&format!("VPCDNS={ip_list}")), "{logs}");
    assert!(logs.contains("INTERNET_RESOLVES"), "{logs}");
    // The HTTPS listener port reaches the frontend with the Host the client
    // sent, by name and by each address.
    assert!(
        logs.contains("BY_NAME=[frontend host=app.int.example.test:443"),
        "{logs}"
    );
    for ip in &ips {
        assert!(
            logs.contains(&format!("BY_IP {ip}=[frontend host={ip}:443")),
            "{logs}"
        );
    }
    assert!(
        logs.contains("LATE=[frontend host=late.int.example.test:443"),
        "{logs}"
    );
    // The HTTP listener port falls back to fakecloud's data plane, which
    // containers reach where the host alias reaches the host's loopback.
    if cfg!(target_os = "macos") {
        assert!(logs.contains("DATAPLANE=[app-dataplane-ok]"), "{logs}");
    }

    // Deleting an ALB gives its addresses back.
    server
        .elbv2_client()
        .await
        .delete_load_balancer()
        .load_balancer_arn(&late.arn)
        .send()
        .await
        .unwrap();
    assert!(alb_ips(&server, &late).await.is_empty());
}
