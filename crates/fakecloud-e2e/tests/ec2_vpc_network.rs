//! With `--dns`, an EC2 instance's network namespace behaves like the inside
//! of its VPC, as an ECS task's does, and fakecloud stays reachable from a
//! private subnet:
//!
//! - the instance's container holds the private IP DescribeInstances reports,
//!   inside its subnet, and reaches another instance of the subnet there;
//! - IMDS answers at `169.254.169.254` (IMDSv2 and IMDSv1) with the instance
//!   profile's credentials, from a private subnet;
//! - it resolves through the VPC's DNS server (a private zone's alias record
//!   to an internal ALB, internet names), and an ALB's HTTPS listener port
//!   reaches the configured frontend by name;
//! - the ALB's HTTP listener, forwarding to an `instance` target group,
//!   reaches a port another instance opened (fakecloud's own data plane, only
//!   reachable from containers where the host alias reaches the host's
//!   loopback: Docker Desktop, OrbStack, Podman machine on macOS);
//! - the opt-ins: `AWS_ENDPOINT_URL` / `AWS_REGION`, the extra CA bundle, and
//!   the host's container engine for an instance tagged for it.

mod helpers;

use std::time::Duration;

use aws_sdk_ec2::types::{IamInstanceProfileSpecification, ResourceType, Tag, TagSpecification};
use aws_sdk_elasticloadbalancingv2::types::{
    Action, ActionTypeEnum, Certificate, LoadBalancerSchemeEnum, ProtocolEnum, TargetDescription,
    TargetTypeEnum,
};
use aws_sdk_route53::types::{
    AliasTarget, Change, ChangeAction, ChangeBatch, HostedZoneConfig, ResourceRecordSet, RrType,
    Vpc, VpcRegion,
};
use base64::Engine;
use helpers::TestServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const IMAGE: &str = "public.ecr.aws/docker/library/busybox:1.36";

const CA: &str =
    "-----BEGIN CERTIFICATE-----\nZmFrZWNsb3VkIHRlc3QgY2E=\n-----END CERTIFICATE-----\n";

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

/// `docker exec <container> sh -c <script>`: stdout, or `None` on failure.
fn exec(container: &str, script: &str) -> Option<String> {
    let out = std::process::Command::new("docker")
        .args(["exec", container, "sh", "-c", script])
        .output()
        .expect("spawn docker");
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The container backing an instance, via the `fakecloud-ec2=<id>` label.
fn container_for(instance_id: &str) -> String {
    let out = std::process::Command::new("docker")
        .args([
            "ps",
            "-q",
            "--filter",
            &format!("label=fakecloud-ec2={instance_id}"),
        ])
        .output()
        .expect("spawn docker");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

async fn free_udp_port() -> u16 {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
    sock.local_addr().unwrap().port()
}

/// A plain HTTP server on all interfaces answering `frontend host=<Host>`.
async fn spawn_frontend() -> u16 {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = conn.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
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
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = conn.write_all(resp.as_bytes()).await;
            });
        }
    });
    port
}

/// Poll `probe` once a second until it returns `Some`, for up to `secs`.
async fn eventually<T>(secs: u64, mut probe: impl FnMut() -> Option<T>) -> Option<T> {
    for _ in 0..secs {
        if let Some(v) = probe() {
            return Some(v);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    None
}

/// The instance's private IP once it is `running` with its container.
async fn running_ip(ec2: &aws_sdk_ec2::Client, id: &str) -> String {
    for _ in 0..240 {
        let d = ec2
            .describe_instances()
            .instance_ids(id)
            .send()
            .await
            .unwrap();
        let inst = d
            .reservations()
            .iter()
            .flat_map(|r| r.instances())
            .find(|i| i.instance_id() == Some(id))
            .cloned();
        if let Some(inst) = inst {
            if inst.state().and_then(|s| s.name()).map(|n| n.as_str()) == Some("running")
                && !container_for(id).is_empty()
            {
                return inst.private_ip_address().unwrap_or_default().to_string();
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("instance {id} never ran");
}

fn ip_in_24(ip: &str, prefix: &str) -> bool {
    ip.strip_prefix(prefix)
        .and_then(|o| o.parse::<u8>().ok())
        .is_some_and(|o| (4..=254).contains(&o))
}

// Multi-threaded: the checks run `docker exec` synchronously, and the
// frontend the instance calls has to keep answering meanwhile.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn instance_in_a_private_subnet_is_inside_its_vpc() {
    if !require_docker_or_skip("instance_in_a_private_subnet_is_inside_its_vpc") {
        return;
    }
    let frontend = spawn_frontend().await;
    let dns_port = free_udp_port().await;
    let ca_dir = tempfile::tempdir().unwrap();
    let ca_path = ca_dir.path().join("edge-ca.pem");
    std::fs::write(&ca_path, CA).unwrap();
    let frontend_env = format!("host.docker.internal:{frontend}");
    let server = TestServer::start_full(
        &[
            ("FAKECLOUD_ELBV2_FRONTEND_HTTPS", frontend_env.as_str()),
            ("FAKECLOUD_EC2_DEFAULT_IMAGE", IMAGE),
            ("FAKECLOUD_EC2_AWS_ENV", "1"),
            ("FAKECLOUD_EC2_EXTRA_CA", ca_path.to_str().unwrap()),
        ],
        &["--dns", "--dns-addr", &format!("0.0.0.0:{dns_port}")],
    )
    .await;
    let ec2 = server.ec2_client().await;
    let elb = server.elbv2_client().await;
    let iam = server.iam_client().await;

    // A VPC whose two subnets have no route to an internet gateway.
    let vpc = ec2
        .create_vpc()
        .cidr_block("10.93.0.0/16")
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
        ("10.93.4.0/24", "us-east-1a"),
        ("10.93.5.0/24", "us-east-1b"),
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

    // An internal ALB: HTTPS goes to the frontend, HTTP to an instance
    // target group on port 8080.
    let lb = elb
        .create_load_balancer()
        .name("app")
        .scheme(LoadBalancerSchemeEnum::Internal)
        .subnets(&subnets[0])
        .subnets(&subnets[1])
        .send()
        .await
        .unwrap()
        .load_balancers()[0]
        .clone();
    let lb_arn = lb.load_balancer_arn().unwrap().to_string();
    let tg_arn = elb
        .create_target_group()
        .name("app-instances")
        .protocol(ProtocolEnum::Http)
        .port(8080)
        .vpc_id(&vpc)
        .target_type(TargetTypeEnum::Instance)
        .health_check_path("/")
        .health_check_interval_seconds(5)
        .healthy_threshold_count(2)
        .send()
        .await
        .unwrap()
        .target_groups()[0]
        .target_group_arn()
        .unwrap()
        .to_string();
    elb.create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Https)
        .port(443)
        .certificates(
            Certificate::builder()
                .certificate_arn("arn:aws:acm:us-east-1:123456789012:certificate/edge")
                .build(),
        )
        .default_actions(
            Action::builder()
                .r#type(ActionTypeEnum::Forward)
                .target_group_arn(&tg_arn)
                .build(),
        )
        .send()
        .await
        .unwrap();
    elb.create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Http)
        .port(80)
        .default_actions(
            Action::builder()
                .r#type(ActionTypeEnum::Forward)
                .target_group_arn(&tg_arn)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let zone = server
        .route53_client()
        .await
        .create_hosted_zone()
        .name("int.example.test")
        .caller_reference("ec2-vpc-network")
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
    server
        .route53_client()
        .await
        .change_resource_record_sets()
        .hosted_zone_id(&zone)
        .change_batch(
            ChangeBatch::builder()
                .changes(
                    Change::builder()
                        .action(ChangeAction::Upsert)
                        .resource_record_set(
                            ResourceRecordSet::builder()
                                .name("app.int.example.test")
                                .r#type(RrType::A)
                                .alias_target(
                                    AliasTarget::builder()
                                        .hosted_zone_id(lb.canonical_hosted_zone_id().unwrap())
                                        .dns_name(lb.dns_name().unwrap())
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
        .unwrap();
    let mut alb_ips: Vec<String> = ec2
        .describe_network_interfaces()
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name("description")
                .values(format!(
                    "ELB {}",
                    lb_arn.split_once(":loadbalancer/").unwrap().1
                ))
                .build(),
        )
        .send()
        .await
        .unwrap()
        .network_interfaces()
        .iter()
        .map(|e| e.private_ip_address().unwrap().to_string())
        .collect();
    alb_ips.sort();
    assert_eq!(alb_ips.len(), 2, "{alb_ips:?}");

    // The instance profile.
    iam.create_role()
        .role_name("builder")
        .assume_role_policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#,
        )
        .send()
        .await
        .unwrap();
    iam.create_instance_profile()
        .instance_profile_name("builder")
        .send()
        .await
        .unwrap();
    iam.add_role_to_instance_profile()
        .instance_profile_name("builder")
        .role_name("builder")
        .send()
        .await
        .unwrap();

    // `web` serves port 8080 from user-data and records what user-data saw;
    // `build` is tagged for the host's container engine.
    let user_data = base64::engine::general_purpose::STANDARD.encode(
        "mkdir -p /www && echo web-says-hi > /www/index.html && httpd -p 8080 -h /www\n\
         echo \"$AWS_ENDPOINT_URL $AWS_REGION\" > /tmp/user-data-env\n",
    );
    let launch = |name: &str, user_data: Option<String>, tags: &[(&str, &str)]| {
        let mut spec = TagSpecification::builder()
            .resource_type(ResourceType::Instance)
            .tags(Tag::builder().key("Name").value(name).build());
        for (k, v) in tags {
            spec = spec.tags(Tag::builder().key(*k).value(*v).build());
        }
        ec2.run_instances()
            .image_id("ami-12345678")
            .min_count(1)
            .max_count(1)
            .subnet_id(&subnets[0])
            .set_user_data(user_data)
            .iam_instance_profile(
                IamInstanceProfileSpecification::builder()
                    .name("builder")
                    .build(),
            )
            .tag_specifications(spec.build())
            .send()
    };
    let web = launch("web", Some(user_data), &[])
        .await
        .unwrap()
        .instances()[0]
        .instance_id()
        .unwrap()
        .to_string();
    let build = launch("build", None, &[("fakecloud:container-engine", "host")])
        .await
        .unwrap()
        .instances()[0]
        .instance_id()
        .unwrap()
        .to_string();
    let web_ip = running_ip(&ec2, &web).await;
    let build_ip = running_ip(&ec2, &build).await;
    let (web_c, build_c) = (container_for(&web), container_for(&build));
    elb.register_targets()
        .target_group_arn(&tg_arn)
        .targets(TargetDescription::builder().id(&web).port(8080).build())
        .send()
        .await
        .unwrap();

    // IMDS, the VPC rules and the load balancer map are in place once the
    // boot is released.
    for c in [&web_c, &build_c] {
        eventually(120, || {
            exec(c, "test -e /run/fakecloud/imds-ready").map(|_| ())
        })
        .await
        .unwrap_or_else(|| panic!("{c} never got IMDS"));
    }

    // Addresses: what DescribeInstances reports, inside the subnet, and the
    // two instances reach each other there.
    assert!(ip_in_24(&web_ip, "10.93.4."), "{web_ip}");
    assert!(ip_in_24(&build_ip, "10.93.4."), "{build_ip}");
    assert_ne!(web_ip, build_ip);
    for (c, ip) in [(&web_c, &web_ip), (&build_c, &build_ip)] {
        let addrs = exec(c, "ip -4 -o addr show").unwrap();
        assert!(addrs.contains(&format!("inet {ip}/24")), "{addrs}");
    }
    assert!(
        exec(&build_c, &format!("ping -c 1 -W 3 {web_ip}")).is_some(),
        "instances in one subnet must reach each other"
    );

    // IMDSv2 (token, then the role's credentials) and IMDSv1. The token
    // request is the one `curl -X PUT` sends: HTTP/1.1, no body. BusyBox `nc`
    // stops reading when its input ends, so the input stays open a while.
    let response = exec(
        &build_c,
        "(printf 'PUT /latest/api/token HTTP/1.1\\r\\nHost: 169.254.169.254\\r\\n\
         X-aws-ec2-metadata-token-ttl-seconds: 60\\r\\nConnection: close\\r\\n\\r\\n'; sleep 3) \
         | nc -w 5 169.254.169.254 80",
    )
    .unwrap_or_default();
    let (head, token) = response.split_once("\r\n\r\n").unwrap_or_default();
    assert!(
        head.starts_with("HTTP/1.1 200") && !token.trim().is_empty(),
        "no IMDSv2 token: {response:?}"
    );
    let token = token.trim();
    let creds = exec(
        &build_c,
        &format!(
            "wget -q -T 5 -O - --header 'X-aws-ec2-metadata-token: {token}' \
             http://169.254.169.254/latest/meta-data/iam/security-credentials/builder"
        ),
    )
    .expect("role credentials over IMDSv2");
    let creds: serde_json::Value = serde_json::from_str(&creds).expect(&creds);
    assert_eq!(creds["Code"], "Success");
    assert!(creds["AccessKeyId"].as_str().is_some_and(|k| !k.is_empty()));
    assert_eq!(
        exec(
            &build_c,
            "wget -q -T 5 -O - http://169.254.169.254/latest/meta-data/local-ipv4"
        )
        .as_deref(),
        Some(build_ip.as_str())
    );

    // DNS through the VPC resolver: the alias to the ALB, internet names.
    let resolved = exec(
        &build_c,
        "nslookup app.int.example.test 2>/dev/null \
         | awk '$1 == \"Address:\" && $2 !~ /:/ {print $2}' | sort | tr '\\n' ' '",
    )
    .unwrap();
    assert_eq!(resolved.trim(), alb_ips.join(" "));
    assert!(
        exec(&build_c, "nslookup example.com >/dev/null 2>&1").is_some(),
        "internet names resolve"
    );
    // The HTTPS listener port reaches the frontend with the Host sent.
    let via_frontend = eventually(30, || {
        exec(
            &build_c,
            "wget -q -T 5 -O - http://app.int.example.test:443/",
        )
    })
    .await;
    assert_eq!(
        via_frontend.as_deref(),
        Some("frontend host=app.int.example.test:443")
    );
    // Out of the private subnet to the host (NAT, as for ECS tasks).
    assert!(
        exec(
            &build_c,
            &format!("wget -q -T 5 -O - http://host.docker.internal:{frontend}/")
        )
        .is_some(),
        "a private subnet reaches outside it"
    );
    // The HTTP listener: fakecloud's data plane, to `web`'s port.
    if cfg!(target_os = "macos") {
        let via_alb = eventually(120, || {
            exec(&build_c, "wget -q -T 5 -O - http://app.int.example.test/")
                .filter(|b| b.contains("web-says-hi"))
        })
        .await;
        assert!(
            via_alb.is_some(),
            "the ALB never reached the instance target"
        );
    }

    // The opt-ins.
    assert_eq!(
        eventually(30, || exec(&web_c, "cat /tmp/user-data-env"))
            .await
            .as_deref(),
        Some(format!("http://host.docker.internal:{} us-east-1", server.port()).as_str()),
        "user-data sees AWS_ENDPOINT_URL and AWS_REGION"
    );
    // The same, sourceable by a process started with a clean environment.
    assert_eq!(
        exec(
            &build_c,
            "env -i sh -c 'set -a; . /etc/fakecloud/aws.env; echo $AWS_ENDPOINT_URL $AWS_REGION'"
        )
        .as_deref(),
        Some(format!("http://host.docker.internal:{} us-east-1", server.port()).as_str())
    );
    assert_eq!(
        exec(&build_c, "echo $SSL_CERT_FILE").as_deref(),
        Some("/etc/fakecloud-ec2/ca-bundle.pem")
    );
    let bundle = exec(&build_c, "cat /etc/fakecloud-ec2/ca-bundle.pem").unwrap();
    assert!(bundle.ends_with(CA.trim_end()), "{bundle}");
    assert!(exec(&build_c, "test -S /var/run/docker.sock").is_some());
    assert!(exec(&web_c, "test -e /var/run/docker.sock").is_none());

    for id in [&web, &build] {
        let _ = ec2.terminate_instances().instance_ids(id).send().await;
    }
    eventually(30, || {
        (container_for(&web).is_empty() && container_for(&build).is_empty()).then_some(())
    })
    .await;
    let _ = std::process::Command::new("docker")
        .args(["network", "rm", &format!("fakecloud-subnet-{}", subnets[0])])
        .output();
}
