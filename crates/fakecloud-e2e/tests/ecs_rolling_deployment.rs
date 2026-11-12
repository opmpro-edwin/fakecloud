//! ECS rolling-update deployments with real containers behind an ALB:
//! the minimum healthy / maximum percent bounds, deployment completion, and
//! the deployment circuit breaker with rollback.

mod helpers;

use std::time::{Duration, Instant};

use aws_sdk_ecs::types::{
    AssignPublicIp, AwsVpcConfiguration, ContainerDefinition, DeploymentCircuitBreaker,
    DeploymentConfiguration, KeyValuePair, LoadBalancer, NetworkConfiguration, NetworkMode,
    PortMapping, Service,
};
use aws_sdk_elasticloadbalancingv2::types::{
    Action, ActionTypeEnum, LoadBalancerSchemeEnum, ProtocolEnum, TargetTypeEnum,
};
use helpers::TestServer;

const IMAGE: &str = "traefik/whoami:v1.10.3";
const CLUSTER: &str = "rolling";
const SERVICE: &str = "web";

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

struct Fixture {
    /// Keeps the server (and its containers) alive for the test.
    _server: TestServer,
    ecs: aws_sdk_ecs::Client,
}

/// A cluster, an internal ALB with an `ip` target group (health check `/`
/// every 5 s) and an awsvpc service of two `whoami` tasks behind it.
async fn service_behind_alb(breaker: Option<(bool, bool)>) -> Fixture {
    let server = TestServer::start().await;
    let ec2 = server.ec2_client().await;
    let ecs = server.ecs_client().await;
    let elbv2 = server.elbv2_client().await;

    let vpc = ec2
        .create_vpc()
        .cidr_block("10.40.0.0/16")
        .send()
        .await
        .expect("create_vpc")
        .vpc()
        .unwrap()
        .vpc_id()
        .unwrap()
        .to_string();
    let subnet = ec2
        .create_subnet()
        .vpc_id(&vpc)
        .cidr_block("10.40.1.0/24")
        .send()
        .await
        .expect("create_subnet")
        .subnet()
        .unwrap()
        .subnet_id()
        .unwrap()
        .to_string();
    let lb_arn = elbv2
        .create_load_balancer()
        .name("rolling-alb")
        .scheme(LoadBalancerSchemeEnum::Internal)
        .send()
        .await
        .expect("create_load_balancer")
        .load_balancers()[0]
        .load_balancer_arn()
        .unwrap()
        .to_string();
    let tg_arn = elbv2
        .create_target_group()
        .name("rolling-tg")
        .protocol(ProtocolEnum::Http)
        .port(8080)
        .vpc_id(&vpc)
        .target_type(TargetTypeEnum::Ip)
        .health_check_path("/")
        .health_check_interval_seconds(5)
        .health_check_timeout_seconds(2)
        .healthy_threshold_count(2)
        .send()
        .await
        .expect("create_target_group")
        .target_groups()[0]
        .target_group_arn()
        .unwrap()
        .to_string();
    elbv2
        .create_listener()
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
        .expect("create_listener");

    ecs.create_cluster()
        .cluster_name(CLUSTER)
        .send()
        .await
        .expect("create_cluster");
    register(&ecs, &["--port", "8080"], "1").await;

    let mut config = DeploymentConfiguration::builder()
        .minimum_healthy_percent(100)
        .maximum_percent(200);
    if let Some((enable, rollback)) = breaker {
        config = config.deployment_circuit_breaker(
            DeploymentCircuitBreaker::builder()
                .enable(enable)
                .rollback(rollback)
                .build(),
        );
    }
    ecs.create_service()
        .cluster(CLUSTER)
        .service_name(SERVICE)
        .task_definition("web")
        .desired_count(2)
        .deployment_configuration(config.build())
        .load_balancers(
            LoadBalancer::builder()
                .target_group_arn(&tg_arn)
                .container_name("app")
                .container_port(8080)
                .build(),
        )
        .network_configuration(
            NetworkConfiguration::builder()
                .awsvpc_configuration(
                    AwsVpcConfiguration::builder()
                        .subnets(&subnet)
                        .assign_public_ip(AssignPublicIp::Disabled)
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .send()
        .await
        .expect("create_service");

    let fixture = Fixture {
        _server: server,
        ecs,
    };
    let svc = fixture
        .wait_until("the first deployment completes", 150, |s| {
            s.deployments().len() == 1
                && s.deployments()[0].rollout_state().map(|r| r.as_str()) == Some("COMPLETED")
                && s.running_count() == 2
        })
        .await;
    assert!(svc.task_definition().unwrap().ends_with("web:1"));
    fixture
}

/// Register the next revision of the `web` family running `command`.
async fn register(ecs: &aws_sdk_ecs::Client, command: &[&str], version: &str) {
    let mut container = ContainerDefinition::builder()
        .name("app")
        .image(IMAGE)
        .essential(true)
        .port_mappings(PortMapping::builder().container_port(8080).build())
        .environment(
            KeyValuePair::builder()
                .name("VERSION")
                .value(version)
                .build(),
        );
    for arg in command {
        container = container.command(*arg);
    }
    ecs.register_task_definition()
        .family("web")
        .network_mode(NetworkMode::Awsvpc)
        .container_definitions(container.build())
        .send()
        .await
        .expect("register_task_definition");
}

impl Fixture {
    async fn describe(&self) -> Service {
        self.ecs
            .describe_services()
            .cluster(CLUSTER)
            .services(SERVICE)
            .send()
            .await
            .expect("describe_services")
            .services()[0]
            .clone()
    }

    async fn deploy(&self, revision: &str) {
        self.ecs
            .update_service()
            .cluster(CLUSTER)
            .service(SERVICE)
            .task_definition(format!("web:{revision}"))
            .send()
            .await
            .expect("update_service");
    }

    async fn wait_until(
        &self,
        what: &str,
        timeout_secs: u64,
        mut done: impl FnMut(&Service) -> bool,
    ) -> Service {
        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        loop {
            let svc = self.describe().await;
            if done(&svc) {
                return svc;
            }
            if Instant::now() > deadline {
                panic!("timed out waiting until {what}: {}", summary(&svc));
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn delete(&self) {
        self.ecs
            .delete_service()
            .cluster(CLUSTER)
            .service(SERVICE)
            .force(true)
            .send()
            .await
            .ok();
    }
}

fn summary(svc: &Service) -> String {
    let deployments: Vec<String> = svc
        .deployments()
        .iter()
        .map(|d| {
            format!(
                "{} {} {} {:?} running={} pending={} failed={}",
                d.id().unwrap_or_default(),
                d.status().unwrap_or_default(),
                d.task_definition().unwrap_or_default(),
                d.rollout_state(),
                d.running_count(),
                d.pending_count(),
                d.failed_tasks()
            )
        })
        .collect();
    let events: Vec<&str> = svc
        .events()
        .iter()
        .take(8)
        .filter_map(|e| e.message())
        .collect();
    format!(
        "running={} pending={} deployments={deployments:?} events={events:?}",
        svc.running_count(),
        svc.pending_count()
    )
}

fn messages(svc: &Service) -> Vec<String> {
    svc.events()
        .iter()
        .filter_map(|e| e.message().map(str::to_string))
        .collect()
}

/// Tasks RUNNING in deployments other than those running `bad_revision`:
/// the tasks that can actually serve.
fn serving(svc: &Service, bad_revision: &str) -> i32 {
    svc.deployments()
        .iter()
        .filter(|d| {
            !d.task_definition()
                .unwrap_or_default()
                .ends_with(&format!("web:{bad_revision}"))
        })
        .map(|d| d.running_count())
        .sum()
}

#[tokio::test]
async fn good_deployment_completes_and_the_old_one_disappears() {
    if !require_docker_or_skip("good_deployment_completes_and_the_old_one_disappears") {
        return;
    }
    let f = service_behind_alb(Some((true, true))).await;
    register(&f.ecs, &["--port", "8080"], "2").await;
    f.deploy("2").await;

    let mut min_running = i32::MAX;
    let mut saw_both = false;
    let svc = f
        .wait_until("the new deployment completes", 180, |s| {
            min_running = min_running.min(s.running_count());
            saw_both |= s.deployments().len() == 2;
            let primary = &s.deployments()[0];
            s.deployments().len() == 1
                && primary
                    .task_definition()
                    .unwrap_or_default()
                    .ends_with("web:2")
                && primary.rollout_state().map(|r| r.as_str()) == Some("COMPLETED")
        })
        .await;
    assert!(saw_both, "the old deployment stays ACTIVE while it drains");
    assert!(min_running >= 2, "running count fell to {min_running}");
    assert_eq!(svc.running_count(), 2);
    assert!(svc.task_definition().unwrap().ends_with("web:2"));
    let primary = &svc.deployments()[0];
    assert_eq!(primary.status(), Some("PRIMARY"));
    assert_eq!(primary.failed_tasks(), 0);
    let id = primary.id().unwrap();
    assert_eq!(
        primary.rollout_state_reason(),
        Some(format!("ECS deployment {id} completed.").as_str())
    );
    let events = messages(&svc);
    assert!(events.contains(&format!(
        "(service {SERVICE}) (deployment {id}) deployment completed."
    )));
    assert!(events.contains(&format!("(service {SERVICE}) has reached a steady state.")));
    f.delete().await;
}

#[tokio::test]
async fn failing_deployment_trips_the_circuit_breaker_and_rolls_back() {
    if !require_docker_or_skip("failing_deployment_trips_the_circuit_breaker_and_rolls_back") {
        return;
    }
    let f = service_behind_alb(Some((true, true))).await;
    let good = f.describe().await.deployments()[0]
        .id()
        .unwrap()
        .to_string();
    register(&f.ecs, &["--this-flag-does-not-exist"], "2").await;
    f.deploy("2").await;

    let mut min_serving = i32::MAX;
    let mut failed_seen: Option<(String, i32, String)> = None;
    let svc = f
        .wait_until("the rollback completes", 240, |s| {
            min_serving = min_serving.min(serving(s, "2"));
            for d in s.deployments() {
                if d.rollout_state().map(|r| r.as_str()) == Some("FAILED") {
                    failed_seen = Some((
                        d.id().unwrap_or_default().to_string(),
                        d.failed_tasks(),
                        d.rollout_state_reason().unwrap_or_default().to_string(),
                    ));
                }
            }
            let primary = &s.deployments()[0];
            s.deployments().len() == 1
                && primary
                    .task_definition()
                    .unwrap_or_default()
                    .ends_with("web:1")
                && primary.rollout_state().map(|r| r.as_str()) == Some("COMPLETED")
        })
        .await;

    let (failed_id, failed_tasks, reason) = failed_seen.expect("the deployment was seen FAILED");
    assert_eq!(
        failed_tasks, 3,
        "the breaker trips at ceil(0.5 * 2) clamped to 3"
    );
    assert_eq!(
        reason,
        "ECS deployment circuit breaker: tasks failed to start."
    );
    assert!(min_serving >= 2, "serving tasks fell to {min_serving}");
    assert!(
        svc.task_definition().unwrap().ends_with("web:1"),
        "the service reverts"
    );
    assert_eq!(svc.running_count(), 2);
    let rollback = &svc.deployments()[0];
    assert_ne!(
        rollback.id(),
        Some(good.as_str()),
        "a new deployment rolls back"
    );
    let events = messages(&svc);
    assert!(events.contains(&format!(
        "(service {SERVICE}) (deployment {failed_id}) deployment failed: tasks failed to start."
    )));
    assert!(events.contains(&format!(
        "(service {SERVICE}) rolling back to deployment {good}."
    )));
    f.delete().await;
}

#[tokio::test]
async fn minimum_healthy_100_keeps_the_old_tasks_serving_a_failing_deployment() {
    if !require_docker_or_skip(
        "minimum_healthy_100_keeps_the_old_tasks_serving_a_failing_deployment",
    ) {
        return;
    }
    let f = service_behind_alb(None).await;
    let old_tasks: Vec<String> = f
        .ecs
        .list_tasks()
        .cluster(CLUSTER)
        .service_name(SERVICE)
        .send()
        .await
        .expect("list_tasks")
        .task_arns()
        .to_vec();
    assert_eq!(old_tasks.len(), 2);
    register(&f.ecs, &["--this-flag-does-not-exist"], "2").await;
    f.deploy("2").await;

    // Without the circuit breaker the deployment keeps retrying; the old
    // tasks keep serving the whole time.
    let started = Instant::now();
    let mut min_serving = i32::MAX;
    let mut last = f.describe().await;
    while started.elapsed() < Duration::from_secs(30) {
        last = f.describe().await;
        min_serving = min_serving.min(serving(&last, "2"));
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(min_serving >= 2, "serving tasks fell to {min_serving}");
    let primary = &last.deployments()[0];
    assert!(primary.task_definition().unwrap().ends_with("web:2"));
    assert_eq!(
        primary.rollout_state().map(|r| r.as_str()),
        Some("IN_PROGRESS")
    );
    assert!(primary.failed_tasks() >= 3, "{}", summary(&last));
    assert_eq!(last.deployments().len(), 2);
    assert_eq!(last.deployments()[1].running_count(), 2);
    let tasks = f
        .ecs
        .describe_tasks()
        .cluster(CLUSTER)
        .set_tasks(Some(old_tasks))
        .send()
        .await
        .expect("describe_tasks");
    assert!(
        tasks
            .tasks()
            .iter()
            .all(|t| t.last_status() == Some("RUNNING") && t.desired_status() == Some("RUNNING")),
        "the original tasks are never stopped"
    );
    f.delete().await;
}

/// A free host port for a bridge-mode `hostPort`.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// `(id, port, state)` of every target registered in `tg_arn`.
async fn target_health(
    elbv2: &aws_sdk_elasticloadbalancingv2::Client,
    tg_arn: &str,
) -> Vec<(String, i32, String)> {
    let mut out: Vec<_> = elbv2
        .describe_target_health()
        .target_group_arn(tg_arn)
        .send()
        .await
        .expect("describe_target_health")
        .target_health_descriptions()
        .iter()
        .map(|d| {
            let t = d.target().unwrap();
            (
                t.id().unwrap().to_string(),
                t.port().unwrap_or_default(),
                d.target_health()
                    .and_then(|h| h.state())
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default(),
            )
        })
        .collect();
    out.sort();
    out
}

/// Bridge-mode tasks all register as `127.0.0.1` and differ only by host
/// port, so the target group must key them by (id, port): the new task's
/// target is added beside the old one, and deregistering the old task's
/// target leaves the new one in place. The group is never empty.
#[tokio::test]
async fn bridge_deployment_keeps_each_tasks_target_and_never_empties_the_group() {
    if !require_docker_or_skip(
        "bridge_deployment_keeps_each_tasks_target_and_never_empties_the_group",
    ) {
        return;
    }
    let server = TestServer::start().await;
    let ec2 = server.ec2_client().await;
    let ecs = server.ecs_client().await;
    let elbv2 = server.elbv2_client().await;

    let vpc = ec2
        .create_vpc()
        .cidr_block("10.41.0.0/16")
        .send()
        .await
        .expect("create_vpc")
        .vpc()
        .unwrap()
        .vpc_id()
        .unwrap()
        .to_string();
    let lb_arn = elbv2
        .create_load_balancer()
        .name("bridge-alb")
        .scheme(LoadBalancerSchemeEnum::Internal)
        .send()
        .await
        .expect("create_load_balancer")
        .load_balancers()[0]
        .load_balancer_arn()
        .unwrap()
        .to_string();
    let tg_arn = elbv2
        .create_target_group()
        .name("bridge-tg")
        .protocol(ProtocolEnum::Http)
        .port(8080)
        .vpc_id(&vpc)
        .target_type(TargetTypeEnum::Instance)
        .health_check_path("/")
        .health_check_interval_seconds(5)
        .health_check_timeout_seconds(2)
        .healthy_threshold_count(2)
        .send()
        .await
        .expect("create_target_group")
        .target_groups()[0]
        .target_group_arn()
        .unwrap()
        .to_string();
    elbv2
        .create_listener()
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
        .expect("create_listener");
    ecs.create_cluster()
        .cluster_name(CLUSTER)
        .send()
        .await
        .expect("create_cluster");

    // Each revision publishes its own host port, as dynamic host ports would.
    let register_bridge = |host_port: u16, version: &'static str| {
        let ecs = ecs.clone();
        async move {
            ecs.register_task_definition()
                .family("web")
                .network_mode(NetworkMode::Bridge)
                .container_definitions(
                    ContainerDefinition::builder()
                        .name("app")
                        .image(IMAGE)
                        .essential(true)
                        .memory(128)
                        .port_mappings(
                            PortMapping::builder()
                                .container_port(8080)
                                .host_port(i32::from(host_port))
                                .build(),
                        )
                        .environment(
                            KeyValuePair::builder()
                                .name("VERSION")
                                .value(version)
                                .build(),
                        )
                        .command("--port")
                        .command("8080")
                        .build(),
                )
                .send()
                .await
                .expect("register_task_definition");
        }
    };
    let old_port = free_port();
    let new_port = loop {
        let port = free_port();
        if port != old_port {
            break port;
        }
    };
    register_bridge(old_port, "1").await;
    ecs.create_service()
        .cluster(CLUSTER)
        .service_name(SERVICE)
        .task_definition("web:1")
        .desired_count(1)
        .deployment_configuration(
            DeploymentConfiguration::builder()
                .minimum_healthy_percent(100)
                .maximum_percent(200)
                .build(),
        )
        .load_balancers(
            LoadBalancer::builder()
                .target_group_arn(&tg_arn)
                .container_name("app")
                .container_port(8080)
                .build(),
        )
        .send()
        .await
        .expect("create_service");
    let f = Fixture {
        _server: server,
        ecs: ecs.clone(),
    };

    let host = "127.0.0.1".to_string();
    let deadline = Instant::now() + Duration::from_secs(150);
    loop {
        let targets = target_health(&elbv2, &tg_arn).await;
        if targets == vec![(host.clone(), i32::from(old_port), "healthy".to_string())] {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "first task never became a healthy target: {targets:?}"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    register_bridge(new_port, "2").await;
    f.deploy("2").await;

    let mut saw_both = false;
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let targets = target_health(&elbv2, &tg_arn).await;
        assert!(
            !targets.is_empty(),
            "the target group went empty during the deployment: {}",
            summary(&f.describe().await)
        );
        let ports: Vec<i32> = targets.iter().map(|t| t.1).collect();
        saw_both |= ports.contains(&i32::from(old_port)) && ports.contains(&i32::from(new_port));
        let svc = f.describe().await;
        let done = svc.deployments().len() == 1
            && svc.deployments()[0]
                .task_definition()
                .unwrap_or_default()
                .ends_with("web:2")
            && svc.deployments()[0].rollout_state().map(|r| r.as_str()) == Some("COMPLETED");
        if done && targets == vec![(host.clone(), i32::from(new_port), "healthy".to_string())] {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "deployment never settled on the new target: {targets:?} {}",
            summary(&svc)
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(
        saw_both,
        "both tasks' targets are registered side by side during the deployment"
    );
    f.delete().await;
}
