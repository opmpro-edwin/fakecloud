//! `FAKECLOUD_ECS_EXTRA_CA` gives every task container a CA bundle (the
//! image's system roots plus that CA) at `/etc/fakecloud-ecs/ca-bundle.pem`,
//! readable by any user, and `SSL_CERT_FILE` pointing at it unless the task
//! definition sets its own.

mod helpers;

use std::time::Duration;

use aws_sdk_ecs::types::{ContainerDefinition, KeyValuePair};
use helpers::TestServer;

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

const EXTRA_CA: &str =
    "-----BEGIN CERTIFICATE-----\nZmFrZWNsb3VkLWVjcy1leHRyYS1jYQ==\n-----END CERTIFICATE-----\n";

const PROBE: &str = r#"
echo "SSL=[$SSL_CERT_FILE]"
echo "ROOTS=$(grep -c 'BEGIN CERTIFICATE' /etc/fakecloud-ecs/ca-bundle.pem)"
grep -q 'ZmFrZWNsb3VkLWVjcy1leHRyYS1jYQ==' /etc/fakecloud-ecs/ca-bundle.pem && echo HAS_EXTRA_CA
echo "USER=$(id -un)"
"#;

async fn run_task(server: &TestServer, family: &str, env: &[(&str, &str)]) -> String {
    let ecs = server.ecs_client().await;
    ecs.create_cluster()
        .cluster_name(family)
        .send()
        .await
        .unwrap();
    let mut container = ContainerDefinition::builder()
        .name("probe")
        .image("public.ecr.aws/docker/library/alpine:3.20")
        .essential(true)
        .user("nobody")
        .command("sh")
        .command("-c")
        .command(PROBE);
    for (name, value) in env {
        container =
            container.environment(KeyValuePair::builder().name(*name).value(*value).build());
    }
    ecs.register_task_definition()
        .family(family)
        .container_definitions(container.build())
        .send()
        .await
        .unwrap();
    let task_arn = ecs
        .run_task()
        .cluster(family)
        .task_definition(family)
        .send()
        .await
        .unwrap()
        .tasks()[0]
        .task_arn()
        .unwrap()
        .to_string();
    let task_id = task_arn.rsplit('/').next().unwrap().to_string();
    let stopped = helpers::wait_until(Duration::from_secs(300), || async {
        let task = ecs
            .describe_tasks()
            .cluster(family)
            .tasks(&task_arn)
            .send()
            .await
            .unwrap()
            .tasks()[0]
            .clone();
        (task.last_status() == Some("STOPPED")).then_some(task)
    })
    .await
    .expect("task never stopped");
    let logs: serde_json::Value = reqwest::Client::new()
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
    let logs = logs["logs"].as_str().unwrap_or_default().to_string();
    assert!(
        logs.contains("USER=nobody"),
        "{} {logs}",
        helpers::ecs_task_summary(&stopped)
    );
    logs
}

#[tokio::test]
async fn task_containers_get_the_extra_ca_with_the_image_roots() {
    if !require_docker_or_skip("task_containers_get_the_extra_ca_with_the_image_roots") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("root.crt");
    std::fs::write(&ca, EXTRA_CA).unwrap();
    let server =
        TestServer::start_with_env(&[("FAKECLOUD_ECS_EXTRA_CA", ca.to_str().unwrap())]).await;

    let logs = run_task(&server, "extra-ca", &[]).await;
    assert!(
        logs.contains("SSL=[/etc/fakecloud-ecs/ca-bundle.pem]"),
        "{logs}"
    );
    assert!(logs.contains("HAS_EXTRA_CA"), "{logs}");
    // Alpine's own roots come first: many certificates, not just the one.
    let roots: usize = logs
        .lines()
        .find_map(|l| l.trim_start_matches("[probe] ").strip_prefix("ROOTS="))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(0);
    assert!(roots > 50, "{logs}");

    // The task definition's own SSL_CERT_FILE wins; the bundle is still there.
    let logs = run_task(&server, "extra-ca-own", &[("SSL_CERT_FILE", "/mine.pem")]).await;
    assert!(logs.contains("SSL=[/mine.pem]"), "{logs}");
    assert!(logs.contains("HAS_EXTRA_CA"), "{logs}");

    // The file is read at each task start: once it is gone, tasks start
    // without the bundle.
    std::fs::remove_file(&ca).unwrap();
    let logs = run_task(&server, "extra-ca-gone", &[]).await;
    assert!(logs.contains("SSL=[]"), "{logs}");
    assert!(!logs.contains("HAS_EXTRA_CA"), "{logs}");
}
