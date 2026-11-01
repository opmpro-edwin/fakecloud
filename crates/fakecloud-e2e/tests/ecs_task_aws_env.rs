//! A task container gets `AWS_ENDPOINT_URL` (fakecloud as the container
//! reaches it), `AWS_REGION` and `AWS_DEFAULT_REGION` (the task's region, as
//! on Fargate), so an unmodified task definition calls fakecloud. Values the
//! container definition sets win.

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

const PROBE: &str = "echo ENDPOINT=[$AWS_ENDPOINT_URL] REGION=[$AWS_REGION] \
                     DEFAULT_REGION=[$AWS_DEFAULT_REGION]; \
                     wget -qO- \"$AWS_ENDPOINT_URL/_fakecloud/health\" >/dev/null \
                     && echo ENDPOINT_REACHABLE";

/// Run a one-container task printing its AWS environment and return the
/// captured output once it stopped.
async fn run_probe_task(server: &TestServer, family: &str, environment: &[(&str, &str)]) -> String {
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
        .command("sh")
        .command("-c")
        .command(PROBE);
    for (name, value) in environment {
        container =
            container.environment(KeyValuePair::builder().name(*name).value(*value).build());
    }
    ecs.register_task_definition()
        .family(family)
        .container_definitions(container.build())
        .send()
        .await
        .unwrap();
    let run = ecs
        .run_task()
        .cluster(family)
        .task_definition(family)
        .send()
        .await
        .unwrap();
    let task_arn = run.tasks()[0].task_arn().unwrap().to_string();
    let task_id = task_arn.rsplit('/').next().unwrap().to_string();
    let mut last = None;
    for _ in 0..600 {
        let task = ecs
            .describe_tasks()
            .cluster(family)
            .tasks(&task_arn)
            .send()
            .await
            .unwrap()
            .tasks()[0]
            .clone();
        if task.last_status() == Some("STOPPED") {
            last = None;
            break;
        }
        last = Some(task);
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    if let Some(task) = last {
        panic!("task never stopped: {}", helpers::ecs_task_summary(&task));
    }
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
    logs["logs"].as_str().unwrap_or_default().to_string()
}

#[tokio::test]
async fn task_gets_fakecloud_endpoint_and_region() {
    if !require_docker_or_skip("task_gets_fakecloud_endpoint_and_region") {
        return;
    }
    // The server's default region differs from the task's (the client's
    // us-east-1): the container gets the task's region, as on Fargate.
    let server = TestServer::start_with_env(&[("FAKECLOUD_REGION", "ap-southeast-1")]).await;

    let logs = run_probe_task(&server, "aws-env-default", &[]).await;
    let port = server.port();
    assert!(
        logs.contains(&format!(
            "ENDPOINT=[http://host.docker.internal:{port}] REGION=[us-east-1] \
             DEFAULT_REGION=[us-east-1]"
        )) || logs.contains(&format!(
            "ENDPOINT=[http://host.containers.internal:{port}] REGION=[us-east-1] \
             DEFAULT_REGION=[us-east-1]"
        )),
        "{logs}"
    );
    assert!(logs.contains("ENDPOINT_REACHABLE"), "{logs}");

    // The container definition's own AWS_REGION wins; the others are filled.
    let logs = run_probe_task(
        &server,
        "aws-env-own-region",
        &[("AWS_REGION", "eu-west-1")],
    )
    .await;
    assert!(
        logs.contains("REGION=[eu-west-1] DEFAULT_REGION=[us-east-1]"),
        "{logs}"
    );
    assert!(logs.contains("ENDPOINT_REACHABLE"), "{logs}");
}
