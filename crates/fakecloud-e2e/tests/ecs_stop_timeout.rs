//! ECS container `stopTimeout`: StopTask sends each container its stop
//! signal and kills it after its own stop timeout (30 s when unset), in the
//! background -- StopTask returns at once and the task shows `STOPPING`
//! until its containers have stopped.

mod helpers;

use std::time::{Duration, Instant};

use aws_sdk_ecs::types::ContainerDefinition;
use helpers::TestServer;

const IMAGE: &str = "public.ecr.aws/docker/library/alpine:3.20";

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

/// Register `family` with one essential container running `script`, with
/// `stop_timeout` when given, and run it on `cluster`. Returns the task ARN.
async fn run(
    ecs: &aws_sdk_ecs::Client,
    cluster: &str,
    family: &str,
    script: &str,
    stop_timeout: Option<i32>,
) -> String {
    ecs.create_cluster()
        .cluster_name(cluster)
        .send()
        .await
        .unwrap();
    let mut container = ContainerDefinition::builder()
        .name("app")
        .image(IMAGE)
        .essential(true)
        .command("sh")
        .command("-c")
        .command(script);
    if let Some(secs) = stop_timeout {
        container = container.stop_timeout(secs);
    }
    ecs.register_task_definition()
        .family(family)
        .container_definitions(container.build())
        .send()
        .await
        .unwrap();
    ecs.run_task()
        .cluster(cluster)
        .task_definition(family)
        .send()
        .await
        .unwrap()
        .tasks()[0]
        .task_arn()
        .unwrap()
        .to_string()
}

async fn describe(ecs: &aws_sdk_ecs::Client, cluster: &str, arn: &str) -> aws_sdk_ecs::types::Task {
    ecs.describe_tasks()
        .cluster(cluster)
        .tasks(arn)
        .send()
        .await
        .unwrap()
        .tasks()[0]
        .clone()
}

/// Poll until the task's `lastStatus` is `want`; panics after `within`.
async fn wait_status(
    ecs: &aws_sdk_ecs::Client,
    cluster: &str,
    arn: &str,
    want: &str,
    within: Duration,
) -> aws_sdk_ecs::types::Task {
    let deadline = Instant::now() + within;
    loop {
        let task = describe(ecs, cluster, arn).await;
        if task.last_status() == Some(want) {
            return task;
        }
        assert!(
            Instant::now() < deadline,
            "task never reached {want}: {:?} ({:?})",
            task.last_status(),
            task.stopped_reason()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn stop(ecs: &aws_sdk_ecs::Client, cluster: &str, arn: &str) -> Duration {
    let started = Instant::now();
    ecs.stop_task()
        .cluster(cluster)
        .task(arn)
        .send()
        .await
        .unwrap();
    started.elapsed()
}

/// A container that ignores SIGTERM (a shell as PID 1 with no handler) is
/// killed after its own `stopTimeout`, not a fixed 10 s.
#[tokio::test]
async fn container_ignoring_sigterm_is_killed_after_its_stop_timeout() {
    if !require_docker_or_skip("container_ignoring_sigterm_is_killed_after_its_stop_timeout") {
        return;
    }
    let server = TestServer::start().await;
    let ecs = server.ecs_client().await;
    let arn = run(
        &ecs,
        "st-ignore",
        "st-ignore",
        "while :; do sleep 1; done",
        Some(3),
    )
    .await;
    wait_status(&ecs, "st-ignore", &arn, "RUNNING", Duration::from_secs(120)).await;

    let stop_call = stop(&ecs, "st-ignore", &arn).await;
    let stopping_from = Instant::now();
    assert!(
        stop_call < Duration::from_secs(2),
        "StopTask waited for the stop: {stop_call:?}"
    );
    let task = wait_status(&ecs, "st-ignore", &arn, "STOPPING", Duration::from_secs(2)).await;
    assert_eq!(task.desired_status(), Some("STOPPED"));
    let task = wait_status(&ecs, "st-ignore", &arn, "STOPPED", Duration::from_secs(20)).await;
    let took = stopping_from.elapsed();
    assert!(
        took >= Duration::from_millis(2800) && took < Duration::from_secs(9),
        "stopped after {took:?}, want ~3 s"
    );
    assert_eq!(task.containers()[0].exit_code(), Some(137), "SIGKILL");
}

/// Without `stopTimeout` the container gets the ECS default of 30 s, and
/// one that exits on SIGTERM stops at once.
#[tokio::test]
async fn default_stop_timeout_and_a_container_exiting_on_sigterm() {
    if !require_docker_or_skip("default_stop_timeout_and_a_container_exiting_on_sigterm") {
        return;
    }
    let server = TestServer::start().await;
    let ecs = server.ecs_client().await;
    let arn = run(
        &ecs,
        "st-term",
        "st-term",
        "trap 'exit 0' TERM; while :; do sleep 0.2; done",
        None,
    )
    .await;
    wait_status(&ecs, "st-term", &arn, "RUNNING", Duration::from_secs(120)).await;

    let task_id = arn.rsplit('/').next().unwrap();
    let out = std::process::Command::new("docker")
        .args(["inspect", "-f", "{{.Config.StopTimeout}}"])
        .arg(format!("{task_id}-app"))
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "30",
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stop_call = stop(&ecs, "st-term", &arn).await;
    assert!(stop_call < Duration::from_secs(2), "{stop_call:?}");
    let stopping_from = Instant::now();
    let task = wait_status(&ecs, "st-term", &arn, "STOPPED", Duration::from_secs(10)).await;
    let took = stopping_from.elapsed();
    assert!(took < Duration::from_secs(5), "stopped after {took:?}");
    assert_eq!(
        task.containers()[0].exit_code(),
        Some(0),
        "exited on SIGTERM"
    );
}
