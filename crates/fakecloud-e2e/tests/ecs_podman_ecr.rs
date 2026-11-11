//! ECR -> ECS under the podman backend (issue #2585). fakecloud rewrites an
//! AWS ECR URI to its own plain-HTTP registry at `127.0.0.1:<port>`. Docker
//! treats a loopback registry as insecure on its own; podman does not, so the
//! task's pull failed with "server gave HTTP response to HTTPS client" until
//! the runtime passed `--tls-verify=false` for fakecloud's registry.
//!
//! Also: task-role credentials at the ECS agent's link-local address under
//! podman (issue #2629).
//!
//! Runs in the podman E2E partition, which installs podman. Per the project's
//! no-silent-skip rule it hard-fails when podman is unavailable.

mod helpers;

use std::process::Stdio;
use std::time::Duration;

use aws_sdk_ecs::types::ContainerDefinition;
use base64::Engine;
use helpers::TestServer;
use tokio::process::Command;

const SEED_IMAGE: &str = "public.ecr.aws/docker/library/alpine:3.20";
const AWS_ACCOUNT: &str = "123456789012";
const AWS_REGION: &str = "us-east-1";

fn require_podman() {
    let ok = std::process::Command::new("podman")
        .arg("info")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(
        ok,
        "podman is required for this test but `podman info` failed"
    );
}

/// The host fakecloud's registry is reached at from podman, and the server
/// env that makes the runtime rewrite ECR URIs to that host. On Linux podman
/// pulls on the host network, so `127.0.0.1` works. On macOS it pulls inside
/// the podman machine VM, where only `host.containers.internal` reaches the
/// host -- the rewrite fakecloud applies when told it runs in a container.
fn registry_host_and_env() -> (&'static str, Vec<(&'static str, &'static str)>) {
    let mut env = vec![("FAKECLOUD_CONTAINER_CLI", "podman")];
    if cfg!(target_os = "linux") {
        ("127.0.0.1", env)
    } else {
        env.push(("FAKECLOUD_IN_CONTAINER", "1"));
        ("host.containers.internal", env)
    }
}

async fn podman(args: &[&str]) -> std::process::Output {
    Command::new("podman")
        .args(args)
        .output()
        .await
        .expect("spawn podman")
}

async fn podman_ok(args: &[&str]) {
    let out = podman(args).await;
    assert!(
        out.status.success(),
        "podman {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Push the seed image to fakecloud ECR as `repo:tag` and return the AWS URI
/// a task definition references it by.
async fn seed_image(registry_host: &str, port: u16, repo: &str, tag: &str) -> String {
    let local_uri = format!("{registry_host}:{port}/{repo}:{tag}");

    let mut pulled = false;
    for attempt in 0..5u64 {
        if podman(&["image", "exists", SEED_IMAGE])
            .await
            .status
            .success()
            || podman(&["pull", "-q", SEED_IMAGE]).await.status.success()
        {
            pulled = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(5 * (attempt + 1))).await;
    }
    assert!(pulled, "could not pull seed image {SEED_IMAGE}");
    podman_ok(&["tag", SEED_IMAGE, &local_uri]).await;

    let auth_dir = tempfile::tempdir().expect("tempdir");
    let auth_file = auth_dir.path().join("auth.json");
    let auth = base64::engine::general_purpose::STANDARD.encode("AWS:fakecloud-seed");
    let config = serde_json::json!({
        "auths": { format!("{registry_host}:{port}"): { "auth": auth } }
    });
    std::fs::write(&auth_file, config.to_string()).expect("write auth file");
    podman_ok(&[
        "push",
        "--tls-verify=false",
        "--authfile",
        auth_file.to_str().unwrap(),
        &local_uri,
    ])
    .await;

    // Drop the local name so the task can only get the image from the
    // registry, which is the path under test.
    podman_ok(&["rmi", &local_uri]).await;

    format!("{AWS_ACCOUNT}.dkr.ecr.{AWS_REGION}.amazonaws.com/{repo}:{tag}")
}

fn port_from_endpoint(endpoint: &str) -> u16 {
    endpoint
        .rsplit(':')
        .next()
        .and_then(|p| p.trim_end_matches('/').parse().ok())
        .expect("port from endpoint")
}

#[tokio::test]
async fn ecs_task_pulls_ecr_image_with_podman() {
    require_podman();
    let (registry_host, env) = registry_host_and_env();
    let server = TestServer::start_with_env(&env).await;
    let port = port_from_endpoint(server.endpoint());

    server
        .ecr_client()
        .await
        .create_repository()
        .repository_name("podman-pull")
        .send()
        .await
        .expect("create_repository");
    let aws_uri = seed_image(registry_host, port, "podman-pull", "v1").await;

    let ecs = server.ecs_client().await;
    ecs.create_cluster()
        .cluster_name("podman-ecr")
        .send()
        .await
        .expect("create_cluster");
    ecs.register_task_definition()
        .family("podman-ecr-task")
        .container_definitions(
            ContainerDefinition::builder()
                .name("app")
                .image(&aws_uri)
                .essential(true)
                .entry_point("/bin/sh")
                .command("-c")
                .command("echo from-podman-ecr && exit 0")
                .build(),
        )
        .send()
        .await
        .expect("register_task_definition");

    let run = ecs
        .run_task()
        .cluster("podman-ecr")
        .task_definition("podman-ecr-task")
        .send()
        .await
        .expect("run_task");
    let arn = run.tasks()[0].task_arn().unwrap().to_string();
    let task_id = arn.rsplit('/').next().unwrap().to_string();

    let mut stopped = None;
    let mut last = None;
    for _ in 0..240 {
        let desc = ecs
            .describe_tasks()
            .cluster("podman-ecr")
            .tasks(&arn)
            .send()
            .await
            .expect("describe_tasks");
        let task = desc.tasks()[0].clone();
        if task.last_status() == Some("STOPPED") {
            stopped = Some(task);
            break;
        }
        last = Some(task);
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let task = stopped.unwrap_or_else(|| {
        panic!(
            "task did not reach STOPPED; last seen: {}",
            last.as_ref()
                .map(helpers::ecs_task_summary)
                .unwrap_or_default()
        )
    });
    assert_ne!(
        task.stop_code().map(|c| c.as_str()),
        Some("TaskFailedToStart"),
        "task failed to start: {:?}",
        task.stopped_reason()
    );

    let logs: serde_json::Value = reqwest::Client::new()
        .get(format!(
            "{}/_fakecloud/ecs/tasks/{task_id}/logs",
            server.endpoint()
        ))
        .send()
        .await
        .expect("fetch task logs")
        .json()
        .await
        .expect("task logs json");
    assert!(
        logs["logs"]
            .as_str()
            .unwrap_or_default()
            .contains("from-podman-ecr"),
        "task logs: {logs}"
    );
    assert_eq!(logs["exitCode"].as_i64(), Some(0), "task logs: {logs}");
}

/// Under podman too, a task-role container reaches its credentials at
/// `http://169.254.170.2` + the injected `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`
/// (the namespace holder routes the address to fakecloud), and the holder is
/// gone once the task stops.
#[tokio::test]
async fn ecs_task_role_credentials_at_link_local_address_with_podman() {
    require_podman();
    let (_, env) = registry_host_and_env();
    let server = TestServer::start_with_env(&env).await;
    let iam = server.iam_client().await;
    let role_arn = iam
        .create_role()
        .role_name("podman-task-role")
        .assume_role_policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#,
        )
        .send()
        .await
        .expect("create_role")
        .role()
        .unwrap()
        .arn()
        .to_string();

    let ecs = server.ecs_client().await;
    ecs.create_cluster()
        .cluster_name("podman-creds")
        .send()
        .await
        .expect("create_cluster");
    ecs.register_task_definition()
        .family("podman-creds-task")
        .task_role_arn(&role_arn)
        .container_definitions(
            ContainerDefinition::builder()
                .name("app")
                .image(SEED_IMAGE)
                .essential(true)
                .entry_point("/bin/sh")
                .command("-c")
                .command(
                    "echo RELATIVE_URI=[$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI]; \
                     wget -qO- \"http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI\" \
                     | grep -o '\"RoleArn\":\"[^\"]*\"'; \
                     echo META_URI_V4=[$ECS_CONTAINER_METADATA_URI_V4]; \
                     wget -qO- \"$ECS_CONTAINER_METADATA_URI_V4\" >/dev/null && echo META=ok; \
                     wget -qO- \"$AWS_ENDPOINT_URL/_fakecloud/health\" >/dev/null && echo HOST_ALIAS=ok",
                )
                .build(),
        )
        .send()
        .await
        .expect("register_task_definition");

    let run = ecs
        .run_task()
        .cluster("podman-creds")
        .task_definition("podman-creds-task")
        .send()
        .await
        .expect("run_task");
    let arn = run.tasks()[0].task_arn().unwrap().to_string();
    let task_id = arn.rsplit('/').next().unwrap().to_string();

    // The first task-role task builds the credentials helper image, whose
    // build is bounded per attempt but may retry once after a stalled package
    // mirror (see `task_creds`), so allow well past one attempt.
    let mut stopped = None;
    let mut last = None;
    for _ in 0..600 {
        let desc = ecs
            .describe_tasks()
            .cluster("podman-creds")
            .tasks(&arn)
            .send()
            .await
            .expect("describe_tasks");
        let task = desc.tasks()[0].clone();
        if task.last_status() == Some("STOPPED") {
            stopped = Some(task);
            break;
        }
        last = Some(task);
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let task = stopped.unwrap_or_else(|| {
        panic!(
            "task did not reach STOPPED; last seen: {}",
            last.as_ref()
                .map(helpers::ecs_task_summary)
                .unwrap_or_default()
        )
    });
    assert_ne!(
        task.stop_code().map(|c| c.as_str()),
        Some("TaskFailedToStart"),
        "task failed to start: {}",
        helpers::ecs_task_summary(&task)
    );

    let logs: serde_json::Value = reqwest::Client::new()
        .get(format!(
            "{}/_fakecloud/ecs/tasks/{task_id}/logs",
            server.endpoint()
        ))
        .send()
        .await
        .expect("fetch task logs")
        .json()
        .await
        .expect("task logs json");
    let text = logs["logs"].as_str().unwrap_or_default();
    assert!(
        text.contains(&format!("RELATIVE_URI=[/v2/credentials/{task_id}]")),
        "task logs: {logs}"
    );
    assert!(
        text.contains(&format!("\"RoleArn\":\"{role_arn}\"")),
        "task logs: {logs}"
    );
    // Task metadata comes from the agent's address, as on ECS.
    assert!(
        text.contains(&format!("META_URI_V4=[http://169.254.170.2/v4/{task_id}]")),
        "task logs: {logs}"
    );
    assert!(text.contains("META=ok"), "task logs: {logs}");
    // The host alias still resolves inside the holder's namespace.
    assert!(text.contains("HOST_ALIAS=ok"), "task logs: {logs}");

    let holders = podman(&[
        "ps",
        "-a",
        "--filter",
        &format!("label=fakecloud-ecs-task={task_id}"),
        "--format",
        "{{.Names}}",
    ])
    .await;
    assert_eq!(
        String::from_utf8_lossy(&holders.stdout).trim(),
        "",
        "task containers left behind"
    );
}
