//! EBS volumes mounted in instance containers E2E: with
//! `FAKECLOUD_EC2_MOUNT_VOLUMES` on, an attached volume appears in the
//! instance at its device name, what is written there stays with the volume
//! when the instance is terminated, and the next instance it is attached to
//! reads it back. Detaching unmounts it; deleting the volume removes its data.

mod helpers;

use aws_sdk_ec2::types::VolumeAttachmentState;
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
    eprintln!("Skipping {test}: docker not available");
    false
}

fn docker(args: &[&str]) -> String {
    let out = std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("spawn docker");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The running container backing an instance, via the `fakecloud-ec2=<id>`
/// label; empty while there is none.
fn container_for(instance_id: &str) -> String {
    docker(&[
        "ps",
        "-q",
        "--filter",
        &format!("label=fakecloud-ec2={instance_id}"),
    ])
}

/// Run `script` in the instance's container and return its output.
fn run_in(instance_id: &str, script: &str) -> String {
    docker(&["exec", &container_for(instance_id), "sh", "-c", script])
}

async fn launch(c: &aws_sdk_ec2::Client) -> (String, String) {
    let launched = c
        .run_instances()
        .image_id("ami-12345678")
        .min_count(1)
        .max_count(1)
        .send()
        .await
        .unwrap();
    let instance = launched.instances().first().unwrap();
    let id = instance.instance_id().unwrap().to_string();
    let zone = instance
        .placement()
        .and_then(|p| p.availability_zone())
        .unwrap()
        .to_string();
    for _ in 0..120 {
        if !container_for(&id).is_empty() {
            return (id, zone);
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    panic!("instance {id} never got a running container");
}

/// Wait until the volume's attachment is in `want`, or until it has none
/// when `want` is `None`.
async fn wait_attachment(
    c: &aws_sdk_ec2::Client,
    volume_id: &str,
    want: Option<VolumeAttachmentState>,
) {
    let mut seen = None;
    for _ in 0..240 {
        let described = c
            .describe_volumes()
            .volume_ids(volume_id)
            .send()
            .await
            .unwrap();
        let volume = described.volumes().first().unwrap();
        seen = volume
            .attachments()
            .first()
            .and_then(|a| a.state())
            .cloned();
        if seen == want {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    panic!("volume {volume_id} never got to {want:?}; it is {seen:?}");
}

async fn attach(c: &aws_sdk_ec2::Client, volume_id: &str, instance_id: &str) {
    c.attach_volume()
        .volume_id(volume_id)
        .instance_id(instance_id)
        .device("/dev/sdf")
        .send()
        .await
        .unwrap();
    wait_attachment(c, volume_id, Some(VolumeAttachmentState::Attached)).await;
}

#[tokio::test]
async fn an_attached_volume_carries_its_data_to_the_next_instance() {
    let test = "an_attached_volume_carries_its_data_to_the_next_instance";
    if !require_docker_or_skip(test) {
        return;
    }
    let server = TestServer::start_full(
        &[
            ("FAKECLOUD_EC2_DEFAULT_IMAGE", "alpine:3"),
            ("FAKECLOUD_EC2_MOUNT_VOLUMES", "1"),
        ],
        &[],
    )
    .await;
    let c = server.ec2_client().await;

    let (first, zone) = launch(&c).await;
    let volume_id = c
        .create_volume()
        .availability_zone(&zone)
        .size(1)
        .send()
        .await
        .unwrap()
        .volume_id()
        .unwrap()
        .to_string();

    // Attached, the volume is a directory at its device name.
    attach(&c, &volume_id, &first).await;
    assert_eq!(
        run_in(
            &first,
            "test -d /dev/sdf && echo kept > /dev/sdf/marker && cat /dev/sdf/marker"
        ),
        "kept"
    );

    // The instance goes; the volume stays, free, with what was written.
    c.terminate_instances()
        .instance_ids(&first)
        .send()
        .await
        .unwrap();
    wait_attachment(&c, &volume_id, None).await;

    let (second, _) = launch(&c).await;
    assert_eq!(
        run_in(&second, "cat /dev/sdf/marker 2>/dev/null || echo absent"),
        "absent"
    );
    attach(&c, &volume_id, &second).await;
    assert_eq!(run_in(&second, "cat /dev/sdf/marker"), "kept");

    // Detached, it is gone from the instance again.
    c.detach_volume()
        .volume_id(&volume_id)
        .send()
        .await
        .unwrap();
    wait_attachment(&c, &volume_id, None).await;
    for _ in 0..120 {
        if !container_for(&second).is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    assert_eq!(
        run_in(&second, "test -e /dev/sdf && echo present || echo absent"),
        "absent"
    );

    // Deleted, its data goes with it.
    c.delete_volume()
        .volume_id(&volume_id)
        .send()
        .await
        .unwrap();
    let label = format!("label=fakecloud-ebs={volume_id}");
    let mut left = String::new();
    for _ in 0..40 {
        left = docker(&["volume", "ls", "-q", "--filter", &label]);
        if left.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    assert!(left.is_empty(), "the volume's data is still there: {left}");

    c.terminate_instances()
        .instance_ids(&second)
        .send()
        .await
        .unwrap();
}
