//! What an instance container can get beyond what EC2 gives an instance,
//! each a fakecloud extension with no AWS equivalent (Docker / Podman).
//!
//! - **AWS SDK environment** (opt-in, `FAKECLOUD_EC2_AWS_ENV=1`). On EC2 an SDK
//!   finds the real endpoints by itself and the region through IMDS. A
//!   workload on a fakecloud instance has to call fakecloud instead, so with
//!   this set the container starts with `AWS_ENDPOINT_URL` (fakecloud as the
//!   instance reaches it) and `AWS_REGION` / `AWS_DEFAULT_REGION` (the
//!   instance's region), as ECS task containers do. They are the container's
//!   environment: PID 1 passes them to user-data, and `docker exec` gives them
//!   to every command. For a process started with a clean environment (`su
//!   -`, `env -i`, a service manager) the same lines are in [`AWS_ENV_PATH`],
//!   which a script can source (`set -a; . /etc/fakecloud/aws.env`). Off by
//!   default, since nothing sets them on EC2.
//! - **A trust bundle** (`FAKECLOUD_EC2_EXTRA_CA`, else the CA ECS tasks get
//!   from `FAKECLOUD_ECS_EXTRA_CA`). Locally the TLS in front of load balancers
//!   comes from a local CA; with one named, the container gets
//!   [`BUNDLE_PATH`] (the image's system roots plus that CA) and
//!   `SSL_CERT_FILE` pointing at it, as task containers do (see
//!   [`fakecloud_core::ca_bundle`]).
//! - **The host's container engine** (tag `fakecloud:container-engine` =
//!   `host`). A build host needs a container engine, which an instance
//!   container cannot run itself. An instance launched with the tag gets the
//!   engine socket of the host fakecloud runs its containers on, mounted at
//!   `/var/run/docker.sock`; the CLI is the user-data's to install. Containers
//!   it starts are siblings of the instance on that host, outside the
//!   instance's VPC and unknown to fakecloud, which neither tracks nor removes
//!   them. The tag is read when the container is created.

use std::collections::BTreeMap;

/// Opt-in for the AWS SDK environment.
const AWS_ENV_ENV: &str = "FAKECLOUD_EC2_AWS_ENV";

/// Directory of the sourceable copy of the AWS SDK environment.
pub(crate) const AWS_ENV_DIR: &str = "/etc/fakecloud";

/// Its file name in [`AWS_ENV_DIR`].
pub(crate) const AWS_ENV_FILE: &str = "aws.env";

/// The sourceable copy of the AWS SDK environment inside an instance.
pub(crate) const AWS_ENV_PATH: &str = "/etc/fakecloud/aws.env";

/// The instances' own extra CA.
pub(crate) const EXTRA_CA_ENV: &str = "FAKECLOUD_EC2_EXTRA_CA";

/// The tasks' extra CA, which instances trust too unless they have their own.
const ECS_EXTRA_CA_ENV: &str = "FAKECLOUD_ECS_EXTRA_CA";

/// Directory of the bundle inside an instance container.
pub(crate) const BUNDLE_DIR: &str = "/etc/fakecloud-ec2";

/// The bundle inside an instance container.
pub(crate) const BUNDLE_PATH: &str = "/etc/fakecloud-ec2/ca-bundle.pem";

/// The tag that gives an instance the host's container engine.
pub(crate) const CONTAINER_ENGINE_TAG: &str = "fakecloud:container-engine";

/// Overrides the engine socket mounted into instances tagged for it: its
/// path on the host the engine runs on.
const ENGINE_SOCKET_ENV: &str = "FAKECLOUD_EC2_HOST_ENGINE_SOCKET";

/// Where the engine socket appears inside the instance, where Docker clients
/// look by default.
const ENGINE_SOCKET_IN_INSTANCE: &str = "/var/run/docker.sock";

fn flag(env: &str) -> bool {
    std::env::var(env)
        .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes"))
        .unwrap_or(false)
}

/// The AWS SDK variables an instance starts with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AwsEnv(Vec<(&'static str, String)>);

impl AwsEnv {
    fn new(fakecloud_host: &str, fakecloud_port: u16, region: &str) -> Self {
        Self(vec![
            (
                "AWS_ENDPOINT_URL",
                format!("http://{fakecloud_host}:{fakecloud_port}"),
            ),
            ("AWS_REGION", region.to_string()),
            ("AWS_DEFAULT_REGION", region.to_string()),
        ])
    }

    /// The `-e` pairs that put them in the container's environment.
    pub(crate) fn args(&self) -> Vec<String> {
        self.0
            .iter()
            .flat_map(|(k, v)| ["-e".to_string(), format!("{k}={v}")])
            .collect()
    }

    /// [`AWS_ENV_PATH`]: one `NAME=value` line each, for `set -a; . file`.
    pub(crate) fn file(&self) -> String {
        self.0.iter().map(|(k, v)| format!("{k}={v}\n")).collect()
    }
}

/// The AWS SDK variables an instance starts with, when opted in.
pub(crate) fn aws_env(fakecloud_host: &str, fakecloud_port: u16, region: &str) -> Option<AwsEnv> {
    flag(AWS_ENV_ENV).then(|| AwsEnv::new(fakecloud_host, fakecloud_port, region))
}

/// The extra CA's PEM, read now: the instances' own, else the tasks'.
pub(crate) fn extra_ca() -> Option<String> {
    let set = |env: &str| std::env::var(env).is_ok_and(|v| !v.trim().is_empty());
    let env = if set(EXTRA_CA_ENV) {
        EXTRA_CA_ENV
    } else {
        ECS_EXTRA_CA_ENV
    };
    fakecloud_core::ca_bundle::extra_ca_from_env(env)
}

/// The `-e` pair pointing `SSL_CERT_FILE` at the bundle.
pub(crate) fn ssl_cert_file_env() -> [String; 2] {
    [
        "-e".to_string(),
        format!("{}={BUNDLE_PATH}", fakecloud_core::ca_bundle::SSL_CERT_FILE),
    ]
}

/// Whether an instance's tags ask for the host's container engine.
pub(crate) fn wants_host_engine(tags: &BTreeMap<String, String>) -> bool {
    tags.get(CONTAINER_ENGINE_TAG)
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("host"))
}

/// The `-v` pair mounting the engine socket at `socket` (its path on the
/// engine's host) into an instance.
pub(crate) fn engine_socket_mount(socket: &str) -> [String; 2] {
    [
        "-v".to_string(),
        format!("{socket}:{ENGINE_SOCKET_IN_INSTANCE}"),
    ]
}

/// The engine socket's path on the host the engine runs on: the operator's
/// override, else Podman's own report of its API socket, else Docker's
/// conventional path (which Docker Desktop also maps for containers).
pub(crate) fn host_engine_socket(cli: &str, podman: bool) -> String {
    if let Some(path) = std::env::var(ENGINE_SOCKET_ENV)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    {
        return path;
    }
    if podman {
        let reported = fakecloud_core::container_net::bounded_output(
            cli,
            &["info", "--format", "{{.Host.RemoteSocket.Path}}"],
        );
        if let Some(path) = reported.as_deref().and_then(socket_path) {
            return path;
        }
        return "/run/podman/podman.sock".to_string();
    }
    ENGINE_SOCKET_IN_INSTANCE.to_string()
}

/// A socket path from an engine's report (`unix://` prefix optional).
fn socket_path(reported: &str) -> Option<String> {
    let path = reported.trim();
    let path = path.strip_prefix("unix://").unwrap_or(path);
    path.starts_with('/').then(|| path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_env_names_fakecloud_and_the_region() {
        let env = AwsEnv::new("host.docker.internal", 4566, "ap-southeast-1");
        assert_eq!(
            env.args(),
            [
                "-e",
                "AWS_ENDPOINT_URL=http://host.docker.internal:4566",
                "-e",
                "AWS_REGION=ap-southeast-1",
                "-e",
                "AWS_DEFAULT_REGION=ap-southeast-1",
            ]
        );
        assert_eq!(
            env.file(),
            "AWS_ENDPOINT_URL=http://host.docker.internal:4566\n\
             AWS_REGION=ap-southeast-1\n\
             AWS_DEFAULT_REGION=ap-southeast-1\n"
        );
        assert_eq!(AWS_ENV_PATH, format!("{AWS_ENV_DIR}/{AWS_ENV_FILE}"));
    }

    #[test]
    fn only_the_tag_value_host_mounts_the_engine() {
        let tags = |v: &str| BTreeMap::from([(CONTAINER_ENGINE_TAG.to_string(), v.to_string())]);
        assert!(wants_host_engine(&tags("host")));
        assert!(wants_host_engine(&tags(" Host ")));
        assert!(!wants_host_engine(&tags("none")));
        assert!(!wants_host_engine(&BTreeMap::new()));
        assert_eq!(
            engine_socket_mount("/var/run/docker.sock"),
            ["-v", "/var/run/docker.sock:/var/run/docker.sock"]
        );
        assert_eq!(
            engine_socket_mount("/run/podman/podman.sock"),
            ["-v", "/run/podman/podman.sock:/var/run/docker.sock"]
        );
    }

    #[test]
    fn engine_socket_paths_are_read_from_the_report() {
        assert_eq!(
            socket_path("unix:///run/user/1000/podman/podman.sock\n").as_deref(),
            Some("/run/user/1000/podman/podman.sock")
        );
        assert_eq!(
            socket_path("/run/podman/podman.sock").as_deref(),
            Some("/run/podman/podman.sock")
        );
        assert_eq!(socket_path("<no value>"), None);
    }

    #[test]
    fn the_bundle_is_named_by_ssl_cert_file() {
        assert_eq!(
            ssl_cert_file_env(),
            ["-e", "SSL_CERT_FILE=/etc/fakecloud-ec2/ca-bundle.pem"]
        );
        assert!(BUNDLE_PATH.starts_with(BUNDLE_DIR));
    }
}
