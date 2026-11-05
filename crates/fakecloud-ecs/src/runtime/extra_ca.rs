//! An extra certificate authority for task containers (Docker / Podman).
//!
//! Locally, TLS in front of load balancers is terminated by an edge whose
//! certificates come from a local CA, which no image trusts. With
//! `FAKECLOUD_ECS_EXTRA_CA` naming a PEM file (a path fakecloud can read), each
//! task container gets a CA bundle at [`BUNDLE_PATH`]: the image's own system
//! roots (or, when the image has none, fakecloud's) followed by that CA, and
//! `SSL_CERT_FILE` pointing at it unless the task definition sets
//! `SSL_CERT_FILE` itself. OpenSSL-based clients (curl, Python's `ssl`, Ruby,
//! PHP) and Go read `SSL_CERT_FILE`; clients that read another variable
//! (`CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`) need it set
//! to the same path in the task definition.
//!
//! The container is created, the bundle copied in, then the container
//! started, so the bundle is there before the entrypoint runs (see
//! [`fakecloud_core::ca_bundle`]). The file is read at every task start; when
//! it is missing or not PEM the task starts without the bundle and a warning
//! says why.

use fakecloud_core::ca_bundle;

use super::{EcsRuntime, CLI_CALL_TIMEOUT, CONTAINER_RUN_TIMEOUT};

/// Env var naming the PEM file of the extra CA.
pub(crate) const EXTRA_CA_ENV: &str = "FAKECLOUD_ECS_EXTRA_CA";

/// Directory of the bundle inside a task container.
const BUNDLE_DIR: &str = "/etc/fakecloud-ecs";

/// The bundle inside a task container.
pub(crate) const BUNDLE_PATH: &str = "/etc/fakecloud-ecs/ca-bundle.pem";

/// The extra CA's PEM, read now, when `FAKECLOUD_ECS_EXTRA_CA` is set.
pub(crate) fn extra_ca() -> Option<String> {
    ca_bundle::extra_ca_from_env(EXTRA_CA_ENV)
}

/// Point `SSL_CERT_FILE` at the bundle unless the task definition sets it.
pub(crate) fn push_ssl_cert_file(env: &mut Vec<(String, String)>) {
    ca_bundle::push_ssl_cert_file(env, BUNDLE_PATH);
}

impl EcsRuntime {
    /// Start a task container from its `run -d` argv. With `extra_ca` the
    /// container is created, given the CA bundle, then started; stdout is the
    /// container ID either way.
    pub(crate) async fn run_task_container(
        &self,
        argv: &[String],
        extra_ca: Option<&str>,
    ) -> Result<std::process::Output, String> {
        let (Some(ca), Some(create)) = (extra_ca, ca_bundle::create_argv(argv)) else {
            return self.cli_output(argv, CONTAINER_RUN_TIMEOUT).await;
        };
        let created = self.cli_output(&create, CONTAINER_RUN_TIMEOUT).await?;
        if !created.status.success() {
            return Ok(created);
        }
        let id = String::from_utf8_lossy(&created.stdout).trim().to_string();
        if let Err(error) =
            ca_bundle::copy_into(&self.cli, &id, ca, BUNDLE_DIR, CLI_CALL_TIMEOUT).await
        {
            tracing::warn!(container = %id, %error, "could not give the task container the {EXTRA_CA_ENV} bundle");
        }
        let started = self.cli_output(["start", &id], CONTAINER_RUN_TIMEOUT).await;
        match started {
            Ok(out) if out.status.success() => Ok(std::process::Output {
                stdout: format!("{id}\n").into_bytes(),
                ..out
            }),
            failed => {
                let _ = self.cli_output(["rm", "-f", &id], CLI_CALL_TIMEOUT).await;
                failed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssl_cert_file_points_at_the_task_bundle() {
        let mut env = Vec::new();
        push_ssl_cert_file(&mut env);
        assert_eq!(
            env,
            [("SSL_CERT_FILE".to_string(), BUNDLE_PATH.to_string())]
        );
        assert!(BUNDLE_PATH.starts_with(BUNDLE_DIR));
    }
}
