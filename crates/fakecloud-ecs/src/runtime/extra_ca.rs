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
//! started, so the bundle is there before the entrypoint runs. The file is
//! read at every task start; when it is missing or not PEM the task starts
//! without the bundle and a warning says why.

use std::ffi::OsString;
use std::path::Path;

use super::{EcsRuntime, CLI_CALL_TIMEOUT, CONTAINER_RUN_TIMEOUT};

/// Env var naming the PEM file of the extra CA.
pub(crate) const EXTRA_CA_ENV: &str = "FAKECLOUD_ECS_EXTRA_CA";

/// Directory of the bundle inside a task container.
const BUNDLE_DIR: &str = "/etc/fakecloud-ecs";

/// The bundle inside a task container.
pub(crate) const BUNDLE_PATH: &str = "/etc/fakecloud-ecs/ca-bundle.pem";

const SSL_CERT_FILE: &str = "SSL_CERT_FILE";

/// Where images and hosts keep their system roots: Debian / Ubuntu / Alpine,
/// RHEL / Amazon Linux, Alpine and macOS, SUSE.
const SYSTEM_ROOTS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
    "/etc/ssl/ca-bundle.pem",
];

const PEM_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----";

/// The extra CA's PEM, read now, when `FAKECLOUD_ECS_EXTRA_CA` is set.
pub(crate) fn extra_ca() -> Option<String> {
    let path = std::env::var(EXTRA_CA_ENV)
        .ok()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())?;
    match std::fs::read_to_string(&path) {
        Ok(pem) if pem.contains(PEM_CERTIFICATE) => Some(pem),
        Ok(_) => {
            tracing::warn!(%path, "{EXTRA_CA_ENV} is not a PEM certificate; tasks start without it");
            None
        }
        Err(error) => {
            tracing::warn!(%path, %error, "cannot read {EXTRA_CA_ENV}; tasks start without it");
            None
        }
    }
}

/// Point `SSL_CERT_FILE` at the bundle unless the task definition sets it.
pub(crate) fn push_ssl_cert_file(env: &mut Vec<(String, String)>) {
    if !env.iter().any(|(k, _)| k == SSL_CERT_FILE) {
        env.push((SSL_CERT_FILE.into(), BUNDLE_PATH.into()));
    }
}

/// The `create` argv for a `run -d` argv.
fn create_argv(run_argv: &[String]) -> Option<Vec<String>> {
    match run_argv {
        [run, detach, rest @ ..] if run == "run" && detach == "-d" => {
            let mut argv = vec!["create".to_string()];
            argv.extend(rest.iter().cloned());
            Some(argv)
        }
        _ => None,
    }
}

/// The bundle: `roots` (when PEM), then the extra CA.
fn bundle(roots: Option<&str>, extra_ca: &str) -> String {
    let mut out = String::new();
    if let Some(roots) = roots.filter(|r| r.contains(PEM_CERTIFICATE)) {
        out.push_str(roots.trim_end());
        out.push('\n');
    }
    out.push_str(extra_ca.trim_end());
    out.push('\n');
    out
}

/// fakecloud's own system roots, for an image that has none.
fn local_system_roots() -> Option<String> {
    SYSTEM_ROOTS
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .find(|pem| pem.contains(PEM_CERTIFICATE))
}

fn write_world_readable(dir: &Path, name: &str, contents: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    let file = dir.join(name);
    std::fs::write(&file, contents)?;
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644))
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
        let (Some(ca), Some(create)) = (extra_ca, create_argv(argv)) else {
            return self.cli_output(argv, CONTAINER_RUN_TIMEOUT).await;
        };
        let created = self.cli_output(&create, CONTAINER_RUN_TIMEOUT).await?;
        if !created.status.success() {
            return Ok(created);
        }
        let id = String::from_utf8_lossy(&created.stdout).trim().to_string();
        if let Err(error) = self.copy_ca_bundle(&id, ca).await {
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

    /// Copy the image's system roots plus `ca` into created container `id` at
    /// [`BUNDLE_PATH`].
    async fn copy_ca_bundle(&self, id: &str, ca: &str) -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| format!("bundle dir: {e}"))?;
        let fetched = dir.path().join("image-roots.pem");
        let mut roots = None;
        for path in SYSTEM_ROOTS {
            let _ = std::fs::remove_file(&fetched);
            let args: [OsString; 4] = [
                "cp".into(),
                "-L".into(),
                format!("{id}:{path}").into(),
                fetched.clone().into(),
            ];
            let copied = self
                .cli_output(&args, CLI_CALL_TIMEOUT)
                .await
                .is_ok_and(|o| o.status.success());
            if let Some(pem) = copied
                .then(|| std::fs::read_to_string(&fetched).ok())
                .flatten()
                .filter(|pem| pem.contains(PEM_CERTIFICATE))
            {
                roots = Some(pem);
                break;
            }
        }
        let roots = roots.or_else(local_system_roots);
        let staged = dir.path().join("bundle");
        write_world_readable(&staged, "ca-bundle.pem", &bundle(roots.as_deref(), ca))
            .map_err(|e| format!("bundle file: {e}"))?;
        // The directory does not exist in the container, so `cp` creates it
        // with the staged directory's contents.
        let args: [OsString; 3] = [
            "cp".into(),
            staged.into(),
            format!("{id}:{BUNDLE_DIR}").into(),
        ];
        let out = self.cli_output(&args, CLI_CALL_TIMEOUT).await?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA: &str = "-----BEGIN CERTIFICATE-----\nlocal\n-----END CERTIFICATE-----\n";

    #[test]
    fn create_argv_replaces_run_detached() {
        let argv: Vec<String> = ["run", "-d", "--name", "t-web", "img"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            create_argv(&argv).unwrap(),
            ["create", "--name", "t-web", "img"]
        );
        assert!(create_argv(&argv[1..]).is_none());
    }

    #[test]
    fn bundle_is_the_roots_then_the_extra_ca() {
        let roots = "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----";
        assert_eq!(bundle(Some(roots), CA), format!("{roots}\n{CA}"));
        // Roots that are not PEM are left out.
        assert_eq!(bundle(Some("garbage"), CA), CA);
        assert_eq!(bundle(None, CA), CA);
    }

    #[test]
    fn ssl_cert_file_is_set_unless_the_task_sets_it() {
        let mut env = vec![("A".to_string(), "1".to_string())];
        push_ssl_cert_file(&mut env);
        assert_eq!(
            env.last().unwrap(),
            &("SSL_CERT_FILE".to_string(), BUNDLE_PATH.to_string())
        );
        let mut own = vec![("SSL_CERT_FILE".to_string(), "/mine.pem".to_string())];
        push_ssl_cert_file(&mut own);
        assert_eq!(own.len(), 1);
        assert_eq!(own[0].1, "/mine.pem");
    }
}
