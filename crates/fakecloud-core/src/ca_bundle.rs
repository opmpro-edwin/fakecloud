//! A CA bundle with one extra certificate authority, copied into a container
//! before it starts (Docker / Podman).
//!
//! Locally, TLS in front of load balancers is terminated by an edge whose
//! certificates come from a local CA, which no image trusts. A runtime that
//! is given that CA's PEM (the ECS runtime with `FAKECLOUD_ECS_EXTRA_CA`, the
//! EC2 runtime with `FAKECLOUD_EC2_EXTRA_CA`) creates the container, copies in
//! a bundle of the image's own system roots (or, when the image has none,
//! fakecloud's) followed by that CA, then starts it, and points
//! `SSL_CERT_FILE` at the bundle. OpenSSL-based clients (curl, Python's `ssl`,
//! Ruby, PHP) and Go read `SSL_CERT_FILE`.

use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

/// Where images and hosts keep their system roots: Debian / Ubuntu / Alpine,
/// RHEL / Amazon Linux, Alpine and macOS, SUSE.
const SYSTEM_ROOTS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
    "/etc/ssl/ca-bundle.pem",
];

const PEM_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----";

/// The env var that points OpenSSL-based clients and Go at a CA bundle.
pub const SSL_CERT_FILE: &str = "SSL_CERT_FILE";

/// The PEM of the extra CA named by env var `env` (a path fakecloud can
/// read), read now. `None` when the variable is unset; a file that is missing
/// or not PEM is logged and skipped.
pub fn extra_ca_from_env(env: &str) -> Option<String> {
    let path = std::env::var(env)
        .ok()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())?;
    match std::fs::read_to_string(&path) {
        Ok(pem) if pem.contains(PEM_CERTIFICATE) => Some(pem),
        Ok(_) => {
            tracing::warn!(%path, "{env} is not a PEM certificate; containers start without it");
            None
        }
        Err(error) => {
            tracing::warn!(%path, %error, "cannot read {env}; containers start without it");
            None
        }
    }
}

/// Point `SSL_CERT_FILE` at `bundle_path` unless `env` already sets it.
pub fn push_ssl_cert_file(env: &mut Vec<(String, String)>, bundle_path: &str) {
    if !env.iter().any(|(k, _)| k == SSL_CERT_FILE) {
        env.push((SSL_CERT_FILE.into(), bundle_path.into()));
    }
}

/// The `create` argv for a `run -d` argv.
pub fn create_argv(run_argv: &[String]) -> Option<Vec<String>> {
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

#[cfg(unix)]
fn write_world_readable(dir: &Path, name: &str, contents: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    let file = dir.join(name);
    std::fs::write(&file, contents)?;
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644))
}

#[cfg(not(unix))]
fn write_world_readable(dir: &Path, name: &str, contents: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join(name), contents)
}

/// Copy the image's system roots plus `ca` into created (not yet started)
/// container `id` as `<dir>/ca-bundle.pem`, creating `dir` when the image has
/// none. Each CLI call is bounded by `timeout`.
pub async fn copy_into(
    cli: &str,
    id: &str,
    ca: &str,
    dir: &str,
    timeout: Duration,
) -> Result<(), String> {
    let run = |args: Vec<OsString>| async move {
        crate::container_net::output_within(tokio::process::Command::new(cli).args(&args), timeout)
            .await
            .map_err(|e| format!("{cli} cp {e}"))
    };
    let tmp = tempfile::tempdir().map_err(|e| format!("bundle dir: {e}"))?;
    let fetched = tmp.path().join("image-roots.pem");
    let mut roots = None;
    for path in SYSTEM_ROOTS {
        let _ = std::fs::remove_file(&fetched);
        let copied = run(vec![
            "cp".into(),
            "-L".into(),
            format!("{id}:{path}").into(),
            fetched.clone().into(),
        ])
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
    let staged = tmp.path().join("bundle");
    write_world_readable(&staged, "ca-bundle.pem", &bundle(roots.as_deref(), ca))
        .map_err(|e| format!("bundle file: {e}"))?;
    let out = run(vec![
        "cp".into(),
        // `<dir>/.`: the directory's contents, into `dir` whether or not the
        // image already has it.
        staged.join(".").into(),
        format!("{id}:{dir}").into(),
    ])
    .await?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
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
    fn ssl_cert_file_is_set_unless_already_set() {
        let mut env = vec![("A".to_string(), "1".to_string())];
        push_ssl_cert_file(&mut env, "/etc/x/ca-bundle.pem");
        assert_eq!(
            env.last().unwrap(),
            &(
                "SSL_CERT_FILE".to_string(),
                "/etc/x/ca-bundle.pem".to_string()
            )
        );
        let mut own = vec![("SSL_CERT_FILE".to_string(), "/mine.pem".to_string())];
        push_ssl_cert_file(&mut own, "/etc/x/ca-bundle.pem");
        assert_eq!(own.len(), 1);
        assert_eq!(own[0].1, "/mine.pem");
    }
}
