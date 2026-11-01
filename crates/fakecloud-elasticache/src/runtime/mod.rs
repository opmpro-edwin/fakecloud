//! Backing-container runtime for ElastiCache.
//!
//! ElastiCache cache clusters / replication groups / serverless caches
//! are backed by a real `redis` or `memcached` process. That process can
//! run either as a local Docker/Podman container (the default) or as a
//! native Kubernetes Pod (`FAKECLOUD_ELASTICACHE_BACKEND=k8s` or the
//! global `FAKECLOUD_CONTAINER_BACKEND=k8s`). The [`ElastiCacheRuntime`]
//! dispatches every operation to the selected [`CacheBackend`]; the
//! shared k8s plumbing lives in the `fakecloud-k8s` crate.

mod k8s;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;

pub use k8s::PendingRdb;

/// Which cache engine a resource runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheEngineKind {
    Redis,
    Valkey,
    Memcached,
}

impl CacheEngineKind {
    /// The Redis-protocol engine for an ElastiCache `Engine` value: `valkey`
    /// runs Valkey, anything else (`redis`) runs Redis OSS.
    pub fn redis_compatible(engine: &str) -> Self {
        if engine.eq_ignore_ascii_case("valkey") {
            CacheEngineKind::Valkey
        } else {
            CacheEngineKind::Redis
        }
    }

    /// Container image for this engine. The Valkey image ships `redis-cli`
    /// and `redis-server` links and keeps its data in `/data`, so every
    /// Redis-protocol code path (exec, `SAVE`, RDB staging) works unchanged.
    pub(crate) fn image(self) -> &'static str {
        match self {
            CacheEngineKind::Redis => "redis:7-alpine",
            CacheEngineKind::Valkey => "valkey/valkey:8.1.10-alpine",
            CacheEngineKind::Memcached => "memcached:1.6-alpine",
        }
    }

    /// Default port the engine listens on.
    fn port(self) -> u16 {
        match self {
            CacheEngineKind::Redis | CacheEngineKind::Valkey => 6379,
            CacheEngineKind::Memcached => 11211,
        }
    }

    /// Whether the engine speaks the Redis protocol and persists an RDB.
    pub(crate) fn is_redis_compatible(self) -> bool {
        matches!(self, CacheEngineKind::Redis | CacheEngineKind::Valkey)
    }
}

/// A running cache backing instance (container or Pod).
#[derive(Debug, Clone)]
pub struct RunningCacheContainer {
    /// Backend-specific handle: a Docker container id, or a Pod name.
    pub container_id: String,
    /// The host port the engine is published on (Docker), or the engine's
    /// in-Pod port (k8s). Persisted in resource state.
    pub host_port: u16,
    /// Address clients connect to: `127.0.0.1` for Docker (published port
    /// on the host), or the Pod IP for k8s.
    pub endpoint_address: String,
    /// Port clients connect to: the published host port for Docker, the
    /// engine's standard port for k8s.
    pub endpoint_port: u16,
    /// Which engine this is — used by the k8s backend to respawn on
    /// reboot.
    pub engine: CacheEngineKind,
}

/// Outcome of a `redis-cli` invocation, normalized across backends so
/// callers don't depend on `std::process::Output`.
#[derive(Debug, Clone)]
pub struct CacheExec {
    /// Whether the command exited 0.
    pub success: bool,
    /// Raw stdout bytes.
    pub stdout: Vec<u8>,
    /// Raw stderr bytes.
    pub stderr: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("container runtime is unavailable")]
    Unavailable,
    #[error("container failed to start: {0}")]
    ContainerStartFailed(String),
}

/// Error initializing the Kubernetes backend at startup. Surfaced to the
/// operator so a misconfigured cluster fails fast rather than silently
/// falling back to Docker.
#[derive(Debug, thiserror::Error)]
pub enum BackendInitError {
    #[error(transparent)]
    Env(#[from] fakecloud_k8s::K8sEnvError),
    #[error(transparent)]
    PodConfig(#[from] fakecloud_k8s::K8sPodConfigError),
    #[error("failed to connect to the Kubernetes cluster: {0}")]
    Connect(String),
}

/// The selected backing-container backend.
#[derive(Debug, Clone)]
enum CacheBackend {
    Docker(DockerCache),
    K8s(k8s::K8sCache),
}

#[derive(Debug, Clone)]
pub struct ElastiCacheRuntime {
    backend: CacheBackend,
    /// Backing containers (Pods) by the resource's incarnation id, never by
    /// the reusable `(account, id)`: a delete and a recreate under the same
    /// id are different incarnations, so one's start, stop or teardown can't
    /// reach the other's container.
    containers: Arc<RwLock<HashMap<String, RunningCacheContainer>>>,
}

impl ElastiCacheRuntime {
    /// Construct the Docker/Podman backend. Returns `None` when no
    /// container CLI is available.
    pub fn new() -> Option<Self> {
        let cli = fakecloud_core::container_net::detect_container_cli()?;
        let net = fakecloud_core::container_net::HostNetworking::detect(&cli);
        Some(Self {
            backend: CacheBackend::Docker(DockerCache {
                cli,
                net,
                instance_id: format!("fakecloud-{}", std::process::id()),
            }),
            containers: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Test-only runtime that needs no container daemon. Handler tests that
    /// only assert the synchronously-recorded `creating` snapshot need
    /// `self.runtime` to be `Some`; the backgrounded `dump_rdb` that follows
    /// returns `Unavailable` immediately (no tracked container) without
    /// shelling out.
    #[cfg(test)]
    pub(crate) fn new_stub() -> Self {
        Self::new_stub_with_cli("true")
    }

    /// [`Self::new_stub`] driving `cli` (`"false"` makes every daemon call
    /// fail, as with an unreachable daemon).
    #[cfg(test)]
    pub(crate) fn new_stub_with_cli(cli: &str) -> Self {
        Self {
            backend: CacheBackend::Docker(DockerCache {
                cli: cli.to_string(),
                net: fakecloud_core::container_net::HostNetworking {
                    host_alias: String::new(),
                    add_host_arg: None,
                    sibling_host: "127.0.0.1".to_string(),
                },
                instance_id: format!("fakecloud-{}", std::process::id()),
            }),
            containers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Construct the Kubernetes backend. `server_port` is fakecloud's
    /// bound port (used when `FAKECLOUD_K8S_SELF_URL` omits one);
    /// `internal_token` guards the per-resource RDB endpoint that seeds
    /// snapshot data into restored Redis Pods. Fails fast on
    /// misconfiguration — never silently degrades.
    pub async fn new_k8s(
        server_port: u16,
        internal_token: String,
    ) -> Result<Self, BackendInitError> {
        let cache = k8s::K8sCache::from_env(server_port, internal_token).await?;
        Ok(Self {
            backend: CacheBackend::K8s(cache),
            containers: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Name of the active backend, for logging.
    pub fn cli_name(&self) -> &str {
        match &self.backend {
            CacheBackend::Docker(d) => &d.cli,
            CacheBackend::K8s(_) => "kubernetes",
        }
    }

    /// The pending-RDB map the server's internal endpoint serves from.
    /// `None` on the Docker backend (which stages snapshots via the
    /// daemon, not HTTP).
    pub fn pending_rdb(&self) -> Option<PendingRdb> {
        match &self.backend {
            CacheBackend::K8s(k) => Some(k.pending_rdb()),
            CacheBackend::Docker(_) => None,
        }
    }

    /// Address fakecloud advertises for clients to reach a spawned cache
    /// container, and uses for readiness probes. `127.0.0.1` on the host;
    /// `host.docker.internal` when fakecloud is containerized (issue
    /// #1539, bug 0.4). Only meaningful for the Docker backend (k8s
    /// addresses are per-Pod and returned from `ensure_*`).
    pub fn endpoint_host(&self) -> &str {
        match &self.backend {
            CacheBackend::Docker(d) => &d.net.sibling_host,
            CacheBackend::K8s(_) => "127.0.0.1",
        }
    }

    /// Start (or replace) the Redis/Valkey container of resource incarnation
    /// `incarnation`, mounting `data_volume` (named from the resource row).
    /// `engine` is the resource's ElastiCache `Engine` (`redis` or `valkey`)
    /// and picks the image. `host_port` is the port the create request named:
    /// the engine is published there when it is free (Docker), so the
    /// endpoint reports it as AWS does; otherwise on an ephemeral port.
    #[allow(clippy::too_many_arguments)]
    pub async fn ensure_redis(
        &self,
        incarnation: &str,
        account_id: &str,
        resource_id: &str,
        engine: &str,
        host_port: Option<u16>,
        data_volume: &str,
        rdb_path: Option<&str>,
        tags: &BTreeMap<String, String>,
    ) -> Result<RunningCacheContainer, RuntimeError> {
        let kind = CacheEngineKind::redis_compatible(engine);
        let running = match &self.backend {
            CacheBackend::Docker(d) => {
                d.spawn_container(
                    incarnation,
                    account_id,
                    resource_id,
                    kind,
                    host_port,
                    rdb_path,
                    Some(data_volume),
                )
                .await?
            }
            CacheBackend::K8s(k) => {
                k.spawn_pod(incarnation, resource_id, kind, rdb_path, tags)
                    .await?
            }
        };
        self.containers
            .write()
            .insert(incarnation.to_string(), running.clone());
        Ok(running)
    }

    /// Start the memcached container of resource incarnation `incarnation`
    /// (in-memory only: no data volume), published on `host_port` when it is
    /// free (see [`Self::ensure_redis`]).
    pub async fn ensure_memcached(
        &self,
        incarnation: &str,
        account_id: &str,
        resource_id: &str,
        host_port: Option<u16>,
        tags: &BTreeMap<String, String>,
    ) -> Result<RunningCacheContainer, RuntimeError> {
        let running = match &self.backend {
            CacheBackend::Docker(d) => {
                d.spawn_container(
                    incarnation,
                    account_id,
                    resource_id,
                    CacheEngineKind::Memcached,
                    host_port,
                    None,
                    None,
                )
                .await?
            }
            CacheBackend::K8s(k) => {
                k.spawn_pod(
                    incarnation,
                    resource_id,
                    CacheEngineKind::Memcached,
                    None,
                    tags,
                )
                .await?
            }
        };
        self.containers
            .write()
            .insert(incarnation.to_string(), running.clone());
        Ok(running)
    }

    /// Stop and remove the backing container of incarnation `incarnation`.
    pub async fn stop(&self, incarnation: &str) {
        let container = self.containers.write().remove(incarnation);
        if let Some(container) = container {
            match &self.backend {
                CacheBackend::Docker(d) => d.remove_container(&container.container_id).await,
                CacheBackend::K8s(k) => k.delete_pod(&container.container_id).await,
            }
        }
    }

    /// Remove a data volume by name (named from the deleted resource's row).
    /// No-op on the k8s backend, which has no Docker volumes.
    pub async fn remove_data_volume_named(&self, name: &str) {
        if let CacheBackend::Docker(d) = &self.backend {
            fakecloud_core::data_volume::remove_volume(&d.cli, name).await;
        }
    }

    /// Whether this backend mounts named Docker volumes (not k8s), i.e.
    /// whether a resource's volume binding matters to recovery.
    pub fn has_data_volumes(&self) -> bool {
        matches!(self.backend, CacheBackend::Docker(_))
    }

    /// The daemon's volume names, for resolving legacy volumes at startup.
    /// `None` on the k8s backend or when the daemon can't answer.
    pub async fn list_volumes(&self) -> Option<std::collections::HashSet<String>> {
        match &self.backend {
            CacheBackend::Docker(d) => fakecloud_core::data_volume::list_volumes(&d.cli).await,
            CacheBackend::K8s(_) => None,
        }
    }

    /// Restart the underlying backing instance, mirroring real
    /// ElastiCache's RebootCacheCluster behaviour. Returns `Unavailable`
    /// if the resource has no live instance tracked here.
    pub async fn restart(
        &self,
        incarnation: &str,
        resource_id: &str,
        tags: &BTreeMap<String, String>,
    ) -> Result<(), RuntimeError> {
        let running = {
            let containers = self.containers.read();
            containers.get(incarnation).cloned()
        };
        let running = running.ok_or(RuntimeError::Unavailable)?;
        match &self.backend {
            CacheBackend::Docker(d) => d.restart_container(&running.container_id).await,
            CacheBackend::K8s(k) => {
                // A Pod can't be restarted in place; recreate it,
                // preserving Redis data by snapshotting it across the
                // recreate. The new Pod keeps the same deterministic name.
                // Per-instance scheduling tags are re-applied to the fresh
                // Pod so a reboot keeps the resource's node placement.
                let updated = k
                    .reboot_pod(incarnation, resource_id, &running, tags)
                    .await?;
                if !self.retrack(incarnation, updated.clone()) {
                    // Deleted (or reset) while the Pod was recreated: the new
                    // Pod belongs to nothing any more.
                    k.delete_pod(&updated.container_id).await;
                    return Err(RuntimeError::Unavailable);
                }
                Ok(())
            }
        }
    }

    /// Record a recreated instance, but only while its incarnation is still
    /// tracked: a `stop` that ran during the recreate removed the entry, and
    /// re-inserting it would track a deleted resource's Pod forever.
    /// Returns whether it was recorded.
    fn retrack(&self, incarnation: &str, running: RunningCacheContainer) -> bool {
        let mut containers = self.containers.write();
        match containers.get_mut(incarnation) {
            Some(entry) => {
                *entry = running;
                true
            }
            None => false,
        }
    }

    /// Execute a `redis-cli` command inside a tracked instance.
    pub async fn exec_redis(
        &self,
        incarnation: &str,
        redis_args: &[String],
    ) -> Result<CacheExec, RuntimeError> {
        let container_id = {
            let containers = self.containers.read();
            containers
                .get(incarnation)
                .map(|c| c.container_id.clone())
                .ok_or(RuntimeError::Unavailable)?
        };
        match &self.backend {
            CacheBackend::Docker(d) => d.exec_redis(&container_id, redis_args).await,
            CacheBackend::K8s(k) => k.exec_redis(&container_id, redis_args).await,
        }
    }

    /// Trigger `SAVE` inside a running Redis instance and copy the
    /// resulting `dump.rdb` out to `dest_path`.
    pub async fn dump_rdb(&self, incarnation: &str, dest_path: &str) -> Result<(), RuntimeError> {
        let container_id = {
            let containers = self.containers.read();
            containers
                .get(incarnation)
                .map(|c| c.container_id.clone())
                .ok_or(RuntimeError::Unavailable)?
        };
        match &self.backend {
            CacheBackend::Docker(d) => d.dump_rdb(&container_id, dest_path).await,
            CacheBackend::K8s(k) => k.dump_rdb(&container_id, dest_path).await,
        }
    }

    pub async fn stop_all(&self) {
        let containers: Vec<RunningCacheContainer> = {
            let mut containers = self.containers.write();
            containers.drain().map(|(_, c)| c).collect()
        };
        for c in containers {
            match &self.backend {
                CacheBackend::Docker(d) => d.remove_container(&c.container_id).await,
                CacheBackend::K8s(k) => k.delete_pod(&c.container_id).await,
            }
        }
    }

    /// Sweep cache Pods orphaned by a previous fakecloud process (k8s
    /// only; the Docker backend relies on the shared reaper).
    pub async fn reap_stale(&self) {
        if let CacheBackend::K8s(k) = &self.backend {
            k.reap_stale().await;
        }
    }
}

/// Docker/Podman backend: shells out to the container CLI, exactly as
/// ElastiCache always has.
#[derive(Debug, Clone)]
struct DockerCache {
    cli: String,
    net: fakecloud_core::container_net::HostNetworking,
    instance_id: String,
}

impl DockerCache {
    /// Start the engine container, published on `host_port` when one is
    /// given and the port is free, else on an ephemeral host port.
    #[allow(clippy::too_many_arguments)]
    async fn spawn_container(
        &self,
        incarnation: &str,
        account_id: &str,
        resource_id: &str,
        engine: CacheEngineKind,
        host_port: Option<u16>,
        rdb_path: Option<&str>,
        data_volume: Option<&str>,
    ) -> Result<RunningCacheContainer, RuntimeError> {
        if let Some(port) = host_port {
            match self
                .spawn_container_on(
                    incarnation,
                    account_id,
                    resource_id,
                    engine,
                    Some(port),
                    rdb_path,
                    data_volume,
                )
                .await
            {
                Err(RuntimeError::ContainerStartFailed(message)) if port_taken(&message) => {
                    tracing::info!(
                        resource_id,
                        port,
                        "requested port is in use on the host; publishing on an ephemeral port"
                    );
                }
                other => return other,
            }
        }
        self.spawn_container_on(
            incarnation,
            account_id,
            resource_id,
            engine,
            None,
            rdb_path,
            data_volume,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn spawn_container_on(
        &self,
        incarnation: &str,
        account_id: &str,
        resource_id: &str,
        engine: CacheEngineKind,
        host_port: Option<u16>,
        rdb_path: Option<&str>,
        data_volume: Option<&str>,
    ) -> Result<RunningCacheContainer, RuntimeError> {
        let image = engine.image();
        let container_port = engine.port();
        let publish = match host_port {
            Some(port) => format!("{port}:{container_port}"),
            None => format!(":{container_port}"),
        };

        let mut args: Vec<String> = vec![
            "create".to_string(),
            "-p".to_string(),
            fakecloud_core::container_net::publish_spec(&publish),
            "--label".to_string(),
            format!("fakecloud-elasticache={resource_id}"),
            "--label".to_string(),
            format!("fakecloud-account={account_id}"),
            "--label".to_string(),
            format!("fakecloud-elasticache-resource={incarnation}"),
            "--label".to_string(),
            format!("fakecloud-instance={}", self.instance_id),
        ];

        // Persist redis/valkey data in a named volume at /data so a container
        // recreated after a fakecloud restart reloads its RDB instead of
        // coming back empty (bug-audit 2026-06-20, 4.2). A named volume (not a
        // bind mount) is daemon-managed, so it works whether or not fakecloud
        // is itself containerized. The name is scoped to the data dir (memory
        // mode: to this process, reaped once it exits), so another data dir or
        // fakecloud reusing the id never reloads this RDB (#2630). memcached
        // is intentionally in-memory only, matching real ElastiCache (a reboot
        // clears it), so it gets no volume.
        if let (true, Some(volume)) = (engine.is_redis_compatible(), data_volume) {
            let volume = volume.to_string();
            fakecloud_core::data_volume::ensure_volume(
                &self.cli,
                &volume,
                fakecloud_core::data_volume::current_scope(),
                &[
                    format!("fakecloud-elasticache={resource_id}"),
                    format!("fakecloud-account={account_id}"),
                ],
            )
            .await;
            args.push("-v".to_string());
            args.push(format!("{volume}:/data"));
        }
        args.push(image.to_string());

        let output = tokio::process::Command::new(&self.cli)
            .args(&args)
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;

        if !output.status.success() {
            return Err(RuntimeError::ContainerStartFailed(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }

        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Stage the snapshot RDB into the created (not yet started)
        // container via `docker cp` rather than a `-v` bind mount. A bind
        // mount of a host path breaks when fakecloud runs in a container
        // (`FAKECLOUD_IN_CONTAINER=1`): the rdb is written inside
        // fakecloud's own filesystem, but the host daemon resolves the bind
        // source against the *host* filesystem, silently yielding an empty
        // cache. `docker cp` copies the bytes across the daemon, so it works
        // on host and in-container alike (issue #1539, bug 0.7). Redis loads
        // /data/dump.rdb at startup, so the copy must precede `start`.
        if let Some(path) = rdb_path {
            let cp_result = tokio::process::Command::new(&self.cli)
                .args(["cp", path, &format!("{container_id}:/data/dump.rdb")])
                .output()
                .await
                .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;
            if !cp_result.status.success() {
                self.remove_container(&container_id).await;
                return Err(RuntimeError::ContainerStartFailed(format!(
                    "failed to stage snapshot rdb into container: {}",
                    String::from_utf8_lossy(&cp_result.stderr).trim()
                )));
            }
        }

        let start_result = tokio::process::Command::new(&self.cli)
            .args(["start", &container_id])
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;

        if !start_result.status.success() {
            self.remove_container(&container_id).await;
            return Err(RuntimeError::ContainerStartFailed(format!(
                "container start failed: {}",
                String::from_utf8_lossy(&start_result.stderr).trim()
            )));
        }

        let host_port = match self.lookup_port(&container_id, container_port).await {
            Ok(host_port) => host_port,
            Err(error) => {
                self.remove_container(&container_id).await;
                return Err(error);
            }
        };

        let wait_result = match engine {
            CacheEngineKind::Redis | CacheEngineKind::Valkey => {
                self.wait_for_redis(host_port).await
            }
            CacheEngineKind::Memcached => self.wait_for_memcached(host_port).await,
        };
        if let Err(error) = wait_result {
            self.remove_container(&container_id).await;
            return Err(error);
        }

        Ok(RunningCacheContainer {
            container_id,
            host_port,
            // sibling_host is 127.0.0.1 on the host (CI, unit tests) and
            // host.docker.internal when fakecloud itself is containerized
            // (issue #1539) — the address a client actually reaches the
            // published port at.
            endpoint_address: self.net.sibling_host.clone(),
            endpoint_port: host_port,
            engine,
        })
    }

    async fn restart_container(&self, container_id: &str) -> Result<(), RuntimeError> {
        let output = tokio::process::Command::new(&self.cli)
            .args(["restart", container_id])
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;
        if !output.status.success() {
            return Err(RuntimeError::ContainerStartFailed(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }
        Ok(())
    }

    async fn exec_redis(
        &self,
        container_id: &str,
        redis_args: &[String],
    ) -> Result<CacheExec, RuntimeError> {
        let mut args = vec![
            "exec".to_string(),
            container_id.to_string(),
            "redis-cli".to_string(),
        ];
        args.extend_from_slice(redis_args);
        let out = tokio::process::Command::new(&self.cli)
            .args(&args)
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;
        Ok(CacheExec {
            success: out.status.success(),
            stdout: out.stdout,
            stderr: out.stderr,
        })
    }

    async fn dump_rdb(&self, container_id: &str, dest_path: &str) -> Result<(), RuntimeError> {
        let save_output = tokio::process::Command::new(&self.cli)
            .args(["exec", container_id, "redis-cli", "SAVE"])
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;
        if !save_output.status.success() {
            return Err(RuntimeError::ContainerStartFailed(
                String::from_utf8_lossy(&save_output.stderr)
                    .trim()
                    .to_string(),
            ));
        }

        let cp_output = tokio::process::Command::new(&self.cli)
            .args(["cp", &format!("{container_id}:/data/dump.rdb"), dest_path])
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;
        if !cp_output.status.success() {
            return Err(RuntimeError::ContainerStartFailed(
                String::from_utf8_lossy(&cp_output.stderr)
                    .trim()
                    .to_string(),
            ));
        }
        Ok(())
    }

    async fn lookup_port(
        &self,
        container_id: &str,
        container_port: u16,
    ) -> Result<u16, RuntimeError> {
        let port_output = tokio::process::Command::new(&self.cli)
            .args(["port", container_id, &container_port.to_string()])
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;

        if !port_output.status.success() {
            let stderr = String::from_utf8_lossy(&port_output.stderr);
            return Err(RuntimeError::ContainerStartFailed(format!(
                "port lookup failed: {stderr}"
            )));
        }

        let port_str = String::from_utf8_lossy(&port_output.stdout);
        port_str
            .trim()
            .rsplit(':')
            .next()
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| {
                RuntimeError::ContainerStartFailed(format!(
                    "could not determine redis port from '{}'",
                    port_str.trim()
                ))
            })
    }

    async fn wait_for_redis(&self, host_port: u16) -> Result<(), RuntimeError> {
        // Probe the same address clients reach the published port at:
        // 127.0.0.1 on the host, host.docker.internal /
        // host.containers.internal when fakecloud is containerized (#1539).
        let host = &self.net.sibling_host;
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if tokio::net::TcpStream::connect(format!("{host}:{host_port}"))
                .await
                .is_ok()
            {
                return Ok(());
            }
        }

        Err(RuntimeError::ContainerStartFailed(
            "redis container did not become ready within 20 seconds".to_string(),
        ))
    }

    async fn wait_for_memcached(&self, host_port: u16) -> Result<(), RuntimeError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let host = &self.net.sibling_host;
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let Ok(mut stream) =
                tokio::net::TcpStream::connect(format!("{host}:{host_port}")).await
            else {
                continue;
            };
            if stream.write_all(b"version\r\n").await.is_err() {
                continue;
            }
            let mut buf = [0u8; 32];
            match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 && buf.starts_with(b"VERSION") => return Ok(()),
                _ => continue,
            }
        }

        Err(RuntimeError::ContainerStartFailed(
            "memcached container did not become ready within 20 seconds".to_string(),
        ))
    }

    async fn remove_container(&self, container_id: &str) {
        let _ = tokio::process::Command::new(&self.cli)
            .args(["rm", "-f", container_id])
            .output()
            .await;
    }
}

/// Whether a container start failed because its host port is taken. Docker
/// reports `port is already allocated` or `address already in use`; Docker
/// Desktop `ports are not available`.
fn port_taken(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("already allocated")
        || message.contains("address already in use")
        || message.contains("ports are not available")
}

/// Docker volume name for a resource's redis data dir in a volume scope
/// (`fakecloud_core::data_volume`): stable for the same data dir across
/// restarts, distinct for any other data dir, memory-mode process, or
/// account.
pub fn scoped_data_volume_name(
    scope_tag: &str,
    account_id: &str,
    resource_id: &str,
    incarnation: &str,
) -> String {
    fakecloud_core::data_volume::scoped_volume_name(
        "elasticache",
        scope_tag,
        &[account_id, resource_id, incarnation],
    )
}

/// The unscoped name builds before #2630 gave a resource's data volume.
/// It carries no account: those builds shared one volume across accounts.
pub fn legacy_data_volume_name(resource_id: &str) -> String {
    fakecloud_core::data_volume::legacy_volume_name("elasticache", &[resource_id])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_volume_name_is_scoped_stable_and_sanitized() {
        assert_eq!(
            scoped_data_volume_name("d0123456789ab", "123456789012", "my-cache", "inc1"),
            "fakecloud-elasticache-data-d0123456789ab-123456789012-my-cache-inc1"
        );
        // Two data dirs never share a volume for the same id.
        assert_ne!(
            scoped_data_volume_name("d0123456789ab", "123456789012", "my-cache", "inc1"),
            scoped_data_volume_name("dba9876543210", "123456789012", "my-cache", "inc1")
        );
        // Nor do two accounts, nor a delete + recreate under the same id.
        assert_ne!(
            scoped_data_volume_name("d0", "111111111111", "my-cache", "inc1"),
            scoped_data_volume_name("d0", "222222222222", "my-cache", "inc1")
        );
        assert_ne!(
            scoped_data_volume_name("d0", "111111111111", "my-cache", "inc1"),
            scoped_data_volume_name("d0", "111111111111", "my-cache", "inc2")
        );
        assert_eq!(
            scoped_data_volume_name("d0", "123456789012", "weird/id:1", "inc1"),
            "fakecloud-elasticache-data-d0-123456789012-weird-id-1-inc1"
        );
        // The legacy name is exactly what pre-scoping builds created.
        assert_eq!(
            legacy_data_volume_name("my-cache"),
            "fakecloud-elasticache-data-my-cache"
        );
    }

    #[test]
    fn port_in_use_start_failures_are_recognised() {
        assert!(port_taken(
            "container start failed: Bind for 0.0.0.0:6379 failed: port is already allocated"
        ));
        assert!(port_taken(
            "ports are not available: exposing port TCP 127.0.0.1:6379 -> 0.0.0.0:0: listen tcp \
             127.0.0.1:6379: bind: address already in use"
        ));
        assert!(!port_taken("container start failed: no such image"));
    }

    #[test]
    fn valkey_engine_runs_a_valkey_image() {
        let valkey = CacheEngineKind::redis_compatible("valkey");
        assert_eq!(valkey, CacheEngineKind::Valkey);
        assert!(valkey.image().starts_with("valkey/valkey:8."));
        assert!(valkey.is_redis_compatible());
        assert_eq!(valkey.port(), 6379);
        let redis = CacheEngineKind::redis_compatible("redis");
        assert_eq!(redis, CacheEngineKind::Redis);
        assert!(redis.image().starts_with("redis:"));
        assert!(!CacheEngineKind::Memcached.is_redis_compatible());
    }

    /// A delete and a recreate under the same id are different incarnations:
    /// stopping the old one never reaches the new one's container.
    #[tokio::test]
    async fn containers_are_tracked_by_incarnation() {
        let rt = ElastiCacheRuntime::new_stub();
        let running = |id: &str| RunningCacheContainer {
            container_id: id.to_string(),
            host_port: 0,
            endpoint_address: "127.0.0.1".to_string(),
            endpoint_port: 6379,
            engine: CacheEngineKind::Redis,
        };
        rt.containers.write().insert("inc-old".into(), running("a"));
        rt.containers.write().insert("inc-new".into(), running("b"));
        rt.stop("inc-old").await;
        let left: Vec<String> = rt
            .containers
            .read()
            .values()
            .map(|c| c.container_id.clone())
            .collect();
        assert_eq!(left, vec!["b".to_string()]);
    }

    #[tokio::test]
    async fn reboot_does_not_retrack_a_stopped_incarnation() {
        let rt = ElastiCacheRuntime::new_stub();
        let running = |id: &str| RunningCacheContainer {
            container_id: id.to_string(),
            host_port: 0,
            endpoint_address: "127.0.0.1".to_string(),
            endpoint_port: 6379,
            engine: CacheEngineKind::Redis,
        };
        rt.containers.write().insert("inc".into(), running("p1"));
        assert!(rt.retrack("inc", running("p2")));
        assert_eq!(rt.containers.read()["inc"].container_id, "p2");
        // Deleted while the Pod was being recreated: not re-inserted.
        rt.stop("inc").await;
        assert!(!rt.retrack("inc", running("p3")));
        assert!(rt.containers.read().is_empty());
    }
}
