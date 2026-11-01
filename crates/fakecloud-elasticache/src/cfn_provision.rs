//! CloudFormation-driven container backing for ElastiCache resources.
//!
//! When `AWS::ElastiCache::CacheCluster` or
//! `AWS::ElastiCache::ReplicationGroup` is provisioned through a CloudFormation
//! stack, the CFN provisioner inserts the record synchronously (so `Ref`/`GetAtt`
//! resolve during provisioning) with status `creating`, then asks ElastiCache to
//! back it with a REAL Redis/Memcached container -- the same container the direct
//! `CreateCacheCluster`/`CreateReplicationGroup` path spawns. This module mirrors
//! that background task for an already-inserted record, so a CFN-provisioned
//! ElastiCache resource is genuinely connectable, not phantom metadata.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::runtime::ElastiCacheRuntime;
use crate::SharedElastiCacheState;

const ENGINE_MEMCACHED: &str = "memcached";

/// Snapshot the create parameters needed to start a backing container off an
/// already-inserted record: engine, the restore `rdb_path` (resolved from the
/// record's `SnapshotName`, if any) and the reserved `fakecloud-k8s/*` Pod
/// scheduling tags (ignored on the Docker backend). Returns `None` if the
/// record is gone (e.g. the stack was deleted before the container booted).
struct ClusterSpawnParams {
    is_memcached: bool,
    engine: String,
    requested_port: Option<u16>,
    rdb_path: Option<String>,
    pod_tags: BTreeMap<String, String>,
}

/// Back an already-inserted (status `creating`) CacheCluster with a real
/// container and flip it to `available`. No-op if the record is gone. Intended
/// to be `tokio::spawn`ed by the CloudFormation `CreateStack` drain so stack
/// creation never blocks on a container boot/pull (the #1539/#1730 timeout
/// lesson).
pub async fn cfn_ensure_cluster_container(
    state: SharedElastiCacheState,
    runtime: Arc<ElastiCacheRuntime>,
    cache_cluster_id: String,
    account_id: String,
) {
    let params = {
        let accounts = state.read();
        let Some(st) = accounts.get(&account_id) else {
            return;
        };
        let Some(cluster) = st.cache_clusters.get(&cache_cluster_id) else {
            return;
        };
        let rdb_path = cluster
            .snapshot_name
            .as_ref()
            .and_then(|snap_name| st.snapshots.get(snap_name))
            .and_then(|snap| snap.rdb_path.clone());
        let pod_tags = st
            .tags
            .get(&cluster.arn)
            .map(|tags| tags.iter().cloned().collect())
            .unwrap_or_default();
        (
            ClusterSpawnParams {
                is_memcached: cluster.engine == ENGINE_MEMCACHED,
                engine: cluster.engine.clone(),
                requested_port: cluster.requested_port,
                rdb_path,
                pod_tags,
            },
            cluster.incarnation(),
            cluster.data_volume_name(
                fakecloud_core::data_volume::current_scope().tag(),
                &account_id,
            ),
        )
    };
    let (params, incarnation, volume) = params;

    let result = if params.is_memcached {
        runtime
            .ensure_memcached(
                &incarnation,
                &account_id,
                &cache_cluster_id,
                params.requested_port,
                &params.pod_tags,
            )
            .await
    } else {
        runtime
            .ensure_redis(
                &incarnation,
                &account_id,
                &cache_cluster_id,
                &params.engine,
                params.requested_port,
                &volume,
                params.rdb_path.as_deref(),
                &params.pod_tags,
            )
            .await
    };

    let mut stop_container = false;
    {
        let mut accounts = state.write();
        if let Some(s) = accounts.get_mut(&account_id) {
            match &result {
                Ok(running) => {
                    // Post-start presence check by incarnation.
                    match s
                        .cache_clusters
                        .get_mut(&cache_cluster_id)
                        .filter(|c| c.incarnation() == incarnation)
                    {
                        Some(c) => {
                            c.cache_cluster_status = "available".to_string();
                            c.endpoint_address = running.endpoint_address.clone();
                            c.endpoint_port = running.endpoint_port;
                            c.host_port = running.host_port;
                            c.container_id = running.container_id.clone();
                        }
                        None => stop_container = true,
                    }
                }
                Err(error) => {
                    tracing::error!(
                        %error,
                        cache_cluster_id = %cache_cluster_id,
                        "CFN-provisioned ElastiCache cache cluster failed to start its container",
                    );
                    match s
                        .cache_clusters
                        .get_mut(&cache_cluster_id)
                        .filter(|c| c.incarnation() == incarnation)
                    {
                        Some(c) => c.cache_cluster_status = "incompatible-network".to_string(),
                        // Deleted while starting: the failed start may still
                        // have created this incarnation's volume.
                        None => stop_container = true,
                    }
                }
            }
        } else {
            // Whole account gone; reap a started container.
            stop_container = true;
        }
    }
    if stop_container {
        crate::service::reap_gone_start(
            &runtime,
            &incarnation,
            (!params.is_memcached).then_some(&*volume),
        )
        .await;
    }
}

/// Back an already-inserted (status `creating`) ReplicationGroup with a real
/// Redis container and flip it to `available`. No-op if the record is gone.
/// Intended to be `tokio::spawn`ed by the CloudFormation `CreateStack` drain.
pub async fn cfn_ensure_replication_group_container(
    state: SharedElastiCacheState,
    runtime: Arc<ElastiCacheRuntime>,
    replication_group_id: String,
    account_id: String,
) {
    let (rdb_path, pod_tags, cluster_enabled, incarnation, volume, engine, requested_port) = {
        let accounts = state.read();
        let Some(st) = accounts.get(&account_id) else {
            return;
        };
        let Some(group) = st.replication_groups.get(&replication_group_id) else {
            return;
        };
        let rdb_path = group
            .snapshot_name
            .as_ref()
            .and_then(|snap_name| st.snapshots.get(snap_name))
            .and_then(|snap| snap.rdb_path.clone());
        let pod_tags: BTreeMap<String, String> = st
            .tags
            .get(&group.arn)
            .map(|tags| tags.iter().cloned().collect())
            .unwrap_or_default();
        (
            rdb_path,
            pod_tags,
            group.cluster_enabled,
            group.incarnation(),
            group.data_volume_name(
                fakecloud_core::data_volume::current_scope().tag(),
                &account_id,
            ),
            group.engine.clone(),
            group.requested_port,
        )
    };

    let result = runtime
        .ensure_redis(
            &incarnation,
            &account_id,
            &replication_group_id,
            &engine,
            requested_port,
            &volume,
            rdb_path.as_deref(),
            &pod_tags,
        )
        .await;

    let mut stop_container = false;
    {
        let mut accounts = state.write();
        if let Some(s) = accounts.get_mut(&account_id) {
            match &result {
                Ok(running) => {
                    if let Some(g) = s
                        .replication_groups
                        .get_mut(&replication_group_id)
                        .filter(|g| g.incarnation() == incarnation)
                    {
                        g.status = "available".to_string();
                        g.endpoint_address = running.endpoint_address.clone();
                        g.endpoint_port = running.endpoint_port;
                        g.host_port = running.host_port;
                        g.container_id = running.container_id.clone();
                        if cluster_enabled {
                            g.configuration_endpoint_address =
                                Some(running.endpoint_address.clone());
                            g.configuration_endpoint_port = Some(running.endpoint_port);
                        }
                    } else {
                        // Deleted during startup: reap the orphaned container.
                        stop_container = true;
                    }
                }
                Err(error) => {
                    tracing::error!(
                        %error,
                        replication_group_id = %replication_group_id,
                        "CFN-provisioned ElastiCache replication group failed to start its container",
                    );
                    match s
                        .replication_groups
                        .get_mut(&replication_group_id)
                        .filter(|g| g.incarnation() == incarnation)
                    {
                        Some(g) => g.status = "incompatible-network".to_string(),
                        // Deleted while starting: the failed start may still
                        // have created this incarnation's volume.
                        None => stop_container = true,
                    }
                }
            }
        } else {
            stop_container = true;
        }
    }
    if stop_container {
        crate::service::reap_gone_start(&runtime, &incarnation, Some(&volume)).await;
    }
}

/// Stop and reap the REAL container backing a CFN-provisioned cache cluster
/// or replication group when its stack is deleted (or the resource is removed
/// by a stack update), and remove its data volume. Mirrors the direct delete
/// teardown so a stack delete does not leak the running engine container.
/// Intended to be `tokio::spawn`ed by the CloudFormation delete drain;
/// `incarnation` and `volume` were captured from the removed row, so a
/// replacement reusing the id is never reached.
pub async fn cfn_teardown_cache_container(
    runtime: Arc<ElastiCacheRuntime>,
    incarnation: String,
    volume: Option<String>,
) {
    crate::service::reap_gone_start(&runtime, &incarnation, volume.as_deref()).await;
}
