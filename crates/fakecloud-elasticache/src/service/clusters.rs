//! ElastiCache `clusters` family handlers extracted from service.rs
//! by audit-2026-05-19 file-split.

use std::borrow::Cow;

use super::*;

impl ElastiCacheService {
    pub(super) async fn create_cache_cluster(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let cache_cluster_id = required_query_param(request, "CacheClusterId")?;
        let engine =
            optional_query_param(request, "Engine").unwrap_or_else(|| ENGINE_REDIS.to_string());
        validate_engine(&engine)?;

        let default_version = match engine.as_str() {
            ENGINE_VALKEY => "8.0",
            ENGINE_MEMCACHED => "1.6.22",
            _ => "7.1",
        };
        let engine_version = optional_query_param(request, "EngineVersion")
            .unwrap_or_else(|| default_version.to_string());
        let cache_node_type = optional_query_param(request, "CacheNodeType")
            .unwrap_or_else(|| "cache.t3.micro".to_string());
        let num_cache_nodes = match optional_query_param(request, "NumCacheNodes") {
            Some(v) => {
                let n = v.parse::<i32>().map_err(|_| {
                    AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameterValue",
                        format!("Invalid value for NumCacheNodes: '{v}'"),
                    )
                })?;
                if n < 1 {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameterValue",
                        format!("NumCacheNodes must be a positive integer, got {n}"),
                    ));
                }
                n
            }
            None => 1,
        };
        let cache_subnet_group_name = optional_query_param(request, "CacheSubnetGroupName")
            .or_else(|| Some("default".to_string()));
        let replication_group_id = optional_query_param(request, "ReplicationGroupId");
        let auto_minor_version_upgrade = parse_optional_bool(
            optional_query_param(request, "AutoMinorVersionUpgrade").as_deref(),
        )?
        .unwrap_or(true);
        let cache_parameter_group_name = optional_query_param(request, "CacheParameterGroupName");
        let security_group_ids =
            parse_query_list_param(request, "SecurityGroupIds", "SecurityGroupId");
        let cache_security_group_names =
            parse_query_list_param(request, "CacheSecurityGroupNames", "CacheSecurityGroupName");
        let log_delivery_configurations = parse_log_delivery_configs(request);
        let transit_encryption_enabled = parse_optional_bool(
            optional_query_param(request, "TransitEncryptionEnabled").as_deref(),
        )?
        .unwrap_or(false);
        let at_rest_encryption_enabled = parse_optional_bool(
            optional_query_param(request, "AtRestEncryptionEnabled").as_deref(),
        )?
        .unwrap_or(false);
        let auth_token = optional_query_param(request, "AuthToken");
        let auth_token_enabled = auth_token.is_some();
        // ElastiCache defaults: 6379 redis/valkey, 11211 memcached.
        let default_port = if engine == ENGINE_MEMCACHED {
            11211
        } else {
            6379
        };
        let requested_port =
            optional_query_param(request, "Port").and_then(|v| v.parse::<u16>().ok());
        let port = requested_port.unwrap_or(default_port);
        let preferred_maintenance_window =
            optional_query_param(request, "PreferredMaintenanceWindow");
        let preferred_availability_zones =
            parse_query_list_param(request, "PreferredAvailabilityZones", "AvailabilityZone");
        let notification_topic_arn = optional_query_param(request, "NotificationTopicArn");
        let snapshot_arns = parse_query_list_param(request, "SnapshotArns", "SnapshotArn");
        let snapshot_name = optional_query_param(request, "SnapshotName");
        let snapshot_retention_limit = optional_query_param(request, "SnapshotRetentionLimit")
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(0);
        let snapshot_window = optional_query_param(request, "SnapshotWindow");
        let outpost_mode = optional_query_param(request, "OutpostMode");
        let preferred_outpost_arn = optional_query_param(request, "PreferredOutpostArn");
        // Default to ipv4 when unspecified, matching AWS's default network stack.
        let network_type =
            Some(optional_query_param(request, "NetworkType").unwrap_or_else(|| "ipv4".into()));
        let ip_discovery =
            Some(optional_query_param(request, "IpDiscovery").unwrap_or_else(|| "ipv4".into()));
        let az_mode =
            Some(optional_query_param(request, "AZMode").unwrap_or_else(|| "single-az".into()));
        let kms_key_id = optional_query_param(request, "KmsKeyId");
        let transit_encryption_mode = optional_query_param(request, "TransitEncryptionMode");
        let data_tiering_enabled =
            parse_optional_bool(optional_query_param(request, "DataTieringEnabled").as_deref())?;
        let cluster_mode = optional_query_param(request, "ClusterMode");
        let preferred_outpost_arns =
            parse_query_list_param(request, "PreferredOutpostArns", "PreferredOutpostArn");
        let tags = parse_tags(request)?;

        let (preferred_availability_zone, arn, rdb_path) = {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&request.account_id);
            if !state.begin_cache_cluster_creation(&cache_cluster_id) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "CacheClusterAlreadyExists",
                    format!("CacheCluster {cache_cluster_id} already exists."),
                ));
            }

            if let Some(ref subnet_group_name) = cache_subnet_group_name {
                if !state.subnet_groups.contains_key(subnet_group_name) {
                    state.cancel_cache_cluster_creation(&cache_cluster_id);
                    return Err(AwsServiceError::aws_error(
                        StatusCode::NOT_FOUND,
                        "CacheSubnetGroupNotFoundFault",
                        format!("Cache subnet group {subnet_group_name} not found."),
                    ));
                }
            }

            if let Some(ref group_id) = replication_group_id {
                if engine == ENGINE_MEMCACHED {
                    state.cancel_cache_cluster_creation(&cache_cluster_id);
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameterValue",
                        "Replication groups are not supported for the memcached engine."
                            .to_string(),
                    ));
                }
                if !state.replication_groups.contains_key(group_id) {
                    state.cancel_cache_cluster_creation(&cache_cluster_id);
                    return Err(AwsServiceError::aws_error(
                        StatusCode::NOT_FOUND,
                        "ReplicationGroupNotFoundFault",
                        format!("ReplicationGroup {group_id} not found."),
                    ));
                }
            }

            // SnapshotNotFoundFault is not declared on CreateCacheCluster in
            // the Smithy model, so a missing snapshot can't be the wire
            // failure here. Treat an unknown snapshot name as "no restore"
            // and let the create succeed with an empty rdb_path — matches
            // the model's set of declared errors and keeps probe-style
            // random snapshot names from getting an undeclared 404.
            let rdb_path = snapshot_name
                .as_ref()
                .and_then(|snap_name| state.snapshots.get(snap_name))
                .and_then(|snap| snap.rdb_path.clone());

            let preferred_availability_zone =
                optional_query_param(request, "PreferredAvailabilityZone")
                    .unwrap_or_else(|| format!("{}a", request.region));
            // ARN carries the request's credential-scope region (req.region), not
            // the frozen server default.
            let arn = elasticache_arn(
                request.region.as_str(),
                &state.account_id,
                "cluster",
                &cache_cluster_id,
            );
            (preferred_availability_zone, arn, rdb_path)
        };

        // Insert the cluster in the "creating" state and return immediately.
        // Starting the backing container can cold-pull a multi-hundred-MB image
        // and wait ~20s for readiness; blocking the CreateCacheCluster response
        // on that made the AWS CLI hit its 60s read timeout. Instead we register
        // the cluster as "creating" (endpoint port 0) and start the container in
        // a background task that flips it to "available" once ready — matching
        // real AWS and how RDS/ECS/Lambda already behave. When no runtime is
        // available we degrade to a metadata-only cluster that is immediately
        // "available" (no data plane), as before. bug-audit 2026-05-28, 3.2.
        let cluster = CacheCluster {
            cache_cluster_id: cache_cluster_id.clone(),
            cache_node_type,
            engine: engine.clone(),
            engine_version,
            cache_cluster_status: if self.runtime.is_some() {
                "creating".to_string()
            } else {
                "available".to_string()
            },
            num_cache_nodes,
            preferred_availability_zone,
            cache_subnet_group_name,
            auto_minor_version_upgrade,
            arn,
            created_at: chrono::Utc::now().to_rfc3339(),
            endpoint_address: "127.0.0.1".to_string(),
            endpoint_port: 0,
            container_id: String::new(),
            host_port: 0,
            data_volume: Some(fakecloud_core::data_volume::DataVolumeBinding::Scoped),
            replication_group_id: replication_group_id.clone(),
            cache_parameter_group_name: cache_parameter_group_name.clone(),
            security_group_ids,
            log_delivery_configurations,
            transit_encryption_enabled,
            at_rest_encryption_enabled,
            auth_token_enabled,
            port,
            requested_port,
            preferred_maintenance_window,
            preferred_availability_zones,
            notification_topic_arn,
            cache_security_group_names,
            snapshot_arns,
            snapshot_name,
            snapshot_retention_limit,
            snapshot_window,
            outpost_mode,
            preferred_outpost_arn,
            network_type,
            ip_discovery,
            az_mode,
            auth_token,
            kms_key_id,
            transit_encryption_mode,
            data_tiering_enabled,
            cluster_mode,
            preferred_outpost_arns,
        };

        let xml = cache_cluster_xml(&cluster, true);
        {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&request.account_id);
            // A DeleteCacheCluster may have raced in during param validation;
            // honor it and do not resurrect the cluster (bug-audit 4.3).
            if state.take_cache_cluster_delete_request(&cache_cluster_id) {
                state.cancel_cache_cluster_creation(&cache_cluster_id);
                return Ok(AwsResponse::xml(
                    StatusCode::OK,
                    query_response_xml(
                        "CreateCacheCluster",
                        ELASTICACHE_NS,
                        &format!("<CacheCluster>{xml}</CacheCluster>"),
                        &request.request_id,
                    ),
                ));
            }
            let cluster_arn = cluster.arn.clone();
            state.finish_cache_cluster_creation(cluster);
            // Initialise the tag bucket for this resource ARN, then merge any
            // `Tags.Tag.N` entries supplied at create time.
            state.tags.entry(cluster_arn.clone()).or_default();
            if !tags.is_empty() {
                merge_tags(state.tags.entry(cluster_arn).or_default(), &tags);
            }
            if let Some(ref group_id) = replication_group_id {
                add_cluster_to_replication_group(state, group_id, &cache_cluster_id);
            }
        }

        // Start the backing container off the request path. The task flips the
        // cluster to "available" (and fills in the endpoint port) when ready, or
        // tears it down if a DeleteCacheCluster arrived while it was starting.
        if let Some(runtime) = self.runtime.clone() {
            let state = self.state.clone();
            let snapshot_store = self.snapshot_store.clone();
            let snapshot_lock = self.snapshot_lock.clone();
            let account_id = request.account_id.clone();
            let id = cache_cluster_id.clone();
            let is_memcached = engine == ENGINE_MEMCACHED;
            let engine = engine.clone();
            // Reserved `fakecloud-k8s/*` scheduling tags for this cluster's
            // Pod, from the create-time tags (ignored on the Docker backend).
            let pod_tags: std::collections::BTreeMap<String, String> =
                tags.iter().cloned().collect();
            // This incarnation's id and volume, pinned now: a delete and a
            // recreate under the same id is a different incarnation, which
            // this task's container, bookkeeping and cleanup never reach.
            let (incarnation, volume) = {
                let accounts = self.state.read();
                match accounts
                    .get(&account_id)
                    .and_then(|s| s.cache_clusters.get(&id))
                {
                    Some(c) => (
                        c.incarnation(),
                        c.data_volume_name(
                            fakecloud_core::data_volume::current_scope().tag(),
                            &account_id,
                        ),
                    ),
                    None => (String::new(), String::new()),
                }
            };
            tokio::spawn(async move {
                if incarnation.is_empty() {
                    return;
                }
                let result = if is_memcached {
                    runtime
                        .ensure_memcached(&incarnation, &account_id, &id, requested_port, &pod_tags)
                        .await
                } else {
                    runtime
                        .ensure_redis(
                            &incarnation,
                            &account_id,
                            &id,
                            &engine,
                            requested_port,
                            &volume,
                            rdb_path.as_deref(),
                            &pod_tags,
                        )
                        .await
                };
                let mut stop_container = false;
                {
                    let mut accounts = state.write();
                    if let Some(s) = accounts.get_mut(&account_id) {
                        match &result {
                            Ok(running) => {
                                // Post-start presence check by incarnation: if
                                // this cluster was deleted (or reset) while it
                                // booted, its row is gone (or is a new
                                // incarnation's) and the container is reaped.
                                match s
                                    .cache_clusters
                                    .get_mut(&id)
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
                                    cache_cluster_id = %id,
                                    "failed to start elasticache cache cluster container",
                                );
                                match s
                                    .cache_clusters
                                    .get_mut(&id)
                                    .filter(|c| c.incarnation() == incarnation)
                                {
                                    Some(c) => {
                                        c.cache_cluster_status = "incompatible-network".to_string()
                                    }
                                    // Deleted while starting: the failed start may still
                                    // have created this incarnation's volume.
                                    None => stop_container = true,
                                }
                            }
                        }
                    } else {
                        // Whole account reset meanwhile.
                        stop_container = true;
                    }
                }
                if stop_container {
                    // Deleted (or reset) while it was starting: reap this
                    // incarnation's container and the volume the delete
                    // couldn't remove while it was still mounted.
                    super::reap_gone_start(
                        &runtime,
                        &incarnation,
                        (!is_memcached).then_some(&*volume),
                    )
                    .await;
                }
                save_snapshot_static(state, snapshot_store, snapshot_lock).await;
            });
        }
        if let Some(ref param_group) = cache_parameter_group_name {
            self.apply_parameters_for_group(&request.account_id, param_group)
                .await;
        }

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "CreateCacheCluster",
                ELASTICACHE_NS,
                &format!("<CacheCluster>{xml}</CacheCluster>"),
                &request.request_id,
            ),
        ))
    }

    pub(super) fn describe_cache_clusters(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let cache_cluster_id = optional_query_param(request, "CacheClusterId");
        let show_cache_node_info =
            parse_optional_bool(optional_query_param(request, "ShowCacheNodeInfo").as_deref())?
                .unwrap_or(false);
        let not_in_replication_groups = parse_optional_bool(
            optional_query_param(request, "ShowCacheClustersNotInReplicationGroups").as_deref(),
        )?
        .unwrap_or(false);
        let max_records = optional_usize_param(request, "MaxRecords")?;
        let marker = optional_query_param(request, "Marker");

        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);
        // Replication-group members have no row of their own; they are
        // derived from their group (`ReplicationGroup::member_cluster`).
        let clusters: Vec<Cow<'_, CacheCluster>> = if let Some(ref cluster_id) = cache_cluster_id {
            let found = state
                .cache_clusters
                .get(cluster_id)
                .map(Cow::Borrowed)
                .or_else(|| {
                    state
                        .replication_group_of_member(cluster_id)
                        .and_then(|g| g.member_cluster(cluster_id))
                        .map(Cow::Owned)
                });
            match found {
                Some(cluster) => vec![cluster],
                None => {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::NOT_FOUND,
                        "CacheClusterNotFound",
                        format!("CacheCluster {cluster_id} not found."),
                    ));
                }
            }
        } else {
            let mut clusters: Vec<Cow<'_, CacheCluster>> = state
                .cache_clusters
                .values()
                .map(Cow::Borrowed)
                .chain(state.derived_member_clusters().into_iter().map(Cow::Owned))
                .filter(|c| !not_in_replication_groups || c.replication_group_id.is_none())
                .collect();
            clusters.sort_by(|a, b| a.cache_cluster_id.cmp(&b.cache_cluster_id));
            clusters
        };

        let (page, next_marker) = paginate(&clusters, marker.as_deref(), max_records)?;
        let members_xml: String = page
            .iter()
            .map(|cluster| {
                format!(
                    "<CacheCluster>{}</CacheCluster>",
                    cache_cluster_xml(cluster, show_cache_node_info)
                )
            })
            .collect();
        let marker_xml = next_marker
            .map(|m| format!("<Marker>{}</Marker>", xml_escape(&m)))
            .unwrap_or_default();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeCacheClusters",
                ELASTICACHE_NS,
                &format!("<CacheClusters>{members_xml}</CacheClusters>{marker_xml}"),
                &request.request_id,
            ),
        ))
    }

    pub(super) async fn delete_cache_cluster(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let cache_cluster_id = required_query_param(request, "CacheClusterId")?;

        // A delete that arrives while the cluster is still being created (in the
        // lock-drop window of CreateCacheCluster, before the cluster is inserted)
        // must not 404 and must not be silently undone by the create's finish
        // step. Record the delete request so finish reaps the container instead
        // of resurrecting the cluster (bug-audit 2026-05-28, 4.3).
        let removed = {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&request.account_id);
            if let Some(cluster) = state.cache_clusters.remove(&cache_cluster_id) {
                if let Some(ref group_id) = cluster.replication_group_id {
                    remove_cluster_from_replication_group(
                        state,
                        group_id,
                        &cluster.cache_cluster_id,
                    );
                }
                state.tags.remove(&cluster.arn);
                Some(cluster)
            } else if state.cache_cluster_creation_in_progress(&cache_cluster_id) {
                state.request_cache_cluster_delete_during_creation(&cache_cluster_id);
                None
            } else if let Some(group) = state.replication_group_of_member(&cache_cluster_id) {
                // A derived replication-group member (no container of its
                // own). As on AWS, only a read replica of a cluster-mode
                // disabled group can be deleted this way, and never the last
                // one or one in a Multi-AZ group; it leaves the group.
                let group_id = group.replication_group_id.clone();
                let is_primary = group.member_clusters.first() == Some(&cache_cluster_id);
                let replicas = group.member_clusters.len().saturating_sub(1);
                if group.cluster_enabled || is_primary || replicas <= 1 || group.multi_az_enabled {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidCacheClusterState",
                        format!(
                            "Cache cluster {cache_cluster_id} is a member of replication group \
                             {group_id} and cannot be deleted on its own: it is the primary, the \
                             last read replica, or the group is cluster-mode enabled or Multi-AZ. \
                             Modify or delete the replication group instead."
                        ),
                    ));
                }
                let mut member = group
                    .member_cluster(&cache_cluster_id)
                    .expect("member of its own group");
                remove_cluster_from_replication_group(state, &group_id, &cache_cluster_id);
                if let Some(g) = state.replication_groups.get_mut(&group_id) {
                    if let Some(r) = g.replicas_per_node_group.as_mut() {
                        *r = (*r - 1).max(0);
                    }
                }
                member.cache_cluster_status = "deleting".to_string();
                return Ok(AwsResponse::xml(
                    StatusCode::OK,
                    query_response_xml(
                        "DeleteCacheCluster",
                        ELASTICACHE_NS,
                        &format!(
                            "<CacheCluster>{}</CacheCluster>",
                            cache_cluster_xml(&member, true)
                        ),
                        &request.request_id,
                    ),
                ));
            } else {
                return Err(AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "CacheClusterNotFound",
                    format!("CacheCluster {cache_cluster_id} not found."),
                ));
            }
        };

        if let (Some(runtime), Some(cluster)) = (self.runtime.as_ref(), removed.as_ref()) {
            // Stop this incarnation's container and drop its data volume, so a
            // later cluster reusing this id starts clean instead of reloading
            // deleted data (bug-audit 2026-06-20, 4.2). A cluster deleted while
            // still starting is reaped by its create task instead.
            runtime.stop(&cluster.incarnation()).await;
            if cluster.engine != ENGINE_MEMCACHED {
                runtime
                    .remove_data_volume_named(&cluster.data_volume_name(
                        fakecloud_core::data_volume::current_scope().tag(),
                        &request.account_id,
                    ))
                    .await;
            }
        }

        let xml = match removed {
            Some(mut deleted_cluster) => {
                deleted_cluster.cache_cluster_status = "deleting".to_string();
                cache_cluster_xml(&deleted_cluster, true)
            }
            None => format!(
                "<CacheClusterId>{cache_cluster_id}</CacheClusterId>\
                 <CacheClusterStatus>deleting</CacheClusterStatus>"
            ),
        };

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DeleteCacheCluster",
                ELASTICACHE_NS,
                &format!("<CacheCluster>{xml}</CacheCluster>"),
                &request.request_id,
            ),
        ))
    }

    // ── Cluster lifecycle extras ──

    pub(super) fn modify_cache_cluster(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = required_query_param(request, "CacheClusterId")?;
        let new_node_count = optional_query_param(request, "NumCacheNodes")
            .as_deref()
            .and_then(|v| v.parse::<i32>().ok());
        let new_node_type = optional_query_param(request, "CacheNodeType");

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        if let Some(group) = state.replication_group_of_member(&id) {
            // A derived member carries its group's configuration; AWS applies
            // these settings through ModifyReplicationGroup.
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidCacheClusterState",
                format!(
                    "Cache cluster {id} is a member of replication group {}; use \
                     ModifyReplicationGroup to change it.",
                    group.replication_group_id
                ),
            ));
        }
        let cluster = state.cache_clusters.get_mut(&id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "CacheClusterNotFound",
                format!("CacheCluster {id} not found."),
            )
        })?;
        if let Some(n) = new_node_count {
            cluster.num_cache_nodes = n;
        }
        if let Some(t) = new_node_type {
            cluster.cache_node_type = t;
        }
        if let Some(v) = optional_query_param(request, "EngineVersion") {
            cluster.engine_version = v;
        }
        if let Some(v) = optional_query_param(request, "CacheParameterGroupName") {
            cluster.cache_parameter_group_name = Some(v);
        }
        if let Some(v) = optional_query_param(request, "PreferredMaintenanceWindow") {
            cluster.preferred_maintenance_window = Some(v);
        }
        if let Some(v) = optional_query_param(request, "NotificationTopicArn") {
            cluster.notification_topic_arn = Some(v);
        }
        if let Some(v) = optional_query_param(request, "SnapshotRetentionLimit")
            .and_then(|v| v.parse::<i32>().ok())
        {
            cluster.snapshot_retention_limit = v;
        }
        if let Some(v) = optional_query_param(request, "SnapshotWindow") {
            cluster.snapshot_window = Some(v);
        }
        if let Some(v) = parse_optional_bool(
            optional_query_param(request, "AutoMinorVersionUpgrade").as_deref(),
        )? {
            cluster.auto_minor_version_upgrade = v;
        }
        // Replace the security-group set only when the caller supplies one.
        let sg_ids = parse_query_list_param(request, "SecurityGroupIds", "SecurityGroupId");
        if !sg_ids.is_empty() {
            cluster.security_group_ids = sg_ids;
        }
        cluster.cache_cluster_status = "modifying".to_string();
        let xml = cache_cluster_xml(cluster, true);
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "ModifyCacheCluster",
                ELASTICACHE_NS,
                &format!("<CacheCluster>{xml}</CacheCluster>"),
                &request.request_id,
            ),
        ))
    }

    pub(super) async fn reboot_cache_cluster(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = required_query_param(request, "CacheClusterId")?;
        if let Some(response) = self.reboot_replication_group_member(request, &id) {
            return Ok(response);
        }
        let (xml, pod_tags, incarnation) = {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&request.account_id);
            let cluster = state.cache_clusters.get_mut(&id).ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "CacheClusterNotFound",
                    format!("CacheCluster {id} not found."),
                )
            })?;
            cluster.cache_cluster_status = "rebooting cache cluster nodes".to_string();
            let arn = cluster.arn.clone();
            let xml = cache_cluster_xml(cluster, true);
            // Re-apply this cluster's reserved `fakecloud-k8s/*` scheduling
            // tags to the recreated Pod (ignored on the Docker backend).
            let pod_tags: std::collections::BTreeMap<String, String> = state
                .tags
                .get(&arn)
                .map(|t| t.iter().cloned().collect())
                .unwrap_or_default();
            (xml, pod_tags, cluster.incarnation())
        };
        // Restart the underlying engine container in the BACKGROUND so a real
        // client observes the reboot without the request blocking on it. The
        // restart + readiness wait can take up to ~120s on the k8s backend
        // (Pod recreate + IP wait + TCP wait), past the ~60s client read
        // timeout — awaiting it inline timed the CLI out (bug-hunt 2026-06-24,
        // 3.3). EC2 RebootInstances and the Create paths already background
        // theirs. Best-effort: with no runtime wired up (tests, no docker) the
        // API still reflects the rebooting state.
        if let Some(runtime) = self.runtime.clone() {
            let state_handle = self.state.clone();
            let account_id = request.account_id.clone();
            let id = id.clone();
            tokio::spawn(async move {
                if let Err(error) = runtime.restart(&incarnation, &id, &pod_tags).await {
                    tracing::warn!(
                        cluster_id = %id,
                        %error,
                        "RebootCacheCluster: container restart failed, leaving rebooting state"
                    );
                    return;
                }
                let mut accounts = state_handle.write();
                let state = accounts.get_or_create(&account_id);
                if let Some(cluster) = state
                    .cache_clusters
                    .get_mut(&id)
                    .filter(|c| c.incarnation() == incarnation)
                {
                    cluster.cache_cluster_status = "available".to_string();
                }
            });
        }
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "RebootCacheCluster",
                ELASTICACHE_NS,
                &format!("<CacheCluster>{xml}</CacheCluster>"),
                &request.request_id,
            ),
        ))
    }

    /// RebootCacheCluster on a derived replication-group member: every member
    /// shares the group's one container, so rebooting a member restarts it.
    /// `None` when `id` is not a derived member.
    fn reboot_replication_group_member(
        &self,
        request: &AwsRequest,
        id: &str,
    ) -> Option<AwsResponse> {
        let (mut member, group_id, incarnation, pod_tags) = {
            let accounts = self.state.read();
            let state = accounts.get(&request.account_id)?;
            let group = state.replication_group_of_member(id)?;
            let member = group.member_cluster(id)?;
            let pod_tags: std::collections::BTreeMap<String, String> = state
                .tags
                .get(&group.arn)
                .map(|t| t.iter().cloned().collect())
                .unwrap_or_default();
            (
                member,
                group.replication_group_id.clone(),
                group.incarnation(),
                pod_tags,
            )
        };
        if let Some(runtime) = self.runtime.clone() {
            tokio::spawn(async move {
                if let Err(error) = runtime.restart(&incarnation, &group_id, &pod_tags).await {
                    tracing::warn!(
                        replication_group_id = %group_id,
                        %error,
                        "RebootCacheCluster: replication group container restart failed"
                    );
                }
            });
        }
        member.cache_cluster_status = "rebooting cache cluster nodes".to_string();
        Some(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "RebootCacheCluster",
                ELASTICACHE_NS,
                &format!(
                    "<CacheCluster>{}</CacheCluster>",
                    cache_cluster_xml(&member, true)
                ),
                &request.request_id,
            ),
        ))
    }
}
