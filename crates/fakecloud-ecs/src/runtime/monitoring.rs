//! `EcsRuntime` `monitoring` family — extracted from service.rs by audit-2026-05-19.

use super::*;

impl EcsRuntime {
    /// Best-effort image digest lookup via `docker image inspect` after a
    /// pull. Returns the first `RepoDigests[0]` entry's `sha256:...` tail
    /// when present, matching what AWS ECS returns on `DescribeTasks`.
    /// `None` on any failure so digest extraction never fails the task.
    pub(super) async fn lookup_image_digest(&self, pull_uri: &str) -> Option<String> {
        let out = fakecloud_core::container_net::output_within(
            self.cli_command().args([
                "image",
                "inspect",
                "-f",
                "{{index .RepoDigests 0}}",
                pull_uri,
            ]),
            CLI_CALL_TIMEOUT,
        )
        .await
        .ok()?;
        if !out.status.success() {
            return None;
        }
        let raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if raw.is_empty() || raw == "<no value>" {
            return None;
        }
        // RepoDigests entries are `<repo>@sha256:<hex>`. Real ECS surfaces
        // the digest portion only.
        Some(
            raw.rsplit_once('@')
                .map(|(_, d)| d.to_string())
                .unwrap_or(raw),
        )
    }

    /// Emit an `ECS Task State Change` EventBridge event. No-op when no
    /// delivery bus is wired. Matches AWS event shape so downstream
    /// rules can filter on `detail.lastStatus`, `detail.stopCode`, etc.
    pub(super) fn emit_state_change(
        &self,
        state: &SharedEcsState,
        account_id: &str,
        task_id: &str,
        last_status: &str,
        stop: Option<(&str, String)>,
    ) {
        let Some(ref bus) = self.delivery_bus else {
            return;
        };
        let Some(task_view) = snapshot_task(state, account_id, task_id) else {
            return;
        };
        let mut detail = serde_json::json!({
            "taskArn": task_view.task_arn,
            "clusterArn": task_view.cluster_arn,
            "lastStatus": last_status,
            "desiredStatus": if last_status == "STOPPED" { "STOPPED" } else { "RUNNING" },
            "launchType": task_view.launch_type,
            "group": task_view.group,
            "taskDefinitionArn": task_view.task_definition_arn,
            "containers": task_view.containers,
        });
        if let Some((code, reason)) = stop {
            detail["stopCode"] = code.into();
            detail["stoppedReason"] = reason.into();
        }
        // The task ARN (`arn:<p>:ecs:<region>:<account>:task/...`) names the
        // region the task runs in; the event originates there.
        let region = task_view.task_arn.split(':').nth(3).unwrap_or("");
        let detail = detail.to_string();
        // The task account's own default bus: never refused.
        if let Err(err) =
            bus.put_event_to_eventbridge(&fakecloud_core::delivery::CrossServiceEvent {
                source: "aws.ecs",
                detail_type: "ECS Task State Change",
                detail: &detail,
                event_bus: "default",
                account_id,
                region,
                resources: std::slice::from_ref(&task_view.task_arn),
                principal_arn: None,
            })
        {
            tracing::warn!(task_id, %err, "ECS task state change event refused");
        }
    }

    /// Emit an `ECS Deployment State Change` EventBridge event
    /// (`SERVICE_DEPLOYMENT_IN_PROGRESS` / `_COMPLETED` / `_FAILED`) for a
    /// service deployment. No-op when no delivery bus is wired.
    pub(crate) fn emit_deployment_state_change(
        &self,
        account_id: &str,
        change: &crate::rollout::DeploymentStateChange,
    ) {
        let Some(ref bus) = self.delivery_bus else {
            return;
        };
        let detail = serde_json::json!({
            "eventType": change.event_type,
            "eventName": change.event_name,
            "deploymentId": change.deployment_id,
            "updatedAt": change.at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "reason": change.reason,
        })
        .to_string();
        // The service ARN names the region the service runs in.
        let region = change.service_arn.split(':').nth(3).unwrap_or("");
        if let Err(err) =
            bus.put_event_to_eventbridge(&fakecloud_core::delivery::CrossServiceEvent {
                source: "aws.ecs",
                detail_type: "ECS Deployment State Change",
                detail: &detail,
                event_bus: "default",
                account_id,
                region,
                resources: std::slice::from_ref(&change.service_arn),
                principal_arn: None,
            })
        {
            tracing::warn!(
                deployment = %change.deployment_id,
                %err,
                "ECS deployment state change event refused"
            );
        }
    }

    /// Forward captured stdout/stderr to CloudWatch Logs when the task's
    /// container definition declares the `awslogs` log driver. No-op when
    /// logs_state isn't wired or the task has no awslogs config.
    pub(super) fn forward_awslogs_if_configured(
        &self,
        state: &SharedEcsState,
        account_id: &str,
        task_id: &str,
        captured: &str,
    ) {
        let Some(ref logs) = self.logs_state else {
            return;
        };
        // Clone out of the read guard so we don't hold it across the logs
        // state write.
        let (cfg, task_region) = {
            let accounts = state.read();
            let Some(s) = accounts.get(account_id) else {
                return;
            };
            let Some(task) = s.tasks.get(task_id) else {
                return;
            };
            let Some(ref cfg) = task.awslogs else {
                return;
            };
            (cfg.clone(), s.region.clone())
        };
        if captured.is_empty() {
            return;
        }
        let now = Utc::now().timestamp_millis();
        let stream_name = cfg.stream_name(task_id);
        let events: Vec<IngestEvent> = captured
            .lines()
            .enumerate()
            .map(|(i, line)| IngestEvent {
                // Stagger within the same millisecond so CloudWatch's
                // chronological-order invariant holds without relying on
                // the host clock's resolution.
                timestamp_ms: now.saturating_add(i as i64),
                message: line.to_string(),
            })
            .collect();
        // The awslogs driver writes to `awslogs-region` (already defaulted to
        // the RunTask region when the option is absent).
        let region = if cfg.region.is_empty() {
            task_region.as_str()
        } else {
            cfg.region.as_str()
        };
        append_events(logs, account_id, region, &cfg.group, &stream_name, &events);
    }
}
