//! The ECS task metadata endpoints a task container reads at
//! `ECS_CONTAINER_METADATA_URI` (v3) and `ECS_CONTAINER_METADATA_URI_V4`.
//!
//! On ECS both point at the agent's link-local address
//! (`http://169.254.170.2/v3/<id>`, `http://169.254.170.2/v4/<id>`). fakecloud
//! serves the same documents at `/_fakecloud/ecs/v3|v4/<task-id>` (the URIs a
//! container gets when its network namespace can't route the agent address)
//! and, through `ecs_creds::link_local_host_middleware`, at `/v3|v4/<task-id>`
//! for requests addressed to `169.254.170.2`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use fakecloud_ecs::SharedEcsState;

/// The response for a task fakecloud doesn't know.
fn task_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({"error": "task not found"})),
    )
        .into_response()
}

/// The v4 task metadata document for `task_id`.
pub fn v4_response(ecs: &SharedEcsState, task_id: &str) -> Response {
    let accounts = ecs.read();
    for (_, state) in accounts.iter() {
        if let Some(t) = state.tasks.get(task_id) {
            let body = serde_json::json!({
                "Cluster": t.cluster_name,
                "TaskARN": t.task_arn,
                "Family": t.family,
                "Revision": t.revision,
                "DesiredStatus": t.desired_status,
                "KnownStatus": t.last_status,
                "Limits": {
                    "CPU": t.cpu.as_ref().and_then(|c| c.parse::<f64>().ok()),
                    "Memory": t.memory.as_ref().and_then(|m| m.parse::<i64>().ok()),
                },
                "PullStartedAt": t.pull_started_at.map(|d| d.to_rfc3339()),
                "PullStoppedAt": t.pull_stopped_at.map(|d| d.to_rfc3339()),
                "CreatedAt": t.created_at.to_rfc3339(),
                "StartedAt": t.started_at.map(|d| d.to_rfc3339()),
                "StoppedAt": t.stopped_at.map(|d| d.to_rfc3339()),
                "AvailabilityZone": "us-east-1a",
                "Containers": t.containers.iter().map(|c| serde_json::json!({
                    "DockerId": c.runtime_id,
                    "Name": c.name,
                    "DockerName": c.runtime_id.as_ref().map(|id| format!("ecs-{}", id)),
                    "Image": c.image,
                    "ImageID": c.image_digest,
                    "Ports": c.network_bindings,
                    "Labels": {},
                    "DesiredStatus": c.last_status,
                    "KnownStatus": c.last_status,
                    "ExitCode": c.exit_code,
                    "Health": {
                        "status": c.health_status.as_deref().unwrap_or("UNKNOWN"),
                    },
                })).collect::<Vec<_>>(),
            });
            return (StatusCode::OK, axum::Json(body)).into_response();
        }
    }
    task_not_found()
}

/// The v3 task metadata document for `task_id`.
pub fn v3_response(ecs: &SharedEcsState, task_id: &str) -> Response {
    let accounts = ecs.read();
    for (_, state) in accounts.iter() {
        if let Some(t) = state.tasks.get(task_id) {
            let body = serde_json::json!({
                "Cluster": t.cluster_name,
                "TaskARN": t.task_arn,
                "Family": t.family,
                "Revision": t.revision,
                "DesiredStatus": t.desired_status,
                "KnownStatus": t.last_status,
                "Containers": t.containers.iter().map(|c| serde_json::json!({
                    "DockerId": c.runtime_id,
                    "Name": c.name,
                    "DockerName": c.runtime_id.as_ref().map(|id| format!("ecs-{}", id)),
                    "Image": c.image,
                    "ImageID": c.image_digest,
                    "Ports": c.network_bindings,
                    "Labels": {},
                    "DesiredStatus": c.last_status,
                    "KnownStatus": c.last_status,
                    "ExitCode": c.exit_code,
                })).collect::<Vec<_>>(),
            });
            return (StatusCode::OK, axum::Json(body)).into_response();
        }
    }
    task_not_found()
}

/// The task ID and metadata version (3 or 4) a link-local path names, if it
/// is one: `/v3/<id>` or `/v4/<id>`, exactly the paths fakecloud also serves
/// under `/_fakecloud/ecs/v3|v4/<task-id>` (one non-empty ID segment).
fn parse_link_local_path(path: &str) -> Option<(u8, &str)> {
    let (version, task_id) = path
        .strip_prefix("/v3/")
        .map(|id| (3, id))
        .or_else(|| path.strip_prefix("/v4/").map(|id| (4, id)))?;
    (!task_id.is_empty() && !task_id.contains('/')).then_some((version, task_id))
}

/// Whether `path` is a link-local task metadata path (`/v3/<id>`,
/// `/v4/<id>`).
pub fn is_link_local_path(path: &str) -> bool {
    parse_link_local_path(path).is_some()
}

/// The metadata response for a link-local path; [`is_link_local_path`] must
/// hold for `path` (anything else is a 404).
pub fn link_local_response(ecs: &SharedEcsState, path: &str) -> Response {
    match parse_link_local_path(path) {
        Some((3, task_id)) => v3_response(ecs, task_id),
        Some((_, task_id)) => v4_response(ecs, task_id),
        None => (StatusCode::NOT_FOUND, "404 page not found\n").into_response(),
    }
}
