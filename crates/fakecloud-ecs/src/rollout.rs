//! The service scheduler for the rolling-update (`ECS`) deployment
//! controller.
//!
//! [`step_service`] moves one REPLICA service through one scheduling round:
//! it accounts for tasks that stopped, replaces tasks that fail their health
//! checks, applies the deployment circuit breaker, drains older deployments
//! and launches tasks, all within the service's `minimumHealthyPercent` and
//! `maximumPercent` bounds, and then retires drained deployments and marks a
//! finished PRIMARY deployment COMPLETED. It does no I/O and reads no clock:
//! the caller passes the time and the load-balancer health it observed, and
//! hands the task launches and stops it returns to the container runtime.
//!
//! The bounds hold across every deployment of the service:
//! - healthy tasks never drop below `ceil(desired * minimumHealthyPercent / 100)`
//!   because of the scheduler;
//! - RUNNING plus PENDING tasks (including tasks still stopping) never exceed
//!   `floor(desired * maximumPercent / 100)`.
//!
//! A task is healthy once it is RUNNING, every essential container with a
//! health check reports HEALTHY, and, for a service behind load balancers, it
//! is healthy in every target group it is registered in.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};

use crate::state::{Deployment, EcsState, Service, Task};

/// `minimumHealthyPercent` of a REPLICA service that does not set one.
pub(crate) const DEFAULT_MINIMUM_HEALTHY_PERCENT: i32 = 100;
/// `maximumPercent` of a REPLICA service that does not set one.
pub(crate) const DEFAULT_MAXIMUM_PERCENT: i32 = 200;

/// The circuit breaker's default threshold is this percent of the desired
/// count, rounded up and clamped to `[MIN, MAX]` (`BOUNDED_PERCENT`, 50).
const CIRCUIT_BREAKER_PERCENT: i64 = 50;
const CIRCUIT_BREAKER_MIN_THRESHOLD: i64 = 3;
const CIRCUIT_BREAKER_MAX_THRESHOLD: i64 = 200;

/// Consecutive start failures of a deployment after which its launches back
/// off (the service throttle logic).
const THROTTLE_AFTER_FAILURES: i32 = 3;
/// First back-off delay; it doubles with each further failure.
const THROTTLE_BASE_DELAY_SECS: i64 = 10;
/// ECS's documented ceiling for the delay between launch attempts.
const THROTTLE_MAX_DELAY_SECS: i64 = 27 * 60;

/// How long a task without any health check must have been RUNNING before
/// it counts as healthy. The runtime reports RUNNING as soon as the container
/// process starts, earlier than the ECS agent does; a container that exits
/// within this window has, in ECS terms, failed to start.
pub(crate) const RUNNING_SETTLE_SECS: i64 = 3;

/// INACTIVE deployments kept per service, newest first. They are no longer
/// listed by DescribeServices but remain rollback targets.
const MAX_INACTIVE_DEPLOYMENTS: usize = 10;

/// `ceil(desired * percent / 100)`: the fewest healthy tasks a deployment
/// may leave the service with.
pub(crate) fn minimum_healthy_tasks(desired: i32, percent: i32) -> i32 {
    let desired = i64::from(desired.max(0));
    let percent = i64::from(percent.max(0));
    ((desired * percent + 99) / 100) as i32
}

/// `floor(desired * percent / 100)`: the most RUNNING plus PENDING tasks a
/// deployment may run the service with.
pub(crate) fn maximum_tasks(desired: i32, percent: i32) -> i32 {
    let desired = i64::from(desired.max(0));
    let percent = i64::from(percent.max(0));
    (desired * percent / 100) as i32
}

/// Failed tasks at which the circuit breaker fails a deployment:
/// `ceil(0.5 * desired)` clamped to `[3, 200]`.
pub(crate) fn circuit_breaker_threshold(desired: i32) -> i32 {
    let raw = (i64::from(desired.max(0)) * CIRCUIT_BREAKER_PERCENT + 99) / 100;
    raw.clamp(CIRCUIT_BREAKER_MIN_THRESHOLD, CIRCUIT_BREAKER_MAX_THRESHOLD) as i32
}

/// Delay before the next launch after `consecutive_failures` tasks of a
/// deployment failed to start, or `None` while launches are not throttled.
pub(crate) fn throttle_delay(consecutive_failures: i32) -> Option<Duration> {
    if consecutive_failures < THROTTLE_AFTER_FAILURES {
        return None;
    }
    let doublings = (consecutive_failures - THROTTLE_AFTER_FAILURES).min(16) as u32;
    let secs = THROTTLE_BASE_DELAY_SECS
        .saturating_mul(1i64 << doublings)
        .min(THROTTLE_MAX_DELAY_SECS);
    Some(Duration::seconds(secs))
}

/// Load-balancer health of one task across every target group it is
/// registered in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LbHealth {
    /// Healthy in every target group (or health checks are off there).
    Healthy,
    /// Not yet healthy somewhere: `initial`, `draining`, or not registered.
    Pending,
    /// Failing health checks in a target group.
    Unhealthy {
        target_group_arn: String,
        port: Option<i64>,
        reason: String,
    },
}

impl LbHealth {
    /// The health of one target from its DescribeTargetHealth state (`None`
    /// when the target group or the target is unknown).
    pub(crate) fn of_target(
        view: Option<&fakecloud_core::delivery::TargetHealthView>,
        target_group_arn: &str,
        port: Option<i64>,
    ) -> Self {
        match view {
            Some(v) if v.state == "healthy" || v.state == "unavailable" => Self::Healthy,
            Some(v) if v.state == "unhealthy" => Self::Unhealthy {
                target_group_arn: target_group_arn.to_string(),
                port,
                reason: v
                    .description
                    .clone()
                    .or_else(|| v.reason.clone())
                    .unwrap_or_else(|| "Health checks failed".to_string()),
            },
            _ => Self::Pending,
        }
    }

    /// Combine the health of two targets of the same task: the task is only
    /// as healthy as its least healthy target.
    pub(crate) fn and(self, other: Self) -> Self {
        match (self, other) {
            (u @ Self::Unhealthy { .. }, _) | (_, u @ Self::Unhealthy { .. }) => u,
            (Self::Pending, _) | (_, Self::Pending) => Self::Pending,
            _ => Self::Healthy,
        }
    }
}

/// What one scheduling round may consult besides the ECS state.
pub(crate) struct StepContext<'a> {
    pub now: DateTime<Utc>,
    /// Load-balancer health per task ID, for RUNNING tasks of services with
    /// load balancers. A missing entry means not (yet) healthy.
    pub lb_health: &'a BTreeMap<String, LbHealth>,
    /// Whether target health can be read at all. Without it, a RUNNING task
    /// counts as healthy in its load balancers.
    pub evaluate_lb: bool,
    /// A full round, as the scheduler ticker runs: it also accounts for
    /// stopped tasks, replaces failing ones, applies the circuit breaker and
    /// retires and completes deployments. The round an API call runs right
    /// away only launches and drains tasks.
    pub full_pass: bool,
}

/// An `ECS Deployment State Change` EventBridge event to emit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeploymentStateChange {
    pub service_arn: String,
    pub deployment_id: String,
    pub event_name: &'static str,
    pub event_type: &'static str,
    pub reason: String,
    pub at: DateTime<Utc>,
}

impl DeploymentStateChange {
    pub(crate) fn in_progress(service_arn: &str, deployment: &Deployment) -> Self {
        Self {
            service_arn: service_arn.to_string(),
            deployment_id: deployment.deployment_id.clone(),
            event_name: "SERVICE_DEPLOYMENT_IN_PROGRESS",
            event_type: "INFO",
            reason: deployment.rollout_state_reason.clone().unwrap_or_else(|| {
                format!("ECS deployment {} in progress.", deployment.deployment_id)
            }),
            at: deployment.updated_at,
        }
    }
}

/// What a scheduling round decided. The task rows already exist (launches)
/// or are marked for stopping (stops) in the state; the caller starts and
/// stops the containers.
#[derive(Debug, Default)]
pub(crate) struct StepOutcome {
    /// Tasks created PENDING that the runtime must start.
    pub launched: Vec<String>,
    /// Tasks to stop, with the reason recorded on them.
    pub stopped: Vec<(String, String)>,
    pub deployment_events: Vec<DeploymentStateChange>,
    /// The round changed the state (worth persisting).
    pub changed: bool,
}

/// Run one scheduling round for the service stored under `key`. Services
/// that are not ACTIVE REPLICA services under the `ECS` deployment
/// controller are left alone.
pub(crate) fn step_service(state: &mut EcsState, key: &str, ctx: &StepContext<'_>) -> StepOutcome {
    let schedulable = state.services.get(key).is_some_and(|s| {
        s.status == "ACTIVE"
            && s.scheduling_strategy != "DAEMON"
            && is_rolling_update_controller(&s.deployment_controller)
    });
    if !schedulable {
        return StepOutcome::default();
    }
    let Some(mut svc) = state.services.remove(key) else {
        return StepOutcome::default();
    };
    let mut step = Step {
        ctx,
        out: StepOutcome::default(),
        events: Vec::new(),
    };
    step.run(state, &mut svc);
    for message in std::mem::take(&mut step.events) {
        state.push_service_event(&svc.service_arn, ctx.now, message);
        step.out.changed = true;
    }
    state.services.insert(key.to_string(), svc);
    step.out
}

/// Whether a `deploymentController.type` is the rolling update this module
/// schedules.
pub(crate) fn is_rolling_update_controller(controller: &str) -> bool {
    controller == "ECS" || controller.is_empty()
}

/// The tasks of `svc`: started by its scheduler (`ecs-svc/<name>`) in its
/// cluster, and not older than the service itself (a service re-created
/// under the same name does not inherit its predecessor's tasks).
pub(crate) fn service_tasks<'a>(state: &'a EcsState, svc: &Service) -> Vec<&'a Task> {
    let tag = format!("ecs-svc/{}", svc.service_name);
    let mut tasks: Vec<&Task> = state
        .tasks
        .values()
        .filter(|t| {
            t.started_by.as_deref() == Some(tag.as_str())
                && t.cluster_name == svc.cluster_name
                && t.created_at >= svc.created_at
        })
        .collect();
    tasks.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.task_id.cmp(&b.task_id))
    });
    tasks
}

/// The deployment a task belongs to: the one that launched it, or, for a
/// task started before deployments tracked their tasks, the newest live
/// deployment of its task definition, else the oldest live deployment.
pub(crate) fn owning_deployment<'a>(svc: &'a Service, task: &Task) -> Option<&'a Deployment> {
    if let Some(id) = task.deployment_id.as_deref() {
        if let Some(d) = svc.deployments.iter().find(|d| d.deployment_id == id) {
            return Some(d);
        }
    }
    let live = || svc.deployments.iter().filter(|d| d.status != "INACTIVE");
    live()
        .find(|d| d.task_definition_arn == task.task_definition_arn)
        .or_else(|| live().next_back())
}

/// RUNNING or PENDING and wanted: counts toward the desired count.
fn is_live(t: &Task) -> bool {
    t.last_status != "STOPPED" && t.desired_status != "STOPPED"
}

/// Asked to stop but not STOPPED yet: still holds a slot under the maximum.
fn is_stopping(t: &Task) -> bool {
    t.last_status != "STOPPED" && t.desired_status == "STOPPED"
}

fn is_pending(t: &Task) -> bool {
    matches!(
        t.last_status.as_str(),
        "PROVISIONING" | "PENDING" | "ACTIVATING"
    )
}

fn is_protected(t: &Task, now: DateTime<Utc>) -> bool {
    t.protection
        .as_ref()
        .is_some_and(|p| p.enabled && p.expiration.is_none_or(|exp| exp > now))
}

/// Health of one task as the service scheduler sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Health {
    Healthy,
    /// Not (yet) healthy: still starting, warming up, or within the grace
    /// period.
    NotYet,
    /// Failing a health check past the grace period: the scheduler replaces
    /// it.
    Failing {
        stopped_reason: String,
        event: String,
    },
}

/// Whether the task definition gives the essential container `name` a
/// health check ECS evaluates.
fn container_has_health_check(state: &EcsState, task: &Task, name: &str) -> bool {
    state
        .task_definitions
        .get(&task.family)
        .and_then(|revisions| revisions.get(&task.revision))
        .and_then(|td| {
            td.container_definitions
                .iter()
                .find(|c| c.get("name").and_then(|v| v.as_str()) == Some(name))
        })
        .and_then(|c| c.get("healthCheck"))
        .and_then(|h| h.get("command"))
        .and_then(|c| c.as_array())
        .and_then(|cmd| cmd.first())
        .and_then(|v| v.as_str())
        .is_some_and(|first| first != "NONE")
}

fn task_health(state: &EcsState, svc: &Service, task: &Task, ctx: &StepContext<'_>) -> Health {
    if task.last_status != "RUNNING" || task.desired_status == "STOPPED" {
        return Health::NotYet;
    }
    let grace = Duration::seconds(i64::from(
        svc.health_check_grace_period_seconds.unwrap_or(0).max(0),
    ));
    let in_grace = task.started_at.is_some_and(|s| ctx.now < s + grace);

    let checked: Vec<_> = task
        .containers
        .iter()
        .filter(|c| c.essential && container_has_health_check(state, task, &c.name))
        .collect();
    if !in_grace
        && checked
            .iter()
            .any(|c| c.health_status.as_deref() == Some("UNHEALTHY"))
    {
        return Health::Failing {
            stopped_reason: "Task failed container health checks".to_string(),
            event: format!(
                "(service {}) (task {}) failed container health checks.",
                svc.service_name, task.task_id
            ),
        };
    }
    let containers_healthy = checked
        .iter()
        .all(|c| c.health_status.as_deref() == Some("HEALTHY"));

    let lb_healthy = if svc.load_balancers.is_empty() || !ctx.evaluate_lb {
        true
    } else {
        match ctx.lb_health.get(&task.task_id) {
            Some(LbHealth::Healthy) => true,
            Some(LbHealth::Unhealthy {
                target_group_arn,
                port,
                reason,
            }) if !in_grace => {
                let port = port.map(|p| format!(" (port {p})")).unwrap_or_default();
                return Health::Failing {
                    stopped_reason: format!(
                        "Task failed ELB health checks in (target-group {target_group_arn})"
                    ),
                    event: format!(
                        "(service {}) (task {}){port} is unhealthy in (target-group {target_group_arn}) due to (reason {reason}).",
                        svc.service_name, task.task_id
                    ),
                };
            }
            _ => false,
        }
    };

    let settled = task
        .started_at
        .is_none_or(|s| ctx.now - s >= Duration::seconds(RUNNING_SETTLE_SECS));
    if containers_healthy && lb_healthy && settled {
        Health::Healthy
    } else {
        Health::NotYet
    }
}

/// What a round needs to know about one task of the service.
struct TaskInfo {
    id: String,
    deployment: Option<String>,
    created_at: DateTime<Utc>,
    live: bool,
    stopping: bool,
    occupying: bool,
    pending: bool,
    protected: bool,
    healthy: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FailureKind {
    /// Stopped before it was ever healthy.
    Start,
    /// Replaced for failing a health check.
    HealthCheck,
}

struct Step<'a, 'c> {
    ctx: &'a StepContext<'c>,
    out: StepOutcome,
    /// Service events, in the order they happened.
    events: Vec<String>,
}

impl Step<'_, '_> {
    fn run(&mut self, state: &mut EcsState, svc: &mut Service) {
        if svc.deployments.is_empty() {
            // A service under this controller always has a PRIMARY
            // deployment; one stored without any gets it here.
            svc.deployments.push(Deployment::new_primary(
                &svc.task_definition_arn,
                svc.desired_count.max(0),
                &svc.launch_type,
                &[],
            ));
            self.out.changed = true;
        }
        self.attribute_tasks(state, svc);
        if self.ctx.full_pass {
            self.observe_health(state, svc);
            self.account_stops(state, svc);
            self.replace_failing(state, svc);
        }
        self.drain(state, svc);
        self.launch(state, svc);
        if self.ctx.full_pass {
            self.retire_drained(state, svc);
            self.complete(state, svc);
        }
        self.update_counts(state, svc);
    }

    fn snapshot(&self, state: &EcsState, svc: &Service) -> Vec<TaskInfo> {
        service_tasks(state, svc)
            .into_iter()
            .map(|t| TaskInfo {
                id: t.task_id.clone(),
                deployment: t.deployment_id.clone(),
                created_at: t.created_at,
                live: is_live(t),
                stopping: is_stopping(t),
                occupying: t.last_status != "STOPPED",
                pending: is_pending(t),
                protected: is_protected(t, self.ctx.now),
                healthy: task_health(state, svc, t, self.ctx) == Health::Healthy,
            })
            .collect()
    }

    /// Record on each task the deployment it belongs to.
    fn attribute_tasks(&mut self, state: &mut EcsState, svc: &Service) {
        let owners: Vec<(String, String)> = service_tasks(state, svc)
            .into_iter()
            .filter_map(|t| {
                let owner = owning_deployment(svc, t)?;
                (t.deployment_id.as_deref() != Some(owner.deployment_id.as_str()))
                    .then(|| (t.task_id.clone(), owner.deployment_id.clone()))
            })
            .collect();
        for (task_id, deployment_id) in owners {
            if let Some(t) = state.tasks.get_mut(&task_id) {
                t.deployment_id = Some(deployment_id);
                self.out.changed = true;
            }
        }
    }

    /// Stamp tasks that became healthy. A healthy task ends its deployment's
    /// run of failures (`resetOnHealthyTask`, on by default).
    fn observe_health(&mut self, state: &mut EcsState, svc: &mut Service) {
        let newly_healthy: Vec<(String, Option<String>)> = service_tasks(state, svc)
            .into_iter()
            .filter(|t| t.healthy_at.is_none() && is_live(t))
            .filter(|t| task_health(state, svc, t, self.ctx) == Health::Healthy)
            .map(|t| (t.task_id.clone(), t.deployment_id.clone()))
            .collect();
        for (task_id, deployment_id) in newly_healthy {
            if let Some(t) = state.tasks.get_mut(&task_id) {
                t.healthy_at = Some(self.ctx.now);
            }
            if let Some(d) = deployment_mut(svc, deployment_id.as_deref()) {
                d.throttle_failures = 0;
                d.next_launch_at = None;
                d.throttle_reported = false;
                if d.status == "PRIMARY" && d.rollout_state == "IN_PROGRESS" {
                    d.failed_tasks = 0;
                }
            }
            self.out.changed = true;
        }
    }

    /// Count tasks that stopped since the last round. One that stopped on
    /// its own before it was ever healthy failed to start.
    fn account_stops(&mut self, state: &mut EcsState, svc: &mut Service) {
        let mut stopped: Vec<(DateTime<Utc>, String)> = service_tasks(state, svc)
            .into_iter()
            .filter(|t| t.last_status == "STOPPED" && !t.stop_accounted)
            .map(|t| (t.stopped_at.unwrap_or(t.created_at), t.task_id.clone()))
            .collect();
        stopped.sort();
        for (_, task_id) in stopped {
            let Some(t) = state.tasks.get_mut(&task_id) else {
                continue;
            };
            t.stop_accounted = true;
            self.out.changed = true;
            let requested = matches!(
                t.stop_code.as_deref(),
                Some("UserInitiated" | "ServiceSchedulerInitiated")
            );
            if requested || t.healthy_at.is_some() {
                continue;
            }
            let deployment_id = t.deployment_id.clone();
            self.record_failure(svc, deployment_id.as_deref(), FailureKind::Start);
        }
    }

    /// Stop tasks that fail their container or load-balancer health checks
    /// past the grace period; their deployment launches replacements.
    fn replace_failing(&mut self, state: &mut EcsState, svc: &mut Service) {
        let failing: Vec<(String, Option<String>, String, String)> = service_tasks(state, svc)
            .into_iter()
            .filter(|t| is_live(t))
            .filter_map(|t| match task_health(state, svc, t, self.ctx) {
                Health::Failing {
                    stopped_reason,
                    event,
                } => Some((
                    t.task_id.clone(),
                    t.deployment_id.clone(),
                    stopped_reason,
                    event,
                )),
                _ => None,
            })
            .collect();
        if failing.is_empty() {
            return;
        }
        let mut stopped = Vec::with_capacity(failing.len());
        for (task_id, deployment_id, reason, event) in failing {
            self.events.push(event);
            self.stop_task(state, &task_id, &reason);
            if let Some(t) = state.tasks.get_mut(&task_id) {
                t.stop_accounted = true;
            }
            stopped.push(task_id);
            self.record_failure(svc, deployment_id.as_deref(), FailureKind::HealthCheck);
        }
        self.events
            .push(stopped_tasks_event(svc, "running", &stopped));
    }

    fn record_failure(
        &mut self,
        svc: &mut Service,
        deployment_id: Option<&str>,
        kind: FailureKind,
    ) {
        let now = self.ctx.now;
        let threshold = circuit_breaker_threshold(svc.desired_count);
        let breaker = svc.circuit_breaker.clone().filter(|cb| cb.enable);
        let service_name = svc.service_name.clone();
        let Some(d) = deployment_mut(svc, deployment_id) else {
            return;
        };
        if kind == FailureKind::Start {
            d.throttle_failures = d.throttle_failures.saturating_add(1);
            if let Some(delay) = throttle_delay(d.throttle_failures) {
                d.next_launch_at = Some(now + delay);
                if !d.throttle_reported {
                    d.throttle_reported = true;
                    self.events.push(format!(
                        "(service {service_name}) is unable to consistently start tasks successfully."
                    ));
                }
            }
        }
        // Only the rollout of the PRIMARY deployment is evaluated, and only
        // until it completes or fails.
        if d.status != "PRIMARY" || d.rollout_state != "IN_PROGRESS" {
            return;
        }
        d.failed_tasks = d.failed_tasks.saturating_add(1);
        d.last_failure_health_check = kind == FailureKind::HealthCheck;
        d.updated_at = now;
        let failed = d.failed_tasks;
        let id = d.deployment_id.clone();
        if let Some(cb) = breaker {
            if failed >= threshold {
                self.fail_deployment(svc, &id, cb.rollback);
            }
        }
    }

    /// The circuit breaker fails a deployment: it launches nothing more and,
    /// with rollback on, the service rolls back to the most recent COMPLETED
    /// deployment through a new deployment of its task definition.
    fn fail_deployment(&mut self, svc: &mut Service, deployment_id: &str, rollback: bool) {
        let now = self.ctx.now;
        let service_name = svc.service_name.clone();
        let service_arn = svc.service_arn.clone();
        let Some(d) = deployment_mut(svc, Some(deployment_id)) else {
            return;
        };
        let what = if d.last_failure_health_check {
            "tasks failed health checks."
        } else {
            "tasks failed to start."
        };
        let reason = format!("ECS deployment circuit breaker: {what}");
        d.rollout_state = "FAILED".into();
        d.rollout_state_reason = Some(reason.clone());
        d.updated_at = now;
        let was_rollback = d.is_rollback;
        self.events.push(format!(
            "(service {service_name}) (deployment {deployment_id}) deployment failed: {what}"
        ));
        self.out.deployment_events.push(DeploymentStateChange {
            service_arn: service_arn.clone(),
            deployment_id: deployment_id.to_string(),
            event_name: "SERVICE_DEPLOYMENT_FAILED",
            event_type: "ERROR",
            reason,
            at: now,
        });
        // A failed rollback is not rolled back again; without a COMPLETED
        // deployment there is nothing to roll back to and the service stalls.
        if !rollback || was_rollback {
            return;
        }
        let Some(target) = svc
            .deployments
            .iter()
            .find(|d| d.deployment_id != deployment_id && d.rollout_state == "COMPLETED")
            .map(|d| (d.deployment_id.clone(), d.task_definition_arn.clone()))
        else {
            return;
        };
        let (target_id, target_td) = target;
        let mut rollback_deployment =
            Deployment::new_primary(&target_td, svc.desired_count.max(0), &svc.launch_type, &[]);
        rollback_deployment.is_rollback = true;
        rollback_deployment.created_at = now;
        rollback_deployment.updated_at = now;
        rollback_deployment.rollout_state_reason = Some(format!(
            "ECS deployment circuit breaker: rolling back to deploymentId {target_id}."
        ));
        if let Some(d) = deployment_mut(svc, Some(deployment_id)) {
            d.status = "ACTIVE".into();
        }
        if let Some((family, revision)) = parse_task_definition_arn(&target_td) {
            svc.family = family;
            svc.revision = revision;
        }
        svc.task_definition_arn = target_td;
        self.events.push(format!(
            "(service {service_name}) rolling back to deployment {target_id}."
        ));
        self.out
            .deployment_events
            .push(DeploymentStateChange::in_progress(
                &service_arn,
                &rollback_deployment,
            ));
        svc.deployments.insert(0, rollback_deployment);
        self.out.changed = true;
    }

    /// Scale tasks in: the PRIMARY deployment down to the desired count, and
    /// older deployments as far as the minimum healthy bound allows.
    fn drain(&mut self, state: &mut EcsState, svc: &mut Service) {
        let Some(primary) = svc.deployments.iter().find(|d| d.status == "PRIMARY") else {
            return;
        };
        let primary_id = primary.deployment_id.clone();
        let primary_failed = primary.rollout_state == "FAILED";
        let desired = svc.desired_count.max(0);
        let min_healthy = minimum_healthy_tasks(
            desired,
            svc.minimum_healthy_percent
                .unwrap_or(DEFAULT_MINIMUM_HEALTHY_PERCENT),
        );
        let infos = self.snapshot(state, svc);
        let mut healthy = infos.iter().filter(|i| i.live && i.healthy).count() as i32;
        let mut stops: Vec<(String, bool)> = Vec::new();

        // Scale-in order: pending tasks, then running ones not yet healthy,
        // then healthy ones; newest first within each.
        let order = |a: &&TaskInfo, b: &&TaskInfo| {
            (a.healthy, !a.pending, std::cmp::Reverse(a.created_at)).cmp(&(
                b.healthy,
                !b.pending,
                std::cmp::Reverse(b.created_at),
            ))
        };

        // The PRIMARY deployment above the desired count (the desired count
        // went down). Protected tasks go last, only when nothing else is left.
        let mut primary_live: Vec<&TaskInfo> = infos
            .iter()
            .filter(|i| i.live && i.deployment.as_deref() == Some(primary_id.as_str()))
            .collect();
        primary_live.sort_by(|a, b| a.protected.cmp(&b.protected).then_with(|| order(a, b)));
        let excess = primary_live.len() as i32 - desired;
        for t in primary_live.iter().take(excess.max(0) as usize) {
            if t.healthy {
                healthy -= 1;
            }
            stops.push((t.id.clone(), !t.pending));
        }

        // Older deployments drain while the service keeps its minimum
        // healthy count. A FAILED PRIMARY (no rollback) freezes them: they
        // keep serving.
        if !primary_failed {
            let old_ids: Vec<String> = svc
                .deployments
                .iter()
                .rev()
                .filter(|d| d.status == "ACTIVE")
                .map(|d| d.deployment_id.clone())
                .collect();
            for old_id in old_ids {
                let mut live: Vec<&TaskInfo> = infos
                    .iter()
                    .filter(|i| i.live && i.deployment.as_deref() == Some(old_id.as_str()))
                    .collect();
                live.sort_by(order);
                let Some(d) = deployment_mut(svc, Some(&old_id)) else {
                    continue;
                };
                // Slots of tasks that stopped on their own are not refilled
                // once the service is at minimum healthy without them.
                let live_count = live.len() as i32;
                if d.desired_count > live_count
                    && (healthy >= min_healthy || d.rollout_state == "FAILED")
                {
                    d.desired_count = live_count;
                }
                for t in live {
                    if t.protected {
                        continue;
                    }
                    let stoppable = if t.healthy {
                        healthy > min_healthy
                    } else {
                        healthy >= min_healthy
                    };
                    if !stoppable {
                        continue;
                    }
                    if t.healthy {
                        healthy -= 1;
                    }
                    d.desired_count = (d.desired_count - 1).max(0);
                    stops.push((t.id.clone(), !t.pending));
                }
            }
        }

        if stops.is_empty() {
            return;
        }
        let reason = format!("Scaling activity initiated by (deployment {primary_id})");
        let running: Vec<String> = stops
            .iter()
            .filter(|(_, running)| *running)
            .map(|(id, _)| id.clone())
            .collect();
        let pending: Vec<String> = stops
            .iter()
            .filter(|(_, running)| !*running)
            .map(|(id, _)| id.clone())
            .collect();
        for (id, _) in &stops {
            self.stop_task(state, id, &reason);
        }
        if !running.is_empty() {
            self.events
                .push(stopped_tasks_event(svc, "running", &running));
        }
        if !pending.is_empty() {
            self.events
                .push(stopped_tasks_event(svc, "pending", &pending));
        }
    }

    /// Launch tasks within the maximum: the PRIMARY deployment up to the
    /// desired count first, then replacements for older deployments that
    /// lost tasks while the service is below its minimum healthy count.
    fn launch(&mut self, state: &mut EcsState, svc: &mut Service) {
        let Some(primary_index) = svc.deployments.iter().position(|d| d.status == "PRIMARY") else {
            return;
        };
        let now = self.ctx.now;
        let desired = svc.desired_count.max(0);
        let max_tasks = maximum_tasks(
            desired,
            svc.maximum_percent.unwrap_or(DEFAULT_MAXIMUM_PERCENT),
        );
        let infos = self.snapshot(state, svc);
        let occupying = infos.iter().filter(|i| i.occupying).count() as i32;
        let mut capacity = (max_tasks - occupying).max(0);
        let live_of = |id: &str| {
            infos
                .iter()
                .filter(|i| i.live && i.deployment.as_deref() == Some(id))
                .count() as i32
        };

        let mut order = vec![primary_index];
        order.extend(
            svc.deployments
                .iter()
                .enumerate()
                .filter(|(_, d)| d.status == "ACTIVE")
                .map(|(i, _)| i),
        );
        let mut started: Vec<String> = Vec::new();
        let mut primary_short = 0;
        for index in order {
            let d = &svc.deployments[index];
            let target = if index == primary_index {
                desired
            } else {
                d.desired_count
            };
            let want = (target - live_of(&d.deployment_id)).max(0);
            if index == primary_index {
                primary_short = want;
            }
            if want == 0
                || d.rollout_state == "FAILED"
                || d.next_launch_at.is_some_and(|at| at > now)
            {
                continue;
            }
            let n = want.min(capacity);
            if n == 0 {
                continue;
            }
            let ids = spawn_for_deployment(state, svc, index, n);
            capacity -= ids.len() as i32;
            started.extend(ids);
        }
        if !started.is_empty() {
            self.events.push(format!(
                "(service {}) has started {} tasks: {}.",
                svc.service_name,
                started.len(),
                task_list(&started)
            ));
            self.out.changed = true;
            self.out.launched.extend(started);
            return;
        }

        // The deployment can neither start nor stop a task: the bounds leave
        // no room (for example 100% minimum and 100% maximum).
        let primary = &mut svc.deployments[primary_index];
        let wedged = self.ctx.full_pass
            && primary_short > 0
            && capacity == 0
            && primary.rollout_state == "IN_PROGRESS"
            && infos
                .iter()
                .filter(|i| i.occupying)
                .all(|i| i.live && !i.pending && !i.stopping);
        if wedged && !primary.config_stuck_reported {
            primary.config_stuck_reported = true;
            self.events.push(format!(
                "(service {}) was unable to stop or start tasks during a deployment because of \
                 the service deployment configuration. Update the minimumHealthyPercent or \
                 maximumPercent value and try again.",
                svc.service_name
            ));
        }
    }

    /// Deployments other than the PRIMARY with no task left become INACTIVE
    /// and drop out of DescribeServices. A FAILED one stays listed while the
    /// PRIMARY deployment (its rollback, or the next deployment) is still in
    /// progress, so the failure can be seen; the PRIMARY completing retires
    /// it.
    fn retire_drained(&mut self, state: &EcsState, svc: &mut Service) {
        let infos = self.snapshot(state, svc);
        let now = self.ctx.now;
        let primary_in_progress = svc
            .deployments
            .iter()
            .any(|d| d.status == "PRIMARY" && d.rollout_state == "IN_PROGRESS");
        for d in svc.deployments.iter_mut().filter(|d| d.status == "ACTIVE") {
            let failed = d.rollout_state == "FAILED";
            if holds_tasks(&infos, &d.deployment_id)
                || (d.desired_count > 0 && !failed)
                || (failed && primary_in_progress)
            {
                continue;
            }
            retire(d, now);
            self.out.changed = true;
        }
        let mut inactive_seen = 0;
        svc.deployments.retain(|d| {
            if d.status != "INACTIVE" {
                return true;
            }
            inactive_seen += 1;
            inactive_seen <= MAX_INACTIVE_DEPLOYMENTS
        });
    }

    /// The PRIMARY deployment completes once it runs the desired count of
    /// healthy tasks and every other deployment has drained; the service has
    /// then reached a steady state.
    fn complete(&mut self, state: &mut EcsState, svc: &mut Service) {
        let infos = self.snapshot(state, svc);
        let desired = svc.desired_count.max(0);
        let service_name = svc.service_name.clone();
        let service_arn = svc.service_arn.clone();
        // Drained FAILED deployments wait for this completion to retire.
        let others_remain = svc.deployments.iter().any(|d| {
            d.status != "PRIMARY"
                && d.status != "INACTIVE"
                && (d.rollout_state != "FAILED" || holds_tasks(&infos, &d.deployment_id))
        });
        let now = self.ctx.now;
        let Some(primary) = svc.deployments.iter_mut().find(|d| d.status == "PRIMARY") else {
            return;
        };
        let mine = |i: &&TaskInfo| i.deployment.as_deref() == Some(primary.deployment_id.as_str());
        let live = infos.iter().filter(mine).filter(|i| i.live).count() as i32;
        let healthy = infos
            .iter()
            .filter(mine)
            .filter(|i| i.live && i.healthy)
            .count() as i32;
        let stray = infos.iter().any(|i| {
            i.occupying
                && (i.stopping || i.deployment.as_deref() != Some(primary.deployment_id.as_str()))
        });
        let at_desired = live == desired && healthy == desired && !stray && !others_remain;
        if at_desired && primary.rollout_state == "IN_PROGRESS" && primary.pending_hook_id.is_none()
        {
            let reason = format!("ECS deployment {} completed.", primary.deployment_id);
            primary.rollout_state = "COMPLETED".into();
            primary.rollout_state_reason = Some(reason.clone());
            primary.updated_at = now;
            self.events.push(format!(
                "(service {service_name}) (deployment {}) deployment completed.",
                primary.deployment_id
            ));
            self.out.deployment_events.push(DeploymentStateChange {
                service_arn: service_arn.clone(),
                deployment_id: primary.deployment_id.clone(),
                event_name: "SERVICE_DEPLOYMENT_COMPLETED",
                event_type: "INFO",
                reason,
                at: now,
            });
            self.out.changed = true;
            for d in svc.deployments.iter_mut().filter(|d| d.status == "ACTIVE") {
                retire(d, now);
            }
        }
        let steady = at_desired
            && svc
                .deployments
                .iter()
                .any(|d| d.status == "PRIMARY" && d.rollout_state == "COMPLETED");
        let log = state.service_events.entry(service_arn).or_default();
        if steady && !log.steady {
            self.events.push(format!(
                "(service {service_name}) has reached a steady state."
            ));
        }
        if log.steady != steady {
            log.steady = steady;
            self.out.changed = true;
        }
    }

    /// Per-deployment and service running / pending counts.
    fn update_counts(&mut self, state: &EcsState, svc: &mut Service) {
        let tasks = service_tasks(state, svc);
        let count = |deployment: Option<&str>, pred: fn(&Task) -> bool| {
            tasks
                .iter()
                .filter(|t| deployment.is_none_or(|id| t.deployment_id.as_deref() == Some(id)))
                .filter(|t| pred(t))
                .count() as i32
        };
        let running = |t: &Task| t.last_status == "RUNNING";
        for d in svc.deployments.iter_mut() {
            let r = count(Some(&d.deployment_id), running);
            let p = count(Some(&d.deployment_id), is_pending);
            if (d.running_count, d.pending_count) != (r, p) {
                d.running_count = r;
                d.pending_count = p;
                self.out.changed = true;
            }
        }
        let r = count(None, running);
        let p = count(None, is_pending);
        if (svc.running_count, svc.pending_count) != (r, p) {
            svc.running_count = r;
            svc.pending_count = p;
            self.out.changed = true;
        }
    }

    /// Mark a task for stopping by the service scheduler.
    fn stop_task(&mut self, state: &mut EcsState, task_id: &str, reason: &str) {
        let Some(t) = state.tasks.get_mut(task_id) else {
            return;
        };
        t.desired_status = "STOPPED".into();
        t.stopping_at = Some(self.ctx.now);
        t.stop_code = Some("ServiceSchedulerInitiated".into());
        t.stopped_reason = Some(reason.to_string());
        self.out
            .stopped
            .push((task_id.to_string(), reason.to_string()));
        self.out.changed = true;
    }
}

/// Whether any task of the deployment is still RUNNING or PENDING.
fn holds_tasks(infos: &[TaskInfo], deployment_id: &str) -> bool {
    infos
        .iter()
        .any(|i| i.occupying && i.deployment.as_deref() == Some(deployment_id))
}

/// A deployment that has been completely replaced.
fn retire(d: &mut Deployment, now: DateTime<Utc>) {
    d.status = "INACTIVE".into();
    d.desired_count = 0;
    d.pending_count = 0;
    d.running_count = 0;
    d.updated_at = now;
}

fn deployment_mut<'a>(svc: &'a mut Service, id: Option<&str>) -> Option<&'a mut Deployment> {
    let id = id?;
    svc.deployments.iter_mut().find(|d| d.deployment_id == id)
}

fn task_list(ids: &[String]) -> String {
    ids.iter()
        .map(|id| format!("(task {id})"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn stopped_tasks_event(svc: &Service, kind: &str, ids: &[String]) -> String {
    format!(
        "(service {}) has stopped {} {kind} tasks: {}.",
        svc.service_name,
        ids.len(),
        task_list(ids)
    )
}

/// `family` and `revision` of a task definition ARN
/// (`...:task-definition/<family>:<revision>`).
pub(crate) fn parse_task_definition_arn(arn: &str) -> Option<(String, i32)> {
    let tail = arn.rsplit_once("task-definition/")?.1;
    let (family, revision) = tail.rsplit_once(':')?;
    Some((family.to_string(), revision.parse().ok()?))
}

/// Create `count` PENDING tasks for the deployment at `index`, running its
/// task definition.
fn spawn_for_deployment(
    state: &mut EcsState,
    svc: &Service,
    index: usize,
    count: i32,
) -> Vec<String> {
    let deployment = &svc.deployments[index];
    let Some((family, revision)) = parse_task_definition_arn(&deployment.task_definition_arn)
    else {
        return Vec::new();
    };
    let mut template = svc.clone();
    template.task_definition_arn = deployment.task_definition_arn.clone();
    template.family = family;
    template.revision = revision;
    // The scheduler has no request region; tasks stay in the region the
    // service's ARN carries.
    let region = svc
        .cluster_arn
        .split(':')
        .nth(3)
        .map(str::to_string)
        .unwrap_or_else(|| state.region.clone());
    let launch_type = if svc.launch_type.is_empty() {
        "FARGATE"
    } else {
        svc.launch_type.as_str()
    };
    let ids = crate::service::spawn_service_tasks(
        state,
        &region,
        &template,
        count,
        svc.role_arn.as_deref().unwrap_or(""),
        launch_type,
        None,
    );
    for id in &ids {
        if let Some(t) = state.tasks.get_mut(id) {
            t.deployment_id = Some(deployment.deployment_id.clone());
        }
    }
    ids
}

#[cfg(test)]
#[path = "rollout_tests.rs"]
mod tests;
