//! Runs the service scheduler ([`crate::rollout`]) against the shared ECS
//! state: reads target-group health, steps each service, and hands the task
//! launches and stops it decides on to the container runtime.

use std::collections::BTreeMap;

use chrono::Utc;

use crate::rollout::{self, DeploymentStateChange, LbHealth, StepContext};
use crate::state::EcsState;

use super::*;

/// Load-balancer health per account, then per task ID.
type LbHealthByAccount = BTreeMap<String, BTreeMap<String, LbHealth>>;

impl EcsService {
    /// One scheduling round. `only` limits it to one service
    /// (`(account_id, "cluster/service")`), which is what an API call runs
    /// right away; `full_pass` is the ticker's complete round (see
    /// [`StepContext::full_pass`]). Returns whether the state changed.
    pub(crate) fn schedule_services(&self, only: Option<(&str, &str)>, full_pass: bool) -> bool {
        let now = Utc::now();
        let lb_health = self.observe_load_balancer_health(only);
        let evaluate_lb = self
            .runtime
            .as_ref()
            .is_some_and(|rt| rt.evaluates_target_health());
        let empty = BTreeMap::new();
        let mut launches: Vec<(String, String)> = Vec::new();
        let mut stops: Vec<(String, String)> = Vec::new();
        let mut deployment_events: Vec<(String, DeploymentStateChange)> = Vec::new();
        let mut changed = false;
        {
            let mut accounts = self.state.write();
            for (account_id, state) in accounts.iter_mut() {
                if only.is_some_and(|(account, _)| account != account_id) {
                    continue;
                }
                let keys: Vec<String> = match only {
                    Some((_, key)) => vec![key.to_string()],
                    None => state.services.keys().cloned().collect(),
                };
                let ctx = StepContext {
                    now,
                    lb_health: lb_health.get(account_id).unwrap_or(&empty),
                    evaluate_lb,
                    full_pass,
                };
                for key in keys {
                    let out = rollout::step_service(state, &key, &ctx);
                    changed |= out.changed;
                    if self.runtime.is_none() {
                        for id in &out.launched {
                            fail_without_runtime(state, id);
                        }
                        for (id, _) in &out.stopped {
                            stop_without_runtime(state, id);
                        }
                    }
                    launches.extend(
                        out.launched
                            .into_iter()
                            .map(|id| (account_id.to_string(), id)),
                    );
                    stops.extend(out.stopped);
                    deployment_events.extend(
                        out.deployment_events
                            .into_iter()
                            .map(|e| (account_id.to_string(), e)),
                    );
                }
            }
        }
        if let Some(rt) = &self.runtime {
            for (account_id, task_id) in launches {
                rt.clone().run_task(self.state.clone(), task_id, account_id);
            }
            for (task_id, reason) in stops {
                let rt = rt.clone();
                tokio::spawn(async move {
                    rt.stop_task(&task_id, &reason).await;
                });
            }
            for (account_id, event) in &deployment_events {
                rt.emit_deployment_state_change(account_id, event);
            }
        }
        changed
    }

    /// Emit `SERVICE_DEPLOYMENT_IN_PROGRESS` for a deployment an API call
    /// just started.
    pub(crate) fn emit_deployment_started(
        &self,
        account_id: &str,
        service_arn: &str,
        deployment: &crate::state::Deployment,
    ) {
        if let Some(rt) = &self.runtime {
            rt.emit_deployment_state_change(
                account_id,
                &DeploymentStateChange::in_progress(service_arn, deployment),
            );
        }
    }

    /// Health of every RUNNING task of the services behind load balancers,
    /// read from their target groups. Read outside the ECS state lock.
    fn observe_load_balancer_health(&self, only: Option<(&str, &str)>) -> LbHealthByAccount {
        let Some(rt) = self
            .runtime
            .as_ref()
            .filter(|rt| rt.evaluates_target_health())
        else {
            return BTreeMap::new();
        };
        type Targets = Vec<(String, Vec<(String, Option<i64>)>)>;
        let mut queries: Vec<(String, String, Targets)> = Vec::new();
        {
            let accounts = self.state.read();
            for (account_id, state) in accounts.iter() {
                if only.is_some_and(|(account, _)| account != account_id) {
                    continue;
                }
                for (key, svc) in &state.services {
                    if svc.status != "ACTIVE"
                        || svc.load_balancers.is_empty()
                        || only.is_some_and(|(_, k)| k != key)
                    {
                        continue;
                    }
                    for task in rollout::service_tasks(state, svc) {
                        if task.last_status != "RUNNING" || task.desired_status == "STOPPED" {
                            continue;
                        }
                        queries.push((
                            account_id.to_string(),
                            task.task_id.clone(),
                            crate::runtime::compute_elbv2_targets(state, task),
                        ));
                    }
                }
            }
        }
        let mut health = LbHealthByAccount::new();
        for (account_id, task_id, targets) in queries {
            if targets.is_empty() {
                continue;
            }
            let mut combined = LbHealth::Healthy;
            for (tg_arn, ids) in &targets {
                for (target_id, port) in ids {
                    let view = rt.target_health(&account_id, tg_arn, target_id, *port);
                    combined = combined.and(LbHealth::of_target(view.as_ref(), tg_arn, *port));
                }
            }
            health
                .entry(account_id)
                .or_default()
                .insert(task_id, combined);
        }
        health
    }
}

/// Without a container runtime a launched task can't start: it stops at
/// once, as ECS reports a task that failed to start.
fn fail_without_runtime(state: &mut EcsState, task_id: &str) {
    let Some(t) = state.tasks.get_mut(task_id) else {
        return;
    };
    t.last_status = "STOPPED".into();
    t.desired_status = "STOPPED".into();
    t.stop_code = Some("TaskFailedToStart".into());
    t.stopped_reason = Some(format!(
        "No container runtime available (docker/podman not installed). {}",
        fakecloud_core::container_net::CONTAINER_RUNTIME_HINT
    ));
    t.stopped_at = Some(Utc::now());
    for c in t.containers.iter_mut() {
        c.last_status = "STOPPED".into();
    }
    let cluster = t.cluster_name.clone();
    if let Some(cluster) = state.clusters.get_mut(&cluster) {
        if cluster.pending_tasks_count > 0 {
            cluster.pending_tasks_count -= 1;
        }
    }
}

/// Without a container runtime there is nothing to wait for: a task the
/// scheduler stops is STOPPED at once, keeping its stop code and reason.
fn stop_without_runtime(state: &mut EcsState, task_id: &str) {
    let Some(t) = state.tasks.get_mut(task_id) else {
        return;
    };
    if t.last_status == "STOPPED" {
        return;
    }
    let was_running = t.started_at.is_some();
    t.last_status = "STOPPED".into();
    t.stopped_at = Some(Utc::now());
    for c in t.containers.iter_mut() {
        c.last_status = "STOPPED".into();
    }
    let cluster = t.cluster_name.clone();
    if let Some(cluster) = state.clusters.get_mut(&cluster) {
        if was_running {
            if cluster.running_tasks_count > 0 {
                cluster.running_tasks_count -= 1;
            }
        } else if cluster.pending_tasks_count > 0 {
            cluster.pending_tasks_count -= 1;
        }
    }
}
