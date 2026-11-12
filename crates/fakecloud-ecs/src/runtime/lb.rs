//! `EcsRuntime` `lb` family — extracted from service.rs by audit-2026-05-19.

use super::*;

impl EcsRuntime {
    pub(super) fn register_lb_targets(
        &self,
        state: &SharedEcsState,
        account_id: &str,
        task_id: &str,
    ) {
        let Some(ref bus) = self.delivery_bus else {
            return;
        };
        let accounts = state.read();
        let Some(s) = accounts.get(account_id) else {
            return;
        };
        let Some(task) = s.tasks.get(task_id) else {
            return;
        };
        let targets = compute_elbv2_targets(s, task);
        drop(accounts);
        for (tg_arn, tg_targets) in targets {
            bus.register_elbv2_targets(account_id, &tg_arn, tg_targets);
        }
    }

    /// Take the task out of its load balancers' target groups, as ECS does
    /// when a task starts stopping (`DEACTIVATING`), before its containers
    /// get the stop signal: the load balancer sends it no new requests while
    /// it drains. Idempotent; the task's ENI and published ports stay until
    /// it is `STOPPED` ([`Self::release_task_network`]).
    pub(super) fn deregister_lb_targets(
        &self,
        state: &SharedEcsState,
        account_id: &str,
        task_id: &str,
    ) {
        let Some(ref bus) = self.delivery_bus else {
            return;
        };
        let accounts = state.read();
        let Some(s) = accounts.get(account_id) else {
            return;
        };
        let Some(task) = s.tasks.get(task_id) else {
            return;
        };
        let targets = compute_elbv2_targets(s, task);
        drop(accounts);
        for (tg_arn, tg_targets) in targets {
            bus.deregister_elbv2_targets(account_id, &tg_arn, tg_targets);
        }
    }

    /// A `STOPPED` task's network goes: its load balancer targets (if a stop
    /// that never passed `STOPPING` left them), its published awsvpc ports
    /// and its ENI, as on ECS.
    pub(super) fn release_task_network(
        &self,
        state: &SharedEcsState,
        account_id: &str,
        task_id: &str,
    ) {
        self.deregister_lb_targets(state, account_id, task_id);
        let accounts = state.read();
        let Some(task) = accounts.get(account_id).and_then(|s| s.tasks.get(task_id)) else {
            return;
        };
        // The task's published awsvpc ports are gone with its containers.
        if let Some(ip) = super::eni::task_eni_ip(task) {
            fakecloud_core::dataplane::unregister_target(account_id, &ip);
        }
        // Its ENI goes with the task, as on ECS.
        if let (Some(bus), Some(eni_id)) = (&self.delivery_bus, super::eni::task_eni_id(task)) {
            bus.delete_task_eni(account_id, &eni_id);
        }
    }

    /// The task starts stopping: a RUNNING task shows `STOPPING` and leaves
    /// its target groups before any container is signalled. No-op for a task
    /// that is not RUNNING (already stopping, or stopped before it ran).
    pub(super) fn begin_stopping(&self, state: &SharedEcsState, account_id: &str, task_id: &str) {
        if mark_stopping(state, account_id, task_id) {
            self.deregister_lb_targets(state, account_id, task_id);
        }
    }

    /// Whether target-group health can be read for this runtime's tasks.
    /// Without it the service scheduler counts a RUNNING task as healthy in
    /// its load balancers.
    pub(crate) fn evaluates_target_health(&self) -> bool {
        self.delivery_bus
            .as_ref()
            .is_some_and(|bus| bus.has_elbv2_target_registration())
    }

    /// Health of one task target in an ELBv2 target group.
    pub(crate) fn target_health(
        &self,
        account_id: &str,
        target_group_arn: &str,
        target_id: &str,
        port: Option<i64>,
    ) -> Option<fakecloud_core::delivery::TargetHealthView> {
        self.delivery_bus.as_ref()?.elbv2_target_health(
            account_id,
            target_group_arn,
            target_id,
            port,
        )
    }
}
