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

    /// A `STOPPED` task's published awsvpc ports and its ENI go, as on ECS.
    /// Its load balancer targets are not touched: on the Docker backend they
    /// went when it started stopping ([`Self::begin_stopping`]), and its
    /// containers are already gone, so a replacement may by now have taken
    /// the same `host:port` target (bridge / host mode with a fixed host
    /// port) -- deregistering again would remove the replacement's. The
    /// Kubernetes backend deregisters on its own before calling this.
    pub(super) fn release_task_network(
        &self,
        state: &SharedEcsState,
        account_id: &str,
        task_id: &str,
    ) {
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

    /// The task starts stopping: a RUNNING task shows `STOPPING`, and the
    /// task leaves its target groups before any container is signalled.
    /// The targets go whatever the status says -- an agent's
    /// SubmitTaskStateChange may have rewritten it while the runtime runs
    /// the task -- which is safe because the task's containers still run:
    /// no replacement can hold the same `host:port` target yet.
    pub(super) fn begin_stopping(&self, state: &SharedEcsState, account_id: &str, task_id: &str) {
        mark_stopping(state, account_id, task_id);
        self.deregister_lb_targets(state, account_id, task_id);
    }

    /// A task whose run failed after it started (its targets possibly
    /// registered, its ENI attached) leaves its target groups and releases
    /// its network before it is marked `STOPPED`, as a stopped task does.
    /// Its containers are not yet gone for good and nothing replaces it
    /// before `STOPPED`. A task that never started registered nothing and is
    /// left alone. Idempotent.
    pub(super) fn release_failed_task(
        &self,
        state: &SharedEcsState,
        account_id: &str,
        task_id: &str,
    ) {
        let started = state
            .read()
            .get(account_id)
            .and_then(|s| s.tasks.get(task_id))
            .is_some_and(|t| t.started_at.is_some());
        if started {
            self.deregister_lb_targets(state, account_id, task_id);
            self.release_task_network(state, account_id, task_id);
        }
    }

    /// Register a task that just went RUNNING with its load balancers,
    /// unless a stop has landed meanwhile. A stop between the RUNNING
    /// transition and this registration already moved the task to
    /// `STOPPING` (deregistering nothing), and nothing would take the new
    /// targets out again while its containers drain: re-check after
    /// registering and deregister such a task.
    pub(super) fn register_lb_targets_unless_stopping(
        &self,
        state: &SharedEcsState,
        account_id: &str,
        task_id: &str,
    ) {
        self.register_lb_targets(state, account_id, task_id);
        if task_desired_stopped(state, account_id, task_id) {
            mark_stopping(state, account_id, task_id);
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
