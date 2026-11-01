use super::*;
use crate::state::{CircuitBreakerConfig, Cluster, TaskDefinition};

const ACCOUNT: &str = "111122223333";
const KEY: &str = "default/web";
const TG: &str =
    "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/web/0123456789abcdef";

fn td_arn(revision: i32) -> String {
    format!("arn:aws:ecs:us-east-1:{ACCOUNT}:task-definition/web:{revision}")
}

fn task_definition(revision: i32, health_check: bool) -> TaskDefinition {
    let mut container = serde_json::json!({
        "name": "app",
        "image": "traefik/whoami:v1.10.3",
        "essential": true,
    });
    if health_check {
        container["healthCheck"] = serde_json::json!({"command": ["CMD-SHELL", "true"]});
    }
    TaskDefinition {
        family: "web".into(),
        revision,
        task_definition_arn: td_arn(revision),
        container_definitions: vec![container],
        status: "ACTIVE".into(),
        task_role_arn: None,
        execution_role_arn: None,
        network_mode: Some("awsvpc".into()),
        requires_compatibilities: vec!["FARGATE".into()],
        compatibilities: vec!["FARGATE".into()],
        cpu: Some("256".into()),
        memory: Some("512".into()),
        pid_mode: None,
        ipc_mode: None,
        volumes: vec![],
        placement_constraints: vec![],
        proxy_configuration: None,
        inference_accelerators: vec![],
        ephemeral_storage: None,
        runtime_platform: None,
        requires_attributes: vec![],
        registered_at: Utc::now(),
        registered_by: None,
        deregistered_at: None,
        tags: vec![],
        enable_fault_injection: None,
    }
}

struct Fixture {
    state: EcsState,
    /// Scheduler clock: starts at the real time the tasks are created at and
    /// only moves forward by `advance`.
    now: DateTime<Utc>,
    lb: BTreeMap<String, LbHealth>,
    evaluate_lb: bool,
}

struct Opts {
    desired: i32,
    min: Option<i32>,
    max: Option<i32>,
    breaker: Option<(bool, bool)>,
    load_balanced: bool,
    health_check: bool,
    grace: Option<i32>,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            desired: 2,
            min: None,
            max: None,
            breaker: None,
            load_balanced: false,
            health_check: false,
            grace: None,
        }
    }
}

impl Fixture {
    fn new(opts: Opts) -> Self {
        let mut state = EcsState::new(ACCOUNT, "us-east-1");
        let cluster_arn = state.cluster_arn("us-east-1", "default");
        state.clusters.insert(
            "default".into(),
            Cluster::new("default", cluster_arn.clone()),
        );
        for revision in 1..=2 {
            state
                .task_definitions
                .entry("web".into())
                .or_default()
                .insert(revision, task_definition(revision, opts.health_check));
        }
        let svc = Service {
            service_name: "web".into(),
            service_arn: format!("arn:aws:ecs:us-east-1:{ACCOUNT}:service/default/web"),
            cluster_name: "default".into(),
            cluster_arn,
            task_definition_arn: td_arn(1),
            family: "web".into(),
            revision: 1,
            desired_count: opts.desired,
            running_count: 0,
            pending_count: 0,
            launch_type: "FARGATE".into(),
            status: "ACTIVE".into(),
            scheduling_strategy: "REPLICA".into(),
            deployment_controller: "ECS".into(),
            minimum_healthy_percent: opts.min,
            maximum_percent: opts.max,
            circuit_breaker: opts
                .breaker
                .map(|(enable, rollback)| CircuitBreakerConfig { enable, rollback }),
            deployments: vec![Deployment::new_primary(
                &td_arn(1),
                opts.desired,
                "FARGATE",
                &[],
            )],
            load_balancers: if opts.load_balanced {
                vec![serde_json::json!({
                    "targetGroupArn": TG,
                    "containerName": "app",
                    "containerPort": 8080,
                })]
            } else {
                vec![]
            },
            service_registries: vec![],
            placement_constraints: vec![],
            placement_strategy: vec![],
            network_configuration: None,
            tags: vec![],
            created_at: Utc::now() - Duration::hours(1),
            created_by: None,
            role_arn: None,
            platform_version: None,
            health_check_grace_period_seconds: opts.grace,
            enable_execute_command: false,
            enable_ecs_managed_tags: false,
            propagate_tags: None,
            capacity_provider_strategy: vec![],
            availability_zone_rebalancing: None,
            volume_configurations: vec![],
            service_connect_configuration: None,
            vpc_lattice_configurations: vec![],
        };
        state.services.insert(KEY.into(), svc);
        Self {
            state,
            now: Utc::now(),
            lb: BTreeMap::new(),
            evaluate_lb: opts.load_balanced,
        }
    }

    fn advance(&mut self, secs: i64) {
        self.now += Duration::seconds(secs);
    }

    fn step(&mut self, full_pass: bool) -> StepOutcome {
        let ctx = StepContext {
            now: self.now,
            lb_health: &self.lb,
            evaluate_lb: self.evaluate_lb,
            full_pass,
        };
        let out = step_service(&mut self.state, KEY, &ctx);
        self.check_bounds();
        out
    }

    /// A scheduler ticker round.
    fn tick(&mut self) -> StepOutcome {
        self.step(true)
    }

    /// The immediate round an API call runs.
    fn api(&mut self) -> StepOutcome {
        self.step(false)
    }

    fn svc(&self) -> &Service {
        &self.state.services[KEY]
    }

    fn svc_mut(&mut self) -> &mut Service {
        self.state.services.get_mut(KEY).unwrap()
    }

    fn deployment(&self, id: &str) -> &Deployment {
        self.svc()
            .deployments
            .iter()
            .find(|d| d.deployment_id == id)
            .unwrap()
    }

    fn primary(&self) -> &Deployment {
        self.svc()
            .deployments
            .iter()
            .find(|d| d.status == "PRIMARY")
            .unwrap()
    }

    /// Start a new deployment of `revision` the way UpdateService does.
    fn deploy(&mut self, revision: i32) -> String {
        let svc = self.svc_mut();
        for d in svc.deployments.iter_mut().filter(|d| d.status == "PRIMARY") {
            d.status = "ACTIVE".into();
        }
        svc.task_definition_arn = td_arn(revision);
        svc.revision = revision;
        let d = Deployment::new_primary(&td_arn(revision), svc.desired_count, "FARGATE", &[]);
        let id = d.deployment_id.clone();
        svc.deployments.insert(0, d);
        id
    }

    fn tasks_of(&self, deployment_id: &str) -> Vec<String> {
        self.state
            .tasks
            .values()
            .filter(|t| t.deployment_id.as_deref() == Some(deployment_id))
            .map(|t| t.task_id.clone())
            .collect()
    }

    fn live_of(&self, deployment_id: &str) -> Vec<String> {
        self.state
            .tasks
            .values()
            .filter(|t| t.deployment_id.as_deref() == Some(deployment_id) && is_live(t))
            .map(|t| t.task_id.clone())
            .collect()
    }

    /// The runtime started the task's containers.
    fn run(&mut self, ids: &[String]) {
        let now = self.now;
        for id in ids {
            let t = self.state.tasks.get_mut(id).unwrap();
            t.last_status = "RUNNING".into();
            t.started_at = Some(now);
            for c in t.containers.iter_mut() {
                c.last_status = "RUNNING".into();
            }
        }
    }

    /// The task's essential container exited on its own.
    fn crash(&mut self, ids: &[String]) {
        let now = self.now;
        for id in ids {
            let t = self.state.tasks.get_mut(id).unwrap();
            t.last_status = "STOPPED".into();
            t.desired_status = "STOPPED".into();
            t.stop_code = Some("EssentialContainerExited".into());
            t.stopped_reason = Some("Essential container in task exited".into());
            t.stopped_at = Some(now);
        }
    }

    /// The runtime finished stopping the tasks the scheduler stopped.
    fn finish(&mut self, out: &StepOutcome) {
        let now = self.now;
        for (id, _) in &out.stopped {
            let t = self.state.tasks.get_mut(id).unwrap();
            t.last_status = "STOPPED".into();
            t.stopped_at = Some(now);
        }
    }

    fn healthy_count(&self) -> usize {
        let ctx = StepContext {
            now: self.now,
            lb_health: &self.lb,
            evaluate_lb: self.evaluate_lb,
            full_pass: true,
        };
        let svc = self.svc();
        service_tasks(&self.state, svc)
            .into_iter()
            .filter(|t| is_live(t) && task_health(&self.state, svc, t, &ctx) == Health::Healthy)
            .count()
    }

    fn events(&self) -> Vec<String> {
        self.state
            .service_events
            .get(&self.svc().service_arn)
            .map(|log| log.events.iter().map(|e| e.message.clone()).collect())
            .unwrap_or_default()
    }

    /// The maximum bound holds after every round.
    fn check_bounds(&self) {
        let svc = self.svc();
        let max = maximum_tasks(
            svc.desired_count,
            svc.maximum_percent.unwrap_or(DEFAULT_MAXIMUM_PERCENT),
        );
        let occupying = service_tasks(&self.state, svc)
            .into_iter()
            .filter(|t| t.last_status != "STOPPED")
            .count() as i32;
        assert!(
            occupying <= max.max(svc.desired_count),
            "{occupying} tasks running or pending exceed the maximum {max}"
        );
    }

    /// Launch and complete the service's first deployment.
    fn complete_initial(&mut self) -> String {
        let id = self.primary().deployment_id.clone();
        let out = self.api();
        self.run(&out.launched);
        self.advance(5);
        self.tick();
        assert_eq!(self.deployment(&id).rollout_state, "COMPLETED");
        id
    }
}

#[test]
fn minimum_healthy_rounds_up_and_maximum_rounds_down() {
    assert_eq!(minimum_healthy_tasks(4, 50), 2);
    assert_eq!(minimum_healthy_tasks(2, 75), 2);
    assert_eq!(minimum_healthy_tasks(3, 50), 2);
    assert_eq!(minimum_healthy_tasks(2, 100), 2);
    assert_eq!(minimum_healthy_tasks(0, 100), 0);
    assert_eq!(minimum_healthy_tasks(5, 0), 0);
    assert_eq!(maximum_tasks(4, 200), 8);
    assert_eq!(maximum_tasks(3, 125), 3);
    assert_eq!(maximum_tasks(3, 150), 4);
    assert_eq!(maximum_tasks(0, 200), 0);
}

#[test]
fn circuit_breaker_threshold_is_half_the_desired_count_within_3_and_200() {
    assert_eq!(circuit_breaker_threshold(0), 3);
    assert_eq!(circuit_breaker_threshold(1), 3);
    assert_eq!(circuit_breaker_threshold(2), 3);
    assert_eq!(circuit_breaker_threshold(6), 3);
    assert_eq!(circuit_breaker_threshold(7), 4);
    assert_eq!(circuit_breaker_threshold(25), 13);
    assert_eq!(circuit_breaker_threshold(400), 200);
    assert_eq!(circuit_breaker_threshold(800), 200);
}

#[test]
fn launch_back_off_starts_at_the_third_failure_and_caps_at_27_minutes() {
    assert_eq!(throttle_delay(0), None);
    assert_eq!(throttle_delay(2), None);
    assert_eq!(throttle_delay(3), Some(Duration::seconds(10)));
    assert_eq!(throttle_delay(4), Some(Duration::seconds(20)));
    assert_eq!(throttle_delay(6), Some(Duration::seconds(80)));
    assert_eq!(throttle_delay(12), Some(Duration::seconds(27 * 60)));
    assert_eq!(throttle_delay(i32::MAX), Some(Duration::seconds(27 * 60)));
}

#[test]
fn load_balancer_health_is_the_worst_of_its_targets() {
    let unhealthy = LbHealth::Unhealthy {
        target_group_arn: TG.into(),
        port: Some(8080),
        reason: "Health checks failed".into(),
    };
    assert_eq!(LbHealth::Healthy.and(LbHealth::Healthy), LbHealth::Healthy);
    assert_eq!(LbHealth::Healthy.and(LbHealth::Pending), LbHealth::Pending);
    assert_eq!(LbHealth::Pending.and(unhealthy.clone()), unhealthy);
    let view = |state: &str| fakecloud_core::delivery::TargetHealthView {
        state: state.into(),
        reason: None,
        description: None,
    };
    assert_eq!(
        LbHealth::of_target(Some(&view("healthy")), TG, None),
        LbHealth::Healthy
    );
    assert_eq!(
        LbHealth::of_target(Some(&view("unavailable")), TG, None),
        LbHealth::Healthy
    );
    assert_eq!(
        LbHealth::of_target(Some(&view("initial")), TG, None),
        LbHealth::Pending
    );
    assert_eq!(LbHealth::of_target(None, TG, None), LbHealth::Pending);
    assert!(matches!(
        LbHealth::of_target(Some(&view("unhealthy")), TG, Some(8080)),
        LbHealth::Unhealthy { .. }
    ));
}

#[test]
fn first_deployment_completes_once_its_tasks_are_healthy() {
    let mut f = Fixture::new(Opts::default());
    let id = f.primary().deployment_id.clone();
    let out = f.api();
    assert_eq!(out.launched.len(), 2);
    assert_eq!(f.tasks_of(&id).len(), 2, "tasks belong to the deployment");

    // Not settled yet: RUNNING for less than the settle window.
    f.run(&out.launched);
    f.tick();
    assert_eq!(f.deployment(&id).rollout_state, "IN_PROGRESS");

    f.advance(RUNNING_SETTLE_SECS);
    let out = f.tick();
    let d = f.deployment(&id);
    assert_eq!(d.rollout_state, "COMPLETED");
    assert_eq!(
        d.rollout_state_reason.as_deref(),
        Some(format!("ECS deployment {id} completed.").as_str())
    );
    assert_eq!((d.running_count, d.pending_count), (2, 0));
    assert_eq!(
        out.deployment_events
            .iter()
            .map(|e| e.event_name)
            .collect::<Vec<_>>(),
        vec!["SERVICE_DEPLOYMENT_COMPLETED"]
    );
    let events = f.events();
    assert!(events[0].starts_with("(service web) has started 2 tasks: (task "));
    assert_eq!(
        &events[1..],
        &[
            format!("(service web) (deployment {id}) deployment completed."),
            "(service web) has reached a steady state.".to_string(),
        ]
    );

    // Steady state is reported once, not every round.
    f.advance(3);
    f.tick();
    assert_eq!(f.events().len(), 3);
}

#[test]
fn rolling_update_starts_new_tasks_before_stopping_old_ones() {
    let mut f = Fixture::new(Opts {
        min: Some(100),
        max: Some(200),
        ..Opts::default()
    });
    let old = f.complete_initial();
    let old_tasks = f.live_of(&old);
    let new = f.deploy(2);

    let out = f.api();
    assert_eq!(out.launched.len(), 2, "maximum 200% leaves room for 2 more");
    assert!(out.stopped.is_empty(), "minimum 100% keeps both old tasks");
    assert_eq!(f.live_of(&old), old_tasks);

    // New tasks pending, then running but not yet settled: nothing stops.
    f.tick();
    f.run(&out.launched);
    f.advance(1);
    let out = f.tick();
    assert!(out.stopped.is_empty());
    assert_eq!(f.healthy_count(), 2);

    // Once healthy, the old tasks drain: the healthy count stays at 2.
    f.advance(RUNNING_SETTLE_SECS);
    let out = f.tick();
    let mut stopped: Vec<String> = out.stopped.iter().map(|(id, _)| id.clone()).collect();
    stopped.sort();
    let mut expected = old_tasks.clone();
    expected.sort();
    assert_eq!(stopped, expected);
    assert_eq!(f.healthy_count(), 2);
    let t = &f.state.tasks[&stopped[0]];
    assert_eq!(t.stop_code.as_deref(), Some("ServiceSchedulerInitiated"));
    assert_eq!(
        t.stopped_reason.as_deref(),
        Some(format!("Scaling activity initiated by (deployment {new})").as_str())
    );
    assert_eq!(f.deployment(&old).desired_count, 0);
    assert_eq!(f.deployment(&new).rollout_state, "IN_PROGRESS");

    f.finish(&out);
    f.advance(1);
    f.tick();
    assert_eq!(f.deployment(&old).status, "INACTIVE");
    assert_eq!(f.deployment(&new).rollout_state, "COMPLETED");
    let json = crate::service::service_to_json(f.svc());
    let listed = json["deployments"].as_array().unwrap();
    assert_eq!(
        listed.len(),
        1,
        "the drained deployment is no longer listed"
    );
    assert_eq!(listed[0]["id"], serde_json::json!(new));
    assert_eq!(listed[0]["rolloutState"], serde_json::json!("COMPLETED"));
}

#[test]
fn minimum_50_percent_stops_old_tasks_first_within_maximum_100() {
    let mut f = Fixture::new(Opts {
        desired: 4,
        min: Some(50),
        max: Some(100),
        ..Opts::default()
    });
    let old = f.complete_initial();
    let new = f.deploy(2);

    let out = f.api();
    assert!(out.launched.is_empty(), "no room under maximum 100%");
    assert_eq!(
        out.stopped.len(),
        2,
        "minimum 50% of 4 lets two old tasks go"
    );
    assert_eq!(f.healthy_count(), 2);

    f.finish(&out);
    let out = f.tick();
    assert_eq!(out.launched.len(), 2);
    assert_eq!(f.live_of(&old).len(), 2);

    f.run(&out.launched);
    f.advance(RUNNING_SETTLE_SECS);
    let out = f.tick();
    assert_eq!(
        out.stopped.len(),
        2,
        "the rest drain once the new tasks are healthy"
    );
    f.finish(&out);
    let out = f.tick();
    assert_eq!(out.launched.len(), 2);
    f.run(&out.launched);
    f.advance(RUNNING_SETTLE_SECS);
    f.tick();
    assert_eq!(f.deployment(&new).rollout_state, "COMPLETED");
    assert_eq!(f.live_of(&new).len(), 4);
    assert_eq!(f.deployment(&old).status, "INACTIVE");
}

#[test]
fn circuit_breaker_fails_the_deployment_and_rolls_back() {
    let mut f = Fixture::new(Opts {
        min: Some(100),
        max: Some(200),
        breaker: Some((true, true)),
        ..Opts::default()
    });
    let old = f.complete_initial();
    let old_tasks = f.live_of(&old);
    let bad = f.deploy(2);

    // Two tasks fail to start, then two more: the breaker trips at 3.
    let out = f.api();
    f.run(&out.launched);
    f.crash(&out.launched);
    f.advance(1);
    let out = f.tick();
    assert_eq!(f.deployment(&bad).failed_tasks, 2);
    assert_eq!(out.launched.len(), 2, "the deployment keeps trying");
    f.crash(&out.launched);
    f.advance(1);
    let out = f.tick();

    let failed = f.deployment(&bad);
    assert_eq!(failed.rollout_state, "FAILED");
    assert_eq!(failed.failed_tasks, 3, "counting stops at the threshold");
    assert_eq!(failed.status, "ACTIVE");
    assert_eq!(
        failed.rollout_state_reason.as_deref(),
        Some("ECS deployment circuit breaker: tasks failed to start.")
    );
    let rollback = f.primary().clone();
    assert_ne!(rollback.deployment_id, old, "a new deployment rolls back");
    assert!(rollback.is_rollback);
    assert_eq!(rollback.task_definition_arn, td_arn(1));
    assert_eq!(rollback.rollout_state, "IN_PROGRESS");
    assert_eq!(
        rollback.rollout_state_reason.as_deref(),
        Some(
            format!("ECS deployment circuit breaker: rolling back to deploymentId {old}.").as_str()
        )
    );
    assert_eq!(f.svc().task_definition_arn, td_arn(1));
    assert_eq!(f.svc().revision, 1);
    let names: Vec<&str> = out.deployment_events.iter().map(|e| e.event_name).collect();
    assert_eq!(
        names,
        vec![
            "SERVICE_DEPLOYMENT_FAILED",
            "SERVICE_DEPLOYMENT_IN_PROGRESS"
        ]
    );
    let events = f.events();
    assert!(events.contains(&format!(
        "(service web) (deployment {bad}) deployment failed: tasks failed to start."
    )));
    assert!(events.contains(&format!("(service web) rolling back to deployment {old}.")));
    assert_eq!(f.live_of(&old), old_tasks, "old tasks keep serving");
    assert_eq!(out.launched.len(), 2, "the rollback starts right away");
    assert!(f
        .tasks_of(&rollback.deployment_id)
        .iter()
        .all(|id| f.state.tasks[id].task_definition_arn == td_arn(1)));

    // The rollback runs to completion like any deployment.
    f.run(&out.launched);
    f.advance(RUNNING_SETTLE_SECS);
    let out = f.tick();
    assert_eq!(out.stopped.len(), 2);
    assert!(f.healthy_count() >= 2);
    f.finish(&out);
    f.advance(1);
    f.tick();
    assert_eq!(
        f.deployment(&rollback.deployment_id).rollout_state,
        "COMPLETED"
    );
    assert_eq!(f.deployment(&old).status, "INACTIVE");
    assert_eq!(f.deployment(&bad).status, "INACTIVE");
    let json = crate::service::service_to_json(f.svc());
    assert_eq!(json["deployments"].as_array().unwrap().len(), 1);
    assert_eq!(json["taskDefinition"], serde_json::json!(td_arn(1)));
}

#[test]
fn failed_deployment_without_rollback_launches_nothing_and_old_tasks_keep_serving() {
    let mut f = Fixture::new(Opts {
        min: Some(50),
        max: Some(200),
        breaker: Some((true, false)),
        ..Opts::default()
    });
    let old = f.complete_initial();
    let bad = f.deploy(2);

    let out = f.api();
    // Minimum 50% of 2 lets one old task go to make room.
    assert_eq!(out.stopped.len(), 1);
    f.finish(&out);
    for _ in 0..3 {
        let launched = f.live_of(&bad);
        f.crash(&launched);
        f.advance(1);
        f.tick();
        if f.deployment(&bad).rollout_state == "FAILED" {
            break;
        }
    }
    assert_eq!(f.deployment(&bad).rollout_state, "FAILED");
    assert_eq!(f.deployment(&bad).status, "PRIMARY", "nothing to roll back");
    let remaining = f.live_of(&old);
    assert_eq!(remaining.len(), 1);

    for _ in 0..5 {
        f.advance(30);
        let out = f.tick();
        assert!(
            out.launched.is_empty(),
            "a FAILED deployment launches nothing"
        );
        assert!(out.stopped.is_empty());
    }
    assert_eq!(f.live_of(&old), remaining, "the old task keeps serving");

    // An old task that dies is replaced in its own revision.
    f.crash(&remaining);
    let out = f.tick();
    assert_eq!(out.launched.len(), 1);
    assert_eq!(
        f.state.tasks[&out.launched[0]].task_definition_arn,
        td_arn(1)
    );
    assert_eq!(
        f.state.tasks[&out.launched[0]].deployment_id.as_deref(),
        Some(old.as_str())
    );
}

#[test]
fn without_circuit_breaker_a_failing_deployment_retries_with_back_off() {
    let mut f = Fixture::new(Opts {
        desired: 1,
        min: Some(100),
        max: Some(200),
        ..Opts::default()
    });
    let old = f.complete_initial();
    let old_tasks = f.live_of(&old);
    let bad = f.deploy(2);

    let mut launched = f.api().launched;
    for attempt in 1..=3 {
        assert_eq!(launched.len(), 1, "attempt {attempt}");
        f.run(&launched);
        f.crash(&launched);
        f.advance(1);
        launched = f.tick().launched;
    }
    // The third consecutive failure starts the back-off.
    assert!(launched.is_empty());
    let d = f.deployment(&bad);
    assert_eq!(d.rollout_state, "IN_PROGRESS");
    assert_eq!(d.failed_tasks, 3);
    assert_eq!(d.next_launch_at, Some(f.now + Duration::seconds(10)));
    assert!(f.events().contains(
        &"(service web) is unable to consistently start tasks successfully.".to_string()
    ));
    f.advance(5);
    assert!(f.tick().launched.is_empty());
    f.advance(5);
    assert_eq!(f.tick().launched.len(), 1, "retried after the delay");
    assert_eq!(
        f.live_of(&old),
        old_tasks,
        "minimum healthy keeps the old task"
    );
}

#[test]
fn a_healthy_task_resets_the_failure_count() {
    let mut f = Fixture::new(Opts {
        breaker: Some((true, true)),
        ..Opts::default()
    });
    f.complete_initial();
    let new = f.deploy(2);
    let out = f.api();
    f.crash(&out.launched[..1]);
    f.run(&out.launched[1..]);
    f.advance(1);
    let out = f.tick();
    assert_eq!(f.deployment(&new).failed_tasks, 1);
    f.run(&out.launched);
    f.advance(RUNNING_SETTLE_SECS);
    f.tick();
    assert_eq!(f.deployment(&new).failed_tasks, 0);
}

#[test]
fn stops_requested_by_users_or_the_scheduler_are_not_failures() {
    let mut f = Fixture::new(Opts {
        breaker: Some((true, true)),
        ..Opts::default()
    });
    let id = f.primary().deployment_id.clone();
    let out = f.api();
    for task_id in &out.launched {
        let t = f.state.tasks.get_mut(task_id).unwrap();
        t.desired_status = "STOPPED".into();
        t.last_status = "STOPPED".into();
        t.stop_code = Some("UserInitiated".into());
    }
    let out = f.tick();
    assert_eq!(f.deployment(&id).failed_tasks, 0);
    assert_eq!(out.launched.len(), 2, "the service replaces them");
}

#[test]
fn load_balancer_health_gates_completion_and_replaces_unhealthy_tasks() {
    let mut f = Fixture::new(Opts {
        load_balanced: true,
        breaker: Some((true, true)),
        grace: Some(30),
        ..Opts::default()
    });
    let id = f.primary().deployment_id.clone();
    let out = f.api();
    f.run(&out.launched);
    f.advance(10);
    f.tick();
    assert_eq!(f.healthy_count(), 0, "not registered healthy yet");
    assert_eq!(f.deployment(&id).rollout_state, "IN_PROGRESS");

    // Unhealthy within the grace period: left alone.
    let (sick, fine) = (out.launched[0].clone(), out.launched[1].clone());
    f.lb.insert(
        sick.clone(),
        LbHealth::Unhealthy {
            target_group_arn: TG.into(),
            port: Some(8080),
            reason: "Health checks failed with these codes: [502]".into(),
        },
    );
    f.lb.insert(fine.clone(), LbHealth::Healthy);
    assert!(f.tick().stopped.is_empty());

    // Past it: replaced, and counted against the deployment.
    f.advance(30);
    let out = f.tick();
    assert_eq!(out.stopped.len(), 1);
    assert_eq!(out.stopped[0].0, sick);
    assert_eq!(
        out.stopped[0].1,
        format!("Task failed ELB health checks in (target-group {TG})")
    );
    assert_eq!(f.deployment(&id).failed_tasks, 1);
    assert_eq!(out.launched.len(), 1, "a replacement starts");
    assert!(f.events().contains(&format!(
        "(service web) (task {sick}) (port 8080) is unhealthy in (target-group {TG}) due to (reason Health checks failed with these codes: [502])."
    )));

    f.finish(&out);
    f.run(&out.launched);
    f.lb.insert(out.launched[0].clone(), LbHealth::Healthy);
    f.advance(5);
    f.tick();
    assert_eq!(f.deployment(&id).rollout_state, "COMPLETED");
}

#[test]
fn container_health_checks_gate_health_and_replace_unhealthy_tasks() {
    let mut f = Fixture::new(Opts {
        health_check: true,
        ..Opts::default()
    });
    let id = f.primary().deployment_id.clone();
    let out = f.api();
    f.run(&out.launched);
    f.advance(10);
    f.tick();
    assert_eq!(f.healthy_count(), 0, "UNKNOWN is not healthy");

    let set_health = |f: &mut Fixture, task: &str, status: &str| {
        for c in f.state.tasks.get_mut(task).unwrap().containers.iter_mut() {
            c.health_status = Some(status.into());
        }
    };
    set_health(&mut f, &out.launched[0], "HEALTHY");
    set_health(&mut f, &out.launched[1], "UNHEALTHY");
    let tick = f.tick();
    assert_eq!(f.healthy_count(), 1);
    assert_eq!(tick.stopped.len(), 1);
    assert_eq!(tick.stopped[0].1, "Task failed container health checks");
    assert_eq!(f.deployment(&id).failed_tasks, 1);
    assert_eq!(f.deployment(&id).rollout_state, "IN_PROGRESS");
}

#[test]
fn per_deployment_counts_follow_their_tasks() {
    let mut f = Fixture::new(Opts::default());
    let old = f.complete_initial();
    let new = f.deploy(2);
    let out = f.api();
    f.run(&out.launched[..1]);
    f.tick();
    let (o, n) = (f.deployment(&old).clone(), f.deployment(&new).clone());
    assert_eq!((o.running_count, o.pending_count), (2, 0));
    assert_eq!((n.running_count, n.pending_count), (1, 1));
    assert_eq!((f.svc().running_count, f.svc().pending_count), (3, 1));

    let mut json = crate::service::service_to_json(f.svc());
    crate::service::refresh_service_json(&f.state, f.svc(), &mut json);
    assert_eq!(json["runningCount"], serde_json::json!(3));
    let listed = json["deployments"].as_array().unwrap();
    assert_eq!(listed[0]["id"], serde_json::json!(new));
    assert_eq!(listed[0]["pendingCount"], serde_json::json!(1));
    assert_eq!(listed[1]["runningCount"], serde_json::json!(2));
    assert!(json["events"][0]["message"]
        .as_str()
        .unwrap()
        .starts_with("(service web) has started 2 tasks"));
}

#[test]
fn lowering_the_desired_count_stops_unprotected_tasks_first() {
    let mut f = Fixture::new(Opts::default());
    f.complete_initial();
    let primary = f.primary().deployment_id.clone();
    let tasks = f.live_of(&primary);
    f.state.tasks.get_mut(&tasks[0]).unwrap().protection = Some(crate::state::TaskProtection {
        enabled: true,
        expiration: None,
    });
    f.svc_mut().desired_count = 1;
    let out = f.api();
    assert_eq!(out.stopped.len(), 1);
    assert_eq!(out.stopped[0].0, tasks[1]);
}

#[test]
fn a_service_stored_without_deployments_gets_a_primary_one() {
    let mut f = Fixture::new(Opts::default());
    f.svc_mut().deployments.clear();
    let out = f.api();
    assert_eq!(out.launched.len(), 2);
    let primary = f.primary().clone();
    assert_eq!(primary.task_definition_arn, td_arn(1));
    assert_eq!(f.tasks_of(&primary.deployment_id).len(), 2);
}

#[test]
fn the_api_round_neither_completes_nor_retires_deployments() {
    let mut f = Fixture::new(Opts::default());
    let old = f.complete_initial();
    let old_tasks = f.live_of(&old);
    f.crash(&old_tasks);
    let new = f.deploy(2);
    f.api();
    assert_eq!(f.deployment(&old).status, "ACTIVE");
    assert_eq!(f.deployment(&old).failed_tasks, 0);
    assert_eq!(f.deployment(&new).rollout_state, "IN_PROGRESS");
}

#[test]
fn deployment_ids_appear_in_their_in_progress_reason() {
    let d = Deployment::new_primary(&td_arn(1), 1, "FARGATE", &[]);
    assert_eq!(
        d.rollout_state_reason.as_deref(),
        Some(format!("ECS deployment {} in progress.", d.deployment_id).as_str())
    );
}

#[test]
fn a_wedged_configuration_is_reported_once() {
    let mut f = Fixture::new(Opts {
        min: Some(100),
        max: Some(100),
        ..Opts::default()
    });
    f.complete_initial();
    f.deploy(2);
    let out = f.tick();
    assert!(out.launched.is_empty() && out.stopped.is_empty());
    f.tick();
    let wedged: Vec<String> = f
        .events()
        .into_iter()
        .filter(|e| e.contains("because of the service deployment configuration"))
        .collect();
    assert_eq!(wedged.len(), 1);
}
