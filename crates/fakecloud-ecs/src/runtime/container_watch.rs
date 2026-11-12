//! Container state for the ECS task waiters (Docker / Podman), without
//! polling every container every few hundred milliseconds.
//!
//! A running task waits for its containers to exit and mirrors their Docker
//! health status onto DescribeTasks. Doing that by running `docker inspect`
//! per container on a short interval costs a process spawn per container
//! per tick, which keeps fakecloud busy while nothing happens and grows with
//! the number of tasks. Instead one watcher per container CLI keeps the
//! state of every container a waiter registered:
//!
//! - Docker: one long-lived `docker events` stream, filtered to fakecloud's
//!   own containers (its instance label) and to the events that matter
//!   (`die`, `oom`, `health_status`, `destroy`), updates the state and wakes
//!   the container's waiter. When the stream ends (daemon restart, killed
//!   CLI) it is reconnected with a backoff, followed by one inspect pass that
//!   catches whatever happened meanwhile.
//! - A safety net inspects every registered container in one batched
//!   `inspect` call every [`SAFETY_NET_INTERVAL`], so an event that never
//!   arrives cannot hang a task.
//! - Podman: `podman events` reports a different JSON shape and event names,
//!   which this does not parse; Podman gets the batched inspect every
//!   [`PODMAN_POLL_INTERVAL`] instead (one process per pass for every task).
//!
//! A waiter registers its containers, runs one inspect for them (catching a
//! container that exited before it registered), then sleeps until one of
//! them changes.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::AsyncBufReadExt;
use tokio::sync::Notify;

use super::config::ContainerCli;
use super::CLI_CALL_TIMEOUT;

/// How often every registered container is inspected when events flow.
const SAFETY_NET_INTERVAL: Duration = Duration::from_secs(15);

/// How often every registered container is inspected on Podman.
const PODMAN_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Longest wait before reconnecting a stream that ended.
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);

/// How long after a stream starts the catch-up inspect runs, so the stream is
/// subscribed by then and nothing falls between the two.
const CATCH_UP_DELAY: Duration = Duration::from_millis(500);

/// The events a waiter cares about.
const EVENTS: &[&str] = &["die", "oom", "health_status", "destroy"];

/// What is known about a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observed {
    /// False once the container exited (or is gone).
    pub(crate) running: bool,
    /// The exit code, once it exited.
    pub(crate) exit_code: Option<i64>,
    /// Docker's health status (`starting` / `healthy` / `unhealthy`), when
    /// the container has a health check.
    pub(crate) health: Option<String>,
    /// The container no longer exists.
    pub(crate) gone: bool,
}

impl Default for Observed {
    fn default() -> Self {
        Self {
            running: true,
            exit_code: None,
            health: None,
            gone: false,
        }
    }
}

struct Watched {
    observed: Observed,
    waiter: Arc<Notify>,
}

/// The state of the containers waiters registered, for one container CLI.
pub(crate) struct ContainerWatch {
    cli: String,
    container_cli: ContainerCli,
    /// `fakecloud-instance=<value>`, the label every container fakecloud
    /// starts carries.
    label: String,
    containers: Mutex<HashMap<String, Watched>>,
    started: OnceLock<()>,
    /// Whether an inspect failure has been logged.
    inspect_warned: std::sync::atomic::AtomicBool,
}

/// A waiter's registration; its containers are forgotten when it drops.
pub(crate) struct Registration {
    watch: Arc<ContainerWatch>,
    ids: Vec<String>,
    waiter: Arc<Notify>,
}

impl Registration {
    /// Wait until one of the registered containers changes (returns at once
    /// when one changed since the last wait).
    pub(crate) async fn changed(&self) {
        self.waiter.notified().await;
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut containers = self.watch.containers.lock();
        for id in &self.ids {
            containers.remove(id);
        }
    }
}

impl ContainerWatch {
    /// The watcher for `cli` (one per CLI and process).
    pub(crate) fn for_cli(cli: &str, container_cli: ContainerCli, label: &str) -> Arc<Self> {
        static WATCHES: OnceLock<Mutex<HashMap<String, Arc<ContainerWatch>>>> = OnceLock::new();
        WATCHES
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .entry(cli.to_string())
            .or_insert_with(|| {
                Arc::new(Self {
                    cli: cli.to_string(),
                    container_cli,
                    label: label.to_string(),
                    containers: Mutex::new(HashMap::new()),
                    started: OnceLock::new(),
                    inspect_warned: Default::default(),
                })
            })
            .clone()
    }

    /// Start keeping `ids` current; the returned registration wakes when one
    /// of them changes.
    pub(crate) fn watch(self: &Arc<Self>, ids: &[String]) -> Registration {
        let waiter = Arc::new(Notify::new());
        {
            let mut containers = self.containers.lock();
            for id in ids {
                containers.insert(
                    id.clone(),
                    Watched {
                        observed: Observed::default(),
                        waiter: waiter.clone(),
                    },
                );
            }
        }
        self.ensure_started();
        Registration {
            watch: self.clone(),
            ids: ids.to_vec(),
            waiter,
        }
    }

    /// What is known about container `id`, when it is registered.
    pub(crate) fn observed(&self, id: &str) -> Option<Observed> {
        self.containers.lock().get(id).map(|w| w.observed.clone())
    }

    fn ensure_started(self: &Arc<Self>) {
        self.started.get_or_init(|| {
            let weak = Arc::downgrade(self);
            tokio::spawn(async move {
                let podman = match weak.upgrade() {
                    Some(watch) => fakecloud_core::container_net::is_podman_async(&watch.cli).await,
                    None => return,
                };
                if podman {
                    poll_loop(weak, PODMAN_POLL_INTERVAL).await;
                } else {
                    event_loop(weak).await;
                }
            });
        });
    }

    /// Update `id` with `f`; wake its waiter when that changed anything.
    fn update(&self, id: &str, f: impl FnOnce(&mut Observed)) {
        let mut containers = self.containers.lock();
        let Some(entry) = find_mut(&mut containers, id) else {
            return;
        };
        let before = entry.observed.clone();
        f(&mut entry.observed);
        if entry.observed != before {
            entry.waiter.notify_one();
        }
    }

    /// Inspect `ids` (every registered container when `None`) in one call.
    pub(crate) async fn refresh(&self, ids: Option<&[String]>) {
        let ids: Vec<String> = match ids {
            Some(ids) => ids.to_vec(),
            None => self.containers.lock().keys().cloned().collect(),
        };
        if ids.is_empty() {
            return;
        }
        let mut args = vec![
            "inspect".to_string(),
            "--type".to_string(),
            "container".to_string(),
            "--format".to_string(),
            INSPECT_FORMAT.to_string(),
        ];
        args.extend(ids.iter().cloned());
        let Ok(out) = self.container_cli.output(&args, CLI_CALL_TIMEOUT).await else {
            return;
        };
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr).to_ascii_lowercase();
        // Nothing parsed and an error that is not about removed containers:
        // the exits this would have caught wait for the event stream.
        if !stdout.lines().any(|l| parse_inspect_line(l).is_some())
            && !stderr.trim().is_empty()
            && !stderr.contains("no such")
            && !self
                .inspect_warned
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            tracing::warn!(error = %stderr.trim(), "cannot inspect ECS task containers");
        }
        let mut seen: Vec<&str> = Vec::new();
        for line in stdout.lines() {
            let Some((full_id, state)) = parse_inspect_line(line) else {
                continue;
            };
            let Some(id) = ids.iter().find(|id| same_container(id, full_id)) else {
                continue;
            };
            seen.push(id);
            self.update(id, |o| {
                // An exit is final: an inspect that started before the
                // container died must not bring it back.
                if o.running {
                    o.running = state.running;
                    o.exit_code = state.exit_code;
                }
                o.health = state.health;
            });
        }
        // An ID the engine says it does not know is gone; one that is merely
        // missing from a failed call is left as it was.
        for id in ids.iter().filter(|id| !seen.contains(&id.as_str())) {
            let short = &id[..id.len().min(12)];
            let unknown = stderr
                .lines()
                .any(|l| l.contains("no such") && l.contains(short));
            if unknown {
                self.update(id, |o| {
                    o.running = false;
                    o.gone = true;
                });
            }
        }
    }

    /// Apply one event from the stream.
    async fn apply(&self, event: Event) {
        match event.action {
            EventAction::Die { exit_code } => {
                self.update(&event.id, |o| {
                    o.running = false;
                    if exit_code.is_some() {
                        o.exit_code = exit_code;
                    }
                });
                if exit_code.is_none() {
                    self.refresh(Some(std::slice::from_ref(&event.id))).await;
                }
            }
            EventAction::Health(status) => {
                self.update(&event.id, |o| o.health = Some(status));
            }
            EventAction::Destroy => self.update(&event.id, |o| {
                o.running = false;
                o.gone = true;
            }),
            // An OOM kill is followed by `die`; look now in case it is not.
            EventAction::Oom => self.refresh(Some(std::slice::from_ref(&event.id))).await,
        }
    }
}

fn find_mut<'a>(containers: &'a mut HashMap<String, Watched>, id: &str) -> Option<&'a mut Watched> {
    if containers.contains_key(id) {
        return containers.get_mut(id);
    }
    containers
        .iter_mut()
        .find(|(k, _)| same_container(k, id))
        .map(|(_, v)| v)
}

/// Whether two container IDs name the same container (either may be the
/// short form of the other).
fn same_container(a: &str, b: &str) -> bool {
    !a.is_empty() && !b.is_empty() && (a.starts_with(b) || b.starts_with(a))
}

/// `.ID`, not `.Id`: the Docker CLI evaluates the template against the typed
/// container, and a field the type lacks (`Id` is only the JSON name) makes it
/// fall back to the raw JSON map, where `.State.Health` is a missing key (an
/// error) for a container without a health check.
const INSPECT_FORMAT: &str =
    "{{.ID}}|{{.State.Status}}|{{.State.ExitCode}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}";

/// One line of [`INSPECT_FORMAT`] output.
fn parse_inspect_line(line: &str) -> Option<(&str, Observed)> {
    let mut parts = line.trim().splitn(4, '|');
    let id = parts.next()?.trim();
    let status = parts.next()?.trim();
    let exit_code: i64 = parts.next()?.trim().parse().ok()?;
    let health = parts.next().unwrap_or("").trim();
    if id.is_empty() {
        return None;
    }
    let exited = matches!(status, "exited" | "dead");
    Some((
        id,
        Observed {
            running: !exited,
            exit_code: exited.then_some(exit_code),
            health: (!health.is_empty()).then(|| health.to_string()),
            gone: false,
        },
    ))
}

#[derive(Debug, PartialEq, Eq)]
enum EventAction {
    Die { exit_code: Option<i64> },
    Oom,
    Health(String),
    Destroy,
}

#[derive(Debug, PartialEq, Eq)]
struct Event {
    id: String,
    action: EventAction,
}

/// A line of `docker events --format '{{json .}}'`.
fn parse_event(line: &str) -> Option<Event> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    if v.get("Type").and_then(|t| t.as_str()) != Some("container") {
        return None;
    }
    let action = v.get("Action").and_then(|a| a.as_str())?;
    let id = v
        .pointer("/Actor/ID")
        .or_else(|| v.get("id"))
        .and_then(|i| i.as_str())?
        .to_string();
    let action = if action == "die" {
        EventAction::Die {
            exit_code: v
                .pointer("/Actor/Attributes/exitCode")
                .and_then(|c| c.as_str())
                .and_then(|c| c.parse().ok()),
        }
    } else if action == "oom" {
        EventAction::Oom
    } else if action == "destroy" {
        EventAction::Destroy
    } else if let Some(status) = action.strip_prefix("health_status:") {
        EventAction::Health(status.trim().to_string())
    } else {
        return None;
    };
    Some(Event { id, action })
}

/// The `events` argv for fakecloud's containers.
fn events_argv(label: &str) -> Vec<String> {
    let mut argv = vec![
        "events".to_string(),
        "--format".to_string(),
        "{{json .}}".to_string(),
        "--filter".to_string(),
        "type=container".to_string(),
        "--filter".to_string(),
        format!("label={label}"),
    ];
    for event in EVENTS {
        argv.push("--filter".to_string());
        argv.push(format!("event={event}"));
    }
    argv
}

/// Docker: follow the event stream, reconnecting when it ends, with the
/// safety-net inspect in between.
async fn event_loop(weak: Weak<ContainerWatch>) {
    let mut delay = Duration::from_secs(1);
    loop {
        let Some(watch) = weak.upgrade() else {
            return;
        };
        let spawned = tokio::process::Command::new(&watch.cli)
            .args(events_argv(&watch.label))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn();
        drop(watch);
        let mut child = match spawned {
            Ok(child) => child,
            Err(error) => {
                tracing::warn!(%error, "cannot follow container events; inspecting every {}s", SAFETY_NET_INTERVAL.as_secs());
                poll_loop(weak, SAFETY_NET_INTERVAL).await;
                return;
            }
        };
        let Some(stdout) = child.stdout.take() else {
            return;
        };
        let mut lines = tokio::io::BufReader::new(stdout).lines();
        let started_at = tokio::time::Instant::now();
        let catch_up = tokio::time::sleep(CATCH_UP_DELAY);
        tokio::pin!(catch_up);
        let mut caught_up = false;
        let mut safety_net = tokio::time::interval_at(
            tokio::time::Instant::now() + SAFETY_NET_INTERVAL,
            SAFETY_NET_INTERVAL,
        );
        safety_net.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                line = lines.next_line() => {
                    let Some(watch) = weak.upgrade() else { return; };
                    match line {
                        Ok(Some(line)) => {
                            if let Some(event) = parse_event(&line) {
                                watch.apply(event).await;
                            }
                        }
                        // The stream ended or broke: reconnect.
                        _ => break,
                    }
                }
                () = &mut catch_up, if !caught_up => {
                    caught_up = true;
                    let Some(watch) = weak.upgrade() else { return; };
                    watch.refresh(None).await;
                }
                _ = safety_net.tick() => {
                    let Some(watch) = weak.upgrade() else { return; };
                    watch.refresh(None).await;
                }
            }
        }
        let _ = child.kill().await;
        // A stream that ran for a while restarts at once; one that keeps
        // failing backs off.
        if started_at.elapsed() > MAX_RECONNECT_DELAY {
            delay = Duration::from_secs(1);
        }
        tracing::debug!(retry_in = ?delay, "container event stream ended; reconnecting");
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(MAX_RECONNECT_DELAY);
    }
}

/// Inspect every registered container every `interval`.
async fn poll_loop(weak: Weak<ContainerWatch>, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let Some(watch) = weak.upgrade() else {
            return;
        };
        watch.refresh(None).await;
    }
}

impl super::EcsRuntime {
    /// Wait for the task to reach a stop condition (an essential container
    /// exits, or every container exits when none is essential), keeping each
    /// container's `healthStatus` on the task current meanwhile, so
    /// DescribeTasks shows health check transitions. Returns the index into
    /// `started` of the container whose exit ended the task, its exit code,
    /// and the stop code.
    pub(super) async fn wait_for_task_exit_with_health(
        &self,
        state: &super::SharedEcsState,
        account_id: &str,
        task_id: &str,
        started: &[super::RunningContainer],
    ) -> Result<super::TaskExitOutcome, super::RuntimeError> {
        let watch = ContainerWatch::for_cli(
            &self.cli,
            self.container_cli(),
            &super::fakecloud_instance_label(),
        );
        let ids: Vec<String> = started.iter().map(|c| c.container_id.clone()).collect();
        let registration = watch.watch(&ids);
        // A container that exited before it was registered sends no event.
        watch.refresh(Some(&ids)).await;

        // StopTask and the scheduler wake the wait (see `run_task_inner`).
        let stop_requested = self
            .stop_requests
            .lock()
            .get(task_id)
            .map(|hook| hook.wake.clone())
            .unwrap_or_default();

        let mut stopping_begun = false;
        let any_essential = started.iter().any(|c| c.essential);
        let mut working: Vec<super::RunningContainer> = started.to_vec();
        let mut first_exited: Option<usize> = None;
        let mut health_shown: Vec<Option<&'static str>> = vec![None; started.len()];
        loop {
            // Once: a later pass may run after a container has exited and
            // freed its host port for a replacement's identical target.
            if !stopping_begun && super::task_desired_stopped(state, account_id, task_id) {
                self.begin_stopping(state, account_id, task_id);
                stopping_begun = true;
            }
            let observed: Vec<Option<Observed>> = ids.iter().map(|id| watch.observed(id)).collect();
            // Health first, so a container that turns unhealthy and exits
            // leaves its last health status on the task.
            let mut updates: Vec<(String, &'static str)> = Vec::new();
            for (i, o) in observed.iter().enumerate() {
                let Some(o) = o else { continue };
                let ecs = o
                    .health
                    .as_deref()
                    .map(super::docker_health_to_ecs)
                    .unwrap_or("UNKNOWN");
                if health_shown[i] != Some(ecs) {
                    health_shown[i] = Some(ecs);
                    updates.push((started[i].name.clone(), ecs));
                }
            }
            set_health_status(state, account_id, task_id, &updates);

            for (i, o) in observed.iter().enumerate() {
                if working[i].exit_code.is_some() {
                    continue;
                }
                let Some(o) = o else { continue };
                if o.running {
                    continue;
                }
                let exit_code = match o.exit_code {
                    Some(code) => code,
                    None if o.gone => {
                        return Err(super::RuntimeError::Wait(format!(
                            "container {} was removed before its exit was seen",
                            started[i].container_id
                        )))
                    }
                    // Exited, exit code still being read.
                    None => continue,
                };
                working[i].exit_code = Some(exit_code);
                if first_exited.is_none() && (started[i].essential || !any_essential) {
                    first_exited = Some(i);
                }
            }
            if super::task_should_stop(&working) {
                let idx = first_exited
                    .or_else(|| working.iter().position(|c| c.exit_code.is_some()))
                    .unwrap_or(0);
                return Ok(super::TaskExitOutcome {
                    exited_index: Some(idx),
                    exit_code: working[idx].exit_code.unwrap_or(-1),
                    stop_code: if any_essential {
                        "EssentialContainerExited"
                    } else {
                        "TaskCompleted"
                    },
                });
            }
            tokio::select! {
                () = registration.changed() => {}
                () = stop_requested.notified() => {}
            }
        }
    }
}

/// Put each `(container name, ECS health status)` onto the task.
fn set_health_status(
    state: &super::SharedEcsState,
    account_id: &str,
    task_id: &str,
    updates: &[(String, &'static str)],
) {
    if updates.is_empty() {
        return;
    }
    let mut accounts = state.write();
    let Some(task) = accounts
        .get_mut(account_id)
        .and_then(|s| s.tasks.get_mut(task_id))
    else {
        return;
    };
    for (name, status) in updates {
        if let Some(c) = task.containers.iter_mut().find(|c| &c.name == name) {
            c.health_status = Some((*status).to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_docker_events() {
        let die = r#"{"status":"die","id":"abc123","from":"alpine","Type":"container","Action":"die","Actor":{"ID":"abc123","Attributes":{"exitCode":"137","image":"alpine","fakecloud-instance":"fakecloud-1"}},"scope":"local","time":1,"timeNano":1}"#;
        assert_eq!(
            parse_event(die),
            Some(Event {
                id: "abc123".into(),
                action: EventAction::Die {
                    exit_code: Some(137)
                }
            })
        );
        let health = r#"{"Type":"container","Action":"health_status: unhealthy","Actor":{"ID":"abc123","Attributes":{}}}"#;
        assert_eq!(
            parse_event(health).unwrap().action,
            EventAction::Health("unhealthy".into())
        );
        let destroy = r#"{"Type":"container","Action":"destroy","Actor":{"ID":"abc123"}}"#;
        assert_eq!(parse_event(destroy).unwrap().action, EventAction::Destroy);
        let oom = r#"{"Type":"container","Action":"oom","Actor":{"ID":"abc123"}}"#;
        assert_eq!(parse_event(oom).unwrap().action, EventAction::Oom);
        // Other types and actions, and garbage, are ignored.
        assert!(parse_event(r#"{"Type":"network","Action":"die","Actor":{"ID":"n"}}"#).is_none());
        assert!(
            parse_event(r#"{"Type":"container","Action":"start","Actor":{"ID":"a"}}"#).is_none()
        );
        assert!(parse_event("not json").is_none());
    }

    #[test]
    fn parses_batched_inspect_lines() {
        let (id, o) = parse_inspect_line("abc123|exited|3|").unwrap();
        assert_eq!(id, "abc123");
        assert_eq!(
            o,
            Observed {
                running: false,
                exit_code: Some(3),
                health: None,
                gone: false
            }
        );
        let (_, o) = parse_inspect_line("abc123|running|0|healthy").unwrap();
        assert!(o.running);
        assert_eq!(o.exit_code, None);
        assert_eq!(o.health.as_deref(), Some("healthy"));
        assert!(parse_inspect_line("garbage").is_none());
        // `.Id` would make the Docker CLI fall back to the raw JSON map,
        // where a container without a health check fails the template.
        assert!(INSPECT_FORMAT.starts_with("{{.ID}}|"));
    }

    #[test]
    fn events_are_filtered_to_fakecloud_containers() {
        let argv = events_argv("fakecloud-instance=fakecloud-1").join(" ");
        assert_eq!(
            argv,
            "events --format {{json .}} --filter type=container \
             --filter label=fakecloud-instance=fakecloud-1 --filter event=die \
             --filter event=oom --filter event=health_status --filter event=destroy"
        );
    }

    #[tokio::test]
    async fn events_wake_the_waiter_of_the_container_only() {
        let watch = Arc::new(ContainerWatch {
            cli: "true".into(),
            container_cli: crate::runtime::EcsRuntime::with_cli_for_tests("true").container_cli(),
            label: "fakecloud-instance=test".into(),
            containers: Mutex::new(HashMap::new()),
            // Never start the stream in this test.
            started: OnceLock::from(()),
            inspect_warned: Default::default(),
        });
        let a = watch.watch(&["aaaaaaaaaaaa1111".to_string()]);
        let b = watch.watch(&["bbbbbbbbbbbb2222".to_string()]);
        watch
            .apply(Event {
                id: "aaaaaaaaaaaa".into(),
                action: EventAction::Health("healthy".into()),
            })
            .await;
        tokio::time::timeout(Duration::from_secs(1), a.changed())
            .await
            .expect("a's waiter wakes");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), b.changed())
                .await
                .is_err(),
            "b's waiter stays asleep"
        );
        watch
            .apply(Event {
                id: "aaaaaaaaaaaa1111".into(),
                action: EventAction::Die { exit_code: Some(0) },
            })
            .await;
        a.changed().await;
        let o = watch.observed("aaaaaaaaaaaa1111").unwrap();
        assert!(!o.running);
        assert_eq!(o.exit_code, Some(0));
        assert_eq!(o.health.as_deref(), Some("healthy"));
        // Dropping a registration forgets its containers.
        drop(a);
        assert!(watch.observed("aaaaaaaaaaaa1111").is_none());
        assert!(watch.observed("bbbbbbbbbbbb2222").is_some());
    }
}
