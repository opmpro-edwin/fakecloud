//! In-process HTTP routing for ELBv2 ALBs.
//!
//! For each ALB whose `state_code == "active"`, the supervisor binds
//! a TCP listener on `127.0.0.1:0` (OS-allocated). Connections are
//! parsed as HTTP/1.1, matched against the listener rules belonging
//! to that LB, and dispatched to the action: `forward` (round-robin
//! over registered targets in the chosen target group),
//! `fixed-response`, `redirect`, or `authenticate-oidc` /
//! `authenticate-cognito` (501 — declared next-batch).
//!
//! A target's answer is streamed to the client as the target sends it,
//! so a response that never ends (Server-Sent Events, a long download)
//! arrives as it is written. As on an ALB, a connection to a target
//! times out after 10 seconds, and an exchange with the target that is
//! idle for longer than the load balancer's
//! `idle_timeout.timeout_seconds` (60 by default) ends: a 504 before
//! the answer's head arrives, the connection closed after.
//!
//! TLS termination, mTLS, and raw NLB TCP are intentionally next-
//! batch work items. The data-plane doc page enumerates the gap.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use chrono::Utc;
use fakecloud_core::delivery::DeliveryBus;
use fakecloud_wafv2::evaluator::{
    evaluate_detailed as waf_evaluate_detailed, WafAction, WafRequest,
};
use fakecloud_wafv2::{IpSet, RegexPatternSet, RuleGroup, SharedWafv2State, WebAcl};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming, SizeHint};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};
use uuid::Uuid;

use crate::accesslogs::{AccessLogRecord, AccessLogger, LogType};
use crate::router::select_actions;
use crate::state::{Action, Listener, LoadBalancer, Rule, SharedElbv2State, TargetGroup};

const ENV_DISABLE: &str = "FAKECLOUD_ELBV2_DISABLE_DATAPLANE";
const SUPERVISOR_TICK_SECS: u64 = 1;
const STICKY_COOKIE: &str = "AWSALB";
/// How long an ALB waits to connect to a target before answering 504.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The `idle_timeout.timeout_seconds` load balancer attribute, and the
/// idle timeout an ALB has when its attributes do not say.
const IDLE_TIMEOUT_ATTRIBUTE: &str = "idle_timeout.timeout_seconds";
const IDLE_TIMEOUT_SECS: u64 = 60;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// What the data plane answers with: whole, or streamed from a target.
type Body = UnsyncBoxBody<Bytes, BoxError>;

pub fn dataplane_enabled() -> bool {
    !matches!(
        std::env::var(ENV_DISABLE).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

/// Per-LB listener handle. Held in the supervisor map so that a LB
/// removal can drop the JoinHandle and free the OS port.
struct BoundListener {
    handle: JoinHandle<()>,
}

impl Drop for BoundListener {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// State shared across the supervisor and per-connection handlers.
#[derive(Clone)]
struct DataPlane {
    state: SharedElbv2State,
    /// Optional WAFv2 state. When set, every ALB request is evaluated
    /// against the WebACL associated with the load balancer (if any)
    /// before the listener-rule router runs.
    waf_state: Option<SharedWafv2State>,
    /// Optional access-log buffer. When set, every served request
    /// emits one access-log line (and one connection-log line if
    /// connection_logs are enabled) into this in-memory buffer; the
    /// flusher background task ships gzipped batches to S3 every
    /// ~60 seconds or when the buffer fills.
    access_logger: Option<Arc<AccessLogger>>,
    /// Count of WAF Count-action matches, keyed by `WebACL ARN | rule
    /// name`. Exposed for tests and future metrics scraping.
    waf_count_metrics: Arc<Mutex<BTreeMap<String, u64>>>,
    /// Round-robin index per target group ARN (mod target count).
    rr_counters: Arc<Mutex<BTreeMap<String, usize>>>,
    /// Sticky-session map: `AWSALB` cookie value -> `tg_arn|target_id|target_port`.
    sticky_targets: Arc<Mutex<BTreeMap<String, String>>>,
    /// Client to the targets (see [`upstream_client`]).
    upstream: reqwest::Client,
    /// Address used to reach loopback-published sibling targets (EC2 instances
    /// and ECS bridge-mode tasks publish their ports on the host daemon).
    /// `127.0.0.1` when fakecloud runs on the host; the host alias
    /// (`host.docker.internal` / `host.containers.internal`) when fakecloud is
    /// itself containerized — otherwise the forward would hit fakecloud's own
    /// loopback and 502 (#1539-class, bug-hunt 2026-06-24 0.B).
    sibling_host: String,
}

/// The HTTP client the data plane forwards plain requests with. It accepts
/// any target certificate, as an ALB does not verify the certificates of
/// HTTPS targets, and sets no timeout for the whole exchange: a streamed
/// answer may last as long as it keeps moving. Idleness is timed per load
/// balancer in `forward_action`.
fn upstream_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        // Disable redirects so we surface them as the upstream sees them.
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .build()
}

/// The load balancer's idle timeout: its `idle_timeout.timeout_seconds`
/// attribute, 60 seconds when unset or not a positive number.
fn idle_timeout_of(lb: &LoadBalancer) -> Duration {
    lb.attributes
        .get(IDLE_TIMEOUT_ATTRIBUTE)
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|s| *s > 0)
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(IDLE_TIMEOUT_SECS))
}

pub fn spawn_dataplane(
    state: SharedElbv2State,
    waf_state: Option<SharedWafv2State>,
    waf_count_metrics: Option<Arc<Mutex<BTreeMap<String, u64>>>>,
) {
    spawn_dataplane_with_delivery(state, waf_state, None, waf_count_metrics);
}

/// Spawn the supervisor and (when a `delivery_bus` is wired) the
/// access-log flusher. The flusher is a separate task so the per-
/// request hot path only buffers; S3 puts run off the request thread.
pub fn spawn_dataplane_with_delivery(
    state: SharedElbv2State,
    waf_state: Option<SharedWafv2State>,
    delivery_bus: Option<Arc<DeliveryBus>>,
    waf_count_metrics: Option<Arc<Mutex<BTreeMap<String, u64>>>>,
) -> Option<Arc<AccessLogger>> {
    if !dataplane_enabled() {
        debug!("ELBv2 data plane disabled via {ENV_DISABLE}");
        return None;
    }
    let upstream = match upstream_client() {
        Ok(c) => c,
        Err(e) => {
            warn!("ELBv2 data plane: failed to build reqwest client: {e}");
            return None;
        }
    };
    let access_logger = delivery_bus.map(|bus| {
        let logger = Arc::new(AccessLogger::new(Arc::clone(&state), bus));
        crate::accesslogs::spawn_flusher(Arc::clone(&logger));
        logger
    });
    let logger_for_caller = access_logger.as_ref().map(Arc::clone);
    let dp = DataPlane {
        state,
        waf_state,
        access_logger,
        waf_count_metrics: waf_count_metrics
            .unwrap_or_else(|| Arc::new(Mutex::new(BTreeMap::new()))),
        rr_counters: Arc::new(Mutex::new(BTreeMap::new())),
        sticky_targets: Arc::new(Mutex::new(BTreeMap::new())),
        upstream,
        // Detect once: shelling the container CLI per request would be wasteful.
        sibling_host: fakecloud_core::container_net::detect_container_cli()
            .map(|cli| fakecloud_core::container_net::HostNetworking::detect(&cli).sibling_host)
            .unwrap_or_else(|| "127.0.0.1".to_string()),
    };
    tokio::spawn(supervisor_loop(dp));
    logger_for_caller
}

async fn supervisor_loop(dp: DataPlane) {
    let mut bindings: BTreeMap<String, BoundListener> = BTreeMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(SUPERVISOR_TICK_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        reconcile(&dp, &mut bindings).await;
    }
}

async fn reconcile(dp: &DataPlane, bindings: &mut BTreeMap<String, BoundListener>) {
    // 1. Snapshot the set of ALBs that need a listener and their schemes.
    let want: Vec<(String, String)> = {
        let accs = dp.state.read();
        let mut out = Vec::new();
        for (_acct, st) in accs.iter() {
            for lb in st.load_balancers.values() {
                if !lb_should_bind(lb) {
                    continue;
                }
                out.push((lb.arn.clone(), lb.lb_type.clone()));
            }
        }
        out
    };
    let want_set: std::collections::HashSet<&String> = want.iter().map(|(arn, _)| arn).collect();

    // 2. Drop bindings for LBs that no longer exist or are not active.
    bindings.retain(|arn, _| want_set.contains(arn));

    // 3. Bind any new ALB.
    for (arn, lb_type) in want.into_iter() {
        if bindings.contains_key(&arn) {
            continue;
        }
        if !lb_type.eq_ignore_ascii_case("application") {
            // Only ALBs get the in-process HTTP data plane in this
            // batch. NLB raw-TCP and GWLB are explicit next-batch
            // items per the data-plane doc.
            continue;
        }
        match TcpListener::bind(("127.0.0.1", 0)).await {
            Ok(listener) => {
                let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
                if port == 0 {
                    warn!("ELBv2 data plane: bind returned port 0 for {arn}; skipping");
                    continue;
                }
                {
                    let mut accs = dp.state.write();
                    let owning_account: Option<String> = accs
                        .iter()
                        .find(|(_, s)| s.load_balancers.contains_key(&arn))
                        .map(|(a, _)| a.clone());
                    if let Some(acct) = owning_account {
                        if let Some(st) = accs.get_mut(&acct) {
                            if let Some(lb) = st.load_balancers.get_mut(&arn) {
                                lb.bound_port = Some(port);
                            }
                        }
                    }
                }
                let dp2 = dp.clone();
                let arn2 = arn.clone();
                let handle = tokio::spawn(async move {
                    accept_loop(dp2, arn2, listener).await;
                });
                bindings.insert(arn.clone(), BoundListener { handle });
                trace!(arn = %arn, port, "ELBv2 data plane: bound listener");
            }
            Err(e) => {
                warn!("ELBv2 data plane: failed to bind for {arn}: {e}");
            }
        }
    }

    // 4. Clear bound_port for any LB the supervisor is no longer holding.
    let mut accs = dp.state.write();
    let acct_ids: Vec<String> = accs.iter().map(|(a, _)| a.clone()).collect();
    for acct in acct_ids {
        if let Some(st) = accs.get_mut(&acct) {
            for lb in st.load_balancers.values_mut() {
                if !bindings.contains_key(&lb.arn) {
                    lb.bound_port = None;
                }
            }
        }
    }
}

fn lb_should_bind(lb: &LoadBalancer) -> bool {
    lb.state_code == "active"
}

async fn accept_loop(dp: DataPlane, lb_arn: String, listener: TcpListener) {
    loop {
        let (sock, peer_addr) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                debug!(arn = %lb_arn, "accept error: {e}");
                continue;
            }
        };
        // Capture the local addr (i.e. the LB's bound listener address)
        // before moving the socket into the connection task. Used for
        // the `destination_ip:port` field of the connection log.
        let local_addr = sock.local_addr().ok();
        let dp2 = dp.clone();
        let lb_arn2 = lb_arn.clone();
        tokio::spawn(async move {
            let connection_start = Instant::now();
            let connection_creation_time = Utc::now();
            let io = TokioIo::new(sock);
            // Clone before the move into the service closure so we
            // still hold an owned reference for the post-serve
            // connection-log emission below.
            let dp_for_log = dp2.clone();
            let lb_for_log = lb_arn2.clone();
            let svc = service_fn(move |req| {
                let dp3 = dp2.clone();
                let lb3 = lb_arn2.clone();
                let peer = peer_addr;
                async move { Ok::<_, Infallible>(handle_request(&dp3, &lb3, peer, req).await) }
            });
            // With upgrades, so a WebSocket handshake the target accepts hands
            // the connection over (see `forward_upgrade`).
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .with_upgrades()
                .await
            {
                debug!("ELBv2 data plane: connection error: {e}");
            }
            // One connection log per established connection, not per
            // request. Keep-alive connections that serve N requests
            // still produce exactly one connection-log entry covering
            // the lifetime of the TCP connection.
            emit_connection_log(
                &dp_for_log,
                &lb_for_log,
                peer_addr,
                local_addr,
                connection_creation_time,
                connection_start,
            );
        });
    }
}

/// Buffer one connection-log record for the LB. Called once per
/// accepted TCP connection after `serve_connection` returns; covers
/// the lifetime of the connection regardless of how many HTTP requests
/// were served on it.
fn emit_connection_log(
    dp: &DataPlane,
    lb_arn: &str,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    creation_time: chrono::DateTime<chrono::Utc>,
    connection_start: Instant,
) {
    let Some(logger) = dp.access_logger.as_ref() else {
        return;
    };
    let elapsed = connection_start.elapsed().as_secs_f64();
    let elb_id = parse_lb_id(lb_arn).unwrap_or_else(|| lb_arn.to_string());
    let (target_ip, target_port) = match local_addr {
        Some(a) => (Some(a.ip().to_string()), Some(a.port())),
        None => (None, None),
    };
    let target_port_list = match (target_ip.as_deref(), target_port) {
        (Some(ip), Some(p)) => format!("{ip}:{p}"),
        _ => "-".to_string(),
    };
    let record = AccessLogRecord {
        log_type: LogType::Connection,
        timestamp: chrono::Utc::now(),
        elb_id,
        client_ip: peer_addr.ip().to_string(),
        client_port: peer_addr.port(),
        target_ip,
        target_port,
        request_processing_time: elapsed,
        target_processing_time: 0.0,
        response_processing_time: 0.0,
        elb_status_code: 0,
        target_status_code: None,
        received_bytes: 0,
        sent_bytes: 0,
        request_method: "-".to_string(),
        request_url: "-".to_string(),
        request_protocol: "-".to_string(),
        user_agent: "-".to_string(),
        ssl_cipher: "-".to_string(),
        ssl_protocol: "-".to_string(),
        target_group_arn: "-".to_string(),
        trace_id: format!("Root=1-{:x}-{}", chrono::Utc::now().timestamp(), short_id()),
        domain_name: "-".to_string(),
        chosen_cert_arn: "-".to_string(),
        matched_rule_priority: "-".to_string(),
        request_creation_time: creation_time,
        actions_executed: "-".to_string(),
        redirect_url: "-".to_string(),
        error_reason: "-".to_string(),
        target_port_list,
        target_status_code_list: "-".to_string(),
        classification: "-".to_string(),
        classification_reason: "-".to_string(),
    };
    logger.record(lb_arn, record);
}

async fn handle_request(
    dp: &DataPlane,
    lb_arn: &str,
    peer_addr: SocketAddr,
    mut req: Request<Incoming>,
) -> Response<Body> {
    let request_start = Instant::now();
    let request_creation_time = Utc::now();
    // A WebSocket handshake: the client's connection, handed over once the
    // target switches protocols.
    let client_upgrade = (req.method() == Method::GET && is_websocket_upgrade(req.headers()))
        .then(|| hyper::upgrade::on(&mut req));
    // Read request fully into memory. Body sizes that matter for ALB
    // tests are small; the streaming-body refactor is its own batch.
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return canned_body(StatusCode::BAD_REQUEST, "Bad Request"),
    };
    let received_bytes = body_bytes.len() as u64;
    let user_agent = parts
        .headers
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();
    let request_method = parts.method.to_string();
    let request_uri_str = parts.uri.to_string();
    let request_protocol = format!("{:?}", parts.version);

    let host = parts
        .headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let mut log_ctx = RequestLogContext {
        request_creation_time,
        request_start,
        received_bytes,
        user_agent,
        request_method,
        request_url: request_uri_str.clone(),
        request_protocol,
        host: host.clone(),
        actions_executed: String::from("waf,forward"),
        action_taken: ActionTaken::Unknown,
        target_ip: None,
        target_port: None,
        target_group_arn: String::from("-"),
        matched_rule_priority: String::from("-"),
        target_status_code: None,
        redirect_url: String::from("-"),
        error_reason: String::from("-"),
    };

    // Pick the listener for this connection. ALBs may have multiple
    // listeners (e.g. 80 + 443); we pick the first listener belonging
    // to this LB, since the in-process bind is single-port for now.
    let snap = match snapshot(dp, lb_arn) {
        Some(s) => s,
        None => {
            let resp = canned_body(StatusCode::SERVICE_UNAVAILABLE, "LB removed");
            return finalize_response(dp, lb_arn, peer_addr, &mut log_ctx, resp);
        }
    };

    let listener = match snap.listener_for_request(&parts.headers) {
        Some(l) => l,
        None => {
            let resp = canned_body(StatusCode::BAD_GATEWAY, "No listener");
            return finalize_response(dp, lb_arn, peer_addr, &mut log_ctx, resp);
        }
    };

    let forwarded = ForwardedFor {
        client_ip: peer_addr.ip(),
        proto: listener
            .protocol
            .as_deref()
            .unwrap_or("HTTP")
            .to_ascii_lowercase(),
        port: listener
            .port
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(80),
    };

    // WAF v2 evaluation: if a WebACL is associated with this LB, run
    // each request through the evaluator before the listener-rule
    // router. Block / Captcha / Challenge short-circuit; Count is
    // recorded but lets the request through.
    if let Some(waf_resp) = evaluate_waf_for_request(
        dp,
        lb_arn,
        &parts.method,
        &parts.uri,
        &parts.headers,
        &body_bytes,
        peer_addr,
    ) {
        log_ctx.actions_executed = String::from("waf");
        log_ctx.action_taken = ActionTaken::WafBlock;
        return finalize_response(dp, lb_arn, peer_addr, &mut log_ctx, boxed(waf_resp));
    }

    let rules: Vec<&Rule> = snap.rules_for_listener(&listener.arn);
    let actions = select_actions(
        &rules,
        &listener.default_actions,
        &parts.method,
        &parts.uri,
        &host,
        &parts.headers,
        Some(peer_addr.ip()),
    );

    let action = match actions.iter().min_by_key(|a| a.order.unwrap_or(0)) {
        Some(a) => a.clone(),
        None => {
            let resp = canned_body(StatusCode::BAD_GATEWAY, "No action");
            return finalize_response(dp, lb_arn, peer_addr, &mut log_ctx, resp);
        }
    };
    log_ctx.matched_rule_priority = "0".to_string();

    let resp = match action.action_type.to_lowercase().as_str() {
        "forward" => {
            log_ctx.actions_executed = "forward".to_string();
            log_ctx.action_taken = ActionTaken::Forward;
            forward_action(
                dp,
                &snap,
                &action,
                parts.method,
                parts.uri,
                parts.headers,
                body_bytes,
                &forwarded,
                client_upgrade,
                &mut log_ctx,
            )
            .await
        }
        "fixed-response" => {
            log_ctx.actions_executed = "fixed-response".to_string();
            log_ctx.action_taken = ActionTaken::FixedResponse;
            boxed(fixed_response_action(&action))
        }
        "redirect" => {
            log_ctx.actions_executed = "redirect".to_string();
            log_ctx.action_taken = ActionTaken::Redirect;
            let r = redirect_action(&action, &host, &parts.uri);
            log_ctx.redirect_url = r
                .headers()
                .get(http::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-")
                .to_string();
            boxed(r)
        }
        "authenticate-oidc" | "authenticate-cognito" => {
            log_ctx.actions_executed = "authenticate".to_string();
            canned_body(
                StatusCode::NOT_IMPLEMENTED,
                "OIDC/Cognito authenticate-action is on the next-batch ELBv2 list",
            )
        }
        other => {
            log_ctx.actions_executed = other.to_string();
            canned_body(
                StatusCode::BAD_GATEWAY,
                &format!("Unsupported action: {other}"),
            )
        }
    };
    finalize_response(dp, lb_arn, peer_addr, &mut log_ctx, resp)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActionTaken {
    Unknown,
    Forward,
    FixedResponse,
    Redirect,
    WafBlock,
}

/// Captured per-request fields used to build the access-log line.
struct RequestLogContext {
    request_creation_time: chrono::DateTime<chrono::Utc>,
    request_start: Instant,
    received_bytes: u64,
    user_agent: String,
    request_method: String,
    request_url: String,
    request_protocol: String,
    host: String,
    actions_executed: String,
    action_taken: ActionTaken,
    target_ip: Option<String>,
    target_port: Option<u16>,
    target_group_arn: String,
    matched_rule_priority: String,
    target_status_code: Option<u16>,
    redirect_url: String,
    error_reason: String,
}

/// Common tail of every code path: emit the response back to the
/// caller and (when access logs are configured for the LB) buffer one
/// access-log line and one connection-log line.
fn finalize_response(
    dp: &DataPlane,
    lb_arn: &str,
    peer_addr: SocketAddr,
    ctx: &mut RequestLogContext,
    resp: Response<Body>,
) -> Response<Body> {
    let Some(logger) = dp.access_logger.as_ref() else {
        return resp;
    };
    // Cheap snapshot of response details before we hand the response
    // back to hyper. A whole answer knows its size now; a streamed one
    // is counted as it goes, and its line written once it ends.
    use hyper::body::Body as _;
    let elb_status_code = resp.status().as_u16();
    let exact_size = resp.body().size_hint().exact();
    let sent_bytes = exact_size.unwrap_or(0);
    let total_elapsed = ctx.request_start.elapsed().as_secs_f64();
    let target_processing_time = match ctx.action_taken {
        ActionTaken::Forward => total_elapsed,
        _ => 0.0,
    };
    let request_processing_time = if matches!(ctx.action_taken, ActionTaken::Forward) {
        0.0
    } else {
        total_elapsed
    };

    let elb_id = parse_lb_id(lb_arn).unwrap_or_else(|| lb_arn.to_string());
    let target_port_list = match (ctx.target_ip.as_deref(), ctx.target_port) {
        (Some(ip), Some(port)) => format!("{ip}:{port}"),
        _ => "-".to_string(),
    };
    let target_status_code_list = ctx
        .target_status_code
        .map(|c| c.to_string())
        .unwrap_or_else(|| "-".to_string());

    let access_record = AccessLogRecord {
        log_type: LogType::Access,
        timestamp: chrono::Utc::now(),
        elb_id: elb_id.clone(),
        client_ip: peer_addr.ip().to_string(),
        client_port: peer_addr.port(),
        target_ip: ctx.target_ip.clone(),
        target_port: ctx.target_port,
        request_processing_time,
        target_processing_time,
        response_processing_time: 0.0,
        elb_status_code,
        target_status_code: ctx.target_status_code,
        received_bytes: ctx.received_bytes,
        sent_bytes,
        request_method: ctx.request_method.clone(),
        request_url: ctx.request_url.clone(),
        request_protocol: ctx.request_protocol.clone(),
        user_agent: ctx.user_agent.clone(),
        ssl_cipher: "-".to_string(),
        ssl_protocol: "-".to_string(),
        target_group_arn: ctx.target_group_arn.clone(),
        trace_id: format!("Root=1-{:x}-{}", chrono::Utc::now().timestamp(), short_id()),
        domain_name: ctx.host.clone(),
        chosen_cert_arn: "-".to_string(),
        matched_rule_priority: ctx.matched_rule_priority.clone(),
        request_creation_time: ctx.request_creation_time,
        actions_executed: ctx.actions_executed.clone(),
        redirect_url: ctx.redirect_url.clone(),
        error_reason: ctx.error_reason.clone(),
        target_port_list,
        target_status_code_list,
        classification: "-".to_string(),
        classification_reason: "-".to_string(),
    };
    if exact_size.is_none() {
        let logger = Arc::clone(logger);
        let lb_arn = lb_arn.to_string();
        return resp.map(|body| {
            Counted::new(body, move |sent| {
                let mut access_record = access_record;
                access_record.sent_bytes = sent;
                logger.record(&lb_arn, access_record);
            })
            .boxed_unsync()
        });
    }
    logger.record(lb_arn, access_record);
    // The connection log is emitted once per accepted TCP connection
    // by `accept_loop` after `serve_connection` returns. Keep-alive
    // connections that serve multiple requests therefore produce
    // exactly one connection-log entry, not one per request.
    resp
}

/// Pull the `app/<name>/<suffix>` path out of an LB ARN — that's the
/// `elb` field AWS uses in the access-log line.
fn parse_lb_id(arn: &str) -> Option<String> {
    let after_loadbalancer = arn.split(":loadbalancer/").nth(1)?;
    Some(after_loadbalancer.to_string())
}

/// Snapshot of the rules/listeners/target-groups for one LB taken
/// under the read lock so the per-request handler doesn't re-lock.
struct LbSnapshot {
    /// The load balancer's security groups: the source instance targets'
    /// security-group rules must admit.
    security_groups: Vec<String>,
    /// How long an exchange with a target may go without a byte either
    /// way (see [`idle_timeout_of`]).
    idle_timeout: Duration,
    listeners: Vec<Listener>,
    rules: Vec<Rule>,
    target_groups: BTreeMap<String, TargetGroup>,
}

impl LbSnapshot {
    fn listener_for_request(&self, _headers: &HeaderMap) -> Option<&Listener> {
        // The dataplane is single-port per LB in this batch — every
        // request lands on the same hyper bind, so we pick the first
        // HTTP-protocol listener as the active one. HTTPS termination
        // is the next-batch item.
        self.listeners
            .iter()
            .find(|l| {
                l.protocol
                    .as_deref()
                    .map(|p| p.eq_ignore_ascii_case("HTTP"))
                    .unwrap_or(false)
            })
            .or_else(|| self.listeners.first())
    }

    fn rules_for_listener(&self, listener_arn: &str) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|r| r.listener_arn == listener_arn)
            .collect()
    }
}

fn snapshot(dp: &DataPlane, lb_arn: &str) -> Option<LbSnapshot> {
    let accs = dp.state.read();
    for (_acct, st) in accs.iter() {
        if let Some(lb) = st.load_balancers.get(lb_arn) {
            let security_groups = lb.security_groups.clone();
            let idle_timeout = idle_timeout_of(lb);
            let listeners: Vec<Listener> = st
                .listeners
                .values()
                .filter(|l| l.load_balancer_arn == lb_arn)
                .cloned()
                .collect();
            let listener_arns: std::collections::HashSet<String> =
                listeners.iter().map(|l| l.arn.clone()).collect();
            let rules: Vec<Rule> = st
                .rules
                .values()
                .filter(|r| listener_arns.contains(&r.listener_arn))
                .cloned()
                .collect();
            let target_groups: BTreeMap<String, TargetGroup> = st
                .target_groups
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            return Some(LbSnapshot {
                security_groups,
                idle_timeout,
                listeners,
                rules,
                target_groups,
            });
        }
    }
    None
}

/// Outcome of running the WAFv2 evaluator for one ALB request.
/// `Allow` means fall through to the listener-rule router; the other
/// variants short-circuit with a synthetic response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WafEvalOutcome {
    NoAcl,
    Allow,
    Count,
    Block,
    Captcha,
    Challenge,
}

/// Run the WebACL associated with `lb_arn` (if any) against the
/// incoming request. Returns `Some(response)` when the resolved
/// [`WafAction`] is terminal (`Block`, `Captcha`, `Challenge`); returns
/// `None` when the request should fall through to the listener-rule
/// router. Count-action matches are recorded in
/// `dp.waf_count_metrics` and do not short-circuit.
fn evaluate_waf_for_request(
    dp: &DataPlane,
    lb_arn: &str,
    method: &Method,
    uri: &http::Uri,
    headers: &HeaderMap,
    body: &Bytes,
    peer_addr: SocketAddr,
) -> Option<Response<Full<Bytes>>> {
    let waf_state = dp.waf_state.as_ref()?;
    let outcome = evaluate_waf_outcome(
        waf_state,
        lb_arn,
        method.as_str(),
        uri,
        headers,
        body.as_ref(),
        peer_addr,
        Some(&dp.waf_count_metrics),
    );
    waf_outcome_to_response(outcome)
}

/// Pure-function form of [`evaluate_waf_for_request`] that resolves
/// the WAF state for one ALB and returns the resolved
/// [`WafEvalOutcome`]. Split out so unit tests can drive it without
/// constructing a full hyper data plane.
#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_waf_outcome(
    waf_state: &SharedWafv2State,
    lb_arn: &str,
    method: &str,
    uri: &http::Uri,
    headers: &HeaderMap,
    body: &[u8],
    peer_addr: SocketAddr,
    count_metrics: Option<&Arc<Mutex<BTreeMap<String, u64>>>>,
) -> WafEvalOutcome {
    let Some(snap) = waf_snapshot_for_lb(waf_state, lb_arn) else {
        return WafEvalOutcome::NoAcl;
    };
    let header_pairs: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_lowercase(), s.to_string()))
        })
        .collect();
    let path = uri.path();
    let query = uri.query().unwrap_or("");
    let req = WafRequest {
        method,
        uri: path,
        headers: &header_pairs,
        body,
        query,
        source_ip: peer_addr.ip(),
        country: None,
        body_size_bytes: body.len() as u64,
    };
    let detailed = waf_evaluate_detailed(
        &req,
        &snap.web_acl,
        &snap.ipsets,
        &snap.regex_sets,
        &snap.rule_groups,
    );
    if !detailed.count_rules.is_empty() {
        if let Some(metrics) = count_metrics {
            let mut m = metrics.lock();
            for rule_name in &detailed.count_rules {
                let key = format!("{}|{}", snap.web_acl.arn, rule_name);
                *m.entry(key).or_insert(0) += 1;
            }
        }
    }
    match detailed.action {
        WafAction::Allow => {
            if !detailed.count_rules.is_empty() {
                WafEvalOutcome::Count
            } else {
                WafEvalOutcome::Allow
            }
        }
        WafAction::Count => WafEvalOutcome::Count,
        WafAction::Block => WafEvalOutcome::Block,
        WafAction::Captcha => WafEvalOutcome::Captcha,
        WafAction::Challenge => WafEvalOutcome::Challenge,
    }
}

fn waf_outcome_to_response(outcome: WafEvalOutcome) -> Option<Response<Full<Bytes>>> {
    match outcome {
        WafEvalOutcome::NoAcl | WafEvalOutcome::Allow | WafEvalOutcome::Count => None,
        WafEvalOutcome::Block => {
            let body = Bytes::from_static(br#"{"message":"Forbidden"}"#);
            let mut resp = Response::new(Full::new(body));
            *resp.status_mut() = StatusCode::FORBIDDEN;
            resp.headers_mut().insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            Some(resp)
        }
        WafEvalOutcome::Captcha => {
            // AWS WAF emits a 405 Method Not Allowed pseudo-response
            // when a CAPTCHA challenge fires for an unsupported
            // request method. The body content is not stable across
            // versions; an empty JSON object matches the wire
            // observation.
            let body = Bytes::from_static(br#"{"message":"Captcha"}"#);
            let mut resp = Response::new(Full::new(body));
            *resp.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
            resp.headers_mut().insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            Some(resp)
        }
        WafEvalOutcome::Challenge => {
            let body = Bytes::from_static(br#"{"message":"Challenge"}"#);
            let mut resp = Response::new(Full::new(body));
            *resp.status_mut() = StatusCode::ACCEPTED;
            resp.headers_mut().insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            Some(resp)
        }
    }
}

/// Snapshot of the WAFv2 state needed to evaluate the WebACL
/// associated with one load balancer. Cloning under the read lock
/// keeps the per-request handler from re-locking.
struct WafSnapshot {
    web_acl: WebAcl,
    ipsets: std::collections::HashMap<String, IpSet>,
    regex_sets: std::collections::HashMap<String, RegexPatternSet>,
    rule_groups: std::collections::HashMap<String, RuleGroup>,
}

fn waf_snapshot_for_lb(waf_state: &SharedWafv2State, lb_arn: &str) -> Option<WafSnapshot> {
    let st = waf_state.read();
    // The web ACL association lives in the load balancer's own region and
    // account.
    for account in st.states_for_resource(lb_arn) {
        let Some(acl_arn) = account.associations.get(lb_arn) else {
            continue;
        };
        let Some(web_acl) = account.web_acls.values().find(|a| &a.arn == acl_arn) else {
            continue;
        };
        let ipsets: std::collections::HashMap<String, IpSet> = account
            .ip_sets
            .values()
            .map(|s| (s.arn.clone(), s.clone()))
            .collect();
        let regex_sets: std::collections::HashMap<String, RegexPatternSet> = account
            .regex_pattern_sets
            .values()
            .map(|s| (s.arn.clone(), s.clone()))
            .collect();
        let rule_groups: std::collections::HashMap<String, RuleGroup> = account
            .rule_groups
            .values()
            .map(|g| (g.arn.clone(), g.clone()))
            .collect();
        return Some(WafSnapshot {
            web_acl: web_acl.clone(),
            ipsets,
            regex_sets,
            rule_groups,
        });
    }
    None
}

fn fixed_response_action(action: &Action) -> Response<Full<Bytes>> {
    let cfg = match action.fixed_response.as_ref() {
        Some(c) => c,
        None => return canned(StatusCode::BAD_GATEWAY, "fixed-response missing config"),
    };
    let status = cfg
        .status_code
        .parse::<u16>()
        .ok()
        .and_then(|c| StatusCode::from_u16(c).ok())
        .unwrap_or(StatusCode::OK);
    let body = cfg.message_body.clone().unwrap_or_default();
    let content_type = cfg
        .content_type
        .clone()
        .unwrap_or_else(|| "text/plain".into());
    let mut resp = Response::new(Full::new(Bytes::from(body)));
    *resp.status_mut() = status;
    if let Ok(v) = HeaderValue::from_str(&content_type) {
        resp.headers_mut().insert(http::header::CONTENT_TYPE, v);
    }
    resp
}

fn redirect_action(
    action: &Action,
    request_host: &str,
    request_uri: &http::Uri,
) -> Response<Full<Bytes>> {
    let cfg = match action.redirect.as_ref() {
        Some(c) => c,
        None => return canned(StatusCode::BAD_GATEWAY, "redirect missing config"),
    };
    let status = match cfg.status_code.as_str() {
        "HTTP_301" => StatusCode::MOVED_PERMANENTLY,
        "HTTP_302" => StatusCode::FOUND,
        _ => StatusCode::FOUND,
    };
    let proto = cfg.protocol.clone().unwrap_or_else(|| "HTTPS".into());
    let host = cfg.host.clone().unwrap_or_else(|| {
        request_host
            .split(':')
            .next()
            .unwrap_or(request_host)
            .to_string()
    });
    let path = cfg
        .path
        .clone()
        .unwrap_or_else(|| request_uri.path().to_string());
    let query = match (cfg.query.clone(), request_uri.query()) {
        (Some(q), _) if !q.is_empty() => format!("?{q}"),
        (_, Some(q)) if !q.is_empty() => format!("?{q}"),
        _ => String::new(),
    };
    let port = cfg.port.clone();
    let port_seg = port
        .filter(|p| p != "#{port}")
        .map(|p| format!(":{p}"))
        .unwrap_or_default();
    // Only the scheme and host are case-insensitive; path and query
    // must preserve original casing (RFC 3986).
    let location = format!(
        "{proto}://{host}{port_seg}{path}{query}",
        proto = proto.to_lowercase(),
        host = host.to_lowercase(),
    );
    let mut resp = Response::new(Full::new(Bytes::new()));
    *resp.status_mut() = status;
    if let Ok(v) = HeaderValue::from_str(&location) {
        resp.headers_mut().insert(http::header::LOCATION, v);
    }
    resp
}

/// The socket to forward to for a chosen target, via the shared
/// [`fakecloud_core::dataplane`] resolution: an endpoint a runtime published
/// for it (an `awsvpc` ECS task's ENI IP, an EC2 instance port), else the
/// historical routing -- `i-*` and ECS bridge-mode (`127.0.0.1`) targets on
/// `sibling_host`, anything else verbatim. The account comes from the target
/// group ARN, since target ids (private IPs) are only unique per account.
/// `lb_security_groups` are the connecting load balancer's groups, which an
/// instance target's security-group rules evaluate as the source.
async fn resolve_upstream(
    tg_arn: &str,
    target_id: &str,
    port: u16,
    sibling_host: &str,
    lb_security_groups: &[String],
) -> fakecloud_core::dataplane::Endpoint {
    let account = fakecloud_core::dataplane::account_of_arn(tg_arn).unwrap_or_default();
    fakecloud_core::dataplane::resolve_target(
        account,
        target_id,
        port,
        sibling_host,
        lb_security_groups,
    )
    .await
}

/// The `X-Forwarded-For` an ALB sends on: the one it was given, if any, with the
/// address of the client that connected to it appended, as AWS does.
fn forwarded_for(existing: Option<&str>, client: &str) -> String {
    match existing {
        Some(existing) => format!("{existing}, {client}"),
        None => client.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn forward_action(
    dp: &DataPlane,
    snap: &LbSnapshot,
    action: &Action,
    method: Method,
    uri: http::Uri,
    headers: HeaderMap,
    body: Bytes,
    forwarded: &ForwardedFor,
    client_upgrade: Option<hyper::upgrade::OnUpgrade>,
    log_ctx: &mut RequestLogContext,
) -> Response<Body> {
    // Prefer `forward.target_groups` (weighted), fall back to the
    // single `target_group_arn` field for legacy actions.
    let target_groups: Vec<(String, i32)> = if let Some(fwd) = action.forward.as_ref() {
        fwd.target_groups
            .iter()
            .map(|t| (t.target_group_arn.clone(), t.weight.unwrap_or(1).max(1)))
            .collect()
    } else if let Some(tg) = action.target_group_arn.as_ref() {
        vec![(tg.clone(), 1)]
    } else {
        return canned_body(
            StatusCode::BAD_GATEWAY,
            "forward action without target groups",
        );
    };

    let total_weight: i32 = target_groups.iter().map(|(_, w)| *w).sum();
    if total_weight <= 0 {
        return canned_body(StatusCode::BAD_GATEWAY, "no positive target-group weight");
    }
    // Pick a target group (weighted round-robin). Lock is taken
    // and released within the helper — never across the upstream
    // .await, which would make the future !Send.
    let pick_idx = pick_weighted(
        &dp.rr_counters,
        &format!("tg:{}", action_key(action)),
        &target_groups,
        total_weight as usize,
    );

    let (tg_arn, _w) = target_groups[pick_idx].clone();
    log_ctx.target_group_arn = tg_arn.clone();
    let tg = match snap.target_groups.get(&tg_arn) {
        Some(t) => t,
        None => return canned_body(StatusCode::SERVICE_UNAVAILABLE, "Target group not found"),
    };

    // Sticky session: if the request carries an AWSALB cookie that
    // maps to a registered target in this TG, prefer that target.
    let sticky_pick: Option<String> = if action
        .forward
        .as_ref()
        .and_then(|f| f.stickiness.as_ref())
        .and_then(|s| s.enabled)
        .unwrap_or(false)
    {
        let cookie = headers
            .get(http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|c| extract_cookie(c, STICKY_COOKIE).map(str::to_string));
        match cookie {
            Some(c) => {
                let map = dp.sticky_targets.lock();
                map.get(&c).cloned()
            }
            None => None,
        }
    } else {
        None
    };

    let routable = routable_targets(&tg.targets);
    if routable.is_empty() {
        return canned_body(StatusCode::SERVICE_UNAVAILABLE, "No healthy targets");
    }

    let chosen: &crate::state::TargetDescription = if let Some(sticky_key) = sticky_pick.as_ref() {
        // sticky_key format: tg_arn|target_id|target_port
        let parts: Vec<&str> = sticky_key.split('|').collect();
        if parts.len() == 3 && parts[0] == tg_arn {
            let port: Option<i32> = parts[2].parse().ok();
            routable
                .iter()
                .copied()
                .find(|t| t.id == parts[1] && t.port == port)
                .unwrap_or_else(|| {
                    routable[round_robin_pick(&dp.rr_counters, &tg_arn, routable.len())]
                })
        } else {
            routable[round_robin_pick(&dp.rr_counters, &tg_arn, routable.len())]
        }
    } else {
        routable[round_robin_pick(&dp.rr_counters, &tg_arn, routable.len())]
    };

    // Build upstream URL: TLS to HTTPS target groups, as an ALB opens one
    // (the client accepts any target certificate, as an ALB does).
    let tls = tg
        .protocol
        .as_deref()
        .is_some_and(|p| p.eq_ignore_ascii_case("HTTPS"));
    let scheme = if tls { "https" } else { "http" };
    let target_port = chosen.port.or(tg.port).unwrap_or(80);
    let Ok(target_port) = u16::try_from(target_port) else {
        return canned_body(StatusCode::BAD_GATEWAY, "target port out of range");
    };
    let upstream = resolve_upstream(
        &tg_arn,
        &chosen.id,
        target_port,
        &dp.sibling_host,
        &snap.security_groups,
    )
    .await;
    // Access logs name the target as AWS does (its private IP and target
    // port) when the id is an address; otherwise the socket we opened.
    if chosen.id.parse::<std::net::IpAddr>().is_ok() {
        log_ctx.target_ip = Some(chosen.id.clone());
        log_ctx.target_port = Some(target_port);
    } else {
        log_ctx.target_ip = Some(upstream.host.clone());
        log_ctx.target_port = Some(upstream.port);
    }
    let path_and_query = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let upstream_url = format!(
        "{scheme}://{}:{}{path_and_query}",
        upstream.host, upstream.port
    );

    // Forward via reqwest. Strip hop-by-hop headers; AWS adds
    // X-Forwarded-* headers.
    let mut req_builder = dp.upstream.request(reqwest_method(&method), &upstream_url);
    let mut forwarded_headers = headers.clone();
    strip_hop_by_hop(&mut forwarded_headers);
    forwarded.apply(&mut forwarded_headers);
    let trace_id = format!("Root=1-{:x}-{}", chrono::Utc::now().timestamp(), short_id());
    forwarded_headers.insert(
        HeaderName::from_static("x-amzn-trace-id"),
        HeaderValue::from_str(&trace_id).unwrap(),
    );
    if let Some(client) = client_upgrade {
        let upgrade = headers
            .get(http::header::UPGRADE)
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_static("websocket"));
        return boxed(
            forward_upgrade(
                &upstream,
                tls,
                snap.idle_timeout,
                method,
                path_and_query,
                forwarded_headers,
                upgrade,
                client,
                log_ctx,
            )
            .await,
        );
    }
    for (k, v) in forwarded_headers.iter() {
        req_builder = req_builder.header(k.as_str(), v.as_bytes());
    }
    if !body.is_empty() {
        req_builder = req_builder.body(body.to_vec());
    }

    // The target has the idle timeout to start answering, as on an ALB;
    // one it cannot be connected to, or that stays silent, is a 504.
    let upstream_resp = match tokio::time::timeout(snap.idle_timeout, req_builder.send()).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            log_ctx.error_reason = format!("UpstreamError: {e}");
            return boxed(upstream_error(&e.to_string(), e.is_timeout()));
        }
        Err(_) => {
            log_ctx.error_reason = "TargetResponseTimeout".to_string();
            return canned_body(StatusCode::GATEWAY_TIMEOUT, "Gateway Timeout");
        }
    };

    let mut resp = Response::new(Body::default());
    *resp.status_mut() = upstream_resp.status();
    log_ctx.target_status_code = Some(upstream_resp.status().as_u16());
    let upstream_headers = upstream_resp.headers().clone();
    for (k, v) in upstream_headers.iter() {
        if !is_hop_by_hop(k.as_str()) {
            resp.headers_mut().append(k.clone(), v.clone());
        }
    }

    // Issue / refresh sticky cookie if stickiness is enabled.
    if action
        .forward
        .as_ref()
        .and_then(|f| f.stickiness.as_ref())
        .and_then(|s| s.enabled)
        .unwrap_or(false)
    {
        let key = format!("{tg_arn}|{}|{}", chosen.id, chosen.port.unwrap_or(0));
        let cookie_val = Uuid::new_v4().simple().to_string();
        dp.sticky_targets.lock().insert(cookie_val.clone(), key);
        let duration = action
            .forward
            .as_ref()
            .and_then(|f| f.stickiness.as_ref())
            .and_then(|s| s.duration_seconds)
            .unwrap_or(86400);
        let cookie_header = format!("{STICKY_COOKIE}={cookie_val}; Max-Age={duration}; Path=/");
        if let Ok(v) = HeaderValue::from_str(&cookie_header) {
            resp.headers_mut().append(http::header::SET_COOKIE, v);
        }
    }

    *resp.body_mut() = relay(upstream_resp, snap.idle_timeout);
    resp
}

/// The target's body, passed on as each part arrives. It ends in an
/// error once the target sends nothing for `idle`, as an ALB closes a
/// connection idle past its timeout.
fn relay(response: reqwest::Response, idle: Duration) -> Body {
    let parts = futures_util::stream::unfold(Some(response), move |response| async move {
        let mut response = response?;
        match tokio::time::timeout(idle, response.chunk()).await {
            Ok(Ok(Some(part))) => Some((Ok(Frame::data(part)), Some(response))),
            Ok(Ok(None)) => None,
            Ok(Err(e)) => Some((Err(BoxError::from(e)), None)),
            Err(_) => Some((
                Err(BoxError::from(
                    "the target was idle past the load balancer's idle timeout",
                )),
                None,
            )),
        }
    });
    StreamBody::new(parts).boxed_unsync()
}

/// A streamed answer on its way to the client, its bytes counted as they
/// go. `done` gets the count once the answer has all gone, failed, or the
/// client went away, as an ALB writes its access-log line when the
/// request completes.
struct Counted {
    inner: Body,
    sent: u64,
    done: Option<Box<dyn FnOnce(u64) + Send>>,
}

impl Counted {
    fn new(inner: Body, done: impl FnOnce(u64) + Send + 'static) -> Self {
        Self {
            inner,
            sent: 0,
            done: Some(Box::new(done)),
        }
    }

    fn finish(&mut self) {
        if let Some(done) = self.done.take() {
            done(self.sent);
        }
    }
}

impl hyper::body::Body for Counted {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.sent += data.len() as u64;
                }
            }
            Poll::Ready(Some(Err(_)) | None) => this.finish(),
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.finish();
    }
}

/// What an ALB tells a target about the client's request, in the
/// `X-Forwarded-*` headers.
struct ForwardedFor {
    /// The address of the client connected to the load balancer.
    client_ip: std::net::IpAddr,
    /// The listener's protocol, lowercased (`http` / `https`).
    proto: String,
    /// The listener's port.
    port: u16,
}

impl ForwardedFor {
    /// Sets the `X-Forwarded-*` headers as an ALB does: the client address is
    /// appended to any `X-Forwarded-For` the client sent, and `Proto` / `Port`
    /// name the listener the request came in on, replacing client values.
    fn apply(&self, headers: &mut HeaderMap) {
        // Several `X-Forwarded-For` lines are one comma-separated chain.
        let existing: Vec<&str> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        let existing = existing.join(", ");
        let xff = forwarded_for(
            (!existing.is_empty()).then_some(existing.as_str()),
            &self.client_ip.to_string(),
        );
        if let Ok(v) = HeaderValue::from_str(&xff) {
            headers.insert(HeaderName::from_static("x-forwarded-for"), v);
        }
        if let Ok(v) = HeaderValue::from_str(&self.proto) {
            headers.insert(HeaderName::from_static("x-forwarded-proto"), v);
        }
        headers.insert(
            HeaderName::from_static("x-forwarded-port"),
            HeaderValue::from(self.port),
        );
    }
}

/// The targets of a target group that take new requests. Healthy targets
/// (and `unavailable` ones, whose group runs no health checks) when there are
/// any; otherwise the ALB fails open across the `unhealthy` and `initial`
/// targets, as AWS routes to all registered targets when none is healthy.
/// `draining` and `unused` targets never take new requests, so a group with
/// nothing else routable is empty.
fn routable_targets(
    targets: &[crate::state::TargetDescription],
) -> Vec<&crate::state::TargetDescription> {
    let healthy: Vec<_> = targets
        .iter()
        .filter(|t| matches!(t.health.state.as_str(), "healthy" | "unavailable"))
        .collect();
    if !healthy.is_empty() {
        return healthy;
    }
    targets
        .iter()
        .filter(|t| matches!(t.health.state.as_str(), "unhealthy" | "initial"))
        .collect()
}

/// The answer to a request the target did not complete: 504 when the
/// connection could not be opened in time or the target stayed silent past
/// the idle timeout, as on an ALB; 502 for any other failure.
fn upstream_error(error: &str, timed_out: bool) -> Response<Full<Bytes>> {
    if timed_out {
        canned(
            StatusCode::GATEWAY_TIMEOUT,
            &format!("Upstream timeout: {error}"),
        )
    } else {
        canned(StatusCode::BAD_GATEWAY, &format!("Upstream error: {error}"))
    }
}

fn round_robin_pick(
    counters: &Arc<Mutex<BTreeMap<String, usize>>>,
    tg_arn: &str,
    n: usize,
) -> usize {
    if n == 0 {
        return 0;
    }
    let mut map = counters.lock();
    let c = map.entry(tg_arn.to_string()).or_insert(0);
    let pick = *c % n;
    *c = c.wrapping_add(1);
    pick
}

fn pick_weighted(
    counters: &Arc<Mutex<BTreeMap<String, usize>>>,
    key: &str,
    target_groups: &[(String, i32)],
    total_weight: usize,
) -> usize {
    if total_weight == 0 {
        return 0;
    }
    let mut map = counters.lock();
    let c = map.entry(key.to_string()).or_insert(0);
    *c = c.wrapping_add(1);
    let mod_n = (*c) % total_weight;
    drop(map);
    let mut chosen = 0usize;
    let mut acc: i32 = 0;
    for (i, (_, w)) in target_groups.iter().enumerate() {
        acc += *w;
        if (mod_n as i32) < acc {
            chosen = i;
            break;
        }
    }
    chosen
}

/// Forwards a WebSocket handshake to the target over a connection of its
/// own. Once the target switches protocols (`101`), the client's connection
/// and the target's are joined until either side closes, as an ALB does on
/// HTTP and HTTPS listeners; any other answer goes back as it came.
#[allow(clippy::too_many_arguments)]
async fn forward_upgrade(
    upstream: &fakecloud_core::dataplane::Endpoint,
    tls: bool,
    idle_timeout: Duration,
    method: Method,
    path_and_query: &str,
    mut headers: HeaderMap,
    upgrade: HeaderValue,
    client: hyper::upgrade::OnUpgrade,
    log_ctx: &mut RequestLogContext,
) -> Response<Full<Bytes>> {
    let mut sender = match open_upgrade_connection(upstream, tls).await {
        Ok(s) => s,
        Err(UpstreamConnectError { message, timed_out }) => {
            log_ctx.error_reason = format!("UpstreamError: {message}");
            return upstream_error(&message, timed_out);
        }
    };

    // The hop-by-hop headers that ask for the switch, which the forwarded
    // headers no longer carry.
    headers.insert(
        http::header::CONNECTION,
        HeaderValue::from_static("upgrade"),
    );
    headers.insert(http::header::UPGRADE, upgrade);
    let mut req = Request::new(http_body_util::Empty::<Bytes>::new());
    *req.method_mut() = method;
    *req.uri_mut() = match path_and_query.parse() {
        Ok(u) => u,
        Err(_) => return canned(StatusCode::BAD_REQUEST, "Bad Request"),
    };
    *req.headers_mut() = headers;
    // The target has the idle timeout to answer the handshake.
    let mut target_resp = match tokio::time::timeout(idle_timeout, sender.send_request(req)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            log_ctx.error_reason = format!("UpstreamError: {e}");
            return upstream_error(&e.to_string(), false);
        }
        Err(_) => {
            log_ctx.error_reason = "UpstreamError: idle timeout".to_string();
            return upstream_error("idle timeout", true);
        }
    };
    log_ctx.target_status_code = Some(target_resp.status().as_u16());

    if target_resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        let status = target_resp.status();
        let target_headers = target_resp.headers().clone();
        let body = match target_resp.into_body().collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => {
                return canned(
                    StatusCode::BAD_GATEWAY,
                    &format!("Upstream body error: {e}"),
                );
            }
        };
        let mut resp = Response::new(Full::new(body));
        *resp.status_mut() = status;
        for (k, v) in target_headers.iter() {
            if !is_hop_by_hop(k.as_str()) {
                resp.headers_mut().append(k.clone(), v.clone());
            }
        }
        return resp;
    }

    // The target's handshake answer goes back whole: its Upgrade, Connection
    // and Sec-WebSocket-Accept are what the client checks.
    let mut resp = Response::new(Full::new(Bytes::new()));
    *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    *resp.headers_mut() = target_resp.headers().clone();
    let target = hyper::upgrade::on(&mut target_resp);
    tokio::spawn(async move {
        let (client, target) = match tokio::try_join!(client, target) {
            Ok(p) => p,
            Err(e) => {
                debug!("ELBv2 data plane: upgrade failed: {e}");
                return;
            }
        };
        let mut client = TokioIo::new(client);
        let mut target = TokioIo::new(target);
        if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut target).await {
            trace!("ELBv2 data plane: upgraded connection ended: {e}");
        }
    });
    resp
}

/// Why a connection to the target for an upgrade could not be opened.
struct UpstreamConnectError {
    message: String,
    /// The TCP connect did not complete in [`CONNECT_TIMEOUT`].
    timed_out: bool,
}

impl UpstreamConnectError {
    fn failed(e: impl std::fmt::Display) -> Self {
        Self {
            message: e.to_string(),
            timed_out: false,
        }
    }
}

/// Opens an HTTP/1.1 connection to the target for a WebSocket handshake:
/// TLS for an HTTPS target group (any certificate accepted, as by an ALB),
/// plain TCP otherwise. The connection task runs with upgrades enabled so the
/// target's `101` hands the stream over.
async fn open_upgrade_connection(
    upstream: &fakecloud_core::dataplane::Endpoint,
    tls: bool,
) -> Result<
    hyper::client::conn::http1::SendRequest<http_body_util::Empty<Bytes>>,
    UpstreamConnectError,
> {
    let stream = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect((upstream.host.as_str(), upstream.port)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(UpstreamConnectError::failed(e)),
        Err(_) => {
            return Err(UpstreamConnectError {
                message: "connect timeout".to_string(),
                timed_out: true,
            })
        }
    };
    if tls {
        let server_name = rustls::pki_types::ServerName::try_from(upstream.host.clone())
            .map_err(UpstreamConnectError::failed)?;
        let stream = tokio_rustls::TlsConnector::from(target_tls_config())
            .connect(server_name, stream)
            .await
            .map_err(UpstreamConnectError::failed)?;
        upgrade_handshake(stream).await
    } else {
        upgrade_handshake(stream).await
    }
}

async fn upgrade_handshake<S>(
    io: S,
) -> Result<
    hyper::client::conn::http1::SendRequest<http_body_util::Empty<Bytes>>,
    UpstreamConnectError,
>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(UpstreamConnectError::failed)?;
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            debug!("ELBv2 data plane: upstream connection error: {e}");
        }
    });
    Ok(sender)
}

/// TLS settings for connections to HTTPS targets: HTTP/1.1 (the upgrade is an
/// HTTP/1.1 mechanism) and no certificate verification, since an ALB accepts
/// any certificate a target presents, self-signed or expired included.
fn target_tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .expect("the ring provider supports the default TLS versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyTargetCert(provider)))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }))
}

/// Accepts the target's certificate whatever it is; handshake signatures are
/// still checked against the certificate's key, so the session is with the
/// holder of that key.
#[derive(Debug)]
struct AcceptAnyTargetCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyTargetCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Whether `headers` ask to switch the connection to WebSocket, the one
/// upgrade an ALB takes.
fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let connection_upgrade = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
    let websocket = headers
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("websocket"));
    connection_upgrade && websocket
}

fn reqwest_method(m: &Method) -> reqwest::Method {
    match m.as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        "PATCH" => reqwest::Method::PATCH,
        "TRACE" => reqwest::Method::TRACE,
        "CONNECT" => reqwest::Method::CONNECT,
        other => reqwest::Method::from_bytes(other.as_bytes()).unwrap_or(reqwest::Method::GET),
    }
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn is_hop_by_hop(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    HOP_BY_HOP.iter().any(|&h| h == n)
}

fn strip_hop_by_hop(h: &mut HeaderMap) {
    let to_remove: Vec<HeaderName> = h
        .keys()
        .filter(|n| is_hop_by_hop(n.as_str()))
        .cloned()
        .collect();
    for n in to_remove {
        h.remove(n);
    }
}

/// A whole answer as the data plane sends it.
fn boxed(resp: Response<Full<Bytes>>) -> Response<Body> {
    resp.map(|body| body.map_err(|never| match never {}).boxed_unsync())
}

fn canned_body(status: StatusCode, msg: &str) -> Response<Body> {
    boxed(canned(status, msg))
}

fn canned(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(msg.to_string())));
    *r.status_mut() = status;
    r.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain"),
    );
    r
}

fn action_key(a: &Action) -> String {
    if let Some(fwd) = a.forward.as_ref() {
        fwd.target_groups
            .iter()
            .map(|t| t.target_group_arn.as_str())
            .collect::<Vec<_>>()
            .join(",")
    } else if let Some(tg) = a.target_group_arn.as_ref() {
        tg.clone()
    } else {
        a.action_type.clone()
    }
}

fn extract_cookie<'a>(cookies: &'a str, name: &str) -> Option<&'a str> {
    for piece in cookies.split(';') {
        let piece = piece.trim_start();
        if let Some(rest) = piece.strip_prefix(&format!("{name}=")) {
            return Some(rest.trim_end());
        }
    }
    None
}

fn short_id() -> String {
    fakecloud_core::ids::short_id(16)
}

#[cfg(test)]
mod upstream_host_tests {
    use super::resolve_upstream;

    const TG: &str = "arn:aws:elasticloadbalancing:us-east-1:444455556666:targetgroup/tg/0123";

    #[tokio::test]
    async fn loopback_published_targets_use_sibling_host() {
        // EC2 instance + ECS bridge-mode (id "127.0.0.1") go via sibling_host.
        let ep = resolve_upstream(TG, "i-0123456789abcdef0", 80, "host.docker.internal", &[]).await;
        assert_eq!(ep.host, "host.docker.internal");
        let ep = resolve_upstream(TG, "127.0.0.1", 8080, "host.containers.internal", &[]).await;
        assert_eq!(
            (ep.host.as_str(), ep.port),
            ("host.containers.internal", 8080)
        );
    }

    #[tokio::test]
    async fn unpublished_ip_used_verbatim() {
        let ep = resolve_upstream(TG, "10.0.4.7", 80, "host.docker.internal", &[]).await;
        assert_eq!((ep.host.as_str(), ep.port), ("10.0.4.7", 80));
    }

    #[tokio::test]
    async fn published_awsvpc_eni_ip_routes_to_its_host_port() {
        // ECS registers the ENI private IP AWS reports, plus where the
        // container port was published; the data plane connects there.
        fakecloud_core::dataplane::register_target(
            "444455556666",
            "10.0.1.37",
            80,
            fakecloud_core::dataplane::Endpoint::new("127.0.0.1", 49200),
        );
        let ep = resolve_upstream(TG, "10.0.1.37", 80, "127.0.0.1", &[]).await;
        assert_eq!((ep.host.as_str(), ep.port), ("127.0.0.1", 49200));
        fakecloud_core::dataplane::unregister_target("444455556666", "10.0.1.37");
    }
}

#[cfg(test)]
mod waf_tests {
    use super::*;
    use chrono::Utc;
    use fakecloud_wafv2::{AccountState, Wafv2Accounts, WebAcl};
    use http::Uri;
    use parking_lot::RwLock;
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};

    const ACCOUNT: &str = "123456789012";
    const LB_ARN: &str =
        "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test/abc";
    const ACL_ARN: &str = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test/xyz";

    fn web_acl_with(default: Value, rules: Vec<Value>) -> WebAcl {
        WebAcl {
            id: "xyz".into(),
            name: "test".into(),
            arn: ACL_ARN.into(),
            scope: "REGIONAL".into(),
            default_action: default,
            description: None,
            rules,
            visibility_config: json!({}),
            capacity: 0,
            lock_token: "lt".into(),
            label_namespace: "awswaf:123456789012:webacl:test:".into(),
            custom_response_bodies: BTreeMap::new(),
            captcha_config: None,
            challenge_config: None,
            token_domains: Vec::new(),
            association_config: None,
            data_protection_config: None,
            on_source_d_do_s_protection_config: None,
            application_config: None,
            retrofitted_by_firewall_manager: false,
            pre_process_firewall_manager_rule_groups: Vec::new(),
            post_process_firewall_manager_rule_groups: Vec::new(),
            managed_by_firewall_manager: false,
            created_time: Utc::now(),
        }
    }

    fn waf_state_with(acl: WebAcl, association: Option<&str>) -> SharedWafv2State {
        let mut accounts = Wafv2Accounts::new();
        let mut acct = AccountState::default();
        acct.web_acls
            .insert(("REGIONAL".into(), acl.name.clone()), acl);
        if let Some(resource) = association {
            acct.associations.insert(resource.into(), ACL_ARN.into());
        }
        *accounts.region_mut(ACCOUNT, "us-east-1") = acct;
        Arc::new(RwLock::new(accounts))
    }

    fn block_path_rule(needle: &str) -> Value {
        json!({
            "Name": "block-admin",
            "Priority": 0,
            "Action": {"Block": {}},
            "VisibilityConfig": {},
            "Statement": {
                "ByteMatchStatement": {
                    "SearchString": needle,
                    "FieldToMatch": {"UriPath": {}},
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                    "PositionalConstraint": "STARTS_WITH",
                }
            }
        })
    }

    fn count_path_rule(needle: &str) -> Value {
        json!({
            "Name": "count-admin",
            "Priority": 0,
            "Action": {"Count": {}},
            "VisibilityConfig": {},
            "Statement": {
                "ByteMatchStatement": {
                    "SearchString": needle,
                    "FieldToMatch": {"UriPath": {}},
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                    "PositionalConstraint": "STARTS_WITH",
                }
            }
        })
    }

    fn ip() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0)
    }

    #[test]
    fn request_blocked_by_associated_webacl() {
        let acl = web_acl_with(json!({"Allow": {}}), vec![block_path_rule("/admin")]);
        let waf = waf_state_with(acl, Some(LB_ARN));
        let outcome = evaluate_waf_outcome(
            &waf,
            LB_ARN,
            "GET",
            &"/admin/x".parse::<Uri>().unwrap(),
            &HeaderMap::new(),
            b"",
            ip(),
            None,
        );
        assert_eq!(outcome, WafEvalOutcome::Block);
        let resp = waf_outcome_to_response(outcome).expect("expected synthetic response");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn request_allowed_when_no_rules_match() {
        let acl = web_acl_with(json!({"Allow": {}}), vec![block_path_rule("/admin")]);
        let waf = waf_state_with(acl, Some(LB_ARN));
        let outcome = evaluate_waf_outcome(
            &waf,
            LB_ARN,
            "GET",
            &"/public".parse::<Uri>().unwrap(),
            &HeaderMap::new(),
            b"",
            ip(),
            None,
        );
        assert_eq!(outcome, WafEvalOutcome::Allow);
        assert!(waf_outcome_to_response(outcome).is_none());
    }

    #[test]
    fn request_allowed_when_no_webacl_associated() {
        let acl = web_acl_with(json!({"Block": {}}), vec![]);
        // Note: we deliberately do NOT associate the ACL with the LB.
        let waf = waf_state_with(acl, None);
        let outcome = evaluate_waf_outcome(
            &waf,
            LB_ARN,
            "GET",
            &"/anything".parse::<Uri>().unwrap(),
            &HeaderMap::new(),
            b"",
            ip(),
            None,
        );
        assert_eq!(outcome, WafEvalOutcome::NoAcl);
        assert!(waf_outcome_to_response(outcome).is_none());
    }

    #[test]
    fn count_action_does_not_block() {
        let acl = web_acl_with(json!({"Allow": {}}), vec![count_path_rule("/admin")]);
        let waf = waf_state_with(acl, Some(LB_ARN));
        let metrics = Arc::new(Mutex::new(BTreeMap::new()));
        let outcome = evaluate_waf_outcome(
            &waf,
            LB_ARN,
            "GET",
            &"/admin/x".parse::<Uri>().unwrap(),
            &HeaderMap::new(),
            b"",
            ip(),
            Some(&metrics),
        );
        assert_eq!(outcome, WafEvalOutcome::Count);
        assert!(waf_outcome_to_response(outcome).is_none());
        let snap = metrics.lock();
        let key = format!("{ACL_ARN}|count-admin");
        assert_eq!(snap.get(&key).copied(), Some(1));
    }

    #[test]
    fn webacl_default_block_returns_403() {
        let acl = web_acl_with(json!({"Block": {}}), vec![]);
        let waf = waf_state_with(acl, Some(LB_ARN));
        let outcome = evaluate_waf_outcome(
            &waf,
            LB_ARN,
            "GET",
            &"/anything".parse::<Uri>().unwrap(),
            &HeaderMap::new(),
            b"",
            ip(),
            None,
        );
        assert_eq!(outcome, WafEvalOutcome::Block);
        let resp = waf_outcome_to_response(outcome).expect("expected synthetic response");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}

#[cfg(test)]
mod forwarded_for_tests {
    use super::forwarded_for;

    #[test]
    fn the_client_address_is_appended() {
        assert_eq!(forwarded_for(None, "192.0.2.10"), "192.0.2.10");
        assert_eq!(
            forwarded_for(Some("198.51.100.4"), "192.0.2.10"),
            "198.51.100.4, 192.0.2.10"
        );
    }
}

#[cfg(test)]
mod forward_tests {
    use super::*;
    use crate::service::Elbv2Service;
    use crate::state::{Elbv2Accounts, TargetDescription, TargetHealth};
    use fakecloud_core::service::{AwsRequest, AwsService};
    use parking_lot::RwLock;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const ACCOUNT: &str = "123456789012";

    fn req(action: &str, params: &[(&str, &str)]) -> AwsRequest {
        AwsRequest {
            service: "elasticloadbalancing".to_string(),
            action: action.to_string(),
            region: "us-east-1".to_string(),
            account_id: ACCOUNT.to_string(),
            request_id: "rid".to_string(),
            headers: HeaderMap::new(),
            query_params: params
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            body: Bytes::new(),
            body_stream: parking_lot::Mutex::new(None),
            path_segments: vec![],
            raw_path: "/".to_string(),
            raw_query: String::new(),
            method: Method::POST,
            is_query_protocol: true,
            access_key_id: None,
            principal: None,
        }
    }

    fn target(id: &str, port: u16, state: &str) -> TargetDescription {
        TargetDescription {
            id: id.to_string(),
            port: Some(i32::from(port)),
            availability_zone: None,
            health: TargetHealth {
                state: state.to_string(),
                reason: None,
                description: None,
            },
            consecutive_success: 0,
            consecutive_failure: 0,
            last_probe_at: None,
        }
    }

    fn states(targets: &[&TargetDescription]) -> Vec<String> {
        targets.iter().map(|t| t.health.state.clone()).collect()
    }

    #[test]
    fn all_unhealthy_targets_take_requests() {
        let targets = vec![
            target("10.0.0.1", 80, "unhealthy"),
            target("10.0.0.2", 80, "unhealthy"),
        ];
        assert_eq!(routable_targets(&targets).len(), 2);
    }

    #[test]
    fn no_healthy_target_fails_open_across_unhealthy_and_initial_only() {
        let targets = vec![
            target("10.0.0.1", 80, "unhealthy"),
            target("10.0.0.2", 80, "initial"),
            target("10.0.0.3", 80, "draining"),
            target("10.0.0.4", 80, "unused"),
        ];
        assert_eq!(
            states(&routable_targets(&targets)),
            vec!["unhealthy", "initial"]
        );
    }

    #[test]
    fn healthy_targets_take_requests_alone_in_a_mix() {
        let targets = vec![
            target("10.0.0.1", 80, "unhealthy"),
            target("10.0.0.2", 80, "healthy"),
            target("10.0.0.3", 80, "initial"),
            target("10.0.0.4", 80, "draining"),
        ];
        let routable = routable_targets(&targets);
        assert_eq!(routable.len(), 1);
        assert_eq!(routable[0].id, "10.0.0.2");
    }

    #[test]
    fn draining_and_unused_targets_are_never_routed() {
        let targets = vec![
            target("10.0.0.1", 80, "draining"),
            target("10.0.0.2", 80, "unused"),
        ];
        assert!(routable_targets(&targets).is_empty());
    }

    fn forwarded(proto: &str, port: u16) -> ForwardedFor {
        ForwardedFor {
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
            proto: proto.to_string(),
            port,
        }
    }

    #[test]
    fn forwarded_headers_name_the_client_and_the_listener() {
        let mut headers = HeaderMap::new();
        forwarded("https", 443).apply(&mut headers);
        assert_eq!(headers["x-forwarded-for"], "10.1.2.3");
        assert_eq!(headers["x-forwarded-proto"], "https");
        assert_eq!(headers["x-forwarded-port"], "443");
    }

    #[test]
    fn forwarded_for_appends_the_client_to_the_existing_chain() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.9"));
        // A client cannot choose the protocol or port the target is told.
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        headers.insert("x-forwarded-port", HeaderValue::from_static("8443"));
        forwarded("http", 80).apply(&mut headers);
        assert_eq!(headers["x-forwarded-for"], "203.0.113.9, 10.1.2.3");
        assert_eq!(headers["x-forwarded-proto"], "http");
        assert_eq!(headers["x-forwarded-port"], "80");
    }

    #[test]
    fn forwarded_for_carries_ipv6_clients_bare() {
        let mut headers = HeaderMap::new();
        ForwardedFor {
            client_ip: "2001:db8::7".parse().unwrap(),
            proto: "http".to_string(),
            port: 80,
        }
        .apply(&mut headers);
        assert_eq!(headers["x-forwarded-for"], "2001:db8::7");
    }

    /// A target that answers each request with the scheme it was reached over
    /// and the `X-Forwarded-*` headers it got, takes WebSocket upgrades and
    /// then echoes bytes, and never answers `/slow`.
    async fn spawn_target(tls: bool) -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = tls.then(|| {
            let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![key.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.key_pair.serialize_der().into()),
            )
            .unwrap();
            tokio_rustls::TlsAcceptor::from(Arc::new(config))
        });
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let scheme = if tls { "https" } else { "http" };
                    let svc = service_fn(move |req| target_answer(scheme, req));
                    let builder = hyper::server::conn::http1::Builder::new();
                    match acceptor {
                        Some(a) => {
                            let Ok(s) = a.accept(sock).await else {
                                return;
                            };
                            let _ = builder
                                .serve_connection(TokioIo::new(s), svc)
                                .with_upgrades()
                                .await;
                        }
                        None => {
                            let _ = builder
                                .serve_connection(TokioIo::new(sock), svc)
                                .with_upgrades()
                                .await;
                        }
                    }
                });
            }
        });
        port
    }

    async fn target_answer(
        scheme: &'static str,
        mut req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        if req.uri().path() == "/slow" {
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        if is_websocket_upgrade(req.headers()) {
            let on = hyper::upgrade::on(&mut req);
            tokio::spawn(async move {
                let Ok(up) = on.await else { return };
                let mut io = TokioIo::new(up);
                let mut buf = [0u8; 64];
                while let Ok(n) = io.read(&mut buf).await {
                    if n == 0 || io.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
            let mut resp = Response::new(Full::new(Bytes::new()));
            *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
            resp.headers_mut()
                .insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
            resp.headers_mut().insert(
                http::header::CONNECTION,
                HeaderValue::from_static("upgrade"),
            );
            return Ok(resp);
        }
        let h = |n: &str| {
            req.headers()
                .get(n)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-")
                .to_string()
        };
        let body = format!(
            "scheme={scheme} xff={} proto={} port={}",
            h("x-forwarded-for"),
            h("x-forwarded-proto"),
            h("x-forwarded-port")
        );
        Ok(Response::new(Full::new(Bytes::from(body))))
    }

    /// A port with nothing listening on it.
    async fn dead_port() -> u16 {
        let l = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        l.local_addr().unwrap().port()
    }

    struct Alb {
        state: SharedElbv2State,
        tg_arn: String,
        port: u16,
    }

    impl Alb {
        fn set_targets(&self, targets: Vec<TargetDescription>) {
            let mut accs = self.state.write();
            let st = accs.get_mut(ACCOUNT).unwrap();
            st.target_groups.get_mut(&self.tg_arn).unwrap().targets = targets;
        }

        fn url(&self, path: &str) -> String {
            format!("http://127.0.0.1:{}{path}", self.port)
        }
    }

    /// An ALB, created through the API, with an HTTP:80 listener forwarding
    /// to a target group of `tg_protocol`, served by the data plane on a
    /// loopback port. `lb_attributes` are applied with
    /// ModifyLoadBalancerAttributes.
    async fn alb(tg_protocol: &str, lb_attributes: &[(&str, &str)]) -> Alb {
        let state: SharedElbv2State = Arc::new(RwLock::new(Elbv2Accounts::new()));
        let svc = Elbv2Service::new(Arc::clone(&state));
        svc.handle(req(
            "CreateLoadBalancer",
            &[("Name", "dp"), ("Subnets.member.1", "subnet-1")],
        ))
        .await
        .unwrap();
        svc.handle(req(
            "CreateTargetGroup",
            &[
                ("Name", "dp-tg"),
                ("Protocol", tg_protocol),
                ("Port", "443"),
            ],
        ))
        .await
        .unwrap();
        let (lb_arn, tg_arn) = {
            let accs = state.read();
            let st = accs.get(ACCOUNT).unwrap();
            (
                st.load_balancers.keys().next().unwrap().clone(),
                st.target_groups.keys().next().unwrap().clone(),
            )
        };
        svc.handle(req(
            "CreateListener",
            &[
                ("LoadBalancerArn", &lb_arn),
                ("Protocol", "HTTP"),
                ("Port", "80"),
                ("DefaultActions.member.1.Type", "forward"),
                ("DefaultActions.member.1.TargetGroupArn", &tg_arn),
            ],
        ))
        .await
        .unwrap();
        for (i, (k, v)) in lb_attributes.iter().enumerate() {
            let key = format!("Attributes.member.{}.Key", i + 1);
            let value = format!("Attributes.member.{}.Value", i + 1);
            svc.handle(req(
                "ModifyLoadBalancerAttributes",
                &[("LoadBalancerArn", &lb_arn), (&key, k), (&value, v)],
            ))
            .await
            .unwrap();
        }
        let dp = DataPlane {
            state: Arc::clone(&state),
            waf_state: None,
            access_logger: None,
            waf_count_metrics: Arc::new(Mutex::new(BTreeMap::new())),
            rr_counters: Arc::new(Mutex::new(BTreeMap::new())),
            sticky_targets: Arc::new(Mutex::new(BTreeMap::new())),
            upstream: upstream_client().unwrap(),
            sibling_host: "127.0.0.1".to_string(),
        };
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(accept_loop(dp, lb_arn, listener));
        Alb {
            state,
            tg_arn,
            port,
        }
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder().no_proxy().build().unwrap()
    }

    async fn get(url: &str) -> (StatusCode, String) {
        let resp = client().get(url).send().await.unwrap();
        let status = resp.status();
        (status, resp.text().await.unwrap())
    }

    #[tokio::test]
    async fn https_target_group_is_reached_over_tls_with_any_certificate() {
        let alb = alb("HTTPS", &[]).await;
        let target_port = spawn_target(true).await;
        alb.set_targets(vec![target("127.0.0.1", target_port, "healthy")]);
        let (status, body) = get(&alb.url("/")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.starts_with("scheme=https "), "{body}");
        // The listener is HTTP:80 and the client connected from loopback.
        assert!(body.contains("xff=127.0.0.1 proto=http port=80"), "{body}");
    }

    #[tokio::test]
    async fn http_target_group_stays_plain_http() {
        let alb = alb("HTTP", &[]).await;
        let target_port = spawn_target(false).await;
        alb.set_targets(vec![target("127.0.0.1", target_port, "healthy")]);
        let (status, body) = get(&alb.url("/")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.starts_with("scheme=http "), "{body}");
    }

    /// Sends a WebSocket handshake through the ALB and checks that bytes
    /// written after the `101` come back from the echoing target.
    async fn websocket_echo(alb: &Alb) {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", alb.port))
            .await
            .unwrap();
        s.write_all(
            b"GET /ws HTTP/1.1\r\nHost: dp\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
              Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        )
        .await
        .unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert_eq!(s.read(&mut byte).await.unwrap(), 1, "connection closed");
            head.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&head);
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        s.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        s.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");
    }

    #[tokio::test]
    async fn websocket_upgrade_passes_through_to_https_targets() {
        let alb = alb("HTTPS", &[]).await;
        let target_port = spawn_target(true).await;
        alb.set_targets(vec![target("127.0.0.1", target_port, "healthy")]);
        websocket_echo(&alb).await;
    }

    #[tokio::test]
    async fn websocket_upgrade_passes_through_to_http_targets() {
        let alb = alb("HTTP", &[]).await;
        let target_port = spawn_target(false).await;
        alb.set_targets(vec![target("127.0.0.1", target_port, "healthy")]);
        websocket_echo(&alb).await;
    }

    #[tokio::test]
    async fn requests_reach_targets_when_all_are_unhealthy() {
        let alb = alb("HTTP", &[]).await;
        let target_port = spawn_target(false).await;
        alb.set_targets(vec![target("127.0.0.1", target_port, "unhealthy")]);
        let (status, body) = get(&alb.url("/")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    #[tokio::test]
    async fn requests_skip_unhealthy_targets_while_one_is_healthy() {
        let alb = alb("HTTP", &[]).await;
        let target_port = spawn_target(false).await;
        alb.set_targets(vec![
            target("127.0.0.1", dead_port().await, "unhealthy"),
            target("127.0.0.1", target_port, "healthy"),
            target("127.0.0.1", dead_port().await, "initial"),
        ]);
        for _ in 0..6 {
            let (status, body) = get(&alb.url("/")).await;
            assert_eq!(status, StatusCode::OK, "{body}");
        }
    }

    #[tokio::test]
    async fn only_draining_targets_answer_503() {
        let alb = alb("HTTP", &[]).await;
        let target_port = spawn_target(false).await;
        alb.set_targets(vec![target("127.0.0.1", target_port, "draining")]);
        let (status, _) = get(&alb.url("/")).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn idle_timeout_attribute_bounds_a_silent_target() {
        let alb = alb("HTTP", &[("idle_timeout.timeout_seconds", "1")]).await;
        let target_port = spawn_target(false).await;
        alb.set_targets(vec![target("127.0.0.1", target_port, "healthy")]);
        let started = Instant::now();
        let (status, body) = get(&alb.url("/slow")).await;
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{body}");
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_secs(1) && waited < Duration::from_secs(10),
            "waited {waited:?}"
        );
    }

    #[tokio::test]
    async fn idle_timeout_comes_from_the_attribute_with_a_60s_default() {
        let alb = alb("HTTP", &[("idle_timeout.timeout_seconds", "4000")]).await;
        let lb = {
            let accs = alb.state.read();
            accs.get(ACCOUNT)
                .unwrap()
                .load_balancers
                .values()
                .next()
                .unwrap()
                .clone()
        };
        assert_eq!(idle_timeout_of(&lb), Duration::from_secs(4000));
        let mut unset = lb.clone();
        unset.attributes.remove(IDLE_TIMEOUT_ATTRIBUTE);
        assert_eq!(idle_timeout_of(&unset), Duration::from_secs(60));
    }
}
