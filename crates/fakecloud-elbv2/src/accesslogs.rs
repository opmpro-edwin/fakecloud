//! ELBv2 access-log + connection-log emission.
//!
//! When an LB has the `access_logs.s3.enabled = true` /
//! `connection_logs.s3.enabled = true` attributes set with a valid
//! `*.s3.bucket`, the data plane records one log line per request /
//! established connection. Lines are buffered per LB in memory and
//! flushed to S3 either on a 60-second timer or when the buffer hits
//! `MAX_BUFFER_LINES`, whichever happens first.
//!
//! Object keys follow the AWS pattern:
//! `<prefix>/AWSLogs/<account>/elasticloadbalancing/<region>/<YYYY>/<MM>/<DD>/<account>_elasticloadbalancing_<region>_<lb-id>_<timestamp>_<ip>_<random>.log.gz`
//!
//! The body is gzip-compressed space-delimited records per the AWS
//! ALB access-log format.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use flate2::write::GzEncoder;
use flate2::Compression;
use parking_lot::Mutex;
use rand::Rng;
use tracing::{debug, warn};

use fakecloud_core::delivery::DeliveryBus;

use crate::state::{LoadBalancer, SharedElbv2State};

/// Lines per buffer that trigger an immediate flush.
pub const MAX_BUFFER_LINES: usize = 1000;
/// Periodic flush interval for the background flusher.
const FLUSH_INTERVAL: Duration = Duration::from_secs(60);

/// One field set per AWS-style access-log entry. Carries every field
/// the ALB log spec lists; NLB connection logs reuse a subset.
#[derive(Debug, Clone)]
pub struct AccessLogRecord {
    pub log_type: LogType,
    pub timestamp: DateTime<Utc>,
    pub elb_id: String,
    pub client_ip: String,
    pub client_port: u16,
    pub target_ip: Option<String>,
    pub target_port: Option<u16>,
    pub request_processing_time: f64,
    pub target_processing_time: f64,
    pub response_processing_time: f64,
    pub elb_status_code: u16,
    pub target_status_code: Option<u16>,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub request_method: String,
    pub request_url: String,
    pub request_protocol: String,
    pub user_agent: String,
    pub ssl_cipher: String,
    pub ssl_protocol: String,
    pub target_group_arn: String,
    pub trace_id: String,
    pub domain_name: String,
    pub chosen_cert_arn: String,
    pub matched_rule_priority: String,
    pub request_creation_time: DateTime<Utc>,
    pub actions_executed: String,
    pub redirect_url: String,
    pub error_reason: String,
    pub target_port_list: String,
    pub target_status_code_list: String,
    pub classification: String,
    pub classification_reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogType {
    /// `access_logs.s3.*` ALB request log.
    Access,
    /// `connection_logs.s3.*` ALB/NLB connection log.
    Connection,
}

impl AccessLogRecord {
    /// Render the record as the space-delimited AWS access-log line.
    /// Fields that contain whitespace, double-quotes, or are otherwise
    /// human-text are wrapped in `"…"` per the AWS spec.
    pub(crate) fn to_log_line(&self) -> String {
        let ts = self.timestamp.format("%Y-%m-%dT%H:%M:%S%.6fZ");
        let req_create = self.request_creation_time.format("%Y-%m-%dT%H:%M:%S%.6fZ");
        let proto = match self.log_type {
            LogType::Access => "http",
            LogType::Connection => "tls",
        };
        let target = match (self.target_ip.as_deref(), self.target_port) {
            (Some(ip), Some(port)) => format!("{ip}:{port}"),
            _ => "-".to_string(),
        };
        let target_status = self
            .target_status_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "-".to_string());
        let request_quoted = format!(
            "\"{} {} {}\"",
            self.request_method, self.request_url, self.request_protocol
        );
        let user_agent_quoted = format!("\"{}\"", quote_inner(&self.user_agent));
        let actions_quoted = format!("\"{}\"", quote_inner(&self.actions_executed));
        let redirect_quoted = format!("\"{}\"", quote_inner(&self.redirect_url));
        let error_quoted = format!("\"{}\"", quote_inner(&self.error_reason));
        let target_list_quoted = format!("\"{}\"", quote_inner(&self.target_port_list));
        let target_status_list_quoted =
            format!("\"{}\"", quote_inner(&self.target_status_code_list));
        let classification_quoted = format!("\"{}\"", quote_inner(&self.classification));
        let classification_reason_quoted =
            format!("\"{}\"", quote_inner(&self.classification_reason));

        format!(
            "{proto} {ts} {elb} {client}:{cport} {target} {rpt:.3} {tpt:.3} {resp_pt:.3} {esc} {tsc} {recv} {sent} {req} {ua} {cipher} {sslp} {tg_arn} {trace} \"{domain}\" \"{cert}\" {rule_prio} {req_ct} {actions} {redir} {err} {tgt_list} {tgt_status_list} {cls} {cls_reason}",
            proto = proto,
            ts = ts,
            elb = self.elb_id,
            client = self.client_ip,
            cport = self.client_port,
            target = target,
            rpt = self.request_processing_time,
            tpt = self.target_processing_time,
            resp_pt = self.response_processing_time,
            esc = self.elb_status_code,
            tsc = target_status,
            recv = self.received_bytes,
            sent = self.sent_bytes,
            req = request_quoted,
            ua = user_agent_quoted,
            cipher = self.ssl_cipher,
            sslp = self.ssl_protocol,
            tg_arn = self.target_group_arn,
            trace = self.trace_id,
            domain = quote_inner(&self.domain_name),
            cert = quote_inner(&self.chosen_cert_arn),
            rule_prio = self.matched_rule_priority,
            req_ct = req_create,
            actions = actions_quoted,
            redir = redirect_quoted,
            err = error_quoted,
            tgt_list = target_list_quoted,
            tgt_status_list = target_status_list_quoted,
            cls = classification_quoted,
            cls_reason = classification_reason_quoted,
        )
    }
}

fn quote_inner(s: &str) -> String {
    s.replace('"', "\\\"")
}

/// Per-LB access-log buffer. Holds a running list of formatted lines
/// plus the metadata needed to address an S3 object on flush.
#[derive(Default)]
pub(crate) struct LbBuffer {
    access_lines: Vec<String>,
    connection_lines: Vec<String>,
}

/// In-memory access-log buffers and the periodic flusher.
pub struct AccessLogger {
    pub(crate) state: SharedElbv2State,
    pub(crate) delivery_bus: Arc<DeliveryBus>,
    /// Buffered lines keyed by load-balancer ARN.
    pub(crate) buffers: Arc<Mutex<BTreeMap<String, LbBuffer>>>,
    /// Per-LB region — usually `us-east-1`. Resolved from the LB ARN
    /// at write time.
    pub(crate) region: String,
}

impl AccessLogger {
    pub fn new(state: SharedElbv2State, delivery_bus: Arc<DeliveryBus>) -> Self {
        Self {
            state,
            delivery_bus,
            buffers: Arc::new(Mutex::new(BTreeMap::new())),
            region: "us-east-1".to_string(),
        }
    }

    /// Append a record to the in-memory buffer. Triggers an immediate
    /// flush for this LB when the buffer would exceed
    /// [`MAX_BUFFER_LINES`].
    pub fn record(&self, lb_arn: &str, record: AccessLogRecord) {
        let line = record.to_log_line();
        let log_type = record.log_type;
        let should_flush = {
            let mut bufs = self.buffers.lock();
            let buf = bufs.entry(lb_arn.to_string()).or_default();
            match log_type {
                LogType::Access => buf.access_lines.push(line),
                LogType::Connection => buf.connection_lines.push(line),
            }
            buf.access_lines.len() >= MAX_BUFFER_LINES
                || buf.connection_lines.len() >= MAX_BUFFER_LINES
        };
        if should_flush {
            self.flush_lb(lb_arn);
        }
    }

    /// Drain and flush every buffered LB. Called by the periodic
    /// flusher and by tests.
    pub fn flush_all(&self) {
        let arns: Vec<String> = {
            let bufs = self.buffers.lock();
            bufs.keys().cloned().collect()
        };
        for arn in arns {
            self.flush_lb(&arn);
        }
    }

    /// Drain the buffer for one LB, gzip + push to its configured S3
    /// bucket. Silent no-op when the LB is missing or the access-log
    /// configuration is incomplete.
    pub fn flush_lb(&self, lb_arn: &str) {
        let (access_lines, connection_lines) = {
            let mut bufs = self.buffers.lock();
            let Some(buf) = bufs.get_mut(lb_arn) else {
                return;
            };
            (
                std::mem::take(&mut buf.access_lines),
                std::mem::take(&mut buf.connection_lines),
            )
        };
        if access_lines.is_empty() && connection_lines.is_empty() {
            return;
        }
        let Some(meta) = self.lb_log_metadata(lb_arn) else {
            // The LB is gone or not configured — drop the lines.
            return;
        };
        if !access_lines.is_empty() {
            if let Some(target) = meta.access.as_ref() {
                self.upload(&meta, target, "access", &access_lines);
            }
        }
        if !connection_lines.is_empty() {
            if let Some(target) = meta.connection.as_ref() {
                self.upload(&meta, target, "conn", &connection_lines);
            }
        }
    }

    fn upload(&self, meta: &LogMetadata, target: &LogTarget, kind: &str, lines: &[String]) {
        let body = match gzip_lines(lines) {
            Ok(b) => b,
            Err(e) => {
                warn!(arn = %meta.lb_arn, "ELBv2 access-log gzip failed: {e}");
                return;
            }
        };
        let key = build_object_key(meta, target.prefix.as_deref(), kind);
        if let Err(e) = self.delivery_bus.put_object_to_s3(
            &meta.account_id,
            &target.bucket,
            &key,
            body,
            Some("application/x-gzip"),
        ) {
            warn!(
                bucket = %target.bucket,
                arn = %meta.lb_arn,
                "ELBv2 access-log S3 put failed: {e}"
            );
        } else {
            debug!(
                bucket = %target.bucket,
                key = %key,
                lines = lines.len(),
                "ELBv2 access-log flushed"
            );
        }
    }

    /// Look up the LB and pull the access / connection log
    /// configuration off its `attributes` map.
    fn lb_log_metadata(&self, lb_arn: &str) -> Option<LogMetadata> {
        let accs = self.state.read();
        for (account, st) in accs.iter() {
            if let Some(lb) = st.load_balancers.get(lb_arn) {
                let access = log_target_from_attrs(lb, "access_logs.s3");
                let connection = log_target_from_attrs(lb, "connection_logs.s3");
                return Some(LogMetadata {
                    account_id: account.clone(),
                    // Pull region out of the ARN
                    // (`arn:aws:elasticloadbalancing:<region>:...`) so
                    // non-`us-east-1` load balancers get the correct
                    // object key; fall back to the bus default for
                    // malformed ARNs.
                    region: parse_arn_region(lb_arn).unwrap_or_else(|| self.region.clone()),
                    lb_arn: lb_arn.to_string(),
                    lb_id: parse_lb_suffix(lb_arn).unwrap_or_else(|| lb.name.clone()),
                    access,
                    connection,
                });
            }
        }
        None
    }
}

/// Pull the region segment out of an ELB ARN — index 3 of the
/// `arn:aws:elasticloadbalancing:<region>:<account>:...` form.
fn parse_arn_region(arn: &str) -> Option<String> {
    let segment = arn.split(':').nth(3)?;
    if segment.is_empty() {
        None
    } else {
        Some(segment.to_string())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LogTarget {
    pub bucket: String,
    pub prefix: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct LogMetadata {
    pub account_id: String,
    pub region: String,
    pub lb_arn: String,
    pub lb_id: String,
    pub access: Option<LogTarget>,
    pub connection: Option<LogTarget>,
}

fn log_target_from_attrs(lb: &LoadBalancer, base_key: &str) -> Option<LogTarget> {
    let enabled_key = format!("{base_key}.enabled");
    let bucket_key = format!("{base_key}.bucket");
    let prefix_key = format!("{base_key}.prefix");
    let enabled = lb
        .attributes
        .get(&enabled_key)
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !enabled {
        return None;
    }
    let bucket = lb.attributes.get(&bucket_key).cloned().unwrap_or_default();
    if bucket.is_empty() {
        return None;
    }
    let prefix = lb
        .attributes
        .get(&prefix_key)
        .cloned()
        .filter(|s| !s.is_empty());
    Some(LogTarget { bucket, prefix })
}

/// Pull the ELB ID out of an LB ARN — it's the last `/`-delimited
/// segment, e.g. `arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test/abcdef0123456789`
/// returns `abcdef0123456789`.
fn parse_lb_suffix(arn: &str) -> Option<String> {
    arn.rsplit('/').next().map(|s| s.to_string())
}

pub(crate) fn build_object_key(meta: &LogMetadata, prefix: Option<&str>, kind: &str) -> String {
    let now = Utc::now();
    let yyyy = now.format("%Y").to_string();
    let mm = now.format("%m").to_string();
    let dd = now.format("%d").to_string();
    let ts = now.format("%Y%m%dT%H%MZ").to_string();
    // 8-byte random id to avoid collisions on rapid flushes.
    let rand_hex: String = {
        let mut buf = [0u8; 8];
        rand::thread_rng().fill(&mut buf);
        buf.iter().map(|b| format!("{b:02x}")).collect()
    };
    // The "ip" field in the AWS pattern is normally the LB's address
    // — fakecloud's ALBs bind on 127.0.0.1, so we use that.
    let ip = "127.0.0.1";
    let kind_seg = match kind {
        "conn" => "conn_",
        _ => "",
    };
    let base = format!(
        "AWSLogs/{account}/elasticloadbalancing/{region}/{yyyy}/{mm}/{dd}/{account}_elasticloadbalancing_{region}_{kind_seg}{lb_id}_{ts}_{ip}_{rand_hex}.log.gz",
        account = meta.account_id,
        region = meta.region,
        lb_id = meta.lb_id,
    );
    match prefix {
        Some(p) if !p.is_empty() => format!("{}/{}", p.trim_end_matches('/'), base),
        _ => base,
    }
}

fn gzip_lines(lines: &[String]) -> std::io::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    for line in lines {
        encoder.write_all(line.as_bytes())?;
        encoder.write_all(b"\n")?;
    }
    encoder.finish()
}

/// Spawn the periodic flusher loop that empties the buffer every
/// [`FLUSH_INTERVAL`] regardless of whether the size cap fires.
pub(crate) fn spawn_flusher(logger: Arc<AccessLogger>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(FLUSH_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            logger.flush_all();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::RwLock;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::state::Elbv2Accounts;

    const ACCOUNT: &str = "123456789012";
    const LB_ARN: &str =
        "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test/abcdef0123456789";

    struct CountingS3 {
        puts: AtomicUsize,
        last_key: Mutex<Option<String>>,
        last_body: Mutex<Option<Vec<u8>>>,
        last_bucket: Mutex<Option<String>>,
    }

    impl CountingS3 {
        fn new() -> Self {
            Self {
                puts: AtomicUsize::new(0),
                last_key: Mutex::new(None),
                last_body: Mutex::new(None),
                last_bucket: Mutex::new(None),
            }
        }
    }

    impl fakecloud_core::delivery::S3Delivery for CountingS3 {
        fn put_object(
            &self,
            _account_id: &str,
            bucket: &str,
            key: &str,
            body: Vec<u8>,
            _content_type: Option<&str>,
        ) -> Result<(), String> {
            self.puts.fetch_add(1, Ordering::SeqCst);
            *self.last_key.lock() = Some(key.to_string());
            *self.last_bucket.lock() = Some(bucket.to_string());
            *self.last_body.lock() = Some(body);
            Ok(())
        }

        fn get_object(
            &self,
            _account_id: &str,
            _bucket: &str,
            _key: &str,
        ) -> Result<Vec<u8>, String> {
            Err("not implemented in test".to_string())
        }
    }

    fn lb_with_access_logs(bucket: &str, prefix: Option<&str>) -> LoadBalancer {
        let mut attrs = BTreeMap::new();
        attrs.insert("access_logs.s3.enabled".to_string(), "true".to_string());
        attrs.insert("access_logs.s3.bucket".to_string(), bucket.to_string());
        if let Some(p) = prefix {
            attrs.insert("access_logs.s3.prefix".to_string(), p.to_string());
        }
        LoadBalancer {
            arn: LB_ARN.to_string(),
            name: "test".to_string(),
            dns_name: "test.us-east-1.elb.amazonaws.com".to_string(),
            canonical_hosted_zone_id: "Z123".to_string(),
            created_time: Utc::now(),
            scheme: "internet-facing".to_string(),
            vpc_id: "vpc-1".to_string(),
            state_code: "active".to_string(),
            state_reason: None,
            lb_type: "application".to_string(),
            availability_zones: vec![],
            security_groups: vec![],
            ip_address_type: "ipv4".to_string(),
            customer_owned_ipv4_pool: None,
            enforce_security_group_inbound_rules_on_private_link_traffic: None,
            enable_prefix_for_ipv6_source_nat: None,
            ipv4_ipam_pool_id: None,
            tags: vec![],
            attributes: attrs,
            minimum_capacity_units: None,
            bound_port: None,
            interfaces: Vec::new(),
        }
    }

    fn make_state(lb: LoadBalancer) -> SharedElbv2State {
        let mut accounts = Elbv2Accounts::new();
        let st = accounts.get_or_create(ACCOUNT);
        st.load_balancers.insert(lb.arn.clone(), lb);
        Arc::new(RwLock::new(accounts))
    }

    fn sample_record() -> AccessLogRecord {
        AccessLogRecord {
            log_type: LogType::Access,
            timestamp: Utc::now(),
            elb_id: "app/test/abcdef0123456789".to_string(),
            client_ip: "10.0.0.1".to_string(),
            client_port: 50000,
            target_ip: Some("10.0.1.1".to_string()),
            target_port: Some(8080),
            request_processing_time: 0.001,
            target_processing_time: 0.005,
            response_processing_time: 0.001,
            elb_status_code: 200,
            target_status_code: Some(200),
            received_bytes: 100,
            sent_bytes: 200,
            request_method: "GET".to_string(),
            request_url: "http://test/path".to_string(),
            request_protocol: "HTTP/1.1".to_string(),
            user_agent: "test-agent".to_string(),
            ssl_cipher: "-".to_string(),
            ssl_protocol: "-".to_string(),
            target_group_arn:
                "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg/abc".to_string(),
            trace_id: "Root=1-12345".to_string(),
            domain_name: "-".to_string(),
            chosen_cert_arn: "-".to_string(),
            matched_rule_priority: "0".to_string(),
            request_creation_time: Utc::now(),
            actions_executed: "forward".to_string(),
            redirect_url: "-".to_string(),
            error_reason: "-".to_string(),
            target_port_list: "10.0.1.1:8080".to_string(),
            target_status_code_list: "200".to_string(),
            classification: "-".to_string(),
            classification_reason: "-".to_string(),
        }
    }

    #[test]
    fn log_line_is_space_delimited_and_contains_quoted_request() {
        let rec = sample_record();
        let line = rec.to_log_line();
        assert!(line.starts_with("http "));
        assert!(line.contains("\"GET http://test/path HTTP/1.1\""));
        assert!(line.contains("\"test-agent\""));
        assert!(line.contains("10.0.0.1:50000"));
    }

    #[test]
    fn buffer_does_not_flush_when_no_lines() {
        let lb = lb_with_access_logs("logs-bucket", None);
        let state = make_state(lb);
        let s3 = Arc::new(CountingS3::new());
        let bus = Arc::new(DeliveryBus::new().with_s3(s3.clone()));
        let logger = AccessLogger::new(state, bus);
        logger.flush_all();
        assert_eq!(s3.puts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn record_then_flush_pushes_one_object_to_configured_bucket() {
        let lb = lb_with_access_logs("my-logs", Some("alb"));
        let state = make_state(lb);
        let s3 = Arc::new(CountingS3::new());
        let bus = Arc::new(DeliveryBus::new().with_s3(s3.clone()));
        let logger = AccessLogger::new(state, bus);
        logger.record(LB_ARN, sample_record());
        logger.flush_all();
        assert_eq!(s3.puts.load(Ordering::SeqCst), 1);
        assert_eq!(s3.last_bucket.lock().as_deref(), Some("my-logs"));
        let key = s3.last_key.lock().clone().expect("key");
        assert!(key.starts_with("alb/AWSLogs/123456789012/elasticloadbalancing/us-east-1/"));
        assert!(key.ends_with(".log.gz"));
        // Body should be a valid gzip stream containing the line.
        let body = s3.last_body.lock().clone().expect("body");
        let mut decoder = flate2::read::GzDecoder::new(body.as_slice());
        let mut decoded = String::new();
        std::io::Read::read_to_string(&mut decoder, &mut decoded).expect("gunzip");
        assert!(decoded.contains("GET http://test/path"));
    }

    #[test]
    fn record_does_not_flush_when_logging_disabled() {
        let mut lb = lb_with_access_logs("ignored", None);
        lb.attributes
            .insert("access_logs.s3.enabled".to_string(), "false".to_string());
        let state = make_state(lb);
        let s3 = Arc::new(CountingS3::new());
        let bus = Arc::new(DeliveryBus::new().with_s3(s3.clone()));
        let logger = AccessLogger::new(state, bus);
        logger.record(LB_ARN, sample_record());
        logger.flush_all();
        assert_eq!(s3.puts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn buffer_flushes_when_max_lines_reached() {
        let lb = lb_with_access_logs("autoflush", None);
        let state = make_state(lb);
        let s3 = Arc::new(CountingS3::new());
        let bus = Arc::new(DeliveryBus::new().with_s3(s3.clone()));
        let logger = AccessLogger::new(state, bus);
        for _ in 0..MAX_BUFFER_LINES {
            logger.record(LB_ARN, sample_record());
        }
        // The MAX_BUFFER_LINES-th record triggers an immediate flush
        // before returning, so puts should be 1.
        assert_eq!(s3.puts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn connection_log_uses_separate_target_and_kind() {
        let mut lb = lb_with_access_logs("access-bucket", None);
        lb.attributes
            .insert("connection_logs.s3.enabled".to_string(), "true".to_string());
        lb.attributes.insert(
            "connection_logs.s3.bucket".to_string(),
            "conn-bucket".to_string(),
        );
        let state = make_state(lb);
        let s3 = Arc::new(CountingS3::new());
        let bus = Arc::new(DeliveryBus::new().with_s3(s3.clone()));
        let logger = AccessLogger::new(state, bus);
        let mut rec = sample_record();
        rec.log_type = LogType::Connection;
        logger.record(LB_ARN, rec);
        logger.flush_all();
        assert_eq!(s3.puts.load(Ordering::SeqCst), 1);
        assert_eq!(s3.last_bucket.lock().as_deref(), Some("conn-bucket"));
        let key = s3.last_key.lock().clone().expect("key");
        assert!(key.contains("_conn_"));
    }

    #[test]
    fn key_pattern_matches_aws_layout() {
        let meta = LogMetadata {
            account_id: "123456789012".to_string(),
            region: "us-east-1".to_string(),
            lb_arn: LB_ARN.to_string(),
            lb_id: "abcdef0123456789".to_string(),
            access: None,
            connection: None,
        };
        let key = build_object_key(&meta, Some("my/prefix"), "access");
        assert!(key.starts_with("my/prefix/AWSLogs/123456789012/elasticloadbalancing/us-east-1/"));
        assert!(key.contains("123456789012_elasticloadbalancing_us-east-1_abcdef0123456789_"));
        assert!(key.ends_with(".log.gz"));
    }

    #[test]
    fn key_uses_region_from_arn_not_default() {
        // LB in eu-west-1; bus default is us-east-1. The key should
        // carry the LB's actual region.
        let arn =
            "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/euwest/abc123";
        let mut lb = lb_with_access_logs("eu-bucket", None);
        lb.arn = arn.to_string();
        let mut accounts = Elbv2Accounts::new();
        let st = accounts.get_or_create(ACCOUNT);
        st.load_balancers.insert(arn.to_string(), lb);
        let state = Arc::new(RwLock::new(accounts));
        let s3 = Arc::new(CountingS3::new());
        let bus = Arc::new(DeliveryBus::new().with_s3(s3.clone()));
        let logger = AccessLogger::new(state, bus);
        logger.record(arn, sample_record());
        logger.flush_all();
        let key = s3.last_key.lock().clone().expect("key");
        assert!(
            key.contains("/elasticloadbalancing/eu-west-1/"),
            "key should carry eu-west-1 region: {key}"
        );
        assert!(
            key.contains("_elasticloadbalancing_eu-west-1_"),
            "key filename should carry eu-west-1: {key}"
        );
    }

    #[test]
    fn parse_arn_region_handles_malformed_arns() {
        assert_eq!(
            parse_arn_region("arn:aws:elasticloadbalancing:us-east-2:1:loadbalancer/app/x/y"),
            Some("us-east-2".to_string())
        );
        assert_eq!(parse_arn_region("nope"), None);
        assert_eq!(parse_arn_region("arn:aws:elb::1:lb"), None);
    }
}
