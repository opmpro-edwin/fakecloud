mod helpers;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aws_sdk_elasticloadbalancingv2::types::{
    Action, ActionTypeEnum, FixedResponseActionConfig, ProtocolEnum, TargetDescription,
    TargetTypeEnum,
};
use helpers::TestServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Tiny HTTP server returning a configurable status + body for every
/// request. The body echoes the path back so tests can verify the
/// data plane forwarded the actual request URI.
struct EchoTarget {
    addr: SocketAddr,
    code: Arc<AtomicU16>,
}

impl EchoTarget {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let code = Arc::new(AtomicU16::new(200));
        let code_for_task = code.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let code = code_for_task.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_string();
                    let c = code.load(Ordering::SeqCst);
                    let body = format!("ECHO {path}");
                    let resp = format!(
                        "HTTP/1.1 {c} OK\r\n\
                         Content-Length: {len}\r\n\
                         Content-Type: text/plain\r\n\
                         Connection: close\r\n\r\n{body}",
                        len = body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        Self { addr, code }
    }

    fn set_code(&self, c: u16) {
        self.code.store(c, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn elbv2_dataplane_forwards_to_target() {
    let server = TestServer::start().await;
    let elbv2 = server.elbv2_client().await;
    let target = EchoTarget::start().await;

    let lb = elbv2
        .create_load_balancer()
        .name("dp-fwd-lb")
        .scheme(aws_sdk_elasticloadbalancingv2::types::LoadBalancerSchemeEnum::Internal)
        .send()
        .await
        .unwrap();
    let lb_arn = lb
        .load_balancers()
        .first()
        .unwrap()
        .load_balancer_arn()
        .unwrap()
        .to_string();

    let tg = elbv2
        .create_target_group()
        .name("dp-fwd-tg")
        .protocol(ProtocolEnum::Http)
        .port(80)
        .target_type(TargetTypeEnum::Ip)
        .health_check_protocol(ProtocolEnum::Http)
        .health_check_path("/")
        .health_check_interval_seconds(5)
        .health_check_timeout_seconds(2)
        .healthy_threshold_count(2)
        .unhealthy_threshold_count(2)
        .send()
        .await
        .unwrap();
    let tg_arn = tg
        .target_groups()
        .first()
        .unwrap()
        .target_group_arn()
        .unwrap()
        .to_string();

    elbv2
        .register_targets()
        .target_group_arn(&tg_arn)
        .targets(
            TargetDescription::builder()
                .id(target.addr.ip().to_string())
                .port(target.addr.port() as i32)
                .build(),
        )
        .send()
        .await
        .unwrap();

    let listener = elbv2
        .create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Http)
        .port(80)
        .default_actions(
            Action::builder()
                .r#type(ActionTypeEnum::Forward)
                .target_group_arn(&tg_arn)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let _ = listener;

    // Wait for the supervisor to bind a port for this LB.
    let port = wait_for_bound_port(&server, &lb_arn, Duration::from_secs(8))
        .await
        .expect("data plane should bind a port for the active LB");

    // Wait for the target to reach `healthy` so the forward action
    // doesn't race with the prober and pick an `initial`-state target
    // that the data plane filters out.
    let became_healthy = wait_for_target_healthy(&elbv2, &tg_arn, Duration::from_secs(10)).await;
    assert!(became_healthy, "target should reach healthy state");

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/foo/bar"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "ECHO /foo/bar");

    target.set_code(503);
    let resp = client
        .get(format!("http://127.0.0.1:{port}/again"))
        .send()
        .await
        .unwrap();
    // 503 is forwarded as-is — the data plane does not synthesize.
    assert_eq!(resp.status().as_u16(), 503);
}

/// A target that accepts WebSocket handshakes and echoes what follows, and
/// answers anything else (the health checks) with 200.
async fn start_websocket_target() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let head = read_head(&mut sock).await.to_ascii_lowercase();
                if head.contains("upgrade: websocket") && head.contains("connection: upgrade") {
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 101 Switching Protocols\r\n\
                              Upgrade: websocket\r\n\
                              Connection: Upgrade\r\n\
                              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                        )
                        .await;
                    let (mut read, mut write) = sock.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                } else {
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                }
            });
        }
    });
    addr
}

/// Reads an HTTP head, up to and including its blank line.
async fn read_head(sock: &mut tokio::net::TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 16 * 1024 {
        match sock.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

#[tokio::test]
async fn elbv2_dataplane_passes_websocket_upgrades() {
    let server = TestServer::start().await;
    let elbv2 = server.elbv2_client().await;
    let target = start_websocket_target().await;

    let lb_arn = elbv2
        .create_load_balancer()
        .name("dp-ws-lb")
        .scheme(aws_sdk_elasticloadbalancingv2::types::LoadBalancerSchemeEnum::Internal)
        .send()
        .await
        .unwrap()
        .load_balancers()
        .first()
        .unwrap()
        .load_balancer_arn()
        .unwrap()
        .to_string();
    let tg_arn = elbv2
        .create_target_group()
        .name("dp-ws-tg")
        .protocol(ProtocolEnum::Http)
        .port(80)
        .target_type(TargetTypeEnum::Ip)
        .health_check_protocol(ProtocolEnum::Http)
        .health_check_path("/")
        .health_check_interval_seconds(5)
        .health_check_timeout_seconds(2)
        .healthy_threshold_count(2)
        .unhealthy_threshold_count(2)
        .send()
        .await
        .unwrap()
        .target_groups()
        .first()
        .unwrap()
        .target_group_arn()
        .unwrap()
        .to_string();
    elbv2
        .register_targets()
        .target_group_arn(&tg_arn)
        .targets(
            TargetDescription::builder()
                .id(target.ip().to_string())
                .port(target.port() as i32)
                .build(),
        )
        .send()
        .await
        .unwrap();
    elbv2
        .create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Http)
        .port(80)
        .default_actions(
            Action::builder()
                .r#type(ActionTypeEnum::Forward)
                .target_group_arn(&tg_arn)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let port = wait_for_bound_port(&server, &lb_arn, Duration::from_secs(8))
        .await
        .expect("data plane should bind a port for the active LB");
    assert!(
        wait_for_target_healthy(&elbv2, &tg_arn, Duration::from_secs(10)).await,
        "target should reach healthy state"
    );

    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    sock.write_all(
        b"GET /socket HTTP/1.1\r\n\
          Host: ws.example\r\n\
          Upgrade: websocket\r\n\
          Connection: Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
          Sec-WebSocket-Version: 13\r\n\r\n",
    )
    .await
    .unwrap();
    let head = read_head(&mut sock).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert!(
        head.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        "the target's accept value comes back: {head}"
    );

    // The connection now carries bytes both ways, framed or not.
    for message in [&b"first"[..], &b"and a second"[..]] {
        sock.write_all(message).await.unwrap();
        let mut echoed = vec![0u8; message.len()];
        tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut echoed))
            .await
            .expect("the echo comes back through the load balancer")
            .unwrap();
        assert_eq!(echoed, message);
    }
}

async fn wait_for_target_healthy(
    elbv2: &aws_sdk_elasticloadbalancingv2::Client,
    tg_arn: &str,
    deadline: Duration,
) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        let resp = elbv2
            .describe_target_health()
            .target_group_arn(tg_arn)
            .send()
            .await
            .unwrap();
        if let Some(d) = resp.target_health_descriptions().first() {
            if let Some(h) = d.target_health() {
                if h.state().map(|s| s.as_str()) == Some("healthy") {
                    return true;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

#[tokio::test]
async fn elbv2_dataplane_fixed_response_action() {
    let server = TestServer::start().await;
    let elbv2 = server.elbv2_client().await;

    let lb = elbv2
        .create_load_balancer()
        .name("dp-fixed-lb")
        .scheme(aws_sdk_elasticloadbalancingv2::types::LoadBalancerSchemeEnum::Internal)
        .send()
        .await
        .unwrap();
    let lb_arn = lb
        .load_balancers()
        .first()
        .unwrap()
        .load_balancer_arn()
        .unwrap()
        .to_string();

    elbv2
        .create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Http)
        .port(80)
        .default_actions(
            Action::builder()
                .r#type(ActionTypeEnum::FixedResponse)
                .fixed_response_config(
                    FixedResponseActionConfig::builder()
                        .status_code("418")
                        .message_body("teapot")
                        .content_type("text/plain")
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();

    let port = wait_for_bound_port(&server, &lb_arn, Duration::from_secs(8))
        .await
        .expect("data plane should bind a port for the active LB");
    let resp = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/anything"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 418);
    assert_eq!(resp.text().await.unwrap(), "teapot");
}

async fn wait_for_bound_port(server: &TestServer, lb_arn: &str, deadline: Duration) -> Option<u16> {
    let url = format!("{}/_fakecloud/elbv2/load-balancers", server.endpoint());
    let client = reqwest::Client::new();
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        if let Ok(r) = client.get(&url).send().await {
            if let Ok(v) = r.json::<serde_json::Value>().await {
                if let Some(arr) = v.get("loadBalancers").and_then(|x| x.as_array()) {
                    for lb in arr {
                        let arn = lb.get("arn").and_then(|x| x.as_str()).unwrap_or("");
                        if arn == lb_arn {
                            if let Some(p) = lb.get("boundPort").and_then(|x| x.as_u64()) {
                                return Some(p as u16);
                            }
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    None
}
