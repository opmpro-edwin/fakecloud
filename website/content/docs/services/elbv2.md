+++
title = "Elastic Load Balancing v2"
description = "ELBv2 control plane — Application/Network/Gateway Load Balancer: load balancers, target groups + targets, listeners + rules + certificates, mTLS trust stores, attributes, capacity reservations, resource policies."
weight = 23
+++

fakecloud implements ELBv2 with full control-plane coverage across all three load balancer types: Application (ALB), Network (NLB), and Gateway (GWLB). 51 operations.

**Status: full API.** Covers load balancer CRUD, target groups + targets + health, listeners + rules + certificates, listener/load-balancer/target-group attributes, capacity reservations, mTLS trust stores + revocations, resource policies, IP pools, IP address types, subnets, security groups, SSL policies, and tags.

## Supported today (full API)

- **Load balancers** — `CreateLoadBalancer`, `DescribeLoadBalancers`, `DeleteLoadBalancer`, `SetSubnets`, `SetSecurityGroups`, `SetIpAddressType`, `ModifyIpPools`
- **VPC placement** — a load balancer's `VpcId` and each `AvailabilityZones` entry's `ZoneName` come from the EC2 subnets it is attached to (`SubnetNotFound` for unknown subnets, `InvalidSubnet` when they span VPCs, `InvalidConfigurationRequest` for two subnets in one zone or a pinned `PrivateIPv4Address` outside its subnet). `SubnetMappings` keep `AllocationId` (reporting the Elastic IP's address), `PrivateIPv4Address` and `IPv6Address`. Security groups must exist in the load balancer's VPC (`InvalidSecurityGroup`); an Application Load Balancer created without any gets the VPC's `default` group. `CanonicalHostedZoneId` is the Route 53 zone AWS publishes for Elastic Load Balancing in the region (separate tables for Application and Network Load Balancers). With no subnets the load balancer sits in the default VPC.
- **Load balancer attributes** — `ModifyLoadBalancerAttributes`, `DescribeLoadBalancerAttributes`
- **Capacity reservations** — `ModifyCapacityReservation`, `DescribeCapacityReservation`
- **Target groups** — `CreateTargetGroup`, `DescribeTargetGroups`, `ModifyTargetGroup`, `DeleteTargetGroup` with cross-resource reference checks (rejects delete while a listener or rule still references the target group, including `ForwardConfig.TargetGroups`)
- **Targets** — `RegisterTargets`, `DeregisterTargets`, `DescribeTargetHealth`
- **Target group attributes** — `ModifyTargetGroupAttributes`, `DescribeTargetGroupAttributes`
- **Listeners** — `CreateListener`, `DescribeListeners`, `ModifyListener`, `DeleteListener` (cascades to rules), `DescribeListenerAttributes`, `ModifyListenerAttributes`
- **Listener certificates** — `AddListenerCertificates`, `RemoveListenerCertificates`, `DescribeListenerCertificates`
- **Action configs** — listener default actions and rule actions keep `AuthenticateOidcConfig` (the `ClientSecret` is stored but, as on AWS, never returned), `AuthenticateCognitoConfig`, `JwtValidationConfig`, `ForwardConfig.TargetGroupStickinessConfig`, redirects and fixed responses, and return them from `Describe*`.
- **Listener rules** — `CreateRule`, `DescribeRules`, `ModifyRule`, `DeleteRule`, `SetRulePriorities` with positive-integer priority validation and target-group existence checks on `Actions`
- **mTLS trust stores** — `CreateTrustStore`, `DescribeTrustStores`, `ModifyTrustStore`, `DeleteTrustStore`, `DescribeTrustStoreAssociations`, `DeleteSharedTrustStoreAssociation`, `GetTrustStoreCaCertificatesBundle`
- **Trust store revocations** — `AddTrustStoreRevocations`, `RemoveTrustStoreRevocations`, `DescribeTrustStoreRevocations`, `GetTrustStoreRevocationContent`
- **Resource policies** — `GetResourcePolicy`
- **Tags** — `AddTags`, `RemoveTags`, `DescribeTags` across load balancers, target groups, listeners, rules, and trust stores
- **Limits / SSL policies** — `DescribeAccountLimits` returns AWS-published default limits; `DescribeSSLPolicies` returns predefined ALB security policies with exact protocol + cipher lists

### Validation matches AWS

- Load balancer name is 1-32 chars, alphanumeric or hyphens, no leading hyphen, no `internal-` prefix on `internet-facing` schemes — returns `ValidationError` with the same wire shape.
- `IpAddressType` is restricted to `ipv4`, `dualstack`, `dualstack-without-public-ipv4` — same enum check on `CreateLoadBalancer`, `SetIpAddressType`, and `SetSubnets`.
- Target group name validation, target type enum (`instance`, `ip`, `lambda`, `alb`), health check threshold ranges all match AWS.
- `DeleteTargetGroup` returns `ResourceInUse` when any listener default action or rule action — including those wrapped in `ForwardConfig.TargetGroups` — still references the target group.
- `CreateRule`/`ModifyRule` reject priority values <= 0 with `ValidationError`, and rule actions referencing a non-existent target group return `TargetGroupNotFound`.
- `CreateListener`/`ModifyListener` reject Protocol/Port mismatches per LB type with `ValidationError`. ALB (`application`) accepts only `HTTP`, `HTTPS` on ports 1-65535. NLB (`network`) accepts only `TCP`, `UDP`, `TCP_UDP`, `TLS` on ports 1-65535. GWLB (`gateway`) accepts only `GENEVE` and pins the port to `6081`.
- `ModifyLoadBalancerAttributes` validates `ipv6.enable_prefix_for_source_nat` against the AWS-supported set `true`, `false`, `on`, `off` and rejects anything else with `ValidationError`. The value round-trips verbatim through `DescribeLoadBalancerAttributes`.
- `wafv2:AssociateWebACL`/`DisassociateWebACL`/`GetWebACLForResource` accept either a load balancer ARN or a listener ARN as `ResourceArn` for ELBv2 targets — the listener ARN is normalized to its parent load-balancer ARN server-side so the data plane lookup matches.

### Idempotent creates

`CreateLoadBalancer` and `CreateTargetGroup` are idempotent on name within a single account: a second call with the same name returns the existing resource instead of throwing, matching AWS's documented idempotency behaviour.

## Smoke test

```sh
fakecloud &

# Subnets come from EC2 (here: the default VPC's)
SUBNETS=$(aws --endpoint-url http://localhost:4566 ec2 describe-subnets \
    --filters Name=default-for-az,Values=true \
    --query 'Subnets[0:2].SubnetId' --output text)

# Create an ALB
LB=$(aws --endpoint-url http://localhost:4566 elbv2 create-load-balancer \
    --name web-alb --type application \
    --subnets $SUBNETS \
    --query 'LoadBalancers[0].LoadBalancerArn' --output text)

# Create a target group
TG=$(aws --endpoint-url http://localhost:4566 elbv2 create-target-group \
    --name web-tg --protocol HTTP --port 80 --vpc-id vpc-12345 \
    --target-type instance \
    --query 'TargetGroups[0].TargetGroupArn' --output text)

# Wire the listener -> target group
aws --endpoint-url http://localhost:4566 elbv2 create-listener \
    --load-balancer-arn "$LB" --protocol HTTP --port 80 \
    --default-actions Type=forward,TargetGroupArn=$TG

# Register a target
aws --endpoint-url http://localhost:4566 elbv2 register-targets \
    --target-group-arn "$TG" --targets Id=i-deadbeef,Port=80

# Health starts `initial`; the prober then health-checks the target and flips it
# to `healthy` / `unhealthy` (see Health probes below).
aws --endpoint-url http://localhost:4566 elbv2 describe-target-health \
    --target-group-arn "$TG"
```

## Introspection

The `/_fakecloud/elbv2/*` endpoints let your tests assert directly on the persisted control-plane state without parsing XML responses:

- `GET /_fakecloud/elbv2/load-balancers` — every ALB/NLB/GWLB across every account
- `GET /_fakecloud/elbv2/target-groups` — every target group, including registered targets and current health
- `GET /_fakecloud/elbv2/listeners` — every listener, with port/protocol/SSL policy/default action
- `GET /_fakecloud/elbv2/rules` — every rule, including the default rules AWS auto-creates per listener

Wrapped by the first-party SDKs: `fc.elbv2().getLoadBalancers()` (TS/Java), `fc.elbv2.getLoadBalancers()` (Python), `fc.ELBv2().GetLoadBalancers(ctx)` (Go), `$fc->elbv2()->getLoadBalancers()` (PHP).

## Health probes

A background prober walks every target group with `HealthCheckEnabled=true` and probes each registered target on its `HealthCheckProtocol`/`HealthCheckPort`/`HealthCheckPath` at the configured `HealthCheckIntervalSeconds`. HTTP/HTTPS probes match the configured `Matcher.HttpCode` (e.g. `200`, `200-299`, `200,301,404`); TCP/TLS probes succeed on connect. After `HealthyThresholdCount` consecutive successes a target flips to `healthy`; after `UnhealthyThresholdCount` consecutive failures it flips to `unhealthy`. Newly registered targets start at `initial` until the first probe completes. `DescribeTargetHealth` returns the live state.

Set `FAKECLOUD_ELBV2_DISABLE_HEALTH_PROBES=true` to turn the prober off and revert to the historical default of synthetic `healthy` for every registered target — useful when targets are placeholder IPs that don't actually answer.

## Addresses and DNS names

An Application Load Balancer gets one requester-managed network interface per subnet, created through EC2's own address allocator, as on AWS: `DescribeNetworkInterfaces` lists them with the description `ELB app/<name>/<id>`, the load balancer's security groups, and a private IP from the subnet that no task ENI or other interface in the subnet shares. `SetSubnets` adds and removes interfaces with the subnets, `SetSecurityGroups` updates their groups, and `DeleteLoadBalancer` deletes them. CloudFormation-created ALBs get them too, and load balancers restored from a snapshot without them get them on start.

The `DNSName` has AWS's format, `internal-<name>-<id>.<region>.elb.amazonaws.com` for an internal scheme and `<name>-<id>.<region>.elb.amazonaws.com` for an internet-facing one. With `--dns`, that name, and a Route 53 alias record pointing at it, resolve to the private IPs of the load balancer's interfaces (see [Route 53](/docs/services/route53/#real-dns-resolver-dns)). An internet-facing ALB resolves to its private IPs too: locally there are no public addresses (a deliberate deviation).

Inside an ECS task's or an EC2 instance's network (Docker / Podman, with `--dns`; see [ECS VPC networking](/docs/services/ecs/#vpc-networking-dns-and-load-balancers) and [EC2 VPC networking](/docs/services/ec2/#vpc-networking)) a TCP connection to one of those IPs on a listener port goes to a frontend that serves the listener:

- `HTTPS` / `TLS` listener ports go to `FAKECLOUD_ELBV2_FRONTEND_HTTPS` (`host:port`, resolved inside the task's network), and `HTTP` listener ports to `FAKECLOUD_ELBV2_FRONTEND_HTTP`. The intended frontend is a TLS edge (Caddy, nginx, Traefik) that picks the ALB by SNI / `Host` and proxies to fakecloud's data plane below. The client's `Host` header and SNI are untouched, since only the destination address is rewritten.
- Without a frontend for the protocol, the connection goes to fakecloud's own data plane for the ALB, which serves plain HTTP on the host's loopback. Containers reach that where the host alias reaches the host's loopback: Docker Desktop, OrbStack and Podman machine, with fakecloud running natively. A containerized fakecloud, or native Linux Docker, needs the frontend variables.

Network Load Balancers and Gateway Load Balancers get no interfaces yet.

## Data plane (in-process HTTP routing)

For every ALB whose `state_code == "active"`, fakecloud binds a TCP listener on `127.0.0.1:0` (OS-allocated) and serves HTTP/1.1 requests through the listener-rule chain you configured. Connections are parsed, routed against your rules in priority order (first non-default match wins; otherwise the listener default actions), and dispatched to the action:

- **`forward`** — picks a target group via the action's weighted distribution and a target within it via round-robin over its `healthy` targets, then proxies the request via `reqwest`. When no target is healthy the ALB fails open, as on AWS: requests go round-robin across the `unhealthy` and `initial` targets; `draining` and `unused` targets never take new requests, and a group with nothing else answers `503`. An `HTTPS` target group is reached over TLS without verifying the target's certificate, as an ALB does; an `HTTP` one over plain HTTP. Targets get HTTP/1.1 unless the target group's `ProtocolVersion` is `HTTP2` or `GRPC`, which lets an HTTPS target negotiate HTTP/2. The request carries `X-Forwarded-For` (the connected client's address appended to any chain the client sent), `X-Forwarded-Proto` and `X-Forwarded-Port` (the listener's protocol and port), and `X-Amzn-Trace-Id`. The load balancer's `idle_timeout.timeout_seconds` attribute (default 60) bounds how long the target may stay silent: past it before the target's response headers arrive, or when no connection to the target (TCP connect plus, for an `HTTPS` target group, the TLS handshake) opens within 10 seconds, the client gets `504`; past it after the headers, the connection is closed. The upstream's status, body, and non-hop-by-hop headers are returned to the client. A WebSocket handshake (`GET` with `Connection: Upgrade` and `Upgrade: websocket`) is forwarded with those headers over a connection of its own; once the target answers `101 Switching Protocols`, its answer goes back whole and the client's connection is joined to the target's until either side closes, as an ALB does on HTTP and HTTPS listeners. As on an ALB, an upgraded connection on which no data moves in either direction for the idle timeout is closed on both sides; any traffic (WebSocket pings included) restarts the timer, so an active connection stays open however long it lives. Any other answer to a handshake is returned like a plain response.
- **`fixed-response`** — returns the configured status code, message body, and content type immediately.
- **`redirect`** — emits a 301 (`HTTP_301`) or 302 (`HTTP_302`) with a `Location` header built from `protocol`/`host`/`port`/`path`/`query`, falling back to the request's own host/path when a field is omitted.
- **`authenticate-oidc` / `authenticate-cognito`** — return `501 Not Implemented` with a body identifying the action; treated as next-batch work.

Sticky sessions: when `ForwardConfig.Stickiness.Enabled=true`, the data plane sets an `AWSALB` cookie on the response (with `Max-Age` from `DurationSeconds`) and pins follow-up requests carrying that cookie to the same target as long as it stays healthy. Rule conditions support `host-header`, `path-pattern` (both with `*`/`?` glob wildcards; host-header is case-insensitive), `http-request-method`, `http-header`, `query-string`, and `source-ip` (IPv4 + IPv6 CIDR). Find the bound port via the `boundPort` field on `GET /_fakecloud/elbv2/load-balancers`.

Targets are reached where they actually listen, while every API response keeps the target's AWS identity. An `ip` target registered by an `awsvpc` ECS service is the task's ENI private IP. The data plane and the prober connect to the host port the task's container port was published on, so this works on Docker Desktop, podman and Linux. An `instance` target (`i-...`) is reached through a forwarder fakecloud starts on first use: it publishes the instance's port on the host. Its address on the instance's subnet counts as a member of the load balancer's security groups, so with security-group enforcement on, an instance rule that admits only the load balancer's group admits the load balancer's traffic, as on AWS. ECS bridge-mode tasks and other `ip` targets are reached at their published or literal address.

Set `FAKECLOUD_ELBV2_DISABLE_DATAPLANE=true` to turn off the data plane (the control plane keeps working; useful when you only need to assert API calls).

## Access logs and connection logs

When an ALB has `access_logs.s3.enabled=true` (and/or `connection_logs.s3.enabled=true`) plus the corresponding bucket attribute set (`access_logs.s3.bucket` for access logs, `connection_logs.s3.bucket` for connection logs), the data plane records one log line per served request and one per established connection. Lines are buffered in memory and flushed to S3 either on a 60-second timer or when the buffer hits 1000 records, whichever comes first. The body is gzip-compressed; the object key follows the AWS pattern:

```
<prefix>/AWSLogs/<account>/elasticloadbalancing/<region>/YYYY/MM/DD/<account>_elasticloadbalancing_<region>_<lb-id>_<timestamp>_<ip>_<random>.log.gz
```

The line format approximates the AWS ALB access-log spec: space-delimited fields covering timestamp, ELB name, client `ip:port`, target `ip:port`, processing times, status codes, byte counts, the quoted request line, user-agent, SSL cipher/protocol, target group ARN, trace id, host, chosen cert, matched rule priority, request creation time, actions executed, redirect URL, error reason, target port list, target status code list, classification, and classification reason.

Tests that need deterministic flush timing can `POST /_fakecloud/elbv2/access-logs/flush` to drain every buffered LB synchronously instead of waiting for the periodic flusher.

## Next-batch work items

- **HTTPS/TLS termination.** Listeners with `Protocol=HTTPS` are stored exactly; the in-process bind is HTTP-only for now. ACM cert lookup + `rustls` termination + mTLS trust-store wiring lands in a follow-up.
- **Raw NLB TCP forwarding.** NLB control-plane CRUD is complete; the data-plane TCP byte-copy lands with the TLS work.
- **`authenticate-oidc` / `authenticate-cognito` actions.** Currently respond `501`; bringing OIDC + Cognito flows online ships separately.

## Limitations

- NLB and GWLB data planes are not implemented. Only the ALB data plane (HTTP request matching, forwarding, WebSocket upgrades, fixed-response, redirect, sticky sessions, access logs) is functional.
- HTTPS/TLS termination is not yet implemented. Listeners with `Protocol=HTTPS` are stored but the in-process bind is HTTP-only.
