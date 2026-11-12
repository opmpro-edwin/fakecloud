+++
title = "ECS"
description = "Elastic Container Service — full API: clusters, task definitions, real Fargate-style task execution via Docker, services with rolling deployments, task sets, container instances, ECS Exec."
weight = 22
+++

fakecloud implements Amazon Elastic Container Service (ECS) with full API coverage. 77 operations.

**Status: full API.** Covers clusters, task definitions, real Fargate-style task execution, services with rolling deployments + CODE_DEPLOY blue/green task sets, daemons, ExpressGatewayService, task sets, container instances, capacity providers, attributes, task protection, ECS Exec, placement constraints / strategies, awsvpc ENI binding, and the agent-side `Submit*` / `DiscoverPollEndpoint` surface.

## Supported today (full API)

- **Clusters** — `CreateCluster`, `DescribeClusters`, `DeleteCluster`, `ListClusters`, `UpdateCluster`, `UpdateClusterSettings`, `PutClusterCapacityProviders`
- **Task definitions** — `RegisterTaskDefinition`, `DescribeTaskDefinition`, `DeregisterTaskDefinition`, `DeleteTaskDefinitions`, `ListTaskDefinitions`, `ListTaskDefinitionFamilies`
- **Tasks** — `RunTask`, `StartTask`, `StopTask`, `DescribeTasks`, `ListTasks` with real Fargate-style execution via Docker/Podman
- **Services** — `CreateService`, `UpdateService`, `DeleteService`, `DescribeServices`, `ListServices`, `ListServicesByNamespace` with desired-count enforcement and rolling deployments
- **Service deployments** — `StopServiceDeployment`, `ListServiceDeployments`, `DescribeServiceDeployments`, `DescribeServiceRevisions`
- **Task sets** — `CreateTaskSet`, `UpdateTaskSet`, `DeleteTaskSet`, `DescribeTaskSets`, `UpdateServicePrimaryTaskSet` (EXTERNAL deployment controller)
- **Container instances** — `RegisterContainerInstance`, `DeregisterContainerInstance`, `DescribeContainerInstances`, `ListContainerInstances`, `UpdateContainerAgent`, `UpdateContainerInstancesState`
- **Attributes** — `PutAttributes`, `DeleteAttributes`, `ListAttributes`
- **Capacity providers** — `CreateCapacityProvider`, `DeleteCapacityProvider`, `DescribeCapacityProviders`, `UpdateCapacityProvider`
- **Task protection** — `GetTaskProtection`, `UpdateTaskProtection`
- **ECS Exec** — `ExecuteCommand` starts the command detached in the task's running container (`docker exec` or `podman exec`; run as given rather than through a shell; stopped when the task stops, or after 20 minutes in images that ship `timeout`) and returns the session at once. Output is not streamed: the session has no `streamUrl`, so `aws ecs execute-command --interactive` cannot attach a shell.
- **Agent surface** — `SubmitContainerStateChange`, `SubmitTaskStateChange`, `SubmitAttachmentStateChanges`, `DiscoverPollEndpoint`
- **Tagging** — `TagResource`, `UntagResource`, `ListTagsForResource` (clusters and task definitions)
- **Account settings** — `PutAccountSetting`, `PutAccountSettingDefault`, `DeleteAccountSetting`, `ListAccountSettings`
- **Daemons** — `RegisterDaemonTaskDefinition`, `DescribeDaemonTaskDefinition`, `DeleteDaemonTaskDefinition`, `ListDaemonTaskDefinitions`, `CreateDaemon`, `DescribeDaemon`, `UpdateDaemon`, `DeleteDaemon`, `ListDaemons`, `DescribeDaemonDeployments`, `ListDaemonDeployments`, `DescribeDaemonRevisions`. `CreateDaemon` spawns one task per matching capacity-provider host so the daemon scales with the cluster.
- **Express gateway services** — `CreateExpressGatewayService`, `DescribeExpressGatewayService`, `UpdateExpressGatewayService`, `DeleteExpressGatewayService` (2026 ECS Express deployment controller)

### Services + rolling deployments

`CreateService` spawns tasks to match `desiredCount` under the service, tagging each with `startedBy=ecs-svc/<name>` so the tasks reconcile back to the service. `UpdateService` supports two independent mutations:

- **Scale** — set a new `desiredCount`. The service spawns additional tasks when scaling up and flips excess tasks to `desiredStatus=STOPPED` (runtime kill on the container) when scaling down.
- **Rolling deployment** — pass a new `taskDefinition` (or `forceNewDeployment`). The previous PRIMARY deployment becomes `ACTIVE` and a new `PRIMARY` deployment starts `IN_PROGRESS`. The service scheduler starts new tasks while RUNNING plus PENDING tasks stay within `maximumPercent` (rounded down, default 200) and stops old ones only while healthy tasks stay at `minimumHealthyPercent` (rounded up, default 100). A task is healthy once it is RUNNING, its essential containers with a `healthCheck` report `HEALTHY`, and it is healthy in every target group it is registered in; tasks failing those checks after `healthCheckGracePeriodSeconds` are replaced. When the new deployment runs `desiredCount` healthy tasks and the old ones have drained, it becomes `COMPLETED` (`ECS deployment <id> completed.`), drained deployments become `INACTIVE` and leave `deployments`, and `events` records the completion and the steady state. Per-deployment `runningCount`, `pendingCount` and `failedTasks` follow the tasks.
- **Deployment circuit breaker** — with `deploymentCircuitBreaker.enable`, tasks of the new deployment that stop before they are ever healthy, or are replaced for failing health checks, count in `failedTasks` (reset when a task becomes healthy). At `ceil(0.5 × desiredCount)` clamped to 3–200 the deployment becomes `FAILED` and launches nothing more; with `rollback` a new deployment of the last `COMPLETED` deployment's task definition starts and the service's `taskDefinition` reverts. Without the circuit breaker a failing deployment keeps retrying, backing off after three consecutive start failures (up to 27 minutes), while the minimum healthy bound keeps the old tasks serving. `ECS Deployment State Change` events go to EventBridge.

`DeleteService` refuses while `desiredCount > 0` unless `force=true`; the forced path scales to 0 and stops every running task under the service before removing it.

#### Placement constraints + strategies

Both `RunTask` and `CreateService` honour `placementConstraints[]` (`distinctInstance`, `memberOf <expression>` against container-instance attributes) and `placementStrategy[]` (`random`, `spread` by attribute, `binpack` by `cpu` / `memory`). The scheduler ranks eligible container instances per strategy before launching; tasks fail with `unable to place a task` when no instance satisfies the constraints, matching real ECS.

#### awsvpc networking

Task definitions with `networkMode=awsvpc` get a per-task ENI in the first subnet of `networkConfiguration.awsvpcConfiguration.subnets[]` (from `RunTask`, or the service's network configuration). The attachment is `PRECREATED` with its `subnetId` when the task is created and `ATTACHED` once it starts, with `networkInterfaceId`, `macAddress`, `privateDnsName` and `privateIPv4Address`. In a subnet fakecloud's EC2 knows, the ENI is a real requester-managed network interface (described by the attachment's ARN, carrying the service's security groups) that EC2 creates and allocates the private IP for, skipping the five addresses AWS reserves in every subnet and every address already in use; it appears in `DescribeNetworkInterfaces` while the task runs and is deleted when the task stops. A subnet EC2 doesn't know gets a synthetic ENI with an address from `10.0.0.0/16`. Each task runs on its own container network, and its container ports are published on ephemeral host ports, so tasks never compete for a host port. A load balancer target `<ENI IP>:<containerPort>` is routed to that published port, which is how an ALB in front of an `awsvpc` service reaches its tasks on Docker Desktop, podman and Linux alike, while `DescribeTargetHealth` and `DescribeTasks` keep reporting the ENI IP. On the Kubernetes backend the ENI attaches when the Pod runs and the target routes to the Pod IP.

#### CODE_DEPLOY blue/green task sets

Services declared with `deploymentController.type=CODE_DEPLOY` skip the in-line rolling deployment and require external task-set churn. `CreateTaskSet` registers a non-primary (`BLUE`) set, `UpdateServicePrimaryTaskSet` flips traffic, and the old set is drained on `DeleteTaskSet`. This matches the AWS deployment pattern CodeDeploy uses to drive blue/green cutovers.

Task-definition families track revisions monotonically; `DeleteTaskDefinitions` requires `DeregisterTaskDefinition` first (real AWS behaviour), and the result flips status to `DELETE_IN_PROGRESS`.

## Task execution

`RunTask` records the task synchronously and kicks off a background docker execution per spawned task:

1. `docker pull <image>` (timestamps captured on the task: `pullStartedAt` / `pullStoppedAt`). A transient registry failure (rate limiting such as `429 Too Many Requests`, common for anonymous `public.ecr.aws` pulls from a shared IP; a registry 5xx; a network timeout) is retried with backoff and falls back to a copy of the image already cached locally. A refused pull (the image or tag no longer exists, or access is denied) stops the task with `TaskFailedToStart` even when a stale copy is cached, as does a transient failure with nothing cached.
2. `docker run -d <image>` (container ID recorded on the task's container)
3. Wait for the containers to exit (exit code → `containers[].exitCode`), keeping each container's `healthStatus` current from its Docker health check
4. `docker logs <id>` (captured stdout/stderr stored on the task + exposed via the introspection endpoint)
5. `docker rm <id>` (cleanup)

Exits and health transitions come from one `docker events` stream for all of fakecloud's containers (`die`, `oom`, `health_status`, `destroy`), so running tasks cost nothing while idle and a stopped container is seen at once. The stream reconnects when it ends (a daemon restart), followed by one inspect of every running task's containers, and one batched `docker inspect` every 15 seconds is the safety net for an event that never arrives. Podman reports events in a different shape and is inspected in one batched call every 2 seconds instead.

Environment variables from the task definition are forwarded with `localhost` / `127.0.0.1` rewritten to `host.docker.internal` so containers reach fakecloud itself the same way Lambda does. `ECS_CONTAINER_METADATA_URI` and `ECS_CONTAINER_METADATA_URI_V4` are also injected so SDKs and sidecars that read task metadata work out of the box. As on ECS they point at the agent's link-local address (`http://169.254.170.2/v3/{task_id}` and `http://169.254.170.2/v4/{task_id}`) whenever the container's network routes that address to fakecloud (see [task role credentials](#task-role-credentials)); otherwise they point at fakecloud's task-metadata endpoint (`/_fakecloud/ecs/v3/{task_id}` and `/_fakecloud/ecs/v4/{task_id}`), which serves the same documents. Each container also gets `AWS_ENDPOINT_URL` (fakecloud's endpoint as the container reaches it, e.g. `http://host.docker.internal:4566`, or `FAKECLOUD_K8S_SELF_URL` on the Kubernetes backend) and `AWS_REGION` / `AWS_DEFAULT_REGION` (the task's region, as Fargate sets them), so an unmodified production task definition calls fakecloud instead of real AWS and finds its region without the instance metadata service. A variable the container definition sets itself (in `environment` or `secrets`) is kept as is.

### Container definition fidelity

The runtime translates the following task-definition fields straight into `docker run` flags so containers see the same shape they would on real ECS:

- `linuxParameters.capabilities.add[]` / `drop[]` -> `--cap-add` / `--cap-drop`
- `linuxParameters.initProcessEnabled=true` -> `--init`
- `linuxParameters.sharedMemorySize` -> `--shm-size <MiB>m`
- `linuxParameters.tmpfs[]` -> `--tmpfs <containerPath>:size=<size>,...`
- `ulimits[]` -> `--ulimit <name>=<soft>:<hard>`
- `user` -> `--user`
- `readonlyRootFilesystem=true` -> `--read-only`
- `pseudoTerminal=true` -> `--tty`
- `stopTimeout` -> `--stop-timeout`, and the grace between the stop signal (the image's `STOPSIGNAL`, `SIGTERM` by default) and `SIGKILL` whenever the task stops: StopTask, service scale-in or deployment replacement, an essential container's exit, force-stop. Unset, it is 30 seconds (the Fargate default and the ECS agent's `ECS_CONTAINER_STOP_TIMEOUT` default); a Fargate task's value is held to Fargate's 2-120 seconds. A task's containers stop side by side in the background: StopTask returns at once and the task shows `lastStatus` `STOPPING` until they have exited, then `STOPPED`. The Kubernetes backend sets the Pod's `terminationGracePeriodSeconds` to the longest container stop timeout.
- `volumeConfigurations[]` (per-task EBS attachments) -> volume per task with size, encryption, and FS type recorded on the task's `attachments[]` and bind-mounted at the declared `mountPoint`

### awslogs flush before STOPPED

Before a task transitions to `STOPPED`, the runtime drains any buffered `awslogs` events for that task synchronously, so `GetLogEvents` immediately after a `DescribeTasks` STOPPED response sees every line the container emitted. No probabilistic delay, no flake-prone polling in tests.

Without a container runtime (docker/podman missing), `RunTask` still returns tasks but they immediately transition to `STOPPED` with `stopCode=TaskFailedToStart`. This keeps the API surface shape-correct so tests on CI agents without Docker can still drive the control-plane surface.

### Pulling from fakecloud ECR

Tasks that reference AWS private-ECR URIs (`<account>.dkr.ecr.<region>.amazonaws.com/<repo>:<tag>`) are resolved against fakecloud's own OCI v2 endpoint. The runtime pulls from `127.0.0.1:<port>/<repo>:<tag>`, retags to the AWS URI, and runs the container under the user-visible image name. The pull is performed by the container engine on the host, so it uses loopback even when fakecloud itself runs in a container (`FAKECLOUD_IN_CONTAINER=1`) -- the host alias containers use does not resolve on a Linux host, and Docker Desktop and OrbStack only accept a plain-HTTP registry over loopback. Podman on macOS or Windows pulls inside its machine VM, where only `host.containers.internal` reaches the host, so that is used there. Set `FAKECLOUD_ECR_REGISTRY_HOST` to override the registry host (for example when a containerized fakecloud's port is published under another address). The registry serves plain HTTP. Docker treats `127.0.0.1` as an insecure registry on its own. Podman does not, so under the podman backend (including a `docker` CLI that is really podman, such as the `podman-docker` shim) fakecloud pulls its own registry with `--tls-verify=false` (only for rewritten ECR URIs; upstream registries keep TLS verification).

Same resolution path applies to Lambda functions deployed with `PackageType=Image`: `Code.ImageUri` pointing at a fakecloud ECR URI is pulled and run on invoke.

### awslogs -> CloudWatch Logs

Container definitions that declare the `awslogs` log driver get their captured stdout/stderr forwarded to fakecloud's CloudWatch Logs service:

```json
"logConfiguration": {
  "logDriver": "awslogs",
  "options": {
    "awslogs-group": "/ecs/my-service",
    "awslogs-stream-prefix": "app",
    "awslogs-region": "us-east-1",
    "awslogs-create-group": "true"
  }
}
```

The runtime creates the log group on demand when `awslogs-create-group=true`, creates a stream named `<prefix>/<container-name>/<task-id>`, and appends one `LogEvent` per captured line. The usual fakecloud-logs API (`DescribeLogStreams`, `GetLogEvents`, subscription filters) then sees the container's output with no additional wiring.

### loadBalancers -> ELBv2 RegisterTargets

Services declared with `loadBalancers[]` register each task's primary IP (awsvpc) or container-instance/container-port pair (bridge/host) into the matching ELBv2 target group via `RegisterTargets` when the task transitions to `RUNNING`, and `DeregisterTargets` when it drains. The cutover happens inline as part of the rolling deployment so health-check and target-state assertions on the target group match what real ECS would produce.

### EventBridge task state change events

Task state transitions fire `aws.ecs` / `ECS Task State Change` events on the default EventBridge bus. Event `detail` carries the task ARN, cluster ARN, last status, stop code / reason on STOPPED, and a summary of each container including exit code. Rules matching `source: aws.ecs` receive these events and can route to SQS, SNS, Lambda, Step Functions — the standard target fan-out.

### Task role credentials

Tasks whose task definition (or a `RunTask` `overrides.taskRoleArn`) names a `taskRoleArn` get the credentials the way they do on ECS: every container gets `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/<task-id>`, and `http://169.254.170.2` inside the task's network answers it. An unmodified AWS SDK or CLI in the container resolves the task role through its default credential chain, and so do scripts that call `curl 169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`. Tasks without a task role get no credentials URI, as on AWS. The endpoint returns the container-credentials JSON the ECS agent serves:

```json
{
  "AccessKeyId": "FSIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2026-04-24T12:00:00Z",
  "RoleArn": "arn:aws:iam::123456789012:role/app-task-role"
}
```

The credentials are a real session for the task role, named after the task ID like on AWS: `GetCallerIdentity` returns `arn:aws:sts::<account>:assumed-role/<role>/<task-id>`. They are minted and registered like an `AssumeRole` session, so they verify under `--verify-sigv4` and, under `--iam`, are evaluated against the role's policies. Refetches return the same set until it nears expiry, then a fresh one. When the task stops its credentials are revoked, and the endpoint answers a stopped, unknown or role-less task the way the ECS agent does: HTTP 400 with `{"code":"InvalidIdInRequest","message":"CredentialsV2Request: Credentials not found","HTTPErrorCode":400}`.

A container that falls back to `AWS_CONTAINER_CREDENTIALS_FULL_URI` also gets `AWS_CONTAINER_AUTHORIZATION_TOKEN`, a per-task token the AWS SDKs send as the `Authorization` header. Under `--iam strict` the full-URI endpoint (`/_fakecloud/ecs/creds/<task-id>`) requires it, so knowing a task ID is not enough to obtain its role's credentials there; a request without the task's token gets HTTP 401 `{"code":"AccessDenied","message":"CredentialsV2Request: Authorization token missing or invalid for this task","HTTPErrorCode":401}`. The agent's relative-URI surface (`169.254.170.2/v2/credentials/<task-id>`) takes no token, as on ECS, where only the task's own network reaches that address (and several SDKs never send a token with a relative URI). Under `--iam strict` fakecloud reproduces that boundary instead: on its main port it answers that surface only to peers on a container network (private bridge / pod addresses such as `172.17.0.0/12`, `10.0.0.0/8`, `192.168.0.0/16`, `100.64.0.0/10`, IPv6 ULA / link-local), which is where a task's NAT'd requests come from, and refuses other clients (the host's own loopback, for one) with the same 401. The `--imds-link-local` listener is unaffected. In the default and `soft` modes the token is not required. The introspection SDKs' task-credentials helpers call the full-URI endpoint without a token, so under `--iam strict` they receive that 401.

How `169.254.170.2` reaches fakecloud: before a task-role container starts, its network namespace gets a NAT rule (nftables, or iptables) that sends `169.254.170.2:80` to fakecloud's listener, which serves the agent's `/v2/credentials/<task-id>` path and the `/v3/<task-id>` / `/v4/<task-id>` task-metadata paths to requests addressed to that host. Nothing listens on port 80 inside the task, so the app keeps every port to itself.

- **Network modes:** `bridge`, `host` and `awsvpc` tasks all get the route (fakecloud's Docker backend emulates `host` on a bridge whose published ports are the task's host ports, never in the host's own namespace). A `none`-mode task has no network, so as on ECS it gets the relative URI with nothing reachable behind it.
- **Docker / Podman:** a small holder container (the counterpart of the ECS agent's pause container), started with `NET_ADMIN`, owns each task-role container's network namespace (and, with `--dns`, every task container's; see [VPC networking](#vpc-networking-dns-and-load-balancers)). It carries the container's network settings (task network, published ports, host alias, `net.*` sysctls), installs the rule with `NET_ADMIN`, and the app container joins it (`--network container:<holder>`), so the rule is in place before the app starts. The holder runs a helper image fakecloud builds once per host (Alpine + `nftables`, tagged `fakecloud-ecs-creds-helper:<hash>`) and is removed with the task.
- **Kubernetes:** a first initContainer (`fakecloud-ecs-creds`, with `NET_ADMIN`) installs the rule in the Pod's network namespace, pointed at `FAKECLOUD_K8S_SELF_URL`, and exits before any task container runs. Its default image is `public.ecr.aws/docker/library/alpine:3.20`, which installs `nftables` at start (so the cluster needs egress to the Alpine package mirror, or use the override below).

Set `FAKECLOUD_ECS_CREDS_HELPER_IMAGE` to use your own helper image on either backend (for a private mirror or an air-gapped cluster); it needs `sh`, `getent`, `awk`, and `nft` or `iptables`.

If the namespace can't be set up (no helper image, `NET_ADMIN` refused by the runtime or by a Pod Security admission policy, no NAT support), fakecloud logs a warning and runs the task anyway with `AWS_CONTAINER_CREDENTIALS_FULL_URI=http://host.docker.internal:<port>/_fakecloud/ecs/creds/<task-id>` (the in-cluster fakecloud URL on Kubernetes) instead. Code that fetches that URL directly still gets the credentials, but the AWS SDKs only accept a plain-HTTP full URI on a loopback or link-local host, so an SDK credential chain refuses it.

### VPC networking (DNS and load balancers)

When fakecloud runs its DNS resolver (`--dns`), a task's network on the Docker / Podman backend behaves like the inside of its VPC:

- **DNS.** The task resolves through its VPC's DNS server: the VPC CIDR's base address plus two (`10.40.0.2` for `10.40.0.0/16`, from the task's subnet; `169.254.169.253` for a task without one), which is its resolver, and `169.254.169.253`. DNS (UDP and TCP 53) to either address goes to fakecloud's resolver, so private hosted zones, alias records and load balancer names resolve as in the VPC (see [Route 53](/docs/services/route53/#real-dns-resolver-dns)), and every other name is forwarded upstream, so internet names still resolve. On an `awsvpc` task's network the container's `/etc/resolv.conf` names the engine's embedded DNS (`127.0.0.11`), which forwards to the VPC resolver from inside the task's namespace. Since the engine's own resolver is replaced, `host.docker.internal` is pinned in the task's hosts file (`host-gateway`) where the engine would otherwise have resolved it through DNS (a containerized fakecloud on Docker Desktop). Containers reach the DNS listener at the host alias on the `--dns-addr` port, so it must listen where they can: the host's loopback is enough on Docker Desktop, OrbStack and Podman machine; native Linux Docker needs `0.0.0.0` (or the bridge gateway); a containerized fakecloud publishes the port under the same number, as it does its main port.
- **Load balancers.** A TCP connection to an Application Load Balancer's private address (see [ELBv2 addresses](/docs/services/elbv2/#addresses-and-dns-names)) on one of its listener ports goes to the frontend for that listener: `FAKECLOUD_ELBV2_FRONTEND_HTTPS` / `FAKECLOUD_ELBV2_FRONTEND_HTTP`, else fakecloud's own ALB data plane. Nothing else is rewritten, so traffic between tasks is untouched.

Every task container (not only task-role ones) gets a namespace holder for this, and the holder installs the rules with nftables (an iptables-only helper image gets the credentials rule only, and a warning). ALB addresses come from EC2's ordinary allocator and an ALB can be created, deleted or given a listener at any time, so the load balancer routes are a map in the holder that fakecloud keeps current: it is filled before the task's container starts and rewritten (`docker exec <holder> nft ...`) within about a second of a change, for every running task. A task started before an ALB existed reaches it as soon as the ALB has an active listener.

The Kubernetes backend gets neither (the Pod uses the cluster's DNS).

### Extra CA for TLS

TLS in front of local load balancers is usually terminated by an edge whose certificates come from a local CA that no image trusts. Set `FAKECLOUD_ECS_EXTRA_CA` to the path of that CA's PEM certificate (a path fakecloud reads; in a container, mount it there) and every task container on the Docker / Podman backend gets:

- `/etc/fakecloud-ecs/ca-bundle.pem`, readable by any user: the image's own system roots (from `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/cert.pem` or `/etc/ssl/ca-bundle.pem`; fakecloud's own when the image has none) followed by the CA. The container is created, the bundle copied in, then the container started, so it is there before the entrypoint runs.
- `SSL_CERT_FILE=/etc/fakecloud-ecs/ca-bundle.pem`, unless the task definition sets `SSL_CERT_FILE`. OpenSSL-based clients (curl, Python's `ssl`, Ruby, PHP) and Go read it. Some read another variable first or instead, which the task definition can point at the same path: curl prefers `CURL_CA_BUNDLE` (which some images set, `curlimages/curl` among them), Python `requests` reads `REQUESTS_CA_BUNDLE`, Node.js `NODE_EXTRA_CA_CERTS`. The JVM uses its own trust store.

The file is read at each task start: when it is missing or not PEM, a warning is logged and the task starts without the bundle.

`RegisterTaskDefinition` (and `RunTask` role overrides, and CloudFormation `AWS::ECS::TaskDefinition`) refuses a `taskRoleArn` or `executionRoleArn` whose trust policy does not let `ecs-tasks.amazonaws.com` assume it with ECS's `ClientException` ("ECS was unable to assume the role '...' that was provided for this task. ..."). Under `--iam strict` a role from another account is refused the same way; `--iam soft` logs it to the IAM audit target and allows it.

### Volumes + mount points

Task-definition `volumes[]` and per-container `mountPoints[]` translate into real `docker run -v` flags so containers see actual files at the paths they expect. Supported volume kinds:

- **Host bind** — `volume.host.sourcePath` is bind-mounted directly. A file written by the container shows up on the host path after the task stops.
- **EFS** — `efsVolumeConfiguration.fileSystemId` resolves to a host-side stub directory under `/tmp/fakecloud/efs/<filesystemId>[/<rootDirectory>]`. Multiple tasks targeting the same filesystem id share the stub, so a writer task and a reader task can exchange data the same way they would on real EFS.
- **FSx for Windows** — `fsxWindowsFileServerVolumeConfiguration.fileSystemId` resolves to an analogous stub under `/tmp/fakecloud/fsx/<filesystemId>/<rootDirectory>`.
- **Docker named volume** — `dockerVolumeConfiguration` passes the volume name through verbatim; docker creates the named volume on first reference.

`mountPoints[].readOnly` is honoured by appending `:ro` to the rendered `-v` flag.

### Secrets injection

Container definitions can pull secrets from SecretsManager or SSM Parameter Store via the standard `secrets[]` field:

```json
"secrets": [
  { "name": "DB_PASSWORD", "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-password-AbCdEf" },
  { "name": "DB_USER",     "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-creds-AbCdEf:username::" },
  { "name": "OLD_TOKEN",   "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:token:value:AWSPREVIOUS:" },
  { "name": "API_KEY",     "valueFrom": "arn:aws:ssm:us-east-1:123456789012:parameter/app/api-key" },
  { "name": "FEATURE",     "valueFrom": "/app/feature-flag:2" }
]
```

The runtime resolves each reference at task start, the way the ECS container agent does, and injects the values as environment variables:

- **Secrets Manager**: `valueFrom` is the secret's full ARN or partial ARN (without the random 6-character suffix), resolved in the account and region the ARN names. Append `:json-key:version-stage:version-id` (all three positions, empty ones unset) to pick a field out of a JSON secret and/or a version by staging label (`AWSCURRENT`, `AWSPREVIOUS`, custom) or version ID. A non-string JSON field is injected the way the agent renders it (`5432`, `true`, `1e+08`). A secret in another account is readable when its resource policy allows the task's account.
- **SSM Parameter Store**: `valueFrom` is a parameter name (in the task's account) or ARN (in the ARN's account; a parameter owned by another account must be shared with a resource policy), optionally with a `:version` or `:label` selector. `SecureString` values are injected decrypted.

A reference that does not resolve (missing secret, version or JSON key, missing parameter, access denied) fails the task with `stopCode=TaskFailedToStart` and a `stoppedReason` in ECS's form, for example `ResourceInitializationError: unable to pull secrets or registry auth: execution resource retrieval failed: unable to retrieve secret from asm: retrieved secret from Secrets Manager did not contain json key password`.

## Protocol

JSON protocol over `POST /`, with `X-Amz-Target: AmazonEC2ContainerServiceV20141113.<Action>`. Request + response bodies are JSON; tags use lowercase `key` / `value` (matches AWS SDK serialization).

## Introspection

Endpoints bypass the public AWS API so tests can assert deterministic state without pagination or role-assumption noise.

| Endpoint | Method | Purpose |
|---|---|---|
| `/_fakecloud/ecs/clusters` | GET | Dump every cluster across all accounts |
| `/_fakecloud/ecs/tasks` | GET | Dump every task; filter with `?cluster=` / `?status=` |
| `/_fakecloud/ecs/tasks/{taskId}` | GET | Single-task deep detail |
| `/_fakecloud/ecs/tasks/{taskId}/logs` | GET | Captured docker stdout/stderr + exit code |
| `/_fakecloud/ecs/tasks/{taskId}/force-stop` | POST | SIGTERM + SIGKILL the running container |
| `/_fakecloud/ecs/tasks/{taskId}/mark-failed` | POST | Flip to STOPPED without killing the container (inject exit code + reason) |
| `/_fakecloud/ecs/events` | GET | Replay the lifecycle event log |
| `/_fakecloud/ecs/metadata/{taskArn}` | GET | Aggregated v4 metadata dump keyed by full task ARN (URL-encode it) |

### Task metadata by ARN

`GET /_fakecloud/ecs/metadata/{taskArn}` returns the same shape a container would see at `ECS_CONTAINER_METADATA_URI_V4`, but addressable from outside the container by full task ARN -- handy when a test holds the `RunTask` response and wants to assert what the in-container SDK metadata loader would observe.

The path segment must be URL-encoded (`arn:aws:ecs:us-east-1:000000000000:task/cluster/<id>` -> `arn%3Aaws%3Aecs%3Aus-east-1%3A000000000000%3Atask%2Fcluster%2F<id>`). SDK helpers (`getEcsTaskMetadata` / `get_task_metadata`) handle the encoding for you.

```json
{
  "task": {
    "cluster": "prod",
    "taskArn": "arn:aws:ecs:us-east-1:000000000000:task/prod/abc123",
    "family": "web",
    "revision": 4,
    "desiredStatus": "RUNNING",
    "knownStatus": "RUNNING",
    "containers": [
      {
        "name": "app",
        "image": "nginx:1.27",
        "imageId": "sha256:...",
        "ports": [{"containerPort": 8080, "hostPort": 32768, "protocol": "tcp"}],
        "labels": {},
        "desiredStatus": "RUNNING",
        "knownStatus": "RUNNING",
        "limits": {"cpu": 0.25, "memory": 512},
        "createdAt": "2026-05-11T10:00:00Z",
        "startedAt": "2026-05-11T10:00:02Z"
      }
    ],
    "pullStartedAt": "2026-05-11T10:00:00Z",
    "pullStoppedAt": "2026-05-11T10:00:01Z",
    "availabilityZone": "us-east-1a",
    "launchType": "FARGATE",
    "vpcId": "vpc-fakecloud",
    "eniId": "eni-..."
  }
}
```

All endpoints are sorted deterministically (by ARN for clusters/tasks, by timestamp for events) so test assertions don't flake on map iteration order.

### Clusters dump

```json
{
  "clusters": [
    {
      "clusterName": "prod",
      "clusterArn": "arn:aws:ecs:us-east-1:111122223333:cluster/prod",
      "status": "ACTIVE",
      "runningTasksCount": 0,
      "pendingTasksCount": 0,
      "activeServicesCount": 0,
      "registeredContainerInstancesCount": 0,
      "capacityProviders": ["FARGATE"],
      "tags": [{"key": "env", "value": "prod"}],
      "createdAt": "2026-04-23T23:00:00+00:00"
    }
  ]
}
```

## SDK usage (testing helper)

The fakecloud client SDKs ship typed wrappers for every introspection endpoint. Use them instead of poking `/_fakecloud/*` paths by hand.

```go
// Go
clusters, _ := fakecloud.New("http://localhost:4566").ECS().GetClusters(ctx)
```

```python
# Python
async with FakeCloud() as fc:
    clusters = await fc.ecs.get_clusters()
```

```typescript
// TypeScript
const fc = new FakeCloud();
const { clusters } = await fc.ecs.getClusters();
```

```rust
// Rust
let fc = FakeCloud::new("http://localhost:4566");
let clusters = fc.ecs().get_clusters().await?;
```

## Source

- [`crates/fakecloud-ecs`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-ecs)
- [AWS ECS API reference](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/Welcome.html)
