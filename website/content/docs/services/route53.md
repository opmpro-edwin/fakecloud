+++
title = "Route 53"
description = "Route 53 control plane — hosted zones, RRsets, health checks, traffic policies, DNSSEC + KSK, query logging, CIDR collections, VPC associations, reusable delegation sets, geo locations, account limits, tags."
weight = 25
+++

fakecloud implements Amazon Route 53's REST-XML control plane end-to-end: hosted zone lifecycle, resource record sets with the full `ChangeResourceRecordSets` semantics (CREATE/UPSERT/DELETE), change tracking, hosted zone limits, list-by-name pagination, `TestDNSAnswer` synthesis, the full health-check lifecycle, versioned traffic policies with policy instances, DNSSEC signing + key-signing keys, query logging configs, CIDR collections, VPC associations + cross-account authorizations, reusable delegation sets, geo locations, account limits, and tags. 71 operations — the entire Route 53 control plane.

**Status: 100% control-plane coverage.** Batches 1–5 shipped.

## Supported today

- **Hosted Zones** — `CreateHostedZone`, `GetHostedZone`, `DeleteHostedZone`, `ListHostedZones`, `ListHostedZonesByName`, `GetHostedZoneCount`, `UpdateHostedZoneComment`, `UpdateHostedZoneFeatures`, `GetHostedZoneLimit`. `CreateHostedZone` seeds default `SOA` + `NS` records at the zone apex matching real Route 53 behavior, returns synthesized AWS name servers (`ns-2048.awsdns-64.com` + 3 siblings) in a `DelegationSet`, and rejects duplicate `CallerReference` with `HostedZoneAlreadyExists`. Private zones require a `VPC`. `DeleteHostedZone` enforces the `HostedZoneNotEmpty` rule when user-managed records exist. Comment and features are updatable in place.
- **Resource Record Sets** — `ChangeResourceRecordSets` accepts the full `ChangeBatch` shape with multiple `Change` entries and supports `CREATE` (rejects existing), `UPSERT` (replace-or-insert), and `DELETE` (errors on the default SOA/NS apex records). `ListResourceRecordSets` returns all record types with optional `SetIdentifier` for weighted/latency/failover routing. Each successful change emits a tracked `ChangeInfo` whose status is reported as `INSYNC` immediately for deterministic tests.
- **Change tracking** — `GetChange` returns per-batch `ChangeInfo` with the `INSYNC` status, submitted timestamp, and the comment from the originating batch.
- **DNS test** — `TestDNSAnswer` synthesizes an answer from the in-memory record set: it looks up the named record/type in the supplied hosted zone and returns the recorded values inside `<RecordData>` with `ResponseCode = NOERROR`. Resolver IP and EDNS0 client subnet IP are echoed back into the response.
- **Health Checks** — `CreateHealthCheck`, `GetHealthCheck`, `UpdateHealthCheck`, `DeleteHealthCheck`, `ListHealthChecks`, `GetHealthCheckCount`, `GetHealthCheckStatus`, `GetHealthCheckLastFailureReason`, `GetCheckerIpRanges`. Full lifecycle for HTTP/HTTPS/TCP/HTTP_STR_MATCH/HTTPS_STR_MATCH/CALCULATED/CLOUDWATCH_METRIC/RECOVERY_CONTROL types with the documented `HealthCheckConfig` shape (port, path, FQDN, search string, request interval, failure threshold, regions, alarm identifier, child checks, routing-control ARN, etc.). `CreateHealthCheck` rejects duplicate `CallerReference` with `HealthCheckAlreadyExists`. `UpdateHealthCheck` enforces optimistic concurrency via `HealthCheckVersion` (mismatch -> `HealthCheckVersionMismatch`), bumps the version on success, and honors the `ResetElements` list to clear `ChildHealthChecks` / `FullyQualifiedDomainName` / `Regions` / `ResourcePath`. `DeleteHealthCheck` rejects with `HealthCheckInUse` while any record set still references the check via `HealthCheckId`. `GetHealthCheckStatus` returns synthetic per-region observations whose `<Status>` reflects the stored value (`Success: HTTP Status Code 200` by default; `Failure: <reason>` / `Failure: Connection timed out` / `Failure: DNS resolution failed` / `InsufficientDataPoints` / `Unknown` after admin flip). `GetHealthCheckLastFailureReason` surfaces the last reason recorded against the check; empty until one is set. `GetCheckerIpRanges` returns the documented Route 53 health checker CIDRs. The reported status is controllable per-test via `POST /_fakecloud/route53/health-checks/{id}/status` so failover and multi-value routing can be exercised without a live prober.
- **Traffic Policies** — `CreateTrafficPolicy`, `GetTrafficPolicy`, `CreateTrafficPolicyVersion`, `UpdateTrafficPolicyComment`, `DeleteTrafficPolicy`, `ListTrafficPolicies`, `ListTrafficPolicyVersions`. Each policy carries an immutable `Id` and a monotonically increasing `Version`; `CreateTrafficPolicyVersion` keeps every prior version queryable via `GetTrafficPolicy(Id, Version)`. `CreateTrafficPolicy` rejects a duplicate `Name` with `TrafficPolicyAlreadyExists`. `DeleteTrafficPolicy` rejects with `TrafficPolicyInUse` while any traffic policy instance still references that `(Id, Version)`. The `Type` field is inferred from the policy document's `RecordType` JSON key and defaults to `A` when absent.
- **Traffic Policy Instances** — `CreateTrafficPolicyInstance`, `GetTrafficPolicyInstance`, `UpdateTrafficPolicyInstance`, `DeleteTrafficPolicyInstance`, `ListTrafficPolicyInstances`, `ListTrafficPolicyInstancesByHostedZone`, `ListTrafficPolicyInstancesByPolicy`, `GetTrafficPolicyInstanceCount`. `CreateTrafficPolicyInstance` validates the target hosted zone exists, validates the `(TrafficPolicyId, TrafficPolicyVersion)` resolves to a real policy, and rejects a duplicate `(HostedZoneId, Name, Type)` instance with `TrafficPolicyInstanceAlreadyExists`. The instance `State` is reported as `Applied` immediately for deterministic tests — fakecloud does not emulate the real `Creating -> Applied` propagation window.
- **DNSSEC + Key Signing Keys** — `GetDNSSEC`, `EnableHostedZoneDNSSEC`, `DisableHostedZoneDNSSEC`, `CreateKeySigningKey`, `DeleteKeySigningKey`, `ActivateKeySigningKey`, `DeactivateKeySigningKey`. `GetDNSSEC` returns the per-zone `ServeSignature` (`SIGNING`/`NOT_SIGNING`, default `NOT_SIGNING`) plus every KSK attached to the zone. `CreateKeySigningKey` requires `CallerReference`, `HostedZoneId`, `KeyManagementServiceArn`, `Name`, and `Status`; rejects a duplicate `Name` per zone with `KeySigningKeyAlreadyExists`; synthesizes the `KeyTag`/`Flag`/`SigningAlgorithm`/`DigestAlgorithm` fields with the documented `ECDSAP256SHA256`/SHA-256 defaults. `DeleteKeySigningKey` returns `InvalidKeySigningKeyStatus` when the KSK is still `ACTIVE` — flip to `INACTIVE` via `DeactivateKeySigningKey` first. `Enable`/`Disable`/`Activate`/`Deactivate` each emit a tracked `ChangeInfo` (`INSYNC`).
- **Query Logging** — `CreateQueryLoggingConfig`, `GetQueryLoggingConfig`, `DeleteQueryLoggingConfig`, `ListQueryLoggingConfigs`. One config per zone; private zones are rejected with `InvalidInput`; duplicate per zone returns `QueryLoggingConfigAlreadyExists`. Configs persist the `CloudWatchLogsLogGroupArn` round-trip but fakecloud doesn't actually publish DNS query logs (no real DNS resolver runs).
- **CIDR Collections** — `CreateCidrCollection`, `ChangeCidrCollection`, `DeleteCidrCollection`, `ListCidrCollections`, `ListCidrLocations`, `ListCidrBlocks`. `CreateCidrCollection` rejects duplicate `Name` with `CidrCollectionAlreadyExistsException` and synthesizes a real Route 53 ARN. `ChangeCidrCollection` honors `PUT` and `DELETE_IF_EXISTS` change actions, applies the entire batch atomically (any unknown action rolls back), and enforces optimistic concurrency via `CollectionVersion` (`CidrCollectionVersionMismatchException`). `DeleteCidrCollection` returns `CidrCollectionInUseException` while any location still has CIDR blocks.
- **VPC Associations** — `AssociateVPCWithHostedZone`, `DisassociateVPCFromHostedZone`, `CreateVPCAssociationAuthorization`, `DeleteVPCAssociationAuthorization`, `ListVPCAssociationAuthorizations`, `ListHostedZonesByVPC`. Both `Associate`/`Disassociate` validate that the target hosted zone exists; `Associate` rejects a public zone with `PublicZoneVPCAssociation`, and `Disassociate` returns `VPCAssociationNotFound` for a VPC the zone is not associated with and refuses to remove the last remaining VPC with `LastVPCAssociation`. `CreateVPCAssociationAuthorization` records the authorized `(VPCId, VPCRegion)` per zone (idempotent on duplicate), and `Delete` removes a single entry — both reject unknown zones with `NoSuchHostedZone` and unknown authorizations with `VPCAssociationAuthorizationNotFound`. Only the VPC's owner may associate a VPC: when the VPC exists in fakecloud's EC2, its owning account is authoritative and any other caller gets `NotAuthorizedException` (and `CreateHostedZone`, or a stack's `AWS::Route53::HostedZone`, naming another account's VPC fails with `InvalidVPCId`). `AssociateVPCWithHostedZone` against another account's zone also requires that zone owner's prior `CreateVPCAssociationAuthorization` for the VPC (`NotAuthorizedException` otherwise). For a VPC id EC2 does not know, the first account to use an authorization is taken as the VPC's owner and no other account may use it until the zone owner deletes the authorization. The zone owner, the VPC's owner and the account recorded as having associated the VPC with the zone may disassociate it; anyone else gets `NotAuthorizedException`. `ListHostedZonesByVPC` returns the caller's own zones associated with the supplied VPC plus other accounts' zones the caller owns the VPC on or associated it with, each with an `Owner.OwningAccount` block naming the owner.
- **Reusable Delegation Sets** — `CreateReusableDelegationSet`, `GetReusableDelegationSet`, `DeleteReusableDelegationSet`, `ListReusableDelegationSets`, `GetReusableDelegationSetLimit`. Each create synthesizes 4 NS records (the same `awsdns-*` shape as hosted zones) and rejects duplicate `CallerReference` with `DelegationSetAlreadyCreated`. `Delete` is blocked with `DelegationSetInUse` while any hosted zone still references the set. `GetReusableDelegationSetLimit` returns `MAX_ZONES_BY_REUSABLE_DELEGATION_SET` (value 500) with a live `Count` of zones currently using the set.
- **Geo Locations** — `ListGeoLocations`, `GetGeoLocation`. fakecloud ships a representative dataset (the 7 continents, the `*` default fallback, a sample of countries — BR, CA, DE, FR, GB, JP, US — and US subdivisions CA/NY/TX/WA) sufficient for `IsTruncated` + `NextContinentCode`/`NextCountryCode`/`NextSubdivisionCode` pagination. `GetGeoLocation` looks up the exact `(continent, country, subdivision)` triple and returns `NoSuchGeoLocation` when no entry matches.
- **Account Limits** — `GetAccountLimit`. All 5 owner-scoped limit types are honored: `MAX_HEALTH_CHECKS_BY_OWNER` (200), `MAX_HOSTED_ZONES_BY_OWNER` (500), `MAX_REUSABLE_DELEGATION_SETS_BY_OWNER` (100), `MAX_TRAFFIC_POLICIES_BY_OWNER` (50), `MAX_TRAFFIC_POLICY_INSTANCES_BY_OWNER` (5). The `Count` field is computed live from the in-memory state (e.g. `MAX_TRAFFIC_POLICIES_BY_OWNER` reports the distinct policy count, not the version count).
- **Tags** — `ChangeTagsForResource`, `ListTagsForResource`, `ListTagsForResources`. Both supported `ResourceType` values (`healthcheck`, `hostedzone`) round-trip the same tag bag. `Change` accepts `AddTags` (insert or update on key collision) and `RemoveTagKeys` in the same call; missing zones/health-checks return `NoSuchHostedZone`/`NoSuchHealthCheck`. The list responses sort tags by key for deterministic test output. Tags are independent of the hosted zone tag passed at create time and don't count toward `MAX_RRSETS_BY_ZONE`.

### Concurrency semantics

Route 53's wire protocol is REST-XML. There is no `If-Match` / `ETag` enforcement at the wire level for hosted zones — Route 53 itself does not require optimistic concurrency control here, and fakecloud follows the same model.

### Idempotency

`CreateHostedZone` rejects a duplicate `CallerReference` with `HostedZoneAlreadyExists` (matches real Route 53). The error response carries the existing zone's resource record set count. `CallerReference` is unique per account.

### Accounts

Route 53 is global (no region), but every resource belongs to the account that created it, as in AWS. Hosted zones, record sets, changes, health checks, traffic policies and instances, DNSSEC and key-signing keys, query logging configs, CIDR collections, reusable delegation sets and tags are visible to and changeable by their owning account only; another account gets the usual `NoSuch*` error and does not see them in its listings or counts. The exceptions are VPC associations: a VPC's owner sees another account's private zones its VPC is associated with in `ListHostedZonesByVPC` (with the zone's id, name and owning account) and may disassociate its VPC from them. A stack's record sets, DNSSEC and key-signing keys can only use hosted zones in the stack's account; a reference to another account's zone fails the resource. Deleting such a resource left over from a pre-scoping snapshot removes it from the zone's owning account. Hosted zone ids stay unique across all accounts. Resources a CloudFormation stack provisions belong to the stack's account, built exactly as the API builds them (a stack's zone carries the same default `SOA` + `NS` records and name servers). The `--dns` resolver, `/_fakecloud/dns/resolve` and the `/_fakecloud/route53/*` admin endpoints carry no account and find zones and health checks in any account. `POST /_fakecloud/reset/route53/{account_id}` clears one account's Route 53 state. Persistence snapshots written before resources were account-scoped are split by owner on load: zones and health checks a CloudFormation stack created move to the stack's account (taking their record sets, DNSSEC state, key-signing keys, query logging configs, VPC authorizations, traffic policy instances and tags with them), and the rest load into the server's default account (`--account-id`). A traffic policy moves with its instances when all of them land in one account, and otherwise stays in the default account. Since older snapshots did not record which account associated a VPC, the default account keeps the right to list and disassociate the VPCs already associated with a migrated stack zone.

### `ChangeBatch` semantics

The full action set is honored:

- `CREATE`: rejected with `InvalidChangeBatch` if `(Name, Type, SetIdentifier)` already exists.
- `UPSERT`: replaces an existing record set with the same `(Name, Type, SetIdentifier)` tuple, otherwise inserts.
- `DELETE`: rejected with `InvalidChangeBatch` if the target is not found, or if it would remove the default `SOA`/`NS` records at the zone apex.

The default SOA/NS records seeded by `CreateHostedZone` carry the AWS-shaped `awsdns-hostmaster.amazon.com.` mailbox and the synthesized name servers from the delegation set. `DeleteHostedZone` ignores them when checking emptiness.

## Smoke test

```sh
fakecloud &

# Create a hosted zone
ZONE=$(aws --endpoint-url http://localhost:4566 route53 create-hosted-zone \
  --name example.com \
  --caller-reference "$(date +%s)")

ID=$(echo "$ZONE" | jq -r '.HostedZone.Id')

# Add an A record
aws --endpoint-url http://localhost:4566 route53 change-resource-record-sets \
  --hosted-zone-id "$ID" \
  --change-batch '{
    "Changes": [
      {
        "Action": "UPSERT",
        "ResourceRecordSet": {
          "Name": "api.example.com.",
          "Type": "A",
          "TTL": 60,
          "ResourceRecords": [{"Value": "203.0.113.1"}]
        }
      }
    ]
  }'

# List records
aws --endpoint-url http://localhost:4566 route53 list-resource-record-sets --hosted-zone-id "$ID"

# Test DNS resolution
aws --endpoint-url http://localhost:4566 route53 test-dns-answer \
  --hosted-zone-id "${ID#/hostedzone/}" \
  --record-name api.example.com \
  --record-type A
```

## Admin endpoints

- `POST /_fakecloud/route53/health-checks/{id}/status` — flip a stored health check's reported status. `status` is one of `"Success"`, `"Failure"`, `"Timeout"`, `"DnsError"`, `"InsufficientDataPoints"`, `"Unknown"`. The `<Status>` element returned by `GetHealthCheckStatus` mirrors what real Route 53 produces: `"Success: HTTP Status Code 200"` for `Success`, `"Failure: <reason>"` (or canned descriptors `"Failure: Endpoint unreachable"`, `"Failure: Connection timed out"`, `"Failure: DNS resolution failed"` when no `reason` is supplied) for `Failure`/`Timeout`/`DnsError`, and the literal strings `"InsufficientDataPoints"` / `"Unknown"` for those flavours. The `reason` body field is recorded for failure-flavoured statuses (`Failure`, `Timeout`, `DnsError`) and surfaced by `GetHealthCheckLastFailureReason`. A `Success`/`InsufficientDataPoints`/`Unknown` flip preserves the historical reason. Returns `204 No Content` on success and `404 Not Found` for an unknown id. Available in every fakecloud SDK as `route53.setHealthCheckStatus(id, ...)` (or the language-idiomatic equivalent).

## Real DNS resolver (`--dns`)

By default Route 53 stores records but nothing answers a real lookup: `TestDNSAnswer` is a record-set lookup, not a DNS server. Start fakecloud with `--dns` and it also runs an actual DNS resolver (UDP + TCP) that answers `A`/`AAAA`/`CNAME`/`MX`/`TXT`/`NS`/`PTR`/`SPF`/`CAA` straight from the zones and records you created in Route 53. Point a container's resolver at fakecloud and a normal `getaddrinfo`/`dig` lookup resolves to the local target. Route 53 becomes the one source of truth for local service discovery, with no separate dnsmasq or `/etc/hosts` layer.

- Longest-suffix zone match across every account's hosted zones; `CNAME`s are chased into local zones and the resolved address records appended.
- Alias records are answered with their target's records under the queried name, as Route 53 does: an alias to an Application Load Balancer (`AliasTarget.DNSName` its DNS name, with or without the `dualstack.` prefix) answers the private IPs of the load balancer's network interfaces, and an alias to another record in a local zone answers that record's values. Load balancer DNS names (`internal-<name>-<id>.<region>.elb.amazonaws.com`) themselves resolve to the same IPs. Answers synthesized this way carry a 60-second TTL. Alias targets of other kinds (CloudFront, S3 websites, API Gateway) answer nothing yet.
- ECS tasks use it as their VPC's DNS server (see [ECS VPC networking](/docs/services/ecs/#vpc-networking-dns-and-load-balancers)), so private hosted zones and alias records resolve inside a task as they do in a VPC.
- Names in no local zone are forwarded to an upstream resolver (`--dns-upstream`), so a container can point its sole resolver at fakecloud and still reach the internet.
- Binding the default port 53 needs root; pass `--dns-addr 127.0.0.1:15353` (or any high port) for an unprivileged run.

```sh
fakecloud --dns --dns-addr 127.0.0.1:15353 &
# ...create a zone + A record as in the smoke test above...
dig @127.0.0.1 -p 15353 api.example.com A     # -> the record's IP
dig @127.0.0.1 -p 15353 registry-1.docker.io A # -> forwarded upstream
```

See the [DNS resolver guide](/docs/guides/dns/) for the docker-compose recipe.

## Caveats

Without `--dns` there is no actual DNS server: requests against the synthesized name servers don't return live responses, and `TestDNSAnswer` looks up records from the in-memory state and returns them; treat it as a record-set lookup, not a real DNS resolver. (With `--dns`, the same records are answered over real DNS — see above.) fakecloud does not run real health probes: `GetHealthCheckStatus` returns synthesized observations whose status defaults to `Success` and only changes when the admin endpoint above is called. fakecloud also does not actually publish DNS query logs to CloudWatch Logs (no real DNS resolver runs) and ships a representative geo-location dataset rather than the full 200+-country ISO catalog Route 53 supports — sufficient for code paths that page through the catalog, but not exhaustive for every country lookup.
