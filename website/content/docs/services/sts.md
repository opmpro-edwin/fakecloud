+++
title = "STS"
description = "AssumeRole, session tokens, federation, caller identity."
weight = 8
+++

fakecloud implements **11 of 11** STS operations at 100% Smithy conformance.

## Supported features

- **AssumeRole** — with session name, duration, policies, external ID; the role's trust policy is evaluated before credentials are issued (Principal, Condition, ExternalId, MFA, service-linked roles)
- **AssumeRoleWithWebIdentity** — OIDC federation; JWT `iss` is matched against a registered `OpenIDConnectProvider` and `aud` against its `client_id_list`; trust policy is enforced with `<provider>:aud` / `<provider>:sub` context keys
- **AssumeRoleWithSAML** — SAML federation; the named provider must exist, audience is matched against the provider metadata's `entityID`, and the trust policy is enforced with `saml:aud` / `saml:iss` context keys
- **GetSessionToken** — temporary credentials
- **GetFederationToken** — federated user credentials
- **GetCallerIdentity** — account ID, user ARN, user ID. As on AWS it needs no permission: under `--iam strict` any caller whose credential resolves gets its identity, even with a policy that explicitly denies `sts:GetCallerIdentity`
- **DecodeAuthorizationMessage** — encoded message decoding
- **GetAccessKeyInfo** — access key metadata

## Protocol

Query protocol. Form-encoded body, `Action` parameter, XML responses.

## Gotchas

- Returned credentials are **dummy placeholders** — fakecloud doesn't validate anything against them. Your test code can use any credentials and fakecloud will accept them.
- `GetCallerIdentity` returns whatever account ID you configured via `--account-id` (default `123456789012`).

## Source

- [`crates/fakecloud-iam`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-iam) — STS lives alongside IAM
- [AWS STS API reference](https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html)
