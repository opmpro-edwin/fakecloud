//! Authentication of the ECR registry API (OCI Distribution, `/v2/...`).
//!
//! `docker login` sends `Authorization: Basic base64("AWS:<password>")`, where
//! the password is the token `GetAuthorizationToken` returned. As on AWS the
//! token is valid for 12 hours and stands for the identity that requested it:
//! the registry serves the token's account, whatever the request says.
//!
//! Under `--verify-sigv4` ([`RegistryAuth::set_verified`]) only such a token, or
//! the server's own runtime credential
//! ([`fakecloud_core::container_net::registry_runtime_basic_credentials`]),
//! authenticates. Without it the registry stays lenient: any `AWS:*` or
//! `test*` user passes, in the account dispatch resolved.

use std::collections::HashMap;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use fakecloud_core::auth::Principal;
use parking_lot::RwLock;

/// How long an issued token authenticates, as on AWS.
pub(crate) const TOKEN_VALIDITY_HOURS: i64 = 12;

/// The identity a `GetAuthorizationToken` token stands for.
#[derive(Debug, Clone)]
pub(crate) struct RegistryToken {
    pub account_id: String,
    pub principal: Option<Principal>,
    pub expires_at: DateTime<Utc>,
}

/// Who a registry request authenticated as.
#[derive(Debug, Clone)]
pub(crate) enum RegistryCaller {
    /// A token this server issued: the request runs as its identity.
    Token(RegistryToken),
    /// fakecloud's own container runtime pulling an image.
    Runtime,
    /// Lenient (verification off) acceptance of any `AWS:*` / `test*` user.
    Unverified,
    /// A SigV4-signed request (verified by dispatch under `--verify-sigv4`).
    Signed,
}

/// Outcome of reading the `Authorization` header.
#[derive(Debug)]
pub(crate) enum BasicCredentials {
    /// No `Authorization` header, or one that is not Basic.
    Absent,
    /// A Basic header whose payload is not base64.
    Malformed,
    Present {
        user: String,
        password: String,
    },
}

/// Parse `Authorization: Basic <base64(user:password)>`; the scheme is
/// case-insensitive (RFC 7617).
pub(crate) fn basic_credentials(header: Option<&str>) -> BasicCredentials {
    let Some(value) = header else {
        return BasicCredentials::Absent;
    };
    let Some(rest) = value
        .get(..6)
        .filter(|scheme| scheme.eq_ignore_ascii_case("basic "))
        .map(|_| &value[6..])
    else {
        return BasicCredentials::Absent;
    };
    let Ok(decoded) = B64.decode(rest.trim().as_bytes()) else {
        return BasicCredentials::Malformed;
    };
    let pair = String::from_utf8_lossy(&decoded);
    let (user, password) = pair.split_once(':').unwrap_or((&pair, ""));
    BasicCredentials::Present {
        user: user.to_string(),
        password: password.to_string(),
    }
}

/// Issued tokens plus the verification mode. Tokens live in memory only.
#[derive(Clone, Default)]
pub(crate) struct RegistryAuth {
    verified: bool,
    tokens: Arc<RwLock<HashMap<String, RegistryToken>>>,
}

impl RegistryAuth {
    pub fn set_verified(&mut self, verified: bool) {
        self.verified = verified;
    }

    /// Record a freshly minted token password for `account_id` / `principal`,
    /// valid until `expires_at`. Expired tokens are swept on the way.
    pub fn issue(
        &self,
        password: &str,
        account_id: &str,
        principal: Option<Principal>,
        expires_at: DateTime<Utc>,
    ) {
        let now = Utc::now();
        let mut tokens = self.tokens.write();
        tokens.retain(|_, t| t.expires_at > now);
        tokens.insert(
            password.to_string(),
            RegistryToken {
                account_id: account_id.to_string(),
                principal,
                expires_at,
            },
        );
    }

    /// The unexpired token behind `password`.
    pub fn token(&self, password: &str, now: DateTime<Utc>) -> Option<RegistryToken> {
        self.tokens
            .read()
            .get(password)
            .filter(|t| t.expires_at > now)
            .cloned()
    }

    /// Authenticate Basic credentials. `None` means unauthenticated (401).
    pub fn authenticate(&self, user: &str, password: &str) -> Option<RegistryCaller> {
        if !self.verified {
            // AWS emits `AWS:<token>`; `test*` is the local dev bypass.
            return (user == "AWS" || user.starts_with("test"))
                .then_some(RegistryCaller::Unverified);
        }
        if user != "AWS" {
            return None;
        }
        let runtime = fakecloud_core::container_net::registry_runtime_basic_credentials();
        if runtime.strip_prefix("AWS:") == Some(password) {
            return Some(RegistryCaller::Runtime);
        }
        self.token(password, Utc::now()).map(RegistryCaller::Token)
    }
}

/// Expiry of a token minted now.
pub(crate) fn token_expiry(now: DateTime<Utc>) -> DateTime<Utc> {
    now + Duration::hours(TOKEN_VALIDITY_HOURS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_scheme_is_case_insensitive() {
        for scheme in ["Basic", "basic", "BASIC"] {
            let header = format!("{scheme} {}", B64.encode("AWS:pw"));
            match basic_credentials(Some(&header)) {
                BasicCredentials::Present { user, password } => {
                    assert_eq!((user.as_str(), password.as_str()), ("AWS", "pw"));
                }
                other => panic!("{scheme}: {other:?}"),
            }
        }
        assert!(matches!(basic_credentials(None), BasicCredentials::Absent));
        assert!(matches!(
            basic_credentials(Some("Bearer x")),
            BasicCredentials::Absent
        ));
        assert!(matches!(
            basic_credentials(Some("Basic !!!")),
            BasicCredentials::Malformed
        ));
    }

    #[test]
    fn lenient_without_verification() {
        let auth = RegistryAuth::default();
        assert!(auth.authenticate("AWS", "anything").is_some());
        assert!(auth.authenticate("testuser", "x").is_some());
        assert!(auth.authenticate("bob", "x").is_none());
    }

    #[test]
    fn verified_accepts_only_issued_unexpired_tokens_and_the_runtime() {
        let mut auth = RegistryAuth::default();
        auth.set_verified(true);
        let now = Utc::now();
        auth.issue("good", "111111111111", None, token_expiry(now));
        auth.issue("old", "111111111111", None, now - Duration::seconds(1));
        match auth.authenticate("AWS", "good") {
            Some(RegistryCaller::Token(t)) => assert_eq!(t.account_id, "111111111111"),
            other => panic!("{other:?}"),
        }
        assert!(auth.authenticate("AWS", "old").is_none(), "expired");
        assert!(auth.authenticate("AWS", "forged").is_none(), "forged");
        assert!(auth.authenticate("test", "good").is_none(), "test* user");
        assert!(auth.authenticate("testuser", "x").is_none(), "test* user");
        let runtime = fakecloud_core::container_net::registry_runtime_basic_credentials();
        let pw = runtime.strip_prefix("AWS:").unwrap();
        assert!(matches!(
            auth.authenticate("AWS", pw),
            Some(RegistryCaller::Runtime)
        ));
        assert!(auth.authenticate("bob", pw).is_none());
    }

    #[test]
    fn token_validity_is_twelve_hours() {
        let now = Utc::now();
        assert_eq!(token_expiry(now) - now, Duration::hours(12));
    }
}
