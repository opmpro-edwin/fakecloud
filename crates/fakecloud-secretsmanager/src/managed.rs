//! Secrets that another service creates and owns on the caller's behalf, such
//! as the master user secret RDS keeps for a DB instance with
//! `ManageMasterUserPassword`.
//!
//! The owning service writes them straight into Secrets Manager state, the way
//! AWS services do through their service-linked access: the secret is an
//! ordinary secret to `DescribeSecret` / `GetSecretValue`, its value is
//! encrypted under its KMS key like one written through `CreateSecret`, and the
//! owning service replaces its value or deletes it as the resource changes.

use std::collections::BTreeMap;

use chrono::Utc;
use fakecloud_core::delivery::KmsHook;
use fakecloud_core::service::AwsServiceError;

use crate::service::encrypt_secret_string;
use crate::state::{Secret, SecretVersion, SharedSecretsManagerState};

/// A secret to create for an owning service.
#[derive(Debug, Clone)]
pub struct ManagedSecret<'a> {
    pub name: &'a str,
    pub description: &'a str,
    /// The key the value is encrypted under, as stored on the secret (an ARN,
    /// key id or alias). `None` leaves the value unencrypted, as a secret
    /// created without a KMS hook is.
    pub kms_key_id: Option<&'a str>,
    pub secret_string: &'a str,
    pub tags: Vec<(String, String)>,
}

/// Create `secret` in `account_id` / `region` and return its ARN. Fails with
/// `ResourceExistsException` when a live secret of that name exists.
pub fn create_managed_secret(
    state: &SharedSecretsManagerState,
    kms_hook: Option<&dyn KmsHook>,
    account_id: &str,
    region: &str,
    secret: ManagedSecret<'_>,
) -> Result<String, AwsServiceError> {
    let now = Utc::now();
    let mut accounts = state.write();
    let regional = accounts.regional_mut(account_id, region);
    regional.clear_name_for_create(secret.name, now)?;
    if regional.secrets.contains_key(secret.name) {
        return Err(AwsServiceError::aws_error(
            http::StatusCode::BAD_REQUEST,
            "ResourceExistsException",
            format!(
                "The operation failed because the secret {} already exists.",
                secret.name
            ),
        ));
    }
    let arn = crate::service::secret_arn(region, account_id, secret.name);
    let version_id = uuid::Uuid::new_v4().to_string();
    let stored = encrypt_secret_string(
        kms_hook,
        account_id,
        region,
        &arn,
        secret.kms_key_id,
        Some(secret.secret_string.to_string()),
    );
    let mut versions = BTreeMap::new();
    versions.insert(
        version_id.clone(),
        SecretVersion {
            version_id: version_id.clone(),
            secret_string: stored,
            secret_binary: None,
            stages: vec!["AWSCURRENT".to_string()],
            created_at: now,
        },
    );
    regional.secrets.insert(
        secret.name.to_string(),
        Secret {
            name: secret.name.to_string(),
            arn: arn.clone(),
            description: Some(secret.description.to_string()),
            kms_key_id: secret.kms_key_id.map(str::to_string),
            versions,
            current_version_id: Some(version_id),
            tags_ever_set: !secret.tags.is_empty(),
            tags: secret.tags,
            deleted: false,
            deletion_date: None,
            created_at: now,
            last_changed_at: now,
            last_accessed_at: None,
            rotation_enabled: None,
            rotation_lambda_arn: None,
            rotation_rules: None,
            last_rotated_at: None,
            resource_policy: None,
            replica_regions: Vec::new(),
            replica_settings: BTreeMap::new(),
            primary_region: None,
        },
    );
    Ok(arn)
}

/// Make `secret_string` the `AWSCURRENT` value of the secret `arn`, the way
/// a rotation does: the old current version becomes `AWSPREVIOUS`. With
/// `kms_key_id` set, the secret moves to that key first. Returns `false`
/// when no live secret has that ARN.
pub fn put_managed_secret_value(
    state: &SharedSecretsManagerState,
    kms_hook: Option<&dyn KmsHook>,
    account_id: &str,
    region: &str,
    arn: &str,
    secret_string: &str,
    kms_key_id: Option<&str>,
) -> bool {
    let now = Utc::now();
    let mut accounts = state.write();
    let regional = accounts.regional_mut(account_id, region);
    let Some(secret) = regional
        .secrets
        .values_mut()
        .find(|s| s.arn == arn && !s.deleted)
    else {
        return false;
    };
    if let Some(key) = kms_key_id {
        secret.kms_key_id = Some(key.to_string());
    }
    let stored = encrypt_secret_string(
        kms_hook,
        account_id,
        region,
        arn,
        secret.kms_key_id.as_deref(),
        Some(secret_string.to_string()),
    );
    for version in secret.versions.values_mut() {
        version
            .stages
            .retain(|s| s != "AWSPREVIOUS" && s != "AWSCURRENT");
    }
    if let Some(previous) = secret
        .current_version_id
        .as_ref()
        .and_then(|id| secret.versions.get_mut(id))
    {
        previous.stages.push("AWSPREVIOUS".to_string());
    }
    // A version with no stage left is deprecated; AWS drops those.
    secret.versions.retain(|_, v| !v.stages.is_empty());
    let version_id = uuid::Uuid::new_v4().to_string();
    secret.versions.insert(
        version_id.clone(),
        SecretVersion {
            version_id: version_id.clone(),
            secret_string: stored,
            secret_binary: None,
            stages: vec!["AWSCURRENT".to_string()],
            created_at: now,
        },
    );
    secret.current_version_id = Some(version_id);
    secret.last_changed_at = now;
    true
}

/// Delete the secret `arn` at once, with no recovery window, as an owning
/// service does when its resource goes away. Returns whether it existed.
pub fn delete_managed_secret(
    state: &SharedSecretsManagerState,
    account_id: &str,
    region: &str,
    arn: &str,
) -> bool {
    let mut accounts = state.write();
    let regional = accounts.regional_mut(account_id, region);
    let before = regional.secrets.len();
    regional.secrets.retain(|_, s| s.arn != arn);
    regional.secrets.len() != before
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared() -> SharedSecretsManagerState {
        std::sync::Arc::new(parking_lot::RwLock::new(
            fakecloud_core::multi_account::MultiRegionState::new("123456789012", "us-east-1", ""),
        ))
    }

    fn current_value(state: &SharedSecretsManagerState, name: &str) -> String {
        let accounts = state.read();
        let secret = &accounts
            .regional("123456789012", "us-east-1")
            .unwrap()
            .secrets[name];
        let current = secret.current_version_id.as_ref().unwrap();
        secret.versions[current].secret_string.clone().unwrap()
    }

    #[test]
    fn managed_secret_lifecycle() {
        let state = shared();
        let arn = create_managed_secret(
            &state,
            None,
            "123456789012",
            "us-east-1",
            ManagedSecret {
                name: "rds!db-1234",
                description: "owned",
                kms_key_id: None,
                secret_string: r#"{"username":"u","password":"a"}"#,
                tags: vec![("aws:secretsmanager:owningService".into(), "rds".into())],
            },
        )
        .unwrap();
        assert!(arn.contains(":secret:rds!db-1234-"), "{arn}");
        assert_eq!(
            current_value(&state, "rds!db-1234"),
            r#"{"username":"u","password":"a"}"#
        );

        // A second create of the same name is refused.
        let err = create_managed_secret(
            &state,
            None,
            "123456789012",
            "us-east-1",
            ManagedSecret {
                name: "rds!db-1234",
                description: "owned",
                kms_key_id: None,
                secret_string: "{}",
                tags: Vec::new(),
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), "ResourceExistsException");

        assert!(put_managed_secret_value(
            &state,
            None,
            "123456789012",
            "us-east-1",
            &arn,
            r#"{"username":"u","password":"b"}"#,
            Some("alias/other"),
        ));
        assert_eq!(
            current_value(&state, "rds!db-1234"),
            r#"{"username":"u","password":"b"}"#
        );
        {
            let accounts = state.read();
            let secret = &accounts
                .regional("123456789012", "us-east-1")
                .unwrap()
                .secrets["rds!db-1234"];
            assert_eq!(secret.kms_key_id.as_deref(), Some("alias/other"));
            assert_eq!(secret.versions.len(), 2);
            assert!(secret
                .versions
                .values()
                .any(|v| v.stages == vec!["AWSPREVIOUS".to_string()]));
        }

        assert!(delete_managed_secret(
            &state,
            "123456789012",
            "us-east-1",
            &arn
        ));
        assert!(!delete_managed_secret(
            &state,
            "123456789012",
            "us-east-1",
            &arn
        ));
        assert!(!put_managed_secret_value(
            &state,
            None,
            "123456789012",
            "us-east-1",
            &arn,
            "{}",
            None
        ));
    }
}
