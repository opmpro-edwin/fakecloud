//! Master user passwords that RDS manages in Secrets Manager
//! (`ManageMasterUserPassword`).
//!
//! As on RDS, the instance gets a generated password and a secret named
//! `rds!db-<uuid>` whose value is `{"username": ..., "password": ...}`,
//! encrypted under `MasterUserSecretKmsKeyId` or the account's
//! `aws/secretsmanager` key. The database runs with that password; rotating it
//! or switching management off changes the password in the database too, and
//! deleting the instance deletes the secret.

use std::sync::Arc;

use fakecloud_core::delivery::KmsHook;
use fakecloud_core::service::AwsServiceError;
use fakecloud_persistence::SnapshotHook;
use fakecloud_secretsmanager::managed::{
    create_managed_secret, delete_managed_secret, put_managed_secret_value, ManagedSecret,
};
use fakecloud_secretsmanager::SharedSecretsManagerState;

/// Access to Secrets Manager for the secrets RDS owns.
#[derive(Clone)]
pub(crate) struct MasterSecretStore {
    state: SharedSecretsManagerState,
    kms_hook: Option<Arc<dyn KmsHook>>,
    /// Persists Secrets Manager state after a change (persistent mode).
    snapshot_hook: Option<SnapshotHook>,
}

impl MasterSecretStore {
    pub(crate) fn new(
        state: SharedSecretsManagerState,
        kms_hook: Option<Arc<dyn KmsHook>>,
        snapshot_hook: Option<SnapshotHook>,
    ) -> Self {
        Self {
            state,
            kms_hook,
            snapshot_hook,
        }
    }

    /// The key a master user secret is reported and encrypted under: the
    /// named key's ARN, or the AWS-managed `aws/secretsmanager` key.
    pub(crate) fn kms_key(
        &self,
        named: Option<&str>,
        account_id: &str,
        region: &str,
    ) -> Option<String> {
        fakecloud_core::delivery::kms_key_arn_or_aws_managed(
            self.kms_hook.as_deref(),
            named,
            account_id,
            region,
            "secretsmanager",
        )
    }

    /// Create the master user secret of the instance `instance_arn` and
    /// return its ARN.
    pub(crate) fn create(
        &self,
        account_id: &str,
        region: &str,
        instance_arn: &str,
        username: &str,
        password: &str,
        kms_key_id: Option<&str>,
    ) -> Result<String, AwsServiceError> {
        let name = format!("rds!db-{}", uuid::Uuid::new_v4());
        let description = format!("Secret associated with primary RDS DB instance: {instance_arn}");
        create_managed_secret(
            &self.state,
            self.kms_hook.as_deref(),
            account_id,
            region,
            ManagedSecret {
                name: &name,
                description: &description,
                kms_key_id,
                secret_string: &secret_value(username, password),
                tags: vec![
                    (
                        "aws:rds:primaryDBInstanceArn".to_string(),
                        instance_arn.to_string(),
                    ),
                    (
                        "aws:secretsmanager:owningService".to_string(),
                        "rds".to_string(),
                    ),
                ],
            },
        )
    }

    /// Store a new password as the secret's current value (and move it to
    /// `kms_key_id` when given). Returns whether the secret exists.
    pub(crate) fn put(
        &self,
        account_id: &str,
        region: &str,
        secret_arn: &str,
        username: &str,
        password: &str,
        kms_key_id: Option<&str>,
    ) -> bool {
        put_managed_secret_value(
            &self.state,
            self.kms_hook.as_deref(),
            account_id,
            region,
            secret_arn,
            &secret_value(username, password),
            kms_key_id,
        )
    }

    pub(crate) fn delete(&self, account_id: &str, region: &str, secret_arn: &str) -> bool {
        delete_managed_secret(&self.state, account_id, region, secret_arn)
    }

    /// Write Secrets Manager state through to disk (no-op in memory mode).
    pub(crate) async fn persist(&self) {
        if let Some(hook) = &self.snapshot_hook {
            hook().await;
        }
    }
}

/// The secret value RDS stores: `{"username": ..., "password": ...}`.
pub(crate) fn secret_value(username: &str, password: &str) -> String {
    let quote = |v: &str| serde_json::Value::String(v.to_string()).to_string();
    format!(
        r#"{{"username":{},"password":{}}}"#,
        quote(username),
        quote(password)
    )
}

/// A generated master password: 28 characters of letters, digits and
/// punctuation RDS allows in a master password (never `/`, `"`, `@`, `'`,
/// `\` or a space), so it also survives connection strings unquoted.
pub(crate) fn generate_master_password() -> String {
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&*+-.:;<>?^_~";
    let random: Vec<u8> = (0..2)
        .flat_map(|_| *uuid::Uuid::new_v4().as_bytes())
        .collect();
    random
        .iter()
        .take(28)
        .map(|b| CHARSET[usize::from(*b) % CHARSET.len()] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_passwords_are_long_varied_and_connection_string_safe() {
        let a = generate_master_password();
        let b = generate_master_password();
        assert_eq!(a.chars().count(), 28);
        assert_ne!(a, b);
        assert!(!a.contains(['/', '"', '@', '\'', '\\', ' ']), "{a}");
        assert_eq!(
            secret_value("master", "p\"w"),
            r#"{"username":"master","password":"p\"w"}"#
        );
    }
}
