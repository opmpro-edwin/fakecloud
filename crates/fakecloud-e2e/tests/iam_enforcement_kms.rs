//! IAM enforcement for KMS encryption-context condition keys.
//!
//! The account root seeds a key and two data keys bound to different
//! encryption contexts; a role allowed `kms:Decrypt` on that key only under
//! `kms:EncryptionContext:connection` = its own connection may decrypt its
//! own data key and nothing else.

mod helpers;

use aws_credential_types::Credentials;
use aws_sdk_iam::Client as IamClient;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::DataKeySpec;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_sts::Client as StsClient;
use helpers::TestServer;

async fn start_strict() -> TestServer {
    TestServer::start_with_env(&[
        ("FAKECLOUD_IAM", "strict"),
        ("FAKECLOUD_VERIFY_SIGV4", "true"),
    ])
    .await
}

fn config(
    server: &TestServer,
    akid: &str,
    secret: &str,
    token: Option<String>,
) -> aws_config::SdkConfig {
    aws_config::SdkConfig::builder()
        .behavior_version(aws_config::BehaviorVersion::latest())
        .endpoint_url(server.endpoint())
        .region(aws_config::Region::new("us-east-1"))
        .credentials_provider(
            aws_credential_types::provider::SharedCredentialsProvider::new(Credentials::new(
                akid,
                secret,
                token,
                None,
                "fakecloud-kms-iam",
            )),
        )
        .build()
}

fn is_access_denied<E: std::fmt::Debug>(err: &E) -> bool {
    format!("{err:?}").contains("AccessDeniedException")
}

#[tokio::test]
async fn decrypt_is_scoped_by_the_encryption_context_condition() {
    let server = start_strict().await;
    let root = config(&server, "test", "test", None);
    let kms = KmsClient::new(&root);
    let key = kms.create_key().send().await.unwrap();
    let key_arn = key.key_metadata().unwrap().arn().unwrap().to_string();

    // One data key per connection, bound to its encryption context.
    let mut blobs = Vec::new();
    for connection in ["tenant-a", "tenant-b"] {
        let data_key = kms
            .generate_data_key()
            .key_id(&key_arn)
            .key_spec(DataKeySpec::Aes256)
            .encryption_context("connection", connection)
            .send()
            .await
            .unwrap();
        blobs.push((
            data_key.ciphertext_blob().unwrap().clone(),
            data_key.plaintext().unwrap().clone(),
        ));
    }

    // The role's only KMS statement: Decrypt on the key, for its own
    // connection's encryption context.
    let iam = IamClient::new(&root);
    let role_arn = iam
        .create_role()
        .role_name("task-tenant-a")
        .assume_role_policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}"#,
        )
        .send()
        .await
        .unwrap()
        .role()
        .unwrap()
        .arn()
        .to_string();
    iam.put_role_policy()
        .role_name("task-tenant-a")
        .policy_name("connection")
        .policy_document(format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Sid":"DataKey","Effect":"Allow","Action":"kms:Decrypt","Resource":"{key_arn}","Condition":{{"StringEquals":{{"kms:EncryptionContext:connection":"tenant-a"}}}}}}]}}"#
        ))
        .send()
        .await
        .unwrap();
    let creds = StsClient::new(&root)
        .assume_role()
        .role_arn(&role_arn)
        .role_session_name("task")
        .send()
        .await
        .unwrap()
        .credentials()
        .unwrap()
        .clone();
    let task = KmsClient::new(&config(
        &server,
        creds.access_key_id(),
        creds.secret_access_key(),
        Some(creds.session_token().to_string()),
    ));

    let decrypt = |blob: Blob, context: Option<(&str, &str)>| {
        let mut req = task.decrypt().ciphertext_blob(blob);
        if let Some((k, v)) = context {
            req = req.encryption_context(k, v);
        }
        req.send()
    };

    // Its own data key, with its own context: allowed.
    let (a_blob, a_plaintext) = blobs[0].clone();
    let out = decrypt(a_blob.clone(), Some(("connection", "tenant-a")))
        .await
        .expect("own context is allowed");
    assert_eq!(out.plaintext().unwrap(), &a_plaintext);
    assert_eq!(out.key_id(), Some(key_arn.as_str()));

    // The other connection's data key: denied.
    let (b_blob, _) = blobs[1].clone();
    let err = decrypt(b_blob, Some(("connection", "tenant-b")))
        .await
        .unwrap_err();
    assert!(is_access_denied(&err), "{err:?}");

    // Its own data key without the context, or with another value: denied
    // before any decryption.
    let err = decrypt(a_blob.clone(), None).await.unwrap_err();
    assert!(is_access_denied(&err), "{err:?}");
    let err = decrypt(a_blob.clone(), Some(("connection", "TENANT-A")))
        .await
        .unwrap_err();
    assert!(is_access_denied(&err), "{err:?}");

    // The condition key name is case-insensitive, the context key part
    // included: a `Connection` context matches the policy's `connection`
    // condition, so IAM allows it and the ciphertext (bound to `connection`)
    // is then refused as KMS refuses a different context.
    let err = decrypt(a_blob, Some(("Connection", "tenant-a")))
        .await
        .unwrap_err();
    assert!(
        format!("{err:?}").contains("InvalidCiphertextException"),
        "{err:?}"
    );

    // Nothing else is allowed: not even a data key for its own context.
    let err = task
        .generate_data_key()
        .key_id(&key_arn)
        .key_spec(DataKeySpec::Aes256)
        .encryption_context("connection", "tenant-a")
        .send()
        .await
        .unwrap_err();
    assert!(is_access_denied(&err), "{err:?}");
}
