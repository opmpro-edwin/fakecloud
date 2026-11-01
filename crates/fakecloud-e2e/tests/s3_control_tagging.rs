//! End-to-end tests for S3 Control resource tagging (`TagResource`,
//! `UntagResource`, `ListTagsForResource`) driven through the real
//! `aws-sdk-s3control` client. Terraform's `aws_s3_bucket` refresh calls
//! `ListTagsForResource` on the bucket ARN, so the S3 Control tag set must be
//! the same one `PutBucketTagging` / `GetBucketTagging` read and write.

mod helpers;

use aws_sdk_s3control::types::Tag;
use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::BeforeTransmitInterceptorContextMut;
use aws_smithy_runtime_api::client::interceptors::Intercept;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_types::config_bag::ConfigBag;
use helpers::TestServer;

const ACCOUNT: &str = "000000000000";

/// The SDK prepends `{AccountId}.` to the S3 Control endpoint host, so it
/// addresses `000000000000.s3-control.us-east-1.localhost.localstack.cloud`.
/// Keep that authority as the `Host` header (fakecloud routes S3 Control on
/// it) but connect to the local server directly, so the test needs no DNS.
#[derive(Debug)]
struct ConnectLocally {
    port: u16,
}

impl Intercept for ConnectLocally {
    fn name(&self) -> &'static str {
        "ConnectLocally"
    }

    fn modify_before_transmit(
        &self,
        context: &mut BeforeTransmitInterceptorContextMut<'_>,
        _runtime_components: &RuntimeComponents,
        _cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        let req = context.request_mut();
        let uri = req.uri().to_string();
        let rest = uri
            .split_once("://")
            .map(|(_, rest)| rest)
            .ok_or("request URI has no scheme")?;
        let (authority, path) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, "/"),
        };
        req.headers_mut().insert("host", authority.to_string());
        req.set_uri(format!("http://127.0.0.1:{}{path}", self.port))?;
        Ok(())
    }
}

async fn s3control_client(server: &TestServer) -> aws_sdk_s3control::Client {
    let conf = aws_sdk_s3control::config::Builder::from(&server.aws_config().await)
        .endpoint_url(format!(
            "http://s3-control.us-east-1.localhost.localstack.cloud:{}",
            server.port()
        ))
        .interceptor(ConnectLocally {
            port: server.port(),
        })
        .build();
    aws_sdk_s3control::Client::from_conf(conf)
}

fn tag(key: &str, value: &str) -> Tag {
    Tag::builder().key(key).value(value).build().unwrap()
}

fn sorted(tags: &[Tag]) -> Vec<(String, String)> {
    let mut v: Vec<_> = tags
        .iter()
        .map(|t| (t.key().to_string(), t.value().to_string()))
        .collect();
    v.sort();
    v
}

#[tokio::test]
async fn s3control_tags_on_general_purpose_bucket_arn() {
    let server = TestServer::start().await;
    let s3 = server.s3_client().await;
    let control = s3control_client(&server).await;
    s3.create_bucket()
        .bucket("tagged-bucket")
        .send()
        .await
        .unwrap();
    let arn = "arn:aws:s3:::tagged-bucket";

    // A bucket with no tags lists an empty set (not NoSuchTagSet).
    let listed = control
        .list_tags_for_resource()
        .account_id(ACCOUNT)
        .resource_arn(arn)
        .send()
        .await
        .unwrap();
    assert!(listed.tags().is_empty(), "{listed:?}");

    control
        .tag_resource()
        .account_id(ACCOUNT)
        .resource_arn(arn)
        .tags(tag("env", "test"))
        .tags(tag("team", "core"))
        .send()
        .await
        .unwrap();

    // Shared with GetBucketTagging.
    let got = s3
        .get_bucket_tagging()
        .bucket("tagged-bucket")
        .send()
        .await
        .unwrap();
    let mut via_s3: Vec<_> = got
        .tag_set()
        .iter()
        .map(|t| (t.key().to_string(), t.value().to_string()))
        .collect();
    via_s3.sort();
    assert_eq!(
        via_s3,
        vec![
            ("env".to_string(), "test".to_string()),
            ("team".to_string(), "core".to_string())
        ]
    );

    // TagResource merges: overwrite one key, add another, keep the third.
    control
        .tag_resource()
        .account_id(ACCOUNT)
        .resource_arn(arn)
        .tags(tag("env", "prod"))
        .tags(tag("owner", "me"))
        .send()
        .await
        .unwrap();
    let listed = control
        .list_tags_for_resource()
        .account_id(ACCOUNT)
        .resource_arn(arn)
        .send()
        .await
        .unwrap();
    assert_eq!(
        sorted(listed.tags()),
        vec![
            ("env".to_string(), "prod".to_string()),
            ("owner".to_string(), "me".to_string()),
            ("team".to_string(), "core".to_string())
        ]
    );

    // UntagResource with several keys (repeated `tagKeys` query param).
    control
        .untag_resource()
        .account_id(ACCOUNT)
        .resource_arn(arn)
        .tag_keys("env")
        .tag_keys("owner")
        .send()
        .await
        .unwrap();
    let listed = control
        .list_tags_for_resource()
        .account_id(ACCOUNT)
        .resource_arn(arn)
        .send()
        .await
        .unwrap();
    assert_eq!(
        sorted(listed.tags()),
        vec![("team".to_string(), "core".to_string())]
    );

    // PutBucketTagging replaces the set; S3 Control sees it.
    s3.put_bucket_tagging()
        .bucket("tagged-bucket")
        .tagging(
            aws_sdk_s3::types::Tagging::builder()
                .tag_set(
                    aws_sdk_s3::types::Tag::builder()
                        .key("from")
                        .value("s3")
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let listed = control
        .list_tags_for_resource()
        .account_id(ACCOUNT)
        .resource_arn(arn)
        .send()
        .await
        .unwrap();
    assert_eq!(
        sorted(listed.tags()),
        vec![("from".to_string(), "s3".to_string())]
    );
}

#[tokio::test]
async fn s3control_tags_on_access_point_arn() {
    let server = TestServer::start().await;
    let s3 = server.s3_client().await;
    let control = s3control_client(&server).await;
    s3.create_bucket()
        .bucket("ap-tag-bucket")
        .send()
        .await
        .unwrap();
    let created = control
        .create_access_point()
        .account_id(ACCOUNT)
        .name("tag-ap")
        .bucket("ap-tag-bucket")
        .send()
        .await
        .unwrap();
    let arn = created.access_point_arn().unwrap().to_string();

    control
        .tag_resource()
        .account_id(ACCOUNT)
        .resource_arn(&arn)
        .tags(tag("k", "v"))
        .send()
        .await
        .unwrap();
    let listed = control
        .list_tags_for_resource()
        .account_id(ACCOUNT)
        .resource_arn(&arn)
        .send()
        .await
        .unwrap();
    assert_eq!(
        sorted(listed.tags()),
        vec![("k".to_string(), "v".to_string())]
    );

    // Access point tags are separate from the bucket's.
    let bucket_tags = control
        .list_tags_for_resource()
        .account_id(ACCOUNT)
        .resource_arn("arn:aws:s3:::ap-tag-bucket")
        .send()
        .await
        .unwrap();
    assert!(bucket_tags.tags().is_empty());

    control
        .untag_resource()
        .account_id(ACCOUNT)
        .resource_arn(&arn)
        .tag_keys("k")
        .send()
        .await
        .unwrap();
    let listed = control
        .list_tags_for_resource()
        .account_id(ACCOUNT)
        .resource_arn(&arn)
        .send()
        .await
        .unwrap();
    assert!(listed.tags().is_empty());
}

#[tokio::test]
async fn s3control_tags_errors() {
    let server = TestServer::start().await;
    let control = s3control_client(&server).await;

    let err = control
        .list_tags_for_resource()
        .account_id(ACCOUNT)
        .resource_arn("arn:aws:s3:::no-such-bucket")
        .send()
        .await
        .unwrap_err();
    let svc = err.into_service_error();
    assert_eq!(svc.meta().code(), Some("NoSuchBucket"), "{svc:?}");

    let err = control
        .tag_resource()
        .account_id(ACCOUNT)
        .resource_arn(format!(
            "arn:aws:s3:us-east-1:{ACCOUNT}:accesspoint/no-such-ap"
        ))
        .tags(tag("k", "v"))
        .send()
        .await
        .unwrap_err();
    let svc = err.into_service_error();
    assert_eq!(svc.meta().code(), Some("NoSuchAccessPoint"), "{svc:?}");

    let err = control
        .list_tags_for_resource()
        .account_id(ACCOUNT)
        .resource_arn("not-an-arn")
        .send()
        .await
        .unwrap_err();
    let svc = err.into_service_error();
    assert_eq!(svc.meta().code(), Some("InvalidRequest"), "{svc:?}");
}

/// With a plain custom endpoint (`AWS_ENDPOINT_URL=http://localhost:<port>`)
/// the SDK sends S3 Control calls to `<account-id>.localhost:<port>` with the
/// account ID in `x-amz-account-id`, no `s3-control` label. fakecloud must
/// route them to S3 Control, not read the account label as a virtual-hosted
/// bucket.
#[tokio::test]
async fn s3control_tags_through_a_custom_endpoint_host() {
    let server = TestServer::start().await;
    let s3 = server.s3_client().await;
    let conf = aws_sdk_s3control::config::Builder::from(&server.aws_config().await)
        .endpoint_url(format!("http://localhost:{}", server.port()))
        .interceptor(ConnectLocally {
            port: server.port(),
        })
        .build();
    let control = aws_sdk_s3control::Client::from_conf(conf);
    s3.create_bucket()
        .bucket("custom-endpoint-bucket")
        .send()
        .await
        .unwrap();
    let arn = "arn:aws:s3:::custom-endpoint-bucket";

    control
        .tag_resource()
        .account_id(ACCOUNT)
        .resource_arn(arn)
        .tags(tag("stack", "local"))
        .send()
        .await
        .expect("TagResource through <account-id>.localhost");
    let listed = control
        .list_tags_for_resource()
        .account_id(ACCOUNT)
        .resource_arn(arn)
        .send()
        .await
        .expect("ListTagsForResource through <account-id>.localhost");
    assert_eq!(
        sorted(listed.tags()),
        vec![("stack".to_string(), "local".to_string())]
    );
    control
        .untag_resource()
        .account_id(ACCOUNT)
        .resource_arn(arn)
        .tag_keys("stack")
        .send()
        .await
        .expect("UntagResource through <account-id>.localhost");
    let listed = control
        .list_tags_for_resource()
        .account_id(ACCOUNT)
        .resource_arn(arn)
        .send()
        .await
        .unwrap();
    assert!(listed.tags().is_empty());
}
