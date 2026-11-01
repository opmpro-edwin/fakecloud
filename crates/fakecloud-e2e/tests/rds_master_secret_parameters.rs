//! RDS instances whose master password RDS manages in Secrets Manager
//! (`ManageMasterUserPassword`), storage autoscaling's `MaxAllocatedStorage`,
//! and DB parameter groups applied to the PostgreSQL server.

mod helpers;

use std::time::Duration;

use aws_sdk_rds::types::{ApplyMethod, Parameter};
use helpers::TestServer;
use tokio_postgres::NoTls;

fn docker_available() -> bool {
    std::process::Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn require_docker_or_skip(test: &str) -> bool {
    if docker_available() {
        return true;
    }
    if std::env::var("CI").is_ok() {
        panic!("docker is required for {test} in CI");
    }
    eprintln!("skipping {test}: docker is not available");
    false
}

async fn connect(
    instance: &aws_sdk_rds::types::DbInstance,
    user: &str,
    password: &str,
    db_name: &str,
) -> Result<tokio_postgres::Client, tokio_postgres::Error> {
    let endpoint = instance.endpoint().expect("endpoint");
    let mut config = tokio_postgres::Config::new();
    config
        .host(endpoint.address().unwrap())
        .port(endpoint.port().unwrap() as u16)
        .user(user)
        .password(password)
        .dbname(db_name)
        .connect_timeout(Duration::from_secs(5));
    let (client, connection) = config.connect(NoTls).await?;
    tokio::spawn(connection);
    Ok(client)
}

/// Poll until `password` logs in (password changes apply asynchronously).
async fn wait_for_login(
    instance: &aws_sdk_rds::types::DbInstance,
    user: &str,
    password: &str,
    db_name: &str,
) -> tokio_postgres::Client {
    let mut last = None;
    for _ in 0..60 {
        match connect(instance, user, password, db_name).await {
            Ok(client) => return client,
            Err(error) => last = Some(error),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("password never logged in: {last:?}");
}

async fn secret_password(sm: &aws_sdk_secretsmanager::Client, arn: &str) -> (String, String) {
    let value = sm
        .get_secret_value()
        .secret_id(arn)
        .send()
        .await
        .expect("GetSecretValue on the master user secret");
    let json: serde_json::Value = serde_json::from_str(value.secret_string().unwrap()).unwrap();
    (
        json["username"].as_str().unwrap().to_string(),
        json["password"].as_str().unwrap().to_string(),
    )
}

async fn show(client: &tokio_postgres::Client, setting: &str) -> String {
    let rows = client
        .simple_query(&format!("SHOW {setting}"))
        .await
        .unwrap_or_else(|e| panic!("SHOW {setting}: {e}"));
    rows.iter()
        .find_map(|m| match m {
            tokio_postgres::SimpleQueryMessage::Row(row) => row.get(0).map(str::to_string),
            _ => None,
        })
        .unwrap()
}

/// The generated password is in the secret and logs into the database;
/// rotating it and turning management off change the password the database
/// takes, and deleting the instance deletes the secret.
#[tokio::test]
async fn managed_master_password_is_the_database_password() {
    if !require_docker_or_skip("managed_master_password_is_the_database_password") {
        return;
    }
    let server = TestServer::start().await;
    let rds = server.rds_client().await;
    let sm = server.secretsmanager_client().await;

    let created = rds
        .create_db_instance()
        .db_instance_identifier("managed-pw")
        .db_instance_class("db.t3.micro")
        .engine("postgres")
        .engine_version("17")
        .master_username("master")
        .manage_master_user_password(true)
        .db_name("app")
        .allocated_storage(200)
        .max_allocated_storage(1000)
        .send()
        .await
        .expect("create");
    let secret = created
        .db_instance()
        .and_then(|i| i.master_user_secret())
        .expect("MasterUserSecret on create")
        .clone();
    let arn = secret.secret_arn().unwrap().to_string();
    assert!(arn.contains(":secret:rds!db-"), "{arn}");
    assert_eq!(secret.secret_status(), Some("active"));
    assert!(secret.kms_key_id().is_some_and(|k| k.contains(":key/")));

    let instance = helpers::wait_for_db_available(&rds, "managed-pw", 900).await;
    assert_eq!(instance.max_allocated_storage(), Some(1000));
    assert_eq!(
        instance.master_user_secret().and_then(|s| s.secret_arn()),
        Some(arn.as_str())
    );
    let (user, password) = secret_password(&sm, &arn).await;
    assert_eq!(user, "master");
    let db = wait_for_login(&instance, &user, &password, "app").await;
    db.simple_query("SELECT 1").await.unwrap();

    // Rotation: the secret's new password becomes the database's.
    rds.modify_db_instance()
        .db_instance_identifier("managed-pw")
        .rotate_master_user_password(true)
        .apply_immediately(true)
        .send()
        .await
        .expect("rotate");
    let (_, rotated) = secret_password(&sm, &arn).await;
    assert_ne!(rotated, password);
    wait_for_login(&instance, "master", &rotated, "app").await;

    // Management off: the secret is deleted and MasterUserPassword applies.
    let modified = rds
        .modify_db_instance()
        .db_instance_identifier("managed-pw")
        .manage_master_user_password(false)
        .master_user_password("plain-password-1")
        .send()
        .await
        .expect("unmanage");
    assert!(modified
        .db_instance()
        .and_then(|i| i.master_user_secret())
        .is_none());
    wait_for_login(&instance, "master", "plain-password-1", "app").await;
    assert!(sm.get_secret_value().secret_id(&arn).send().await.is_err());

    // And on again: a new secret with a new password.
    let modified = rds
        .modify_db_instance()
        .db_instance_identifier("managed-pw")
        .manage_master_user_password(true)
        .send()
        .await
        .expect("manage again");
    let arn = modified
        .db_instance()
        .and_then(|i| i.master_user_secret())
        .and_then(|s| s.secret_arn())
        .expect("new secret")
        .to_string();
    let (_, password) = secret_password(&sm, &arn).await;
    wait_for_login(&instance, "master", &password, "app").await;

    rds.delete_db_instance()
        .db_instance_identifier("managed-pw")
        .skip_final_snapshot(true)
        .send()
        .await
        .expect("delete");
    assert!(sm.get_secret_value().secret_id(&arn).send().await.is_err());
}

/// A DB parameter group's PostgreSQL settings run the server: static ones
/// (`shared_preload_libraries`, so `pg_cron` loads and its extension can be
/// created) from creation, dynamic ones as soon as the group changes, and a
/// later static change at the next reboot. RDS-only `rds.*` settings are
/// left out.
#[tokio::test]
async fn parameter_group_settings_run_the_postgres_server() {
    if !require_docker_or_skip("parameter_group_settings_run_the_postgres_server") {
        return;
    }
    let server = TestServer::start().await;
    let rds = server.rds_client().await;
    let param = |name: &str, value: &str, method: ApplyMethod| {
        Parameter::builder()
            .parameter_name(name)
            .parameter_value(value)
            .apply_method(method)
            .build()
    };

    rds.create_db_parameter_group()
        .db_parameter_group_name("pg-cron")
        .db_parameter_group_family("postgres17")
        .description("pg_cron")
        .send()
        .await
        .unwrap();
    rds.modify_db_parameter_group()
        .db_parameter_group_name("pg-cron")
        .parameters(param("rds.force_ssl", "1", ApplyMethod::PendingReboot))
        .parameters(param(
            "shared_preload_libraries",
            "pg_stat_statements,pg_cron",
            ApplyMethod::PendingReboot,
        ))
        .parameters(param(
            "cron.database_name",
            "app",
            ApplyMethod::PendingReboot,
        ))
        .parameters(param(
            "idle_in_transaction_session_timeout",
            "60000",
            ApplyMethod::Immediate,
        ))
        .send()
        .await
        .unwrap();

    rds.create_db_instance()
        .db_instance_identifier("pg-params")
        .db_instance_class("db.t3.micro")
        .engine("postgres")
        .engine_version("17")
        .master_username("master")
        .master_user_password("secret-123")
        .db_name("app")
        .db_parameter_group_name("pg-cron")
        .send()
        .await
        .expect("create");
    let instance = helpers::wait_for_db_available(&rds, "pg-params", 900).await;

    let db = wait_for_login(&instance, "master", "secret-123", "app").await;
    let preload = show(&db, "shared_preload_libraries").await;
    assert!(preload.contains("pg_cron"), "{preload}");
    assert!(preload.contains("pg_stat_statements"), "{preload}");
    assert_eq!(
        show(&db, "idle_in_transaction_session_timeout").await,
        "1min"
    );
    db.simple_query("CREATE EXTENSION pg_cron")
        .await
        .expect("CREATE EXTENSION pg_cron in cron.database_name");
    db.simple_query("SELECT cron.schedule('nightly', '0 3 * * *', 'SELECT 1')")
        .await
        .expect("pg_cron schedules a job");

    // A dynamic setting applies without a reboot.
    rds.modify_db_parameter_group()
        .db_parameter_group_name("pg-cron")
        .parameters(param(
            "idle_in_transaction_session_timeout",
            "30000",
            ApplyMethod::Immediate,
        ))
        .parameters(param("max_connections", "150", ApplyMethod::PendingReboot))
        .send()
        .await
        .unwrap();
    let mut applied = false;
    for _ in 0..40 {
        let db = connect(&instance, "master", "secret-123", "app")
            .await
            .unwrap();
        if show(&db, "idle_in_transaction_session_timeout").await == "30s" {
            applied = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(applied, "dynamic setting never applied");
    // A static one waits for the reboot.
    let db = connect(&instance, "master", "secret-123", "app")
        .await
        .unwrap();
    assert_eq!(show(&db, "max_connections").await, "100");

    rds.reboot_db_instance()
        .db_instance_identifier("pg-params")
        .send()
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let instance = helpers::wait_for_db_available(&rds, "pg-params", 300).await;
    let db = wait_for_login(&instance, "master", "secret-123", "app").await;
    assert_eq!(show(&db, "max_connections").await, "150");
    let preload = show(&db, "shared_preload_libraries").await;
    assert!(preload.contains("pg_cron"), "{preload}");

    rds.delete_db_instance()
        .db_instance_identifier("pg-params")
        .skip_final_snapshot(true)
        .send()
        .await
        .unwrap();
}
