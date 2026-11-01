//! Keeping the database server of an instance in line with its RDS
//! configuration: the DB parameter group's settings (`crate::db_parameters`)
//! and the master password.

use super::*;

use crate::runtime::{container_engine, RunningDbContainer};

/// Apply a DB parameter group's PostgreSQL settings to a server that just
/// started, and restart it when a static setting waits for a restart, so the
/// group is in effect from the first boot as on RDS. Returns the restarted
/// container, `None` when nothing restarted. Not restarted on Kubernetes,
/// where a restart recreates the Pod and its data directory with it.
pub(crate) async fn apply_postgres_settings_at_boot(
    runtime: &RdsRuntime,
    incarnation: &str,
    engine: &str,
    username: &str,
    password: &str,
    db_name: &str,
    settings: &[(String, String)],
) -> Option<RunningDbContainer> {
    if settings.is_empty() || container_engine(engine) != "postgres" {
        return None;
    }
    match runtime
        .apply_postgres_settings(incarnation, username, password, db_name, settings)
        .await
    {
        Ok(true) if !runtime.is_k8s() => {
            match runtime
                .restart(incarnation, engine, username, password, db_name)
                .await
            {
                Ok(running) => Some(running),
                Err(error) => {
                    tracing::warn!(%error, incarnation, "restart for static DB parameters failed");
                    None
                }
            }
        }
        Ok(_) => None,
        Err(error) => {
            tracing::warn!(%error, incarnation, "applying the DB parameter group failed");
            None
        }
    }
}

/// What a background parameter sync needs about one instance.
struct SyncTarget {
    incarnation: String,
    username: String,
    password: String,
    db_name: String,
    settings: Vec<(String, String)>,
}

impl RdsService {
    /// The PostgreSQL settings of DB parameter group `group` for an instance
    /// of `engine`; empty for other engines or an unknown group.
    pub(crate) fn postgres_settings_for(
        &self,
        account_id: &str,
        engine: &str,
        group: Option<&str>,
    ) -> Vec<(String, String)> {
        if container_engine(engine) != "postgres" {
            return Vec::new();
        }
        let accounts = self.state.read();
        group
            .and_then(|name| accounts.get(account_id)?.parameter_groups.get(name))
            .map(crate::db_parameters::postgres_settings)
            .unwrap_or_default()
    }

    /// Re-apply their DB parameter group to the running PostgreSQL servers of
    /// the available instances `select` picks, in the background. Dynamic
    /// settings take effect at once; static ones wait for the next reboot,
    /// as `pending-reboot` parameters do on RDS.
    pub(crate) fn spawn_parameter_sync(
        &self,
        account_id: &str,
        select: impl Fn(&DbInstance) -> bool,
    ) {
        let Some(runtime) = self.runtime.clone() else {
            return;
        };
        let targets: Vec<SyncTarget> = {
            let accounts = self.state.read();
            let Some(state) = accounts.get(account_id) else {
                return;
            };
            state
                .instances
                .values()
                .filter(|i| {
                    i.db_instance_status == "available"
                        && container_engine(&i.engine) == "postgres"
                        && select(i)
                })
                .map(|i| SyncTarget {
                    incarnation: i.dbi_resource_id.clone(),
                    username: i.master_username.clone(),
                    password: i.master_user_password.clone(),
                    db_name: i
                        .db_name
                        .clone()
                        .unwrap_or_else(|| default_db_name(&i.engine).to_string()),
                    settings: i
                        .db_parameter_group_name
                        .as_deref()
                        .and_then(|name| state.parameter_groups.get(name))
                        .map(crate::db_parameters::postgres_settings)
                        .unwrap_or_default(),
                })
                .collect()
        };
        for target in targets {
            let runtime = runtime.clone();
            tokio::spawn(async move {
                if let Err(error) = runtime
                    .apply_postgres_settings(
                        &target.incarnation,
                        &target.username,
                        &target.password,
                        &target.db_name,
                        &target.settings,
                    )
                    .await
                {
                    tracing::warn!(
                        %error,
                        incarnation = %target.incarnation,
                        "applying the DB parameter group failed"
                    );
                }
            });
        }
    }

    /// Change the master password of `instance`'s running database from
    /// `current_password` to its stored one, in the background (RDS also
    /// applies a new master password asynchronously).
    pub(crate) fn spawn_master_password_change(
        &self,
        instance: &DbInstance,
        current_password: String,
    ) {
        let Some(runtime) = self.runtime.clone() else {
            return;
        };
        let incarnation = instance.dbi_resource_id.clone();
        let engine = instance.engine.clone();
        let username = instance.master_username.clone();
        let new_password = instance.master_user_password.clone();
        let db_name = instance
            .db_name
            .clone()
            .unwrap_or_else(|| default_db_name(&instance.engine).to_string());
        tokio::spawn(async move {
            if let Err(error) = runtime
                .set_master_password(
                    &incarnation,
                    &engine,
                    &username,
                    &current_password,
                    &new_password,
                    &db_name,
                )
                .await
            {
                tracing::error!(%error, %incarnation, "changing the master password failed");
            }
        });
    }
}
