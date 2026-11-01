//! Applying a DB parameter group to the PostgreSQL server that backs an
//! instance.
//!
//! RDS sets a group's values as server configuration. fakecloud does the same
//! with `ALTER SYSTEM` on the running server, so the values live in the data
//! directory's `postgresql.auto.conf`: a reload applies the dynamic ones at
//! once, and the static ones (`shared_preload_libraries`, ...) wait for the
//! next restart, as `pending-reboot` parameters do on RDS.
//!
//! Not every RDS parameter is a PostgreSQL setting. The ones that configure
//! RDS itself (`rds.*`, such as `rds.force_ssl`), `ssl` (fakecloud serves no
//! TLS) and values that are RDS formulas (`{DBInstanceClassMemory/32768}`) are
//! left out.

use crate::state::DbParameterGroup;

/// Settings whose value PostgreSQL parses as a list and quotes element by
/// element in `ALTER SYSTEM`. RDS writes them comma separated
/// (`pg_stat_statements,pg_cron`); passed as one literal they would become a
/// single element named `pg_stat_statements,pg_cron`, so each element is
/// passed as its own literal.
const LIST_QUOTED_SETTINGS: &[&str] = &[
    "local_preload_libraries",
    "search_path",
    "session_preload_libraries",
    "shared_preload_libraries",
    "temp_tablespaces",
];

/// The user-set values of `group` that are PostgreSQL settings, by name.
pub(crate) fn postgres_settings(group: &DbParameterGroup) -> Vec<(String, String)> {
    group
        .parameters
        .iter()
        .filter(|(name, value)| is_postgres_setting(name, value))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

fn is_postgres_setting(name: &str, value: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let rds_only = lower.starts_with("rds.") || lower == "ssl";
    let formula = value.contains('{');
    let valid_name = !name.is_empty()
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.');
    valid_name && !rds_only && !formula
}

/// The `ALTER SYSTEM SET` statement for one setting. `name` has been checked
/// by [`postgres_settings`] to be a plain (possibly dotted) identifier. `None`
/// for an empty list: the setting keeps its default, which the reset that
/// precedes these statements restored.
pub(crate) fn alter_system_set(name: &str, value: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let literals: Vec<String> = if LIST_QUOTED_SETTINGS.contains(&lower.as_str()) {
        value
            .split(',')
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .map(quote_literal)
            .collect()
    } else {
        vec![quote_literal(value)]
    };
    if literals.is_empty() {
        return None;
    }
    Some(format!("ALTER SYSTEM SET {name} = {}", literals.join(", ")))
}

/// A PostgreSQL string literal (standard_conforming_strings is on by default).
pub(crate) fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// A PostgreSQL quoted identifier.
pub(crate) fn quote_ident(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(params: &[(&str, &str)]) -> DbParameterGroup {
        DbParameterGroup {
            db_parameter_group_name: "pg".to_string(),
            db_parameter_group_arn: "arn:aws:rds:us-east-1:123456789012:pg:pg".to_string(),
            db_parameter_group_family: "postgres17".to_string(),
            description: "test".to_string(),
            parameters: params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            parameter_apply_methods: Default::default(),
            tags: Vec::new(),
        }
    }

    #[test]
    fn rds_only_parameters_are_left_out() {
        let settings = postgres_settings(&group(&[
            ("rds.force_ssl", "1"),
            ("ssl", "1"),
            ("shared_buffers", "{DBInstanceClassMemory/32768}"),
            ("shared_preload_libraries", "pg_stat_statements,pg_cron"),
            ("cron.database_name", "app"),
            ("idle_in_transaction_session_timeout", "60000"),
            ("bad name; drop", "1"),
        ]));
        let names: Vec<&str> = settings.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "cron.database_name",
                "idle_in_transaction_session_timeout",
                "shared_preload_libraries"
            ]
        );
    }

    #[test]
    fn list_settings_are_set_element_by_element() {
        assert_eq!(
            alter_system_set("shared_preload_libraries", "pg_stat_statements, pg_cron").unwrap(),
            "ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements', 'pg_cron'"
        );
        assert_eq!(
            alter_system_set("cron.database_name", "app").unwrap(),
            "ALTER SYSTEM SET cron.database_name = 'app'"
        );
        assert_eq!(
            alter_system_set("log_line_prefix", "%t,%p 'x'").unwrap(),
            "ALTER SYSTEM SET log_line_prefix = '%t,%p ''x'''"
        );
        assert_eq!(alter_system_set("shared_preload_libraries", ""), None);
        assert_eq!(quote_ident("ma\"ster"), "\"ma\"\"ster\"");
    }
}
