//! The AWS SDK environment a task container starts with.
//!
//! Fargate gives every container `AWS_REGION` and `AWS_DEFAULT_REGION` (the
//! task's region), and an SDK finds the region there because a task cannot
//! reach the instance metadata service. A task fakecloud runs also needs to
//! call fakecloud rather than real AWS, so it gets `AWS_ENDPOINT_URL` as well:
//! fakecloud's own endpoint as the container reaches it. An unmodified task
//! definition then talks to fakecloud. Variables the container definition
//! sets (in `environment` or `secrets`) always win.

/// Add `AWS_ENDPOINT_URL`, `AWS_REGION` and `AWS_DEFAULT_REGION` to `env`,
/// each unless the container already sets it.
pub(crate) fn push_aws_sdk_env(env: &mut Vec<(String, String)>, endpoint_url: &str, region: &str) {
    for (name, value) in [
        ("AWS_ENDPOINT_URL", endpoint_url),
        ("AWS_REGION", region),
        ("AWS_DEFAULT_REGION", region),
    ] {
        if !env.iter().any(|(existing, _)| existing == name) {
            env.push((name.to_string(), value.to_string()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value<'a>(env: &'a [(String, String)], name: &str) -> Option<&'a str> {
        env.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    #[test]
    fn task_gets_endpoint_and_region_unless_it_sets_them() {
        let mut env = vec![("APP".to_string(), "1".to_string())];
        push_aws_sdk_env(
            &mut env,
            "http://host.docker.internal:4566",
            "ap-southeast-1",
        );
        assert_eq!(
            value(&env, "AWS_ENDPOINT_URL"),
            Some("http://host.docker.internal:4566")
        );
        assert_eq!(value(&env, "AWS_REGION"), Some("ap-southeast-1"));
        assert_eq!(value(&env, "AWS_DEFAULT_REGION"), Some("ap-southeast-1"));

        // The task definition's own values win and are not duplicated.
        let mut env = vec![
            ("AWS_REGION".to_string(), "eu-west-1".to_string()),
            (
                "AWS_ENDPOINT_URL".to_string(),
                "http://proxy:8080".to_string(),
            ),
        ];
        push_aws_sdk_env(
            &mut env,
            "http://host.docker.internal:4566",
            "ap-southeast-1",
        );
        assert_eq!(value(&env, "AWS_REGION"), Some("eu-west-1"));
        assert_eq!(value(&env, "AWS_ENDPOINT_URL"), Some("http://proxy:8080"));
        assert_eq!(value(&env, "AWS_DEFAULT_REGION"), Some("ap-southeast-1"));
        assert_eq!(env.iter().filter(|(k, _)| k == "AWS_REGION").count(), 1);
    }
}
