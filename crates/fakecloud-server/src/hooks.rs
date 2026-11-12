//! Cross-service hook adapters extracted from main.rs by audit-2026-05-19.

use std::sync::Arc;

pub(crate) struct KmsHookAdapter {
    pub(crate) inner: fakecloud_kms::hook::KmsServiceHook,
    /// Shared KMS state, snapshotted after the hook mints an `aws/<service>`
    /// AWS-managed key on first use, so the key survives a restart and the
    /// corresponding ciphertext stays decryptable.
    pub(crate) state: fakecloud_kms::SharedKmsState,
    pub(crate) snapshot_store: std::sync::OnceLock<Arc<dyn fakecloud_persistence::SnapshotStore>>,
}

impl KmsHookAdapter {
    pub(crate) fn new(
        state: fakecloud_kms::SharedKmsState,
        usage: fakecloud_kms::hook::SharedKmsUsageState,
    ) -> Self {
        Self {
            inner: fakecloud_kms::hook::KmsServiceHook::new(state.clone(), usage),
            state,
            snapshot_store: std::sync::OnceLock::new(),
        }
    }

    pub(crate) fn set_snapshot_store(&self, store: Arc<dyn fakecloud_persistence::SnapshotStore>) {
        let _ = self.snapshot_store.set(store);
    }

    fn save_snapshot_blocking(&self, store: &dyn fakecloud_persistence::SnapshotStore) {
        let snapshot = fakecloud_kms::KmsSnapshot {
            schema_version: fakecloud_kms::KMS_SNAPSHOT_SCHEMA_VERSION,
            accounts: Some(self.state.read().clone()),
            state: None,
        };
        match serde_json::to_vec(&snapshot) {
            Ok(bytes) => {
                if let Err(err) = store.save(&bytes) {
                    tracing::error!(%err, "kms hook snapshot save failed");
                }
            }
            Err(err) => tracing::error!(%err, "kms hook snapshot serialize failed"),
        }
    }

    /// Persist KMS state after a key was minted, durably, before the hook
    /// call returns: a restart right after must still find the key (and so
    /// decrypt what was encrypted under it). On a multi-thread Tokio runtime
    /// the blocking serialize + write runs inside `block_in_place`, so the
    /// worker's other tasks move to another thread instead of stalling;
    /// elsewhere it runs directly.
    fn persist_minted_key(&self) {
        let Some(store) = self.snapshot_store.get() else {
            return;
        };
        let multi_thread = tokio::runtime::Handle::try_current()
            .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
        if multi_thread {
            tokio::task::block_in_place(|| self.save_snapshot_blocking(store.as_ref()));
        } else {
            self.save_snapshot_blocking(store.as_ref());
        }
    }

    /// Resolve `key_id`, persisting KMS state when that minted a key.
    fn resolve_and_persist(
        &self,
        account_id: &str,
        region: &str,
        key_id: &str,
        service_principal: &str,
    ) -> Result<String, String> {
        let (arn, minted) = self
            .inner
            .resolve_key_arn_tracked(account_id, region, key_id, service_principal)
            .map_err(|e| e.to_string())?;
        if minted {
            self.persist_minted_key();
        }
        Ok(arn)
    }
}

impl fakecloud_core::delivery::KmsHook for KmsHookAdapter {
    fn encrypt(
        &self,
        account_id: &str,
        region: &str,
        key_id: &str,
        plaintext: &[u8],
        service_principal: &str,
        encryption_context: std::collections::HashMap<String, String>,
    ) -> Result<String, String> {
        // Resolve first (minting and persisting an AWS-managed key on first
        // use), then encrypt under the resolved key.
        let key_arn = self.resolve_and_persist(account_id, region, key_id, service_principal)?;
        self.inner
            .encrypt(
                account_id,
                region,
                &key_arn,
                plaintext,
                service_principal,
                encryption_context,
            )
            .map_err(|e| e.to_string())
    }

    fn decrypt(
        &self,
        account_id: &str,
        ciphertext_b64: &str,
        service_principal: &str,
        encryption_context: std::collections::HashMap<String, String>,
    ) -> Result<Vec<u8>, String> {
        self.inner
            .decrypt(
                account_id,
                ciphertext_b64,
                service_principal,
                encryption_context,
            )
            .map_err(|e| e.to_string())
    }

    fn resolve_key_arn(
        &self,
        account_id: &str,
        region: &str,
        key_id: &str,
        service_principal: &str,
    ) -> Result<String, String> {
        self.resolve_and_persist(account_id, region, key_id, service_principal)
    }

    fn aws_managed_key_arn(
        &self,
        account_id: &str,
        region: &str,
        service: &str,
        service_principal: &str,
    ) -> Result<String, String> {
        let (arn, minted) =
            self.inner
                .aws_managed_key_arn_tracked(account_id, region, service, service_principal);
        if minted {
            self.persist_minted_key();
        }
        Ok(arn)
    }
}

pub(crate) struct SesEmailDispatcher {
    pub(crate) state: fakecloud_ses::SharedSesState,
}

impl fakecloud_core::delivery::EmailDispatcher for SesEmailDispatcher {
    fn send_email(
        &self,
        account_id: &str,
        from: &str,
        to: &str,
        subject: &str,
        body_text: &str,
        body_html: Option<&str>,
    ) {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        state.sent_emails.push(fakecloud_ses::SentEmail {
            message_id: format!("cognito-{}", uuid::Uuid::new_v4()),
            from: from.to_string(),
            to: vec![to.to_string()],
            cc: Vec::new(),
            bcc: Vec::new(),
            subject: Some(subject.to_string()),
            html_body: body_html.map(|s| s.to_string()),
            text_body: Some(body_text.to_string()),
            raw_data: None,
            template_name: None,
            template_data: None,
            dkim_signature: None,
            headers: Vec::new(),
            timestamp: chrono::Utc::now(),
            email_tags: Vec::new(),
            delivery_insights: Vec::new(),
        });
    }
}

/// SES SendEmail dispatcher for cross-service universal targets
/// (EventBridge Scheduler `arn:aws:scheduler:::aws-sdk:sesv2:sendEmail`,
/// EventBridge Rules with SES targets). Distinct from `SesEmailDispatcher`
/// which is the single-recipient primitive Cognito uses — this one
/// preserves multi-recipient + subject + html semantics that real callers
/// pass via the SES API shape.
pub(crate) struct SesSendEmailDispatcherImpl {
    pub(crate) state: fakecloud_ses::SharedSesState,
}

impl fakecloud_core::delivery::SesSendEmailDispatcher for SesSendEmailDispatcherImpl {
    #[allow(clippy::too_many_arguments)]
    fn send_email(
        &self,
        account_id: &str,
        from: &str,
        to: Vec<String>,
        cc: Vec<String>,
        bcc: Vec<String>,
        subject: Option<&str>,
        text_body: Option<&str>,
        html_body: Option<&str>,
    ) -> Result<(), String> {
        if to.is_empty() && cc.is_empty() && bcc.is_empty() {
            return Err("at least one recipient required".to_string());
        }
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        state.sent_emails.push(fakecloud_ses::SentEmail {
            message_id: format!("scheduler-{}", uuid::Uuid::new_v4()),
            from: from.to_string(),
            to,
            cc,
            bcc,
            subject: subject.map(String::from),
            html_body: html_body.map(String::from),
            text_body: text_body.map(String::from),
            raw_data: None,
            template_name: None,
            template_data: None,
            dkim_signature: None,
            headers: Vec::new(),
            timestamp: chrono::Utc::now(),
            email_tags: Vec::new(),
            delivery_insights: Vec::new(),
        });
        Ok(())
    }
}

/// ELBv2 target registration/deregistration from ECS runtime.
pub(crate) struct Elbv2TargetRegistrationImpl {
    pub(crate) state: fakecloud_elbv2::SharedElbv2State,
}

impl fakecloud_core::delivery::Elbv2TargetRegistration for Elbv2TargetRegistrationImpl {
    fn register_targets(
        &self,
        account_id: &str,
        target_group_arn: &str,
        targets: Vec<(String, Option<i64>)>,
    ) {
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(account_id);
        let Some(tg) = st.target_groups.get_mut(target_group_arn) else {
            return;
        };
        for (id, port) in targets {
            // Same (Id, Port) matching as RegisterTargets: bridge/host-mode
            // tasks share one host address and differ only by port.
            tg.register_target(fakecloud_elbv2::TargetDescription::new_registered(
                id,
                port.map(|p| p as i32),
                None,
            ));
        }
    }

    fn deregister_targets(
        &self,
        account_id: &str,
        target_group_arn: &str,
        targets: Vec<(String, Option<i64>)>,
    ) {
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(account_id);
        let Some(tg) = st.target_groups.get_mut(target_group_arn) else {
            return;
        };
        for (id, port) in targets {
            // Same (Id, Port) matching as DeregisterTargets: only this task's
            // port goes, never another task's target on the same address.
            tg.deregister_target(&id, port.map(|p| p as i32));
        }
    }

    fn target_health(
        &self,
        account_id: &str,
        target_group_arn: &str,
        target_id: &str,
        port: Option<i64>,
    ) -> Option<fakecloud_core::delivery::TargetHealthView> {
        let accounts = self.state.read();
        let tg = accounts
            .get(account_id)?
            .target_groups
            .get(target_group_arn)?;
        let port = port.map(|p| p as i32);
        let target = tg
            .targets
            .iter()
            .find(|t| t.id == target_id && (port.is_none() || t.port == port))?;
        if !tg.health_check_enabled {
            return Some(fakecloud_core::delivery::TargetHealthView {
                state: "unavailable".into(),
                reason: Some("Target.HealthCheckDisabled".into()),
                description: Some("Health checks disabled".into()),
            });
        }
        Some(fakecloud_core::delivery::TargetHealthView {
            state: target.health.state.clone(),
            reason: target.health.reason.clone(),
            description: target.health.description.clone(),
        })
    }
}

/// EC2 network interfaces for the ECS runtime's `awsvpc` task ENIs, through
/// the same requester-managed ENI path other services use.
pub(crate) struct Ec2NetworkLookupImpl {
    pub(crate) state: fakecloud_ec2::SharedEc2State,
}

impl fakecloud_core::delivery::Ec2NetworkLookup for Ec2NetworkLookupImpl {
    fn create_task_eni(
        &self,
        account_id: &str,
        subnet_id: &str,
        group_ids: Vec<String>,
        description: String,
    ) -> Result<fakecloud_core::delivery::TaskEni, String> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        let (eni_id, private_ip) = fakecloud_ec2::vpc_lookup::create_service_eni(
            state,
            fakecloud_ec2::vpc_lookup::ServiceEni {
                subnet_id,
                group_ids,
                description,
                private_ip: None,
            },
        )
        .map_err(|e| format!("{e:?}"))?;
        let mac_address = state
            .network_interfaces
            .get(&eni_id)
            .map(|e| e.mac_address.clone())
            .unwrap_or_default();
        Ok(fakecloud_core::delivery::TaskEni {
            eni_id,
            private_ip,
            mac_address,
        })
    }

    fn delete_task_eni(&self, account_id: &str, eni_id: &str) {
        let mut accounts = self.state.write();
        if let Some(state) = accounts.get_mut(account_id) {
            fakecloud_ec2::vpc_lookup::delete_service_eni(state, eni_id);
        }
    }
}

/// ECS RunTask runner for cross-service universal targets. Wraps an
/// `Arc<EcsService>` so the call goes through the same validation +
/// runtime spawn path as a direct ECS RunTask request.
pub(crate) struct EcsTaskRunnerImpl {
    pub(crate) service: Arc<fakecloud_ecs::EcsService>,
}

impl fakecloud_core::delivery::EcsTaskRunner for EcsTaskRunnerImpl {
    fn run_task(
        &self,
        account_id: &str,
        cluster: &str,
        task_definition: &str,
        launch_type: Option<&str>,
        count: usize,
    ) -> Result<(), String> {
        self.service
            .run_task_external(account_id, cluster, task_definition, launch_type, count)
    }
}

/// SageMaker pipeline starter used by EventBridge Scheduler's
/// `sagemaker:pipeline` target: persists a PipelineExecution record so the
/// Describe/List pipeline-execution ops resolve it.
pub(crate) struct SageMakerPipelineDeliveryImpl {
    pub(crate) state: fakecloud_sagemaker::SharedSageMakerState,
}

impl fakecloud_core::delivery::SageMakerPipelineDelivery for SageMakerPipelineDeliveryImpl {
    fn start_pipeline_execution(&self, pipeline_arn: &str, parameters: &serde_json::Value) {
        fakecloud_sagemaker::start_pipeline_execution_from_delivery(
            &self.state,
            pipeline_arn,
            parameters,
        );
    }
}

/// SMS dispatcher used by Cognito's verification flow: append to the SNS
/// account's `sms_messages` so test code can assert on what landed.
pub(crate) struct SnsSmsDispatcher {
    pub(crate) state: fakecloud_sns::SharedSnsState,
}

impl fakecloud_core::delivery::SmsDispatcher for SnsSmsDispatcher {
    fn send_sms(&self, account_id: &str, region: &str, phone_number: &str, message: &str) {
        let mut accounts = self.state.write();
        let state = accounts.regional_mut(account_id, region);
        state
            .sms_messages
            .push((phone_number.to_string(), message.to_string()));
    }
}

#[cfg(test)]
mod kms_hook_adapter_tests {
    use super::*;
    use fakecloud_core::delivery::KmsHook;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counts saves and records the number of keys in the last snapshot.
    #[derive(Default)]
    struct CountingStore {
        saves: AtomicUsize,
        last_keys: AtomicUsize,
    }

    impl fakecloud_persistence::SnapshotStore for CountingStore {
        fn load(&self) -> std::io::Result<Option<Vec<u8>>> {
            Ok(None)
        }

        fn save(&self, bytes: &[u8]) -> std::io::Result<()> {
            let snap: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            let keys = snap["accounts"]["accounts"]["123456789012"]["keys"]
                .as_object()
                .map_or(0, |k| k.len());
            self.last_keys.store(keys, Ordering::SeqCst);
            self.saves.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn adapter() -> (KmsHookAdapter, Arc<CountingStore>) {
        let state: fakecloud_kms::SharedKmsState = Arc::new(parking_lot::RwLock::new(
            fakecloud_core::multi_account::MultiAccountState::new("123456789012", "us-east-1", ""),
        ));
        let adapter = KmsHookAdapter::new(state, Default::default());
        let store = Arc::new(CountingStore::default());
        adapter.set_snapshot_store(store.clone());
        (adapter, store)
    }

    /// A minted key is saved before the hook call returns (no yield needed),
    /// on the multi-thread runtime the server runs; existing keys save nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn minted_keys_are_saved_before_the_call_returns() {
        let (adapter, store) = adapter();
        let principal = "timestream.amazonaws.com";
        adapter
            .resolve_key_arn(
                "123456789012",
                "us-east-1",
                "alias/aws/timestream",
                principal,
            )
            .unwrap();
        assert_eq!(store.saves.load(Ordering::SeqCst), 1);
        assert_eq!(store.last_keys.load(Ordering::SeqCst), 1);
        adapter
            .encrypt(
                "123456789012",
                "us-east-1",
                "alias/aws/timestream",
                b"x",
                principal,
                Default::default(),
            )
            .unwrap();
        assert_eq!(store.saves.load(Ordering::SeqCst), 1, "no new key, no save");
        adapter
            .aws_managed_key_arn("123456789012", "eu-west-1", "timestream", principal)
            .unwrap();
        assert_eq!(store.saves.load(Ordering::SeqCst), 2);
        assert_eq!(store.last_keys.load(Ordering::SeqCst), 2);
    }

    /// Outside a multi-thread runtime the save runs directly, still before
    /// the call returns.
    #[test]
    fn minted_keys_are_saved_without_a_runtime() {
        let (adapter, store) = adapter();
        adapter
            .aws_managed_key_arn(
                "123456789012",
                "us-east-1",
                "dynamodb",
                "dynamodb.amazonaws.com",
            )
            .unwrap();
        assert_eq!(store.saves.load(Ordering::SeqCst), 1);
    }
}

#[cfg(test)]
mod task_eni_tests {
    use super::*;
    use fakecloud_core::delivery::Ec2NetworkLookup;

    #[test]
    fn task_eni_is_a_real_ec2_interface_in_the_subnet() {
        let ec2: fakecloud_ec2::SharedEc2State = Arc::new(parking_lot::RwLock::new(
            fakecloud_core::multi_account::MultiAccountState::new("123456789012", "us-east-1", ""),
        ));
        // The default VPC's subnets stand in for the task's subnet.
        let subnet = fakecloud_ec2::vpc_lookup::default_vpc_subnets(&ec2, "123456789012")
            .into_iter()
            .next()
            .expect("default subnet");
        let lookup = Ec2NetworkLookupImpl { state: ec2.clone() };
        let eni = lookup
            .create_task_eni(
                "123456789012",
                &subnet.subnet_id,
                vec!["sg-1".into()],
                "arn:aws:ecs:us-east-1:123456789012:attachment/a1".into(),
            )
            .expect("eni");
        assert!(fakecloud_ec2::vpc_lookup::ip_in_cidr(
            &eni.private_ip,
            &subnet.cidr_block
        ));
        assert!(!fakecloud_ec2::vpc_lookup::ip_is_reserved(
            &eni.private_ip,
            &subnet.cidr_block
        ));
        {
            let accounts = ec2.read();
            let iface = &accounts.get("123456789012").unwrap().network_interfaces[&eni.eni_id];
            assert!(iface.requester_managed);
            assert_eq!(iface.mac_address, eni.mac_address);
            assert_eq!(iface.group_ids, vec!["sg-1".to_string()]);
        }
        // A second task never gets the same address.
        let other = lookup
            .create_task_eni("123456789012", &subnet.subnet_id, Vec::new(), String::new())
            .unwrap();
        assert_ne!(other.private_ip, eni.private_ip);
        // Unknown subnet: refused.
        assert!(lookup
            .create_task_eni("123456789012", "subnet-nope", Vec::new(), String::new())
            .is_err());
        lookup.delete_task_eni("123456789012", &eni.eni_id);
        assert!(!ec2
            .read()
            .get("123456789012")
            .unwrap()
            .network_interfaces
            .contains_key(&eni.eni_id));
    }
}

#[cfg(test)]
mod elbv2_target_registration_tests {
    use super::*;
    use fakecloud_core::delivery::Elbv2TargetRegistration;

    const ACCOUNT: &str = "123456789012";
    const TG: &str = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg/1";

    fn hook_with_target_group() -> Elbv2TargetRegistrationImpl {
        let state: fakecloud_elbv2::SharedElbv2State = Arc::new(parking_lot::RwLock::new(
            fakecloud_elbv2::Elbv2Accounts::new(),
        ));
        state.write().get_or_create(ACCOUNT).target_groups.insert(
            TG.to_string(),
            fakecloud_elbv2::TargetGroup {
                arn: TG.to_string(),
                name: "tg".to_string(),
                protocol: Some("HTTP".to_string()),
                port: Some(80),
                vpc_id: None,
                target_type: "instance".to_string(),
                ip_address_type: "ipv4".to_string(),
                protocol_version: None,
                health_check_protocol: None,
                health_check_port: None,
                health_check_enabled: true,
                health_check_path: None,
                health_check_interval_seconds: 30,
                health_check_timeout_seconds: 5,
                healthy_threshold_count: 5,
                unhealthy_threshold_count: 2,
                matcher_http_code: None,
                matcher_grpc_code: None,
                load_balancer_arns: Vec::new(),
                targets: Vec::new(),
                tags: Vec::new(),
                attributes: Default::default(),
                created_time: chrono::Utc::now(),
            },
        );
        Elbv2TargetRegistrationImpl { state }
    }

    fn targets(hook: &Elbv2TargetRegistrationImpl) -> Vec<(String, Option<i32>)> {
        let accounts = hook.state.read();
        let mut out: Vec<_> = accounts.get(ACCOUNT).unwrap().target_groups[TG]
            .targets
            .iter()
            .map(|t| (t.id.clone(), t.port))
            .collect();
        out.sort();
        out
    }

    fn host(port: Option<i64>) -> Vec<(String, Option<i64>)> {
        vec![("127.0.0.1".to_string(), port)]
    }

    #[test]
    fn bridge_tasks_on_one_host_address_each_keep_their_target() {
        let hook = hook_with_target_group();
        hook.register_targets(ACCOUNT, TG, host(Some(32768)));
        hook.register_targets(ACCOUNT, TG, host(Some(32769)));
        assert_eq!(
            targets(&hook),
            vec![
                ("127.0.0.1".to_string(), Some(32768)),
                ("127.0.0.1".to_string(), Some(32769)),
            ]
        );
        assert!(hook
            .target_health(ACCOUNT, TG, "127.0.0.1", Some(32768))
            .is_some());
        assert!(hook
            .target_health(ACCOUNT, TG, "127.0.0.1", Some(32769))
            .is_some());
    }

    #[test]
    fn deregistering_one_task_leaves_the_other_on_the_same_address() {
        // A rolling deployment: the new task registers before the old one is
        // deregistered; the group must never go empty.
        let hook = hook_with_target_group();
        hook.register_targets(ACCOUNT, TG, host(Some(32768)));
        hook.register_targets(ACCOUNT, TG, host(Some(32769)));
        hook.deregister_targets(ACCOUNT, TG, host(Some(32768)));
        assert_eq!(targets(&hook), vec![("127.0.0.1".to_string(), Some(32769))]);
        assert!(hook
            .target_health(ACCOUNT, TG, "127.0.0.1", Some(32768))
            .is_none());
    }

    #[test]
    fn re_registering_the_same_target_does_not_duplicate_it() {
        let hook = hook_with_target_group();
        hook.register_targets(ACCOUNT, TG, host(Some(32768)));
        hook.register_targets(ACCOUNT, TG, host(Some(32768)));
        assert_eq!(targets(&hook), vec![("127.0.0.1".to_string(), Some(32768))]);
    }

    #[test]
    fn port_less_targets_follow_the_register_and_deregister_rules() {
        let hook = hook_with_target_group();
        // Port-less registration is its own (id, no port) entry, as with
        // RegisterTargets, and re-registering it does not duplicate it.
        hook.register_targets(ACCOUNT, TG, host(None));
        hook.register_targets(ACCOUNT, TG, host(None));
        hook.register_targets(ACCOUNT, TG, host(Some(32768)));
        assert_eq!(
            targets(&hook),
            vec![
                ("127.0.0.1".to_string(), None),
                ("127.0.0.1".to_string(), Some(32768)),
            ]
        );
        // Deregistering a specific port leaves the port-less entry alone.
        hook.deregister_targets(ACCOUNT, TG, host(Some(32768)));
        assert_eq!(targets(&hook), vec![("127.0.0.1".to_string(), None)]);
        // A port-less deregistration removes the id on every port, as with
        // DeregisterTargets.
        hook.register_targets(ACCOUNT, TG, host(Some(32769)));
        hook.deregister_targets(ACCOUNT, TG, host(None));
        assert!(targets(&hook).is_empty());
    }

    #[test]
    fn awsvpc_targets_with_distinct_addresses_are_unchanged() {
        let hook = hook_with_target_group();
        hook.register_targets(ACCOUNT, TG, vec![("10.0.1.5".to_string(), Some(8080))]);
        hook.register_targets(ACCOUNT, TG, vec![("10.0.1.6".to_string(), Some(8080))]);
        hook.deregister_targets(ACCOUNT, TG, vec![("10.0.1.5".to_string(), Some(8080))]);
        assert_eq!(targets(&hook), vec![("10.0.1.6".to_string(), Some(8080))]);
    }
}
