use std::{collections::BTreeMap, env};

use bloom_petals::package::{PreparedPetalPackage, RouteIndexRecord};

const AGENT_ACTION_INTENT: &str = "hyperliquid.agent_action";
const ACTION_CAPS: &[&str] = &["bloom:http", "bloom:sign", "bloom:store"];
const SESSION_ACTION_ROUTES: &[&str] = &[
    "[network]/agent_sessions/[wallet]/[index]/[session]/cancel.json",
    "[network]/agent_sessions/[wallet]/[index]/[session]/cancel_all",
    "[network]/agent_sessions/[wallet]/[index]/[session]/close_all",
    "[network]/agent_sessions/[wallet]/[index]/[session]/order.json",
    "[network]/agent_sessions/[wallet]/[index]/[session]/schedule_cancel.json",
    "[network]/agent_sessions/[wallet]/[index]/[session]/update_leverage.json",
];
const DERIVATION_ROUTE: &str = "[network]/agent_sessions/[wallet]/[index]/new.json";
const OWNER_SIGNING_ROUTES: &[(&str, &str)] = &[
    (
        "[network]/exchange/[wallet]/[index]/cancel.json",
        "hyperliquid.cancel",
    ),
    (
        "[network]/exchange/[wallet]/[index]/cancel_by_cloid.json",
        "hyperliquid.cancel_by_cloid",
    ),
    (
        "[network]/exchange/[wallet]/[index]/order.json",
        "hyperliquid.order",
    ),
    (
        "[network]/exchange/[wallet]/[index]/schedule_cancel.json",
        "hyperliquid.schedule_cancel",
    ),
    (
        "[network]/exchange/[wallet]/[index]/send_asset.json",
        "hyperliquid.usd_send",
    ),
    (
        "[network]/exchange/[wallet]/[index]/update_leverage.json",
        "hyperliquid.update_leverage",
    ),
    (
        "[network]/exchange/[wallet]/[index]/usd_class_transfer.json",
        "hyperliquid.usd_class_transfer",
    ),
    (
        "[network]/exchange/[wallet]/[index]/usd_send.json",
        "hyperliquid.usd_send",
    ),
    (
        "[network]/exchange/[wallet]/[index]/withdraw.json",
        "hyperliquid.withdraw",
    ),
];

fn routes_by_pattern(package: &PreparedPetalPackage) -> BTreeMap<&str, &RouteIndexRecord> {
    package
        .route_index
        .routes
        .iter()
        .map(|route| (route.pattern.as_str(), route))
        .collect()
}

fn required_caps(route: &RouteIndexRecord) -> Vec<&str> {
    route
        .install_metadata
        .required_caps
        .iter()
        .map(String::as_str)
        .collect()
}

fn operation_classes(route: &RouteIndexRecord) -> Vec<&str> {
    route
        .key_derive_operation_classes
        .iter()
        .map(String::as_str)
        .collect()
}

#[test]
fn exact_built_package_scopes_delegated_and_direct_signing_metadata() {
    let archive = env::var("HYPERLIQUID_PACKAGE_ARCHIVE")
        .expect("HYPERLIQUID_PACKAGE_ARCHIVE must name the exact package archive under test");
    let package = PreparedPetalPackage::from_petal_tar(&archive)
        .expect("the exact built package must satisfy Bloom's authenticated route contract");
    let routes = routes_by_pattern(&package);

    let derivation = routes
        .get(DERIVATION_ROUTE)
        .expect("agent-session derivation route");
    assert_eq!(operation_classes(derivation), [AGENT_ACTION_INTENT]);
    assert_eq!(
        derivation.install_metadata.sign_intent.as_deref(),
        Some("hyperliquid.approve_agent")
    );
    assert_eq!(
        required_caps(derivation),
        [
            "bloom:http",
            "bloom:key.derive",
            "bloom:sign",
            "bloom:store",
        ]
    );
    let mut expected_scope = SESSION_ACTION_ROUTES
        .iter()
        .map(|pattern| routes[*pattern].route_id.as_str())
        .chain(std::iter::once(derivation.route_id.as_str()))
        .collect::<Vec<_>>();
    expected_scope.sort_unstable();
    assert_eq!(
        derivation
            .key_derive_allowed_routes
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        expected_scope
    );
    assert!(derivation.key_derive_scope_declared);
    assert_eq!(
        derivation.key_derive_allowed_crypto_suites,
        ["secp256k1-keccak256-recoverable"]
    );
    assert_eq!(
        derivation.key_derive_maximum_lifetime_ms,
        Some(86_400_000)
    );

    let delegated_routes = package
        .route_index
        .routes
        .iter()
        .filter(|route| !route.key_derive_operation_classes.is_empty())
        .map(|route| route.pattern.as_str())
        .collect::<Vec<_>>();
    assert_eq!(delegated_routes, [DERIVATION_ROUTE]);

    for pattern in SESSION_ACTION_ROUTES {
        let route = routes
            .get(pattern)
            .unwrap_or_else(|| panic!("missing {pattern}"));
        assert_eq!(
            route.install_metadata.sign_intent.as_deref(),
            Some(AGENT_ACTION_INTENT),
            "{pattern}"
        );
        assert_eq!(required_caps(route), ACTION_CAPS, "{pattern}");
        assert!(route.key_derive_operation_classes.is_empty(), "{pattern}");
    }

    let agent_action_routes = package
        .route_index
        .routes
        .iter()
        .filter(|route| route.install_metadata.sign_intent.as_deref() == Some(AGENT_ACTION_INTENT))
        .map(|route| route.pattern.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        agent_action_routes,
        SESSION_ACTION_ROUTES
            .iter()
            .copied()
            .collect::<Vec<_>>()
    );

    for (pattern, intent) in OWNER_SIGNING_ROUTES {
        let route = routes
            .get(pattern)
            .unwrap_or_else(|| panic!("missing {pattern}"));
        assert_eq!(
            route.install_metadata.sign_intent.as_deref(),
            Some(*intent),
            "{pattern}"
        );
        assert_eq!(required_caps(route), ACTION_CAPS, "{pattern}");
        assert!(route.key_derive_operation_classes.is_empty(), "{pattern}");
    }
}

// Real compiled route -> Machine VM host boundary, with no Broker or venue.
#[tokio::test]
async fn compiled_withdrawal_preserves_prepared_request_and_never_submits_while_pending() {
    use async_trait::async_trait;
    use bloom_petal_contract::prepared::{Request, SigningError, SigningOutcome, Spend};
    use bloom_petals::{
        DispatchOp, DispatchRequest, DispatchResponse, HostError, HostVfsEntry, NameRegistry,
        PetalHost, PetalRunner, PetalStore, PetalVm, RunOptions, abi::PetalRouteContext,
    };
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Host {
        requests: Mutex<Vec<(Request, PetalRouteContext)>>,
    }
    #[async_trait]
    impl PetalHost for Host {
        async fn vfs_lookup(&self, _: &str) -> Result<HostVfsEntry, HostError> {
            Err(HostError::Denied("fixture".into()))
        }
        async fn vfs_read(&self, _: &str) -> Result<Vec<u8>, HostError> {
            Err(HostError::Denied("fixture".into()))
        }
        async fn vfs_list(&self, _: &str) -> Result<Vec<HostVfsEntry>, HostError> {
            Err(HostError::Denied("fixture".into()))
        }
        async fn vfs_write(&self, _: &str, _: &[u8]) -> Result<(), HostError> {
            panic!("unexpected VFS write")
        }
        async fn sign_payload_outcome(
            &self,
            _: bloom_petals::PayloadSignRequest,
        ) -> Result<bloom_petals::SignOutcome, HostError> {
            panic!("prepared signing must never fall back to legacy signing")
        }
        async fn http_fetch(
            &self,
            _: bloom_petals::HttpRequest,
            _: bloom_petals::policy::NetPolicy,
            _: usize,
        ) -> Result<bloom_petals::HttpResponse, HostError> {
            panic!("pending/recovery must never submit to the venue")
        }
        async fn prepared_sign(
            &self,
            request: Request,
            context: PetalRouteContext,
        ) -> Result<SigningOutcome, SigningError> {
            let mut requests = self.requests.lock().unwrap();
            requests.push((request, context));
            if requests.len() == 1 {
                Ok(SigningOutcome::ApprovalPending {
                    action_id: "fixture-approval".into(),
                    expires_ms: u64::MAX,
                })
            } else {
                Ok(SigningOutcome::RecoveryRequired {
                    status: "submission_uncertain".into(),
                })
            }
        }
    }
    let archive = env::var("HYPERLIQUID_PACKAGE_ARCHIVE").unwrap();
    let package = PreparedPetalPackage::from_petal_tar(&archive).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let store = PetalStore::open(temp.path().join("petals")).unwrap();
    store.install_prepared_petal_package(package).unwrap();
    let registry = Arc::new(NameRegistry::open(temp.path().join("registry")).unwrap());
    let runner = PetalRunner::new(store, registry, PetalVm::new().unwrap());
    let host = Arc::new(Host::default());
    let trusted = vec![
        ("bloom.wallet".into(), "alice".into()),
        ("bloom.account".into(), "2".into()),
        ("bloom.owner_key_fingerprint".into(), "cd".repeat(32)),
    ];
    let account_context = |number| bloom_vfs::handlers::wallets::AccountPetalContext {
        wallet: "alice".into(), number,
        evm_fingerprint: Some("cd".repeat(32)), solana_fingerprint: None,
        freshness: serde_json::from_value(serde_json::json!("fresh")).unwrap(),
    };
    let selected = account_context(2);
    let path = "testnet/exchange/alice/2/withdraw.json";
    let body =
        br#"{"destination":"0x00000000000000000000000000000000000000aa","amount":"10","nonce":42}"#;
    for expected in ["fixture-approval", "submission_uncertain"] {
        let response = runner
            .dispatch_petal_route_with_trusted_params(
                "hyperliquid",
                DispatchRequest {
                    op: DispatchOp::Write,
                    path: path.into(),
                    body: body.to_vec(),
                    ctx: vec![],
                },
                host.clone(),
                None,
                RunOptions::default(),
                &trusted,
                Some(&selected),
            )
            .await
            .unwrap()
            .response;
        match response {
            DispatchResponse::Error { code, message } => {
                assert_eq!(code, -3);
                assert!(message.contains(expected), "{message}");
            }
            other => panic!("expected approval/recovery, got {other:?}"),
        }
    }
    let response = runner
        .dispatch_petal_route_with_trusted_params(
            "hyperliquid",
            DispatchRequest {
                op: DispatchOp::Read,
                path: path.into(),
                body: vec![],
                ctx: vec![],
            },
            host.clone(),
            None,
            RunOptions::default(),
            &trusted,
            Some(&selected),
        )
        .await
        .unwrap()
        .response;
    assert!(matches!(response, DispatchResponse::Read(_)));
    assert_eq!(host.requests.lock().unwrap().len(), 2, "read must not sign");
    for (network, account) in [("mainnet", "2"), ("testnet", "1")] {
        let mut isolated = trusted.clone();
        isolated[1].1 = account.into();
        let selected = account_context(account.parse().unwrap());
        runner
            .dispatch_petal_route_with_trusted_params(
                "hyperliquid",
                DispatchRequest {
                    op: DispatchOp::Write,
                    path: format!("{network}/exchange/alice/{account}/withdraw.json"),
                    body: body.to_vec(),
                    ctx: vec![],
                },
                host.clone(),
                None,
                RunOptions::default(),
                &isolated,
                Some(&selected),
            )
            .await
            .unwrap();
    }
    let requests = host.requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    assert_ne!(
        requests[0].0.operation_key, requests[2].0.operation_key,
        "network scopes differ"
    );
    assert_ne!(
        requests[0].0.operation_key, requests[3].0.operation_key,
        "account scopes differ"
    );
    assert_eq!(requests[3].1.trusted_account().unwrap().number, 1);
    assert_eq!(
        requests[0].0, requests[1].0,
        "retry must preserve nonce/action/operation key"
    );
    let (request, context) = &requests[0];
    assert_eq!(context.trusted_account().unwrap().number, 2);
    assert_eq!(request.wallet, "alice");
    assert_eq!(request.action.operation_class, "hyperliquid.withdraw");
    assert_eq!(request.action.spend, Spend::Unspecified);
    assert_eq!(request.action.payload.preimage.len(), 66);
    request.validate().unwrap();
    let review: serde_json::Value = serde_json::from_slice(&request.action.review.bytes).unwrap();
    assert_eq!(review["kind"], "eip712");
    assert_eq!(review["typed_data"]["message"]["amount"], "10");
    assert_eq!(review["typed_data"]["message"]["time"], 42);
    assert_eq!(
        review["typed_data"]["message"]["destination"],
        "0x00000000000000000000000000000000000000aa"
    );
}
