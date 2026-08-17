use std::{collections::BTreeMap, env};

use bloom_petals::package::{PreparedPetalPackage, RouteIndexRecord};

const AGENT_ACTION_INTENT: &str = "hyperliquid.agent_action";
const ACTION_CAPS: &[&str] = &["bloom:http", "bloom:sign", "bloom:store"];
const SESSION_ACTION_ROUTES: &[(&str, &str)] = &[
    (
        "[network]/agent_sessions/[wallet]/[session]/cancel.json",
        "r000008",
    ),
    (
        "[network]/agent_sessions/[wallet]/[session]/cancel_all",
        "r000009",
    ),
    (
        "[network]/agent_sessions/[wallet]/[session]/close_all",
        "r000010",
    ),
    (
        "[network]/agent_sessions/[wallet]/[session]/order.json",
        "r000013",
    ),
    (
        "[network]/agent_sessions/[wallet]/[session]/schedule_cancel.json",
        "r000015",
    ),
    (
        "[network]/agent_sessions/[wallet]/[session]/update_leverage.json",
        "r000019",
    ),
];
const DERIVATION_ROUTE: (&str, &str) = ("[network]/agent_sessions/[wallet]/new.json", "r000021");
const OWNER_SIGNING_ROUTES: &[(&str, &str)] = &[
    (
        "[network]/exchange/[wallet]/cancel.json",
        "hyperliquid.cancel",
    ),
    (
        "[network]/exchange/[wallet]/cancel_by_cloid.json",
        "hyperliquid.cancel_by_cloid",
    ),
    (
        "[network]/exchange/[wallet]/order.json",
        "hyperliquid.order",
    ),
    (
        "[network]/exchange/[wallet]/schedule_cancel.json",
        "hyperliquid.schedule_cancel",
    ),
    (
        "[network]/exchange/[wallet]/send_asset.json",
        "hyperliquid.usd_send",
    ),
    (
        "[network]/exchange/[wallet]/update_leverage.json",
        "hyperliquid.update_leverage",
    ),
    (
        "[network]/exchange/[wallet]/usd_send.json",
        "hyperliquid.usd_send",
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
        .get(DERIVATION_ROUTE.0)
        .expect("agent-session derivation route");
    assert_eq!(derivation.route_id, DERIVATION_ROUTE.1);
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

    let delegated_routes = package
        .route_index
        .routes
        .iter()
        .filter(|route| !route.key_derive_operation_classes.is_empty())
        .map(|route| route.pattern.as_str())
        .collect::<Vec<_>>();
    assert_eq!(delegated_routes, [DERIVATION_ROUTE.0]);

    for (pattern, route_id) in SESSION_ACTION_ROUTES {
        let route = routes
            .get(pattern)
            .unwrap_or_else(|| panic!("missing {pattern}"));
        assert_eq!(&route.route_id, route_id, "{pattern}");
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
            .map(|(pattern, _)| *pattern)
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
