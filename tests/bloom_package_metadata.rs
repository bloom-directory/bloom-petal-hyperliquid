use std::{collections::BTreeMap, env};

use bloom_petals::package::{PreparedPetalPackage, RouteIndexRecord};

const AGENT_ACTION_INTENT: &str = "hyperliquid.agent_action";
const BUILDER_ORDER_INTENT: &str = "hyperliquid.builder_order";
const SESSION_BUILDER_ORDER_ROUTE: (&str, &str) = (
    "[network]/agent_sessions/[wallet]/[index]/[session]/builder_order.json",
    "r000008",
);
const ACTION_CAPS: &[&str] = &["bloom:http", "bloom:sign", "bloom:store"];
const SESSION_ACTION_ROUTES: &[(&str, &str)] = &[
    (
        "[network]/agent_sessions/[wallet]/[index]/[session]/cancel.json",
        "r000009",
    ),
    (
        "[network]/agent_sessions/[wallet]/[index]/[session]/cancel_all",
        "r000010",
    ),
    (
        "[network]/agent_sessions/[wallet]/[index]/[session]/close_all",
        "r000011",
    ),
    (
        "[network]/agent_sessions/[wallet]/[index]/[session]/order.json",
        "r000014",
    ),
    (
        "[network]/agent_sessions/[wallet]/[index]/[session]/schedule_cancel.json",
        "r000020",
    ),
    (
        "[network]/agent_sessions/[wallet]/[index]/[session]/update_leverage.json",
        "r000024",
    ),
];
const DERIVATION_ROUTE: (&str, &str) = ("[network]/agent_sessions/[wallet]/[index]/new.json", "r000026");
const OWNER_SIGNING_ROUTES: &[(&str, &str)] = &[
    (
        "[network]/exchange/[wallet]/[index]/approve_builder_fee.json",
        "hyperliquid.approve_builder_fee",
    ),
    (
        "[network]/exchange/[wallet]/[index]/cancel.json",
        "hyperliquid.cancel",
    ),
    (
        "[network]/exchange/[wallet]/[index]/cancel_by_cloid.json",
        "hyperliquid.cancel_by_cloid",
    ),
    (
        "[network]/exchange/[wallet]/[index]/builder_order.json",
        BUILDER_ORDER_INTENT,
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
        .get(DERIVATION_ROUTE.0)
        .expect("agent-session derivation route");
    assert_eq!(derivation.route_id, DERIVATION_ROUTE.1);

    // Inspect the exact packaged runtime source, not a second manifest-only
    // list: request_session_key passes session_key_scope(..) to derive_key,
    // which builds the scope from these two constants.
    let workflow = package
        .files
        .iter()
        .find(|file| file.path == "route/src/workflow.rs")
        .expect("packaged session runtime source");
    let workflow = std::str::from_utf8(&workflow.bytes).expect("UTF-8 runtime source");
    let quoted = |declaration: &str, end: &str| {
        workflow
            .split(declaration)
            .nth(1)
            .unwrap_or_else(|| panic!("runtime declaration {declaration}"))
            .split(end)
            .next()
            .unwrap()
            .split('"')
            .enumerate()
            .filter_map(|(index, value)| (index % 2 == 1).then_some(value))
            .collect::<Vec<_>>()
    };
    let runtime_scope = quoted("const SESSION_KEY_ALLOWED_ROUTES: [&str; 7] = [", "];");
    let runtime_builder_route = quoted("const SESSION_KEY_BUILDER_ORDER_ROUTE: &str = ", ";");
    let request = workflow
        .split("fn request_session_key(")
        .nth(1)
        .expect("runtime derivation request")
        .split("fn session_key_slot(")
        .next()
        .unwrap();
    assert!(request.contains("session_key_scope(builder_bound)"));
    assert!(request.contains("allowed_routes,"));
    let scope_fn = workflow
        .split("fn session_key_scope(")
        .nth(1)
        .expect("runtime session key scope")
        .split("\n}\n")
        .next()
        .unwrap();
    assert!(scope_fn.contains("SESSION_KEY_ALLOWED_ROUTES"));
    assert!(scope_fn.contains("routes.push(SESSION_KEY_BUILDER_ORDER_ROUTE.to_owned())"));
    let mut expected_scope = SESSION_ACTION_ROUTES
        .iter()
        .map(|(pattern, _)| {
            routes
                .get(pattern)
                .expect("session action route")
                .route_id
                .as_str()
        })
        .collect::<Vec<_>>();
    expected_scope.push(derivation.route_id.as_str());
    assert_eq!(
        runtime_scope, expected_scope,
        "runtime derivation scope must match the exact package's action and creation routes"
    );
    let builder_order_route = routes
        .get(SESSION_BUILDER_ORDER_ROUTE.0)
        .expect("session builder-order route")
        .route_id
        .as_str();
    assert_eq!(
        runtime_builder_route,
        [builder_order_route],
        "a builder-bound session key must be scoped to the exact package's session builder-order route"
    );

    let mut derived_classes = operation_classes(derivation);
    derived_classes.sort_unstable();
    assert_eq!(derived_classes, [AGENT_ACTION_INTENT, BUILDER_ORDER_INTENT]);
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

    let builder_order = routes
        .get(SESSION_BUILDER_ORDER_ROUTE.0)
        .expect("session builder-order route");
    assert_eq!(builder_order.route_id, SESSION_BUILDER_ORDER_ROUTE.1);
    assert_eq!(
        builder_order.install_metadata.sign_intent.as_deref(),
        Some(BUILDER_ORDER_INTENT)
    );
    assert_eq!(required_caps(builder_order), ACTION_CAPS);
    assert!(builder_order.key_derive_operation_classes.is_empty());

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

/// The package's only fee-bearing class must be the one the pinned Bloom
/// catalogues with a fee asset, on both of the Machine's enrollment paths.
/// Bloom's exact-signing check refuses a `{"kind":"fee"}` claim under a class
/// catalogued fee-free (`FEE_NOT_ALLOWED`), so a pin whose enrollment writes
/// `fee_asset: None` for every class cannot sign a builder order at all. The
/// catalogue is private to the `bloom` binary, so this reads the enrollment
/// source the check script's Bloom checkout provides; it runs from
/// `crates/bloom-petals` inside that checkout.
#[test]
fn pinned_bloom_catalogues_the_builder_order_class_with_a_fee_asset() {
    let enrollment = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../bloom/src/triad_enrollment.rs");
    let source = std::fs::read_to_string(&enrollment)
        .unwrap_or_else(|error| panic!("read {}: {error}", enrollment.display()));
    assert!(
        source.contains(&format!(
            "const HYPERLIQUID_BUILDER_ORDER_CLASS: &str = \"{BUILDER_ORDER_INTENT}\";"
        )),
        "the pinned Bloom does not catalogue {BUILDER_ORDER_INTENT} as a fee-bearing class"
    );
    assert!(
        source.matches("fee_asset: catalogued_fee_asset(").count() >= 2,
        "the pinned Bloom must catalogue fee assets per class on both the developer and release enrollment paths"
    );
    assert!(
        !source.contains("fee_asset: None"),
        "the pinned Bloom still enrolls a class with an unconditional fee_asset: None"
    );
}
