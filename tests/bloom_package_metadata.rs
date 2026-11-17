use std::{collections::BTreeMap, env};

use bloom_petals::package::{PreparedPetalPackage, RouteIndexRecord};

const AGENT_ACTION_INTENT: &str = "hyperliquid.agent_action";
const BUILDER_ORDER_INTENT: &str = "hyperliquid.builder_order";
/// The chain and asset this Petal's builder-fee claim declares, mirroring
/// `ClaimEffects::builder_order_fee` in `route/src/workflow.rs`. Broker denies
/// a claim whose declared fee asset is not the one the pinned Bloom catalogued
/// for the class (`FEE_ASSET_MISMATCH`), so these must be the catalogued pair.
const FEE_CLAIM_CHAIN: &str = "hyperliquid";
const FEE_CLAIM_ASSET: &str = "usdc";
/// The name the pinned Bloom's catalog row refers to the class by. The row
/// names this const rather than the class string, so pinning the row means
/// matching on the identifier.
const CLASS_CONST: &str = "HYPERLIQUID_BUILDER_ORDER_CLASS";
const SESSION_BUILDER_ORDER_ROUTE: (&str, &str) = (
    "[network]/agent_sessions/[wallet]/[index]/[session]/builder_order.json",
    "r000008",
);
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
        .get(DERIVATION_ROUTE)
        .expect("agent-session derivation route");
    // The manifest declares both classes because the host takes the derived
    // key's route scope from `[[key.derive]]` and validates the requested
    // classes as a subset of these. A session created without a builder bound
    // requests `agent_action` alone, so only a builder-bound session can sign
    // under the fee-bearing class.
    assert_eq!(
        operation_classes(derivation),
        [AGENT_ACTION_INTENT, BUILDER_ORDER_INTENT]
    );
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
    // The builder-order route is scoped by the manifest like every other
    // session route, but it signs under its own fee-bearing intent, so it is
    // not part of the agent-action list above.
    let mut expected_scope = SESSION_ACTION_ROUTES
        .iter()
        .copied()
        .chain(std::iter::once(SESSION_BUILDER_ORDER_ROUTE.0))
        .map(|pattern| routes[pattern].route_id.as_str())
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
            "const {CLASS_CONST}: &str = \"{BUILDER_ORDER_INTENT}\";"
        )),
        "the pinned Bloom does not name {BUILDER_ORDER_INTENT} as a fee-bearing class"
    );

    // Everything below is about the *enrollment* paths, so all of it reads the
    // production half only: the pin's own tests deliberately plant
    // `fee_asset: None` fixtures to exercise its heal, and grepping the whole
    // file conflated those with a real enrollment path.
    //
    // The window ends at the first `#[cfg(test)]`. A marker *before* the
    // catalog would cut it short ahead of everything asserted here, which the
    // next assertion refuses outright. A marker after it -- a nested
    // `#[cfg(test)]` among the pin's own tests, which is routine -- leaves the
    // split unchanged and is not an error. The split is positional, not
    // semantic: a production item written *after* the test module would escape
    // this window, so the `fee_asset: None` sweep at the end is a backstop, not
    // a proof. The catalog assertions do not lean on the split for their force.
    let (production, _) = source
        .split_once("#[cfg(test)]")
        .unwrap_or((source.as_str(), ""));
    let catalog_declaration = "const FEE_BEARING_OPERATION_CLASSES:";
    assert!(
        production.contains(catalog_declaration),
        "`{catalog_declaration}` is not in the pinned Bloom's production half; either the \
         catalog is gone or a `#[cfg(test)]` now precedes it, which would hide every \
         assertion below"
    );

    // The catalogued row itself, not merely the class name. Naming the class
    // is what the assertion above does, and it is not enough on its own: the
    // enrolled fee asset comes from this table, so a pin that emptied the
    // table, or kept the row and changed its asset, would deny *every* builder
    // order -- `FEE_NOT_ALLOWED` for an absent row, `FEE_ASSET_MISMATCH` for
    // the wrong asset -- while every other assertion in this test still
    // passed. Both of those mutations did pass before this block existed.
    //
    // Matched per row rather than across the whole table, so a second venue's
    // row cannot satisfy this one's fields.
    let table = production
        .split_once(catalog_declaration)
        .and_then(|(_, rest)| rest.split_once("];"))
        .map(|(initializer, _)| initializer)
        .expect("the assertion above proves the declaration is present");
    let row = table
        .split("CataloguedFeeAsset {")
        .find(|row| row.contains(&format!("operation_class: {CLASS_CONST}")))
        .unwrap_or_else(|| {
            panic!(
                "the pinned Bloom's fee-bearing class table has no row for {CLASS_CONST}, so \
                 {BUILDER_ORDER_INTENT} is enrolled fee-free and Broker denies every \
                 builder-fee claim under it with FEE_NOT_ALLOWED"
            )
        });
    for field in [
        format!("chain: {FEE_CLAIM_CHAIN:?}"),
        format!("asset: {FEE_CLAIM_ASSET:?}"),
    ] {
        assert!(
            row.contains(&field),
            "the pinned Bloom catalogues {BUILDER_ORDER_INTENT} without `{field}`; this \
             Petal's claim declares {FEE_CLAIM_CHAIN}/{FEE_CLAIM_ASSET}, and Broker denies a \
             claim whose fee asset is not the catalogued one with FEE_ASSET_MISMATCH"
        );
    }

    assert!(
        production
            .matches("fee_asset: catalogued_fee_asset(")
            .count()
            >= 2,
        "the pinned Bloom must derive each class's fee asset from that table on both the \
         developer and release enrollment paths"
    );
    assert!(
        !production.contains("fee_asset: None"),
        "the pinned Bloom still enrolls a class with an unconditional fee_asset: None"
    );
}
