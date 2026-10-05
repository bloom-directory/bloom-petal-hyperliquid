mod protocol;
mod settings;
mod workflow;

pub use protocol::*;
pub use serde_json;
pub use workflow::*;

pub fn static_list(names: &[(&str, bool, bool)]) -> Vec<petal::RouteChild> {
    names
        .iter()
        .map(|(name, is_dir, is_writable)| {
            if *is_dir {
                petal::dir(*name)
            } else if *is_writable {
                petal::writable(*name)
            } else {
                petal::file(*name)
            }
        })
        .collect()
}

/// The route identity `petal::route_file!` binds; the Petal build tool
/// generates the real one per route, and tests that compile a route source
/// into this crate supply this stand-in. Route parameters still come from the
/// context's explicit `params`, exactly as Bloom supplies them.
#[cfg(test)]
pub struct __PetalRouteIdentity;

#[cfg(test)]
impl petal::RouteIdentity for __PetalRouteIdentity {
    const PATH: &'static str = "";
    const CANONICAL_PATH: &'static str = "";
    const PARAMS: &'static [(&'static str, usize)] = &[];
}

/// The admission guards on the four order routes are what keep every order in
/// the fee class its route signs under, so each route's real `write` handler
/// is driven here with the bodies it must refuse. Every refusal happens before
/// any host call, so no host is needed.
#[cfg(test)]
mod order_route_admission {
    use petal::{RawCtx, RawGuest, RouteError};

    mod owner_order {
        include!("../files/[network]/exchange/[wallet]/[index]/order.json.rs");
    }
    mod owner_builder_order {
        include!("../files/[network]/exchange/[wallet]/[index]/builder_order.json.rs");
    }
    mod session_order {
        include!("../files/[network]/agent_sessions/[wallet]/[index]/[session]/order.json.rs");
    }
    mod session_builder_order {
        include!(
            "../files/[network]/agent_sessions/[wallet]/[index]/[session]/builder_order.json.rs"
        );
    }

    type Write = fn(RawCtx, Vec<u8>) -> Result<(), RouteError>;
    const ORDINARY_ROUTES: [(&str, Write); 2] = [
        (
            "exchange order.json",
            <owner_order::Route as RawGuest>::write,
        ),
        (
            "session order.json",
            <session_order::Route as RawGuest>::write,
        ),
    ];
    const BUILDER_ROUTES: [(&str, Write); 2] = [
        (
            "exchange builder_order.json",
            <owner_builder_order::Route as RawGuest>::write,
        ),
        (
            "session builder_order.json",
            <session_builder_order::Route as RawGuest>::write,
        ),
    ];

    fn ctx() -> RawCtx {
        RawCtx {
            petal_root: "petals/hyperliquid".into(),
            package_hash: "0".repeat(64),
            path: "testnet/exchange/main/0/order.json".into(),
            params: [
                ("network", "testnet"),
                ("wallet", "main"),
                ("index", "0"),
                ("session", "s1"),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect(),
            actor: None,
        }
    }

    fn order_body(builder: Option<crate::serde_json::Value>) -> Vec<u8> {
        let mut action = crate::serde_json::json!({
            "type": "order",
            "orders": [{
                "a": 0, "b": true, "p": "100", "s": "0.01", "r": false,
                "t": {"limit": {"tif": "Gtc"}}
            }],
            "grouping": "na"
        });
        if let Some(builder) = builder {
            action["builder"] = builder;
        }
        crate::serde_json::to_vec(&crate::serde_json::json!({"action": action})).unwrap()
    }

    fn builder() -> crate::serde_json::Value {
        crate::serde_json::json!({"b": "0x0000000000000000000000000000000000000001", "f": 10})
    }

    fn refusal(route: &str, result: Result<(), RouteError>) -> String {
        match result {
            Err(RouteError::Invalid(message)) => message,
            other => panic!("{route} did not refuse the body as invalid: {other:?}"),
        }
    }

    #[test]
    fn ordinary_order_routes_refuse_a_builder() {
        for (route, write) in ORDINARY_ROUTES {
            let message = refusal(route, write(ctx(), order_body(Some(builder()))));
            assert!(
                message.contains("cannot carry a builder fee"),
                "{route}: {message}"
            );
            assert!(message.contains("builder_order.json"), "{route}: {message}");
        }
    }

    #[test]
    fn builder_order_routes_require_a_builder() {
        for (route, write) in BUILDER_ROUTES {
            let message = refusal(route, write(ctx(), order_body(None)));
            assert!(
                message.contains("requires an order carrying a builder fee"),
                "{route}: {message}"
            );
            assert!(message.contains("order.json"), "{route}: {message}");
        }
    }

    #[test]
    fn every_order_route_refuses_other_action_types() {
        let cancel = crate::serde_json::to_vec(&crate::serde_json::json!({
            "action": {"type": "cancel", "cancels": [{"a": 0, "o": 42}]}
        }))
        .unwrap();
        for (route, write) in ORDINARY_ROUTES.into_iter().chain(BUILDER_ROUTES) {
            let message = refusal(route, write(ctx(), cancel.clone()));
            assert!(
                message.contains("cannot submit action type cancel"),
                "{route}: {message}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn agent_session_creation_declares_key_derivation_capability() {
        let source = include_str!("../files/[network]/agent_sessions/[wallet]/[index]/new.json.rs");
        assert!(source.contains("bloom:key.derive"));
    }

    #[test]
    fn session_success_evidence_resolves_to_public_user_routes() {
        let sources = [
            include_str!(
                "../files/[network]/agent_sessions/[wallet]/[index]/[session]/cancel.json.rs"
            ),
            include_str!(
                "../files/[network]/agent_sessions/[wallet]/[index]/[session]/update_leverage.json.rs"
            ),
        ];
        for source in sources {
            let path = source
                .split("\"path_from_bloom_root\": \"")
                .nth(1)
                .expect("session help declares a success evidence path")
                .split('"')
                .next()
                .unwrap();
            assert!(
                path.starts_with("petals/hyperliquid/<network>/users/<owner_address>/"),
                "{path}"
            );
            let route = path
                .strip_prefix("petals/hyperliquid/")
                .unwrap()
                .replace("<network>", "[network]")
                .replace("<owner_address>", "[account]")
                .replace("/BTC.json", "/[coin].json");
            let source_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("files")
                .join(format!("{route}.rs"));
            assert!(source_path.is_file(), "evidence route is missing: {route}");
        }
    }
}
