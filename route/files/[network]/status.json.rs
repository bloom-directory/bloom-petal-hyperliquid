petal::route_file!(spec: petal::static_read_spec(), read: |ctx: &petal::Ctx| {
    let network = petal::param(ctx, "network")
        .ok()
        .and_then(|value| crate::Network::parse(value).ok())
        .map(|network| format!("{network:?}"));
    petal::read_json_value(&crate::serde_json::json!({
        "network": network,
        "api": "Hyperliquid HyperCore",
        "info": "/info",
        "exchange": "/exchange"
    }))
});
