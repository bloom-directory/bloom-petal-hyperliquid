petal::route_file!(spec: petal::store_read_spec(), read: |ctx: &petal::Ctx| {
    let network = match petal::param(ctx, "network").and_then(|value| {
        crate::Network::parse(value).map_err(|error| petal::error(-3, error))
    }) {
        Ok(network) => network,
        Err(response) => return response,
    };
    let wallet = match petal::param(ctx, "wallet").and_then(|value| {
        crate::parse_address(value)
            .map(|address| format!("{address:#x}"))
            .map_err(|error| petal::error(-3, error))
    }) {
        Ok(wallet) => wallet,
        Err(response) => return response,
    };
    match crate::load_wallet_session_error(network, &wallet) {
        Ok(Some(error)) => petal::read_json(&crate::serde_json::json!({"error": error})),
        Ok(None) => petal::read_json(&crate::serde_json::json!({"error": null})),
        Err(response) => response,
    }
});
