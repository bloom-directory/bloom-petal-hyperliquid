petal::route_file!(
    spec: petal::write_spec().caps(&["bloom:http", "bloom:store", "bloom:sign"]),
    read: |_ctx: &petal::Ctx| {
        petal::read_json(&crate::serde_json::json!({
            "description": "write a Hyperliquid send_asset.json request; signed actions require Bloom approval"
        }))
    },
    write: |ctx: &petal::Ctx, body: &[u8]| {
        if let Err(response) = crate::validate_body_size(body) {
            return response;
        }
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
        crate::usd_send(ctx, network, wallet, body)
    }
);
