petal::route_file!(
    spec: petal::signing_write_spec("hyperliquid.usd_send")
        .caps(&["bloom:http", "bloom:store", "bloom:sign"]),
    read: |_ctx: &petal::Ctx| {
        petal::read_json_value(&crate::serde_json::json!({
            "description": "deprecated compatibility alias for usd_send.json; this submits Hyperliquid usdSend, not sendAsset. Refused before any ceremony while the account is in unified account mode, which new accounts start in: read users/<account>/abstraction.json and write {\"abstraction\":\"disabled\"} to set_abstraction.json first"
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
            crate::parse_wallet_id(value).map_err(|error| petal::error(-3, error))
        }) {
            Ok(wallet) => wallet,
            Err(response) => return response,
        };
        crate::usd_send(ctx, network, wallet, body)
    }
);
