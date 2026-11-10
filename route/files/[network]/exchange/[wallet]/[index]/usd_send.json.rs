petal::route_file!(
    spec: petal::signing_write_spec("hyperliquid.usd_send")
        .caps(&["bloom:http", "bloom:store", "bloom:sign"]),
    read: |_ctx: &petal::Ctx| {
        petal::read_json_value(&crate::serde_json::json!({
            "description": "write a Hyperliquid usdSend request; owner signing may require Bloom approval",
            "body": {
                "destination": "0x-prefixed account address",
                "amount": "positive USDC decimal with at most 6 decimal places",
                "nonce": "optional; omit it and Bloom allocates one. If set, it must be the current Unix time in milliseconds"
            },
            "example": {"destination": "<0x recipient address>", "amount": "1"},
            "success_evidence": "after the owner approves and the same body is written again, last_response.json has status ok; it holds only the latest owner exchange response for this account"
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
