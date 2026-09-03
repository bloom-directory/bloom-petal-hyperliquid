petal::route_file!(
    spec: petal::signing_write_spec("hyperliquid.approve_builder_fee")
        .caps(&["bloom:http", "bloom:store", "bloom:sign"]),
    read: |_ctx: &petal::Ctx| {
        petal::read_json_value(&crate::serde_json::json!({
            "description": "write a Hyperliquid approveBuilderFee request approving a maximum fee for a builder; must be signed by the main wallet and may require Bloom approval",
            "body": {
                "builder": "optional lowercase 0x builder address; omit to use this release's embedded default builder, if configured",
                "max_fee_tenths_bps": "maximum builder fee in tenths of a basis point (10 = 1bp); capped by the venue at 1000 (1%)",
                "nonce": "optional timestamp in milliseconds"
            }
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
        crate::approve_builder_fee(ctx, network, wallet, body)
    }
);
