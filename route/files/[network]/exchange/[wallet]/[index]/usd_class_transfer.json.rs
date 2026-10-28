petal::route_file!(
    spec: petal::signing_write_spec("hyperliquid.usd_class_transfer")
        .caps(&["bloom:http", "bloom:store", "bloom:sign"]),
    read: |_ctx: &petal::Ctx| {
        petal::read_json_value(&crate::serde_json::json!({
            "description": "write a Hyperliquid usdClassTransfer request moving USDC between this wallet's spot and perp engines; owner signing may require Bloom approval",
            "body": {
                "amount": "positive USDC decimal with at most 6 decimal places",
                "to_perp": "true moves spot USDC into perp, false moves perp USDC into spot",
                "nonce": "optional; omit it and Bloom allocates one. If set, it must be the current Unix time in milliseconds"
            },
            "example": {"amount": "10", "to_perp": true},
            "success_evidence": "after the owner approves and the same body is written again, users/<owner_address>/spot_state.json and clearinghouse.json show the moved USDC; read owner_address from wallets/<wallet>/<index>/address.evm"
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
        crate::usd_class_transfer(ctx, network, wallet, body)
    }
);
