petal::route_file!(
    spec: petal::signing_write_spec("hyperliquid.set_abstraction")
        .caps(&["bloom:http", "bloom:store", "bloom:sign"]),
    read: |_ctx: &petal::Ctx| {
        petal::read_json_value(&crate::serde_json::json!({
            "description": "write a Hyperliquid userSetAbstraction request switching this account's mode; must be signed by the main wallet and may require Bloom approval. The current mode is readable at users/<account>/abstraction.json",
            "body": {
                "abstraction": "disabled (standard: spot and perp USDC are separate, usdSend and usdClassTransfer allowed), unifiedAccount (spot and perp USDC merged; the venue refuses usdSend and usdClassTransfer while active) or portfolioMargin",
                "user": "optional 0x account address, which must be this wallet's own address: Hyperliquid changes the mode of the signing account only. Required until this wallet has signed through this Petal once; omit it after that",
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
        crate::set_abstraction(ctx, network, wallet, body)
    }
);
