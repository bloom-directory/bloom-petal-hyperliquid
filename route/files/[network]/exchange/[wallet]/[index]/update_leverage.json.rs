petal::route_file!(
    spec: petal::signing_write_spec("hyperliquid.update_leverage")
        .caps(&["bloom:http", "bloom:store", "bloom:sign"]),
    read: |_ctx: &petal::Ctx| {
        petal::read_json_value(&crate::serde_json::json!({
            "description": "update leverage as the wallet owner; the first write stages it for the owner's Bloom approval and fails with approval required; after the owner approves, write the exact same body again to submit it",
            "request_schema": {
                "action": {
                    "type": "updateLeverage",
                    "asset": "asset index (see order.json)",
                    "isCross": "boolean",
                    "leverage": "unsigned integer"
                },
                "nonce": "optional; omit it and Bloom allocates one. If set, it must be the current Unix time in milliseconds",
                "vaultAddress": "optional 0x vault or subaccount address",
                "expiresAfter": "optional Unix timestamp in milliseconds"
            },
            "example": {"action": {"type": "updateLeverage", "asset": 0, "isCross": true, "leverage": 1}},
            "success_evidence": {
                "path_from_bloom_root": "petals/hyperliquid/<network>/users/<owner_address>/active_asset_data/BTC.json",
                "predicate": "leverage.type and leverage.value match the request; replace BTC with the coin",
                "notes": "Read owner_address from wallets/<wallet>/<index>/address.evm"
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
        let request = match crate::serde_json::from_slice::<crate::SignSubmit>(body) {
            Ok(request) => request,
            Err(error) => return petal::error(-3, format!("invalid exchange body: {error}")),
        };
        if !matches!(
            &request.action,
            crate::ExchangeAction::UpdateLeverage { .. }
        ) {
            return petal::error(
                -3,
                format!(
                    "update_leverage.json cannot submit action type {}",
                    request.action.kind()
                ),
            );
        }
        crate::owner_action_write(
            ctx,
            network,
            wallet,
            "update_leverage.json",
            body,
            request,
        )
    }
);
