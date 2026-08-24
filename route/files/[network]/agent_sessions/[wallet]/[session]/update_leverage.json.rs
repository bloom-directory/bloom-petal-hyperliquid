petal::route_file!(
    spec: petal::signing_write_spec("hyperliquid.agent_action")
        .caps(&["bloom:http", "bloom:store", "bloom:sign"]),
    read: |_ctx: &petal::Ctx| {
        petal::read_json_value(&crate::serde_json::json!({
            "description": "write a bounded session leverage update; Bloom signs it with the stored agent key",
            "request_schema": {
                "action": {
                    "type": "updateLeverage",
                    "asset": "unsigned integer asset id",
                    "isCross": "boolean",
                    "leverage": "unsigned integer from 1 through the session maximum"
                },
                "nonce": "optional unsigned integer; omit to let Bloom allocate a monotonic nonce",
                "vaultAddress": "optional lowercase 0x address",
                "expiresAfter": "optional Unix timestamp in milliseconds"
            },
            "example": {
                "action": {
                    "type": "updateLeverage",
                    "asset": 0,
                    "isCross": true,
                    "leverage": 1
                }
            },
            "success_evidence": "after writing, require a new audit.jsonl entry whose action is updateLeverage; last_response.json alone may be stale"
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
        let session = match petal::param(ctx, "session") {
            Ok(session) => session,
            Err(response) => return response,
        };
        let request = match crate::serde_json::from_slice::<crate::SignSubmit>(body) {
            Ok(request) => request,
            Err(error) => return petal::error(-3, format!("invalid session action: {error}")),
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
        crate::session_action_write(ctx, network, &wallet, session, request)
    }
);
