petal::route_file!(
    spec: petal::signing_write_spec("hyperliquid.agent_action")
        .caps(&["bloom:http", "bloom:store", "bloom:sign"]),
    read: |_ctx: &petal::Ctx| {
        petal::read_json_value(&crate::serde_json::json!({
            "description": "write one or more bounded session orders; Bloom signs them with the stored agent key",
            "request_schema": {
                "action": {
                    "type": "order",
                    "orders": [{
                        "a": "unsigned integer asset id",
                        "b": "boolean; true buys and false sells",
                        "p": "positive decimal price string",
                        "s": "positive decimal size string",
                        "r": "boolean reduce-only flag",
                        "t": {"limit": {"tif": "Alo, Gtc, or Ioc"}},
                        "c": "optional 16-byte 0x client order id"
                    }],
                    "grouping": "na, normalTpsl, or positionTpsl",
                    "builder": "optional builder fee object"
                },
                "nonce": "optional unsigned integer; omit to let Bloom allocate a monotonic nonce",
                "vaultAddress": "optional lowercase 0x address",
                "expiresAfter": "optional Unix timestamp in milliseconds"
            },
            "example": {
                "action": {
                    "type": "order",
                    "orders": [{
                        "a": 0,
                        "b": true,
                        "p": "95000",
                        "s": "0.00011",
                        "r": false,
                        "t": {"limit": {"tif": "Alo"}},
                        "c": "0x00112233445566778899aabbccddeeff"
                    }],
                    "grouping": "na"
                }
            },
            "success_evidence": "after writing, require a new audit.jsonl order entry whose response reports resting; last_response.json alone may be stale"
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
        if !matches!(&request.action, crate::ExchangeAction::Order { .. }) {
            return petal::error(
                -3,
                format!(
                    "order.json cannot submit action type {}",
                    request.action.kind()
                ),
            );
        }
        crate::session_action_write(ctx, network, &wallet, session, request)
    }
);
