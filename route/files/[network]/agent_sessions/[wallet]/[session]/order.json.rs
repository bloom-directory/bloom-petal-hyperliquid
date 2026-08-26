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
                    "builder": "unsupported because delegated claims cannot represent an exact builder fee"
                },
                "nonce": "optional unsigned integer; omit to let Bloom allocate a monotonic nonce",
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
            "success_evidence": {
                "source": "immutable_correlated_exchange_receipt",
                "path_from_session_root": "receipts/<submitted_cloid>/order.json",
                "poll_interval_ms": 1000,
                "timeout_ms": 120000,
                "predicate": "receipt cloid equals the submitted order c field, request equals that submitted order item, and response.response.data.statuses[0].resting.oid exists",
                "result": "the correlated resting response confirms venue acceptance and its oid is the venue order id",
                "notes": "Submit a unique client order id. The create-only receipt records the original batch item and item_index, and its response statuses array contains only that item's positional venue status. It is scoped by session, action, and normalized cloid, so it cannot race last_response.json or be overwritten by a later action. An accepted filesystem write is asynchronous and dispatch can take longer than 30 seconds; keep polling the exact receipt path for the full timeout."
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
