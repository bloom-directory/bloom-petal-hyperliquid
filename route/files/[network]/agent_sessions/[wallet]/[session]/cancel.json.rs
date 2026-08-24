petal::route_file!(
    spec: petal::signing_write_spec("hyperliquid.agent_action")
        .caps(&["bloom:http", "bloom:store", "bloom:sign"]),
    read: |_ctx: &petal::Ctx| {
        petal::read_json_value(&crate::serde_json::json!({
            "description": "cancel bounded session orders by venue order id or client order id; Bloom signs the action with the stored agent key",
            "request_schema": {
                "action": "a cancel or cancelByCloid object matching one of the examples",
                "nonce": "optional unsigned integer; omit to let Bloom allocate a monotonic nonce",
                "vaultAddress": "optional lowercase 0x address",
                "expiresAfter": "optional Unix timestamp in milliseconds"
            },
            "examples": {
                "by_order_id": {
                    "action": {
                        "type": "cancel",
                        "cancels": [{"a": 0, "o": 123456789}]
                    }
                },
                "by_client_order_id": {
                    "action": {
                        "type": "cancelByCloid",
                        "cancels": [{
                            "asset": 0,
                            "cloid": "0x00112233445566778899aabbccddeeff"
                        }]
                    }
                }
            },
            "success_evidence": {
                "source": "live_venue_state",
                "path_from_bloom_root": "petals/hyperliquid/<network>/users/<owner_address>/open_orders.json",
                "poll_interval_ms": 1000,
                "timeout_ms": 120000,
                "predicate": "no open-order entry has the canceled oid or cloid",
                "notes": "Read owner_address from session.json. An accepted filesystem write is asynchronous and dispatch can take longer than 30 seconds; keep polling for the full timeout until the predicate matches. Do not use last_response.json as evidence for the current action."
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
        if !matches!(
            &request.action,
            crate::ExchangeAction::Cancel { .. } | crate::ExchangeAction::CancelByCloid { .. }
        ) {
            return petal::error(
                -3,
                format!(
                    "cancel.json cannot submit action type {}",
                    request.action.kind()
                ),
            );
        }
        crate::session_action_write(ctx, network, &wallet, session, request)
    }
);
