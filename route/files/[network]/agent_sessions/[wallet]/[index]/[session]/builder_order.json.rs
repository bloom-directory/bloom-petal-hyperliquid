petal::route_file!(
    spec: petal::signing_write_spec("hyperliquid.builder_order")
        .caps(&["bloom:http", "bloom:store", "bloom:sign"]),
    read: |_ctx: &petal::Ctx| {
        petal::read_json_value(&crate::serde_json::json!({
            "description": "UNAVAILABLE at the pinned Bloom contract: every call to this route is refused, and agent_sessions/[wallet]/[index]/new.json refuses the builder bound it would need. Builder fees are owner-signed only; write builder-bearing orders to exchange/[wallet]/[index]/builder_order.json. Two things must change in Bloom first: a derived key's scope must be narrowed to the classes it requested rather than the derivation being refused outright, and the reusable key-scope approval must carry value limits, or Broker denies the fee claim with VALUE_ASSET_NOT_ALLOWED. When this route works, it will write one or more bounded session orders carrying a builder fee, signed with the stored agent key under the fee-bearing hyperliquid.builder_order class.",
            "request_schema": {
                "action": {
                    "type": "order",
                    "orders": [{
                        "a": "unsigned integer asset id",
                        "b": "boolean; true buys and false sells. A sell must use tif Alo (post-only)",
                        "p": "positive decimal price string",
                        "s": "positive decimal size string",
                        "r": "boolean reduce-only flag",
                        "t": {"limit": {"tif": "Alo, Gtc, or Ioc for a buy; Alo only for a sell, because a sell that crosses the book fills above its limit and its builder fee cannot be bounded"}},
                        "c": "required client order id: 0x plus 32 hex digits, new for every order. This route's success evidence is keyed on it, so an order without one cannot be confirmed"
                    }],
                    "grouping": "na, normalTpsl, or positionTpsl",
                    "builder": {"b": "lowercase builder address; would have to match the session's builder_address, which cannot be set at the pinned contract", "f": "fee in tenths of a basis point, at most the session's max_builder_fee_tenths_bps and the venue cap"}
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
                    "grouping": "na",
                    "builder": {"b": "0x0000000000000000000000000000000000000001", "f": 10}
                }
            },
            "success_evidence": {
                "source": "immutable_correlated_exchange_receipt",
                "path_from_session_root": "receipts/<submitted_cloid>/order.json",
                "poll_interval_ms": 1000,
                "timeout_ms": 120000,
                "predicate": "receipt cloid equals the submitted order c field, request equals that submitted order item, and response.response.data.statuses[0] carries either resting.oid or filled.oid",
                "result": "the correlated response confirms venue acceptance: resting.oid is the venue order id of an order now on the book, filled.oid is the venue order id of one that matched immediately. A buy may do either, so treat both as success",
                "notes": "Submit a unique client order id. The create-only receipt records the original batch item and item_index, and its response statuses array contains only that item's positional venue status. It is scoped by session, action, and normalized cloid, so it cannot race last_response.json or be overwritten by a later action. An accepted filesystem write is asynchronous and dispatch can take longer than 30 seconds. The receipt path normally returns not-found until dispatch completes; treat that as pending, wait poll_interval_ms, and retry the same exact path until the predicate matches or timeout_ms expires. A status of error, or a rejection naming the order, is terminal: stop polling and report it rather than waiting out timeout_ms."
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
        let crate::ExchangeAction::Order { orders, .. } = &request.action else {
            return petal::error(
                -3,
                format!(
                    "builder_order.json cannot submit action type {}",
                    request.action.kind()
                ),
            );
        };
        if !request.action.carries_builder() {
            return petal::error(
                -3,
                "builder_order.json requires an order carrying a builder fee; write orders without one to order.json",
            );
        }
        if let Err(error) = crate::validate_order_cloids(orders) {
            return petal::error(-3, error);
        }
        // Checked after route fit, so a caller who sent the wrong action type
        // or a malformed order still learns that first.
        //
        // No session key carries the fee-bearing class at the pinned Bloom, and
        // `new.json` refuses the bound this route would check against, so every
        // call fails. Left to run on, the caller would reach `session_policy`
        // and be told the fee is "outside the session's approved builder
        // bound" -- true, but it reads as something a bound would fix, and no
        // bound can be set. `session_key_classes` in route/src/workflow.rs has
        // the two Bloom reasons; both are in README.md.
        if !crate::SESSION_BUILDER_FEES_AVAILABLE {
            return petal::error(
                -3,
                "session-signed builder fees are not available at the pinned Bloom contract; \
                 submit builder-bearing orders through the owner-signed \
                 exchange/[wallet]/[index]/builder_order.json route",
            );
        }
        crate::session_action_write(ctx, network, &wallet, session, request)
    }
);
