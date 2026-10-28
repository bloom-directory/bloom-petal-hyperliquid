petal::route_file!(
    spec: petal::signing_write_spec("hyperliquid.order")
        .caps(&["bloom:http", "bloom:store", "bloom:sign"]),
    read: |_ctx: &petal::Ctx| {
        petal::read_json_value(&crate::serde_json::json!({
            "description": "write a Hyperliquid order as the wallet owner; the first write stages it for the owner's Bloom approval and fails with approval required; after the owner approves, write the exact same body again to submit it",
            "request_schema": {
                "action": {
                    "type": "order",
                    "orders": [{
                        "a": "unsigned integer asset index: a perpetual's position in the universe array of <network>/perp_meta.json for the same network (mainnet and testnet differ), or 10000 + its index in <network>/spot_meta.json for spot",
                        "b": "boolean; true buys and false sells",
                        "p": "positive decimal price string",
                        "s": "positive decimal size string",
                        "r": "boolean reduce-only flag",
                        "t": {"limit": {"tif": "Alo (post-only), Gtc, or Ioc"}},
                        "c": "optional 16-byte 0x client order id"
                    }],
                    "grouping": "na, normalTpsl, or positionTpsl"
                },
                "nonce": "optional; omit it and Bloom allocates one. If set, it must be the current Unix time in milliseconds",
                "vaultAddress": "optional 0x vault or subaccount address",
                "expiresAfter": "optional Unix timestamp in milliseconds"
            },
            "example": {
                "action": {
                    "type": "order",
                    "orders": [{
                        "a": "<replace with the coin's index in <network>/perp_meta.json>",
                        "b": true,
                        "p": "95000",
                        "s": "0.0002",
                        "r": false,
                        "t": {"limit": {"tif": "Alo"}},
                        "c": "0x00112233445566778899aabbccddeeff"
                    }],
                    "grouping": "na"
                }
            },
            "success_evidence": {
                "staged": "the first write fails with permission denied naming approval required for exchange: the order waits for the owner and is not submitted",
                "path_from_bloom_root": "petals/hyperliquid/<network>/users/<owner_address>/open_orders.json",
                "predicate": "after approval and the repeated write, an open order has the submitted cloid, or the submitted coin, side, limitPx and sz",
                "notes": "Read owner_address from wallets/<wallet>/<index>/address.evm. last_response.json holds only the latest owner exchange response for this account"
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
        if !matches!(&request.action, crate::ExchangeAction::Order { .. }) {
            return petal::error(
                -3,
                format!(
                    "order.json cannot submit action type {}",
                    request.action.kind()
                ),
            );
        }
        crate::owner_action_write(ctx, network, wallet, "order.json", body, request)
    }
);
