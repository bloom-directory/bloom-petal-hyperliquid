petal::route_file!(
    spec: petal::signing_write_spec("hyperliquid.order")
        .caps(&["bloom:http", "bloom:store", "bloom:sign"]),
    read: |_ctx: &petal::Ctx| {
        // The complete request shape, so an agent never has to read this
        // package's source to place an order.
        petal::read_json_value(&crate::serde_json::json!({
            "description": "Write this JSON to place an owner-signed order. When owner approval is needed the write fails with an approval-required error and records the signing request; give its ceremony to the owner, then write the exact same body again. Nothing is sent until the owner approves.",
            "example": {
                "action": {
                    "type": "order",
                    "orders": [{
                        "a": 3,
                        "b": true,
                        "p": "76704",
                        "s": "0.00015",
                        "r": false,
                        "t": {"limit": {"tif": "Alo"}}
                    }],
                    "grouping": "na"
                }
            },
            "fields": {
                "a": "asset index: the coin's position in <network>/perp_meta.json universe (also listed in asset_ids.md); mainnet and testnet differ",
                "b": "true buys, false sells",
                "p": "limit price as a decimal string with at most 5 significant figures; <network>/mids.json has the current mark",
                "s": "size in the coin as a decimal string with at most szDecimals decimals (from perp_meta.json)",
                "r": "reduce-only",
                "t": "{\"limit\":{\"tif\":\"Gtc\"}} rests, \"Ioc\" fills what it can immediately, \"Alo\" is post-only; or {\"trigger\":{\"isMarket\":…,\"triggerPx\":…,\"tpsl\":…}}",
                "c": "optional client order id, 16 bytes as 0x hex",
                "grouping": "\"na\" for plain orders",
                "nonce": "omit it; the Petal uses the current time in milliseconds",
                "expiresAfter": "optional expiry in milliseconds since the epoch"
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
