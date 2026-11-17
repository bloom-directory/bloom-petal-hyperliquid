petal::route_file!(
    spec: petal::signing_write_spec("hyperliquid.order")
        .caps(&["bloom:http", "bloom:store", "bloom:sign"]),
    read: |_ctx: &petal::Ctx| {
        let example = |raw: &str| crate::serde_json::from_str::<crate::serde_json::Value>(raw).unwrap_or_default();
        petal::read_json_value(&crate::serde_json::json!({
            "description": "Write one JSON object to place owner-signed orders. Unknown fields are rejected. When owner approval is needed the write fails with an approval-required error; give its ceremony to the owner, then write the exact same body again. Nothing is sent until the owner approves.",
            "limit_example": example(r#"{"action":{"type":"order","orders":[{"a":3,"b":true,"p":"76704","s":"0.00015","r":false,"t":{"limit":{"tif":"Alo"}},"c":"0x0000000000000000000000000000a001"}],"grouping":"na"}}"#),
            "take_profit_example": example(r#"{"action":{"type":"order","orders":[{"a":3,"b":false,"p":"80000","s":"0.00015","r":true,"t":{"trigger":{"isMarket":true,"triggerPx":"80000","tpsl":"tp"}},"c":"0x0000000000000000000000000000a002"}],"grouping":"positionTpsl"}}"#),
            "top_level": {
                "action": "required: {type: \"order\", orders, grouping}",
                "vaultAddress": "optional 0x address of a vault or subaccount to trade for; it is signed. Omit to trade the selected account",
                "nonce": "optional unsigned integer in milliseconds. Omit it; the Petal reserves one and reuses it when you retry the same body",
                "expiresAfter": "optional; the venue rejects the action after this time in milliseconds since the epoch"
            },
            "action": {
                "orders": "required non-empty list; one request may hold several orders while the owner review stays under 256 fields",
                "grouping": "required: \"na\" for independent orders, \"normalTpsl\" for an entry followed by its TP/SL orders, \"positionTpsl\" for TP/SL on the open position",
                "builder": "rejected: builder fees are not supported"
            },
            "order": {
                "a": "required asset id: a perp's index in <network>/perp_meta.json universe; a spot pair is 10000 + its index in <network>/spot_meta.json. Mainnet and testnet differ",
                "b": "required: true buys, false sells",
                "p": "required price as a decimal string. Integers are always allowed; otherwise at most 5 significant figures and at most 6 - szDecimals decimal places for perps, 8 - szDecimals for spot. <network>/mids.json has current mids",
                "s": "required size in the coin (not USD) as a decimal string with at most szDecimals decimals, from perp_meta.json or spot_meta.json",
                "r": "required reduce-only flag",
                "t": "required, exactly one of {\"limit\":{\"tif\":\"Gtc\"|\"Ioc\"|\"Alo\"}} or {\"trigger\":{\"isMarket\":bool,\"triggerPx\":decimal string,\"tpsl\":\"tp\"|\"sl\"}}. Gtc fills what crosses now and rests the remainder; Ioc fills what it can now and cancels the rest; Alo only rests and is rejected if it would cross",
                "c": "required client order id: 0x plus 32 hex digits, new for every order. The Petal refuses a repeat only within one request; reusing one from an earlier request is accepted, and then c no longer identifies this order. Use it to find the order in users/<account>/frontend_open_orders.json and fills.json"
            },
            "uncertain_outcome": "If a write fails after approval, the order may still have reached Hyperliquid. Write the same body again (the same nonce can never execute twice), or reconcile by c before writing anything with a new nonce: a new nonce is a new order. Reconciling by c is only reliable if no earlier request used the same c."
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
        let crate::ExchangeAction::Order { orders, .. } = &request.action else {
            return petal::error(
                -3,
                format!(
                    "order.json cannot submit action type {}",
                    request.action.kind()
                ),
            );
        };
        if request.action.carries_builder() {
            return petal::error(
                -3,
                "order.json cannot carry a builder fee; write the same body to builder_order.json, which signs under the fee-bearing hyperliquid.builder_order class",
            );
        }
        if let Err(error) = crate::validate_order_cloids(orders) {
            return petal::error(-3, error);
        }
        crate::owner_action_write(ctx, network, wallet, "order.json", body, request)
    }
);
