petal::route_file!(
    spec: petal::signing_write_spec("hyperliquid.cancel_by_cloid")
        .caps(&["bloom:http", "bloom:store", "bloom:sign"]),
    read: |_ctx: &petal::Ctx| {
        petal::read_json_value(&crate::serde_json::json!({
            "description": "cancel orders as the wallet owner by client order id; the first write stages it for the owner's Bloom approval and fails with approval required; after the owner approves, write the exact same body again to submit it",
            "request_schema": {
                "action": {
                    "type": "cancelByCloid",
                    "cancels": [{"asset": "the order's asset index (see order.json)", "cloid": "16-byte 0x client order id"}]
                },
                "nonce": "optional; omit it and Bloom allocates one. If set, it must be the current Unix time in milliseconds",
                "vaultAddress": "optional 0x vault or subaccount address",
                "expiresAfter": "optional Unix timestamp in milliseconds"
            },
            "example": {"action": {"type": "cancelByCloid", "cancels": [{"asset": 0, "cloid": "0x00112233445566778899aabbccddeeff"}]}},
            "success_evidence": {
                "path_from_bloom_root": "petals/hyperliquid/<network>/users/<owner_address>/open_orders.json",
                "predicate": "no open order has the canceled cloid",
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
            crate::ExchangeAction::CancelByCloid { .. }
        ) {
            return petal::error(
                -3,
                format!(
                    "cancel_by_cloid.json cannot submit action type {}",
                    request.action.kind()
                ),
            );
        }
        crate::owner_action_write(
            ctx,
            network,
            wallet,
            "cancel_by_cloid.json",
            body,
            request,
        )
    }
);
