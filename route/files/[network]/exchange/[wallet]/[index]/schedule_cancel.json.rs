petal::route_file!(
    spec: petal::signing_write_spec("hyperliquid.schedule_cancel")
        .caps(&["bloom:http", "bloom:store", "bloom:sign"]),
    read: |_ctx: &petal::Ctx| {
        petal::read_json_value(&crate::serde_json::json!({
            "description": "schedule or clear Hyperliquid's dead-man's-switch cancellation as the wallet owner; the first write stages it for the owner's Bloom approval and fails with approval required; after the owner approves, write the exact same body again to submit it",
            "request_schema": {
                "action": {"type": "scheduleCancel", "time": "optional Unix timestamp in milliseconds; omit to clear the schedule"},
                "nonce": "optional; omit it and Bloom allocates one. If set, it must be the current Unix time in milliseconds",
                "vaultAddress": "optional 0x vault or subaccount address",
                "expiresAfter": "optional Unix timestamp in milliseconds"
            },
            "examples": {
                "schedule": {"action": {"type": "scheduleCancel", "time": "<Unix ms at least 5 seconds from now>"}},
                "clear": {"action": {"type": "scheduleCancel"}}
            },
            "success_evidence": "after the repeated write, last_response.json has status ok; it holds only the latest owner exchange response for this account"
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
            crate::ExchangeAction::ScheduleCancel { .. }
        ) {
            return petal::error(
                -3,
                format!(
                    "schedule_cancel.json cannot submit action type {}",
                    request.action.kind()
                ),
            );
        }
        crate::owner_action_write(
            ctx,
            network,
            wallet,
            "schedule_cancel.json",
            body,
            request,
        )
    }
);
