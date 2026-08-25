petal::route_file!(
    spec: petal::signing_write_spec("hyperliquid.agent_action")
        .caps(&["bloom:http", "bloom:store", "bloom:sign"]),
    read: |_ctx: &petal::Ctx| {
        petal::read_json_value(&crate::serde_json::json!({
            "description": "schedule or clear Hyperliquid dead-man's-switch cancellation; Bloom signs it with the stored agent key",
            "request_schema": {
                "action": {
                    "type": "scheduleCancel",
                    "time": "optional Unix timestamp in milliseconds; omit to clear the schedule"
                },
                "nonce": "optional unsigned integer; omit to let Bloom allocate a monotonic nonce",
                "expiresAfter": "optional Unix timestamp in milliseconds"
            },
            "examples": {
                "schedule": {
                    "action": {"type": "scheduleCancel", "time": 1730000000000_u64}
                },
                "clear": {
                    "action": {"type": "scheduleCancel"}
                }
            },
            "success_evidence": "after writing, require a new audit.jsonl entry whose action is scheduleCancel; last_response.json alone may be stale"
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
        crate::session_action_write(ctx, network, &wallet, session, request)
    }
);
