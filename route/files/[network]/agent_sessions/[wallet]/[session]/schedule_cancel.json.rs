petal::route_file!(
    spec: petal::write_spec().caps(&["bloom:http", "bloom:store"]),
    read: |_ctx: &petal::Ctx| {
        petal::read_json_value(&crate::serde_json::json!({
            "description": "write a bounded session schedule_cancel.json request; it is signed by the stored agent key"
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
        crate::session_action_write(network, &wallet, session, request)
    }
);
