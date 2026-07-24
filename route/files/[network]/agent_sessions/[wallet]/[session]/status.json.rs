petal::route_file!(spec: petal::store_read_spec(), read: |ctx: &petal::Ctx| {
    let network = match petal::param(ctx, "network").and_then(|value| {
        crate::Network::parse(value).map_err(|error| petal::error(-3, error))
    }) {
        Ok(network) => network,
        Err(response) => return response,
    };
    let wallet = match petal::param(ctx, "wallet").and_then(|value| {
        crate::parse_address(value)
            .map(|address| format!("{address:#x}"))
            .map_err(|error| petal::error(-3, error))
    }) {
        Ok(wallet) => wallet,
        Err(response) => return response,
    };
    let session_id = match petal::param(ctx, "session") {
        Ok(session) => session,
        Err(response) => return response,
    };
    match crate::load_session(network, &wallet, session_id) {
        Ok(Some(session)) => petal::read_json(&crate::serde_json::json!({
            "id": session.id,
            "wallet": session.wallet,
            "network": session.network,
            "agent_address": session.agent_address,
            "created_ms": session.created_ms,
            "expires_ms": session.expires_ms,
            "stopped": session.stopped,
            "max_notional_usd": session.max_notional_usd,
            "max_leverage": session.max_leverage,
            "assets": session.assets,
            "last_error": session.last_error
        })),
        Ok(None) => petal::error(-1, "session not found"),
        Err(response) => response,
    }
});
