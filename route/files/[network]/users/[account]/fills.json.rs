petal::route_file!(
    spec: petal::account_read_spec().caps(&["bloom:http"]),
    read: |ctx: &petal::Ctx| {
        let network = match petal::param(ctx, "network").and_then(|value| {
            crate::Network::parse(value).map_err(|error| petal::error(-3, error))
        }) {
            Ok(network) => network,
            Err(response) => return response,
        };
        let account = match petal::param(ctx, "account").and_then(|value| {
            crate::parse_address(value)
                .map(|address| format!("{address:#x}"))
                .map_err(|error| petal::error(-3, error))
        }) {
            Ok(account) => account,
            Err(response) => return response,
        };
        crate::http_read_json(
            network,
            "/info",
            crate::serde_json::json!({"type": "userFills", "user": account}),
        )
    }
);
