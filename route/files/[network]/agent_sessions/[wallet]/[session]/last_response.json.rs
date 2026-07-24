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
    let session = match petal::param(ctx, "session") {
        Ok(session) => session,
        Err(response) => return response,
    };
    match crate::load_session_response(network, &wallet, session) {
        Ok(Some(response)) => petal::read_json_value(&response),
        Ok(None) => petal::error(-3, "no session response"),
        Err(response) => response,
    }
});
