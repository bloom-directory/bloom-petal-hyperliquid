petal::route_file!(spec: petal::http_read_spec(5_000), read: |ctx: &petal::Ctx| {
    let network = match petal::param(ctx, "network").and_then(|value| {
        crate::Network::parse(value).map_err(|error| petal::error(-3, error))
    }) {
        Ok(network) => network,
        Err(response) => return response,
    };
    let coin = match petal::param(ctx, "coin") {
        Ok(coin) => coin,
        Err(response) => return response,
    };
    let end = petal::sdk::now_ms();
    crate::http_read_json(
        network,
        "/info",
        crate::serde_json::json!({
            "type": "fundingHistory",
            "coin": coin,
            "startTime": end.saturating_sub(86_400_000),
            "endTime": end
        }),
    )
});
