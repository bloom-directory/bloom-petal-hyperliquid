petal::route_file!(spec: petal::http_read_spec(), read: |ctx: &petal::Ctx| {
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
    let interval = match petal::param(ctx, "interval") {
        Ok(interval) => interval,
        Err(response) => return response,
    };
    let end = petal::sdk::now_ms();
    crate::http_read_json(
        network,
        "/info",
        crate::serde_json::json!({
            "type": "candleSnapshot",
            "req": {
                "coin": coin,
                "interval": interval,
                "startTime": end.saturating_sub(3_600_000),
                "endTime": end
            }
        }),
    )
});
