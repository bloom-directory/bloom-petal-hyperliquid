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
    let interval = match petal::param(ctx, "interval") {
        Ok(interval) => interval,
        Err(response) => return response,
    };
    let interval_ms = match interval {
        "1m" => 60_000_u64,
        "3m" => 3 * 60_000,
        "5m" => 5 * 60_000,
        "15m" => 15 * 60_000,
        "30m" => 30 * 60_000,
        "1h" => 60 * 60_000,
        "2h" => 2 * 60 * 60_000,
        "4h" => 4 * 60 * 60_000,
        "8h" => 8 * 60 * 60_000,
        "12h" => 12 * 60 * 60_000,
        "1d" => 24 * 60 * 60_000,
        "3d" => 3 * 24 * 60 * 60_000,
        "1w" => 7 * 24 * 60 * 60_000,
        "1M" => 30 * 24 * 60 * 60_000,
        _ => return petal::error(-3, format!("unsupported candle interval {interval}")),
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
                "startTime": end.saturating_sub(interval_ms.saturating_mul(500)),
                "endTime": end
            }
        }),
    )
});
