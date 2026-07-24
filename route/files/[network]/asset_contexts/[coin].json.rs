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
    let response = match crate::http_json(
        network,
        "/info",
        crate::serde_json::json!({"type": "metaAndAssetCtxs"}),
    ) {
        Ok(response) => response,
        Err(response) => return response,
    };
    if let Some(parts) = response.as_array()
        && let (Some(meta), Some(contexts)) = (parts.first(), parts.get(1))
        && let (Some(universe), Some(contexts)) = (
            meta.get("universe").and_then(crate::serde_json::Value::as_array),
            contexts.as_array(),
        )
        && let Some((index, asset)) = universe.iter().enumerate().find(|(_, asset)| {
            asset.get("name").and_then(crate::serde_json::Value::as_str) == Some(coin)
        })
    {
        return petal::read_json_value(&crate::serde_json::json!({
            "meta": asset,
            "context": contexts.get(index).cloned().unwrap_or(crate::serde_json::Value::Null)
        }));
    }
    petal::read_json_value(&crate::serde_json::json!({"coin": coin, "found": false}))
});
