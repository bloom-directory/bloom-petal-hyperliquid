petal::route_file!(spec: petal::http_read_spec(), read: |ctx: &petal::Ctx| {
    let network = match petal::param(ctx, "network").and_then(|value| {
        crate::Network::parse(value).map_err(|error| petal::error(-3, error))
    }) {
        Ok(network) => network,
        Err(response) => return response,
    };
    crate::http_read_json(
        network,
        "/info",
        crate::serde_json::json!({"type": "spotMetaAndAssetCtxs"}),
    )
});
