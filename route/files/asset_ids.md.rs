petal::route_file!(spec: petal::read_spec(), read: |_ctx: &petal::Ctx| {
    petal::read_json(&"# Asset IDs\n\nPerpetual asset ids are returned by `perp_meta.json`; spot ids use Hyperliquid's documented 10000 + spot-index encoding.\n")
});
