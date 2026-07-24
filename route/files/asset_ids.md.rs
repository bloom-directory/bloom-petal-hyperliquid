petal::route_file!(spec: petal::static_read_spec(), read: |_ctx: &petal::Ctx| {
    petal::read_json_value(&"# Asset IDs\n\nPerpetual asset ids are returned by `perp_meta.json`; spot ids use Hyperliquid's documented 10000 + spot-index encoding.\n")
});
