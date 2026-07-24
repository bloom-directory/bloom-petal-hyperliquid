petal::route_file!(spec: petal::static_read_spec(), read: |_ctx: &petal::Ctx| {
    petal::read_json_value(&"# Hyperliquid Petal\n\nReads use Hyperliquid /info. Writes are signed through Bloom and persisted under inspectable response/status files. Exchange writes cover order, cancel, cancel-by-cloid, schedule-cancel, leverage, raw signed, and `usd_send.json`. The deprecated `send_asset.json` route is a compatibility alias for `usdSend`, not Hyperliquid's generalized `sendAsset` action. Agent sessions provide bounded owner-approved trading, cancel-all, close-all, and audit.\n")
});
