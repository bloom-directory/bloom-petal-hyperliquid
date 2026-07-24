petal::route_file!(spec: petal::read_spec(), read: |_ctx: &petal::Ctx| {
    petal::read_json(&"# Hyperliquid Petal\n\nReads use Hyperliquid /info. Writes are signed through Bloom and persisted under inspectable response/status files. Exchange writes cover order, cancel, cancel-by-cloid, schedule-cancel, leverage, raw signed, and usdSend. Agent sessions provide bounded owner-approved trading, cancel-all, close-all, and audit.\n")
});
