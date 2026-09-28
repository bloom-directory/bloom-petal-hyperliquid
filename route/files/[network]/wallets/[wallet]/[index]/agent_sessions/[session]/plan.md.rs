petal::route_file!(spec: petal::static_read_spec(), read: |ctx: &petal::Ctx| {
    let wallet = match petal::param(ctx, "wallet").and_then(|value| {
        crate::parse_wallet_id(value).map_err(|error| petal::error(-3, error))
    }) {
        Ok(wallet) => wallet,
        Err(response) => return response,
    };
    let session = match petal::param(ctx, "session") {
        Ok(session) => session,
        Err(response) => return response,
    };
    petal::read_json_value(&format!(
        "# Hyperliquid agent session\n\n- Wallet: `{wallet}`\n- Session: `{session}`\n\nThe session key is retained only in Bloom's private store.\n"
    ))
});
