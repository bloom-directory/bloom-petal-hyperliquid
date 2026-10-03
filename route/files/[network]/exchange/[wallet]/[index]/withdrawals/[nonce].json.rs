petal::route_file!(spec: petal::store_read_spec(), read: |ctx: &petal::Ctx| {
    let network = match petal::param(ctx, "network").and_then(|value| {
        crate::Network::parse(value).map_err(|error| petal::error(-3, error))
    }) {
        Ok(network) => network,
        Err(response) => return response,
    };
    let wallet = match petal::param(ctx, "wallet").and_then(|value| {
        crate::parse_wallet_id(value).map_err(|error| petal::error(-3, error))
    }) {
        Ok(wallet) => wallet,
        Err(response) => return response,
    };
    let nonce = match petal::param(ctx, "nonce").and_then(|value| {
        value
            .parse::<u64>()
            .map_err(|_| petal::error(-3, "withdrawal nonce must be a plain decimal number"))
    }) {
        Ok(nonce) => nonce,
        Err(response) => return response,
    };
    crate::withdraw_record(network, &wallet, nonce)
});
