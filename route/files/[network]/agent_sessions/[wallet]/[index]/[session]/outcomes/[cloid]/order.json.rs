petal::route_file!(spec: petal::store_read_spec(), read: |ctx: &petal::Ctx| {
    let network = match petal::param(ctx, "network").and_then(|v| crate::Network::parse(v).map_err(|e| petal::error(-3,e))) { Ok(v) => v, Err(e) => return e };
    let wallet = match petal::param(ctx, "wallet").and_then(|v| crate::parse_wallet_id(v).map_err(|e| petal::error(-3,e))) { Ok(v) => v, Err(e) => return e };
    let session = match petal::param(ctx, "session") { Ok(v) => v, Err(e) => return e };
    let cloid = match petal::param(ctx, "cloid") { Ok(v) => v, Err(e) => return e };
    match crate::load_session_outcome(network, &wallet, session, cloid, "order") {
        Ok(Some(outcome)) => petal::read_json_value(&outcome),
        Ok(None) => petal::error(-1, "order outcome not found"),
        Err(e) => e,
    }
});
