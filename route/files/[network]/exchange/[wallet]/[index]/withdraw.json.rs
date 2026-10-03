petal::route_file!(
    spec: petal::signing_write_spec("hyperliquid.withdraw")
        .caps(&["bloom:http", "bloom:store", "bloom:sign"]),
    read: |_ctx: &petal::Ctx| {
        petal::read_json_value(&crate::serde_json::json!({
            "description": "write an owner-approved Hyperliquid withdraw3 withdrawal that debits USDC from this account and settles on Arbitrum; owner signing may require Bloom approval. The venue deducts its flat fee (1 USDC as of writing) from the withdrawn amount, so the destination receives the amount minus the fee. Venue acceptance is not settlement proof; confirm with the withdrawal ledger and the Arbitrum transaction. Withdrawals are owner-only and are never available to delegated agent sessions",
            "body": {
                "destination": "non-zero 0x-prefixed destination address on Arbitrum",
                "amount": "positive USDC decimal with at most 6 decimal places that exceeds the venue withdrawal fee",
                "nonce": "optional timestamp in milliseconds; retries of the same body reuse the recorded operation"
            },
            "records": "withdrawals/ lists every recorded withdrawal; withdrawals/<nonce>.json is the durable operation record (action, nonce, status approval_pending/submitted/accepted/rejected, venue response). status accepted means venue acceptance, never settlement proof"
        }))
    },
    write: |ctx: &petal::Ctx, body: &[u8]| {
        if let Err(response) = crate::validate_body_size(body) {
            return response;
        }
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
        crate::withdraw(ctx, network, wallet, body)
    }
);
