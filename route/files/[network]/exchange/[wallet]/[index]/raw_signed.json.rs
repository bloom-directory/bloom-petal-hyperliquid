petal::route_file!(
    spec: petal::write_spec().caps(&["bloom:http", "bloom:store"]),
    read: |_ctx: &petal::Ctx| {
        petal::read_json_value(&crate::serde_json::json!({
            "description": "submit a pre-signed Hyperliquid action; Bloom validates and relays the supplied signature but does not create or approve it"
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
        let request = match crate::serde_json::from_slice::<crate::SignedSubmit>(body) {
            Ok(request) => request,
            Err(error) => return petal::error(-3, format!("invalid signed body: {error}")),
        };
        // A relayed signature skips every builder check: the fee is neither
        // bounded, nor approved, nor declared to the owner here, and the
        // order could be spot, a trigger or a crossing sell. Builder fees go
        // through the owner-signed route only.
        if request.action.carries_builder() {
            return petal::error(
                -3,
                "raw_signed.json cannot relay an order that carries a builder fee: nothing here bounds or declares the fee; write the unsigned body to builder_order.json instead",
            );
        }
        crate::submit_l1(
            network,
            wallet,
            request.action,
            request.nonce,
            request.signature,
            request.vault_address,
            request.expires_after,
        )
    }
);
