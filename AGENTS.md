# Hyperliquid Petal operating contract

Read `README.md` and inspect the target file before every write. Market and
account reads are best-effort POST requests to Hyperliquid's `/info` endpoint.

Exchange writes accept JSON bodies documented by `order.json`, `cancel.json`,
`cancel_by_cloid.json`, `schedule_cancel.json`, `update_leverage.json`,
`raw_signed.json`, `usd_send.json`, `usd_class_transfer.json`, and
`approve_builder_fee.json`. `usd_class_transfer.json` and
`approve_builder_fee.json` are owner-only, signed by the main wallet, and
deliberately absent from the delegated agent session surface. `send_asset.json`
is a deprecated alias for `usd_send.json`; it does not implement Hyperliquid's
generalized `sendAsset` action. `order.json` may carry an optional per-order
`builder` fee; it is signed only under an authorization claim that names the
builder address and exact fee, and a delegated session may use one only if it
was created with a matching `builder_address`/`max_builder_fee_tenths_bps`
bound. Owner-signed actions may return an approval-required error;
retry the exact same body after completing the Bloom ceremony. Agent sessions
are created through `agent_sessions/<wallet>/new.json` with a stable `id` and
must be inspected through their `status.json`, `last_response.json`, and
`last_error.json` files.

Route files own their parameter parsing, `/info` request bodies, response
projection, read descriptions, write-action compatibility, and endpoint
selection. Do not add catch-all `read` or `write` functions that inspect the
current route path, filename, or suffix. Keep shared route code limited to
typed protocol logic and substantial infrastructure such as HTTP, signing,
storage, idempotency, session policy, and multi-step exchange operations.

Run `scripts/check-route-architecture.sh` after changing route files or shared
route code.

Never infer that a staged transaction, approval challenge, or accepted route
write means a broadcast or fill completed. Do not use mainnet with material
funds without explicit authorization.
