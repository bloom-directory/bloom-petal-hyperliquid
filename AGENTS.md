# Hyperliquid Petal operating contract

Read `README.md` and inspect the target file before every write. Market and
account reads are best-effort POST requests to Hyperliquid's `/info` endpoint.

Exchange writes accept JSON bodies documented by `order.json`, `cancel.json`,
`cancel_by_cloid.json`, `schedule_cancel.json`, `update_leverage.json`,
`raw_signed.json`, `usd_send.json`, and `usd_class_transfer.json`.
`usd_class_transfer.json` moves USDC between the wallet's own spot and perp
engines and is owner-only; it is deliberately absent from the delegated agent
session surface. `send_asset.json` is a deprecated alias
for `usd_send.json`; it does not implement Hyperliquid's generalized
`sendAsset` action. Owner-signed actions may return an approval-required error;
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
