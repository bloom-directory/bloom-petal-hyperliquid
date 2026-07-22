# Hyperliquid Petal operating contract

Read `README.md` and inspect the target file before every write. Market and
account reads are best-effort POST requests to Hyperliquid's `/info` endpoint.

Exchange writes accept JSON bodies documented by `order.json`, `cancel.json`,
`schedule_cancel.json`, `update_leverage.json`, `raw_signed.json`, and
`send_asset.json`. Owner-signed actions may return an approval-required error;
retry the exact same body after completing the Bloom ceremony. Agent sessions
are created through `agent_sessions/<wallet>/new.json` with a stable `id` and must be inspected
through their `status.json`, `last_response.json`, and `last_error.json` files.

Never infer that a staged transaction, approval challenge, or accepted route
write means a broadcast or fill completed. Do not use mainnet with material
funds without explicit authorization.
