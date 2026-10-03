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
generalized `sendAsset` action. An order carrying a per-order `builder` fee is
written to `builder_order.json` (owner-signed, or through the session route of
the same name), which signs under `hyperliquid.builder_order`, the Petal's only
fee-bearing operation class; `order.json` refuses a builder. It is signed only
under an authorization claim that names the builder address and exact fee,
and a delegated session may use one only if it was created with a matching
`builder_address`/`max_builder_fee_tenths_bps` bound, which is also what adds
the builder-order route and class to that session key's scope. Owner-signed actions may return an approval-required error;

`withdraw.json`.
`usd_class_transfer.json` moves USDC between the wallet's own spot and perp
engines and is owner-only; it is deliberately absent from the delegated agent
session surface. `send_asset.json` is a deprecated alias
for `usd_send.json`; it does not implement Hyperliquid's generalized
`sendAsset` action. `withdraw.json` submits Hyperliquid's `withdraw3`
action: it debits the gross amount from the account's withdrawable USDC and
settles on Arbitrum minus the venue's flat fee, so venue acceptance is never
settlement proof. Operation records are listed at `withdrawals/` and readable
at `withdrawals/<nonce>.json`; while a record is `submitted` (outcome
uncertain), never resubmit — reconcile through the record and venue reads. A
nonce is bound to its exact action: reusing it for a different body is
rejected, not treated as a retry. Owner-signed actions may return an approval-required error;
retry the exact same body after completing the Bloom ceremony. Agent sessions
are created through `agent_sessions/new.json` with a stable `id` and
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

## Account-scoped routes

Select a wallet and numbered account under `/petals/hyperliquid/<network>/{exchange,agent_sessions}/<wallet>/<index>/`. Market reads and `users/<account>/` address reads remain public under the network; `[account]` means an on-chain address and is distinct from `[index]`.

`[wallet]` and adjacent `[index]` are explicit route captures. Bloom resolves them against the live core wallet projection and supplies trusted `bloom.wallet` and `bloom.account` context. Every numbered account, including 0, has a separate private store. Legacy unnumbered settings and sessions are not carried into account 0. The core wallet tree remains `/wallets/<wallet>/<index>/`.


Before upgrading from routes without `[index]`, finish and reconcile pending operations using the installed build. Retain its package and private records until recovery is complete; do not delete them. A new route/package cannot inspect outbox entries staged by the old route/package. Core wallet custody and outbox entries remain intact. Modern numbered account stores are carried through signed package lineage; the legacy unnumbered store is not automatically imported.
For submitted withdrawals, inspect the old nonce/action record and venue withdrawal ledger before retrying; acceptance is not settlement proof. Stop/revoke old venue agents before establishing new numbered sessions, retaining the old public session state and Signer custody references for recovery.
