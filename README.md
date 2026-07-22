# Hyperliquid Petal

This package moves Bloom's Hyperliquid HyperCore surface into a standalone
local Petal. It exposes read-only market/account files, signed exchange
actions, owner-approved USD transfers, and bounded API-agent sessions under
`/petals/hyperliquid/`.

All HTTP access, persistence, and signing are mediated by Bloom. Private keys
and signatures are never returned through the public
filesystem. The exchange surface includes orders, cancels, cancel-by-cloid,
scheduled cancel, leverage updates, raw signed payloads, and internal USD
sends. Agent sessions include owner-approved creation, bounded agent-key
actions, stop, cancel-all, close-all, audit, and fail-closed orphan recovery.
A session request requires a stable `id` so an approval-required request can
be retried with the exact same body without rotating its agent key.
A successful write means the route completed; inspect the durable response,
status, and error files before treating an action as submitted.

Build and validate with:

```sh
scripts/build.sh
cargo run --manifest-path ../bloom/Cargo.toml -p bloom -- petals build .
```
