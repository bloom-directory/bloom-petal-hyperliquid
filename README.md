# Hyperliquid Petal

This package moves Bloom's Hyperliquid HyperCore surface into a standalone
local Petal. It exposes read-only market/account files, signed exchange
actions, owner-approved USDC transfers, and bounded API-agent sessions under
`petals/hyperliquid/`.

All HTTP access, persistence, and owner signing are mediated by Bloom's triad
authority path. Bounded agent keys remain in the Petal's private store; private
keys and signatures are never returned through the public filesystem. The exchange
surface covers orders, cancels, cancel-by-cloid, scheduled cancel, leverage
updates, raw signed payloads, and internal USD sends. Agent sessions provide
owner-approved creation, bounded agent-key actions, stop, cancel-all,
close-all, and audit. The canonical transfer route is `usd_send.json`;
`send_asset.json` remains as a compatibility alias and does not implement
Hyperliquid's distinct generalized `sendAsset` action.

A session request requires a stable `id` and the wallet's `owner_address` when
the mounted path uses a wallet ID. The exact body can be retried across the
owner approval ceremony without rotating its agent key. A
successful write means the route completed; inspect the durable response,
status, and error files before treating an action as submitted.

## Build

```sh
scripts/check-route-architecture.sh
scripts/build.sh
cargo run --manifest-path ../bloom/Cargo.toml -p bloom -- petals build .
```

Run the host-side test suites with:

```sh
cargo test --manifest-path route/Cargo.toml --locked
```

## Installation

Bloom provisions the pinned Hyperliquid release during `bloom init` when
`hyperliquid` is present in `[petals].preinstalled` (it is part of Bloom's
default set). To install this repository manually while developing:

```sh
bloom petals install https://github.com/bloom-directory/bloom-petal-hyperliquid
bloom vfs cat /petals/hyperliquid/README.md
bloom vfs ls /petals/hyperliquid/mainnet
```

## Releases

Installable archives are built by the tag-triggered release workflow using the
pinned `bloom-directory/petal` packaging toolchain. CI runs the same packaging
validation before a tag is created. Release tags use Semantic Versioning with
a `v` prefix and publish:

- `hyperliquid-vX.Y.Z.petal.tar.gz`
- `SHA256SUMS`
- `petal-release.json`

Published assets are immutable. Bloom's built-in catalog pins the release tag,
source commit, archive name, and package hash. The route crate and canonical
Petal SDK are locked in `route/Cargo.lock`.
