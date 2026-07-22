#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WASM_TOOLS_ROOT="$ROOT/target/wasm-tools"
if [ ! -x "$WASM_TOOLS_ROOT/bin/wasm-tools" ]; then
  cargo install --offline --root "$WASM_TOOLS_ROOT" wasm-tools --version 1.254.0
fi
PATH="$WASM_TOOLS_ROOT/bin:$PATH" cargo run --offline --manifest-path "$ROOT/xtask/Cargo.toml" --release
