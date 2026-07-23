#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WASM_TOOLS_ROOT="$ROOT/target/wasm-tools"
WASM_TOOLS_VERSION="1.254.0"
if ! rustup target list --installed | grep -Fxq wasm32-unknown-unknown; then
  rustup target add wasm32-unknown-unknown
fi
if command -v wasm-tools >/dev/null 2>&1 \
  && [ "$(wasm-tools --version)" = "wasm-tools $WASM_TOOLS_VERSION" ]; then
  WASM_TOOLS_BIN="$(command -v wasm-tools)"
elif [ -x "$WASM_TOOLS_ROOT/bin/wasm-tools" ] \
  && [ "$("$WASM_TOOLS_ROOT/bin/wasm-tools" --version)" = "wasm-tools $WASM_TOOLS_VERSION" ]; then
  WASM_TOOLS_BIN="$WASM_TOOLS_ROOT/bin/wasm-tools"
else
  cargo install --locked --root "$WASM_TOOLS_ROOT" wasm-tools --version "$WASM_TOOLS_VERSION"
  WASM_TOOLS_BIN="$WASM_TOOLS_ROOT/bin/wasm-tools"
fi
WASM_TOOLS_DIR="$(dirname "$WASM_TOOLS_BIN")"
if [ -n "${GITHUB_PATH:-}" ]; then
  printf '%s\n' "$WASM_TOOLS_DIR" >> "$GITHUB_PATH"
fi
PATH="$WASM_TOOLS_DIR:$PATH" \
  cargo run --locked --manifest-path "$ROOT/xtask/Cargo.toml" --release
