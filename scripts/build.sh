#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PETAL_REV="864a80b407387871bae06aabe77b91865e55f7bc"

if [[ "${PETAL_COMPILE_TIME_SECRET+x}" == "x" ]]; then
  if [[ -z "$PETAL_COMPILE_TIME_SECRET" ]]; then
    echo "PETAL_COMPILE_TIME_SECRET is not configured" >&2
    exit 1
  fi
  export HYPERLIQUID_BUILDER_ADDRESS="$PETAL_COMPILE_TIME_SECRET"
  unset PETAL_COMPILE_TIME_SECRET
fi

# Bloom materializes composed route artifacts here after package validation
# (both `bloom petals install <dir>` and the developer provenance-enrollment
# path write it directly into this tree). They are derived from the route
# sources and must not survive a source rebuild, or the next
# `bloom petals build/install` rejects the stale bytes before it gets a
# chance to regenerate them.
rm -rf -- "$ROOT/artifacts"

if [[ -n "${PETAL_BIN:-}" ]]; then
  "$PETAL_BIN" build --root "$ROOT"
else
  tool_root="$ROOT/target/petal-tool"
  cargo install \
    --git https://github.com/bloom-directory/petal \
    --rev "$PETAL_REV" \
    --locked \
    --root "$tool_root" \
    bloom-petal-cli
  "$tool_root/bin/petal" build --root "$ROOT"
fi
