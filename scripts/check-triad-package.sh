#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BLOOM_CONTRACT_REV="bbbb5a3a610b09e4a8bd61bb301bb89ae718e9fb"
BLOOM_ROOT="${BLOOM_ROOT:?set BLOOM_ROOT to a checkout of bloom-directory/bloom at $BLOOM_CONTRACT_REV}"
PACKAGE_ARCHIVE="${PACKAGE_ARCHIVE:?set PACKAGE_ARCHIVE to the exact built Hyperliquid .petal.tar.gz}"

actual_rev="$(git -C "$BLOOM_ROOT" rev-parse HEAD)"
if [[ "$actual_rev" != "$BLOOM_CONTRACT_REV" ]]; then
  echo "Bloom contract checkout must be exactly $BLOOM_CONTRACT_REV (found $actual_rev)" >&2
  exit 1
fi

if [[ ! -f "$PACKAGE_ARCHIVE" ]]; then
  echo "Hyperliquid package archive not found: $PACKAGE_ARCHIVE" >&2
  exit 1
fi

test_name="hyperliquid_package_contract"
test_path="$BLOOM_ROOT/crates/bloom-petals/tests/$test_name.rs"
package_tar="$(mktemp "${TMPDIR:-/tmp}/hyperliquid-package.XXXXXX.tar")"
if [[ -e "$test_path" ]]; then
  echo "refusing to overwrite existing Bloom test: $test_path" >&2
  rm -f "$package_tar"
  exit 1
fi

cleanup() {
  rm -f "$test_path"
  rm -f "$package_tar"
}
trap cleanup EXIT
cp "$ROOT/tests/bloom_package_metadata.rs" "$test_path"
gzip -dc "$PACKAGE_ARCHIVE" > "$package_tar"

HYPERLIQUID_PACKAGE_ARCHIVE="$package_tar" \
  cargo test \
    --locked \
    --manifest-path "$BLOOM_ROOT/Cargo.toml" \
    -p bloom-petals \
    --test "$test_name"
