#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

failed=0

if rg -n \
  'crate::(read|write)\s*\(|(pub\s+)?fn\s+(read|write|session_read|session_write|exchange_read|exchange_write|read_request|validate_write_file_action)\s*\(' \
  route/files route/src; then
  echo "route architecture check: catch-all read/write dispatch is forbidden" >&2
  failed=1
fi

if rg -n 'current_route_(canonical_)?path\s*\(' route/src; then
  echo "route architecture check: shared code must not inspect route identity" >&2
  failed=1
fi

if rg -n 'petal\s*=\s*\{[^}]*path\s*=\s*"\.\./sdk"' route/Cargo.toml \
  || rg -n '^path\s*=\s*"sdk"$' petal-build.toml; then
  echo "route architecture check: use the canonical pinned Petal SDK" >&2
  failed=1
fi

if [[ -e sdk/Cargo.toml || -e xtask/Cargo.toml ]]; then
  echo "route architecture check: vendored SDKs and builders are forbidden" >&2
  failed=1
fi

petal_rev="$(sed -n 's/^PETAL_REV="\([0-9a-f]\{40\}\)"$/\1/p' scripts/build.sh)"
if [[ -z "$petal_rev" ]]; then
  echo "route architecture check: scripts/build.sh must pin a full Petal commit" >&2
  failed=1
else
  for pin_file in route/Cargo.toml petal-build.toml .github/workflows/ci.yml .github/workflows/release.yml; do
    if ! rg -q "$petal_rev" "$pin_file"; then
      echo "route architecture check: Petal tooling pin differs in $pin_file" >&2
      failed=1
    fi
  done
fi

while IFS= read -r route_file; do
  if ! rg -q 'read:' "$route_file"; then
    echo "route architecture check: writable route needs a local read handler: $route_file" >&2
    failed=1
  fi
done < <(rg -l 'petal::write_spec' route/files)

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

echo "route architecture check passed"
