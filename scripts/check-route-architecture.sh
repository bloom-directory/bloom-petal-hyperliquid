#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

failed=0

if command -v rg >/dev/null 2>&1; then
  search_lines() { rg -n -- "$@"; }
  search_quiet() { rg -q -- "$@"; }
  search_files() { rg -l -- "$@"; }
else
  search_lines() {
    local pattern="$1"
    shift
    grep -R -n -E -- "$pattern" "$@"
  }
  search_quiet() {
    local pattern="$1"
    shift
    grep -R -q -E -- "$pattern" "$@"
  }
  search_files() {
    local pattern="$1"
    shift
    grep -R -l -E -- "$pattern" "$@"
  }
fi

if search_lines \
  'crate::(read|write)[[:space:]]*\(|(pub[[:space:]]+)?fn[[:space:]]+(read|write|session_read|session_write|exchange_read|exchange_write|read_request|validate_write_file_action)[[:space:]]*\(' \
  route/files route/src; then
  echo "route architecture check: catch-all read/write dispatch is forbidden" >&2
  failed=1
fi

if search_lines 'current_route_(canonical_)?path[[:space:]]*\(' route/src; then
  echo "route architecture check: shared code must not inspect route identity" >&2
  failed=1
fi

if search_lines 'petal[[:space:]]*=[[:space:]]*\{[^}]*path[[:space:]]*=[[:space:]]*"\.\./sdk"' route/Cargo.toml \
  || search_lines '^path[[:space:]]*=[[:space:]]*"sdk"$' petal-build.toml; then
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
    if ! search_quiet "$petal_rev" "$pin_file"; then
      echo "route architecture check: Petal tooling pin differs in $pin_file" >&2
      failed=1
    fi
  done
fi

while IFS= read -r route_file; do
  if ! search_quiet 'read:' "$route_file"; then
    echo "route architecture check: writable route needs a local read handler: $route_file" >&2
    failed=1
  fi
done < <(search_files 'petal::write_spec' route/files)

if search_files 'secret_key|load_secret_bytes|load_secret_json|"secrets"' route/files >/dev/null; then
  echo "route architecture check: route files must not reference secret-namespace accessors" >&2
  failed=1
fi

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

echo "route architecture check passed"
