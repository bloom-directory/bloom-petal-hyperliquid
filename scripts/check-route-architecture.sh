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
