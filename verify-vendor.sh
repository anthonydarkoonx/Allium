#!/usr/bin/env bash
# Verifies ./vendor against vendor.sha256 (exact file set and contents).
# Run from the repo root before building. Exits non-zero on any mismatch,
# missing file, or extra file.
set -euo pipefail
cd "$(dirname "$0")"
[ -f vendor.sha256 ] || { echo "vendor.sha256 missing" >&2; exit 1; }
(cd vendor && sha256sum --check --quiet --strict ../vendor.sha256)
extra=$(cd vendor && LC_ALL=C find . -type f | LC_ALL=C sort | diff - <(awk '{print substr($0, index($0,$2))}' ../vendor.sha256 | LC_ALL=C sort) || true)
if [ -n "$extra" ]; then
    echo "vendor/ file set differs from vendor.sha256:" >&2
    echo "$extra" >&2
    exit 1
fi
echo "vendor/ verified: $(wc -l < vendor.sha256) files match vendor.sha256"
