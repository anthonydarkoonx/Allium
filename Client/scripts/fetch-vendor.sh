#!/usr/bin/env bash
# Rebuilds ../vendor from Cargo.lock with `cargo vendor` (published crates.io
# releases) and regenerates ../vendor.sha256 to match.
#
# The shipped tree already contains vendor/ and vendor.sha256; you only need
# this after changing a dependency or Cargo.lock. Review the diff of
# vendor.sha256 before committing it: it is what ../verify-vendor.sh trusts.
#
# Every download is checked by cargo against the checksum in Cargo.lock, and
# --locked refuses to change Cargo.lock. (Until 11.21 this script cloned
# pinned upstream git commits instead; see 11.21-migration-report.md.)
#
# Runs in a temp copy of the manifest: inside Client/, the source replacement
# in .cargo/config.toml would make cargo read the old vendor/ itself.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(cd .. && pwd)"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cp Cargo.toml Cargo.lock "$tmp/"
cp -r src "$tmp/src"
(cd "$tmp" && cargo vendor --quiet --locked --versioned-dirs "$tmp/vendor" >/dev/null)

rm -rf "$ROOT/vendor"
mv "$tmp/vendor" "$ROOT/vendor"
(cd "$ROOT/vendor" && LC_ALL=C find . -type f | LC_ALL=C sort | xargs -d '\n' sha256sum) > "$ROOT/vendor.sha256"
"$ROOT/verify-vendor.sh"
echo "Done. Review the change to vendor.sha256 before committing."
