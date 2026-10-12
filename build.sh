#!/usr/bin/env bash
# Verified build: checks vendor/ against vendor.sha256 BEFORE cargo runs.
#
# This must happen before cargo, not inside a build.rs: dependency build
# scripts and proc-macros (typenum, libc, syn, semver, ...) execute during
# compilation, ahead of this workspace's own build.rs, so a tampered vendor/
# tree would already have run code by then.
#
# Usage: ./build.sh [client|relays|authority|all] [extra cargo args...]
#   default target: all.  Extra args go to `cargo build` (e.g. --release).
# Always passes --locked so Cargo.lock cannot silently change.
set -euo pipefail
cd "$(dirname "$0")"

./verify-vendor.sh

target="${1:-all}"
[ "$#" -gt 0 ] && shift
case "$target" in
    client)    dirs=(Client) ;;
    relays)    dirs=(Relays) ;;
    authority) dirs=(Authority) ;;
    all)       dirs=(Client Relays Authority) ;;
    *) echo "usage: $0 [client|relays|authority|all] [cargo args]" >&2; exit 2 ;;
esac

for d in "${dirs[@]}"; do
    echo "== cargo build --locked ($d)"
    (cd "$d" && cargo build --locked "$@")
done
