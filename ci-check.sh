#!/usr/bin/env bash
# Supply-chain and build checks. Run locally or from CI (see
# .github/workflows/ci.yml). Fails on the first problem.
#
#   ./ci-check.sh            run everything that is installed; warn if
#                            cargo-audit / cargo-deny are missing
#   REQUIRE_AUDIT=1 ./ci-check.sh
#                            missing cargo-audit / cargo-deny is an error
#                            (CI sets this so the checks cannot be skipped)
set -euo pipefail
cd "$(dirname "$0")"

echo "== 1/5 vendor tree matches vendor.sha256"
./verify-vendor.sh

echo "== 2/5 vendor/ is exactly what crates.io serves for Client/Cargo.lock"
# vendor.sha256 only proves vendor/ is unchanged since the manifest was made.
# This proves the tree itself is genuine: re-vendor from the lockfile (each
# download is checked against the Cargo.lock checksum) and diff. It runs in a
# temp copy because inside Client/ the source replacement in .cargo/config.toml
# would make cargo read vendor/ itself. Needs network (or a warm cargo cache).
revendor="$(mktemp -d)"
trap 'rm -rf "$revendor"' EXIT
cp Client/Cargo.toml Client/Cargo.lock "$revendor/"
cp -r Client/src "$revendor/src"
if (cd "$revendor" && cargo vendor --locked --versioned-dirs "$revendor/vendor" >/dev/null 2>"$revendor/vendor.log"); then
    if ! diff -r "$revendor/vendor" vendor >/dev/null; then
        echo "error: vendor/ differs from a fresh 'cargo vendor' of Client/Cargo.lock:" >&2
        diff -rq "$revendor/vendor" vendor >&2 || true
        exit 1
    fi
    echo "vendor/ matches a fresh cargo vendor of Client/Cargo.lock"
elif [ "${REQUIRE_AUDIT:-0}" = 1 ]; then
    echo "error: cargo vendor failed (network?):" >&2; tail -5 "$revendor/vendor.log" >&2; exit 1
else
    echo "warning: cargo vendor failed (network?), skipping the re-vendor check:" >&2
    tail -2 "$revendor/vendor.log" >&2
fi

echo "== 3/5 cargo build --locked (Cargo.lock must be up to date)"
for d in Client Relays Authority; do
    (cd "$d" && cargo build --locked)
done

run_tool() {  # run_tool <cargo-subcommand> <args...>
    local sub="$1"
    if cargo "$sub" --version >/dev/null 2>&1; then
        return 0
    fi
    if [ "${REQUIRE_AUDIT:-0}" = 1 ]; then
        echo "error: cargo-$sub is required but not installed" >&2
        exit 1
    fi
    echo "warning: cargo-$sub not installed, skipping (install with: cargo install --locked cargo-$sub)" >&2
    return 1
}

echo "== 4/5 cargo audit (RustSec advisories)"
if run_tool audit; then
    for d in Client Relays Authority; do
        (cd "$d" && cargo audit --deny warnings)
    done
fi

echo "== 5/5 cargo deny (advisories + sources)"
if run_tool deny; then
    for d in Client Relays Authority; do
        (cd "$d" && cargo deny --manifest-path Cargo.toml --config ../deny.toml check advisories sources)
    done
fi

if [ "${RUN_E2E:-0}" = 1 ]; then
    echo "== 6 (optional) end-to-end loopback run (real binaries: hidden service + throughput)"
    ./e2e-loopback.sh --build
    echo "== 7 (optional) 24 hidden services publishing through one middle relay"
    ./e2e-hs-publish-load.sh
else
    echo "(skipping the end-to-end loopback run; set RUN_E2E=1 to include it)"
fi

echo "All checks passed."
