#!/bin/bash
# Guard-observation history: a service started WITHOUT --guard/--middle (so it
# picks its route from the authority) on a network whose relays have only just
# appeared.
#
#   ./e2e-guard-history.sh            use the release binaries already built
#   ./e2e-guard-history.sh --build    build them first
#
# By default a relay must have been seen for 6 hours before it can be an
# unpinned guard, and that history used to live in memory only, so a service
# that exited on the error could never get past the wait. Checks:
#   1. a first start fails with the guard-age error and saves the history
#      beside its guard state (inside --hidden-service-dir)
#   2. the same service restarted after the history is 7 hours old (the file is
#      back-dated to stand in for the wait) picks a route and publishes
#   3. a fresh service with --min-guard-age 0 publishes straight away
#   4. a fresh service without it still fails (control: nothing was loosened)
# The relays here republish every 600 s, not every 20 s as in e2e-loopback.sh:
# a client fetches the signed vote and then the descriptors, and keeps only
# descriptors the vote lists, so a relay that republishes between the two is
# dropped from that fetch. At 20 s that happened in about 1 fetch in 6 here (9
# or 11 of 13 relays instead of 13) and made check 3 flaky.
# Exit status: 0 if every check passed, 1 if any failed, 2 if it could not run.

set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_PORT="${BASE_PORT:-19000}"
BIG_MB="${BIG_MB:-64}"
MIN_MBPS="${MIN_MBPS:-5}"

AUTH_BIN="${AUTH_BIN:-$ROOT/Authority/target/release/allium-authority-cli}"
RELAY_BIN="${RELAY_BIN:-$ROOT/Relays/target/release/allium-relay-cli}"
CLIENT_BIN="${CLIENT_BIN:-$ROOT/Client/target/release/allium}"

die() { echo "e2e: cannot run: $*" >&2; FAILS=1; exit 2; }   # FAILS=1 keeps the logs for diagnosis

if [ "${1:-}" = "--build" ]; then
    for d in Authority Relays Client; do
        echo "e2e: building $d ..."
        (cd "$ROOT/$d" && cargo build --release --locked --offline 2>&1 | tail -1) || die "build of $d failed"
    done
fi
for b in "$AUTH_BIN" "$RELAY_BIN" "$CLIENT_BIN"; do
    [ -x "$b" ] || die "$b is missing (run with --build)"
done
command -v curl >/dev/null || die "curl is required"
command -v python3 >/dev/null || die "python3 is required"
unset ALLIUM_RELAY_WORKERS   # test the default on purpose

W="$(mktemp -d /tmp/allium-e2e.XXXXXX)"
# The client's default state file is ~/.allium/state (plus ~/.allium/state.guard-history): without this a
# test run would overwrite the persisted guard of whoever runs it. HOME points into the work directory,
# which is removed with it.
export HOME="$W/home"; mkdir -p "$HOME"
PIDS=()
FAILS=0
cleanup() {
    for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
    sleep 0.5
    for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done
    # anything else started with this run's files (e.g. the throw-away service)
    pkill -9 -f "$W/" 2>/dev/null
    if [ "${KEEP_DIR:-0}" = 1 ] || [ "$FAILS" != 0 ]; then
        echo "e2e: logs kept in $W"
    else
        rm -rf "$W"
    fi
}
trap cleanup EXIT
trap 'exit 2' INT TERM

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }

declare -A PID_OF CMD_OF
start() {  # start NAME CMD...   (log in $W/NAME.log)
    local name=$1; shift
    CMD_OF[$name]="$(printf '%q ' "$@")"
    nohup "$@" > "$W/$name.log" 2>&1 &
    PID_OF[$name]=$!
    PIDS+=("$!")
}
restart() {  # restart NAME: stop it and start the same command again, with a fresh log
    local name=$1
    kill "${PID_OF[$name]}" 2>/dev/null; sleep 0.5; kill -9 "${PID_OF[$name]}" 2>/dev/null
    eval "nohup ${CMD_OF[$name]} > \"$W/$name.log\" 2>&1 &"
    PID_OF[$name]=$!
    PIDS+=("$!")
}
wait_for() {  # wait_for FILE PATTERN SECONDS
    local f=$1 pat=$2 n=$3 i
    for ((i = 0; i < n * 2; i++)); do
        grep -q -- "$pat" "$f" 2>/dev/null && return 0
        sleep 0.5
    done
    return 1
}

AUTH_PORT=$BASE_PORT
WEB_PORT=$((BASE_PORT + 1))
SOCKS_PORT=$((BASE_PORT + 2))
G_PORT=$((BASE_PORT + 10))
M_PORT=$((BASE_PORT + 11))   # three middles: +11 +12 +13
X_PORT=$((BASE_PORT + 14))   # three exits:   +14 +15 +16
AUTH="127.0.0.1:$AUTH_PORT"
# Each relay in its own /16 so the service's vanguard rules (no two hops in one network) can be met.
G_IP=127.10.0.1; M_IPS=(127.20.0.1 127.60.0.1 127.70.0.1); X_IPS=(127.30.0.1 127.40.0.1 127.50.0.1)

# ---- the network ----------------------------------------------------------
start auth "$AUTH_BIN" authority --bind "$AUTH" --identity-file "$W/auth.key" \
    --allow-open-authority --allow-private-extend --name auth
wait_for "$W/auth.log" "listening on" 20 || die "the authority did not start (see $W/auth.log)"

relay() {  # relay ROLE NAME IP PORT [extra...]
    local role=$1 name=$2 ip=$3 port=$4; shift 4
    start "$name" "$RELAY_BIN" "$role" --bind "$ip:$port" --identity-file "$W/$name.key" \
        --allow-private-extend --authority "$AUTH" --allow-unpinned-authority \
        --publish-interval 600 --name "$name" "$@"
}
relay guard g "$G_IP" "$G_PORT"
for i in 0 1 2; do relay middle "m$i" "${M_IPS[$i]}" $((M_PORT + i)); done
for i in 0 1 2; do relay exit "x$i" "${X_IPS[$i]}" $((X_PORT + i)) --allow-private --allow-ports "$WEB_PORT"; done
# extra middles (own /16 each) so vanguard selection can always succeed for many services
for i in 3 4 5 6 7 8; do relay middle "m$i" "127.$((80 + i * 5)).0.1" $((BASE_PORT + 30 + i)); done
# A relay's first publish to the authority occasionally times out at start-up (about 2 in 100 relay
# starts here, with the old and the new code alike), and with a 600 s republish interval it would not
# be retried for ten minutes. So a relay that has not published after 25 s is restarted once.
for n in g m0 m1 m2 m3 m4 m5 m6 m7 m8 x0 x1 x2; do
    if ! wait_for "$W/$n.log" "published descriptor" 25; then
        echo "e2e: relay $n missed its first publish; restarting it once"
        restart "$n"
        wait_for "$W/$n.log" "published descriptor" 45 || die "relay $n never published to the authority (see $W/$n.log)"
    fi
done

# the web server: a small page and a big file
mkdir -p "$W/www"
echo "<h1>hello from the hidden service</h1>" > "$W/www/index.html"
head -c $((BIG_MB * 1000 * 1000)) /dev/urandom > "$W/www/big.bin"
start www python3 -m http.server "$WEB_PORT" --bind 127.0.0.1 --directory "$W/www"
wait_for "$W/www.log" "Serving HTTP" 10 || sleep 1


noroute=(--authority "$AUTH" --allow-unpinned-authority --hidden-service-port "127.0.0.1:$WEB_PORT" --timeout 6 --publish-interval 600)

# ---- 1: first start fails and saves the history ---------------------------
OUT="$(timeout 60 "$CLIENT_BIN" service "${noroute[@]}" --identity-file "$W/a.key" --hidden-service-dir "$W/hsA" 2>&1)"; rc=$?
HIST="$(ls "$W"/hsA/*.guard-history 2>/dev/null | head -1)"
if [ "$rc" != 0 ] && echo "$OUT" | grep -q "none has been observed for the required" && [ -n "$HIST" ] && [ "$(grep -vc '^#' "$HIST")" -ge 3 ]; then
    pass "first start: refused for lack of guard history, and $(grep -vc '^#' "$HIST") relays' first-seen times were saved"
    echo "$OUT" | grep -q "observations were saved" && pass "first start: the error says what to do next" || fail "first start: the error has no hint"
else
    fail "first start: rc=$rc, history='$HIST'"; echo "$OUT" | tail -4 | cut -c1-220
fi

# ---- 2: after the wait (history back-dated 7 h) the same service publishes -
if [ -n "$HIST" ]; then
    python3 - "$HIST" <<'PY'
import sys, time
p = sys.argv[1]
old = time.time() - 7 * 3600
lines = [l for l in open(p).read().splitlines() if l.strip() and not l.startswith('#')]
open(p, 'w').write('# back-dated by the test\n' + ''.join(f"{l.split()[0]} {old}\n" for l in lines))
PY
    start svcB "$CLIENT_BIN" service "${noroute[@]}" --identity-file "$W/a.key" --hidden-service-dir "$W/hsA"
    if wait_for "$W/svcB.log" "published descriptor for" 120; then
        pass "after the wait: the same service picked its own route and published"
    else
        fail "after the wait: it did not publish"; tail -4 "$W/svcB.log" | cut -c1-220
    fi
fi

# ---- 3: --min-guard-age 0 publishes straight away -------------------------
start svcC "$CLIENT_BIN" service "${noroute[@]}" --identity-file "$W/c.key" --hidden-service-dir "$W/hsC" --min-guard-age 0
if wait_for "$W/svcC.log" "published descriptor for" 120; then
    grep -q "WARNING: --min-guard-age" "$W/svcC.log" && pass "--min-guard-age 0: published at once, with a warning" || fail "--min-guard-age 0: published but printed no warning"
else
    fail "--min-guard-age 0: did not publish"; tail -4 "$W/svcC.log" | cut -c1-220
fi

# ---- 4: control: a fresh service without the flag still fails ------------
OUT="$(timeout 60 "$CLIENT_BIN" service "${noroute[@]}" --identity-file "$W/d.key" --hidden-service-dir "$W/hsD" 2>&1)"; rc=$?
if [ "$rc" != 0 ] && echo "$OUT" | grep -q "none has been observed for the required"; then
    pass "control: a fresh service with the default still refuses a brand-new guard"
else
    fail "control: rc=$rc"; echo "$OUT" | tail -3 | cut -c1-220
fi

echo
if [ "$FAILS" = 0 ]; then echo "e2e: all checks passed"; exit 0; else echo "e2e: $FAILS check(s) FAILED"; exit 1; fi
