#!/bin/bash
# Many hidden services publishing through the SAME middle relay.
#
#   ./e2e-hs-publish-load.sh             use the release binaries already built
#   N_SERVICES=40 ./e2e-hs-publish-load.sh
#   AUTH_BIN=/path/to/other/authority ./e2e-hs-publish-load.sh   (to compare authorities)
#
# A hidden service publishes over guard -> middle -> authority, so the
# authority sees the middle relay, not the publisher (11.38-hs-quota-report.md).
# An authority that rate-limits or charges a quota per peer address therefore
# refuses honest services once enough share a middle. This starts N_SERVICES
# (default 24) services, 3 s apart, all with the same --middle, on a loopback
# network of 13 relays (each in its own /16 so vanguard selection can succeed),
# and checks that every one publishes.
#   Old authority (per-peer limiter): 17 of 24 publish, 7 are refused "rate limited".
#   Current authority:                24 of 24 publish.
# Services are staggered because 24 simultaneous directory fetches time out on
# loopback, which would test the harness, not the authority.
# Exit status: 0 if all published, 1 if not, 2 if it could not run.

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

GUARD="$G_IP:$G_PORT"; MIDDLE="${M_IPS[0]}:$M_PORT"
common=(--authority "$AUTH" --allow-unpinned-authority --guard "$GUARD" --middle "$MIDDLE")


N=${N_SERVICES:-24}
echo "live-quota: starting $N services, all through the same middle $MIDDLE"
for i in $(seq 1 $N); do
    start "svc$i" "$CLIENT_BIN" service "${common[@]}" --hidden-service-port "127.0.0.1:$WEB_PORT" \
        --identity-file "$W/svc$i.key" --hidden-service-dir "$W/hs$i" --timeout 6 --publish-interval 600
    sleep 3   # staggered: 24 simultaneous directory fetches time out on loopback (a harness limit, not the quota)
done
ok=0; refused=0
for i in $(seq 1 $N); do
    if wait_for "$W/svc$i.log" "published descriptor for" 40; then ok=$((ok+1)); fi
done
refused=$(grep -l -i "rate limited" "$W"/svc*.log 2>/dev/null | wc -l)
echo "live-quota RESULT: $ok of $N services published; $refused service logs mention a refusal/rate limit"
grep -h -i "rate limited" "$W"/svc*.log 2>/dev/null | sort | uniq -c | head -3 | cut -c1-160
if [ "$ok" = "$N" ]; then echo "live-quota: ALL PUBLISHED"; FAILS=0; exit 0; else echo "live-quota: NOT ALL PUBLISHED"; FAILS=1; exit 1; fi
