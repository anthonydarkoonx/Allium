#!/bin/bash
# End-to-end check on one machine, with the real release binaries.
#
#   ./e2e-loopback.sh            use the release binaries already built
#   ./e2e-loopback.sh --build    build them first (cargo build --release --locked --offline)
#
# It starts an authority, 1 guard, 9 middles, 3 exits, a local web server, a
# hidden service and a SOCKS client, all on loopback, and checks that:
#   1. a hidden service publishes a blinded descriptor and a client fetches it
#      and gets the page back through a real rendezvous        (hidden service)
#   2. an address nobody published is refused cleanly
#   3. a large download through a normal circuit completes, in full, at no less
#      than MIN_MBPS MB/s                                       (throughput)
#   4. a second download on the SAME circuit is not much slower than the first
#      (a per-cell cost that grows with a circuit's age shows up here)
#
# Relays republish every 600 s (default 1200 s), not every 20 s: a client fetches the signed vote and then
# the descriptors and keeps only descriptors the vote lists, so a relay that republishes between the two
# is dropped from that fetch. With 13 relays at 20 s that happened often enough to make the checks that
# depend on a directory fetch fail about one run in four (see report 11.20.md, "Later operational findings").
# Relays run with their default settings: ALLIUM_RELAY_WORKERS is unset on
# purpose (a relay that cannot dial its next hop under the default settings was
# once invisible to every test that forced one worker).
#
# Environment (all optional):
#   BASE_PORT   first of ~20 UDP/TCP ports to use      (default 19000)
#   BIG_MB      size of the download test file, in MB  (default 64)
#   MIN_MBPS    throughput floor, MB/s                 (default 5; loopback gives ~30)
#   KEEP_DIR=1  keep the work directory (logs) when done
# Exit status: 0 if every check passed, 1 if any failed, 2 if it could not run.
# Loopback numbers say nothing about real networks; this guards against
# regressions, it does not measure internet speed.

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
# Extra middles (each in its own /16): with only 7 relays the service's random vanguard layers
# sometimes leave no valid pair for an intro circuit ("no valid pair of vanguard relays"), which
# made the hidden-service check fail about one run in eight.
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

# ---- 1 + 2: hidden service -----------------------------------------------
start service "$CLIENT_BIN" service "${common[@]}" --hidden-service-port "127.0.0.1:$WEB_PORT" \
    --identity-file "$W/svc.key" --hidden-service-dir "$W/hs" --timeout 6 --publish-interval 60
if wait_for "$W/service.log" "published descriptor for" 120; then
    ADDR="$(cat "$W/hs/hostname" 2>/dev/null)"
    OUT="$(timeout 150 "$CLIENT_BIN" client "${common[@]}" --timeout 8 --fetch-onion "$ADDR" --fetch-onion-path / 2>&1)"
    if echo "$OUT" | grep -q "hello from the hidden service" && echo "$OUT" | grep -q "HTTP/1.0 200"; then
        pass "hidden service: published, fetched, decrypted and answered through a rendezvous"
    else
        fail "hidden service: the page did not come back (see below)"; echo "$OUT" | tail -8 | cut -c1-200
    fi
    # an address nobody published: a valid-looking one from a throw-away identity
    FAKE="$(timeout 25 "$CLIENT_BIN" service "${common[@]}" --hidden-service-port "127.0.0.1:$WEB_PORT" \
        --identity-file "$W/other.key" --hidden-service-dir "$W/hs2" 2>&1 | grep -m1 "address is" | awk '{print $NF}')"
    pkill -f "$W/other.key" 2>/dev/null
    if [ -n "$FAKE" ]; then
        OUT2="$(timeout 100 "$CLIENT_BIN" client "${common[@]}" --timeout 8 --fetch-onion "$FAKE" --fetch-onion-path / 2>&1)"
        if echo "$OUT2" | grep -q "no live descriptor"; then
            pass "hidden service: an unpublished address is refused cleanly"
        else
            fail "hidden service: an unpublished address was not refused as expected"; echo "$OUT2" | tail -3 | cut -c1-200
        fi
    else
        fail "hidden service: could not make a throw-away address for the refusal check"
    fi
else
    fail "hidden service: the service never published a descriptor"; tail -6 "$W/service.log" | cut -c1-200
fi

# ---- 3 + 4: throughput on a normal circuit -------------------------------
start socks "$CLIENT_BIN" client --exit "${X_IPS[0]}:$X_PORT" --guard "$GUARD" --middle "$MIDDLE" \
    --socks-port "$SOCKS_PORT" --timeout 8
wait_for "$W/socks.log" "keepalive" 60 || sleep 5

download() {  # prints "bytes seconds"
    curl -s -o /dev/null --max-time 180 --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
        -w "%{size_download} %{time_total}" "http://127.0.0.1:$WEB_PORT/big.bin"
}
want=$((BIG_MB * 1000 * 1000))
speeds=()
for run in 1 2; do
    read -r bytes secs <<< "$(download)"
    mbps="$(python3 -c "print(round(${bytes:-0} / max(${secs:-1}, 0.001) / 1e6, 1))")"
    speeds+=("$mbps")
    if [ "${bytes:-0}" != "$want" ]; then
        fail "throughput run $run: got ${bytes:-0} of $want bytes in ${secs:-?}s (the download stopped early)"
    elif python3 -c "import sys; sys.exit(0 if $mbps >= $MIN_MBPS else 1)"; then
        pass "throughput run $run: $BIG_MB MB in ${secs}s = $mbps MB/s (floor $MIN_MBPS)"
    else
        fail "throughput run $run: $mbps MB/s is under the $MIN_MBPS MB/s floor"
    fi
done
if python3 -c "import sys; a,b=${speeds[0]},${speeds[1]}; sys.exit(0 if a > 0 and b >= 0.5*a else 1)"; then
    pass "same circuit stays fast: run 2 (${speeds[1]} MB/s) is within half of run 1 (${speeds[0]} MB/s)"
else
    fail "same circuit slows down: run 1 ${speeds[0]} MB/s, run 2 ${speeds[1]} MB/s"
fi

# ---- 5: SOCKS username/password isolation ----------------------------------
# The same download under proxy credentials must succeed, and must ride a
# circuit of its own (the client logs the isolated circuit's key, which is
# a digest of the credentials, never the credentials themselves).
auth_bytes="$(curl -s -o /dev/null --max-time 180 --socks5-hostname "app1:secret@127.0.0.1:$SOCKS_PORT" \
    -w "%{size_download}" "http://127.0.0.1:$WEB_PORT/big.bin")"
if [ "${auth_bytes:-0}" != "$want" ]; then
    fail "socks auth: authenticated download got ${auth_bytes:-0} of $want bytes"
elif ! grep -q "isolated\[auth:" "$W/socks.log"; then
    fail "socks auth: the download succeeded but no separate circuit was built for the credentials (see $W/socks.log)"
elif grep -q "secret" "$W/socks.log"; then
    fail "socks auth: the proxy password appears in the client log"
else
    pass "socks auth: credentials get their own circuit and never reach the log"
fi

echo
if [ "$FAILS" = 0 ]; then echo "e2e: all checks passed"; exit 0; else echo "e2e: $FAILS check(s) FAILED"; exit 1; fi
