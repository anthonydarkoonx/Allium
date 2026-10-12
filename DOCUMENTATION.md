# Allium — Operator & User Guide

Allium is an onion-routing network that runs over **UDP**. Traffic from a
client goes through three relays (guard → middle → exit), so no single relay
knows both who you are and where you are going. This guide covers every
component in this repository:

| Component | Binary | Source | What it does |
|---|---|---|---|
| Directory authority | `allium-authority-cli authority` | `Authority/` | Relays publish to it; clients and services fetch the relay list and hidden-service descriptors from it |
| Relays | `allium-relay-cli guard\|middle\|exit` | `Relays/` | Carry circuits. The exit also makes the real outbound connections |
| Client | `allium client` | `Client/` | Builds a 3-hop circuit and opens a local SOCKS5 proxy |
| Hidden service | `allium service` | `Client/` | Hosts a `.allium` address in front of a local server |
| Echo server | `allium echo` | `Client/` | A tiny TCP echo server, only for testing |

> Everything below was written from the source code in this repository. Where
> behaviour could not be confirmed from the code, the text says so.

---

## 1. How the network fits together

```
                     ┌────────────────────┐
   relays publish →  │  Directory         │  ← clients / services fetch
   signed descriptors│  Authority (UDP)   │    the relay list & HS descriptors
                     └────────────────────┘

 Client ──UDP──▶ Guard ──UDP──▶ Middle ──UDP──▶ Exit ──TCP──▶ Internet
   │
   └── SOCKS5 on 127.0.0.1:9050  ◀── your browser / curl / apps
```

- **Everything is UDP.** Authority, relays and client all talk UDP. Firewalls
  must allow *UDP* on each port (a TCP rule does nothing). The only TCP is the
  exit's final connection to the destination, and a hidden service's connection
  to its local web server.
- **What a link reveals.** Each cell is wrapped in one encryption layer per
  relay, and since layer format `0xA4` the layer header that names the next
  hop (or, on the exit's layer, the destination) is *inside* that
  encryption. Someone tapping the wire between two relays sees sequence
  numbers, lengths and ciphertext; which relay comes next, and where the
  traffic finally goes, is known only to the relay holding the key.
- **Identity keys.** Every authority and relay has a 32-byte master key stored
  hex-encoded in a file (`--identity-file`, created on first run). Clients pin
  the *authority's* identity with `--trust-authority HEX`, which stops an
  impostor from answering in its place.
- **Ports are free to choose.** `9030` appears in older notes, but a port is
  whatever you pass to `--bind`. Your VPS authority uses **9000**, with relays
  on 9001–9003.

---

## 2. Quick start (using the existing VPS network)

```bash
cd Client
./target/release/allium client \
  --authority 203.0.113.10:9000 \
  --trust-authority 0000000000000000000000000000000000000000000000000000000000000000
```

Leave it running, then in another terminal:

```bash
curl --socks5-hostname 127.0.0.1:9050 http://ipleak.net
```

Point any SOCKS5-capable app at `127.0.0.1:9050` (Firefox: Settings → Network
Settings → Manual proxy → SOCKS Host `127.0.0.1`, port `9050`, SOCKS v5, tick
*Proxy DNS when using SOCKS v5*).

Always use `--socks5-hostname` (curl) / "proxy DNS" (browsers) so name lookups
happen at the exit relay and not on your machine.

---

## 3. Building

All dependencies are vendored; no network is needed. From the repository root:

```bash
./build.sh              # verify vendor/ then build Client, Relays and Authority (debug)
./build.sh all --release
./build.sh client --release      # or: relays | authority
```

`build.sh` first runs `verify-vendor.sh`, which checks `vendor/` against
`vendor.sha256` and refuses to continue if any file changed. It builds with
`--locked`, so `Cargo.lock` cannot change silently. Extra arguments are passed
to `cargo build`.

Binaries:

| Binary | Path after `--release` |
|---|---|
| Client | `Client/target/release/allium` |
| Relays | `Relays/target/release/allium-relay-cli` |
| Authority | `Authority/target/release/allium-authority-cli` |

Other scripts: `ci-check.sh` (also re-downloads every crate and compares it with
`vendor/`), and the end-to-end tests `e2e-loopback.sh`, `e2e-guard-history.sh`
and `e2e-hs-publish-load.sh`. `./e2e-loopback.sh --build` runs a whole network
(authority, 13 relays, hidden service, SOCKS client) on one machine and is the
best working example of how the pieces are started.

---

## 4. Setting up a directory authority

### 4.1 Run it

```bash
./allium-authority-cli authority \
  --bind 0.0.0.0:9000 \
  --name authority \
  --identity-file /root/allium/keys/authority.key \
  --allow-open-authority
```

On first run the identity file is created. On every start the authority prints
its public identity, which clients need:

```
allium authority: identity (for --trust-authority/--authorities): <64 hex chars>
```

Read it again later with:

```bash
journalctl -u allium-authority | grep 'identity (for'
```

Keep the identity file. If it is lost, a new key is generated and every client's
`--trust-authority` value stops matching.

The authority refuses to start unless you pass **either** `--authorities` (a
relay allowlist) **or** `--allow-open-authority`.

### 4.2 Authority flags

| Flag | Default | Meaning |
|---|---|---|
| `--bind IP:PORT` | required | UDP address to listen on. `0.0.0.0:PORT` listens on all interfaces |
| `--name NAME` | `authority` | Human-readable node name |
| `--identity-file PATH` | none | 32-byte master key, hex. Created if missing. Without it the key is not persisted |
| `--idle-timeout SECONDS` | library default | Reap idle circuits after this long |
| `--require-return-routability BOOL` | `true` | Require each CREATE's backward-authenticity token. Takes a value: `--require-return-routability=false` |
| `--allow-private-extend` | off | Allow EXTEND to private/loopback/link-local addresses. For loopback test networks only |
| `--authorities HEX[,HEX…]` | none | Allowlist of relay identity keys whose descriptors are accepted |
| `--allow-open-authority` | off | Accept descriptors from **any** relay with any self-made identity |
| `--max-descriptors N` | `4096` | Most relays held at once (the most one directory reply can carry). At the cap a new identity displaces the newest relay that never refreshed its descriptor, or is refused if every held relay has refreshed. A relay refreshing itself is always accepted. `0` disables the cap |
| `--max-relays-per-subnet N` | `64` | Most live relays one address block (IPv4 /16, IPv6 /32, by the address they published from) may hold at once. `0` disables it |

The authority also serves hidden-service descriptors (publish and fetch) with no
extra setup. It has no `--config` option; use flags (or a systemd unit).

### 4.3 Security: do not leave it open

`--allow-open-authority` means anyone who can reach the UDP port can register a
relay, and so can place malicious relays on the paths of every client. The
authority prints a warning for exactly this reason.

What an open authority *does* defend against is being filled up or crowded
out. New identities are rate-limited per address block (32 per /16 per hour),
each block may hold at most `--max-relays-per-subnet` (64) live relays, and the
directory as a whole holds at most `--max-descriptors` (4096, the most one
directory reply can carry). At that cap a newcomer displaces the newest relay
that has never come back to refresh its descriptor (a real relay refreshes
every lifetime; a throwaway identity never does), so a flood of fake relays
only ever evicts other fake relays. Before these caps existed, an over-full
authority simply stopped answering every client.

For a network that you intend to use for real, give it an allowlist:

```bash
./allium-authority-cli authority --bind 0.0.0.0:9000 \
  --identity-file /root/allium/keys/authority.key \
  --authorities HEX_OF_GUARD,HEX_OF_MIDDLE,HEX_OF_EXIT
```

You need each relay's identity hex for this. **I could not find where a relay
prints its identity hex** (the relay prints only "listening on" and "published
descriptor" lines), so working this out is an open item. The authority's own
identity line is the only one printed today.

Known limits (from the authority source): no `--measured-bandwidth-file`
(bandwidth-weighted scoring) and no multi-authority signed-vote quorum on the
authority side.

### 4.4 systemd unit

(Full walkthrough, including a dedicated user and hardening, is in section 12.)

Your VPS runs it like this (`/etc/systemd/system/allium-authority.service`; the
override file is in `allium-authority.service.d/override.conf`):

```ini
[Unit]
Description=Allium directory authority
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/Authority/target/release/allium-authority-cli authority \
  --bind 0.0.0.0:9000 --name authority \
  --identity-file /root/allium/keys/authority.key --allow-open-authority
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

(The exact contents of your unit were not available; only the command line was
visible. Adapt as needed.) Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now allium-authority
sudo systemctl status allium-authority
```

### 4.5 Firewall

Open **UDP** on the authority port (and each relay port):

```bash
sudo ufw allow 9000/udp
sudo ufw allow 9001:9003/udp
```

Cloud providers often have a second firewall in their control panel. It must
allow the same UDP ports.

---

## 5. Setting up relays

Three roles: **guard** (first hop; the only relay a client contacts directly),
**middle**, and **exit** (makes the real connections). Run each as its own
process on its own port. A usable network needs at least one of each; more of
each gives better anonymity.

### 5.1 Run them

```bash
R=./Relays/target/release/allium-relay-cli
AUTH=203.0.113.10:9000
AUTH_KEY=0000000000000000000000000000000000000000000000000000000000000000

$R guard  --bind 203.0.113.10:9001 --identity-file /root/allium/keys/guard.key \
          --name guard  --authority $AUTH --trust-authority $AUTH_KEY

$R middle --bind 203.0.113.10:9002 --identity-file /root/allium/keys/middle.key \
          --name middle --authority $AUTH --trust-authority $AUTH_KEY

$R exit   --bind 203.0.113.10:9003 --identity-file /root/allium/keys/exit.key \
          --name exit   --authority $AUTH --trust-authority $AUTH_KEY \
          --allow-ports 80,443
```

- The host in `--bind` is the address **published** to the directory (there is
  no `--advertise` override in this CLI). Bind each relay to its real, public
  IP; do not use `0.0.0.0` or the clients will be told an unusable address.
- A relay publishes its signed descriptor at startup and then every
  `--publish-interval` seconds, and it also refreshes its list of known relays
  from the authority. It prints `published descriptor to …` when this works.
- If `--authority` is set you must give `--trust-authority HEX` (or the
  explicit `--allow-unpinned-authority`, for demos).

### 5.2 Flags common to guard, middle and exit

| Flag | Default | Meaning |
|---|---|---|
| `--bind IP:PORT` | required | UDP address; its host is what gets published |
| `--name NAME` | the role name | Node name |
| `--identity-file PATH` | none | Master key file (hex). Created if missing. **Set this**, or the relay is a new identity on every start |
| `--idle-timeout SECONDS` | library default | Reap idle circuits |
| `--max-circuit-age SECONDS` | unlimited | Hard cap on a circuit's lifetime, on top of idle-timeout |
| `--allow-private-extend` | off | Allow EXTEND to private/loopback/link-local addresses (loopback test networks only) |
| `--require-return-routability BOOL` | `true` | Backward-authenticity token check. `--require-return-routability=false` to disable |
| `--authority IP:PORT[,IP:PORT…]` | none | Authority(ies) to publish to and fetch from |
| `--trust-authority HEX` | none | Pin the authority's identity. Required whenever `--authority` is set (unless the next flag) |
| `--allow-unpinned-authority` | off | Proceed with `--authority` but no pin. Demo only |
| `--publish-interval SECONDS` | `1200` | How often to republish and refresh the directory |

### 5.3 Exit-only flags

| Flag | Default | Meaning |
|---|---|---|
| `--allow-ports PORT[,PORT…]` | see note | TCP ports this exit will CONNECT to |
| `--allow-udp-ports PORT[,PORT…]` | none | UDP ports this exit will relay datagrams to |
| `--allow-private` | off | Allow CONNECT/RESOLVE to private/local addresses. **Dangerous**: lets circuits reach the exit's own network |
| `--allow-amplification-ports` | off | Allow UDP to ports often abused for amplification (DNS, NTP, …) |

Note: the default port list when `--allow-ports` is omitted could not be
confirmed from the code. Always pass it explicitly. A refused destination shows
up in the client log as an *"exit refused port"* error; that is the policy
working, not a bug.

### 5.4 Environment

| Variable | Meaning |
|---|---|
| `ALLIUM_RELAY_WORKERS` | Number of worker shards per relay. **Leave unset (= 1).** With more than one worker a relay's own outbound traffic (EXTEND, directory refresh) is unreliable, and the relay prints a warning at startup |

Relays have no `--config` option.

### 5.5 systemd

(Full walkthrough is in section 12.)

Your server uses `allium-guard`, `allium-middle` and `allium-exit` units. A
template (adapt paths, ports and keys):

```ini
# /etc/systemd/system/allium-guard.service
[Unit]
Description=Allium guard relay
After=network-online.target allium-authority.service
Wants=network-online.target

[Service]
ExecStart=/opt/Relays/target/release/allium-relay-cli guard \
  --bind 203.0.113.10:9001 --name guard \
  --identity-file /root/allium/keys/guard.key \
  --authority 203.0.113.10:9000 \
  --trust-authority 0000000000000000000000000000000000000000000000000000000000000000
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Copy it for `middle` and `exit`, changing the role, port, name and key (and
adding `--allow-ports` for the exit). Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now allium-guard allium-middle allium-exit
```

### 5.6 Updating the server

Condensed from `How to update.txt`:

```bash
scp -i ~/.ssh/id_ed25519 Allium-<version>.zip root@203.0.113.10:/opt/
ssh -i ~/.ssh/id_ed25519 root@203.0.113.10
cd /opt && unzip Allium-<version>.zip
cd Authority && cargo build --release && cd ../Relays && cargo build --release
sudo systemctl restart allium-authority
sudo systemctl restart allium-guard allium-middle allium-exit
```

Restart the authority first, then the relays (they republish on start). Because
`--identity-file` persists, the authority's identity hex does not change.

**Upgrade every node together.** The layer wire format carries a version byte
(`0xA4` in this release, which moved the next-hop address and layer kind under
the encryption). A node on one format and a node on another refuse each
other's cells with a `peer speaks a pre-0xA4 layer format` (or `peer speaks
layer format 0x..`) message; there is no mixed-version mode. So upgrade the
authority, all relays, every client and every hidden service in one go; until
the last one is rebuilt, circuits through it fail at the handshake.

---

## 6. Using the client

### 6.1 Command shape

```
allium [--config FILE | -f FILE] <role> [flags]
```

`--config`/`-f` must come **before** the role. Roles are `client`, `service`
and `echo`. There is no `--help` flag; this document and
`Client/src/bin/allium_cli/args.rs` are the flag reference. Flags can be written
`--flag value` or `--flag=value`.

### 6.2 Choosing a route

Either let the client fetch a route from the authority:

```bash
allium client --authority HOST:PORT --trust-authority HEX
```

or give the whole route by hand (the authority is then not contacted, unless you
also use `--fetch-onion`):

```bash
allium client --guard 1.2.3.4:9001 --middle 1.2.3.5:9002 --exit 1.2.3.6:9003
```

You must give either all three of `--guard/--middle/--exit` or `--authority`.
If you give an authority, you must also pin it (`--trust-authority`) or pass
`--allow-unpinned-authority` explicitly (demo only; it allows impersonation).

A built-in default authority can be supplied with the environment variables
`ALLIUM_DEFAULT_AUTHORITY` (IP:PORT) and `ALLIUM_DEFAULT_TRUST_AUTHORITY`
(hex). They are used only when neither a complete manual route nor `--authority`
was given.

### 6.3 Client flags

**Route and trust**

| Flag | Default | Meaning |
|---|---|---|
| `--authority IP:PORT` | none | Directory authority to fetch the route from |
| `--trust-authority HEX` | none | Pin the authority's identity. Several keys may be comma-separated |
| `--allow-unpinned-authority` | off | Skip pinning. Not recommended |
| `--authority-quorum N` | none | Number of authorities that must agree. Not confirmed from the code; the default of unset is fine for one authority |
| `--guard IP:PORT` | none | Manual first hop |
| `--middle IP:PORT` | none | Manual second hop |
| `--exit IP:PORT` | none | Manual third hop |
| `--trust-guard HEX` | none | Pin the guard's identity (comma-separated list allowed) |
| `--trust-middle HEX` | none | Pin the middle's identity |
| `--trust-exit HEX` | none | Pin the exit's identity |
| `--min-guard-age SECONDS` | 6 hours | How long a relay must have been in the directory before it may be an unpinned guard. `0` disables the check; useful on a new test network, weaker otherwise |
| `--state-file PATH` | `~/.allium/state` | Remembers the chosen guard between runs (the guard history is kept alongside as `…guard-history`). `--state-file ""` turns it off |
| `--require-pq` | off | Require post-quantum (ML-KEM-768) key exchange on every hop |

**SOCKS proxy**

| Flag | Default | Meaning |
|---|---|---|
| `--socks-port PORT` | `9050` | Local port of the SOCKS5 proxy (always on `127.0.0.1`) |
| `--allow-udp` | off | Enable SOCKS5 UDP ASSOCIATE |
| `--isolate-by-destination` | **on** | Use a separate circuit per first-party site, so sites cannot be linked by sharing a circuit. `--no-isolate-by-destination` turns it off (one shared circuit; faster, linkable) |

**Isolating applications from each other.** The proxy accepts SOCKS5
username/password authentication with *any* credentials. It never checks
them; what they do is isolation: streams sent under different
`(username, password)` pairs never share a circuit, whatever their
destinations, and this holds even with `--no-isolate-by-destination`. Give
each application (or each browser container or profile) its own proxy
password and the exit cannot link them. Only a hash of the credentials is
kept in memory. This is the same mechanism as Tor's `IsolateSOCKSAuth`:

```bash
curl --socks5-hostname 'app1:anything@127.0.0.1:9050' https://example.org
curl --socks5-hostname 'app2:anything@127.0.0.1:9050' https://example.org   # a different circuit
```

**Timing and reliability**

| Flag | Default | Meaning |
|---|---|---|
| `--timeout SECONDS` | `5` | Per-hop / receive timeout |
| `--retries N` | `2` | Retries per step |
| `--connect-attempts N` | `3` | Attempts for each CONNECT (must be ≥ 1) |
| `--connect-timeout SECONDS` | `15` | Timeout for each CONNECT (must be > 0) |
| `--keepalive-interval SECONDS` | `90` | Ping to keep the circuit alive. `0` disables |
| `--mtu BYTES` | `256` | Chunk size the SOCKS proxy uses when sending data (exact effect not confirmed from the code; leave at the default) |
| `--no-congestion` | off | Turn off the congestion-control window |

**Hidden services (client side)**

| Flag | Default | Meaning |
|---|---|---|
| `--fetch-onion ADDR.allium` | none | Fetch one page from a hidden service, print it and exit |
| `--fetch-onion-path PATH` | `/` | URL path for `--fetch-onion` |
| `--client-auth-key-file PATH` | none | File holding this client's private authorization key (created if missing) |
| `--print-client-auth-key` | off | Print this client's public authorization key, then exit. Needs `--client-auth-key-file` |

**Testing**

| Flag | Default | Meaning |
|---|---|---|
| `--self-test` | off | Run a built-in test through the circuit instead of the SOCKS proxy |
| `--target IP:PORT` | `127.0.0.1:9100` | Destination for `--self-test` (run `allium echo --bind 127.0.0.1:9100` on the exit's side) |

**Global:** `--config FILE` / `-f FILE` (before the role).

### 6.4 Stopping

`Ctrl-C` or `SIGTERM` (for example `systemctl stop`) shuts it down cleanly.

### 6.5 Common problems

| Message | Cause |
|---|---|
| `guard handshake with "authority" … timed out` | Nothing answering at that UDP address. Wrong port, firewall, or the authority is down. Check `ss -ulnp` on the server |
| `no reply from the guard` | The guard is down or UDP is blocked to it |
| `not in the pinned trust set` | `--trust-authority` does not match the authority's current identity |
| `--authority … is set without --trust-authority` | Add the pin (or `--allow-unpinned-authority` for a demo) |
| `exit refused port` | The exit's `--allow-ports` does not include that destination port |
| `peer speaks a pre-0xA4 layer format` / `peer speaks layer format 0x..` | A relay (or this client) is on an older or newer build. Every node on a circuit must run the same release; see §5.6 |
| First page load of each site is slow | Expected with `--isolate-by-destination` (the default): each first-party site gets its own circuit, built on first use. `--no-isolate-by-destination` trades that for one shared, linkable circuit |

---

## 7. Config files (client and service)

Instead of flags you can use a config file: `allium -f ~/.allium/client.rc client`.
Flags override the file. The format depends on the extension: `.toml` is
parsed as TOML; anything else is parsed as an **alliumrc**, a flat Tor-style
file of `Keyword value` lines (`#` for comments, keywords are case-insensitive,
values may be wrapped in double quotes).

Only `client` and `service` read config files. Relays and the authority use
flags only.

Directives that the code accepts for the **client**:

| Directive | Same as |
|---|---|
| `Authority` | `--authority` |
| `TrustAuthority` | `--trust-authority` |
| `AllowUnpinnedAuthority` | `--allow-unpinned-authority` (`1/0`, `yes/no`, `true/false`, `on/off`) |
| `AuthorityQuorum` | `--authority-quorum` |
| `Guard`, `Middle`, `Exit` | `--guard`, `--middle`, `--exit` |
| `TrustGuard`, `TrustMiddle`, `TrustExit` | `--trust-guard/-middle/-exit` |
| `SocksPort` | `--socks-port` |
| `Target`, `SelfTest` | `--target`, `--self-test` |
| `MTU` | `--mtu` |
| `UseCongestionControl` | the opposite of `--no-congestion` |
| `AllowUDP` | `--allow-udp` |
| `IsolateByDestination` | `--isolate-by-destination` / `--no-isolate-by-destination` (default `yes`) |
| `RequirePostQuantum` | `--require-pq` |
| `ConnectAttempts`, `ConnectTimeout` | `--connect-attempts`, `--connect-timeout` |
| `Timeout`, `Retries` | `--timeout`, `--retries` |
| `KeepalivePeriod` | `--keepalive-interval` |
| `FetchOnion`, `FetchOnionPath` | `--fetch-onion`, `--fetch-onion-path` |
| `StateFile` | `--state-file` |
| `ClientAuthKeyFile` | `--client-auth-key-file` |

Example `client.rc`:

```
Authority 203.0.113.10:9000
TrustAuthority 0000000000000000000000000000000000000000000000000000000000000000
SocksPort 9050
IsolateByDestination yes
```

The directive table also lists relay directives (`ORPort`, `Nickname`,
`IdentityFile`, `Address`, `RelayBandwidthRate`, `MyFamily`, `BehindNAT`,
`AllowPorts`, …), because `alliumrc.rs` was written to cover every role. The
separate relay and authority binaries in this repo do not read config files, so
use their command-line flags.

---

## 8. Hidden services

A hidden service is reachable at an address like `abc…xyz.allium` without
having a public IP, a port-forward or an open port. The address is derived from
the service's identity key. Clients reach it through an *introduction point* and
a *rendezvous* circuit, so neither side learns the other's IP.

### 8.1 Prerequisites

1. A running directory authority (hidden-service descriptors are stored there).
2. Enough relays for the service to build its circuits. The end-to-end test
   uses 1 guard, 9 middles and 3 exits. Each relay should be in a different /16
   network because the service's "vanguard" rules refuse to put two hops in one
   network; with too few relays you may see *"no valid pair of vanguard relays"*.
3. A local server for the content (nginx, Apache, `python3 -m http.server`,
   anything speaking HTTP).

### 8.2 Run a service

```bash
# 1. a local web server, only on loopback
mkdir -p ~/site && echo '<h1>hello</h1>' > ~/site/index.html
python3 -m http.server 8080 --bind 127.0.0.1 --directory ~/site &

# 2. the hidden service
allium service \
  --authority 203.0.113.10:9000 \
  --trust-authority 0000000000000000000000000000000000000000000000000000000000000000 \
  --hidden-service-port 127.0.0.1:8080 \
  --hidden-service-dir ~/.allium/hidden_service/mysite
```

When it is ready it prints:

```
service: address is <something>.allium
Hidden service ready:  <something>.allium
Reachable through N introduction point(s) once the directory authority has this descriptor (up to …s).
```

The address is also saved in `<hidden-service-dir>/hostname`. The descriptor can
take up to one publish interval to appear.

Always set `--hidden-service-dir`. It holds:

- `hs_ed25519_secret_key`: the service's private key (**this is your address;
  back it up and keep it secret**; whoever has it can impersonate the service),
- `hostname`: the public address,
- the persisted guard and vanguard layers.

Without it, the service picks a new guard on every start, which weakens
anonymity (the service prints a warning). If you omit both it and
`--identity-file`, the directory defaults to `~/.allium/hidden_service/<name>`.
The directory is hardened to mode 0700.

### 8.3 Visit it

```bash
allium client --authority 203.0.113.10:9000 --trust-authority HEX \
  --fetch-onion <address>.allium --fetch-onion-path /
```

This prints the HTTP response and exits. For a browser, run the normal client
and open `http://<address>.allium/` through the SOCKS proxy; `.allium` names are
handled by the proxy itself, so use remote DNS (`--socks5-hostname` / "proxy
DNS").

```bash
curl --socks5-hostname 127.0.0.1:9050 http://<address>.allium/
```

An address nobody has published is refused with `no live descriptor`.

### 8.4 Service flags

| Flag | Default | Meaning |
|---|---|---|
| `--hidden-service-port IP:PORT` | required | Local server that gets the traffic. Not exposed directly |
| `--hidden-service-dir DIR` | `~/.allium/hidden_service/<name>` | Key, hostname, guard state |
| `--identity-file PATH` | `<dir>/hs_ed25519_secret_key` | Override the key file location |
| `--name NAME` | `service` | Name used for the default directory and log lines |
| `--authority IP:PORT` | required | Directory authority |
| `--trust-authority HEX` | required unless unpinned | Pin the authority |
| `--allow-unpinned-authority` | off | Skip pinning (demo only) |
| `--authority-quorum N` | none | As for the client |
| `--guard IP:PORT` / `--middle IP:PORT` | picked from the directory | Manual entry hops |
| `--trust-guard HEX` / `--trust-middle HEX` | none | Pin those hops |
| `--intro-count N` | `3` | Number of introduction points |
| `--publish-interval SECONDS` | built-in default | How often the descriptor is republished |
| `--timeout SECONDS` | `5` | Per-hop timeout |
| `--retries N` | `2` | Retries |
| `--keepalive-interval SECONDS` | `90` | Circuit keepalive; `0` disables |
| `--min-guard-age SECONDS` | 6 hours | As for the client |
| `--allow-short-rendezvous` | off | Allow a rendezvous circuit without the extra hop when none is available. This lets a hostile rendezvous point learn the service's middle relay, so leave it off |
| `--client-auth-key HEX` | none | **Repeatable.** Restrict the service to clients holding these keys |

Matching alliumrc directives for a service: `HiddenServiceDir`,
`HiddenServicePort` (either `IP:PORT` or `80 IP:PORT`), `Authority`,
`TrustAuthority`, `AllowUnpinnedAuthority`, `Guard`, `Middle`, `TrustGuard`,
`TrustMiddle`, `Nickname`, `IdentityFile`, `HiddenServiceNumIntroductionPoints`,
`RendPostPeriod`, `Timeout`, `Retries`, `KeepalivePeriod` and
`ClientAuthorizedKey` (repeatable). Only **one** `HiddenServiceDir` and one
`HiddenServicePort` are allowed per file; run another `service` process for a
second site.

```
# mysite.rc   →   allium -f mysite.rc service
HiddenServiceDir ~/.allium/hidden_service/mysite
HiddenServicePort 80 127.0.0.1:8080
Authority 203.0.113.10:9000
TrustAuthority 0000000000000000000000000000000000000000000000000000000000000000
```

### 8.5 Private services (client authorization)

By default anyone who knows the `.allium` address can connect. To restrict it:

```bash
# On the client machine: create a key and print the public half
allium client --client-auth-key-file ~/.allium/client-auth.key --print-client-auth-key
#   client: your client-authorization public key is <64 hex>

# On the service: allow only that key (repeat for each client)
allium service … --client-auth-key <64 hex>

# On the client: always pass the same key file
allium client … --client-auth-key-file ~/.allium/client-auth.key --fetch-onion <addr>.allium
```

The public key may be shared; keep the key file private.

### 8.6 Running a service permanently

```ini
# /etc/systemd/system/allium-service.service
[Unit]
Description=Allium hidden service
After=network-online.target

[Service]
ExecStart=/usr/local/bin/allium service \
  --authority 203.0.113.10:9000 \
  --trust-authority 0000000000000000000000000000000000000000000000000000000000000000 \
  --hidden-service-port 127.0.0.1:8080 \
  --hidden-service-dir /var/lib/allium/mysite
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

---

## 9. The echo server (testing)

```bash
allium echo --bind 127.0.0.1:9100
```

`--bind` is the only flag, and it is required. It is a plain TCP echo server for
use with `client --self-test --target 127.0.0.1:9100`.

---

## 10. Checklist: bring up a network from scratch

1. Build everything: `./build.sh all --release`.
2. On the authority host: start `allium-authority-cli authority …` and copy the
   `identity (for --trust-authority…)` line.
3. Open **UDP** for the authority and relay ports (host firewall *and* provider
   panel).
4. Start at least one guard, one middle and one exit, each with its own
   `--bind PUBLIC_IP:PORT`, `--identity-file`, `--authority`, `--trust-authority`.
   Wait for `published descriptor to …` in each log.
5. On your own machine run the client with `--authority` and `--trust-authority`
   and look for a built circuit and the SOCKS listener.
6. `curl --socks5-hostname 127.0.0.1:9050 http://ipleak.net` should show the
   exit's IP.
7. For a real deployment, replace `--allow-open-authority` with `--authorities`.

## 11. Security notes

- **Open authority.** `--allow-open-authority` (used on your VPS now) lets
  anyone register relays. Use it for demos only. The descriptor caps
  (`--max-descriptors`, `--max-relays-per-subnet`, §4.3) keep an open
  authority answering under a flood, but they cannot stop an attacker's
  relays from being *listed*; only an allowlist does that.
- **Stream isolation.** The client uses one circuit per first-party site by
  default, and SOCKS5 username/password credentials (any values) put an
  application's streams on circuits of their own (§6.3). Turn destination
  isolation off only if you accept that everything you visit through the
  proxy can be linked at the exit.
- **What relays and the wire see.** Layer headers are encrypted (§1), so a
  tap between two relays learns neither the next hop nor the destination.
  The exit still sees the destination, and the guard still sees you; that is
  inherent to onion routing.
- **Pin the authority.** Without `--trust-authority`, an attacker on the network
  path can impersonate the authority. `--allow-unpinned-authority` exists only
  for single-machine tests.
- **Private-address flags** (`--allow-private`, `--allow-private-extend`) let
  circuits reach internal addresses. Never enable them on a public relay.
- **Keep keys.** Identity files (authority, relays, hidden-service secret key)
  and the client's `~/.allium/state` should be readable only by their owner and
  backed up where losing them matters.
- **Exit policy.** Choose `--allow-ports` deliberately; an exit's operator is
  the one whose IP appears to destinations.
- **Small network.** With a handful of relays all run by one operator, the
  anonymity guarantees are limited; Allium's strength comes from many
  independent relays.

---

## 12. systemd unit files for the authority and relays

systemd starts the processes at boot, restarts them if they crash, and collects
their logs in the journal. Your VPS already uses `allium-authority`,
`allium-guard`, `allium-middle` and `allium-exit`. This section shows how to
build those from scratch. The unit files here are templates written from the
command lines in this repo; check the paths and ports against your machine.

### 12.1 Prepare the machine (once)

Running as `root` works (your VPS does) but a bug in a network-facing daemon
then hands over the whole machine. A dedicated user is safer:

```bash
# a system user with no login and no home shell
sudo useradd --system --home-dir /var/lib/allium --create-home --shell /usr/sbin/nologin allium

# binaries in a fixed place
sudo install -m 0755 Authority/target/release/allium-authority-cli /usr/local/bin/
sudo install -m 0755 Relays/target/release/allium-relay-cli        /usr/local/bin/

# a private directory for identity keys
sudo install -d -m 0700 -o allium -g allium /var/lib/allium/keys
```

Keys are created automatically on first start if the `--identity-file` path does
not exist, so you do not make them by hand. If you are moving an existing
authority, copy its key file first so the identity (and every client's
`--trust-authority` value) stays the same:

```bash
sudo cp /root/allium/keys/authority.key /var/lib/allium/keys/authority.key
sudo chown allium:allium /var/lib/allium/keys/*.key
sudo chmod 600 /var/lib/allium/keys/*.key
```

Do this for the guard, middle and exit keys too if you want to keep their
identities.

### 12.2 The authority unit

`/etc/systemd/system/allium-authority.service`

```ini
[Unit]
Description=Allium directory authority
Documentation=file:///opt/allium/DOCUMENTATION.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=allium
Group=allium
ExecStart=/usr/local/bin/allium-authority-cli authority \
    --bind 0.0.0.0:9000 \
    --name authority \
    --identity-file /var/lib/allium/keys/authority.key \
    --allow-open-authority
Restart=on-failure
RestartSec=3
LimitNOFILE=65536

# hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/lib/allium
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
```

What each part does:

| Setting | Why |
|---|---|
| `After=/Wants=network-online.target` | Do not start before the network is up |
| `User=/Group=` | Run unprivileged. Ports 9000 and up need no root |
| `ExecStart=` | The full command. Line continuations (`\`) must have **no trailing spaces**. Use absolute paths. To change a flag, edit here |
| `Restart=on-failure`, `RestartSec=3` | Restart after a crash, not after a clean `systemctl stop` |
| `ReadWritePaths=` | With `ProtectSystem=strict` the whole filesystem is read-only except these paths, which is where the key is written |
| `PrivateTmp`, `NoNewPrivileges`, etc. | Standard sandboxing. Remove a line if it causes a start failure on your system |

When you move to an allowlist, swap `--allow-open-authority` for
`--authorities HEX,HEX,HEX` (section 4.3).

### 12.3 The relay units

All three relay units differ only in role, port, name and key (and the exit's
port policy). Replace `203.0.113.10` with the relay's public IP; the host in
`--bind` is the address that gets published.

`/etc/systemd/system/allium-guard.service`

```ini
[Unit]
Description=Allium guard relay
After=network-online.target allium-authority.service
Wants=network-online.target

[Service]
Type=simple
User=allium
Group=allium
ExecStart=/usr/local/bin/allium-relay-cli guard \
    --bind 203.0.113.10:9001 \
    --name guard \
    --identity-file /var/lib/allium/keys/guard.key \
    --authority 203.0.113.10:9000 \
    --trust-authority 0000000000000000000000000000000000000000000000000000000000000000
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/lib/allium
RestrictAddressFamilies=AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/allium-middle.service` is the same with:

```ini
Description=Allium middle relay
ExecStart=/usr/local/bin/allium-relay-cli middle \
    --bind 203.0.113.10:9002 \
    --name middle \
    --identity-file /var/lib/allium/keys/middle.key \
    --authority 203.0.113.10:9000 \
    --trust-authority 0000000000000000000000000000000000000000000000000000000000000000
```

`/etc/systemd/system/allium-exit.service` is the same with an exit policy:

```ini
Description=Allium exit relay
ExecStart=/usr/local/bin/allium-relay-cli exit \
    --bind 203.0.113.10:9003 \
    --name exit \
    --identity-file /var/lib/allium/keys/exit.key \
    --authority 203.0.113.10:9000 \
    --trust-authority 0000000000000000000000000000000000000000000000000000000000000000 \
    --allow-ports 80,443
```

Notes:

- Do **not** set `ALLIUM_RELAY_WORKERS` (section 5.4).
- `After=allium-authority.service` only helps when the authority is on the same
  machine. For a relay on another host, drop it. The relay publishes
  periodically, so it recovers if the authority is up a little later.
- Each relay needs its **own** key file and port. Two relays sharing a key would
  have the same identity.
- To run several relays of one role on a machine, copy the unit and change
  `--name`, `--bind` port and `--identity-file`.

### 12.4 Optional: one template unit for all roles

If you prefer fewer files, put the role-independent options in an environment
file and use an instance name. Create `/etc/systemd/system/allium-relay@.service`:

```ini
[Unit]
Description=Allium %i relay
After=network-online.target
Wants=network-online.target

[Service]
User=allium
Group=allium
EnvironmentFile=/etc/allium/%i.env
ExecStart=/usr/local/bin/allium-relay-cli %i \
    --bind ${BIND} --name %i \
    --identity-file /var/lib/allium/keys/%i.key \
    --authority ${AUTHORITY} --trust-authority ${TRUST_AUTHORITY} $EXTRA_ARGS
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/allium

[Install]
WantedBy=multi-user.target
```

and `/etc/allium/exit.env` (one file per role: `guard.env`, `middle.env`,
`exit.env`):

```bash
BIND=203.0.113.10:9003
AUTHORITY=203.0.113.10:9000
TRUST_AUTHORITY=0000000000000000000000000000000000000000000000000000000000000000
EXTRA_ARGS=--allow-ports 80,443
```

Start with `systemctl enable --now allium-relay@guard allium-relay@middle allium-relay@exit`.
The instance name must be exactly `guard`, `middle` or `exit`, because it is
passed to the binary as the role. (This template is untested.)

### 12.5 Install and start

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now allium-authority
sudo systemctl enable --now allium-guard allium-middle allium-exit
```

`enable` starts them at boot; `--now` starts them immediately. Check:

```bash
systemctl status allium-authority allium-guard allium-middle allium-exit --no-pager
ss -ulnp | grep allium          # each should hold its UDP port
journalctl -u allium-guard -f   # follow the log; look for "published descriptor"
```

### 12.6 Day-to-day

| Task | Command |
|---|---|
| Restart after an upgrade | `sudo systemctl restart allium-authority` then `sudo systemctl restart allium-guard allium-middle allium-exit`. Clients and hidden services must be on the same release too (§5.6) |
| Stop | `sudo systemctl stop allium-exit` (sends SIGTERM) |
| Edit a unit | `sudo systemctl edit --full allium-exit`, or edit the file then `sudo systemctl daemon-reload` and restart |
| Change one setting without touching the file | `sudo systemctl edit allium-exit` creates a drop-in `override.conf`. Your authority already has one; to *replace* `ExecStart` in a drop-in, first put an empty `ExecStart=` line, then the new one |
| Recent log | `journalctl -u allium-exit -n 50 --no-pager` |
| Why did it fail to start | `systemctl status allium-exit` and `journalctl -xeu allium-exit` |
| Show the authority's identity | `journalctl -u allium-authority | grep 'identity (for' | tail -1` |
| Disable at boot | `sudo systemctl disable allium-exit` |

### 12.7 Troubleshooting units

| Symptom | Likely cause |
|---|---|
| `status=203/EXEC` | Wrong path in `ExecStart`, or the binary is not executable |
| `status=217/USER` | The `allium` user does not exist |
| `Permission denied` writing the key | The key directory is not owned by `allium`, or not listed in `ReadWritePaths` |
| `Failed to parse` or "unrecognized" flag | A trailing space after a `\`, or a flag spelled differently. Run the command by hand first |
| Starts, then exits at once | Run the exact `ExecStart` by hand as the `allium` user: `sudo -u allium /usr/local/bin/allium-relay-cli exit …` and read the error |
| Relay runs but never shows "published descriptor" | `--authority` address or port wrong, UDP blocked, or the `--trust-authority` hex is stale |
| Publish refused with `this directory already holds its maximum of N relays` or `this address block already has N live relays registered` | The authority's caps (§4.3) are full. Raise `--max-descriptors` / `--max-relays-per-subnet` on the authority, or wait for stale relays to expire |
| Authority identity changed after moving to a new user | The key was not copied; a fresh key was generated. Restore the old file and restart |
