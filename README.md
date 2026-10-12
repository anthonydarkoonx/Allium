# Allium

An onion-routing network over **UDP**, written in Rust.

A client builds a three-hop circuit (guard → middle → exit) and opens a local
SOCKS5 proxy; any application pointed at it reaches the internet through the
exit, with no single relay knowing both who you are and where you are going.
The same client can host a `.allium` hidden service in front of a local
server.

```
 Client ──UDP──▶ Guard ──UDP──▶ Middle ──UDP──▶ Exit ──TCP──▶ Internet
   │                                              ▲
   └── SOCKS5 on 127.0.0.1:9050                   │
                                                  │
                     ┌────────────────────┐       │
   relays publish →  │ Directory authority│ ← clients fetch the relay list
                     └────────────────────┘   and hidden-service descriptors
```

> **Status: experimental.** Allium is an independent design, not a Tor
> implementation, and has had no outside cryptographic review. Do not rely on
> it where your safety depends on anonymity. See [Security](#security).

## Features

- **UDP transport** end to end; fixed-size 1192-byte cells, per-hop keyed
  sequence-number masking, cell-level reliability and congestion control.
- **Encrypted layer headers.** Which relay comes next, and the final
  destination, travel inside each hop's AEAD layer; a tap between two relays
  sees only sequence numbers, lengths and ciphertext.
- **Hybrid post-quantum handshake**: X25519 plus ML-KEM-768, with
  `--require-pq` to refuse any hop that offers classical-only.
- **Pinned identities.** Clients pin the directory authority's Ed25519 key;
  relay identities come from the authority's signed votes.
- **Stream isolation** on by default: one circuit per first-party site, and
  SOCKS5 username/password credentials (any values) put an application's
  traffic on circuits of its own, like Tor's `IsolateSOCKSAuth`.
- **Hidden services** with blinded, encrypted descriptors, introduction and
  rendezvous points, vanguards, and optional client authorization.
- **Exit policy** with port allow-lists and a private/loopback/link-local
  address block that survives DNS rebinding and IP-notation tricks.
- **Flood-resistant directory authority**: per-subnet publish rate limits,
  a per-subnet live-relay cap and a global descriptor cap with
  refresh-aware eviction.
- **Reproducible dependencies.** Every crate the client builds against is
  vendored and hash-pinned; `verify-vendor.sh` runs before `cargo` does.

## Components

| Component | Binary | Source |
|---|---|---|
| Directory authority | `allium-authority-cli authority` | `Authority/` |
| Relays | `allium-relay-cli guard\|middle\|exit` | `Relays/` |
| Client (SOCKS5 proxy) | `allium client` | `Client/` |
| Hidden service | `allium service` | `Client/` |
| Echo server (testing) | `allium echo` | `Client/` |

## Building

Rust 1.85 or newer.  `vendor/`.

```bash
./build.sh all --release      # verifies vendor/ first, then builds all three
```

Binaries land in `Client/target/release/allium`,
`Relays/target/release/allium-relay-cli` and
`Authority/target/release/allium-authority-cli`.

## Try it on one machine

`e2e-loopback.sh` brings up an authority, thirteen relays, a hidden service
and a SOCKS client on loopback, then checks a rendezvous, throughput and
SOCKS-auth isolation. It is also the best worked example of how the pieces
are started.

```bash
./e2e-loopback.sh --build
```

## Using an existing network

```bash
cd Client
./target/release/allium client \
  --authority 203.0.113.10:9000 \
  --trust-authority <authority identity, 64 hex chars>
```

Then point any SOCKS5-capable program at `127.0.0.1:9050`. Always use the
proxy's hostname mode (`curl --socks5-hostname …`, "Proxy DNS when using
SOCKS v5" in Firefox) so names are resolved at the exit, not on your machine.
To keep two applications apart, give each its own proxy credentials:

```bash
curl --socks5-hostname 'app1:x@127.0.0.1:9050' https://example.org
curl --socks5-hostname 'app2:x@127.0.0.1:9050' https://example.org   # separate circuit
```

The full operator and user guide — authority and relay setup, every flag,
config files, hidden services, systemd units, troubleshooting — is in
[`DOCUMENTATION.md`](DOCUMENTATION.md).

## Repository layout

```
Authority/   directory authority library + CLI
Relays/      relay library (guard/middle/exit) + CLI
Client/      client library (SOCKS proxy, hidden services) + CLI
vendor/      vendored crates, pinned by vendor.sha256
build.sh     verify vendor/, then cargo build --locked
ci-check.sh  vendor re-verification, locked builds, cargo audit, cargo deny
e2e-*.sh     end-to-end tests on loopback
```

`Relays/` and `Authority/` share one library lineage; `Client/` is a separate
implementation of the same wire protocol. A protocol change has to land in
both, and the test suites pin the byte layout so they cannot drift apart.

## Testing

```bash
(cd Client && cargo test --locked)
(cd Relays && cargo test --locked)
(cd Authority && cargo test --locked)
./ci-check.sh            # supply-chain checks; RUN_E2E=1 adds the loopback runs
```

## Security

Allium's protocol and code have been reviewed internally but not by an
outside party. Known limits worth understanding before using it:

- A single directory authority is a single point of trust for path
  selection and sees every client's IP. Running several and configuring
  all of them in the client enables quorum voting.
- All cells are one fixed size and there is no cover traffic, so a global
  passive observer can correlate flows by timing and volume.
- The guard still sees you and the exit still sees your destination; that
  is inherent to onion routing.
- A small network run by one operator offers little anonymity however good
  the protocol is.

Every node on a circuit must run the same release: the layer wire format is
versioned and there is no mixed-version mode.

If you find a security problem, please report it privately to the
maintainer rather than opening a public issue.

## License

No license file is included in this repository yet. Until one is added, the
code is provided for review and testing only; contact the maintainer before
redistributing or building on it.
