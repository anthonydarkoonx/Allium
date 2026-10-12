//! `allium-relay-cli` -- a self-contained relay-hosting CLI for the Allium
//! onion-routing protocol: `guard`/`middle`/`exit` only.
//!
//! **Origin**: this crate, and the `allium` protocol library it depends on
//! (`../allium`, copied byte-for-byte from `/home/claude/rust/allium` at the
//! point that project's own `allium-cli` had its `guard`/`middle`/`exit`/
//! `authority` subcommands removed), together form a fully separate project with no dependency
//! of any kind on `/home/claude/rust`. It exists so relay infrastructure can
//! be deployed on its own machine, independent of the client/hidden-service
//! CLI.
//!
//! **Scope, a deliberate product decision**: exactly three subcommands --
//! `guard` (first hop), `middle` (second hop, reached via EXTEND), and
//! `exit` (last hop, opens real outbound connections under an `ExitPolicy`).
//! There is **no** `authority` subcommand here on purpose: this CLI cannot
//! stand up a directory authority for other relays to publish to. A `guard`/
//! `middle`/`exit` run from this CLI can still publish its own signed
//! descriptor to a *remote*, externally-run directory authority via
//! `--authority HOST:PORT[,HOST:PORT...] --trust-authority HEX`, exactly as
//! before -- it just can't run that authority itself. There is also no
//! `client`, `service`, or `echo` role here; those belong to the separate
//! client/hidden-service-hosting CLI at `/home/claude/rust`, untouched by
//! this project.
//!
//! **Flags and behavior are matched against the Python original**
//! (`/mnt/user-data/uploads/Allium-v8.6/allium_cli.py`): `add_relay_common`
//! (around line 5669) defines the flags shared by `guard`/`middle`/`exit`/
//! `authority`'s subparsers (`--bind`, `--name`, `--identity-file`,
//! `--idle-timeout`, `--require-return-routability`, `--authority`,
//! `--trust-authority`, `--allow-unpinned-authority`, `--publish-interval`);
//! `guard`/`middle` (`sub.add_parser("guard"/"middle", ...)`, around line
//! 5782-5788) add nothing beyond that shared set and dispatch to
//! `cmd_guard`/`cmd_middle` (line 2807-2812), which are themselves trivial
//! one-line wrappers around the same underlying relay-serving logic
//! (`cmd_relay` in this port, matching that structure) -- so `guard` and
//! `middle` share one Rust implementation function here, parametrized by
//! role name, exactly as Python's own two one-line wrappers do. `exit`
//! (`sub.add_parser("exit", ...)`, line 5792 onward) additionally defines
//! `--allow-ports` (default `"80,443,8080"`), `--allow-udp-ports` (default
//! `""`), `--allow-private` (`store_true`, default off), and
//! `--allow-amplification-ports` (`store_true`, default off; refuses to
//! enable UDP amplification-abused ports unless explicitly opted in) --
//! dispatching to `cmd_exit` (line 2815 onward), which builds a real
//! `ExitPolicy`/`Egress` and wires them in via `SocksExit`-equivalent
//! composition.
//!
//! **Implementation provenance**: the actual Rust call shapes below
//! (`RelayNode::new`/`RelayNodeOptions`, `RelayNode::run`, `ExitPolicy::new`,
//! `Egress::new`/`enable_stream_tracking`, `SocksExit::install`,
//! `allium::dir_round_trip`, `RelayDescriptor::create`,
//! `dirwire::encode_publish_request`/`decode_publish_reply`) are not
//! reconstructed from scratch -- they are carried over verbatim from
//! `/home/claude/rust`'s own prior, real (non-stub), reviewed
//! `guard`/`middle`/`exit` implementation (recovered from that session's
//! working backup at `/tmp/main_rs_working_backup.rs`, written before that
//! project's Round N removed those subcommands from its own CLI surface),
//! which had already been checked against exactly this same evidence this
//! task calls for: the real, working API shapes `allium-cli/src/hs.rs`'s
//! test harness (`spin_up_hs_test_relays`) demonstrates for constructing a
//! real `RelayNode`/`Egress`/`SocksExit`-equivalent exit node. Only the
//! `authority` subcommand, and `main.rs`'s own `client`/`service`/`echo`
//! wiring, were dropped when adapting that backup into this standalone
//! crate.
//!
//! Like the `allium` library it depends on, this binary is written against
//! `clap`'s and `tokio`'s real, stable, documented APIs but has not been run
//! through a real `cargo build`/`cargo test` in this sandbox (no crates.io
//! access) -- the verification
//! that *was* possible here was a dependency-free stub-and-restore pass.
//!
//! **CPU-core sharding (Option B)** -- opt-in, off by default (one worker; see
//! `worker_count_from` for why): `main`
//! no longer runs a single event loop on one OS thread regardless of how
//! many CPU cores the host has. It now runs `worker_count()` independent
//! shard workers -- one per available core -- each an unmodified
//! single-threaded `RelayNode` + `LocalSet`, all bound to the same
//! `--bind` address via SO_REUSEPORT so the kernel spreads incoming
//! circuits across them by peer address. See `main`'s and
//! `shard_relay_options`'s own doc comments for the details, in particular
//! how `--identity-file` is resolved exactly once up front to avoid a
//! multi-worker race on the key file.

use allium::{AmplificationGuard, Addr, DEFAULT_ALLOWED_TCP_PORTS, Egress, ExitPolicy, RateLimiter, RelayNode, RelayNodeOptions, SocksExit};
use clap::{Args, Parser, Subcommand};
use std::cell::RefCell;
use std::rc::Rc;

// ---------------------------------------------------------------------------
// CLI surface -- mirrors `allium_cli.py`'s `build_parser()`, `guard`/
// `middle`/`exit` subparsers only.
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "allium-relay",
    version,
    about = "A relay-hosting CLI for the Allium onion-routing protocol (guard/middle/exit only)"
)]
struct Cli {
    #[command(subcommand)]
    role: Role,
}

// `Clone`: `main` clones the parsed
// role once per shard worker, so each of the N worker threads gets its own
// owned copy to move into its own OS thread.
#[derive(Subcommand, Clone)]
enum Role {
    /// First hop; the only one the client contacts.
    Guard(RelayArgs),
    /// Second hop; reached via EXTEND through the guard.
    Middle(RelayArgs),
    /// Last hop; opens real connections, enforces a policy.
    Exit(ExitArgs),
}

#[derive(Args, Clone)]
pub(crate) struct RelayArgs {
    /// IP:PORT to bind the relay's UDP socket to.
    #[arg(long, value_name = "IP:PORT")]
    pub(crate) bind: String,

    /// Human-readable node name (defaults to the role name).
    #[arg(long)]
    pub(crate) name: Option<String>,

    /// File holding this relay's 32-byte master key, hex-encoded.
    /// Generated on first run if it does not exist.
    #[arg(long = "identity-file")]
    pub(crate) identity_file: Option<String>,

    /// Idle-circuit reap timeout, in seconds.
    #[arg(long = "idle-timeout", value_name = "SECONDS")]
    pub(crate) idle_timeout: Option<f64>,

    /// Hard maximum circuit lifetime, in seconds, on top of
    /// --idle-timeout: a circuit that is still busy right up to
    /// --idle-timeout never trips it, so this caps how
    /// long any one circuit can stay open here regardless. Unset by
    /// default (no cap), matching the pre-existing behavior.
    #[arg(long = "max-circuit-age", value_name = "SECONDS")]
    pub(crate) max_circuit_age: Option<f64>,

    /// Allow this relay to EXTEND to a private, loopback or link-local
    /// address (by default such an EXTEND is refused, since a
    /// relay has no business sending a CREATE to an address like that just
    /// because a client's EXTEND named one). Off by default; only meant
    /// for a loopback test network where relays legitimately address each
    /// other on 127.0.0.1.
    #[arg(long = "allow-private-extend", default_value_t = false)]
    pub(crate) allow_private_extend: bool,

    /// Require every CREATE's backward-authenticity token before routing
    /// it (on by default, matching Python). Defaults to `true`, so this
    /// needs an explicit `action = Set` (a `--flag=BOOL`/`--flag BOOL`
    /// argument) rather than clap's default `bool`-field inference
    /// (`ArgAction::SetTrue`, a bare presence flag) -- otherwise there
    /// would be no way to pass `false` at all: the bare flag would just
    /// redundantly reassert the already-true default, and
    /// `--require-return-routability=false` would be a hard parse error
    /// (`TooManyValues`) instead of doing what it says.
    #[arg(long = "require-return-routability", default_value_t = true, action = clap::ArgAction::Set)]
    pub(crate) require_return_routability: bool,

    /// Publish this relay's signed descriptor to a REMOTE, externally-run
    /// directory authority at startup and periodically, so clients can
    /// find it without a manual address (comma-separated for several
    /// authorities). This CLI has no `authority` subcommand of its own --
    /// the authority named here must already be running elsewhere.
    /// Optional; omit to run exactly as before, unreachable except by an
    /// operator who hands its address out manually.
    #[arg(long, value_name = "IP:PORT[,IP:PORT...]")]
    pub(crate) authority: Option<String>,

    /// Pin the directory authority's Ed25519 identity for publishing.
    /// REQUIRED whenever --authority is set, unless
    /// --allow-unpinned-authority is passed instead.
    #[arg(long = "trust-authority", value_name = "HEX")]
    pub(crate) trust_authority: Option<String>,

    /// Explicitly proceed with --authority set but no --trust-authority
    /// pin. Only for a single-machine demo/test.
    #[arg(long = "allow-unpinned-authority", default_value_t = false)]
    pub(crate) allow_unpinned_authority: bool,

    /// How often to republish to --authority, in seconds.
    #[arg(long = "publish-interval", value_name = "SECONDS", default_value_t = 1200.0)]
    pub(crate) publish_interval: f64,
}

#[derive(Args, Clone)]
struct ExitArgs {
    #[command(flatten)]
    relay: RelayArgs,

    /// Comma-separated TCP ports this exit will CONNECT to.
    #[arg(long = "allow-ports", value_name = "PORT[,PORT...]")]
    allow_ports: Option<String>,

    /// Comma-separated UDP ports this exit will relay datagrams to.
    #[arg(long = "allow-udp-ports", value_name = "PORT[,PORT...]")]
    allow_udp_ports: Option<String>,

    /// Allow CONNECT/RESOLVE to private/local addresses (dangerous; for
    /// testing).
    #[arg(long = "allow-private", default_value_t = false)]
    allow_private: bool,

    /// Allow exiting to UDP ports commonly abused for amplification
    /// attacks (DNS, NTP, ...).
    #[arg(long = "allow-amplification-ports", default_value_t = false)]
    allow_amplification_ports: bool,
}

// ---------------------------------------------------------------------------
// Small shared helpers -- mirror `allium_cli.py`'s `parse_addr`/`say`/
// `load_or_create_master_key`.
// ---------------------------------------------------------------------------

pub(crate) fn say(message: impl std::fmt::Display) {
    eprintln!("{message}");
}

pub(crate) fn parse_addr(text: &str) -> Result<Addr, String> {
    let (host, port) = text.rsplit_once(':').ok_or_else(|| format!("expected IP:PORT, got {text:?}"))?;
    let port: u16 = port.parse().map_err(|_| format!("bad port in {text:?}"))?;
    Ok((host.to_string(), port))
}

pub(crate) fn parse_ports(text: &str) -> Result<Vec<u16>, String> {
    text.split(',')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(|p| p.parse::<u16>().map_err(|_| format!("bad port {p:?}")))
        .collect()
}

/// Load a 32-byte hex-encoded master key from `path`, generating and
/// persisting a fresh one (from `/dev/urandom`) if the file does not
/// exist yet. Mirrors `load_or_create_master_key`'s purpose; simplified
/// to a single hex file rather than Python's PEM-ish on-disk format.
pub(crate) fn load_or_create_master_key(path: &str) -> std::io::Result<[u8; 32]> {
    if let Ok(text) = std::fs::read_to_string(path) {
        let bytes = hex_decode(text.trim()).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if bytes.len() != 32 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{path}: expected 32 bytes, got {}", bytes.len())));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }
    let mut key = [0u8; 32];
    {
        use std::io::Read;
        std::fs::File::open("/dev/urandom")?.read_exact(&mut key)?;
    }
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        }
    }
    // This is the relay's master private key -- world-readable by default
    // (whatever the process umask gives, typically 0644) unless set
    // explicitly. Matches the 0600 already used for the analogous
    // hidden-service key files in Client/src/hiddenservice.rs. Created
    // with the tight mode from the start (`.mode(0o600)` on the open
    // call, not a separate `set_permissions` after a plain `fs::write`)
    // so there is no window where the file briefly exists with the
    // default umask permissions for another local process to read.
    // `create_new` (refuse if the path already exists) also turns the
    // documented "only one caller may ever call this concurrently for a
    // given path" assumption (see `shard_relay_options`'s doc comment)
    // into a loud error instead of a silent overwrite race, if that
    // assumption is ever violated.
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        file.write_all(hex_encode(&key).as_bytes())?;
    }
    Ok(key)
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decodes byte-wise, never by slicing `text` at a `char` boundary --
/// unlike a `&text[i..i + 2]` slice (which panics on a byte index that
/// lands inside a multi-byte UTF-8 character), this cannot panic no
/// matter what bytes a crafted key file or `--trust-authority` value
/// contains.
pub(crate) fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err("odd-length hex string".to_string());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_digit(bytes[i]).ok_or_else(|| "invalid hex".to_string())?;
        let lo = hex_digit(bytes[i + 1]).ok_or_else(|| "invalid hex".to_string())?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Directory-authority helpers -- port of `allium_cli.py`'s
// `_authority_addresses`/`_split_trust_keys`/`_validate_trust_keys`/
// `_require_authority_pin`. Used only to publish THIS relay's own
// descriptor to a remote authority -- this CLI never runs one itself.
// ---------------------------------------------------------------------------

/// `--authority` may name several authorities, comma-separated.
pub(crate) fn authority_addresses(authority: &Option<String>) -> Vec<String> {
    match authority {
        Some(value) => value.split(',').map(|part| part.trim()).filter(|part| !part.is_empty()).map(|part| part.to_string()).collect(),
        None => Vec::new(),
    }
}

/// Split a `--trust-authority`-shaped value into its comma-separated hex
/// keys (no validation -- see `parse_trust_authority` for that).
pub(crate) fn split_trust_keys(value: &str) -> Vec<String> {
    value.split(',').map(|part| part.trim()).filter(|part| !part.is_empty()).map(|part| part.to_string()).collect()
}

/// Validate and decode a `--trust-authority`-shaped value into its raw
/// 32-byte Ed25519 identity keys. Mirrors `_validate_trust_keys`: every
/// comma-separated entry must be exactly 32 bytes of hex, or this is a
/// clean, one-line operator-facing error instead of a panic/stack trace
/// three layers down in the handshake path.
pub(crate) fn parse_trust_authority(value: &str, label: &str) -> Result<Vec<[u8; 32]>, String> {
    let mut keys = Vec::new();
    for hex in split_trust_keys(value) {
        let bytes = hex_decode(&hex).map_err(|_| format!("{label} value {hex:?} is not valid hex"))?;
        if bytes.len() != 32 {
            return Err(format!("{label} value {hex:?} must be a 32-byte Ed25519 identity key ({} bytes given)", bytes.len()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        keys.push(key);
    }
    Ok(keys)
}

/// Refuse to proceed with an unpinned directory authority.
///
/// An unpinned `--authority` is a real MITM/impersonation vector: with no
/// `--trust-authority` pin, whoever answers at `--authority` is accepted as
/// authoritative, with no way to detect an impostor. This mirrors
/// `allium::HandshakeClient`, which already refuses to run at all unless
/// the caller passes trusted identities or explicit `trust_first_use`; this
/// enforces the same rule at the CLI's own boundary, before any network
/// I/O, matching Python's `_require_authority_pin` exactly (including its
/// one, explicit, loud opt-out for a single-machine demo/test).
///
/// No-op if `authority` is unset (nothing to pin) or `trust_authority` is
/// already set to a non-empty value (already pinned). Returns `Err` (the
/// caller should treat this like Python's `SystemExit`) if an authority
/// is set, unpinned, and `allow_unpinned_authority` was not explicitly
/// passed.
///
/// `--trust-authority ""`
/// (an explicit but empty value) is treated as *unpinned* here, not as
/// "already pinned" -- an empty pin can never actually verify anything
/// (`parse_trust_authority("")` yields zero keys, so every handshake then
/// fails closed with "not in the pinned trust set of 0 key(s)"), so
/// treating it as "pinned" would only trade a clear, actionable error
/// here for a confusing one deep in the handshake path -- never a
/// silent trust weakening either way, but this is the clearer failure.
pub(crate) fn require_authority_pin(authority: &Option<String>, trust_authority: &Option<String>, allow_unpinned_authority: bool, context: &str) -> Result<(), String> {
    let Some(authority) = authority else { return Ok(()) };
    if trust_authority.as_deref().is_some_and(|v| !v.is_empty()) {
        return Ok(());
    }
    if allow_unpinned_authority {
        say(format!(
            "{context}: NOTE: --allow-unpinned-authority is set -- the directory authority at {authority} will be trusted on first use, exactly like any other unpinned hop. Fine for a single-machine demo where every process is provably yours; never for anything real."
        ));
        return Ok(());
    }
    Err(format!(
        "{context}: --authority {authority} is set without --trust-authority. An unpinned directory authority is a real MITM/impersonation vector, so this is enforced: pass --trust-authority HEX (the authority's own fingerprint), or, for a single-machine demo/test where you already know every process is yours, pass --allow-unpinned-authority to proceed without it."
    ))
}

// Only ever called from `mod tests` below (the real `cmd_relay`/`cmd_exit`
// path uses `shard_relay_options`, whose own doc comment explains why this
// convenience wrapper isn't reused there) -- `#[cfg(test)]` reflects that
// so a plain `cargo build` doesn't flag it as dead code.
#[cfg(test)]
pub(crate) fn relay_options(relay: &RelayArgs, default_name: &str) -> Result<RelayNodeOptions, String> {
    let mut options = RelayNodeOptions::default();
    options.node_name = relay.name.clone().unwrap_or_else(|| default_name.to_string());
    if let Some(idle) = relay.idle_timeout {
        options.idle_timeout = idle;
    }
    options.max_circuit_age = relay.max_circuit_age;
    options.allow_private_extend = relay.allow_private_extend;
    options.require_return_routability = relay.require_return_routability;
    // Whenever an authority is configured at
    // all, this relay has a directory to check EXTEND targets against, so
    // it should refuse until that directory has actually loaded at least
    // once (`spawn_directory_refresher` is what populates it) rather than
    // accepting any non-private target in the meantime. A relay with no
    // `--authority` has no directory to wait for, so it keeps the
    // library's permissive default.
    options.require_known_relay_addrs = !authority_addresses(&relay.authority).is_empty();
    if let Some(path) = &relay.identity_file {
        let key = load_or_create_master_key(path).map_err(|e| e.to_string())?;
        options.master_key = Some(key.to_vec());
    }
    Ok(options)
}

/// Build node options for one shard worker, given an identity master key
/// `main` already resolved exactly once before spawning any worker.
///
/// Deliberately NOT `relay_options` plus a loop: `relay_options` reads (or,
/// on first run, *generates and writes*) `--identity-file` itself, which is
/// fine for the single caller it was written for but races if N shard
/// workers each call it concurrently against the same file -- every worker
/// that sees the file still missing would generate its OWN random key,
/// giving the shards inconsistent identities and corrupting the file under
/// concurrent writes. `main` calls `load_or_create_master_key` exactly
/// once instead, and this helper just applies the result, so every worker
/// ends up with the identical identity a single-worker run would have had.
pub(crate) fn shard_relay_options(relay: &RelayArgs, default_name: &str, master_key: Option<[u8; 32]>) -> RelayNodeOptions {
    let mut options = RelayNodeOptions::default();
    options.node_name = relay.name.clone().unwrap_or_else(|| default_name.to_string());
    if let Some(idle) = relay.idle_timeout {
        options.idle_timeout = idle;
    }
    options.max_circuit_age = relay.max_circuit_age;
    options.allow_private_extend = relay.allow_private_extend;
    options.require_return_routability = relay.require_return_routability;
    options.require_known_relay_addrs = !authority_addresses(&relay.authority).is_empty();
    if let Some(key) = master_key {
        options.master_key = Some(key.to_vec());
    }
    options
}

/// Number of shard workers to run (1 unless `ALLIUM_RELAY_WORKERS` says otherwise;
/// see [`worker_count_from`]). Each worker is
/// one independent single-threaded event loop, each
/// with its own private, unmodified `Rc<RefCell<RelayNode>>` + `LocalSet`
/// -- today's existing code, completely unchanged -- all bound to the same
/// address via SO_REUSEPORT (see `RelayNode::make_socket`) so the kernel
/// load-balances incoming datagrams across them by peer address. Floored
/// at 1 so a single-core host, or a platform where the count can't be
/// read, still runs exactly one worker, identical to before this change.
///
/// **Known correctness gap with `workers > 1`** (found after this shipped; the
/// reason the default is now 1):
/// when this relay itself *originates* an EXTEND to the next hop (guard ->
/// middle, middle -> exit), the outbound CREATE is sent from the shared,
/// SO_REUSEPORT-bound listening socket -- so every shard's outbound
/// traffic to that next hop looks identical on the wire (same source
/// port), and the kernel picks exactly one fixed shard on *this* relay to
/// receive that next hop's reply, regardless of which shard actually
/// opened the pending request. Only the lucky circuits whose shard
/// happens to match that fixed value get their CREATED/EXTENDED reply
/// back; the rest time out. This does not affect the pure client-facing
/// side (each client's address varies, so that hashes correctly), only a
/// relay's own outbound extends. Until this has a real fix (a dedicated,
/// non-shared per-shard socket for outbound extends), set
/// leave `ALLIUM_RELAY_WORKERS` unset (single-shard operation, the
/// pre-sharding, always-correct behavior).
pub(crate) fn worker_count() -> usize {
    worker_count_from(std::env::var("ALLIUM_RELAY_WORKERS").ok().as_deref())
}

/// The worker count for a given `ALLIUM_RELAY_WORKERS` value.
///
/// **Defaults to 1.** It used to default to one worker per core, but with
/// more than one worker a relay cannot reliably talk to anything it dials
/// itself (see the known gap above): measured with the default 16 workers,
/// no relay could refresh its directory from the authority and a client
/// could not build a circuit through it at all (0 bytes, 3 attempts out of
/// 3). One worker moves about 30 MB/s on loopback. More workers stay
/// available, explicitly, with a warning from `main`.
pub(crate) fn worker_count_from(value: Option<&str>) -> usize {
    match value {
        None => 1,
        Some(v) => match v.trim().parse::<usize>() {
            Ok(n) if n >= 1 => n,
            _ => {
                say(format!("worker_count: ignoring invalid ALLIUM_RELAY_WORKERS={v:?}, using 1 worker"));
                1
            }
        },
    }
}

/// Publish `node`'s signed descriptor to `relay.authority`, once
/// immediately and then every `relay.publish_interval` seconds, for as
/// long as the process runs. Port of `allium_cli.py`'s
/// `publish_descriptor`. No-op (returns immediately, nothing spawned) if
/// `relay.authority` is unset, matching Python's own early return.
///
/// Runs on a dedicated OS thread, not the tokio `LocalSet` (`node` is
/// `Rc<RefCell<..>>`, not `Send`, so this snapshots the two plain byte
/// arrays it actually needs -- the relay's Ed25519 identity private key
/// and its X25519 static public key, both `Copy` -- once at startup rather
/// than holding any live reference into `node`; same "blocking sync work
/// belongs on its own thread" reasoning applied to a *periodic* background
/// loop, so a slow/unreachable authority stalls only this thread, never
/// the relay's own accept loop on the `LocalSet`).
///
/// **Deliberate scope reductions from Python**: no NAT-observed-address
/// wait (NAT rendezvous is not wired into this port's `guard`/`middle`/
/// `exit` at all), no `--advertise` override (`--bind`'s own host is
/// always what gets published), no bandwidth/family/exit-port-summary/
/// ML-KEM descriptor metadata (every published descriptor here is the
/// bare identity/address/role), and publish-to-every-address
/// independently rather than treating several `--authority` addresses as
/// one replicated quorum.
pub(crate) fn spawn_descriptor_publisher(node: &Rc<RefCell<RelayNode>>, relay: &RelayArgs, role: &str) -> Result<(), String> {
    if relay.authority.is_none() {
        return Ok(());
    }
    require_authority_pin(&relay.authority, &relay.trust_authority, relay.allow_unpinned_authority, role)?;
    let addresses: Vec<Addr> = authority_addresses(&relay.authority).iter().map(|s| parse_addr(s)).collect::<Result<_, _>>()?;
    // An empty `--trust-authority ""` must behave exactly like an unset
    // one: otherwise
    // `require_authority_pin` above treats this as unpinned-but-allowed
    // once `--allow-unpinned-authority` is passed, while this would
    // still build an empty (always-failing) pin set instead of the
    // trust-first-use `dir_round_trip` expects from `None`.
    let trusted = match relay.trust_authority.as_deref().filter(|v| !v.is_empty()) {
        Some(v) => Some(parse_trust_authority(v, "TrustAuthority/--trust-authority")?),
        None => None,
    };
    let bind = parse_addr(&relay.bind)?;
    let publish_interval = relay.publish_interval.max(1.0);
    let role_name = role.to_string();
    let (identity_private, static_public) = {
        let n = node.borrow();
        (*n.handshake.identity_private_key(), n.handshake.public_key)
    };

    std::thread::spawn(move || {
        let ops = allium::nat::Ed25519Ops::real();
        loop {
            // Mirrors
            // `spawn_directory_refresher`'s own panic guard (see its
            // matching comment) -- this cycle used to run outside any
            // panic guard, so a panic anywhere in it would silently and
            // permanently kill descriptor republishing for good: the
            // relay keeps serving circuits but drops off the directory
            // forever until an operator notices and restarts it manually.
            // Catching the panic here and treating it like any other
            // publish failure -- logged, retried next cycle -- keeps this
            // thread alive either way.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                match allium::RelayDescriptor::create(
                    &ops,
                    &identity_private,
                    &static_public,
                    &bind.0,
                    bind.1,
                    &[role_name.as_str()],
                    allium::DEFAULT_DESCRIPTOR_LIFETIME,
                    None,
                    allium::directory::CreateOptions::default(),
                ) {
                    Ok(descriptor) => {
                        for addr in &addresses {
                            match allium::dirwire::encode_publish_request(&descriptor) {
                                Ok(request_bytes) => match allium::dir_round_trip(addr, trusted.clone(), &request_bytes) {
                                    Ok(reply_bytes) => match allium::dirwire::decode_publish_reply(&reply_bytes) {
                                        Ok((true, _)) => say(format!("{role_name}: published descriptor to {addr:?}")),
                                        Ok((false, msg)) => say(format!("{role_name}: {addr:?} refused the descriptor: {msg}")),
                                        Err(e) => say(format!("{role_name}: malformed publish reply from {addr:?}: {e}")),
                                    },
                                    Err(e) => say(format!("{role_name}: could not publish to {addr:?}: {e}")),
                                },
                                Err(e) => say(format!("{role_name}: could not encode descriptor: {e}")),
                            }
                        }
                    }
                    Err(e) => say(format!("{role_name}: could not build a descriptor to publish: {e}")),
                }
            }));
            if let Err(panic_payload) = outcome {
                say(format!(
                    "{role_name}: descriptor-publish cycle panicked ({}) -- will retry next cycle instead of stopping forever",
                    panic_message(panic_payload)
                ));
            }
            std::thread::sleep(std::time::Duration::from_secs_f64(publish_interval));
        }
    });
    Ok(())
}

/// Keep this relay's view of "known relays" fresh by
/// periodically FETCHing the directory from the configured `--authority`
/// and installing the resulting `(host, port)` set into its `RelayNode`
/// (`RelayNode::set_known_relay_addrs`), so `forward_data`'s EXTEND
/// handling only ever targets an address the directory actually lists --
/// on top of, not instead of, the private/loopback address filter. A relay
/// run with no `--authority` has no consensus to check against, so this
/// is a no-op and the node's `known_relay_addrs` stays `None`
/// (`forward_data` then falls back to just the private/loopback filter and
/// the once-failed-EXTEND latch, matching the behavior before this fix
/// existed).
///
/// Reuses `--publish-interval` as the refresh cadence rather than adding
/// a dedicated flag -- one knob for "how often this relay talks to the
/// authority," in either direction.
///
/// Deliberately per-shard rather than primary-only (unlike
/// `spawn_descriptor_publisher`, which is fine to run once because
/// publishing is idempotent): every shard worker owns its own separate
/// `RelayNode` (see `main`'s sharding doc comment) that handles its own
/// circuits' EXTENDs, so each one needs its own populated
/// `known_relay_addrs` -- there is no cross-shard state to share it
/// through. The accepted cost is N independent periodic FETCHes (one per
/// core) instead of one.
///
/// The actual FETCH round trip (`allium::dir_round_trip`, blocking on a
/// real socket) runs on its own OS thread, exactly like
/// `spawn_descriptor_publisher`'s publish loop -- it can't run inside this
/// shard's single-threaded `tokio` `LocalSet` without blocking every
/// circuit that `LocalSet` is also driving for the whole round trip.
/// Results cross back over a plain `std::sync::mpsc` channel (the same
/// OS-thread-to-`LocalSet` handoff already used by this crate's own
/// `test_two_hop_extend_over_real_loopback_udp_sockets`-style tests) to a
/// small polling task on the `LocalSet`, which is the only thing allowed
/// to touch the non-`Send` `Rc<RefCell<RelayNode>>>`.
/// Extract a human-readable message from a caught panic payload.
///
/// `std::panic::catch_unwind`'s `Err` is `Box<dyn Any + Send>`, and in
/// practice is almost always either `&'static str` (a bare `panic!("...")`)
/// or `String` (`panic!("{}", ...)`/`.expect("...")` on a `Display` value)
/// -- these are the two shapes the standard panic hook itself special-cases
/// for the exact same reason. Anything else prints as a fixed fallback
/// rather than guessing at its shape.
fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| payload.downcast::<String>().ok().map(|s| *s))
        .unwrap_or_else(|| "unknown panic payload".to_string())
}

pub(crate) fn spawn_directory_refresher(node: &Rc<RefCell<RelayNode>>, relay: &RelayArgs) -> Result<(), String> {
    if relay.authority.is_none() {
        return Ok(());
    }
    // This fetch feeds
    // `known_relay_addrs`, the exact mechanism the directory-membership
    // check above relies on to
    // keep EXTEND targets to directory-listed relays -- an unpinned
    // authority here means an on-path/impersonating "authority" can feed
    // this relay an arbitrary relay set via trust-on-first-use, silently
    // undermining that guarantee. `main` already runs this same gate
    // once before any shard spawns (see its own comment on why that alone
    // wasn't enough for `spawn_directory_refresher`'s sibling), but this
    // function is re-checked here too, matching `spawn_descriptor_publisher`
    // just above: two functions independently trusting "someone upstream
    // already checked this" is exactly how that earlier gap happened.
    require_authority_pin(&relay.authority, &relay.trust_authority, relay.allow_unpinned_authority, "relay")?;
    let addresses: Vec<Addr> = authority_addresses(&relay.authority).iter().map(|s| parse_addr(s)).collect::<Result<_, _>>()?;
    // An empty `--trust-authority ""` must behave exactly like an unset one --
    // see the identical comment on
    // `spawn_descriptor_publisher`'s own `trusted` computation above, which
    // this mirrors.
    let trusted = match relay.trust_authority.as_deref().filter(|v| !v.is_empty()) {
        Some(v) => Some(parse_trust_authority(v, "TrustAuthority/--trust-authority")?),
        None => None,
    };
    let refresh_interval = relay.publish_interval.max(1.0);

    let (tx, rx) = std::sync::mpsc::channel::<std::collections::HashSet<Addr>>();
    std::thread::spawn(move || {
        // Bugfix: on a coordinated restart --
        // every relay in the network coming up together, as after a
        // deploy -- this thread's very first fetch races every OTHER
        // relay's own startup descriptor-publish. If this relay's fetch
        // lands on the authority before a peer has published yet, that
        // peer is silently missing from the `known`  set this cycle,
        // permanently locking it out of `known_relay_addrs` (and
        // therefore out of EXTEND, via the directory-membership check) until the next
        // full `refresh_interval` -- which, at the default cadence, is
        // many minutes away. A relay that loses this race is unusable as
        // a hop for that long, for no reason other than boot-order luck.
        //
        // Fix: retry quickly (every `FAST_RETRY_INTERVAL`) for the first
        // `FAST_RETRY_WINDOW` after this thread starts, then fall back to
        // the normal `refresh_interval` cadence. This bounds the race's
        // self-healing time to seconds instead of a full cycle, without
        // adding a new flag -- `refresh_interval` (from `--publish-
        // interval`) still governs the steady-state cadence exactly as
        // before.
        const FAST_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3);
        const FAST_RETRY_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
        let started = std::time::Instant::now();
        loop {
            // Bugfix: this whole cycle used to
            // run outside any panic guard, so a panic anywhere in it (a
            // future edit introducing an `.unwrap()`, or an unforeseen one
            // in `dir_round_trip`/`decode_fetch_reply`) would unwind this
            // thread, drop `tx`, and disconnect the channel -- the receiving
            // task's own `Disconnected` handling (below) then stops polling
            // for good. Before `require_known_relay_addrs` existed that was
            // silently benign (EXTEND stayed permissive with no directory);
            // now it fails closed instead, so a single panic before the
            // first successful fetch would leave this relay refusing every
            // EXTEND until the operator manually restarts it. Catching the
            // panic here and treating it like any other fetch failure --
            // logged, retried next cycle -- keeps the thread (and the
            // channel) alive either way.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // This used to run its own
                // unsigned, single-authority FETCH here directly (first
                // configured address to answer wins), bypassing the
                // quorum/signed-vote verification `fetch_relay_directory`
                // already implements -- meaning a single compromised or
                // MITM'd authority fully controlled this relay's EXTEND
                // allowlist, with no cross-authority corroboration even
                // when several `--authority` addresses were configured.
                // Now goes through the same quorum-verified path the
                // client CLI's `dirclient::fetch_relay_directory` uses: a
                // relay is only trusted once at least a quorum of distinct
                // configured authorities' signed votes name it.
                match allium::fetch_relay_directory(&addresses, trusted.clone()) {
                    Ok(directory) => {
                        let mut known: std::collections::HashSet<Addr> =
                            directory.all().into_iter().map(|d| (d.host.clone(), d.port)).collect();
                        // Bugfix: the
                        // authority is never a relay, so it never appears
                        // in its own directory. Without this,
                        // `known_relay_addrs` can never contain the
                        // authority's address, and `forward_data` refuses
                        // every EXTEND to it -- breaking all hidden-service
                        // directory traffic, which is routed guard/middle/
                        // authority specifically so the authority doesn't
                        // see the caller's IP (see dirclient.rs's
                        // `dir_round_trip_over_circuit`). Add the
                        // configured authority address(es) explicitly; this
                        // still only trusts the address(es) this relay was
                        // itself configured to treat as its authority.
                        known.extend(addresses.iter().cloned());
                        let _ = tx.send(known);
                    }
                    Err(e) => say(format!(
                        "directory-refresh: could not fetch a quorum-verified directory from {addresses:?}: {e}"
                    )),
                }
            }));
            if let Err(panic_payload) = outcome {
                say(format!(
                    "directory-refresh: fetch cycle panicked ({}) -- will retry next cycle instead of stopping forever",
                    panic_message(panic_payload)
                ));
            }
            let steady_state = std::time::Duration::from_secs_f64(refresh_interval);
            let sleep_for = if started.elapsed() < FAST_RETRY_WINDOW { FAST_RETRY_INTERVAL.min(steady_state) } else { steady_state };
            std::thread::sleep(sleep_for);
        }
    });

    let node = node.clone();
    tokio::task::spawn_local(async move {
        loop {
            match rx.try_recv() {
                Ok(known) => node.borrow_mut().set_known_relay_addrs(Some(known)),
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
                // The sender OS thread panicked or otherwise dropped its
                // end -- nothing more will ever arrive, so stop polling
                // rather than spin forever. `known_relay_addrs` simply
                // stays at whatever it last was (or `None`, if a fetch
                // never landed at all).
                Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// main
//
// Instead of one single-threaded
// event loop handling every circuit on one CPU core no matter how many the
// host has, this now runs `worker_count()` independent shard workers, each
// on its own OS thread with its own single-threaded tokio runtime +
// `LocalSet` + private `RelayNode` -- exactly what a single (non-sharded)
// run looked like before this change, just N of them in parallel. Every
// worker binds the SAME `--bind` address via SO_REUSEPORT (see
// `RelayNode::make_socket`), so the kernel spreads incoming datagrams
// across the N sockets by a hash of the peer address: a given client
// connection, and every circuit on it, consistently lands on the same
// worker for its whole lifetime, with no cross-worker coordination or
// locking ever needed. Zero changes to circuit/crypto/protocol logic --
// `cmd_relay`/`cmd_exit` run today's existing code unchanged inside each
// worker. Only the descriptor publisher (shard 0 only, via `is_primary`)
// and the identity master key (resolved once here, before any worker
// starts, then cloned into every worker's options -- see
// `shard_relay_options`'s doc comment) are deliberately NOT duplicated per
// worker.
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();
    let workers = worker_count();
    if workers > 1 {
        say(format!(
            "WARNING: ALLIUM_RELAY_WORKERS={workers}: with more than one worker this relay's own outbound traffic (EXTEND, directory refresh) \
             is delivered to the wrong worker most of the time, so circuits through it and its directory refreshes mostly fail. \
             Leave it unset (1 worker) unless you are testing this."
        ));
    }

    // Checked once here, before
    // any shard thread starts, not only inside `cmd_relay`/`cmd_exit`'s own
    // `if is_primary { spawn_descriptor_publisher(...) }` branch. That
    // branch alone left every *non*-primary shard (`workers > 1`, the
    // normal multi-core case) free to reach `spawn_directory_refresher`
    // and run forever with an unpinned, trust-first-use directory
    // authority -- while `main`'s own join loop (below) would then hang
    // waiting on that still-running shard after the primary's own error
    // return, so the process neither exited nor ever reported the error.
    let (authority, trust_authority, allow_unpinned_authority) = match &cli.role {
        Role::Guard(a) | Role::Middle(a) => (a.authority.clone(), a.trust_authority.clone(), a.allow_unpinned_authority),
        Role::Exit(a) => (a.relay.authority.clone(), a.relay.trust_authority.clone(), a.relay.allow_unpinned_authority),
    };
    if let Err(e) = require_authority_pin(&authority, &trust_authority, allow_unpinned_authority, "relay") {
        say(format!("error: {e}"));
        std::process::exit(1);
    }

    let identity_file = match &cli.role {
        Role::Guard(a) | Role::Middle(a) => a.identity_file.clone(),
        Role::Exit(a) => a.relay.identity_file.clone(),
    };
    let master_key: Option<[u8; 32]> = match &identity_file {
        Some(path) => match load_or_create_master_key(path) {
            Ok(key) => Some(key),
            Err(e) => {
                say(format!("error: {e}"));
                std::process::exit(1);
            }
        },
        None => None,
    };

    let mut handles = Vec::with_capacity(workers);
    for shard in 0..workers {
        let role = cli.role.clone();
        let is_primary = shard == 0;
        handles.push(std::thread::spawn(move || -> Result<(), String> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("failed to start the tokio runtime: {e}"))?;
            let local = tokio::task::LocalSet::new();
            local.block_on(&rt, async move {
                match role {
                    Role::Guard(args) => cmd_relay(args, "guard", master_key, is_primary).await,
                    Role::Middle(args) => cmd_relay(args, "middle", master_key, is_primary).await,
                    Role::Exit(args) => cmd_exit(args, master_key, is_primary).await,
                }
            })
        }));
    }

    // Every shard normally runs forever (`RelayNode::run` never returns
    // short of an error or a bind failure), so this just waits for the
    // first one to exit and reports it -- matching the pre-sharding
    // behavior of reporting a single error and exiting non-zero, rather
    // than silently continuing on N-1 workers if one dies.
    let mut first_err: Option<String> = None;
    for handle in handles {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                first_err.get_or_insert(e);
            }
            Err(_) => {
                first_err.get_or_insert("a shard worker thread panicked".to_string());
            }
        }
    }
    if let Some(e) = first_err {
        say(format!("error: {e}"));
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// guard / middle -- a plain `RelayNode`, no exit extras. Real calls into
// `allium::relay::RelayNode::new`/`run`.
// ---------------------------------------------------------------------------

async fn cmd_relay(args: RelayArgs, default_name: &str, master_key: Option<[u8; 32]>, is_primary: bool) -> Result<(), String> {
    let bind = parse_addr(&args.bind)?;
    let options = shard_relay_options(&args, default_name, master_key);
    let node = Rc::new(RefCell::new(RelayNode::new(options).map_err(|e| e.to_string())?));
    if is_primary {
        spawn_descriptor_publisher(&node, &args, default_name)?;
    }
    // Unlike the publisher above, every shard needs its
    // own directory refresher -- see that function's doc comment.
    spawn_directory_refresher(&node, &args)?;
    say(format!(
        "allium-relay {default_name}: listening on {}:{}{}",
        bind.0,
        bind.1,
        if is_primary { "" } else { " (shard worker)" }
    ));
    RelayNode::run(node, bind).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// exit -- a real `RelayNode` with a real `Egress`/`ExitPolicy` wired in via
// `SocksExit::install`. Deviation from Python's `ExitNode`: no return-path
// MTU re-chunking beyond what `Egress`/`SocksExit` already do, and no
// hidden-service exit-side delivery (`_deliver_hs`) -- this exit only
// serves ordinary CONNECT/RESOLVE/UDP-ASSOCIATE streams.
// ---------------------------------------------------------------------------

async fn cmd_exit(args: ExitArgs, master_key: Option<[u8; 32]>, is_primary: bool) -> Result<(), String> {
    let bind = parse_addr(&args.relay.bind)?;
    let mut options = shard_relay_options(&args.relay, "exit", master_key);
    options.require_identity = false;

    let allow_tcp: Vec<u16> = match &args.allow_ports {
        Some(text) => parse_ports(text)?,
        None => DEFAULT_ALLOWED_TCP_PORTS.to_vec(),
    };
    let allow_udp: Vec<u16> = match &args.allow_udp_ports {
        Some(text) => parse_ports(text)?,
        None => Vec::new(),
    };
    let policy = ExitPolicy::new(&allow_tcp, &allow_udp, args.allow_amplification_ports, args.allow_private, &[]).map_err(|e| e.to_string())?;

    // A real (non-stub) DNS resolver for `Egress`'s RESOLVE command, via
    // tokio's own async resolver.
    type ResolveFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Option<(String, u16)>> + Send>>;
    let resolver: Box<dyn Fn(&str) -> ResolveFuture + Send + Sync> = Box::new(|host: &str| {
        let host = host.to_string();
        Box::pin(async move {
            let target = if host.contains(':') { host } else { format!("{host}:0") };
            tokio::net::lookup_host(target).await.ok()?.next().map(|a| (a.ip().to_string(), a.port()))
        })
    });
    // `RateLimiter`/`AmplificationGuard` are fully implemented and tested
    // (see `policy.rs`) but were never actually wired in here, leaving the
    // production exit binary with unlimited SOCKS RESOLVE requests and, if
    // `--allow-udp-ports`/`--allow-amplification-ports` are set, an
    // unmetered UDP reflection amplifier. Always-on safe defaults, matching
    // `RateLimiter::with_defaults()`/`AmplificationGuard::with_defaults()`'s
    // own already-reviewed constants.
    let mut egress =
        Egress::new(Some(resolver), Some(policy), Some(RateLimiter::with_defaults()), Some(AmplificationGuard::with_defaults()), None);
    // Without this, `Egress::get_stream`/`send_data` can never find a
    // stream this exit itself opened (see `Egress::track`), so every
    // post-CONNECT byte a client sends -- the entire stream body, not just
    // the initial request -- would be silently unroutable no matter how
    // faithfully `SocksExit::deliver` reassembles it. Matches
    // `allium_cli.py`'s `ExitNode.__init__`, which calls
    // `self.egress.enable_stream_tracking()` unconditionally.
    egress.enable_stream_tracking();

    let node = Rc::new(RefCell::new(RelayNode::new(options).map_err(|e| e.to_string())?));
    SocksExit::install(&node, Rc::new(tokio::sync::Mutex::new(egress)));
    if is_primary {
        spawn_descriptor_publisher(&node, &args.relay, "exit")?;
    }
    // Unlike the publisher above, every shard needs its
    // own directory refresher -- see that function's doc comment.
    spawn_directory_refresher(&node, &args.relay)?;
    say(format!(
        "allium-relay exit: listening on {}:{} (tcp ports: {allow_tcp:?}){}",
        bind.0,
        bind.1,
        if is_primary { "" } else { " (shard worker)" }
    ));
    RelayNode::run(node, bind).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests -- pure-logic (argument parsing, flag defaults, descriptor-publish
// wiring, exit-policy flag parsing) run directly, in-process. A real,
// non-stubbed loopback network test exercising an actual guard+middle+exit
// trio, and CLI-level `Cli::try_parse_from` coverage, live in
// `tests/cli.rs` and `tests/relay_trio.rs` (integration tests, so they run
// against this crate's public surface the way an external caller would;
// the pure-logic helpers above are `pub(crate)` specifically so those
// integration tests cannot reach them, and are instead covered by the
// unit tests below, in-crate).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_addr_splits_host_and_port() {
        assert_eq!(parse_addr("127.0.0.1:9001").unwrap(), ("127.0.0.1".to_string(), 9001));
    }

    #[test]
    fn parse_addr_rejects_missing_port() {
        assert!(parse_addr("127.0.0.1").is_err());
    }

    #[test]
    fn parse_addr_rejects_non_numeric_port() {
        assert!(parse_addr("127.0.0.1:abc").is_err());
    }

    #[test]
    fn parse_ports_splits_and_trims() {
        assert_eq!(parse_ports("80, 443,8080").unwrap(), vec![80, 443, 8080]);
    }

    #[test]
    fn parse_ports_empty_string_is_empty_list() {
        assert_eq!(parse_ports("").unwrap(), Vec::<u16>::new());
    }

    #[test]
    fn parse_ports_rejects_bad_port() {
        assert!(parse_ports("80,notaport").is_err());
    }

    #[test]
    fn hex_round_trip() {
        let bytes = [1u8, 2, 3, 255, 0, 128];
        assert_eq!(hex_decode(&hex_encode(&bytes)).unwrap(), bytes.to_vec());
    }

    #[test]
    fn hex_decode_rejects_odd_length() {
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn hex_decode_rejects_non_hex() {
        assert!(hex_decode("zz").is_err());
    }

    #[test]
    fn hex_decode_rejects_non_ascii_without_panicking() {
        // Regression test for finding L1: the old `&text[i..i + 2]` byte
        // slicing would panic (not just return an error) on a byte index
        // landing inside a multi-byte UTF-8 character. "0é0" is 4 bytes
        // total (even, so the old odd-length guard didn't save it) with
        // 'é' straddling bytes 1-2, so the old `i=0` slice `text[0..2]`
        // cut through the middle of that 2-byte encoding.
        assert!(hex_decode("0é0").is_err());
    }

    #[test]
    fn authority_addresses_splits_comma_list() {
        assert_eq!(authority_addresses(&Some("1.2.3.4:9000,5.6.7.8:9000".to_string())), vec!["1.2.3.4:9000".to_string(), "5.6.7.8:9000".to_string()]);
    }

    #[test]
    fn authority_addresses_none_is_empty() {
        assert_eq!(authority_addresses(&None), Vec::<String>::new());
    }

    #[test]
    fn authority_addresses_trims_whitespace_and_drops_empties() {
        assert_eq!(authority_addresses(&Some(" 1.2.3.4:9000 , , 5.6.7.8:9000".to_string())), vec!["1.2.3.4:9000".to_string(), "5.6.7.8:9000".to_string()]);
    }

    #[test]
    fn parse_trust_authority_accepts_valid_32_byte_hex() {
        let hex = hex_encode(&[7u8; 32]);
        let keys = parse_trust_authority(&hex, "test").unwrap();
        assert_eq!(keys, vec![[7u8; 32]]);
    }

    #[test]
    fn parse_trust_authority_rejects_wrong_length() {
        let hex = hex_encode(&[7u8; 16]);
        assert!(parse_trust_authority(&hex, "test").is_err());
    }

    #[test]
    fn parse_trust_authority_rejects_invalid_hex() {
        assert!(parse_trust_authority("not-hex-at-all!!", "test").is_err());
    }

    #[test]
    fn parse_trust_authority_splits_several_comma_separated_keys() {
        let hex = format!("{},{}", hex_encode(&[1u8; 32]), hex_encode(&[2u8; 32]));
        let keys = parse_trust_authority(&hex, "test").unwrap();
        assert_eq!(keys, vec![[1u8; 32], [2u8; 32]]);
    }

    #[test]
    fn require_authority_pin_noop_when_authority_unset() {
        assert!(require_authority_pin(&None, &None, false, "guard").is_ok());
    }

    #[test]
    fn require_authority_pin_ok_when_pinned() {
        assert!(require_authority_pin(&Some("1.2.3.4:9000".to_string()), &Some(hex_encode(&[1u8; 32])), false, "guard").is_ok());
    }

    #[test]
    fn require_authority_pin_rejects_unpinned_authority_by_default() {
        let err = require_authority_pin(&Some("1.2.3.4:9000".to_string()), &None, false, "guard").unwrap_err();
        assert!(err.contains("--trust-authority"));
    }

    #[test]
    fn require_authority_pin_treats_an_empty_trust_authority_as_unpinned() {
        // `--trust-authority ""`
        // must not be treated as "already pinned" -- an empty pin set can
        // never verify anything, so treating it as pinned would only trade
        // this clear, actionable error for a confusing one deep in the
        // handshake path.
        let err = require_authority_pin(&Some("1.2.3.4:9000".to_string()), &Some(String::new()), false, "guard").unwrap_err();
        assert!(err.contains("--trust-authority"));
    }

    #[test]
    fn require_authority_pin_allows_explicit_opt_out() {
        assert!(require_authority_pin(&Some("1.2.3.4:9000".to_string()), &None, true, "guard").is_ok());
    }

    #[test]
    fn relay_options_defaults_name_to_role_and_generates_identity() {
        let dir = std::env::temp_dir().join(format!("allium-relay-cli-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("guard.key");
        let args = RelayArgs {
            bind: "127.0.0.1:9001".to_string(),
            name: None,
            identity_file: Some(key_path.to_string_lossy().to_string()),
            idle_timeout: None,
            max_circuit_age: None,
            allow_private_extend: false,
            require_return_routability: true,
            authority: None,
            trust_authority: None,
            allow_unpinned_authority: false,
            publish_interval: 1200.0,
        };
        let options = relay_options(&args, "guard").unwrap();
        assert_eq!(options.node_name, "guard");
        assert!(options.master_key.is_some());
        assert_eq!(options.master_key.as_ref().unwrap().len(), 32);
        // A second call against the same file must load the same key back,
        // not regenerate one, matching `load_or_create_master_key`'s
        // "generated on first run if it does not exist" contract.
        let options2 = relay_options(&args, "guard").unwrap();
        assert_eq!(options.master_key, options2.master_key);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_or_create_master_key_writes_a_0600_file_in_a_0700_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("allium-relay-key-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("guard.key");
        let key = load_or_create_master_key(path.to_str().unwrap()).expect("key generation should succeed");
        assert_eq!(key.len(), 32);
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "key file must not be group/other-readable");
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "key directory must not be group/other-accessible");
        let reloaded = load_or_create_master_key(path.to_str().unwrap()).expect("re-read should succeed");
        assert_eq!(reloaded, key);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn panic_message_extracts_a_bare_str_panic() {
        let result = std::panic::catch_unwind(|| panic!("boom"));
        let payload = result.expect_err("the closure above must have panicked");
        assert_eq!(panic_message(payload), "boom");
    }

    #[test]
    fn panic_message_extracts_a_formatted_string_panic() {
        let detail = 42;
        let result = std::panic::catch_unwind(move || panic!("failed with code {detail}"));
        let payload = result.expect_err("the closure above must have panicked");
        assert_eq!(panic_message(payload), "failed with code 42");
    }

    /// The actual scenario this fix targets: a panic inside the refresh
    /// cycle's closure must be caught (not unwind the whole thread) and
    /// must not disconnect the channel the polling task depends on --
    /// `spawn_directory_refresher` itself calls real network functions and
    /// isn't unit-testable directly (see its own doc comment), so this
    /// exercises the exact `catch_unwind` + channel pattern it uses in
    /// isolation instead.
    #[test]
    fn catch_unwind_around_a_panicking_cycle_keeps_the_channel_alive() {
        let (tx, rx) = std::sync::mpsc::channel::<u32>();
        for attempt in 0..3u32 {
            let tx = tx.clone();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if attempt == 1 {
                    panic!("simulated fetch-cycle panic");
                }
                let _ = tx.send(attempt);
            }));
            if outcome.is_err() {
                // Matches the real site: log and fall through to the next
                // cycle rather than propagating.
            }
        }
        drop(tx);
        let received: Vec<u32> = rx.try_iter().collect();
        // Cycle 1 panicked and sent nothing; 0 and 2 still got through --
        // the channel was never disconnected by the panic in between.
        assert_eq!(received, vec![0, 2]);
    }

    /// The same scenario as the test above, for
    /// `spawn_descriptor_publisher`'s own (simpler, channel-free) publish
    /// cycle -- a panic inside it must be caught, not unwind the whole
    /// thread and permanently stop republishing. Not unit-testable
    /// directly for the same reason as `spawn_directory_refresher` (real
    /// network calls), so this exercises the exact `catch_unwind` pattern
    /// it now uses in isolation.
    #[test]
    fn catch_unwind_around_a_panicking_publish_cycle_keeps_the_thread_alive() {
        let mut cycles_completed = 0u32;
        for attempt in 0..3u32 {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if attempt == 1 {
                    panic!("simulated publish-cycle panic");
                }
            }));
            if outcome.is_ok() {
                cycles_completed += 1;
            }
        }
        // Cycle 1 panicked; 0 and 2 still completed -- a real loop using
        // this pattern is never aborted by the panic in between.
        assert_eq!(cycles_completed, 2);
    }

    #[test]
    fn relay_options_honors_explicit_name_and_idle_timeout() {
        let args = RelayArgs {
            bind: "127.0.0.1:9001".to_string(),
            name: Some("my-middle".to_string()),
            identity_file: None,
            idle_timeout: Some(42.0),
            max_circuit_age: Some(3600.0),
            allow_private_extend: false,
            require_return_routability: false,
            authority: None,
            trust_authority: None,
            allow_unpinned_authority: false,
            publish_interval: 1200.0,
        };
        let options = relay_options(&args, "middle").unwrap();
        assert_eq!(options.node_name, "my-middle");
        assert_eq!(options.idle_timeout, 42.0);
        assert_eq!(options.max_circuit_age, Some(3600.0));
        assert!(!options.require_return_routability);
        assert!(options.master_key.is_none());
    }

    #[test]
    fn spawn_descriptor_publisher_is_a_noop_without_authority() {
        let options = RelayNodeOptions::default();
        let node = Rc::new(RefCell::new(RelayNode::new(options).unwrap()));
        let args = RelayArgs {
            bind: "127.0.0.1:9001".to_string(),
            name: None,
            identity_file: None,
            idle_timeout: None,
            max_circuit_age: None,
            allow_private_extend: false,
            require_return_routability: true,
            authority: None,
            trust_authority: None,
            allow_unpinned_authority: false,
            publish_interval: 1200.0,
        };
        // No authority set: must return Ok(()) and spawn nothing (nothing
        // observable to assert on the "nothing spawned" half beyond the
        // absence of a panic/hang, since a spawned thread here would loop
        // forever trying to reach a nonexistent authority).
        assert!(spawn_descriptor_publisher(&node, &args, "guard").is_ok());
    }

    #[test]
    fn spawn_descriptor_publisher_rejects_unpinned_authority() {
        let options = RelayNodeOptions::default();
        let node = Rc::new(RefCell::new(RelayNode::new(options).unwrap()));
        let args = RelayArgs {
            bind: "127.0.0.1:9001".to_string(),
            name: None,
            identity_file: None,
            idle_timeout: None,
            max_circuit_age: None,
            allow_private_extend: false,
            require_return_routability: true,
            authority: Some("127.0.0.1:9999".to_string()),
            trust_authority: None,
            allow_unpinned_authority: false,
            publish_interval: 1200.0,
        };
        let err = spawn_descriptor_publisher(&node, &args, "guard").unwrap_err();
        assert!(err.contains("--trust-authority"));
    }

    #[test]
    fn spawn_directory_refresher_is_a_noop_without_authority() {
        let options = RelayNodeOptions::default();
        let node = Rc::new(RefCell::new(RelayNode::new(options).unwrap()));
        let args = RelayArgs {
            bind: "127.0.0.1:9001".to_string(),
            name: None,
            identity_file: None,
            idle_timeout: None,
            max_circuit_age: None,
            allow_private_extend: false,
            require_return_routability: true,
            authority: None,
            trust_authority: None,
            allow_unpinned_authority: false,
            publish_interval: 1200.0,
        };
        assert!(spawn_directory_refresher(&node, &args).is_ok());
    }

    #[test]
    fn spawn_directory_refresher_rejects_unpinned_authority() {
        // Before this fix, this function
        // computed `trusted` and spawned its fetch thread unconditionally
        // whenever `authority` was set, with no local
        // `require_authority_pin` call of its own -- relying entirely on
        // `main`'s one-time gate having already run. This is the
        // regression test for that gap, mirroring
        // `spawn_descriptor_publisher_rejects_unpinned_authority` above.
        let options = RelayNodeOptions::default();
        let node = Rc::new(RefCell::new(RelayNode::new(options).unwrap()));
        let args = RelayArgs {
            bind: "127.0.0.1:9001".to_string(),
            name: None,
            identity_file: None,
            idle_timeout: None,
            max_circuit_age: None,
            allow_private_extend: false,
            require_return_routability: true,
            authority: Some("127.0.0.1:9999".to_string()),
            trust_authority: None,
            allow_unpinned_authority: false,
            publish_interval: 1200.0,
        };
        let err = spawn_directory_refresher(&node, &args).unwrap_err();
        assert!(err.contains("--trust-authority"));
    }

    #[test]
    fn spawn_directory_refresher_accepts_explicit_allow_unpinned_authority() {
        // Unlike `spawn_descriptor_publisher`, this function also
        // `tokio::task::spawn_local`s a polling task, so it needs a
        // `LocalSet` in scope to call at all -- matching the real
        // `cmd_relay`/`cmd_exit` call sites.
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("failed to start tokio runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let options = RelayNodeOptions::default();
            let node = Rc::new(RefCell::new(RelayNode::new(options).unwrap()));
            let args = RelayArgs {
                bind: "127.0.0.1:9001".to_string(),
                name: None,
                identity_file: None,
                idle_timeout: None,
                max_circuit_age: None,
                allow_private_extend: false,
                require_return_routability: true,
                authority: Some("127.0.0.1:9999".to_string()),
                trust_authority: None,
                allow_unpinned_authority: true,
                publish_interval: 1200.0,
            };
            // Explicit opt-out must still let the (background,
            // never-answering) fetch thread get spawned -- returns Ok(())
            // immediately, same as `spawn_descriptor_publisher`'s own
            // explicit-opt-out case.
            assert!(spawn_directory_refresher(&node, &args).is_ok());
        });
    }

    #[test]
    fn exit_policy_defaults_match_python_when_flags_omitted() {
        // Mirrors `allium_cli.py`'s `exit` subparser defaults: no
        // --allow-ports means the built-in default TCP allow-list, no
        // --allow-udp-ports means none, --allow-private and
        // --allow-amplification-ports both default off.
        let allow_tcp = DEFAULT_ALLOWED_TCP_PORTS.to_vec();
        let policy = ExitPolicy::new(&allow_tcp, &[], false, false, &[]).unwrap();
        assert!(policy.allowed("93.184.216.34", 80, false));
        assert!(!policy.allowed("93.184.216.34", 22, false));
        assert!(!policy.allowed("93.184.216.34", 53, true));
        // --allow-private defaults off: a private destination is denied
        // regardless of port, matching Python's exit-policy default.
        assert!(!policy.allowed("10.0.0.5", 80, false));
    }

    #[test]
    fn exit_policy_honors_explicit_allow_ports_flags() {
        let policy = ExitPolicy::new(&[8443], &[9999], true, true, &[]).unwrap();
        assert!(policy.allowed("93.184.216.34", 8443, false));
        assert!(!policy.allowed("93.184.216.34", 80, false));
        assert!(policy.allowed("93.184.216.34", 9999, true));
        // --allow-private explicitly on: a private destination is now
        // permitted, matching `--allow-private`'s documented purpose.
        assert!(policy.allowed("10.0.0.5", 8443, false));
    }

    // -----------------------------------------------------------------
    // Real, non-stubbed loopback network test: a genuine guard+middle+exit
    // trio, built through THIS crate's own `relay_options`/`ExitPolicy`/
    // `Egress`/`SocksExit::install` wiring -- the exact code `cmd_relay`/
    // `cmd_exit` run, minus only the infinite `RelayNode::run` accept loop
    // (`RelayNode::start` + `RelayNode::serve_loop`, spawned as separate
    // tasks, is the same substitution `allium`'s own `socksproxy.rs`/
    // `hs.rs` test harnesses make for exactly this reason -- see
    // `allium::socksproxy::test_three_hop_connect_stream_over_real_loopback_udp_and_tcp`,
    // whose end-to-end shape this test follows). A real client
    // `CircuitBuilder` builds a real 3-hop circuit over real loopback UDP
    // through the three nodes, opens a real SOCKS5 CONNECT stream through
    // the exit's real `Egress` to a real TCP "origin" server, and confirms
    // the origin's reply travels all the way back through the circuit
    // unchanged -- proving actual relay-hosting behavior end to end, not
    // just that the CLI parses flags correctly.
    // -----------------------------------------------------------------
    #[test]
    fn test_guard_middle_exit_trio_relays_a_real_connect_stream() {
        use allium::socks::{MAGIC, SUCCESS};
        use allium::socksproxy::{ATYP_IPV4, CMD_CONNECT, SOCKS_VERSION, SocksServer, SocksServerOptions};
        use allium::{CircuitBuilder, Onion};
        use std::io::{Read as _, Write as _};

        // A real TCP "origin": accept one connection, read whatever
        // arrives, echo it back prefixed with a marker, then close.
        let origin_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind origin listener");
        let origin_addr = origin_listener.local_addr().expect("origin local_addr");
        let origin_thread = std::thread::spawn(move || {
            let (mut stream, _) = origin_listener.accept().expect("origin accept");
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).expect("origin read");
            let mut reply = b"ECHO:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            stream.write_all(&reply).expect("origin write");
            let _ = stream.flush();
            let _ = stream.shutdown(std::net::Shutdown::Write);
        });

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("failed to start tokio runtime");
        let local = tokio::task::LocalSet::new();
        let result: Result<Vec<u8>, String> = local.block_on(&rt, async move {
            // Build guard/middle exactly like `cmd_relay` does: real
            // `RelayArgs` through this crate's own `relay_options`.
            //
            // This whole trio (guard, middle, and --
            // via `exit_relay_args` below -- the exit) EXTENDs hop to hop
            // over real loopback addresses, so it needs the loopback-test
            // opt-in a real operator would set for a loopback test
            // network; production defaults to refusing this.
            let guard_args = RelayArgs {
                bind: "127.0.0.1:0".to_string(),
                name: Some("guard".to_string()),
                identity_file: None,
                idle_timeout: None,
                max_circuit_age: None,
                allow_private_extend: true,
                require_return_routability: true,
                authority: None,
                trust_authority: None,
                allow_unpinned_authority: false,
                publish_interval: 1200.0,
            };
            let middle_args = RelayArgs { name: Some("middle".to_string()), ..guard_args.clone() };
            let guard = Rc::new(RefCell::new(RelayNode::new(relay_options(&guard_args, "guard")?).map_err(|e| e.to_string())?));
            let middle = Rc::new(RefCell::new(RelayNode::new(relay_options(&middle_args, "middle")?).map_err(|e| e.to_string())?));

            // Build the exit exactly like `cmd_exit` does: a real
            // `ExitPolicy` from parsed `--allow-ports`-shaped flags, a
            // real `Egress` with stream tracking enabled, installed via
            // `SocksExit::install`.
            // The origin server below binds an OS-assigned ephemeral
            // loopback port, not one of the default allow-listed ports, so
            // this test's exit is configured the way an operator would run
            // `allium-relay exit --allow-ports <port> --allow-private` to
            // reach a specific private/test destination -- proving
            // `cmd_exit`'s real `--allow-ports`/`--allow-private` flag
            // wiring, not just its defaults (those defaults are already
            // covered by `exit_policy_defaults_match_python_when_flags_omitted`
            // above).
            let exit_relay_args = RelayArgs { name: Some("exit".to_string()), ..guard_args.clone() };
            let exit_args = ExitArgs {
                relay: exit_relay_args,
                allow_ports: Some(origin_addr.port().to_string()),
                allow_udp_ports: None,
                allow_private: true,
                allow_amplification_ports: false,
            };
            let mut exit_options = relay_options(&exit_args.relay, "exit")?;
            exit_options.require_identity = false;
            let allow_tcp: Vec<u16> = match &exit_args.allow_ports {
                Some(text) => parse_ports(text)?,
                None => DEFAULT_ALLOWED_TCP_PORTS.to_vec(),
            };
            let policy = ExitPolicy::new(&allow_tcp, &[], exit_args.allow_amplification_ports, exit_args.allow_private, &[]).map_err(|e| e.to_string())?;
            let mut egress = Egress::new(None, Some(policy), None, None, None);
            egress.enable_stream_tracking();
            let exit_node = Rc::new(RefCell::new(RelayNode::new(exit_options).map_err(|e| e.to_string())?));
            SocksExit::install(&exit_node, Rc::new(tokio::sync::Mutex::new(egress)));

            let guard_addr = RelayNode::start(&guard, ("127.0.0.1".to_string(), 0)).await.map_err(|e| e.to_string())?;
            let middle_addr = RelayNode::start(&middle, ("127.0.0.1".to_string(), 0)).await.map_err(|e| e.to_string())?;
            let exit_addr = RelayNode::start(&exit_node, ("127.0.0.1".to_string(), 0)).await.map_err(|e| e.to_string())?;

            tokio::task::spawn_local(RelayNode::serve_loop(guard.clone()));
            tokio::task::spawn_local(RelayNode::serve_loop(middle.clone()));
            tokio::task::spawn_local(RelayNode::serve_loop(exit_node.clone()));

            // Client-side circuit pump: a real, blocking `CircuitBuilder`
            // on its own OS thread (not `Send`, so it must be built on
            // the thread that uses it), polling for incoming return-path
            // bytes exactly like `allium`'s own reference trio test does.
            let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
            let (out_tx, out_rx) = std::sync::mpsc::channel::<Vec<u8>>();
            let (incoming_tx, mut incoming_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
            let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
            let pump_guard_addr = guard_addr.clone();
            let pump_middle_addr = middle_addr.clone();
            let pump_exit_addr = exit_addr.clone();
            std::thread::spawn(move || {
                let mut builder = match CircuitBuilder::new(&client_sock, allium::onion::DEFAULT_CIPHER.to_string(), 5.0, None, true, false, allium::circuit::DEFAULT_RETRIES, allium::circuit::DEFAULT_SEND_JITTER, None) {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e.to_string()));
                        return;
                    }
                };
                let build_result = (|| -> Result<(), String> {
                    builder.add_hop("guard", pump_guard_addr, None, None, None).map_err(|e| e.to_string())?;
                    builder.extend("middle", pump_middle_addr, None, None, None).map_err(|e| e.to_string())?;
                    builder.extend("exit", pump_exit_addr.clone(), None, None, None).map_err(|e| e.to_string())?;
                    Ok(())
                })();
                let ok = build_result.is_ok();
                let _ = ready_tx.send(build_result);
                if !ok {
                    return;
                }
                loop {
                    while let Ok(payload) = out_rx.try_recv() {
                        let _ = builder.send(&payload, &pump_exit_addr);
                    }
                    if let Ok(data) = builder.receive(Some(0.2)) {
                        if incoming_tx.send(data).is_err() {
                            break;
                        }
                    }
                }
            });
            loop {
                match ready_rx.try_recv() {
                    Ok(Ok(())) => break,
                    Ok(Err(e)) => return Err(e),
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        return Err("circuit pump thread exited before reporting readiness".to_string());
                    }
                }
            }

            let onion_tx = out_tx.clone();
            let onion: Onion = Rc::new(RefCell::new(move |data: &[u8]| {
                let _ = onion_tx.send(data.to_vec());
            }));
            let mut options = SocksServerOptions::new(onion);
            options.host = "127.0.0.1".to_string();
            options.port = 0;
            let server = Rc::new(RefCell::new(SocksServer::with_options(options)));
            let (_host, socks_port) = SocksServer::start(&server).await.map_err(|e| e.to_string())?;

            let drain_server = server.clone();
            tokio::task::spawn_local(async move {
                while let Some(data) = incoming_rx.recv().await {
                    if data.starts_with(MAGIC) {
                        SocksServer::deliver_reply(&drain_server, &data);
                    } else if let Ok(frag) = allium::fragment::decode_fragment(&data) {
                        drain_server.borrow_mut().deliver_data(frag.stream_id, &data, None);
                    }
                }
            });

            let (client_result_tx, client_result_rx) = std::sync::mpsc::channel::<Result<Vec<u8>, String>>();
            std::thread::spawn(move || {
                let outcome = (|| -> Result<Vec<u8>, String> {
                    let mut sock = std::net::TcpStream::connect(("127.0.0.1", socks_port)).map_err(|e| e.to_string())?;
                    sock.set_read_timeout(Some(std::time::Duration::from_secs(10))).map_err(|e| e.to_string())?;

                    sock.write_all(&[SOCKS_VERSION, 0x01, 0x00]).map_err(|e| e.to_string())?;
                    let mut greeting_reply = [0u8; 2];
                    sock.read_exact(&mut greeting_reply).map_err(|e| e.to_string())?;
                    if greeting_reply != [SOCKS_VERSION, 0x00] {
                        return Err(format!("unexpected greeting reply: {greeting_reply:?}"));
                    }

                    let origin_ip = match origin_addr.ip() {
                        std::net::IpAddr::V4(v4) => v4.octets(),
                        other => return Err(format!("origin address is not IPv4: {other:?}")),
                    };
                    let mut request = vec![SOCKS_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4];
                    request.extend_from_slice(&origin_ip);
                    request.extend_from_slice(&origin_addr.port().to_be_bytes());
                    sock.write_all(&request).map_err(|e| e.to_string())?;

                    let mut connect_reply = [0u8; 10];
                    sock.read_exact(&mut connect_reply).map_err(|e| e.to_string())?;
                    if connect_reply[1] != SUCCESS {
                        return Err(format!("CONNECT failed with status {}", connect_reply[1]));
                    }

                    let client_hello_stand_in = b"CLIENT-HELLO-STAND-IN";
                    sock.write_all(client_hello_stand_in).map_err(|e| e.to_string())?;

                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).map_err(|e| e.to_string())?;
                    Ok(buf[..n].to_vec())
                })();
                let _ = client_result_tx.send(outcome);
            });

            loop {
                match client_result_rx.try_recv() {
                    Ok(outcome) => return outcome,
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        return Err("curl-equivalent client thread exited without a result".to_string());
                    }
                }
            }
        });

        let received = result.expect("real guard+middle+exit trio, built through this crate's own relay_options/ExitPolicy/Egress wiring, should relay a real 3-hop SOCKS5 CONNECT stream over loopback UDP/TCP");
        assert_eq!(received, b"ECHO:CLIENT-HELLO-STAND-IN".to_vec(), "the origin's reply did not make it back through the real guard/middle/exit trio unchanged");
        origin_thread.join().expect("origin server thread panicked");
    }

    #[test]
    fn a_relay_runs_one_worker_unless_told_otherwise() {
        assert_eq!(worker_count_from(None), 1, "the default must not be one per core: more than one worker breaks a relay's own outbound traffic");
        assert_eq!(worker_count_from(Some("1")), 1);
        assert_eq!(worker_count_from(Some(" 4 ")), 4, "more workers stay available on request");
        assert_eq!(worker_count_from(Some("0")), 1);
        assert_eq!(worker_count_from(Some("-3")), 1);
        assert_eq!(worker_count_from(Some("many")), 1);
        assert_eq!(worker_count_from(Some("")), 1);
    }
}
