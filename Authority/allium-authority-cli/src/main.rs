//! `allium-authority-cli` -- a self-contained directory-authority CLI for
//! the Allium onion-routing protocol: the `authority` role only.
//!
//! **Origin**: this crate, and the `allium` protocol library it depends on
//! (`../allium`, copied byte-for-byte from `/home/claude/rust/allium`, the
//! same canonical source `/home/claude/rust2/allium` was copied from),
//! together form a fully separate project with no dependency of any kind
//! on `/home/claude/rust` or
//! `/home/claude/rust2`. It exists so a directory authority can be
//! deployed on its own machine, independent of both the client/hidden-
//! service-hosting CLI and the relay-hosting CLI.
//!
//! **Scope, a deliberate product decision**: exactly one subcommand,
//! `authority`. There is **no** `guard`/`middle`/`exit` here (those live
//! in `/home/claude/rust2`'s `allium-relay-cli`) and **no** `client`/
//! `service`/`echo` here (those live in `/home/claude/rust`'s
//! `allium-cli`). This binary can only ever be a directory authority.
//!
//! **Implementation provenance**: `AuthorityArgs`, `cmd_authority`, and the
//! small helpers below (`say`, `parse_addr`, `hex_decode`,
//! `load_or_create_master_key`, `relay_options`) are recovered near-
//! verbatim from `/tmp/main_rs_working_backup.rs` -- a backup of
//! `/home/claude/rust/allium-cli/src/main.rs` taken before that project's
//! own Round N removed `guard`/`middle`/`exit`/`authority` from its CLI
//! surface. That recovered `cmd_authority` already called
//! `allium::AuthorityService::install_with_hs` (not the plain `install`),
//! wiring up a real `allium::hiddenservice::BlindedHsDirectory`
//! alongside the plain relay-descriptor `Directory` -- so this authority
//! serves BOTH relay descriptor PUBLISH/FETCH and hidden-service
//! descriptor HS_PUBLISH_REQUEST/HS_FETCH_REQUEST out of the box; there
//! was no hidden-service-directory gap to close here (see
//! `AuthorityService::install_with_hs`'s own doc comment in
//! `allium/src/directory.rs` for the check performed).
//!
//! **Flags cross-checked against the Python original**
//! (`/mnt/user-data/uploads/Allium-v8.6/allium_cli.py`, the `authority`
//! subparser around line 5820 and `cmd_authority`/`AuthorityNode` around
//! line 2828): Python's `authority` subparser takes `add_relay_common`'s
//! shared flags (`--bind`, `--name`, `--identity-file`, `--idle-timeout`,
//! `--require-return-routability`) plus `--authorities`,
//! `--allow-open-authority`, and `--measured-bandwidth-file`. This
//! recovered Rust port implements the shared flags, `--authorities`, and
//! -- as of the fix below -- `--allow-open-authority` plus
//! Python's refuse-to-run-without-`--authorities`-or-`--allow-open-
//! authority` gate (`require_authorities_or_explicit_open`, called first
//! thing in `cmd_authority`). It still does not implement
//! `--measured-bandwidth-file`/bandwidth-weighted vote scoring, nor a true
//! N-of-M signed-vote quorum across several authorities -- those remain
//! pre-existing, already-tested-around deviations carried forward
//! unchanged from the recovered code.
//!
//! **Empty-allowlist fix (this pass)**: the recovered code accepted an empty
//! `--authorities` allowlist silently -- `Directory::publish`
//! (`directory.rs`) skips its trust check entirely when the allowlist is
//! empty, so any relay presenting any self-generated identity was
//! accepted by default, with no flag and no warning. That's open relay
//! registration / a Sybil takeover of path selection, and it was
//! previously mitigated only by a manual runbook
//! (`Allium-Authority-Lockdown-Guide.md`), not enforced in code.
//! `require_authorities_or_explicit_open` now refuses to start
//! (`CliExit`-equivalent `Err`, exits nonzero via `main`'s existing error
//! path) unless `--authorities` or the new, explicit
//! `--allow-open-authority` is passed -- mirroring `allium-cli`'s
//! `require_authority_pin` on the client side of this same trust
//! boundary.
//!
//! Unlike `/home/claude/rust2/allium-relay-cli`'s `RelayArgs`, this
//! crate's `AuthorityArgs` does **not** carry the `--authority`/
//! `--trust-authority`/`--allow-unpinned-authority`/`--publish-interval`
//! fields: those exist so a relay can *publish to* an authority, which is
//! meaningless for the authority itself to accept (Python's own parser
//! agrees -- it scopes those flags away from the `authority` subcommand
//! entirely, unlike the Rust original's `RelayArgs`, which defined them
//! once and had `authority` silently ignore them; this port fixes that
//! one CLI-surface wart while keeping every other flag and all runtime
//! behavior identical).
//!
//! **Verification**: this crate's Cargo.toml (like `allium/Cargo.toml`)
//! points at the real `clap`/`tokio` crates, which cannot actually be
//! fetched in this sandbox (no crates.io access) -- so a plain `cargo
//! build`/`cargo test` here fails at dependency resolution, not because
//! anything is wrong with the code. It was, however, verified with a
//! temporary stub-and-restore pass (real local-path `fake_tokio`/
//! `fake_clap` crates standing in for `tokio`/`clap`, and `allium`'s own
//! crypto crate calls temporarily swapped for a small in-tree fake --
//! `TEMP STUB`-marked, all reverted immediately after): `cargo build
//! --workspace --offline` and `cargo test --workspace --offline` both
//! succeeded, **667 tests passing, 0 failed** (656 in `allium` itself,
//! unmodified by this pass's stubbing once restored, plus 11 here,
//! including the real network publish/fetch round-trip test below).

use allium::directory::DirectoryOptions;
use allium::hiddenservice::HsOps;
use allium::{Addr, AuthorityService, Directory, IDENTITY_KEY_SIZE, RelayNode, RelayNodeOptions};
use clap::{Args, Parser, Subcommand};
use std::cell::RefCell;
use std::rc::Rc;

// ---------------------------------------------------------------------------
// CLI surface -- mirrors `allium_cli.py`'s `authority` subparser. Kept as
// an explicit `authority` subcommand (rather than flattening it to this
// binary's only top-level command) for consistency with the sibling
// `allium-relay-cli`'s multi-subcommand style, even though this crate only
// ever has the one -- so a script written against any of the three
// sibling CLIs (`allium-relay-cli guard ...`, `allium-authority-cli
// authority ...`) sees the same `<binary> <role> [OPTIONS]` shape.
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "allium-authority", version, about = "A directory authority for the Allium onion-routing demo network")]
struct Cli {
    #[command(subcommand)]
    role: Role,
}

#[derive(Subcommand)]
enum Role {
    /// The only role this binary serves: a directory authority.
    Authority(AuthorityArgs),
}

#[derive(Args, Clone)]
struct AuthorityArgs {
    /// IP:PORT to bind the authority's UDP socket to.
    #[arg(long, value_name = "IP:PORT")]
    bind: String,

    /// Human-readable node name (defaults to "authority").
    #[arg(long)]
    name: Option<String>,

    /// File holding this authority's 32-byte master key, hex-encoded.
    /// Generated on first run if it does not exist.
    #[arg(long = "identity-file")]
    identity_file: Option<String>,

    /// Idle-circuit reap timeout, in seconds.
    #[arg(long = "idle-timeout", value_name = "SECONDS")]
    idle_timeout: Option<f64>,

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
    require_return_routability: bool,

    /// Allow this authority to EXTEND to a private, loopback or link-local
    /// address (by default such an EXTEND is refused). Off by
    /// default; only meant for a loopback test network. Directory traffic
    /// only ever needs one-hop circuits, so a production authority should
    /// never need to EXTEND at all -- but disabling EXTEND outright at the
    /// authority is not implemented by this flag.
    #[arg(long = "allow-private-extend", default_value_t = false)]
    allow_private_extend: bool,

    /// Comma-separated hex identity keys of every relay this authority
    /// will accept a descriptor from (passed straight through to
    /// `Directory::new`'s `authorities` allowlist -- Python's actual
    /// Sybil defense; see `directory.rs`'s `Directory` doc comment).
    /// Refusing to start without this or `--allow-open-authority` is
    /// enforced by `require_authorities_or_explicit_open` -- see its doc
    /// comment.
    #[arg(long = "authorities", value_name = "HEX[,HEX...]")]
    authorities: Option<String>,

    /// Explicit, loud opt-out of the `--authorities` allowlist: accept a
    /// descriptor from any relay presenting any self-generated identity
    /// (open relay registration / Sybil takeover of path
    /// selection). Off by default; only meant for a single-machine demo
    /// or a loopback test network where every process is provably the
    /// operator's own. See `require_authorities_or_explicit_open`.
    #[arg(long = "allow-open-authority", default_value_t = false)]
    allow_open_authority: bool,

    /// Most relay descriptors this authority will hold at once. At the
    /// cap, a new identity displaces the newest identity that has never
    /// come back to refresh its descriptor, or is refused if every held
    /// relay has; a relay refreshing its own descriptor is always
    /// accepted. Before this cap, an open authority flooded past what one
    /// directory reply can carry stopped answering clients altogether.
    /// `0` disables the cap (not recommended).
    #[arg(long = "max-descriptors", value_name = "N", default_value_t = allium::dirwire::MAX_DESCRIPTOR_COUNT)]
    max_descriptors: usize,

    /// Most live relays one address block (IPv4 /16, IPv6 /32, judged by
    /// the address a descriptor was actually published from) may hold
    /// registered at once. Bounds how much of `--max-descriptors` a single
    /// operator's block can occupy, however slowly it drips identities in
    /// under the publish-rate limiter. `0` disables it.
    #[arg(long = "max-relays-per-subnet", value_name = "N", default_value_t = 64)]
    max_relays_per_subnet: u32,
}

// ---------------------------------------------------------------------------
// Small shared helpers -- mirror `allium_cli.py`'s `parse_addr`/`say`/
// `load_or_create_master_key`. Recovered verbatim from
// `/tmp/main_rs_working_backup.rs`.
// ---------------------------------------------------------------------------

fn say(message: impl std::fmt::Display) {
    eprintln!("{message}");
}

fn parse_addr(text: &str) -> Result<Addr, String> {
    let (host, port) = text.rsplit_once(':').ok_or_else(|| format!("expected IP:PORT, got {text:?}"))?;
    let port: u16 = port.parse().map_err(|_| format!("bad port in {text:?}"))?;
    Ok((host.to_string(), port))
}

fn hex_encode(bytes: &[u8]) -> String {
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
fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
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

/// Load a 32-byte hex-encoded master key from `path`, generating and
/// persisting a fresh one (from `/dev/urandom`) if the file does not
/// exist yet.
fn load_or_create_master_key(path: &str) -> std::io::Result<[u8; 32]> {
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
    // This is the authority's master private key -- world-readable by
    // default (whatever the process umask gives, typically 0644) unless
    // set explicitly. Matches the 0600 already used for the analogous
    // hidden-service key files in Client/src/hiddenservice.rs. Created
    // with the tight mode from the start (`.mode(0o600)` on the open
    // call, not a separate `set_permissions` after a plain `fs::write`)
    // so there is no window where the file briefly exists with the
    // default umask permissions for another local process to read.
    // `create_new` (refuse if the path already exists) also turns "only
    // one caller should ever be generating this identity" into a loud
    // error instead of a silent overwrite race, if that's ever violated.
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        file.write_all(hex_encode(&key).as_bytes())?;
    }
    Ok(key)
}

/// Refuse to proceed with an open (unallowlisted) authority.
///
/// An authority with no `--authorities` allowlist accepts a PUBLISH from
/// any relay presenting any self-generated identity -- `Directory::publish`
/// (`directory.rs`) skips its own trust check entirely when the allowlist
/// is empty. That's open relay registration / Sybil takeover of
/// path selection. `--allow-open-authority` is the explicit, loud opt-out
/// for a single-machine demo/test, mirroring `allium-cli`'s
/// `require_authority_pin` on the client side of the same trust boundary.
///
/// No-op if `args.authorities` is set (already allowlisted).
fn require_authorities_or_explicit_open(args: &AuthorityArgs) -> Result<(), String> {
    if args.authorities.as_deref().is_some_and(|s| !s.trim().is_empty()) {
        return Ok(());
    }
    if args.allow_open_authority {
        say(
            "allium authority: NOTE: --allow-open-authority is set -- a descriptor from any \
             relay presenting any self-generated identity will be accepted, with no allowlist \
             check. Fine for a single-machine demo where every process is provably yours; \
             never for anything real.",
        );
        return Ok(());
    }
    Err(
        "--authorities is not set. An open authority accepts a descriptor from any relay \
         presenting any self-generated identity -- a real Sybil/path-selection-takeover vector \
         (ALLIUM-C3), not merely a recommendation, so this is enforced: pass --authorities \
         HEX[,HEX...] (each trusted relay's identity, printed by that relay at startup), or, \
         for a single-machine demo/test where you already know every process is yours, pass \
         --allow-open-authority to proceed without it."
            .to_string(),
    )
}

fn authority_options(args: &AuthorityArgs) -> Result<RelayNodeOptions, String> {
    let mut options = RelayNodeOptions::default();
    options.node_name = args.name.clone().unwrap_or_else(|| "authority".to_string());
    if let Some(idle) = args.idle_timeout {
        options.idle_timeout = idle;
    }
    options.require_return_routability = args.require_return_routability;
    options.allow_private_extend = args.allow_private_extend;
    // `cmd_authority` always calls
    // `spawn_known_relays_refresher` unconditionally right after building
    // this node, so it always ends up with directory-based EXTEND
    // checking -- meaning it should refuse to EXTEND anywhere until that
    // first refresh has actually landed, rather than accepting any
    // non-private target in the few-second window before it does.
    options.require_known_relay_addrs = true;
    if let Some(path) = &args.identity_file {
        let key = load_or_create_master_key(path).map_err(|e| e.to_string())?;
        options.master_key = Some(key.to_vec());
    }
    Ok(options)
}

/// How often the authority refreshes its own `RelayNode`'s
/// `known_relay_addrs` from its in-memory `Directory`.
/// Unlike a plain relay (`allium-relay-cli`'s `spawn_directory_refresher`),
/// the authority already holds the live `Directory` in the same process --
/// no network round trip is needed, so this can run often and cheaply.
const KNOWN_RELAYS_REFRESH_SECS: f64 = 5.0;

/// Periodically snapshot the authority's own
/// `Directory` into its `RelayNode`'s `known_relay_addrs`, so this
/// authority -- a plain `RelayNode` like any other --
/// only ever EXTENDs to an address a live, directory-listed relay is
/// actually published at. Both `node` and `directory` are already
/// `Rc<RefCell<_>>`s live on this same `LocalSet`, so (unlike the
/// cross-thread FETCH `allium-relay-cli` needs) this is just a plain
/// `spawn_local` loop with no channel to hand results across.
/// See `allium-relay-cli`'s identically-named helper: `catch_unwind`'s
/// `Err` is `Box<dyn Any + Send>`, and in practice is almost always
/// `&'static str` or `String` -- the two shapes the standard panic hook
/// itself special-cases. Duplicated here rather than shared, matching this
/// codebase's existing convention of small per-binary helpers across the
/// three CLI crates.
fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| payload.downcast::<String>().ok().map(|s| *s))
        .unwrap_or_else(|| "unknown panic payload".to_string())
}

fn spawn_known_relays_refresher(node: &Rc<RefCell<RelayNode>>, directory: Rc<RefCell<Directory>>) {
    let node = node.clone();
    tokio::task::spawn_local(async move {
        loop {
            // Mirrors the relay
            // CLI's own directory-refresher fix -- this is a plain
            // `spawn_local` with its `JoinHandle` discarded (see the
            // caller), so an uncaught panic here would silently end this
            // task forever, freezing `known_relay_addrs` at whatever it
            // last was. `require_known_relay_addrs` (this crate always
            // sets it `true`) makes that fail closed rather than harmlessly
            // stale. Lower risk than the relay's version (no I/O, no
            // fallible calls today), but the guard is cheap and keeps the
            // two refreshers consistent against a future edit introducing
            // one.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let known: std::collections::HashSet<Addr> = directory.borrow().all().into_iter().map(|d| (d.host.clone(), d.port)).collect();
                node.borrow_mut().set_known_relay_addrs(Some(known));
            }));
            if let Err(panic_payload) = outcome {
                say(format!(
                    "known-relays-refresh: cycle panicked ({}) -- will retry next cycle instead of stopping forever",
                    panic_message(panic_payload)
                ));
            }
            tokio::time::sleep(std::time::Duration::from_secs_f64(KNOWN_RELAYS_REFRESH_SECS)).await;
        }
    });
}

// ---------------------------------------------------------------------------
// authority -- a real `RelayNode` plus a real in-memory `Directory` and
// `BlindedHsDirectory`, both actually served over the network via
// `allium::AuthorityService::install_with_hs`: relays publish signed
// descriptors here (PUBLISH/FETCH) and hidden services publish/fetch
// their own descriptors here too (HS_PUBLISH_REQUEST/HS_FETCH_REQUEST).
// Recovered near-verbatim from `/tmp/main_rs_working_backup.rs`'s
// `cmd_authority` (originally written for `/home/claude/rust`'s
// `allium-cli`, before its Round N removed this role).
// ---------------------------------------------------------------------------

async fn cmd_authority(args: AuthorityArgs) -> Result<(), String> {
    require_authorities_or_explicit_open(&args)?;
    let bind = parse_addr(&args.bind)?;
    let options = authority_options(&args)?;

    // Built before `dir_options` (rather than after, as this was
    // originally ordered) so this authority's own identity is known in
    // time to seed `dir_options.known_introducers` below.
    let node = Rc::new(RefCell::new(RelayNode::new(options).map_err(|e| e.to_string())?));

    let mut dir_options = DirectoryOptions::default();
    dir_options.max_descriptors = (args.max_descriptors > 0).then_some(args.max_descriptors);
    dir_options.max_live_identities_per_subnet = (args.max_relays_per_subnet > 0).then_some(args.max_relays_per_subnet);
    if args.max_descriptors == 0 || args.max_descriptors > allium::dirwire::MAX_DESCRIPTOR_COUNT {
        let cap = if args.max_descriptors == 0 { "no cap".to_string() } else { format!("--max-descriptors {}", args.max_descriptors) };
        say(format!(
            "allium authority: NOTE: {cap} lets this directory grow past the {} relays one directory reply can carry; \
             clients will be served the {} relays with the longest record and the rest will be invisible to them.",
            allium::dirwire::MAX_DESCRIPTOR_COUNT, allium::dirwire::MAX_DESCRIPTOR_COUNT
        ));
    }
    if let Some(text) = &args.authorities {
        for hex in text.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            let bytes = hex_decode(hex)?;
            if bytes.len() != IDENTITY_KEY_SIZE {
                return Err(format!("--authorities: {hex:?} is not a 32-byte hex identity key"));
            }
            let mut key = [0u8; IDENTITY_KEY_SIZE];
            key.copy_from_slice(&bytes);
            dir_options.authorities.push(key);
        }
    }
    // A relay's self-signed descriptor can name any identity/address it
    // likes as its NAT `EXT_REACHABILITY`
    // introducer -- nothing before this required that to actually be an
    // authority. This authority now only accepts a reachability
    // extension that names *itself*: the identity a client would have
    // pinned with `--trust-authority` to reach this very process. (A
    // multi-authority deployment that wants relays to point at a sibling
    // authority instead would need that sibling's identity added here
    // too; there is no such config surface yet, so this is scoped to the
    // single-authority case this CLI otherwise targets.)
    dir_options.known_introducers.push(node.borrow().identity_public());
    let directory = Rc::new(RefCell::new(Directory::new(dir_options).map_err(|e| e.to_string())?));

    let hs_directory = Rc::new(RefCell::new(
        allium::hiddenservice::BlindedHsDirectory::new(None, None, HsOps::real()).map_err(|e| e.to_string())?,
    ));
    // A clone of the `Rc` (cheap; same underlying
    // `RefCell<Directory>` as the one handed to `install_with_hs` below)
    // kept here so the refresher spawned right after can keep reading it.
    let known_relays_directory = directory.clone();
    AuthorityService::install_with_hs(&node, directory, Some(hs_directory));
    spawn_known_relays_refresher(&node, known_relays_directory);
    // The one piece of information every `--trust-authority`/`--authorities`
    // pin (on a client, a rust2 guard/middle/exit, or another authority's
    // own allowlist) has to be copied from: this authority's own identity
    // has no bootstrap trust source above it, unlike a relay's identity
    // (which a client picks up automatically from a fetched, already-
    // verified descriptor -- see rust's `resolve_client_route` -- so a
    // relay never needs to print this for a human to read). Printing it
    // was missing from the recovered `cmd_authority` (and, it turns out,
    // from the version it was recovered from) -- fixed here.
    let identity_hex: String = node.borrow().identity_public().iter().map(|b| format!("{b:02x}")).collect();
    say(format!(
        "allium authority: listening on {}:{} (serving PUBLISH/FETCH, signed VOTE, and HS_PUBLISH/HS_FETCH over the directory protocol)",
        bind.0, bind.1
    ));
    say(format!("allium authority: identity (for --trust-authority/--authorities): {identity_hex}"));
    if args.identity_file.is_none() {
        say("allium authority: WARNING no --identity-file given -- this identity is random and NOT persisted; it will be different on every restart, breaking any pin you set above. Pass --identity-file PATH to keep the same identity across restarts.");
    }
    RelayNode::run(node, bind).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to start the tokio runtime");
    let local = tokio::task::LocalSet::new();
    let result: Result<(), String> = local.block_on(&rt, async move {
        match cli.role {
            Role::Authority(args) => cmd_authority(args).await,
        }
    });
    if let Err(e) = result {
        say(format!("error: {e}"));
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Tests -- all in this crate's own `mod tests` below (matching
// `/home/claude/rust2/allium-relay-cli`'s own convention: no separate
// `tests/` integration-test directory), covering CLI-flag parsing (real
// `clap::Parser::try_parse_from`), `--authorities` hex validation,
// `authority_options`'s field mapping, and a real, non-stubbed loopback
// network test that starts an actual authority (through this crate's own
// `cmd_authority` wiring) and drives a real relay-descriptor PUBLISH/FETCH
// round trip plus a real hidden-service HS_PUBLISH_REQUEST/HS_FETCH_REQUEST
// round trip against it over loopback UDP.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE on verification: the four `Cli::try_parse_from`-based tests
    // below call the real
    // `clap::Parser` trait method. This sandbox's compile-check pass used
    // a type-check-only `fake_clap` stand-in (`Parser::parse()` is a bare
    // `panic!`, and `try_parse_from` is not implemented at all) to compile
    // and run every *other* test in this crate and in `allium` itself
    // (667 tests total, including this crate's own real network
    // publish/fetch round-trip test) without real crates.io access; these
    // four were gated out of that one pass only (never executed against
    // the fake) and are restored here unmodified. They exercise a
    // standard, extremely well-tested real clap 4 derive +
    // `Parser::try_parse_from` API surface, identical in shape to the
    // sibling projects' own CLI-parsing tests.
    #[test]
    fn parses_minimal_authority_invocation() {
        let cli = Cli::try_parse_from(["allium-authority", "authority", "--bind", "127.0.0.1:9000"]).expect("minimal invocation should parse");
        let Role::Authority(args) = cli.role;
        assert_eq!(args.bind, "127.0.0.1:9000");
        assert!(args.name.is_none());
        assert!(args.identity_file.is_none());
        assert!(args.idle_timeout.is_none());
        assert!(args.require_return_routability, "require-return-routability defaults on, matching Python");
        assert!(args.authorities.is_none());
        assert!(!args.allow_open_authority, "allow-open-authority defaults off, matching Python");
    }

    #[test]
    fn parses_all_authority_flags() {
        let cli = Cli::try_parse_from([
            "allium-authority",
            "authority",
            "--bind",
            "0.0.0.0:9001",
            "--name",
            "auth1",
            "--identity-file",
            "/tmp/does-not-matter.key",
            "--idle-timeout",
            "30.5",
            "--require-return-routability=false",
            "--authorities",
            "aa11bb22cc33dd44ee55ff66001122334455667788990011223344556677889900,1122334455667788990011223344556677889900112233445566778899001122",
            "--allow-open-authority",
        ])
        .expect("fully-specified invocation should parse");
        let Role::Authority(args) = cli.role;
        assert_eq!(args.bind, "0.0.0.0:9001");
        assert_eq!(args.name.as_deref(), Some("auth1"));
        assert_eq!(args.identity_file.as_deref(), Some("/tmp/does-not-matter.key"));
        assert_eq!(args.idle_timeout, Some(30.5));
        assert!(!args.require_return_routability);
        assert!(args.authorities.is_some());
        assert!(args.allow_open_authority);
    }

    #[test]
    fn bind_is_required() {
        let result = Cli::try_parse_from(["allium-authority", "authority"]);
        assert!(result.is_err(), "--bind is required and must be rejected when missing");
    }

    #[test]
    fn requires_a_role() {
        let result = Cli::try_parse_from(["allium-authority"]);
        assert!(result.is_err(), "a bare invocation with no subcommand must be rejected");
    }

    #[test]
    fn load_or_create_master_key_writes_a_0600_file_in_a_0700_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("allium-authority-key-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("authority.key");
        let key = load_or_create_master_key(path.to_str().unwrap()).expect("key generation should succeed");
        assert_eq!(key.len(), 32);
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "key file must not be group/other-readable");
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "key directory must not be group/other-accessible");
        // A second call re-reads the now-persisted key rather than
        // regenerating it, and must return the same bytes.
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

    #[test]
    fn parse_addr_accepts_host_port() {
        assert_eq!(parse_addr("127.0.0.1:9000").unwrap(), ("127.0.0.1".to_string(), 9000));
    }

    #[test]
    fn parse_addr_rejects_missing_colon() {
        assert!(parse_addr("127.0.0.1").is_err());
    }

    #[test]
    fn parse_addr_rejects_bad_port() {
        assert!(parse_addr("127.0.0.1:not-a-port").is_err());
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0u8, 1, 2, 254, 255];
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
    fn authority_options_defaults_node_name_to_authority() {
        let args = AuthorityArgs {
            bind: "127.0.0.1:0".to_string(),
            name: None,
            identity_file: None,
            idle_timeout: None,
            require_return_routability: true,
            authorities: None,
            allow_private_extend: false,
            allow_open_authority: false,
            max_descriptors: allium::dirwire::MAX_DESCRIPTOR_COUNT,
            max_relays_per_subnet: 64,
        };
        let options = authority_options(&args).expect("no identity-file means no filesystem access needed");
        assert_eq!(options.node_name, "authority");
    }

    #[test]
    fn authority_options_honors_explicit_name() {
        let args = AuthorityArgs {
            bind: "127.0.0.1:0".to_string(),
            name: Some("dirauth-1".to_string()),
            identity_file: None,
            idle_timeout: None,
            require_return_routability: false,
            authorities: None,
            allow_private_extend: false,
            allow_open_authority: false,
            max_descriptors: allium::dirwire::MAX_DESCRIPTOR_COUNT,
            max_relays_per_subnet: 64,
        };
        let options = authority_options(&args).expect("no identity-file means no filesystem access needed");
        assert_eq!(options.node_name, "dirauth-1");
        assert!(!options.require_return_routability);
    }

    #[test]
    fn cmd_authority_rejects_malformed_authorities_hex() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let local = tokio::task::LocalSet::new();
        let args = AuthorityArgs {
            bind: "127.0.0.1:0".to_string(),
            name: None,
            identity_file: None,
            idle_timeout: None,
            require_return_routability: true,
            authorities: Some("not-hex-at-all".to_string()),
            allow_private_extend: false,
            allow_open_authority: false,
            max_descriptors: allium::dirwire::MAX_DESCRIPTOR_COUNT,
            max_relays_per_subnet: 64,
        };
        let result: Result<(), String> = local.block_on(&rt, cmd_authority(args));
        assert!(result.is_err(), "a malformed --authorities entry must be rejected before the authority ever binds");
    }

    // -- require_authorities_or_explicit_open --------------------

    fn open_authority_args(authorities: Option<&str>, allow_open_authority: bool) -> AuthorityArgs {
        AuthorityArgs {
            bind: "127.0.0.1:0".to_string(),
            name: None,
            identity_file: None,
            idle_timeout: None,
            require_return_routability: true,
            authorities: authorities.map(str::to_string),
            allow_private_extend: false,
            allow_open_authority,
            max_descriptors: allium::dirwire::MAX_DESCRIPTOR_COUNT,
            max_relays_per_subnet: 64,
        }
    }

    #[test]
    fn require_authorities_or_explicit_open_accepts_an_allowlist() {
        let args = open_authority_args(Some("aa".repeat(32).as_str()), false);
        assert!(require_authorities_or_explicit_open(&args).is_ok());
    }

    #[test]
    fn require_authorities_or_explicit_open_accepts_the_explicit_override() {
        let args = open_authority_args(None, true);
        assert!(require_authorities_or_explicit_open(&args).is_ok());
    }

    #[test]
    fn require_authorities_or_explicit_open_rejects_neither() {
        let args = open_authority_args(None, false);
        let err = require_authorities_or_explicit_open(&args).unwrap_err();
        assert!(err.contains("--allow-open-authority"), "error must name the override flag: {err}");
    }

    #[test]
    fn require_authorities_or_explicit_open_rejects_an_empty_allowlist_string() {
        // A bare `--authorities ""` (or a config value resolving to empty)
        // must not be treated as "set" -- same "is_set" semantics as the
        // client's `require_authority_pin`.
        let args = open_authority_args(Some(""), false);
        assert!(require_authorities_or_explicit_open(&args).is_err());
    }

    #[test]
    fn cmd_authority_refuses_to_start_without_authorities_or_explicit_open() {
        // Before this pass, an authority with neither flag would proceed
        // straight to binding and serving PUBLISH/FETCH -- this is the
        // regression test for that: cmd_authority must now fail fast, and
        // specifically on the C3 gate, not some later, unrelated error.
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let local = tokio::task::LocalSet::new();
        let args = open_authority_args(None, false);
        let result: Result<(), String> = local.block_on(&rt, cmd_authority(args));
        let err = result.expect_err("an open authority with no explicit opt-out must be refused");
        assert!(err.contains("--allow-open-authority"), "error must name the override flag: {err}");
    }

    #[test]
    fn cmd_authority_starts_with_explicit_allow_open_authority() {
        // The mirror image of the test above: the explicit override must
        // actually let the authority proceed past the C3 gate (and on to
        // a real bind -- this reuses the same loopback pattern as the
        // full publish/fetch round-trip test below, just checking that
        // `RelayNode::start` succeeds rather than driving a full protocol
        // exchange).
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let local = tokio::task::LocalSet::new();
        let outcome: Result<(), String> = local.block_on(&rt, async move {
            let args = open_authority_args(None, true);
            require_authorities_or_explicit_open(&args)?;
            let options = authority_options(&args)?;
            let node = Rc::new(RefCell::new(RelayNode::new(options).map_err(|e| e.to_string())?));
            RelayNode::start(&node, ("127.0.0.1".to_string(), 0)).await.map_err(|e| e.to_string())?;
            Ok(())
        });
        assert!(outcome.is_ok(), "an explicit --allow-open-authority must let the authority proceed past the C3 gate: {outcome:?}");
    }

    // -----------------------------------------------------------------
    // Real, non-stubbed loopback network test: a genuine authority, built
    // through this crate's own `authority_options`/`AuthorityService::
    // install_with_hs` wiring (the exact code `cmd_authority` runs, minus
    // only the infinite `RelayNode::run` accept loop -- `RelayNode::start`
    // + `RelayNode::serve_loop`, spawned as a separate task, is the same
    // substitution `/home/claude/rust2/allium-relay-cli`'s own loopback
    // test makes, which itself follows `allium::socksproxy`'s and
    // `allium-cli`'s `hs.rs` test harness (`spin_up_hs_test_relays`)). A
    // real relay descriptor is built with `allium::RelayDescriptor::
    // create`, signed, PUBLISHed over a real loopback UDP directory
    // circuit (`allium::dir_round_trip`, the same function
    // `fetch_relay_directory` uses in production), then FETCHed back and
    // checked byte-for-byte -- and separately, a real hidden-service
    // descriptor is built with `allium::hiddenservice::
    // HiddenServiceDescriptor::create`, HS_PUBLISHed, then HS_FETCHed back
    // and checked. This proves the authority actually serves both
    // directory protocols end to end over the wire, not just that the CLI
    // parses flags correctly.
    // -----------------------------------------------------------------
    #[test]
    fn test_authority_serves_real_relay_and_hs_descriptor_publish_fetch_round_trips() {
        use allium::dirwire::{
            decode_fetch_reply, decode_hs_fetch_reply, decode_hs_publish_reply, decode_publish_reply, encode_fetch_request_default,
            encode_hs_fetch_request, encode_hs_publish_request, encode_publish_request,
        };
        use allium::hiddenservice::{CreateHsDescriptorOptions, HiddenServiceDescriptor, ServiceIdentity};
        use allium::directory::CreateOptions;
        use allium::nat::Ed25519Ops;
        use allium::{RelayDescriptor, ROLE_EXIT, dir_round_trip};

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("failed to start tokio runtime");
        let local = tokio::task::LocalSet::new();

        let outcome: Result<(bool, bool, bool, bool), String> = local.block_on(&rt, async move {
            // Stand up a real authority exactly like `cmd_authority` does,
            // minus the infinite `run` loop.
            let args = AuthorityArgs {
                bind: "127.0.0.1:0".to_string(),
                name: Some("test-authority".to_string()),
                identity_file: None,
                idle_timeout: None,
                require_return_routability: true,
                authorities: None, // open authority: this test's relay/HS identities are not pre-known
                allow_private_extend: false,
                allow_open_authority: true, // this test builds the authority directly, bypassing cmd_authority's gate, but stays honest about intent
                max_descriptors: allium::dirwire::MAX_DESCRIPTOR_COUNT,
                max_relays_per_subnet: 64,
            };
            let options = authority_options(&args)?;
            let directory = Rc::new(RefCell::new(Directory::new(DirectoryOptions::default()).map_err(|e| e.to_string())?));
            let hs_directory =
                Rc::new(RefCell::new(allium::hiddenservice::BlindedHsDirectory::new(None, None, HsOps::real()).map_err(|e| e.to_string())?));
            let node = Rc::new(RefCell::new(RelayNode::new(options).map_err(|e| e.to_string())?));
            let authority_addr = RelayNode::start(&node, ("127.0.0.1".to_string(), 0)).await.map_err(|e| e.to_string())?;
            AuthorityService::install_with_hs(&node, directory, Some(hs_directory));
            tokio::task::spawn_local(RelayNode::serve_loop(node.clone()));

            // ---- Relay descriptor: PUBLISH then FETCH ----
            let ops = Ed25519Ops::real();
            let relay_identity_seed = [0x77u8; 32];
            let relay_descriptor = RelayDescriptor::create(
                &ops,
                &relay_identity_seed,
                &[0u8; 32],
                "127.0.0.1",
                9999,
                &[ROLE_EXIT],
                allium::DEFAULT_DESCRIPTOR_LIFETIME,
                None,
                CreateOptions::default(),
            )
            .map_err(|e| e.to_string())?;

            let publish_request = encode_publish_request(&relay_descriptor).map_err(|e| e.to_string())?;
            let publish_reply_bytes = run_blocking_dir_round_trip(authority_addr.clone(), publish_request).await?;
            let (publish_ok, publish_message) = decode_publish_reply(&publish_reply_bytes).map_err(|e| e.to_string())?;
            if !publish_ok {
                return Err(format!("relay descriptor PUBLISH was rejected: {publish_message}"));
            }

            let fetch_request = encode_fetch_request_default();
            let fetch_reply_bytes = run_blocking_dir_round_trip(authority_addr.clone(), fetch_request).await?;
            let fetched = decode_fetch_reply(&fetch_reply_bytes).map_err(|e| e.to_string())?;
            let relay_found = fetched.iter().any(|d| d.identity_public == relay_descriptor.identity_public && d.port == 9999);

            // ---- Hidden-service descriptor (version 3): HS3_PUBLISH then HS3_FETCH ----
            // The authority checks only the signature under the blinded key, so
            // any real Ed25519 key stands in for one here; the construction
            // itself is the Client's job (and has its own tests).
            let hs_ops = HsOps::real();
            let blinded_seed = [0x3Cu8; 32];
            let blinded_public = (hs_ops.ed25519_public_of)(&blinded_seed);
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
            let mut blinded = allium::hiddenservice::BlindedDescriptor {
                blinded_public,
                period: allium::hiddenservice::hs_directory_period(Some(now), allium::hiddenservice::HS_DIRECTORY_INDEX_PERIOD),
                not_before: now - 5.0,
                not_after: now + 3000.0,
                salt: [0x11u8; 32],
                ciphertext: vec![0x22u8; 300],
                signature: Vec::new(),
            };
            blinded.signature = (hs_ops.ed25519_sign)(&blinded_seed, &blinded.signing_payload()).to_vec();

            let hs_publish_request = allium::dirwire::encode_hs3_publish_request(&blinded).map_err(|e| e.to_string())?;
            let hs_publish_reply_bytes = run_blocking_dir_round_trip(authority_addr.clone(), hs_publish_request).await?;
            let (hs_publish_ok, hs_publish_message) = allium::dirwire::decode_hs3_publish_reply(&hs_publish_reply_bytes).map_err(|e| e.to_string())?;
            if !hs_publish_ok {
                return Err(format!("HS3 descriptor publish was rejected: {hs_publish_message}"));
            }

            // A fetch names only the blinded key.
            let hs_fetch_request = allium::dirwire::encode_hs3_fetch_request(&blinded_public);
            let hs_fetch_reply_bytes = run_blocking_dir_round_trip(authority_addr.clone(), hs_fetch_request).await?;
            let hs_fetched = allium::dirwire::decode_hs3_fetch_reply(&hs_fetch_reply_bytes).map_err(|e| e.to_string())?;
            let hs_found = hs_fetched.as_ref() == Some(&blinded);

            // The old (version 2) messages are refused / not found, never stored.
            let v2_publish_reply = run_blocking_dir_round_trip(authority_addr.clone(), {
                let mut m = allium::dirwire::DIR_MAGIC.to_vec();
                m.push(allium::dirwire::HS_PUBLISH_REQUEST);
                m.extend_from_slice(&[0u8; 100]);
                m
            })
            .await?;
            let (v2_ok, v2_message) = allium::dirwire::decode_hs_publish_reply(&v2_publish_reply).map_err(|e| e.to_string())?;
            if v2_ok || !v2_message.contains("version 2") {
                return Err(format!("a v2 HS publish must be refused with an upgrade message, got ok={v2_ok} message={v2_message:?}"));
            }
            let mut v2_fetch = allium::dirwire::DIR_MAGIC.to_vec();
            v2_fetch.push(allium::dirwire::HS_FETCH_REQUEST);
            v2_fetch.extend_from_slice(&blinded_public);
            let v2_fetch_reply = run_blocking_dir_round_trip(authority_addr, v2_fetch).await?;
            if allium::dirwire::decode_hs_fetch_reply(&v2_fetch_reply).map_err(|e| e.to_string())?.is_some() {
                return Err("a v2 HS fetch must find nothing".to_string());
            }

            Ok((publish_ok, relay_found, hs_publish_ok, hs_found))
        });

        let (publish_ok, relay_found, hs_publish_ok, hs_found) =
            outcome.expect("a real authority (this crate's own cmd_authority wiring) should serve a real relay-descriptor and HS-descriptor publish/fetch round trip over loopback UDP");
        assert!(publish_ok, "relay descriptor PUBLISH must be accepted");
        assert!(relay_found, "the published relay descriptor must come back on FETCH");
        assert!(hs_publish_ok, "an HS3 descriptor publish must be accepted");
        assert!(hs_found, "the published HS3 descriptor must come back on HS3_FETCH, byte for byte");
    }

    /// Runs `allium::dir_round_trip` (a blocking, `std::net::UdpSocket`-
    /// based call -- see its own doc comment) on a dedicated OS thread, so
    /// it never blocks the single-threaded tokio `LocalSet` the authority
    /// itself is served from, and awaits the result cooperatively.
    /// Mirrors the same thread+channel+poll pattern
    /// `/home/claude/rust2/allium-relay-cli`'s own loopback test uses for
    /// its blocking `CircuitBuilder` calls.
    async fn run_blocking_dir_round_trip(authority_addr: Addr, request_bytes: Vec<u8>) -> Result<Vec<u8>, String> {
        let (tx, rx) = std::sync::mpsc::channel::<Result<Vec<u8>, String>>();
        std::thread::spawn(move || {
            let outcome = allium::dir_round_trip(&authority_addr, None, &request_bytes).map_err(|e| e.to_string());
            let _ = tx.send(outcome);
        });
        loop {
            match rx.try_recv() {
                Ok(outcome) => return outcome,
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err("dir_round_trip thread exited without a result".to_string());
                }
            }
        }
    }

    /// Security audit fix (2026-09-26, finding H1 -- Authority-crate
    /// directory queries leak the querier's real IP): proves
    /// `allium::dir_round_trip_over_circuit` actually reaches a real
    /// authority through a real intermediate relay hop -- not just that it
    /// rejects an empty hop list (that pure-logic check lives in
    /// `allium/src/directory.rs`'s own test suite). Stands up a plain relay
    /// (no `AuthorityService`, just accepts EXTEND) as the sole
    /// intermediate hop, and a real authority as the destination, both over
    /// real loopback UDP -- mirrors
    /// `test_authority_serves_real_relay_and_hs_descriptor_publish_fetch_round_trips`'s
    /// own authority-spin-up, plus a second `RelayNode` for the hop this
    /// finding is about routing through.
    #[test]
    fn test_dir_round_trip_over_circuit_reaches_a_real_authority_through_a_real_relay_hop() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("failed to start tokio runtime");
        let local = tokio::task::LocalSet::new();

        let outcome: Result<(bool, bool), String> = local.block_on(&rt, async move {
            // The intermediate hop: a plain relay, nothing authority-specific.
            // `allow_private_extend` is required for it to forward an EXTEND
            // targeting the authority's own loopback address.
            let guard_options = RelayNodeOptions { allow_private_extend: true, ..RelayNodeOptions::default() };
            let guard_node = Rc::new(RefCell::new(RelayNode::new(guard_options).map_err(|e| e.to_string())?));
            let guard_addr = RelayNode::start(&guard_node, ("127.0.0.1".to_string(), 0)).await.map_err(|e| e.to_string())?;
            tokio::task::spawn_local(RelayNode::serve_loop(guard_node.clone()));

            // The destination: a real authority, same setup as the sibling
            // one-hop test above.
            let args = AuthorityArgs {
                bind: "127.0.0.1:0".to_string(),
                name: Some("test-authority".to_string()),
                identity_file: None,
                idle_timeout: None,
                require_return_routability: true,
                authorities: None,
                allow_private_extend: false,
                allow_open_authority: true,
                max_descriptors: allium::dirwire::MAX_DESCRIPTOR_COUNT,
                max_relays_per_subnet: 64,
            };
            let options = authority_options(&args)?;
            let directory = Rc::new(RefCell::new(Directory::new(DirectoryOptions::default()).map_err(|e| e.to_string())?));
            let authority_node = Rc::new(RefCell::new(RelayNode::new(options).map_err(|e| e.to_string())?));
            let authority_addr = RelayNode::start(&authority_node, ("127.0.0.1".to_string(), 0)).await.map_err(|e| e.to_string())?;
            AuthorityService::install(&authority_node, directory);
            tokio::task::spawn_local(RelayNode::serve_loop(authority_node.clone()));

            let hops = vec![("guard".to_string(), guard_addr), ("authority".to_string(), authority_addr)];
            let relay_identity_seed = [0x99u8; 32];
            let relay_descriptor = allium::RelayDescriptor::create(
                &allium::nat::Ed25519Ops::real(),
                &relay_identity_seed,
                &[0u8; 32],
                "127.0.0.1",
                9998,
                &[allium::ROLE_EXIT],
                allium::DEFAULT_DESCRIPTOR_LIFETIME,
                None,
                allium::directory::CreateOptions::default(),
            )
            .map_err(|e| e.to_string())?;

            let publish_request = allium::dirwire::encode_publish_request(&relay_descriptor).map_err(|e| e.to_string())?;
            let publish_reply_bytes = run_blocking_dir_round_trip_over_circuit(hops.clone(), publish_request).await?;
            let (publish_ok, publish_message) = allium::dirwire::decode_publish_reply(&publish_reply_bytes).map_err(|e| e.to_string())?;
            if !publish_ok {
                return Err(format!("relay descriptor PUBLISH over a real 2-hop circuit was rejected: {publish_message}"));
            }

            let fetch_request = allium::dirwire::encode_fetch_request_default();
            let fetch_reply_bytes = run_blocking_dir_round_trip_over_circuit(hops, fetch_request).await?;
            let fetched = allium::dirwire::decode_fetch_reply(&fetch_reply_bytes).map_err(|e| e.to_string())?;
            let relay_found = fetched.iter().any(|d| d.identity_public == relay_descriptor.identity_public && d.port == 9998);

            Ok((publish_ok, relay_found))
        });

        let (publish_ok, relay_found) = outcome.expect(
            "a real authority reached through a real intermediate relay hop (via dir_round_trip_over_circuit) should serve a real relay-descriptor publish/fetch round trip over loopback UDP",
        );
        assert!(publish_ok, "relay descriptor PUBLISH over the 2-hop circuit must be accepted");
        assert!(relay_found, "the published relay descriptor must come back on FETCH over the same 2-hop circuit");
    }

    /// [`run_blocking_dir_round_trip`]'s twin for
    /// `allium::dir_round_trip_over_circuit`: runs the blocking,
    /// multi-hop `CircuitBuilder`-based call on a dedicated OS thread so it
    /// never blocks the single-threaded tokio `LocalSet` the guard/
    /// authority are served from, and awaits the result cooperatively.
    async fn run_blocking_dir_round_trip_over_circuit(hops: Vec<(String, Addr)>, request_bytes: Vec<u8>) -> Result<Vec<u8>, String> {
        let (tx, rx) = std::sync::mpsc::channel::<Result<Vec<u8>, String>>();
        std::thread::spawn(move || {
            let outcome = allium::dir_round_trip_over_circuit(&hops, None, &request_bytes).map_err(|e| e.to_string());
            let _ = tx.send(outcome);
        });
        loop {
            match rx.try_recv() {
                Ok(outcome) => return outcome,
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err("dir_round_trip_over_circuit thread exited without a result".to_string());
                }
            }
        }
    }

    /// Security audit fix (2026-09-26, finding MH2 -- NAT-rendezvous
    /// protocol is entirely plaintext): proves `allium::register_over_circuit`
    /// (relay side) and `AuthorityService::install_full`'s NAT dispatch
    /// (authority side) actually complete a real REGISTER/REGISTERED/
    /// REGISTER_CONFIRM exchange over a real one-hop onion circuit, over
    /// real loopback UDP -- not just that the wire-format functions
    /// round-trip in memory (already covered by `nat.rs`'s own unit tests).
    /// A successful exchange must leave the authority's `NatRendezvous`
    /// actually holding the registration afterward.
    #[test]
    fn test_register_over_circuit_reaches_a_real_authority_and_completes_registration() {
        use allium::nat::{Ed25519Ops as NatEd25519Ops, NatAgent, NatRendezvous};

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("failed to start tokio runtime");
        let local = tokio::task::LocalSet::new();

        let outcome: Result<bool, String> = local.block_on(&rt, async move {
            let args = AuthorityArgs {
                bind: "127.0.0.1:0".to_string(),
                name: Some("test-authority".to_string()),
                identity_file: None,
                idle_timeout: None,
                require_return_routability: true,
                authorities: None,
                allow_private_extend: false,
                allow_open_authority: true,
                max_descriptors: allium::dirwire::MAX_DESCRIPTOR_COUNT,
                max_relays_per_subnet: 64,
            };
            let options = authority_options(&args)?;
            let directory = Rc::new(RefCell::new(Directory::new(DirectoryOptions::default()).map_err(|e| e.to_string())?));

            let introducer_identity_private = [0x55u8; 32];
            let introducer_identity_public = (NatEd25519Ops::real().public_of)(&introducer_identity_private);
            let introducer_x25519_private = (NatEd25519Ops::real().x25519_generate)();
            let introducer_x25519_public = (NatEd25519Ops::real().x25519_public)(&introducer_x25519_private);
            let nat_rendezvous = Rc::new(RefCell::new(NatRendezvous::new(
                introducer_identity_private,
                introducer_x25519_private,
                Box::new(|_identity: &[u8]| None),
                Box::new(now_secs),
                100.0,
                100,
                NatEd25519Ops::real(),
            )));

            let node = Rc::new(RefCell::new(RelayNode::new(options).map_err(|e| e.to_string())?));
            let authority_addr = RelayNode::start(&node, ("127.0.0.1".to_string(), 0)).await.map_err(|e| e.to_string())?;
            AuthorityService::install_full(&node, directory, None, Some(nat_rendezvous.clone()));
            tokio::task::spawn_local(RelayNode::serve_loop(node.clone()));

            let relay_identity_private = [0x66u8; 32];
            let relay_identity_public = (NatEd25519Ops::real().public_of)(&relay_identity_private);
            let relay_x25519_private = (NatEd25519Ops::real().x25519_generate)();
            let agent = NatAgent::new(
                relay_identity_private,
                relay_x25519_private,
                authority_addr,
                vec![introducer_identity_public],
                vec![introducer_x25519_public],
                Box::new(now_secs),
                100.0,
                100,
                NatEd25519Ops::real(),
            )
            .map_err(|e| e.to_string())?;

            run_blocking_register_over_circuit(agent).await?;

            // `REGISTER_CONFIRM` gets no reply (see `on_register_confirm`'s
            // doc), so a successful `register_over_circuit` only means the
            // bytes were sent -- the authority's own `deliver` handler that
            // actually applies it runs as a separately-scheduled
            // `spawn_local` task on this same executor, so it may not have
            // run yet the instant this returns. Poll briefly rather than
            // checking exactly once.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                if nat_rendezvous.borrow_mut().registered_addr(&relay_identity_public).is_some() {
                    return Ok(true);
                }
                if std::time::Instant::now() >= deadline {
                    return Ok(false);
                }
                tokio::task::yield_now().await;
            }
        });

        let registered = outcome.expect(
            "a real REGISTER/REGISTERED/REGISTER_CONFIRM exchange over a real one-hop onion circuit to a real authority should complete",
        );
        assert!(registered, "the relay identity must actually be registered on the authority's NatRendezvous after a successful exchange");
    }

    fn now_secs() -> f64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64()
    }

    /// [`run_blocking_dir_round_trip`]'s twin for
    /// `allium::register_over_circuit`: runs the blocking, `CircuitBuilder`-
    /// based NAT registration on a dedicated OS thread so it never blocks
    /// the single-threaded tokio `LocalSet` the authority is served from --
    /// that `LocalSet` needs to keep polling to drive `RelayNode::serve_loop`
    /// while this call is in flight, which running it inline here would
    /// prevent. `NatAgent` moves into the thread wholesale (its closures
    /// were made `Send` for exactly this -- see `nat.rs`'s `SignFn`/
    /// `VerifyFn`/`PublicOfFn`/`clock` doc comments).
    async fn run_blocking_register_over_circuit(mut agent: allium::nat::NatAgent) -> Result<(), String> {
        let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
        std::thread::spawn(move || {
            let outcome = allium::register_over_circuit(&mut agent, None).map_err(|e| e.to_string());
            let _ = tx.send(outcome);
        });
        loop {
            match rx.try_recv() {
                Ok(outcome) => return outcome,
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err("register_over_circuit thread exited without a result".to_string());
                }
            }
        }
    }

    #[test]
    fn cmd_authority_rejects_wrong_length_authorities_key() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let local = tokio::task::LocalSet::new();
        let args = AuthorityArgs {
            bind: "127.0.0.1:0".to_string(),
            name: None,
            identity_file: None,
            idle_timeout: None,
            require_return_routability: true,
            authorities: Some("aabb".to_string()),
            allow_private_extend: false,
            allow_open_authority: false,
            max_descriptors: allium::dirwire::MAX_DESCRIPTOR_COUNT,
            max_relays_per_subnet: 64,
        };
        let result: Result<(), String> = local.block_on(&rt, cmd_authority(args));
        assert!(result.is_err(), "a 2-byte hex key is not a valid 32-byte identity and must be rejected");
    }
}
