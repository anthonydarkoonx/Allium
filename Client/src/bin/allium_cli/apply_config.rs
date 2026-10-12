//! `apply_config`: fill in any CLI flag the operator left unset from
//! `--config`/`-f` (port of `allium_cli.py`'s function of the same name).
//!
//! Precedence is CLI flag > config file > this binary's own hardcoded
//! default (see [`allium::config::resolve`]). This consumes and returns
//! `Args`; every field it touches defaults to `None` in [`crate::args`] so
//! "not given on the CLI" is distinguishable from "given, and happens to
//! match the old default".
//!
//! Two file formats are accepted, picked by extension: a file ending in
//! `.toml` is parsed as the original nested-table format
//! ([`allium::config::load_config`]); anything else -- a bare `alliumrc`,
//! a leftover `torrc`/`.torrc` file, whatever -- is parsed as a real flat
//! `torrc`-style file ([`allium::alliumrc::parse_alliumrc`]), Tor's own
//! one-directive-per-line shape. Both produce the identical [`Table`]
//! shape, so everything below reads from `config` without caring which
//! file an operator wrote.

use std::path::Path;

use allium::config::{
    client_section, client_trust_section, load_config, resolve, service_section,
    service_trust_section, Table, Value,
};
use allium::alliumrc::parse_alliumrc;
use allium::hiddenservice::{client_auth_public_key, load_or_create_client_auth_key};

use crate::args::Args;
use crate::cli_error::CliExit;
use crate::helpers::{
    apply_default_authority, hex_decode, hex_encode, require_authority_pin, say, validate_trust_keys,
};

/// `os.path.expanduser`'s common cases: a bare `~` or a `~/...` prefix,
/// expanded via `$HOME`. (`~user` forms are not handled, matching the
/// existing [`allium::alliumrc`] copy of this same helper -- deliberately
/// duplicated per module rather than shared; see that module's docs.)
fn expanduser(path: &str) -> String {
    let home = match std::env::var("HOME") {
        Ok(h) if !h.is_empty() => h,
        _ => return path.to_string(),
    };
    if path == "~" {
        return home;
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return format!("{}/{}", home.trim_end_matches('/'), rest);
    }
    path.to_string()
}

fn cfg_str(table: &Table, key: &str) -> Option<String> {
    table.get(key).and_then(Value::as_str).map(|s| s.to_string())
}

fn cfg_i64(table: &Table, key: &str) -> Option<i64> {
    table.get(key).and_then(Value::as_i64)
}

fn cfg_f64(table: &Table, key: &str) -> Option<f64> {
    table.get(key).and_then(Value::as_f64)
}

fn cfg_bool(table: &Table, key: &str) -> Option<bool> {
    table.get(key).and_then(Value::as_bool)
}

fn cfg_str_array(table: &Table, key: &str) -> Option<Vec<String>> {
    table.get(key).and_then(Value::as_array).map(|items| {
        items.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()
    })
}

fn resolve_str(cli: Option<String>, cfg: Option<String>, default: Option<&str>) -> Option<String> {
    resolve(cli, cfg, default.map(|s| s.to_string()))
}

fn resolve_i64(cli: Option<i64>, cfg: Option<i64>, default: i64) -> i64 {
    resolve(cli, cfg, Some(default)).expect("default is Some")
}

fn resolve_f64(cli: Option<f64>, cfg: Option<f64>, default: f64) -> f64 {
    resolve(cli, cfg, Some(default)).expect("default is Some")
}

fn resolve_bool(cli: Option<bool>, cfg: Option<bool>, default: bool) -> bool {
    resolve(cli, cfg, Some(default)).expect("default is Some")
}

/// Non-empty-string truthiness for an already-resolved value, matching
/// Python's `if value:` on a config-derived string.
fn truthy(s: &Option<String>) -> bool {
    matches!(s, Some(v) if !v.is_empty())
}

pub fn apply_config(mut args: Args) -> Result<Args, CliExit> {
    let mut config: Table = Table::new();
    if let Some(path) = args.config.clone() {
        if !path.is_empty() {
            config = if path.to_lowercase().ends_with(".toml") {
                load_config(Path::new(&path))?
            } else {
                parse_alliumrc(Path::new(&path), &args.role)?
            };
        }
    }

    if let Some(config_role) = cfg_str(&config, "role") {
        if config_role != args.role {
            say(&format!(
                "NOTE: --config says role = '{config_role}', but you ran the '{}' \
                 subcommand; the subcommand decides what this process does, the config \
                 file's 'role' is only a label.\n",
                args.role
            ));
        }
    }

    if args.role == "client" {
        apply_client(&mut args, &config)?;
    }
    if args.role == "service" {
        apply_service(&mut args, &config)?;
    }

    Ok(args)
}

fn apply_client(args: &mut Args, config: &Table) -> Result<(), CliExit> {
    let client = client_section(config)?;
    let trust = client_trust_section(config)?;

    args.client_auth_key_file =
        resolve_str(args.client_auth_key_file.clone(), cfg_str(&client, "client_auth_key_file"), None);
    if truthy(&args.client_auth_key_file) {
        args.client_auth_key_file = Some(expanduser(args.client_auth_key_file.as_deref().unwrap()));
    }

    if args.print_client_auth_key {
        // A pure key-management convenience -- generate/load the key and
        // print its public half so it can be copied into a service's
        // --client-auth-key/ClientAuthorizedKey, then exit cleanly. This
        // needs none of the network setup an ordinary client run
        // requires, so it is handled here, before that requirement below
        // would otherwise reject a --print-client-auth-key-only
        // invocation.
        let Some(key_file) = &args.client_auth_key_file else {
            return Err(CliExit::error(
                "--print-client-auth-key needs --client-auth-key-file PATH (or \
                 client.client_auth_key_file/ClientAuthKeyFile in --config) -- that's \
                 where the key is generated and kept",
            ));
        };
        let private_key = load_or_create_client_auth_key(Path::new(key_file))
            .map_err(|e| CliExit::error(format!("client: {e}")))?;
        let public_hex = hex_encode(&client_auth_public_key(&private_key));
        say(&format!("client: your client-authorization public key is {public_hex}"));
        say(&format!(
            "client: give this to the hidden service's operator to run with \
             --client-auth-key {public_hex} (or ClientAuthorizedKey {public_hex} in \
             their alliumrc) -- it does not need to be kept secret, only the private \
             key alongside it at {key_file} does"
        ));
        return Err(CliExit::clean());
    }

    args.guard = resolve_str(args.guard.clone(), cfg_str(&client, "guard"), None);
    args.middle = resolve_str(args.middle.clone(), cfg_str(&client, "middle"), None);
    args.exit_addr = resolve_str(args.exit_addr.clone(), cfg_str(&client, "exit"), None);
    args.authority = resolve_str(args.authority.clone(), cfg_str(&client, "authority"), None);
    args.authority_quorum = resolve(args.authority_quorum, cfg_i64(&client, "authority_quorum"), None);
    args.trust_authority = resolve_str(args.trust_authority.clone(), cfg_str(&trust, "authority"), None);
    args.allow_unpinned_authority =
        Some(resolve_bool(args.allow_unpinned_authority, cfg_bool(&trust, "allow_unpinned"), false));

    let have_manual_route = truthy(&args.guard) && truthy(&args.middle) && truthy(&args.exit_addr);
    if !have_manual_route {
        // Only consult the built-in default when there's no complete
        // manual route -- a fully-specified --guard/--middle/--exit
        // always wins outright and should not be silently overridden by
        // a default authority the operator never asked for.
        apply_default_authority(args);
    }
    if truthy(&args.trust_authority) {
        args.trust_authority = Some(validate_trust_keys(
            args.trust_authority.as_deref().unwrap(),
            "TrustAuthority/--trust-authority",
        )?);
    }
    if !have_manual_route && !truthy(&args.authority) {
        return Err(CliExit::error(
            "either all of --guard/--middle/--exit, or --authority, is required: pass \
             them on the CLI, or set client.guard/middle/exit or client.authority in \
             the file given to --config",
        ));
    }
    // A fully-specified manual route always wins outright: --authority is
    // simply not consulted in that case, rather than merged with it
    // partially, so there is never an ambiguous "two of three manual, one
    // fetched" circuit.

    args.target = resolve_str(args.target.clone(), cfg_str(&client, "target"), Some("127.0.0.1:9100"));
    args.socks_port = Some(resolve_i64(args.socks_port, cfg_i64(&client, "socks_port"), 9050));
    args.self_test = Some(resolve_bool(args.self_test, cfg_bool(&client, "self_test"), false));
    args.mtu = Some(resolve_i64(args.mtu, cfg_i64(&client, "mtu"), 256));
    args.timeout = Some(resolve_f64(args.timeout, cfg_f64(&client, "timeout"), 5.0));
    args.retries = Some(resolve_i64(args.retries, cfg_i64(&client, "retries"), 2));
    // `congestion` in the file is written in the positive sense (it's
    // what an operator would expect to read); `--no-congestion` is the
    // CLI's negative sense, so the sign is flipped here rather than
    // reusing `resolve` directly on mismatched polarities.
    if args.no_congestion.is_none() {
        args.no_congestion = Some(!resolve_bool(None, cfg_bool(&client, "congestion"), true));
    }
    args.allow_udp = Some(resolve_bool(args.allow_udp, cfg_bool(&client, "allow_udp"), false));
    // On by default: with one shared circuit, every site an application
    // visits is linkable at the exit by the circuit alone. The cost is a
    // circuit build per first-party site; `--no-isolate-by-destination`
    // (or `IsolateByDestination no`) is the explicit opt-out.
    args.isolate_by_destination = Some(resolve_bool(
        args.isolate_by_destination,
        cfg_bool(&client, "isolate_by_destination"),
        true,
    ));
    args.keepalive_interval =
        Some(resolve_f64(args.keepalive_interval, cfg_f64(&client, "keepalive_interval"), 90.0));
    args.require_pq = Some(resolve_bool(args.require_pq, cfg_bool(&client, "require_pq"), false));
    args.connect_attempts =
        Some(resolve_i64(args.connect_attempts, cfg_i64(&client, "connect_attempts"), 3));
    if args.connect_attempts.unwrap() < 1 {
        return Err(CliExit::error("client: --connect-attempts must be at least 1"));
    }
    args.connect_timeout =
        Some(resolve_f64(args.connect_timeout, cfg_f64(&client, "connect_timeout"), 15.0));
    if args.connect_timeout.unwrap() <= 0.0 {
        return Err(CliExit::error("client: --connect-timeout must be positive"));
    }
    args.trust_guard = resolve_str(args.trust_guard.clone(), cfg_str(&trust, "guard"), None);
    args.trust_middle = resolve_str(args.trust_middle.clone(), cfg_str(&trust, "middle"), None);
    args.trust_exit = resolve_str(args.trust_exit.clone(), cfg_str(&trust, "exit"), None);
    if truthy(&args.trust_guard) {
        args.trust_guard =
            Some(validate_trust_keys(args.trust_guard.as_deref().unwrap(), "TrustGuard/--trust-guard")?);
    }
    if truthy(&args.trust_middle) {
        args.trust_middle = Some(validate_trust_keys(
            args.trust_middle.as_deref().unwrap(),
            "TrustMiddle/--trust-middle",
        )?);
    }
    if truthy(&args.trust_exit) {
        args.trust_exit =
            Some(validate_trust_keys(args.trust_exit.as_deref().unwrap(), "TrustExit/--trust-exit")?);
    }

    // A .allium fetch is its own path entirely (see run_fetch_onion) --
    // these two are only meaningful together with --fetch-onion, so they
    // are resolved here rather than given their own role-specific block.
    args.fetch_onion = resolve_str(args.fetch_onion.clone(), cfg_str(&client, "fetch_onion"), None);
    args.fetch_onion_path =
        resolve_str(args.fetch_onion_path.clone(), cfg_str(&client, "fetch_onion_path"), Some("/"));

    // A fully-specified manual guard/middle/exit route means --authority
    // is never actually contacted -- unless --fetch-onion is also given,
    // which always needs the authority regardless. Only require a pin
    // when the authority will genuinely be dereferenced.
    if truthy(&args.authority) && (!have_manual_route || truthy(&args.fetch_onion)) {
        require_authority_pin(args, "client")?;
    }

    // Defaults to a per-user path, same as Tor's `~/.tor/state`, rather
    // than `None`. Before this,
    // guard persistence was fully built (see `load_persisted_guard`/
    // `save_persisted_guard` in `dirclient.rs` -- atomic write, 0600
    // permissions, graceful fallback when the persisted guard is gone)
    // but never actually engaged unless an operator remembered to pass
    // `--state-file` themselves, so a plain `allium client` re-randomized
    // its guard on every single restart -- reopening exactly the
    // predictable-path/guard-discovery exposure entry guards exist to
    // close. `--state-file ""` (or `state_file = ""` in the config file)
    // still opts out, same as `--config ""` already does for the config
    // file itself: `resolve()` treats an explicit CLI/config `""` as a
    // real (non-`None`) value that wins over this default, and
    // `fetch_route_from_authority` already filters out an empty
    // `state_file` before using it.
    args.state_file =
        resolve_str(args.state_file.clone(), cfg_str(&client, "state_file"), Some("~/.allium/state"));
    if truthy(&args.state_file) {
        args.state_file = Some(expanduser(args.state_file.as_deref().unwrap()));
    }

    Ok(())
}

fn apply_service(args: &mut Args, config: &Table) -> Result<(), CliExit> {
    let service = service_section(config)?;
    let trust = service_trust_section(config)?;

    args.guard = resolve_str(args.guard.clone(), cfg_str(&service, "guard"), None);
    args.middle = resolve_str(args.middle.clone(), cfg_str(&service, "middle"), None);
    args.authority = resolve_str(args.authority.clone(), cfg_str(&service, "authority"), None);
    args.authority_quorum = resolve(args.authority_quorum, cfg_i64(&service, "authority_quorum"), None);
    args.trust_authority = resolve_str(args.trust_authority.clone(), cfg_str(&trust, "authority"), None);
    args.allow_unpinned_authority =
        Some(resolve_bool(args.allow_unpinned_authority, cfg_bool(&trust, "allow_unpinned"), false));
    apply_default_authority(args);
    if truthy(&args.trust_authority) {
        args.trust_authority = Some(validate_trust_keys(
            args.trust_authority.as_deref().unwrap(),
            "TrustAuthority/--trust-authority",
        )?);
    }
    if !truthy(&args.authority) {
        return Err(CliExit::error(
            "--authority is required: pass it on the CLI, or set service.authority in \
             the file given to --config -- a hidden service is only reachable through \
             a directory authority's introduction-point lookup",
        ));
    }
    let pin_context = match &args.name {
        Some(n) if !n.is_empty() => n.clone(),
        _ => "service".to_string(),
    };
    require_authority_pin(args, &pin_context)?;
    args.trust_guard = resolve_str(args.trust_guard.clone(), cfg_str(&trust, "guard"), None);
    args.trust_middle = resolve_str(args.trust_middle.clone(), cfg_str(&trust, "middle"), None);
    if truthy(&args.trust_guard) {
        args.trust_guard =
            Some(validate_trust_keys(args.trust_guard.as_deref().unwrap(), "TrustGuard/--trust-guard")?);
    }
    if truthy(&args.trust_middle) {
        args.trust_middle = Some(validate_trust_keys(
            args.trust_middle.as_deref().unwrap(),
            "TrustMiddle/--trust-middle",
        )?);
    }

    // HiddenServiceDir, mirroring real Tor: a directory that holds only
    // the service's key -- and, once the address is known, a `hostname`
    // file naming it -- so an alliumrc as simple as
    //     HiddenServiceDir ~/.allium/my_service
    //     HiddenServicePort 80 127.0.0.1:8080
    // is enough to stand a service up, with no --identity-file needed at
    // all. An explicit --identity-file (CLI or config) still overrides
    // the key path this derives, same as --advertise overriding --bind.
    //
    // `args.name` is resolved here (ahead of its other use below) so a
    // caller giving neither --hidden-service-dir nor --identity-file still
    // gets a real, dedicated directory to default into next, rather than a
    // bare CWD-relative filename with no directory-hardening step at all.
    args.name = resolve_str(args.name.clone(), cfg_str(&service, "name"), Some("service"));
    args.hidden_service_dir =
        resolve_str(args.hidden_service_dir.clone(), cfg_str(&service, "hidden_service_dir"), None);
    if !truthy(&args.hidden_service_dir) {
        args.hidden_service_dir = Some(format!("~/.allium/hidden_service/{}", args.name.as_deref().unwrap_or("service")));
    }
    args.hidden_service_dir = Some(expanduser(args.hidden_service_dir.as_deref().unwrap()));

    let hidden_service_port =
        resolve_str(args.hidden_service_port.clone(), cfg_str(&service, "hidden_service_port"), None);
    let Some(hidden_service_port) = hidden_service_port.filter(|s| !s.is_empty()) else {
        return Err(CliExit::error(
            "--hidden-service-port IP:PORT is required: pass it on the CLI, or set \
             service.hidden_service_port (or HiddenServicePort in an alliumrc) in the \
             file given to --config -- this is the local address of the ordinary web \
             server (nginx, Apache, anything speaking plain HTTP) that actually serves \
             your content; Allium just forwards rendezvous traffic to it (see \
             examples/alliumrc)",
        ));
    };
    args.hidden_service_port = Some(hidden_service_port);

    // `hidden_service_dir` is always set by this point (explicitly, or
    // defaulted above), so the identity file always lands inside a real,
    // dedicated directory that `ServiceIdentity::load_or_create` hardens
    // to 0700 -- never a bare, CWD-relative filename.
    let default_identity_file = format!("{}/hs_ed25519_secret_key", args.hidden_service_dir.as_deref().unwrap_or_default());
    let identity_file = resolve_str(
        args.identity_file.clone(),
        cfg_str(&service, "identity_file"),
        Some(&default_identity_file),
    )
    .unwrap();
    args.identity_file = Some(expanduser(&identity_file));

    args.timeout = Some(resolve_f64(args.timeout, cfg_f64(&service, "timeout"), 5.0));
    args.retries = Some(resolve_i64(args.retries, cfg_i64(&service, "retries"), 2));
    args.intro_count = Some(resolve_i64(args.intro_count, cfg_i64(&service, "intro_count"), 3));
    args.publish_interval = resolve(args.publish_interval, cfg_f64(&service, "publish_interval"), None);
    args.keepalive_interval =
        Some(resolve_f64(args.keepalive_interval, cfg_f64(&service, "keepalive_interval"), 90.0));

    // Client authorization: restrict who can even learn this service's
    // introduction points, by hex X25519 public key. Empty (the default)
    // means an ordinary, unrestricted service.
    let raw_client_auth_keys = resolve(
        args.client_auth_key.clone().filter(|v| !v.is_empty()),
        cfg_str_array(&service, "client_auth_keys"),
        None,
    );
    let mut client_auth_keys = Vec::new();
    for hex_key in raw_client_auth_keys.into_iter().flatten() {
        let key_bytes = hex_decode(&hex_key).map_err(|_| {
            CliExit::error(format!("--client-auth-key/ClientAuthorizedKey value '{hex_key}' is not valid hex"))
        })?;
        if key_bytes.len() != 32 {
            return Err(CliExit::error(format!(
                "--client-auth-key/ClientAuthorizedKey value '{hex_key}' must be a 32-byte \
                 X25519 public key ({} bytes given) -- see 'client --print-client-auth-key' \
                 for how a client generates one",
                key_bytes.len()
            )));
        }
        client_auth_keys.push(key_bytes);
    }
    args.client_auth_keys = client_auth_keys;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn scratch_file(text: &str, ext: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!("allium-cli-apply-config-test-{}-{n}.{ext}", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(text.as_bytes()).unwrap();
        path.to_path_buf()
    }

    fn base_client_args() -> Args {
        Args { role: "client".to_string(), ..Args::default() }
    }

    #[test]
    fn client_manual_route_needs_no_authority_and_gets_defaults() {
        let mut args = base_client_args();
        args.guard = Some("1.1.1.1:1".to_string());
        args.middle = Some("1.1.1.1:2".to_string());
        args.exit_addr = Some("1.1.1.1:3".to_string());
        let args = apply_config(args).unwrap();
        assert_eq!(args.target.as_deref(), Some("127.0.0.1:9100"));
        assert_eq!(args.socks_port, Some(9050));
        assert_eq!(args.mtu, Some(256));
        assert_eq!(args.timeout, Some(5.0));
        assert_eq!(args.retries, Some(2));
        assert_eq!(args.no_congestion, Some(false));
        assert_eq!(args.connect_attempts, Some(3));
        assert_eq!(args.connect_timeout, Some(15.0));
        assert_eq!(args.fetch_onion_path.as_deref(), Some("/"));
    }

    #[test]
    fn client_without_route_or_authority_is_an_error() {
        // Held even though this test doesn't touch the default-authority
        // env vars itself -- it depends on them being *unset*, so it must
        // not interleave with a test elsewhere that transiently sets them
        // (see `crate::helpers::env_test_lock`).
        let _guard = crate::helpers::env_test_lock::LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let args = base_client_args();
        assert!(apply_config(args).is_err());
    }

    #[test]
    fn client_manual_route_is_unaffected_by_an_unpinned_fallback_authority() {
        // Even with --authority also set (as an unused fallback), a fully
        // manual guard/middle/exit route means --authority is never
        // dereferenced (see build_circuit's own comment) -- no reason to
        // demand a pin for something that won't be used.
        let mut args = base_client_args();
        args.guard = Some("1.1.1.1:1".to_string());
        args.middle = Some("2.2.2.2:2".to_string());
        args.exit_addr = Some("3.3.3.3:3".to_string());
        args.authority = Some("10.0.0.1:9030".to_string());
        assert!(apply_config(args).is_ok());
    }

    #[test]
    fn client_manual_route_plus_fetch_onion_still_requires_a_pin() {
        // --fetch-onion always needs the authority (it's the only way a
        // .allium address resolves to introduction points), regardless of
        // an otherwise-complete manual guard/middle/exit route.
        let mut args = base_client_args();
        args.guard = Some("1.1.1.1:1".to_string());
        args.middle = Some("2.2.2.2:2".to_string());
        args.exit_addr = Some("3.3.3.3:3".to_string());
        args.authority = Some("10.0.0.1:9030".to_string());
        args.fetch_onion = Some("someaddress.allium".to_string());
        assert!(apply_config(args).is_err());
    }

    #[test]
    fn client_authority_without_trust_pin_is_rejected_unless_allowed() {
        let mut args = base_client_args();
        args.authority = Some("2.2.2.2:9030".to_string());
        assert!(apply_config(args.clone()).is_err());

        args.allow_unpinned_authority = Some(true);
        let resolved = apply_config(args).unwrap();
        assert_eq!(resolved.authority.as_deref(), Some("2.2.2.2:9030"));
    }

    #[test]
    fn client_trust_authority_is_validated_and_canonicalized() {
        let mut args = base_client_args();
        args.authority = Some("2.2.2.2:9030".to_string());
        args.trust_authority = Some("AB".repeat(32));
        let resolved = apply_config(args).unwrap();
        assert_eq!(resolved.trust_authority.as_deref(), Some("ab".repeat(32).as_str()));
    }

    #[test]
    fn client_connect_attempts_and_timeout_are_validated() {
        let mut args = base_client_args();
        args.guard = Some("1.1.1.1:1".to_string());
        args.middle = Some("1.1.1.1:2".to_string());
        args.exit_addr = Some("1.1.1.1:3".to_string());
        args.connect_attempts = Some(0);
        assert!(apply_config(args.clone()).is_err());

        args.connect_attempts = Some(1);
        args.connect_timeout = Some(0.0);
        assert!(apply_config(args).is_err());
    }

    #[test]
    fn client_config_file_supplies_manual_route() {
        let path = scratch_file(
            "[client]\nguard = \"1.1.1.1:1\"\nmiddle = \"1.1.1.1:2\"\nexit = \"1.1.1.1:3\"\n",
            "toml",
        );
        let mut args = base_client_args();
        args.config = Some(path.to_string_lossy().to_string());
        let resolved = apply_config(args).unwrap();
        assert_eq!(resolved.guard.as_deref(), Some("1.1.1.1:1"));
        assert_eq!(resolved.middle.as_deref(), Some("1.1.1.1:2"));
        assert_eq!(resolved.exit_addr.as_deref(), Some("1.1.1.1:3"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn cli_flag_overrides_config_file() {
        let path = scratch_file("[client]\ntarget = \"9.9.9.9:1\"\n", "toml");
        let mut args = base_client_args();
        args.guard = Some("1.1.1.1:1".to_string());
        args.middle = Some("1.1.1.1:2".to_string());
        args.exit_addr = Some("1.1.1.1:3".to_string());
        args.target = Some("5.5.5.5:2".to_string());
        args.config = Some(path.to_string_lossy().to_string());
        let resolved = apply_config(args).unwrap();
        assert_eq!(resolved.target.as_deref(), Some("5.5.5.5:2"));
        std::fs::remove_file(&path).ok();
    }

    fn base_service_args() -> Args {
        Args { role: "service".to_string(), ..Args::default() }
    }

    #[test]
    fn service_requires_authority_then_hidden_service_port() {
        // See the comment on `client_without_route_or_authority_is_an_error`:
        // this depends on the default-authority env vars being unset.
        let _guard = crate::helpers::env_test_lock::LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let args = base_service_args();
        assert!(apply_config(args).is_err());

        let mut args = base_service_args();
        args.authority = Some("2.2.2.2:9030".to_string());
        args.allow_unpinned_authority = Some(true);
        assert!(apply_config(args).is_err()); // still missing --hidden-service-port
    }

    #[test]
    fn service_with_unpinned_authority_raises() {
        let mut args = base_service_args();
        args.hidden_service_port = Some("127.0.0.1:8080".to_string());
        args.authority = Some("10.0.0.1:9030".to_string());
        assert!(apply_config(args).is_err());
    }

    #[test]
    fn service_with_pinned_authority_is_fine() {
        let mut args = base_service_args();
        args.hidden_service_port = Some("127.0.0.1:8080".to_string());
        args.authority = Some("10.0.0.1:9030".to_string());
        args.trust_authority = Some("aa".repeat(32));
        assert!(apply_config(args).is_ok());
    }

    #[test]
    fn service_defaults_identity_file_under_a_dedicated_hardened_directory() {
        // With neither --hidden-service-dir nor --identity-file given,
        // the identity file must still land inside
        // a real, dedicated directory (so it gets 0700-hardened), never a
        // bare, CWD-relative filename like the old "service.key" default.
        let mut args = base_service_args();
        args.authority = Some("2.2.2.2:9030".to_string());
        args.allow_unpinned_authority = Some(true);
        args.hidden_service_port = Some("127.0.0.1:8080".to_string());
        let resolved = apply_config(args).unwrap();
        assert_eq!(resolved.name.as_deref(), Some("service"));
        let hidden_service_dir = resolved.hidden_service_dir.as_deref().unwrap();
        assert!(hidden_service_dir.ends_with(".allium/hidden_service/service"), "{hidden_service_dir}");
        assert!(!hidden_service_dir.starts_with('~'), "{hidden_service_dir}");
        assert_eq!(resolved.identity_file.as_deref(), Some(format!("{hidden_service_dir}/hs_ed25519_secret_key").as_str()));

        let mut args = base_service_args();
        args.authority = Some("2.2.2.2:9030".to_string());
        args.allow_unpinned_authority = Some(true);
        args.hidden_service_port = Some("127.0.0.1:8080".to_string());
        args.hidden_service_dir = Some("/tmp/svc".to_string());
        let resolved = apply_config(args).unwrap();
        assert_eq!(resolved.identity_file.as_deref(), Some("/tmp/svc/hs_ed25519_secret_key"));
    }

    #[test]
    fn service_client_auth_keys_are_decoded_and_validated() {
        let mut args = base_service_args();
        args.authority = Some("2.2.2.2:9030".to_string());
        args.allow_unpinned_authority = Some(true);
        args.hidden_service_port = Some("127.0.0.1:8080".to_string());
        args.client_auth_key = Some(vec!["ab".repeat(32)]);
        let resolved = apply_config(args).unwrap();
        assert_eq!(resolved.client_auth_keys.len(), 1);
        assert_eq!(resolved.client_auth_keys[0].len(), 32);

        let mut bad = base_service_args();
        bad.authority = Some("2.2.2.2:9030".to_string());
        bad.allow_unpinned_authority = Some(true);
        bad.hidden_service_port = Some("127.0.0.1:8080".to_string());
        bad.client_auth_key = Some(vec!["nothex".to_string()]);
        assert!(apply_config(bad).is_err());
    }

    #[test]
    fn alliumrc_style_config_file_also_works_for_service() {
        let path = scratch_file(
            "role service\nauthority 2.2.2.2:9030\nallowunpinnedauthority true\nhiddenserviceport 80 127.0.0.1:8080\n",
            "conf",
        );
        let mut args = base_service_args();
        args.config = Some(path.to_string_lossy().to_string());
        let resolved = apply_config(args).unwrap();
        assert_eq!(resolved.hidden_service_port.as_deref(), Some("127.0.0.1:8080"));
        std::fs::remove_file(&path).ok();
    }

    // -- built-in default authority, wired end-to-end through apply_config --
    //
    // `crate::helpers::DEFAULT_AUTHORITIES` is a `const` (empty in this
    // source tree), so unlike the Python original's tests -- which
    // monkeypatch `allium_cli.DEFAULT_AUTHORITIES` directly -- these drive
    // the same fallback through the `ALLIUM_DEFAULT_AUTHORITY`/
    // `ALLIUM_DEFAULT_TRUST_AUTHORITY` env vars `default_authority()`
    // checks first (see `helpers::default_authority`'s doc), which
    // exercises the exact same `apply_default_authority`/
    // `require_authority_pin` wiring. All share `env_test_lock::LOCK` so
    // they can't interleave with each other or with `helpers`' own
    // default-authority tests.

    fn clear_default_authority_env() -> std::sync::MutexGuard<'static, ()> {
        let guard = crate::helpers::env_test_lock::LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("ALLIUM_DEFAULT_AUTHORITY");
        std::env::remove_var("ALLIUM_DEFAULT_TRUST_AUTHORITY");
        guard
    }

    #[test]
    fn client_default_authority_fills_in_when_no_manual_route_or_authority() {
        let _guard = clear_default_authority_env();
        std::env::set_var("ALLIUM_DEFAULT_AUTHORITY", "203.0.113.9:9030");
        std::env::set_var("ALLIUM_DEFAULT_TRUST_AUTHORITY", "aa".repeat(32));
        let resolved = apply_config(base_client_args()).unwrap(); // must not raise
        assert_eq!(resolved.authority.as_deref(), Some("203.0.113.9:9030"));
        assert_eq!(resolved.trust_authority.as_deref(), Some("aa".repeat(32).as_str()));
        std::env::remove_var("ALLIUM_DEFAULT_AUTHORITY");
        std::env::remove_var("ALLIUM_DEFAULT_TRUST_AUTHORITY");
    }

    #[test]
    fn client_default_authority_never_overrides_a_complete_manual_route() {
        let _guard = clear_default_authority_env();
        std::env::set_var("ALLIUM_DEFAULT_AUTHORITY", "203.0.113.9:9030");
        std::env::set_var("ALLIUM_DEFAULT_TRUST_AUTHORITY", "aa".repeat(32));
        let mut args = base_client_args();
        args.guard = Some("1.1.1.1:1".to_string());
        args.middle = Some("2.2.2.2:2".to_string());
        args.exit_addr = Some("3.3.3.3:3".to_string());
        let resolved = apply_config(args).unwrap();
        // Matches --authority's own help text: a fully manual route wins
        // outright, and the default must not be silently substituted in
        // for an operator who deliberately gave one.
        assert_eq!(resolved.authority, None);
        std::env::remove_var("ALLIUM_DEFAULT_AUTHORITY");
        std::env::remove_var("ALLIUM_DEFAULT_TRUST_AUTHORITY");
    }

    #[test]
    fn client_explicit_cli_authority_wins_over_default() {
        let _guard = clear_default_authority_env();
        std::env::set_var("ALLIUM_DEFAULT_AUTHORITY", "203.0.113.9:9030");
        std::env::set_var("ALLIUM_DEFAULT_TRUST_AUTHORITY", "aa".repeat(32));
        let mut args = base_client_args();
        args.authority = Some("10.0.0.5:9030".to_string());
        args.allow_unpinned_authority = Some(true);
        let resolved = apply_config(args).unwrap();
        assert_eq!(resolved.authority.as_deref(), Some("10.0.0.5:9030"));
        assert_eq!(resolved.trust_authority, None); // the default's pin is never bolted on
        std::env::remove_var("ALLIUM_DEFAULT_AUTHORITY");
        std::env::remove_var("ALLIUM_DEFAULT_TRUST_AUTHORITY");
    }

    #[test]
    fn service_default_authority_satisfies_the_required_check() {
        let _guard = clear_default_authority_env();
        std::env::set_var("ALLIUM_DEFAULT_AUTHORITY", "203.0.113.9:9030");
        std::env::set_var("ALLIUM_DEFAULT_TRUST_AUTHORITY", "aa".repeat(32));
        let mut args = base_service_args();
        args.hidden_service_port = Some("127.0.0.1:8080".to_string());
        let resolved = apply_config(args).unwrap(); // must not raise
        assert_eq!(resolved.authority.as_deref(), Some("203.0.113.9:9030"));
        assert_eq!(resolved.trust_authority.as_deref(), Some("aa".repeat(32).as_str()));
        std::env::remove_var("ALLIUM_DEFAULT_AUTHORITY");
        std::env::remove_var("ALLIUM_DEFAULT_TRUST_AUTHORITY");
    }

    #[test]
    fn service_no_default_and_no_authority_still_raises() {
        let _guard = clear_default_authority_env();
        let mut args = base_service_args();
        args.hidden_service_port = Some("127.0.0.1:8080".to_string());
        assert!(apply_config(args).is_err());
    }
}
