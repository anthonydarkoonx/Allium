//! The CLI's argument surface and a small hand-rolled parser.
//!
//! Python's `build_parser()` uses `argparse`, with three subcommands
//! (`echo`/`client`/`service`) each carrying their own flag set, plus a
//! `--config`/`-f PATH` option that must appear *before* the role. No
//! argument-parsing crate is vendored in this sandbox, so this is a small
//! dedicated parser scoped to exactly this fixed grammar -- the same
//! "hand-roll a minimal subset
//! rather than vendor a large dependency chain" call already made for
//! [`allium::config`]'s TOML parser.
//!
//! Every flag defaults to `None` (mirroring `argparse`'s `default=None`
//! throughout `allium_cli.py`), so `apply_config` can distinguish "not
//! given on the CLI" from "given, and happens to match the old default".
//! The two exceptions are `print_client_auth_key` (Python default
//! `False`, not `None` -- it is a pure CLI convenience, never resolved
//! against a config file) and `client_auth_keys` (populated only by
//! [`crate::apply_config::apply_config`], never directly by the parser).

use crate::cli_error::CliExit;

/// Parsed CLI arguments plus (after `apply_config`) values merged in from
/// a `--config` file. One `None`/`Some` per Python `argparse` default:
/// see the module doc.
#[derive(Debug, Clone, Default)]
pub struct Args {
    pub role: String,
    pub config: Option<String>,

    // -- echo --------------------------------------------------------------
    pub bind: Option<String>,

    // -- client --------------------------------------------------------------
    pub guard: Option<String>,
    pub middle: Option<String>,
    pub exit_addr: Option<String>,
    pub authority_quorum: Option<i64>,
    pub authority: Option<String>,
    pub target: Option<String>,
    pub socks_port: Option<i64>,
    pub self_test: Option<bool>,
    pub mtu: Option<i64>,
    pub timeout: Option<f64>,
    pub retries: Option<i64>,
    pub no_congestion: Option<bool>,
    pub allow_udp: Option<bool>,
    pub isolate_by_destination: Option<bool>,
    pub require_pq: Option<bool>,
    pub connect_attempts: Option<i64>,
    pub connect_timeout: Option<f64>,
    pub keepalive_interval: Option<f64>,
    pub trust_guard: Option<String>,
    pub trust_middle: Option<String>,
    pub trust_exit: Option<String>,
    pub trust_authority: Option<String>,
    pub allow_unpinned_authority: Option<bool>,
    /// Service only: allow a rendezvous circuit with no extra hop between the
    /// middle relay and the rendezvous point when none is available. Off by
    /// default, because that short path lets a hostile rendezvous point learn
    /// the service's fixed middle relay.
    pub allow_short_rendezvous: Option<bool>,
    /// Client and service: how long (seconds) a relay must have been seen in
    /// the directory before it may be picked as an unpinned guard. `None`
    /// means the built-in 6 hours. Lowering it (0 turns the check off) is for
    /// small or brand-new test networks: it lets a relay that has just
    /// appeared claim the guard role.
    pub min_guard_age: Option<f64>,
    pub fetch_onion: Option<String>,
    pub fetch_onion_path: Option<String>,
    pub state_file: Option<String>,
    pub client_auth_key_file: Option<String>,
    /// `argparse` default `False` (not `None`): a pure CLI convenience,
    /// never merged with a config file.
    pub print_client_auth_key: bool,

    // -- service -------------------------------------------------------------
    pub hidden_service_port: Option<String>,
    pub hidden_service_dir: Option<String>,
    pub identity_file: Option<String>,
    pub name: Option<String>,
    pub intro_count: Option<i64>,
    pub publish_interval: Option<f64>,
    /// Raw hex strings from `--client-auth-key` (repeatable), before
    /// `apply_config` decodes and validates them into
    /// [`Args::client_auth_keys`].
    pub client_auth_key: Option<Vec<String>>,
    /// Decoded, validated 32-byte X25519 public keys -- populated only by
    /// `apply_config`, empty (unrestricted service) by default.
    pub client_auth_keys: Vec<Vec<u8>>,

    // -- populated at runtime, never by the parser or apply_config -----------
    /// `{hop_name: ML-KEM-768 encapsulation key}`, filled in by
    /// `dirclient::build_circuit`/`_resolve_entry_hops` once a route is
    /// fetched from the directory (mirrors Python's dynamically-added
    /// `args.kem_keys` attribute). Empty for a manual guard/middle/exit
    /// route, which has no signed descriptor to take a PQ key from.
    pub kem_keys: std::collections::HashMap<String, Vec<u8>>,
}

fn usage_error(msg: impl Into<String>) -> CliExit {
    CliExit::error(msg.into())
}

/// Splits `--flag=value` into `("--flag", Some("value"))`; anything else
/// (including a bare `-f`, which never takes `=value` form here) is
/// returned unsplit.
fn split_flag(tok: &str) -> (&str, Option<&str>) {
    if tok.starts_with("--") {
        if let Some(eq) = tok.find('=') {
            return (&tok[..eq], Some(&tok[eq + 1..]));
        }
    }
    (tok, None)
}

/// Consumes and returns this flag's value: either the `=value` already
/// split off, or the next whitespace-separated token (advancing `*i` to
/// point at it).
fn take_value(tokens: &[String], i: &mut usize, flag: &str, inline: Option<&str>) -> Result<String, CliExit> {
    if let Some(v) = inline {
        return Ok(v.to_string());
    }
    *i += 1;
    tokens
        .get(*i)
        .cloned()
        .ok_or_else(|| usage_error(format!("argument {flag}: expected one argument")))
}

fn parse_int(flag: &str, s: &str) -> Result<i64, CliExit> {
    s.parse::<i64>().map_err(|_| usage_error(format!("argument {flag}: invalid int value: '{s}'")))
}

fn parse_float(flag: &str, s: &str) -> Result<f64, CliExit> {
    s.parse::<f64>().map_err(|_| usage_error(format!("argument {flag}: invalid float value: '{s}'")))
}

/// Parse the full process argument vector (excluding argv[0]).
pub fn parse_args(raw: &[String]) -> Result<Args, CliExit> {
    let mut i = 0;
    let mut config: Option<String> = None;
    while i < raw.len() {
        let (flag, inline) = split_flag(&raw[i]);
        match flag {
            "--config" | "-f" => {
                config = Some(take_value(raw, &mut i, flag, inline)?);
                i += 1;
            }
            _ => break,
        }
    }
    let role = raw
        .get(i)
        .cloned()
        .ok_or_else(|| usage_error("the following arguments are required: role (echo, client, service)"))?;
    i += 1;
    let rest = &raw[i..];

    let mut args = Args { role: role.clone(), config, ..Args::default() };
    match role.as_str() {
        "echo" => parse_echo(rest, &mut args)?,
        "client" => parse_client(rest, &mut args)?,
        "service" => parse_service(rest, &mut args)?,
        other => {
            return Err(usage_error(format!(
                "argument role: invalid choice: '{other}' (choose from 'echo', 'client', 'service')"
            )))
        }
    }
    Ok(args)
}

fn parse_echo(tokens: &[String], args: &mut Args) -> Result<(), CliExit> {
    let mut i = 0;
    while i < tokens.len() {
        let (flag, inline) = split_flag(&tokens[i]);
        match flag {
            "--bind" => args.bind = Some(take_value(tokens, &mut i, flag, inline)?),
            other => return Err(usage_error(format!("unrecognized arguments: {other}"))),
        }
        i += 1;
    }
    if args.bind.is_none() {
        return Err(usage_error("the following arguments are required: --bind"));
    }
    Ok(())
}

#[allow(clippy::cognitive_complexity)]
fn parse_client(tokens: &[String], args: &mut Args) -> Result<(), CliExit> {
    let mut i = 0;
    while i < tokens.len() {
        let (flag, inline) = split_flag(&tokens[i]);
        match flag {
            "--guard" => args.guard = Some(take_value(tokens, &mut i, flag, inline)?),
            "--middle" => args.middle = Some(take_value(tokens, &mut i, flag, inline)?),
            "--exit" => args.exit_addr = Some(take_value(tokens, &mut i, flag, inline)?),
            "--authority-quorum" => {
                let v = take_value(tokens, &mut i, flag, inline)?;
                args.authority_quorum = Some(parse_int(flag, &v)?);
            }
            "--authority" => args.authority = Some(take_value(tokens, &mut i, flag, inline)?),
            "--target" => args.target = Some(take_value(tokens, &mut i, flag, inline)?),
            "--socks-port" => {
                let v = take_value(tokens, &mut i, flag, inline)?;
                args.socks_port = Some(parse_int(flag, &v)?);
            }
            "--self-test" => args.self_test = Some(true),
            "--mtu" => {
                let v = take_value(tokens, &mut i, flag, inline)?;
                args.mtu = Some(parse_int(flag, &v)?);
            }
            "--timeout" => {
                let v = take_value(tokens, &mut i, flag, inline)?;
                args.timeout = Some(parse_float(flag, &v)?);
            }
            "--retries" => {
                let v = take_value(tokens, &mut i, flag, inline)?;
                args.retries = Some(parse_int(flag, &v)?);
            }
            "--no-congestion" => args.no_congestion = Some(true),
            "--allow-udp" => args.allow_udp = Some(true),
            "--isolate-by-destination" => args.isolate_by_destination = Some(true),
            "--no-isolate-by-destination" => args.isolate_by_destination = Some(false),
            "--require-pq" => args.require_pq = Some(true),
            "--connect-attempts" => {
                let v = take_value(tokens, &mut i, flag, inline)?;
                args.connect_attempts = Some(parse_int(flag, &v)?);
            }
            "--connect-timeout" => {
                let v = take_value(tokens, &mut i, flag, inline)?;
                args.connect_timeout = Some(parse_float(flag, &v)?);
            }
            "--keepalive-interval" => {
                let v = take_value(tokens, &mut i, flag, inline)?;
                args.keepalive_interval = Some(parse_float(flag, &v)?);
            }
            "--trust-guard" => args.trust_guard = Some(take_value(tokens, &mut i, flag, inline)?),
            "--trust-middle" => args.trust_middle = Some(take_value(tokens, &mut i, flag, inline)?),
            "--trust-exit" => args.trust_exit = Some(take_value(tokens, &mut i, flag, inline)?),
            "--trust-authority" => args.trust_authority = Some(take_value(tokens, &mut i, flag, inline)?),
            "--allow-unpinned-authority" => args.allow_unpinned_authority = Some(true),
            "--fetch-onion" => args.fetch_onion = Some(take_value(tokens, &mut i, flag, inline)?),
            "--fetch-onion-path" => args.fetch_onion_path = Some(take_value(tokens, &mut i, flag, inline)?),
            "--state-file" => args.state_file = Some(take_value(tokens, &mut i, flag, inline)?),
            "--min-guard-age" => args.min_guard_age = Some(parse_min_guard_age(&take_value(tokens, &mut i, flag, inline)?)?),
            "--client-auth-key-file" => {
                args.client_auth_key_file = Some(take_value(tokens, &mut i, flag, inline)?)
            }
            "--print-client-auth-key" => args.print_client_auth_key = true,
            other => return Err(usage_error(format!("unrecognized arguments: {other}"))),
        }
        i += 1;
    }
    Ok(())
}

/// `--min-guard-age SECONDS`: a finite, non-negative number of seconds.
fn parse_min_guard_age(value: &str) -> Result<f64, CliExit> {
    let secs = parse_float("--min-guard-age", value)?;
    if !secs.is_finite() || secs < 0.0 {
        return Err(usage_error(format!("argument --min-guard-age: expected a number of seconds >= 0, got '{value}'")));
    }
    Ok(secs)
}

fn parse_service(tokens: &[String], args: &mut Args) -> Result<(), CliExit> {
    let mut i = 0;
    while i < tokens.len() {
        let (flag, inline) = split_flag(&tokens[i]);
        match flag {
            "--hidden-service-port" => {
                args.hidden_service_port = Some(take_value(tokens, &mut i, flag, inline)?)
            }
            "--hidden-service-dir" => {
                args.hidden_service_dir = Some(take_value(tokens, &mut i, flag, inline)?)
            }
            "--identity-file" => args.identity_file = Some(take_value(tokens, &mut i, flag, inline)?),
            "--name" => args.name = Some(take_value(tokens, &mut i, flag, inline)?),
            "--guard" => args.guard = Some(take_value(tokens, &mut i, flag, inline)?),
            "--middle" => args.middle = Some(take_value(tokens, &mut i, flag, inline)?),
            "--authority-quorum" => {
                let v = take_value(tokens, &mut i, flag, inline)?;
                args.authority_quorum = Some(parse_int(flag, &v)?);
            }
            "--authority" => args.authority = Some(take_value(tokens, &mut i, flag, inline)?),
            "--trust-authority" => args.trust_authority = Some(take_value(tokens, &mut i, flag, inline)?),
            "--allow-unpinned-authority" => args.allow_unpinned_authority = Some(true),
            "--allow-short-rendezvous" => args.allow_short_rendezvous = Some(true),
            "--min-guard-age" => args.min_guard_age = Some(parse_min_guard_age(&take_value(tokens, &mut i, flag, inline)?)?),
            "--trust-guard" => args.trust_guard = Some(take_value(tokens, &mut i, flag, inline)?),
            "--trust-middle" => args.trust_middle = Some(take_value(tokens, &mut i, flag, inline)?),
            "--intro-count" => {
                let v = take_value(tokens, &mut i, flag, inline)?;
                args.intro_count = Some(parse_int(flag, &v)?);
            }
            "--publish-interval" => {
                let v = take_value(tokens, &mut i, flag, inline)?;
                args.publish_interval = Some(parse_float(flag, &v)?);
            }
            "--timeout" => {
                let v = take_value(tokens, &mut i, flag, inline)?;
                args.timeout = Some(parse_float(flag, &v)?);
            }
            "--retries" => {
                let v = take_value(tokens, &mut i, flag, inline)?;
                args.retries = Some(parse_int(flag, &v)?);
            }
            "--keepalive-interval" => {
                let v = take_value(tokens, &mut i, flag, inline)?;
                args.keepalive_interval = Some(parse_float(flag, &v)?);
            }
            "--client-auth-key" => {
                let v = take_value(tokens, &mut i, flag, inline)?;
                args.client_auth_key.get_or_insert_with(Vec::new).push(v);
            }
            other => return Err(usage_error(format!("unrecognized arguments: {other}"))),
        }
        i += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_echo_bind() {
        let args = parse_args(&toks(&["echo", "--bind", "0.0.0.0:9100"])).unwrap();
        assert_eq!(args.role, "echo");
        assert_eq!(args.bind.as_deref(), Some("0.0.0.0:9100"));
    }

    #[test]
    fn echo_requires_bind() {
        assert!(parse_args(&toks(&["echo"])).is_err());
    }

    #[test]
    fn parses_leading_config_before_role() {
        let args = parse_args(&toks(&["--config", "/tmp/alliumrc", "echo", "--bind", "0.0.0.0:9100"])).unwrap();
        assert_eq!(args.config.as_deref(), Some("/tmp/alliumrc"));
        assert_eq!(args.role, "echo");

        let args2 = parse_args(&toks(&["-f", "/tmp/alliumrc", "echo", "--bind", "0.0.0.0:9100"])).unwrap();
        assert_eq!(args2.config.as_deref(), Some("/tmp/alliumrc"));
    }

    #[test]
    fn supports_equals_form() {
        let args = parse_args(&toks(&["echo", "--bind=0.0.0.0:9100"])).unwrap();
        assert_eq!(args.bind.as_deref(), Some("0.0.0.0:9100"));
    }

    #[test]
    fn parses_client_flags_including_booleans_and_numbers() {
        let args = parse_args(&toks(&[
            "client",
            "--guard",
            "1.2.3.4:9001",
            "--middle",
            "1.2.3.4:9002",
            "--exit",
            "1.2.3.4:9003",
            "--socks-port",
            "9051",
            "--timeout",
            "2.5",
            "--self-test",
            "--isolate-by-destination",
        ]))
        .unwrap();
        assert_eq!(args.role, "client");
        assert_eq!(args.guard.as_deref(), Some("1.2.3.4:9001"));
        assert_eq!(args.middle.as_deref(), Some("1.2.3.4:9002"));
        assert_eq!(args.exit_addr.as_deref(), Some("1.2.3.4:9003"));
        assert_eq!(args.socks_port, Some(9051));
        assert_eq!(args.timeout, Some(2.5));
        assert_eq!(args.self_test, Some(true));
        assert_eq!(args.isolate_by_destination, Some(true));
        // Untouched flags stay None, matching argparse's default=None.
        assert_eq!(args.require_pq, None);
        assert_eq!(args.no_congestion, None);
    }

    /// Destination isolation defaults on (in `apply_config`), so the
    /// explicit opt-out has to parse to `Some(false)`, distinguishable
    /// from "not mentioned".
    #[test]
    fn no_isolate_by_destination_parses_to_explicit_false() {
        let args = parse_args(&toks(&["client", "--no-isolate-by-destination"])).unwrap();
        assert_eq!(args.isolate_by_destination, Some(false));
        let args = parse_args(&toks(&["client"])).unwrap();
        assert_eq!(args.isolate_by_destination, None);
    }

    #[test]
    fn client_print_auth_key_defaults_false_not_none() {
        let args = parse_args(&toks(&["client", "--guard", "a:1", "--middle", "a:2", "--exit", "a:3"])).unwrap();
        assert!(!args.print_client_auth_key);
    }

    #[test]
    fn rejects_bad_int_and_float_values() {
        assert!(parse_args(&toks(&["client", "--socks-port", "notanumber"])).is_err());
        assert!(parse_args(&toks(&["client", "--timeout", "notafloat"])).is_err());
    }

    #[test]
    fn parses_service_repeatable_client_auth_key() {
        let args = parse_args(&toks(&[
            "service",
            "--hidden-service-port",
            "127.0.0.1:8080",
            "--client-auth-key",
            "aa",
            "--client-auth-key",
            "bb",
        ]))
        .unwrap();
        assert_eq!(args.role, "service");
        assert_eq!(args.hidden_service_port.as_deref(), Some("127.0.0.1:8080"));
        assert_eq!(args.client_auth_key, Some(vec!["aa".to_string(), "bb".to_string()]));
    }

    #[test]
    fn allow_short_rendezvous_is_a_service_only_opt_in_off_by_default() {
        let off = parse_args(&toks(&["service", "--hidden-service-port", "127.0.0.1:8080"])).unwrap();
        assert_eq!(off.allow_short_rendezvous, None);
        let on = parse_args(&toks(&["service", "--hidden-service-port", "127.0.0.1:8080", "--allow-short-rendezvous"])).unwrap();
        assert_eq!(on.allow_short_rendezvous, Some(true));
        // it concerns the service's own circuits only, so the client does not take it
        assert!(parse_args(&toks(&["client", "--guard", "a:1", "--middle", "a:2", "--exit", "a:3", "--allow-short-rendezvous"])).is_err());
    }

    #[test]
    fn rejects_unknown_role_and_unknown_flag() {
        assert!(parse_args(&toks(&["bogus"])).is_err());
        assert!(parse_args(&toks(&["echo", "--nope", "x"])).is_err());
    }

    #[test]
    fn rejects_missing_role() {
        assert!(parse_args(&toks(&[])).is_err());
    }

    #[test]
    fn min_guard_age_is_a_client_and_service_option_that_takes_non_negative_seconds() {
        assert_eq!(parse_args(&toks(&["client"])).unwrap().min_guard_age, None, "default: the built-in six hours");
        for role in [&["client"][..], &["service", "--hidden-service-port", "127.0.0.1:8080"][..]] {
            let mut zero: Vec<&str> = role.to_vec();
            zero.extend(["--min-guard-age", "0"]);
            assert_eq!(parse_args(&toks(&zero)).unwrap().min_guard_age, Some(0.0));
            let mut inline: Vec<&str> = role.to_vec();
            inline.push("--min-guard-age=3600");
            assert_eq!(parse_args(&toks(&inline)).unwrap().min_guard_age, Some(3600.0));
            for bad in ["--min-guard-age=-5", "--min-guard-age=abc", "--min-guard-age=nan", "--min-guard-age=inf"] {
                let mut t: Vec<&str> = role.to_vec();
                t.push(bad);
                assert!(parse_args(&toks(&t)).is_err(), "{bad} must be rejected");
            }
        }
    }
}
