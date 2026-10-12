//! Real `torrc`-style config-file support for Allium's demo CLI.
//!
//! Full port of `alliumrc.py`. `allium::config` already gives the CLI a
//! `--config` file, but it borrows TOML's syntax (`[service]` tables and
//! all) rather than the one-directive-per-line shape everyone who has run
//! Tor already knows. This module adds that shape -- `Keyword value`
//! lines, `#` comments, no sections -- parsed into the exact same nested
//! [`crate::config::Table`] shape [`crate::config::load_config`] produces,
//! so every downstream helper (`relay_section`, `service_section`,
//! `resolve`, and `allium-cli`'s own `apply_config`) needs no changes to
//! accept it.
//!
//! **`AlliumrcError` "subclasses" `ConfigError`** the way Python's does (so
//! a caller that only catches `ConfigError` still catches this): rather
//! than a wrapper type, this is a plain type alias to
//! [`crate::config::ConfigError`] itself -- the same one-enum/one-type
//! alias pattern already used elsewhere in this crate (e.g.
//! `directory::SignatureInvalid`).
//!
//! Because an `alliumrc` has no sections, a directive's meaning depends on
//! which role is actually running -- `role` is passed in up front (chosen
//! by the CLI subcommand before this file is ever read) and used to pick
//! the one dict shape a directive should land in, and to reject a
//! directive that doesn't apply to the role actually being run.
//!
//! Dependency-free (no crate-touching code at all): pure string parsing
//! plus `std::fs`.

use crate::config::{ConfigError, Table, Value};
use std::collections::HashMap;

pub type AlliumrcError = ConfigError;

fn err(message: impl Into<String>) -> AlliumrcError {
    ConfigError { message: message.into() }
}

// ---------------------------------------------------------------------------
// Value coercion
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Str,
    Int,
    Float,
    Bool,
}

const TRUE_WORDS: [&str; 4] = ["1", "yes", "true", "on"];
const FALSE_WORDS: [&str; 4] = ["0", "no", "false", "off"];

fn coerce(value: &str, kind: Kind, where_: &str, keyword: &str) -> Result<Value, AlliumrcError> {
    match kind {
        Kind::Str => Ok(Value::String(value.to_string())),
        Kind::Bool => {
            let word = value.trim().to_lowercase();
            if TRUE_WORDS.contains(&word.as_str()) {
                Ok(Value::Bool(true))
            } else if FALSE_WORDS.contains(&word.as_str()) {
                Ok(Value::Bool(false))
            } else {
                Err(err(format!("{where_}: {keyword} expects a boolean (1/0, yes/no, true/false), got {value:?}")))
            }
        }
        Kind::Int => value
            .trim()
            .parse::<i64>()
            .map(Value::Integer)
            .map_err(|_| err(format!("{where_}: {keyword} expects an integer, got {value:?}"))),
        Kind::Float => value
            .trim()
            .parse::<f64>()
            .map(Value::Float)
            .map_err(|_| err(format!("{where_}: {keyword} expects a number, got {value:?}"))),
    }
}

/// Set `config["a"]["b"]["c"] = value` for `dotted == "a.b.c"`, creating
/// each intermediate table as needed -- exactly the shape
/// `crate::config`'s `Table`/`Value::Table` uses.
fn set_dotted(config: &mut Table, dotted: &str, value: Value) {
    let parts: Vec<&str> = dotted.split('.').collect();
    let mut node = config;
    for part in &parts[..parts.len() - 1] {
        let entry = node.entry((*part).to_string()).or_insert_with(|| Value::Table(Table::new()));
        if !matches!(entry, Value::Table(_)) {
            *entry = Value::Table(Table::new());
        }
        node = match entry {
            Value::Table(t) => t,
            _ => unreachable!(),
        };
    }
    node.insert(parts[parts.len() - 1].to_string(), value);
}

/// Record that `keyword` is about to set `dotted`, and reject it if a
/// *different* directive already claimed the same target path.
fn claim(owner: &mut HashMap<String, String>, dotted: &str, keyword: &str, where_: &str) -> Result<(), AlliumrcError> {
    if let Some(prior) = owner.get(dotted) {
        if prior != keyword {
            return Err(err(format!("{where_}: {keyword} conflicts with an earlier {prior} directive -- both would set {dotted}; remove one of them")));
        }
    }
    owner.insert(dotted.to_string(), keyword.to_string());
    Ok(())
}

// ---------------------------------------------------------------------------
// Directive registry
// ---------------------------------------------------------------------------

const RELAY_ROLES: [&str; 4] = ["guard", "middle", "exit", "authority"];
const PUBLISHING_RELAY_ROLES: [&str; 3] = ["guard", "middle", "exit"];

fn role_section(role: &str) -> Option<&'static str> {
    match role {
        "guard" | "middle" | "exit" | "authority" => Some("relay"),
        "client" => Some("client"),
        "service" => Some("service"),
        _ => None,
    }
}

struct Directive {
    rel_path: &'static str,
    kind: Kind,
    roles: &'static [&'static str],
}

fn directives() -> HashMap<&'static str, Directive> {
    let relay_and_service: &'static [&'static str] = &["guard", "middle", "exit", "authority", "service"];
    let relay_roles: &'static [&'static str] = &RELAY_ROLES;
    let publishing: &'static [&'static str] = &PUBLISHING_RELAY_ROLES;
    let publishing_plus_client_service: &'static [&'static str] = &["guard", "middle", "exit", "client", "service"];
    let client_service: &'static [&'static str] = &["client", "service"];
    let client_only: &'static [&'static str] = &["client"];
    let exit_only: &'static [&'static str] = &["exit"];
    let service_only: &'static [&'static str] = &["service"];

    let mut m: HashMap<&'static str, Directive> = HashMap::new();
    m.insert("nickname", Directive { rel_path: "name", kind: Kind::Str, roles: relay_and_service });
    m.insert("orport", Directive { rel_path: "bind", kind: Kind::Str, roles: relay_roles });
    m.insert("identityfile", Directive { rel_path: "identity_file", kind: Kind::Str, roles: relay_and_service });
    m.insert("idletimeout", Directive { rel_path: "idle_timeout", kind: Kind::Float, roles: relay_roles });
    m.insert("address", Directive { rel_path: "advertise", kind: Kind::Str, roles: publishing });
    m.insert("authorityfingerprint", Directive { rel_path: "trust.authority", kind: Kind::Str, roles: publishing });
    m.insert("allowunpinnedauthority", Directive { rel_path: "trust.allow_unpinned", kind: Kind::Bool, roles: publishing_plus_client_service });
    m.insert("publishperiod", Directive { rel_path: "publish_interval", kind: Kind::Float, roles: publishing });
    m.insert("relaybandwidthrate", Directive { rel_path: "bandwidth", kind: Kind::Str, roles: publishing });
    m.insert("myfamily", Directive { rel_path: "family", kind: Kind::Str, roles: publishing });
    m.insert("behindnat", Directive { rel_path: "behind_nat", kind: Kind::Bool, roles: publishing });
    m.insert("authority", Directive { rel_path: "authority", kind: Kind::Str, roles: publishing_plus_client_service });
    m.insert("trustauthority", Directive { rel_path: "trust.authority", kind: Kind::Str, roles: client_service });
    m.insert("authorityquorum", Directive { rel_path: "authority_quorum", kind: Kind::Int, roles: client_service });
    m.insert("allowports", Directive { rel_path: "exit_policy.allow_ports", kind: Kind::Str, roles: exit_only });
    m.insert("allowudpports", Directive { rel_path: "exit_policy.allow_udp_ports", kind: Kind::Str, roles: exit_only });
    m.insert("allowprivateaddresses", Directive { rel_path: "exit_policy.allow_private", kind: Kind::Bool, roles: exit_only });
    m.insert("allowamplificationports", Directive { rel_path: "exit_policy.allow_amplification_ports", kind: Kind::Bool, roles: exit_only });
    m.insert("guard", Directive { rel_path: "guard", kind: Kind::Str, roles: client_service });
    m.insert("middle", Directive { rel_path: "middle", kind: Kind::Str, roles: client_service });
    m.insert("exit", Directive { rel_path: "exit", kind: Kind::Str, roles: client_only });
    m.insert("socksport", Directive { rel_path: "socks_port", kind: Kind::Int, roles: client_only });
    m.insert("target", Directive { rel_path: "target", kind: Kind::Str, roles: client_only });
    m.insert("selftest", Directive { rel_path: "self_test", kind: Kind::Bool, roles: client_only });
    m.insert("mtu", Directive { rel_path: "mtu", kind: Kind::Int, roles: client_only });
    m.insert("usecongestioncontrol", Directive { rel_path: "congestion", kind: Kind::Bool, roles: client_only });
    m.insert("allowudp", Directive { rel_path: "allow_udp", kind: Kind::Bool, roles: client_only });
    m.insert("isolatebydestination", Directive { rel_path: "isolate_by_destination", kind: Kind::Bool, roles: client_only });
    m.insert("connectattempts", Directive { rel_path: "connect_attempts", kind: Kind::Int, roles: client_only });
    m.insert("requirepostquantum", Directive { rel_path: "require_pq", kind: Kind::Bool, roles: client_only });
    m.insert("connecttimeout", Directive { rel_path: "connect_timeout", kind: Kind::Float, roles: client_only });
    m.insert("trustguard", Directive { rel_path: "trust.guard", kind: Kind::Str, roles: client_service });
    m.insert("trustmiddle", Directive { rel_path: "trust.middle", kind: Kind::Str, roles: client_service });
    m.insert("trustexit", Directive { rel_path: "trust.exit", kind: Kind::Str, roles: client_only });
    m.insert("fetchonion", Directive { rel_path: "fetch_onion", kind: Kind::Str, roles: client_only });
    m.insert("fetchonionpath", Directive { rel_path: "fetch_onion_path", kind: Kind::Str, roles: client_only });
    m.insert("statefile", Directive { rel_path: "state_file", kind: Kind::Str, roles: client_only });
    m.insert("clientauthkeyfile", Directive { rel_path: "client_auth_key_file", kind: Kind::Str, roles: client_only });
    m.insert("timeout", Directive { rel_path: "timeout", kind: Kind::Float, roles: client_service });
    m.insert("retries", Directive { rel_path: "retries", kind: Kind::Int, roles: client_service });
    m.insert("keepaliveperiod", Directive { rel_path: "keepalive_interval", kind: Kind::Float, roles: client_service });
    m.insert("hiddenservicenumintroductionpoints", Directive { rel_path: "intro_count", kind: Kind::Int, roles: service_only });
    m.insert("rendpostperiod", Directive { rel_path: "publish_interval", kind: Kind::Float, roles: service_only });
    m
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Split one already-stripped, non-comment line into `(keyword, value)`.
/// `value` is everything after the first run of whitespace, trimmed, with
/// one matching pair of surrounding double quotes removed if present.
fn split_directive(line: &str) -> (String, String) {
    let mut parts = line.splitn(2, char::is_whitespace);
    let keyword = parts.next().unwrap_or("").to_string();
    let mut value = parts.next().unwrap_or("").trim().to_string();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value = value[1..value.len() - 1].to_string();
    }
    (keyword, value)
}

/// Strip a leading UTF-8 BOM, if present (mirrors Python's `"utf-8-sig"`).
fn strip_bom(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

/// Parse a flat `alliumrc`-style file into the [`Table`] shape
/// [`crate::config::load_config`] produces.
///
/// # Errors
/// A missing/unreadable file, an unknown directive, a directive that
/// doesn't apply to `role`, a malformed value, `HiddenServiceDir`/
/// `HiddenServicePort` given more than once, or two *different* directives
/// that would set the same underlying value.
pub fn parse_alliumrc(path: &str, role: &str) -> Result<Table, AlliumrcError> {
    let meta = std::fs::metadata(path);
    match &meta {
        Ok(m) if m.is_dir() => return Err(err(format!("{path} is a directory, not a config file"))),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(err(format!("config file not found: {path}"))),
        Err(e) => return Err(err(format!("could not read {path}: {e}"))),
    }
    let bytes = std::fs::read(path).map_err(|e| err(format!("could not read {path}: {e}")))?;
    let text = String::from_utf8(bytes).map_err(|e| err(format!("{path} is not a text file: {e}")))?;
    let text = strip_bom(&text);

    let mut config: Table = Table::new();
    let section = role_section(role);
    let mut seen_hidden_service_dir = false;
    let mut seen_hidden_service_port = false;
    let mut owner: HashMap<String, String> = HashMap::new();
    let directives = directives();

    for (idx, raw_line) in text.lines().enumerate() {
        let lineno = idx + 1;
        let stripped = raw_line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        let (keyword, value) = split_directive(stripped);
        let where_ = format!("{path}:{lineno}");
        let canonical = keyword.to_lowercase();

        if canonical == "role" {
            config.insert("role".to_string(), Value::String(value));
            continue;
        }

        if canonical == "hiddenservicedir" {
            if role != "service" {
                return Err(err(format!("{where_}: HiddenServiceDir only applies to the 'service' role, not {role:?}")));
            }
            if seen_hidden_service_dir {
                return Err(err(format!(
                    "{where_}: HiddenServiceDir given more than once -- an Allium alliumrc describes exactly one hidden service; run a separate 'service' process, each with its own alliumrc, for another one"
                )));
            }
            seen_hidden_service_dir = true;
            let hs_dir = expand_user(&value);
            if hs_dir.is_empty() {
                return Err(err(format!("{where_}: HiddenServiceDir needs a directory path")));
            }
            set_dotted(&mut config, "service.hidden_service_dir", Value::String(hs_dir));
            continue;
        }

        if canonical == "hiddenserviceport" {
            if role != "service" {
                return Err(err(format!("{where_}: HiddenServicePort only applies to the 'service' role, not {role:?}")));
            }
            if seen_hidden_service_port {
                return Err(err(format!(
                    "{where_}: HiddenServicePort given more than once -- unlike real Tor's per-virtual-port mappings, an Allium service forwards to exactly one local address"
                )));
            }
            seen_hidden_service_port = true;
            let tokens: Vec<&str> = value.split_whitespace().collect();
            let target = match tokens.len() {
                1 => tokens[0].to_string(),
                2 => tokens[1].to_string(),
                _ => {
                    return Err(err(format!(
                        "{where_}: HiddenServicePort takes 'TARGET' or 'VIRTPORT TARGET' (e.g. '80 127.0.0.1:8080'), got {value:?}"
                    )));
                }
            };
            if target.is_empty() {
                return Err(err(format!("{where_}: HiddenServicePort needs a target host:port")));
            }
            set_dotted(&mut config, "service.hidden_service_port", Value::String(target));
            continue;
        }

        if canonical == "clientauthorizedkey" {
            if role != "service" {
                return Err(err(format!("{where_}: ClientAuthorizedKey only applies to the 'service' role, not {role:?}")));
            }
            if value.is_empty() {
                return Err(err(format!("{where_}: ClientAuthorizedKey needs a hex X25519 public key")));
            }
            let service = config.entry("service".to_string()).or_insert_with(|| Value::Table(Table::new()));
            if !matches!(service, Value::Table(_)) {
                *service = Value::Table(Table::new());
            }
            if let Value::Table(t) = service {
                let list = t.entry("client_auth_keys".to_string()).or_insert_with(|| Value::Array(Vec::new()));
                if let Value::Array(a) = list {
                    a.push(Value::String(value));
                }
            }
            continue;
        }

        if canonical == "datadirectory" {
            if !RELAY_ROLES.contains(&role) {
                return Err(err(format!("{where_}: DataDirectory only applies to a relay role (guard/middle/exit/authority), not {role:?}")));
            }
            let data_dir = expand_user(&value);
            if data_dir.is_empty() {
                return Err(err(format!("{where_}: DataDirectory needs a directory path")));
            }
            claim(&mut owner, "relay.identity_file", "DataDirectory", &where_)?;
            let identity_path = [data_dir.as_str(), "keys", "ed25519_master_id_secret_key"].join(std::path::MAIN_SEPARATOR_STR);
            set_dotted(&mut config, "relay.identity_file", Value::String(identity_path));
            continue;
        }

        let Some(entry) = directives.get(canonical.as_str()) else {
            return Err(err(format!("{where_}: unknown directive {keyword:?}")));
        };
        if !entry.roles.contains(&role) {
            return Err(err(format!("{where_}: {keyword} does not apply to the {role:?} role")));
        }
        let Some(section) = section else {
            return Err(err(format!("{where_}: {keyword} cannot be used with role {role:?}")));
        };
        let coerced = coerce(&value, entry.kind, &where_, &keyword)?;
        let dotted = format!("{section}.{}", entry.rel_path);
        claim(&mut owner, &dotted, &keyword, &where_)?;
        set_dotted(&mut config, &dotted, coerced);
    }

    Ok(config)
}

/// A small `~`/`~user`-free `os.path.expanduser` equivalent: only handles
/// the common `~/...` and bare `~` cases (this crate has no user-database
/// lookup available), which is everything `examples/alliumrc` and this
/// module's own tests exercise.
fn expand_user(path: &str) -> String {
    if path == "~" || path.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            let home = home.to_string_lossy().to_string();
            if path == "~" {
                return home;
            }
            return format!("{home}{}", &path[1..]);
        }
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_alliumrc(text: &str) -> String {
        let dir = std::env::temp_dir();
        let name = format!("alliumrc_test_{}_{}.tmp", std::process::id(), rand_suffix());
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(text.as_bytes()).unwrap();
        path.to_string_lossy().to_string()
    }

    fn rand_suffix() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
    }

    fn get<'a>(t: &'a Table, path: &str) -> Option<&'a Value> {
        let mut node = t;
        let parts: Vec<&str> = path.split('.').collect();
        for part in &parts[..parts.len() - 1] {
            node = match node.get(*part) {
                Some(Value::Table(t)) => t,
                _ => return None,
            };
        }
        node.get(parts[parts.len() - 1])
    }

    fn s(v: Option<&Value>) -> &str {
        match v.unwrap() {
            Value::String(s) => s,
            _ => panic!("not a string"),
        }
    }
    fn f(v: Option<&Value>) -> f64 {
        match v.unwrap() {
            Value::Float(f) => *f,
            _ => panic!("not a float"),
        }
    }
    fn i(v: Option<&Value>) -> i64 {
        match v.unwrap() {
            Value::Integer(i) => *i,
            _ => panic!("not an int"),
        }
    }
    fn b(v: Option<&Value>) -> bool {
        match v.unwrap() {
            Value::Bool(b) => *b,
            _ => panic!("not a bool"),
        }
    }

    #[test]
    fn test_missing_file_raises() {
        let e = parse_alliumrc("/nonexistent/path/does-not-exist", "guard").unwrap_err();
        assert!(e.message.contains("not found"));
    }

    #[test]
    fn test_directory_given_instead_of_file_raises() {
        let dir = std::env::temp_dir();
        assert!(parse_alliumrc(dir.to_str().unwrap(), "guard").is_err());
    }

    #[test]
    fn test_blank_lines_and_comments_are_ignored() {
        let path = write_alliumrc("\n# a comment\n   \nORPort 0.0.0.0:9001\n# trailing\n");
        let data = parse_alliumrc(&path, "guard").unwrap();
        assert_eq!(s(get(&data, "relay.bind")), "0.0.0.0:9001");
    }

    #[test]
    fn test_directive_names_are_case_insensitive() {
        let path = write_alliumrc("orport 0.0.0.0:9001\nNICKNAME guard9\n");
        let data = parse_alliumrc(&path, "guard").unwrap();
        assert_eq!(s(get(&data, "relay.bind")), "0.0.0.0:9001");
        assert_eq!(s(get(&data, "relay.name")), "guard9");
    }

    #[test]
    fn test_quoted_value_has_quotes_stripped() {
        let path = write_alliumrc("Nickname \"guard with spaces\"\nORPort 0.0.0.0:9001\n");
        let data = parse_alliumrc(&path, "guard").unwrap();
        assert_eq!(s(get(&data, "relay.name")), "guard with spaces");
    }

    #[test]
    fn test_unknown_directive_raises_with_line_number() {
        let path = write_alliumrc("ORPort 0.0.0.0:9001\nNotARealDirective foo\n");
        let e = parse_alliumrc(&path, "guard").unwrap_err();
        assert!(e.message.contains(":2:"));
        assert!(e.message.contains("NotARealDirective"));
    }

    #[test]
    fn test_role_label_is_purely_informational() {
        let path = write_alliumrc("Role service\nORPort 0.0.0.0:9001\n");
        let data = parse_alliumrc(&path, "guard").unwrap();
        assert_eq!(s(data.get("role")), "service");
        assert_eq!(s(get(&data, "relay.bind")), "0.0.0.0:9001");
    }

    #[test]
    fn test_directive_not_valid_for_current_role_raises() {
        let path = write_alliumrc("ORPort 0.0.0.0:9001\nGuard 127.0.0.1:9001\n");
        let e = parse_alliumrc(&path, "guard").unwrap_err();
        assert!(e.message.contains("Guard"));
        assert!(e.message.contains("guard"));
    }

    #[test]
    fn test_authority_directive_invalid_for_authority_role_itself() {
        let path = write_alliumrc("ORPort 0.0.0.0:9030\nAuthority 1.2.3.4:9030\n");
        assert!(parse_alliumrc(&path, "authority").is_err());
    }

    #[test]
    fn test_exit_only_directive_invalid_for_guard() {
        let path = write_alliumrc("ORPort 0.0.0.0:9001\nAllowPorts 80,443\n");
        assert!(parse_alliumrc(&path, "guard").is_err());
    }

    #[test]
    fn test_datadirectory_only_valid_for_relay_roles() {
        let path = write_alliumrc("Guard 1.2.3.4:1\nMiddle 1.2.3.4:2\nDataDirectory ~/x\n");
        assert!(parse_alliumrc(&path, "client").is_err());
    }

    #[test]
    fn test_full_relay_config() {
        let path = write_alliumrc(
            "Nickname exit9\n\
             ORPort 0.0.0.0:9003\n\
             IdentityFile ~/.allium/exit9.key\n\
             IdleTimeout 120\n\
             Authority 10.10.10.2:9030\n\
             Address 203.0.113.5:9003\n\
             AuthorityFingerprint deadbeef\n\
             PublishPeriod 600\n\
             AllowPorts 80,443,8080\n\
             AllowUDPPorts 53\n\
             AllowPrivateAddresses yes\n\
             AllowAmplificationPorts no\n",
        );
        let data = parse_alliumrc(&path, "exit").unwrap();
        assert_eq!(s(get(&data, "relay.name")), "exit9");
        assert_eq!(s(get(&data, "relay.bind")), "0.0.0.0:9003");
        assert_eq!(s(get(&data, "relay.identity_file")), "~/.allium/exit9.key");
        assert_eq!(f(get(&data, "relay.idle_timeout")), 120.0);
        assert_eq!(s(get(&data, "relay.authority")), "10.10.10.2:9030");
        assert_eq!(s(get(&data, "relay.advertise")), "203.0.113.5:9003");
        assert_eq!(s(get(&data, "relay.trust.authority")), "deadbeef");
        assert_eq!(f(get(&data, "relay.publish_interval")), 600.0);
        assert_eq!(s(get(&data, "relay.exit_policy.allow_ports")), "80,443,8080");
        assert_eq!(s(get(&data, "relay.exit_policy.allow_udp_ports")), "53");
        assert!(b(get(&data, "relay.exit_policy.allow_private")));
        assert!(!b(get(&data, "relay.exit_policy.allow_amplification_ports")));
    }

    #[test]
    fn test_datadirectory_derives_identity_file_like_real_tor() {
        let path = write_alliumrc("ORPort 0.0.0.0:9001\nDataDirectory ~/.allium/guard1\n");
        let data = parse_alliumrc(&path, "guard").unwrap();
        let expected = [expand_user("~/.allium/guard1").as_str(), "keys", "ed25519_master_id_secret_key"].join(std::path::MAIN_SEPARATOR_STR);
        assert_eq!(s(get(&data, "relay.identity_file")), expected);
    }

    #[test]
    fn test_bad_bool_value_raises() {
        let path = write_alliumrc("ORPort 0.0.0.0:9003\nAllowPrivateAddresses maybe\n");
        assert!(parse_alliumrc(&path, "exit").is_err());
    }

    #[test]
    fn test_bad_float_value_raises() {
        let path = write_alliumrc("ORPort 0.0.0.0:9001\nIdleTimeout soon\n");
        assert!(parse_alliumrc(&path, "guard").is_err());
    }

    #[test]
    fn test_identityfile_then_datadirectory_conflict_raises() {
        let path = write_alliumrc("ORPort 0.0.0.0:9003\nIdentityFile ~/.allium/exit9.key\nDataDirectory ~/.allium/exit9\n");
        let e = parse_alliumrc(&path, "exit").unwrap_err();
        assert!(e.message.contains("conflicts"));
    }

    #[test]
    fn test_datadirectory_then_identityfile_conflict_raises() {
        let path = write_alliumrc("ORPort 0.0.0.0:9003\nDataDirectory ~/.allium/exit9\nIdentityFile ~/.allium/exit9.key\n");
        let e = parse_alliumrc(&path, "exit").unwrap_err();
        assert!(e.message.contains("conflicts"));
    }

    #[test]
    fn test_bom_prefixed_file_parses() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("alliumrc_bom_{}.tmp", rand_suffix()));
        let mut bytes = vec![0xEFu8, 0xBB, 0xBF];
        bytes.extend_from_slice(b"ORPort 0.0.0.0:9003\nNickname exit9\n");
        std::fs::write(&path, bytes).unwrap();
        let data = parse_alliumrc(path.to_str().unwrap(), "exit").unwrap();
        assert_eq!(s(get(&data, "relay.bind")), "0.0.0.0:9003");
        assert_eq!(s(get(&data, "relay.name")), "exit9");
    }

    #[test]
    fn test_allowunpinnedauthority_directive_parses_for_a_relay_role() {
        let path = write_alliumrc("ORPort 0.0.0.0:9003\nAuthority 10.10.10.2:9030\nAllowUnpinnedAuthority yes\n");
        let data = parse_alliumrc(&path, "exit").unwrap();
        assert!(b(get(&data, "relay.trust.allow_unpinned")));
    }

    #[test]
    fn test_allowunpinnedauthority_directive_accepts_boolean_words() {
        for (word, expected) in [("yes", true), ("no", false), ("1", true), ("0", false)] {
            let path = write_alliumrc(&format!("ORPort 0.0.0.0:9003\nAllowUnpinnedAuthority {word}\n"));
            let data = parse_alliumrc(&path, "exit").unwrap();
            assert_eq!(b(get(&data, "relay.trust.allow_unpinned")), expected);
        }
    }

    #[test]
    fn test_full_client_config() {
        let path = write_alliumrc(
            "Guard 127.0.0.1:9001\nMiddle 10.0.0.2:9002\nExit 10.0.0.2:9003\n\
             Target 10.0.0.2:9100\nSocksPort 9060\nUseCongestionControl no\n\
             AllowUDP yes\nKeepAlivePeriod 45\nTrustGuard aabbcc\n\
             FetchOnion abc.allium\nFetchOnionPath /index.html\n",
        );
        let data = parse_alliumrc(&path, "client").unwrap();
        assert_eq!(s(get(&data, "client.guard")), "127.0.0.1:9001");
        assert_eq!(s(get(&data, "client.middle")), "10.0.0.2:9002");
        assert_eq!(s(get(&data, "client.exit")), "10.0.0.2:9003");
        assert_eq!(s(get(&data, "client.target")), "10.0.0.2:9100");
        assert_eq!(i(get(&data, "client.socks_port")), 9060);
        assert!(!b(get(&data, "client.congestion")));
        assert!(b(get(&data, "client.allow_udp")));
        assert_eq!(f(get(&data, "client.keepalive_interval")), 45.0);
        assert_eq!(s(get(&data, "client.trust.guard")), "aabbcc");
        assert_eq!(s(get(&data, "client.fetch_onion")), "abc.allium");
        assert_eq!(s(get(&data, "client.fetch_onion_path")), "/index.html");
    }

    #[test]
    fn test_state_file_directive() {
        let path = write_alliumrc("Authority 10.0.0.9:9030\nStateFile ~/.allium/client-state.json\n");
        let data = parse_alliumrc(&path, "client").unwrap();
        assert_eq!(s(get(&data, "client.state_file")), "~/.allium/client-state.json");
    }

    #[test]
    fn test_state_file_rejected_outside_client_role() {
        let path = write_alliumrc("ORPort 0.0.0.0:9001\nStateFile /tmp/state.json\n");
        assert!(parse_alliumrc(&path, "guard").is_err());
    }

    #[test]
    fn test_client_auth_key_file_directive() {
        let path = write_alliumrc("Authority 10.0.0.9:9030\nClientAuthKeyFile ~/.allium/client-auth.key\n");
        let data = parse_alliumrc(&path, "client").unwrap();
        assert_eq!(s(get(&data, "client.client_auth_key_file")), "~/.allium/client-auth.key");
    }

    #[test]
    fn test_client_auth_key_file_rejected_outside_client_role() {
        let path = write_alliumrc("ORPort 0.0.0.0:9001\nClientAuthKeyFile /tmp/auth.key\n");
        assert!(parse_alliumrc(&path, "guard").is_err());
    }

    #[test]
    fn test_hidden_service_dir_and_port_single_token() {
        let path = write_alliumrc("HiddenServiceDir ~/.allium/svc1\nHiddenServicePort 127.0.0.1:8080\nAuthority 10.10.10.2:9030\n");
        let data = parse_alliumrc(&path, "service").unwrap();
        assert_eq!(s(get(&data, "service.hidden_service_dir")), expand_user("~/.allium/svc1"));
        assert_eq!(s(get(&data, "service.hidden_service_port")), "127.0.0.1:8080");
        assert_eq!(s(get(&data, "service.authority")), "10.10.10.2:9030");
        assert!(get(&data, "service.identity_file").is_none());
    }

    #[test]
    fn test_hidden_service_port_two_token_torstyle_uses_target_only() {
        let path = write_alliumrc("HiddenServiceDir ~/.allium/svc1\nHiddenServicePort 80 127.0.0.1:8080\nAuthority 10.10.10.2:9030\n");
        let data = parse_alliumrc(&path, "service").unwrap();
        assert_eq!(s(get(&data, "service.hidden_service_port")), "127.0.0.1:8080");
    }

    #[test]
    fn test_hidden_service_port_too_many_tokens_raises() {
        let path = write_alliumrc("HiddenServicePort 80 127.0.0.1:8080 extra\n");
        assert!(parse_alliumrc(&path, "service").is_err());
    }

    #[test]
    fn test_duplicate_hidden_service_dir_raises() {
        let path = write_alliumrc("HiddenServiceDir ~/.allium/svc1\nHiddenServiceDir ~/.allium/svc2\n");
        let e = parse_alliumrc(&path, "service").unwrap_err();
        assert!(e.message.contains("more than once"));
    }

    #[test]
    fn test_duplicate_hidden_service_port_raises() {
        let path = write_alliumrc("HiddenServicePort 127.0.0.1:8080\nHiddenServicePort 127.0.0.1:9090\n");
        assert!(parse_alliumrc(&path, "service").is_err());
    }

    #[test]
    fn test_hidden_service_directives_rejected_outside_service_role() {
        let path = write_alliumrc("ORPort 0.0.0.0:9001\nHiddenServiceDir ~/.allium/x\n");
        assert!(parse_alliumrc(&path, "guard").is_err());
        let path = write_alliumrc("ORPort 0.0.0.0:9001\nHiddenServicePort 127.0.0.1:80\n");
        assert!(parse_alliumrc(&path, "guard").is_err());
    }

    #[test]
    fn test_client_authorized_key_accumulates_a_list() {
        let path = write_alliumrc(
            "HiddenServiceDir ~/.allium/svc1\nHiddenServicePort 127.0.0.1:8080\nAuthority 10.10.10.2:9030\n\
             ClientAuthorizedKey aa11\nClientAuthorizedKey bb22\nClientAuthorizedKey cc33\n",
        );
        let data = parse_alliumrc(&path, "service").unwrap();
        match get(&data, "service.client_auth_keys").unwrap() {
            Value::Array(a) => {
                let strs: Vec<&str> = a
                    .iter()
                    .map(|v| match v {
                        Value::String(s) => s.as_str(),
                        _ => panic!("not a string"),
                    })
                    .collect();
                assert_eq!(strs, vec!["aa11", "bb22", "cc33"]);
            }
            _ => panic!("not an array"),
        }
    }

    #[test]
    fn test_client_authorized_key_needs_a_value() {
        let path = write_alliumrc("ClientAuthorizedKey \n");
        assert!(parse_alliumrc(&path, "service").is_err());
    }

    #[test]
    fn test_client_authorized_key_rejected_outside_service_role() {
        let path = write_alliumrc("ORPort 0.0.0.0:9001\nClientAuthorizedKey aa11\n");
        assert!(parse_alliumrc(&path, "guard").is_err());
    }

    #[test]
    fn test_full_service_config() {
        let path = write_alliumrc(
            "HiddenServiceDir ~/.allium/svc1\nHiddenServicePort 80 127.0.0.1:8080\nNickname myservice\n\
             Guard 127.0.0.1:9001\nMiddle 10.0.0.2:9002\nAuthority 10.10.10.2:9030\n\
             TrustAuthority deadbeef\nTrustGuard cafef00d\nTrustMiddle f00dcafe\n\
             HiddenServiceNumIntroductionPoints 5\nRendPostPeriod 900\n\
             Timeout 3.5\nRetries 4\nKeepAlivePeriod 30\n",
        );
        let data = parse_alliumrc(&path, "service").unwrap();
        assert_eq!(s(get(&data, "service.hidden_service_dir")), expand_user("~/.allium/svc1"));
        assert_eq!(s(get(&data, "service.hidden_service_port")), "127.0.0.1:8080");
        assert_eq!(s(get(&data, "service.name")), "myservice");
        assert_eq!(s(get(&data, "service.guard")), "127.0.0.1:9001");
        assert_eq!(s(get(&data, "service.middle")), "10.0.0.2:9002");
        assert_eq!(s(get(&data, "service.authority")), "10.10.10.2:9030");
        assert_eq!(s(get(&data, "service.trust.authority")), "deadbeef");
        assert_eq!(s(get(&data, "service.trust.guard")), "cafef00d");
        assert_eq!(s(get(&data, "service.trust.middle")), "f00dcafe");
        assert_eq!(i(get(&data, "service.intro_count")), 5);
        assert_eq!(f(get(&data, "service.publish_interval")), 900.0);
        assert_eq!(f(get(&data, "service.timeout")), 3.5);
        assert_eq!(i(get(&data, "service.retries")), 4);
        assert_eq!(f(get(&data, "service.keepalive_interval")), 30.0);
    }

    #[test]
    fn test_alliumrcerror_is_a_configerror() {
        // AlliumrcError is a type alias to ConfigError in this port, so this
        // is trivially true -- kept as a test for parity with Python's
        // subclass check and to document the choice.
        fn accepts_config_error(_e: ConfigError) {}
        let e = parse_alliumrc("/nonexistent", "guard").unwrap_err();
        accepts_config_error(e);
    }
}
