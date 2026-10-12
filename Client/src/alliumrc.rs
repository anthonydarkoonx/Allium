//! Real `torrc`-style config-file support for Allium's demo CLI, Rust port
//! of `alliumrc.py` (424 Python lines).
//!
//! [`crate::config`] already gives `allium_cli` a `--config` file so an
//! operator doesn't have to retype every `--flag` on every launch -- but
//! it borrowed TOML's syntax (`[service]` tables and all) rather than the
//! one-directive-per-line shape everyone who has ever run Tor already
//! knows. That shape is what this module adds: a genuine, flat
//! `alliumrc` -- `Keyword value` lines, `#` comments, no sections --
//! parsed into the exact same nested [`crate::config::Table`] shape
//! [`crate::config::load_config`] produces, so every downstream helper
//! ([`crate::config::service_section`], [`crate::config::resolve`], and
//! `allium_cli`'s config-application step) needs **no changes at all** to
//! accept it. `allium_cli` picks whichever of the two this module or
//! [`crate::config`] parses based on the file's extension.
//!
//! This is deliberately the easy on-ramp for hidden services in
//! particular: the two directives that matter most, `HiddenServiceDir`
//! and `HiddenServicePort`, are spelled exactly as they are in a real Tor
//! `torrc`, and `HiddenServiceDir` gets the same treatment real Tor gives
//! it -- a directory that holds the service's key (named
//! `hs_ed25519_secret_key`, Tor's own filename) and, once the address is
//! known, a `hostname` file containing it.
//!
//! Because an `alliumrc` has no sections, a directive's meaning depends on
//! which role is actually running -- exactly like real Tor, where the same
//! option namespace is shared by every mode the binary can run in. Unlike
//! real Tor (one process, many simultaneous roles and many
//! `HiddenServiceDir` blocks in one file), Allium runs one role per
//! process, chosen by the subcommand, *before* this file is ever read --
//! so `role` is known up front and is used here to pick the one dict
//! shape a directive should land in, and to reject a directive that
//! doesn't apply to the role actually being run (`Guard` in a `guard`
//! role's own alliumrc, say) the same way real Tor would reject an option
//! that doesn't apply to its current configuration.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use crate::config::{ConfigError, Table, Value};

/// An alliumrc file was missing, unreadable, malformed, or had a bad
/// directive.
///
/// Python subclasses `ConfigError` so `allium_cli`'s config-application
/// step -- which already turns a `ConfigError` into one clean exit
/// message -- needs no separate branch to also handle an
/// alliumrc-specific mistake; [`From<AlliumrcError> for ConfigError`] is
/// this crate's equivalent of that subclass relationship.
#[derive(Debug, Clone, PartialEq)]
pub struct AlliumrcError(pub String);

impl fmt::Display for AlliumrcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for AlliumrcError {}

impl From<AlliumrcError> for ConfigError {
    fn from(e: AlliumrcError) -> ConfigError {
        ConfigError(e.0)
    }
}

fn err(msg: impl Into<String>) -> AlliumrcError {
    AlliumrcError(msg.into())
}

// ---------------------------------------------------------------------
// Value coercion
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Str,
    Int,
    Float,
    Bool,
}

fn coerce(value: &str, kind: Kind, where_: &str, keyword: &str) -> Result<Value, AlliumrcError> {
    match kind {
        Kind::Str => Ok(Value::Str(value.to_string())),
        Kind::Bool => {
            let word = value.trim().to_lowercase();
            if matches!(word.as_str(), "1" | "yes" | "true" | "on") {
                Ok(Value::Bool(true))
            } else if matches!(word.as_str(), "0" | "no" | "false" | "off") {
                Ok(Value::Bool(false))
            } else {
                Err(err(format!(
                    "{where_}: {keyword} expects a boolean (1/0, yes/no, true/false), got {value:?}"
                )))
            }
        }
        Kind::Int => value.trim().parse::<i64>().map(Value::Int).map_err(|_| {
            err(format!("{where_}: {keyword} expects an integer, got {value:?}"))
        }),
        Kind::Float => value.trim().parse::<f64>().map(Value::Float).map_err(|_| {
            err(format!("{where_}: {keyword} expects a number, got {value:?}"))
        }),
    }
}

/// Set `config["a"]["b"]["c"] = value` for `dotted == "a.b.c"`, creating
/// each intermediate table with plain [`Table`]s -- exactly the shape
/// [`crate::config`]'s section helpers expect. Unlike the strict TOML
/// reader's own path-setter, this one simply overwrites (matching
/// Python's `_set`/`dict.setdefault`) -- rejecting a conflicting
/// *different* directive is [`claim`]'s job, not this function's.
fn set(config: &mut Table, dotted: &str, value: Value) {
    crate::config::set_path(config, dotted, value);
}

/// Record that `keyword` is about to set `dotted`, and reject it if a
/// *different* directive already claimed the same target path.
///
/// Without this, two directives that happen to write the same dotted path
/// (e.g. `IdentityFile` and `DataDirectory` both write
/// `relay.identity_file`) silently let whichever one appears later in the
/// file win, with no warning -- for an identity-bearing path that's a
/// "the config file did something other than what it visually says"
/// trap: an operator who pins `IdentityFile` and later adds
/// `DataDirectory` (or vice versa) would have their explicit key path
/// silently discarded.
fn claim(owner: &mut BTreeMap<String, String>, dotted: &str, keyword: &str, where_: &str) -> Result<(), AlliumrcError> {
    if let Some(prior) = owner.get(dotted) {
        if prior != keyword {
            return Err(err(format!(
                "{where_}: {keyword} conflicts with an earlier {prior} directive -- \
                 both would set {dotted}; remove one of them"
            )));
        }
    }
    owner.insert(dotted.to_string(), keyword.to_string());
    Ok(())
}

// ---------------------------------------------------------------------
// Directive registry
// ---------------------------------------------------------------------
//
// canonical (lowercased) directive name -> (dotted path *within its
// role's top-level section*, value kind, roles it may be used with).
//
// `role` decides both which top-level section a directive's dotted path
// is rooted at (see `role_section`) and whether the directive is even
// valid -- e.g. `Guard`/`Middle` (a *manual entry hop*) only make sense
// for `client` and `service`, which build their own circuits; a relay
// never picks its own entry hop, so using them in a `guard`/`middle`/
// `exit` alliumrc is rejected the same way an unknown directive would be.

/// Roles that share `allium_cli`'s relay-common flags (bind/name/
/// identity/idle-timeout) -- every relay-shaped role, authority included.
const RELAY_ROLES: &[&str] = &["guard", "middle", "exit", "authority"];

/// The subset of [`RELAY_ROLES`] that also publishes (advertise/
/// trust-authority/publish-interval) -- authority does not, since it has
/// nothing to publish to itself.
const PUBLISHING_RELAY_ROLES: &[&str] = &["guard", "middle", "exit"];

const RELAY_PLUS_SERVICE: &[&str] = &["guard", "middle", "exit", "authority", "service"];
const PUBLISHING_PLUS_CLIENT_SERVICE: &[&str] = &["guard", "middle", "exit", "client", "service"];
const CLIENT_SERVICE: &[&str] = &["client", "service"];
const CLIENT_ONLY: &[&str] = &["client"];
const EXIT_ONLY: &[&str] = &["exit"];
const SERVICE_ONLY: &[&str] = &["service"];

struct Directive {
    canonical: &'static str,
    rel_path: &'static str,
    kind: Kind,
    roles: &'static [&'static str],
}

const DIRECTIVES: &[Directive] = &[
    // --- relay roles: guard, middle, exit, authority -------------------
    Directive { canonical: "nickname", rel_path: "name", kind: Kind::Str, roles: RELAY_PLUS_SERVICE },
    Directive { canonical: "orport", rel_path: "bind", kind: Kind::Str, roles: RELAY_ROLES },
    Directive { canonical: "identityfile", rel_path: "identity_file", kind: Kind::Str, roles: RELAY_PLUS_SERVICE },
    Directive { canonical: "idletimeout", rel_path: "idle_timeout", kind: Kind::Float, roles: RELAY_ROLES },
    Directive { canonical: "address", rel_path: "advertise", kind: Kind::Str, roles: PUBLISHING_RELAY_ROLES },
    Directive {
        canonical: "authorityfingerprint",
        rel_path: "trust.authority",
        kind: Kind::Str,
        roles: PUBLISHING_RELAY_ROLES,
    },
    Directive {
        canonical: "allowunpinnedauthority",
        rel_path: "trust.allow_unpinned",
        kind: Kind::Bool,
        roles: PUBLISHING_PLUS_CLIENT_SERVICE,
    },
    Directive { canonical: "publishperiod", rel_path: "publish_interval", kind: Kind::Float, roles: PUBLISHING_RELAY_ROLES },
    Directive { canonical: "relaybandwidthrate", rel_path: "bandwidth", kind: Kind::Str, roles: PUBLISHING_RELAY_ROLES },
    Directive { canonical: "myfamily", rel_path: "family", kind: Kind::Str, roles: PUBLISHING_RELAY_ROLES },
    Directive { canonical: "behindnat", rel_path: "behind_nat", kind: Kind::Bool, roles: PUBLISHING_RELAY_ROLES },
    // a directory authority address, shared by every role that publishes
    // to or fetches from one -- deliberately *not* named `DirAuthority`
    // (real Tor's directive of that name has a completely different,
    // multi-field shape) so nobody expects that syntax to work here.
    Directive { canonical: "authority", rel_path: "authority", kind: Kind::Str, roles: PUBLISHING_PLUS_CLIENT_SERVICE },
    Directive { canonical: "trustauthority", rel_path: "trust.authority", kind: Kind::Str, roles: CLIENT_SERVICE },
    Directive { canonical: "authorityquorum", rel_path: "authority_quorum", kind: Kind::Int, roles: CLIENT_SERVICE },
    // --- exit-only exit-policy knobs ------------------------------------
    Directive { canonical: "allowports", rel_path: "exit_policy.allow_ports", kind: Kind::Str, roles: EXIT_ONLY },
    Directive { canonical: "allowudpports", rel_path: "exit_policy.allow_udp_ports", kind: Kind::Str, roles: EXIT_ONLY },
    Directive {
        canonical: "allowprivateaddresses",
        rel_path: "exit_policy.allow_private",
        kind: Kind::Bool,
        roles: EXIT_ONLY,
    },
    Directive {
        canonical: "allowamplificationports",
        rel_path: "exit_policy.allow_amplification_ports",
        kind: Kind::Bool,
        roles: EXIT_ONLY,
    },
    // --- client -----------------------------------------------------------
    Directive { canonical: "guard", rel_path: "guard", kind: Kind::Str, roles: CLIENT_SERVICE },
    Directive { canonical: "middle", rel_path: "middle", kind: Kind::Str, roles: CLIENT_SERVICE },
    Directive { canonical: "exit", rel_path: "exit", kind: Kind::Str, roles: CLIENT_ONLY },
    Directive { canonical: "socksport", rel_path: "socks_port", kind: Kind::Int, roles: CLIENT_ONLY },
    Directive { canonical: "target", rel_path: "target", kind: Kind::Str, roles: CLIENT_ONLY },
    Directive { canonical: "selftest", rel_path: "self_test", kind: Kind::Bool, roles: CLIENT_ONLY },
    Directive { canonical: "mtu", rel_path: "mtu", kind: Kind::Int, roles: CLIENT_ONLY },
    Directive { canonical: "usecongestioncontrol", rel_path: "congestion", kind: Kind::Bool, roles: CLIENT_ONLY },
    Directive { canonical: "allowudp", rel_path: "allow_udp", kind: Kind::Bool, roles: CLIENT_ONLY },
    Directive {
        canonical: "isolatebydestination",
        rel_path: "isolate_by_destination",
        kind: Kind::Bool,
        roles: CLIENT_ONLY,
    },
    Directive { canonical: "connectattempts", rel_path: "connect_attempts", kind: Kind::Int, roles: CLIENT_ONLY },
    Directive { canonical: "requirepostquantum", rel_path: "require_pq", kind: Kind::Bool, roles: CLIENT_ONLY },
    Directive { canonical: "connecttimeout", rel_path: "connect_timeout", kind: Kind::Float, roles: CLIENT_ONLY },
    Directive { canonical: "trustguard", rel_path: "trust.guard", kind: Kind::Str, roles: CLIENT_SERVICE },
    Directive { canonical: "trustmiddle", rel_path: "trust.middle", kind: Kind::Str, roles: CLIENT_SERVICE },
    Directive { canonical: "trustexit", rel_path: "trust.exit", kind: Kind::Str, roles: CLIENT_ONLY },
    Directive { canonical: "fetchonion", rel_path: "fetch_onion", kind: Kind::Str, roles: CLIENT_ONLY },
    Directive { canonical: "fetchonionpath", rel_path: "fetch_onion_path", kind: Kind::Str, roles: CLIENT_ONLY },
    Directive { canonical: "statefile", rel_path: "state_file", kind: Kind::Str, roles: CLIENT_ONLY },
    // this client's own client-authorization key -- ClientAuthorizedKey,
    // by contrast, is a *service*-side directive and is special-cased
    // further down since it is repeatable.
    Directive { canonical: "clientauthkeyfile", rel_path: "client_auth_key_file", kind: Kind::Str, roles: CLIENT_ONLY },
    // shared between client and service, which both build their own
    // circuits and so share this whole knob set
    Directive { canonical: "timeout", rel_path: "timeout", kind: Kind::Float, roles: CLIENT_SERVICE },
    Directive { canonical: "retries", rel_path: "retries", kind: Kind::Int, roles: CLIENT_SERVICE },
    Directive { canonical: "keepaliveperiod", rel_path: "keepalive_interval", kind: Kind::Float, roles: CLIENT_SERVICE },
    // --- hidden service -----------------------------------------------------
    // HiddenServiceDir / HiddenServicePort are special-cased in
    // `parse_alliumrc` (each needs more than a single value copied
    // straight into the table).
    Directive {
        canonical: "hiddenservicenumintroductionpoints",
        rel_path: "intro_count",
        kind: Kind::Int,
        roles: SERVICE_ONLY,
    },
    Directive { canonical: "rendpostperiod", rel_path: "publish_interval", kind: Kind::Float, roles: SERVICE_ONLY },
    // ClientAuthorizedKey is also special-cased further down: unlike
    // every other directive here, it is repeatable (one line per
    // authorized client) and accumulates into a list rather than being
    // overwritten by a second occurrence.
];

fn role_section(role: &str) -> Option<&'static str> {
    match role {
        "guard" | "middle" | "exit" | "authority" => Some("relay"),
        "client" => Some("client"),
        "service" => Some("service"),
        _ => None,
    }
}

// ---------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------

/// Split one already-stripped, non-comment line into `(keyword, value)`.
///
/// `value` is everything after the first run of whitespace, trimmed, with
/// one matching pair of surrounding double quotes removed if present --
/// real Tor allows quoting a value for exactly this reason (to keep
/// leading/trailing space, or embed a literal `#`), so a copy-pasted
/// quoted value from a real `torrc` still parses here rather than
/// silently keeping its quote marks.
fn split_directive(line: &str) -> (String, String) {
    let mut split_at = line.len();
    for (i, c) in line.char_indices() {
        if c.is_whitespace() {
            split_at = i;
            break;
        }
    }
    let keyword = &line[..split_at];
    let mut value = line[split_at..].trim().to_string();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value = value[1..value.len() - 1].to_string();
    }
    (keyword.to_string(), value)
}

/// `os.path.expanduser`-equivalent: expands a leading `~` or `~/...`
/// against `$HOME`. Left unchanged (matching Python's own fallback) if
/// `HOME` isn't set.
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

/// Parse a flat `alliumrc`-style file into the [`Table`] shape
/// [`crate::config::load_config`] produces.
///
/// # Arguments
/// * `path` -- the file to read.
/// * `role` -- the subcommand actually being run (`"guard"`, `"client"`,
///   `"service"`, ...) -- known up front from argument parsing, and used
///   to decide both where each directive's value lands (see
///   [`role_section`]) and whether it is even valid for this role.
///
/// # Errors
/// [`AlliumrcError`] on a missing/unreadable file, an unknown directive, a
/// directive that doesn't apply to `role`, a malformed value,
/// `HiddenServiceDir`/`HiddenServicePort` given more than once (Allium
/// runs one hidden service per process), or two *different* directives
/// that would set the same underlying value.
pub fn parse_alliumrc(path: &Path, role: &str) -> Result<Table, AlliumrcError> {
    if path.is_dir() {
        return Err(err(format!("{} is a directory, not a config file", path.display())));
    }
    let bytes = std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            err(format!("config file not found: {}", path.display()))
        } else {
            err(format!("could not read {}: {e}", path.display()))
        }
    })?;
    // A leading UTF-8 BOM (common from Windows editors) is stripped
    // transparently, matching Python's `encoding="utf-8-sig"`; plain
    // UTF-8 without one is unaffected.
    let bytes: &[u8] =
        if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) { &bytes[3..] } else { &bytes[..] };
    let text = std::str::from_utf8(bytes)
        .map_err(|e| err(format!("{} is not a text file: {e}", path.display())))?;

    let mut config: Table = Table::new();
    let section = role_section(role);
    let mut seen_hidden_service_dir = false;
    let mut seen_hidden_service_port = false;
    let mut owner: BTreeMap<String, String> = BTreeMap::new();

    for (idx, raw_line) in text.lines().enumerate() {
        let lineno = idx + 1;
        let stripped = raw_line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        let (keyword, value) = split_directive(stripped);
        let where_ = format!("{}:{lineno}", path.display());
        let canonical = keyword.to_lowercase();

        if canonical == "role" {
            // Purely an informational label, exactly like TOML's own
            // top-level `role = "..."` -- what actually runs is always
            // the subcommand, never this file. Kept for parity with a
            // hand-converted TOML file.
            config.insert("role".to_string(), Value::Str(value));
            continue;
        }

        if canonical == "hiddenservicedir" {
            if role != "service" {
                return Err(err(format!(
                    "{where_}: HiddenServiceDir only applies to the 'service' role, not {role:?}"
                )));
            }
            if seen_hidden_service_dir {
                return Err(err(format!(
                    "{where_}: HiddenServiceDir given more than once -- an Allium alliumrc \
                     describes exactly one hidden service; run a separate 'service' process, \
                     each with its own alliumrc, for another one"
                )));
            }
            seen_hidden_service_dir = true;
            let hs_dir = expanduser(&value);
            if hs_dir.is_empty() {
                return Err(err(format!("{where_}: HiddenServiceDir needs a directory path")));
            }
            set(&mut config, "service.hidden_service_dir", Value::Str(hs_dir));
            continue;
        }

        if canonical == "hiddenserviceport" {
            if role != "service" {
                return Err(err(format!(
                    "{where_}: HiddenServicePort only applies to the 'service' role, not {role:?}"
                )));
            }
            if seen_hidden_service_port {
                return Err(err(format!(
                    "{where_}: HiddenServicePort given more than once -- unlike real Tor's \
                     per-virtual-port mappings, an Allium service forwards to exactly one \
                     local address"
                )));
            }
            seen_hidden_service_port = true;
            let tokens: Vec<&str> = value.split_whitespace().collect();
            let target = match tokens.len() {
                1 => tokens[0].to_string(),
                // Real Tor's "VIRTPORT TARGET" shape. The virtual port is
                // accepted so a copy-pasted real torrc line still parses,
                // but isn't yet meaningful: Allium has one address per
                // service, not per-port routing, so only TARGET is used.
                2 => tokens[1].to_string(),
                _ => {
                    return Err(err(format!(
                        "{where_}: HiddenServicePort takes 'TARGET' or 'VIRTPORT TARGET' \
                         (e.g. '80 127.0.0.1:8080'), got {value:?}"
                    )));
                }
            };
            if target.is_empty() {
                return Err(err(format!("{where_}: HiddenServicePort needs a target host:port")));
            }
            set(&mut config, "service.hidden_service_port", Value::Str(target));
            continue;
        }

        if canonical == "clientauthorizedkey" {
            // Repeatable -- one line per authorized client -- unlike
            // every other directive in DIRECTIVES, which the last
            // occurrence simply overwrites. Restricting a service to
            // specific clients means naming *all* of them, so this
            // accumulates into a list rather than losing all but the
            // last line to a silent typo.
            if role != "service" {
                return Err(err(format!(
                    "{where_}: ClientAuthorizedKey only applies to the 'service' role, not {role:?}"
                )));
            }
            if value.is_empty() {
                return Err(err(format!(
                    "{where_}: ClientAuthorizedKey needs a hex X25519 public key"
                )));
            }
            let service =
                config.entry("service".to_string()).or_insert_with(|| Value::Table(Table::new()));
            if !matches!(service, Value::Table(_)) {
                *service = Value::Table(Table::new());
            }
            if let Value::Table(t) = service {
                let keys = t
                    .entry("client_auth_keys".to_string())
                    .or_insert_with(|| Value::Array(Vec::new()));
                if !matches!(keys, Value::Array(_)) {
                    *keys = Value::Array(Vec::new());
                }
                if let Value::Array(arr) = keys {
                    arr.push(Value::Str(value));
                }
            }
            continue;
        }

        if canonical == "datadirectory" {
            if !RELAY_ROLES.contains(&role) {
                return Err(err(format!(
                    "{where_}: DataDirectory only applies to a relay role \
                     (guard/middle/exit/authority), not {role:?}"
                )));
            }
            let data_dir = expanduser(&value);
            if data_dir.is_empty() {
                return Err(err(format!("{where_}: DataDirectory needs a directory path")));
            }
            // Mirrors real Tor's own on-disk layout exactly: the identity
            // key lives at "<DataDirectory>/keys/ed25519_master_id_secret_key".
            claim(&mut owner, "relay.identity_file", "DataDirectory", &where_)?;
            let key_path = Path::new(&data_dir).join("keys").join("ed25519_master_id_secret_key");
            set(&mut config, "relay.identity_file", Value::Str(key_path.to_string_lossy().into_owned()));
            continue;
        }

        let entry = DIRECTIVES.iter().find(|d| d.canonical == canonical);
        let directive = match entry {
            Some(d) => d,
            None => return Err(err(format!("{where_}: unknown directive {keyword:?}"))),
        };
        if !directive.roles.contains(&role) {
            return Err(err(format!("{where_}: {keyword} does not apply to the {role:?} role")));
        }
        let section_name = match section {
            Some(s) => s,
            None => {
                // Every role reachable through `DIRECTIVES`' `roles` lists
                // has a section (see `role_section`); this only fires for
                // a `role` string that isn't a real Allium subcommand.
                return Err(err(format!("{where_}: {keyword} cannot be used with role {role:?}")));
            }
        };
        let coerced = coerce(&value, directive.kind, &where_, &keyword)?;
        let dotted = format!("{section_name}.{}", directive.rel_path);
        claim(&mut owner, &dotted, &keyword, &where_)?;
        set(&mut config, &dotted, coerced);
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn scratch_rc(text: &str) -> std::path::PathBuf {
        let n = {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            COUNTER.fetch_add(1, Ordering::Relaxed)
        };
        let path =
            std::env::temp_dir().join(format!("allium-rc-test-{}-{n}", std::process::id()));
        std::fs::write(&path, text).unwrap();
        path
    }

    fn table_str<'a>(t: &'a Table, key: &str) -> &'a str {
        t.get(key).and_then(Value::as_str).unwrap_or_else(|| panic!("missing key {key:?} in {t:?}"))
    }

    #[test]
    fn missing_file_raises_alliumrcerror() {
        let e = parse_alliumrc(Path::new("/nonexistent/path/does-not-exist"), "guard").unwrap_err();
        assert!(e.0.contains("not found"), "{}", e.0);
    }

    #[test]
    fn alliumrcerror_converts_into_configerror() {
        let e = AlliumrcError("boom".to_string());
        let c: ConfigError = e.into();
        assert_eq!(c.0, "boom");
    }

    #[test]
    fn directory_given_instead_of_file_raises() {
        let dir = std::env::temp_dir();
        assert!(parse_alliumrc(&dir, "guard").is_err());
    }

    #[test]
    fn blank_lines_and_comments_are_ignored() {
        let path = scratch_rc("\n# a comment\n   \nORPort 0.0.0.0:9001\n# trailing\n");
        let data = parse_alliumrc(&path, "guard").unwrap();
        assert_eq!(table_str(data["relay"].as_table().unwrap(), "bind"), "0.0.0.0:9001");
    }

    #[test]
    fn directive_names_are_case_insensitive() {
        let path = scratch_rc("orport 0.0.0.0:9001\nNICKNAME guard9\n");
        let data = parse_alliumrc(&path, "guard").unwrap();
        let relay = data["relay"].as_table().unwrap();
        assert_eq!(table_str(relay, "bind"), "0.0.0.0:9001");
        assert_eq!(table_str(relay, "name"), "guard9");
    }

    #[test]
    fn quoted_value_has_quotes_stripped() {
        let path = scratch_rc("Nickname \"guard with spaces\"\nORPort 0.0.0.0:9001\n");
        let data = parse_alliumrc(&path, "guard").unwrap();
        assert_eq!(table_str(data["relay"].as_table().unwrap(), "name"), "guard with spaces");
    }

    #[test]
    fn unknown_directive_raises_with_line_number() {
        let path = scratch_rc("ORPort 0.0.0.0:9001\nNotARealDirective foo\n");
        let e = parse_alliumrc(&path, "guard").unwrap_err();
        assert!(e.0.contains(":2:"), "{}", e.0);
        assert!(e.0.contains("NotARealDirective"), "{}", e.0);
    }

    #[test]
    fn role_label_is_purely_informational() {
        let path = scratch_rc("Role service\nORPort 0.0.0.0:9001\n");
        let data = parse_alliumrc(&path, "guard").unwrap();
        assert_eq!(data.get("role").and_then(Value::as_str), Some("service"));
        assert_eq!(table_str(data["relay"].as_table().unwrap(), "bind"), "0.0.0.0:9001");
    }

    #[test]
    fn directive_not_valid_for_current_role_raises() {
        let path = scratch_rc("ORPort 0.0.0.0:9001\nGuard 127.0.0.1:9001\n");
        let e = parse_alliumrc(&path, "guard").unwrap_err();
        assert!(e.0.contains("Guard"), "{}", e.0);
        assert!(e.0.contains("guard"), "{}", e.0);
    }

    #[test]
    fn authority_directive_invalid_for_authority_role_itself() {
        let path = scratch_rc("ORPort 0.0.0.0:9030\nAuthority 1.2.3.4:9030\n");
        assert!(parse_alliumrc(&path, "authority").is_err());
    }

    #[test]
    fn exit_only_directive_invalid_for_guard() {
        let path = scratch_rc("ORPort 0.0.0.0:9001\nAllowPorts 80,443\n");
        assert!(parse_alliumrc(&path, "guard").is_err());
    }

    #[test]
    fn datadirectory_only_valid_for_relay_roles() {
        let path = scratch_rc("Guard 1.2.3.4:1\nMiddle 1.2.3.4:2\nDataDirectory ~/x\n");
        assert!(parse_alliumrc(&path, "client").is_err());
    }

    #[test]
    fn full_relay_config() {
        let path = scratch_rc(
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
        let relay = data["relay"].as_table().unwrap();
        assert_eq!(table_str(relay, "name"), "exit9");
        assert_eq!(table_str(relay, "bind"), "0.0.0.0:9003");
        assert_eq!(table_str(relay, "identity_file"), "~/.allium/exit9.key");
        assert_eq!(relay.get("idle_timeout").and_then(Value::as_f64), Some(120.0));
        assert_eq!(table_str(relay, "authority"), "10.10.10.2:9030");
        assert_eq!(table_str(relay, "advertise"), "203.0.113.5:9003");
        assert_eq!(table_str(relay["trust"].as_table().unwrap(), "authority"), "deadbeef");
        assert_eq!(relay.get("publish_interval").and_then(Value::as_f64), Some(600.0));
        let policy = relay["exit_policy"].as_table().unwrap();
        assert_eq!(table_str(policy, "allow_ports"), "80,443,8080");
        assert_eq!(table_str(policy, "allow_udp_ports"), "53");
        assert_eq!(policy.get("allow_private").and_then(Value::as_bool), Some(true));
        assert_eq!(policy.get("allow_amplification_ports").and_then(Value::as_bool), Some(false));
    }

    #[test]
    fn datadirectory_derives_identity_file_like_real_tor() {
        let path = scratch_rc("ORPort 0.0.0.0:9001\nDataDirectory ~/.allium/guard1\n");
        let data = parse_alliumrc(&path, "guard").unwrap();
        let expected = Path::new(&expanduser("~/.allium/guard1"))
            .join("keys")
            .join("ed25519_master_id_secret_key");
        assert_eq!(table_str(data["relay"].as_table().unwrap(), "identity_file"), expected.to_string_lossy());
    }

    #[test]
    fn bad_bool_value_raises() {
        let path = scratch_rc("ORPort 0.0.0.0:9003\nAllowPrivateAddresses maybe\n");
        assert!(parse_alliumrc(&path, "exit").is_err());
    }

    #[test]
    fn bad_float_value_raises() {
        let path = scratch_rc("ORPort 0.0.0.0:9001\nIdleTimeout soon\n");
        assert!(parse_alliumrc(&path, "guard").is_err());
    }

    #[test]
    fn identityfile_then_datadirectory_conflict_raises() {
        let path = scratch_rc(
            "ORPort 0.0.0.0:9003\nIdentityFile ~/.allium/exit9.key\nDataDirectory ~/.allium/exit9\n",
        );
        let e = parse_alliumrc(&path, "exit").unwrap_err();
        assert!(e.0.contains("conflicts"), "{}", e.0);
    }

    #[test]
    fn datadirectory_then_identityfile_conflict_raises() {
        let path = scratch_rc(
            "ORPort 0.0.0.0:9003\nDataDirectory ~/.allium/exit9\nIdentityFile ~/.allium/exit9.key\n",
        );
        let e = parse_alliumrc(&path, "exit").unwrap_err();
        assert!(e.0.contains("conflicts"), "{}", e.0);
    }

    #[test]
    fn bom_prefixed_file_parses() {
        let n = {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            COUNTER.fetch_add(1, Ordering::Relaxed)
        };
        let path =
            std::env::temp_dir().join(format!("allium-rc-bom-test-{}-{n}", std::process::id()));
        let mut bytes = vec![0xEFu8, 0xBB, 0xBF];
        bytes.extend_from_slice(b"ORPort 0.0.0.0:9003\nNickname exit9\n");
        std::fs::write(&path, &bytes).unwrap();
        let data = parse_alliumrc(&path, "exit").unwrap();
        let relay = data["relay"].as_table().unwrap();
        assert_eq!(table_str(relay, "bind"), "0.0.0.0:9003");
        assert_eq!(table_str(relay, "name"), "exit9");
    }

    #[test]
    fn allowunpinnedauthority_directive_parses_for_a_relay_role() {
        let path = scratch_rc("ORPort 0.0.0.0:9003\nAuthority 10.10.10.2:9030\nAllowUnpinnedAuthority yes\n");
        let data = parse_alliumrc(&path, "exit").unwrap();
        let trust = data["relay"].as_table().unwrap()["trust"].as_table().unwrap();
        assert_eq!(trust.get("allow_unpinned").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn allowunpinnedauthority_directive_accepts_boolean_words() {
        for (word, expected) in [("yes", true), ("no", false), ("1", true), ("0", false)] {
            let path = scratch_rc(&format!("ORPort 0.0.0.0:9003\nAllowUnpinnedAuthority {word}\n"));
            let data = parse_alliumrc(&path, "exit").unwrap();
            let trust = data["relay"].as_table().unwrap()["trust"].as_table().unwrap();
            assert_eq!(trust.get("allow_unpinned").and_then(Value::as_bool), Some(expected));
        }
    }

    #[test]
    fn full_client_config() {
        let path = scratch_rc(
            "Guard 127.0.0.1:9001\nMiddle 10.0.0.2:9002\nExit 10.0.0.2:9003\n\
             Target 10.0.0.2:9100\nSocksPort 9060\nUseCongestionControl no\n\
             AllowUDP yes\nKeepAlivePeriod 45\nTrustGuard aabbcc\n\
             FetchOnion abc.allium\nFetchOnionPath /index.html\n",
        );
        let data = parse_alliumrc(&path, "client").unwrap();
        let client = data["client"].as_table().unwrap();
        assert_eq!(table_str(client, "guard"), "127.0.0.1:9001");
        assert_eq!(table_str(client, "middle"), "10.0.0.2:9002");
        assert_eq!(table_str(client, "exit"), "10.0.0.2:9003");
        assert_eq!(table_str(client, "target"), "10.0.0.2:9100");
        assert_eq!(client.get("socks_port").and_then(Value::as_i64), Some(9060));
        assert_eq!(client.get("congestion").and_then(Value::as_bool), Some(false));
        assert_eq!(client.get("allow_udp").and_then(Value::as_bool), Some(true));
        assert_eq!(client.get("keepalive_interval").and_then(Value::as_f64), Some(45.0));
        assert_eq!(table_str(client["trust"].as_table().unwrap(), "guard"), "aabbcc");
        assert_eq!(table_str(client, "fetch_onion"), "abc.allium");
        assert_eq!(table_str(client, "fetch_onion_path"), "/index.html");
    }

    #[test]
    fn state_file_directive() {
        let path = scratch_rc("Authority 10.0.0.9:9030\nStateFile ~/.allium/client-state.json\n");
        let data = parse_alliumrc(&path, "client").unwrap();
        // ~ expansion happens at config-application time, same as every
        // other path-shaped directive -- the parser itself just copies
        // the literal string.
        assert_eq!(table_str(data["client"].as_table().unwrap(), "state_file"), "~/.allium/client-state.json");
    }

    #[test]
    fn state_file_rejected_outside_client_role() {
        let path = scratch_rc("ORPort 0.0.0.0:9001\nStateFile /tmp/state.json\n");
        assert!(parse_alliumrc(&path, "guard").is_err());
    }

    #[test]
    fn client_auth_key_file_directive() {
        let path = scratch_rc("Authority 10.0.0.9:9030\nClientAuthKeyFile ~/.allium/client-auth.key\n");
        let data = parse_alliumrc(&path, "client").unwrap();
        assert_eq!(
            table_str(data["client"].as_table().unwrap(), "client_auth_key_file"),
            "~/.allium/client-auth.key"
        );
    }

    #[test]
    fn client_auth_key_file_rejected_outside_client_role() {
        let path = scratch_rc("ORPort 0.0.0.0:9001\nClientAuthKeyFile /tmp/auth.key\n");
        assert!(parse_alliumrc(&path, "guard").is_err());
    }

    #[test]
    fn hidden_service_dir_and_port_single_token() {
        let path = scratch_rc(
            "HiddenServiceDir ~/.allium/svc1\nHiddenServicePort 127.0.0.1:8080\nAuthority 10.10.10.2:9030\n",
        );
        let data = parse_alliumrc(&path, "service").unwrap();
        let service = data["service"].as_table().unwrap();
        assert_eq!(table_str(service, "hidden_service_dir"), expanduser("~/.allium/svc1"));
        assert_eq!(table_str(service, "hidden_service_port"), "127.0.0.1:8080");
        assert_eq!(table_str(service, "authority"), "10.10.10.2:9030");
        assert!(!service.contains_key("identity_file"));
    }

    #[test]
    fn hidden_service_port_two_token_torstyle_uses_target_only() {
        let path = scratch_rc(
            "HiddenServiceDir ~/.allium/svc1\nHiddenServicePort 80 127.0.0.1:8080\nAuthority 10.10.10.2:9030\n",
        );
        let data = parse_alliumrc(&path, "service").unwrap();
        assert_eq!(table_str(data["service"].as_table().unwrap(), "hidden_service_port"), "127.0.0.1:8080");
    }

    #[test]
    fn hidden_service_port_too_many_tokens_raises() {
        let path = scratch_rc("HiddenServicePort 80 127.0.0.1:8080 extra\n");
        assert!(parse_alliumrc(&path, "service").is_err());
    }

    #[test]
    fn duplicate_hidden_service_dir_raises() {
        let path = scratch_rc("HiddenServiceDir ~/.allium/svc1\nHiddenServiceDir ~/.allium/svc2\n");
        let e = parse_alliumrc(&path, "service").unwrap_err();
        assert!(e.0.contains("more than once"), "{}", e.0);
    }

    #[test]
    fn duplicate_hidden_service_port_raises() {
        let path = scratch_rc("HiddenServicePort 127.0.0.1:8080\nHiddenServicePort 127.0.0.1:9090\n");
        assert!(parse_alliumrc(&path, "service").is_err());
    }

    #[test]
    fn hidden_service_directives_rejected_outside_service_role() {
        let path = scratch_rc("ORPort 0.0.0.0:9001\nHiddenServiceDir ~/.allium/x\n");
        assert!(parse_alliumrc(&path, "guard").is_err());
        let path = scratch_rc("ORPort 0.0.0.0:9001\nHiddenServicePort 127.0.0.1:80\n");
        assert!(parse_alliumrc(&path, "guard").is_err());
    }

    #[test]
    fn client_authorized_key_accumulates_a_list() {
        let path = scratch_rc(
            "HiddenServiceDir ~/.allium/svc1\nHiddenServicePort 127.0.0.1:8080\n\
             Authority 10.10.10.2:9030\nClientAuthorizedKey aa11\nClientAuthorizedKey bb22\n\
             ClientAuthorizedKey cc33\n",
        );
        let data = parse_alliumrc(&path, "service").unwrap();
        let keys = data["service"].as_table().unwrap()["client_auth_keys"].as_array().unwrap();
        let keys: Vec<&str> = keys.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(keys, vec!["aa11", "bb22", "cc33"]);
    }

    #[test]
    fn client_authorized_key_needs_a_value() {
        let path = scratch_rc("ClientAuthorizedKey \n");
        assert!(parse_alliumrc(&path, "service").is_err());
    }

    #[test]
    fn client_authorized_key_rejected_outside_service_role() {
        let path = scratch_rc("ORPort 0.0.0.0:9001\nClientAuthorizedKey aa11\n");
        assert!(parse_alliumrc(&path, "guard").is_err());
    }

    #[test]
    fn full_service_config() {
        let path = scratch_rc(
            "HiddenServiceDir ~/.allium/svc1\nHiddenServicePort 80 127.0.0.1:8080\n\
             Nickname myservice\nGuard 127.0.0.1:9001\nMiddle 10.0.0.2:9002\n\
             Authority 10.10.10.2:9030\nTrustAuthority deadbeef\nTrustGuard cafef00d\n\
             TrustMiddle f00dcafe\nHiddenServiceNumIntroductionPoints 5\nRendPostPeriod 900\n\
             Timeout 3.5\nRetries 4\nKeepAlivePeriod 30\n",
        );
        let data = parse_alliumrc(&path, "service").unwrap();
        let service = data["service"].as_table().unwrap();
        assert_eq!(table_str(service, "hidden_service_dir"), expanduser("~/.allium/svc1"));
        assert_eq!(table_str(service, "hidden_service_port"), "127.0.0.1:8080");
        assert_eq!(table_str(service, "name"), "myservice");
        assert_eq!(table_str(service, "guard"), "127.0.0.1:9001");
        assert_eq!(table_str(service, "middle"), "10.0.0.2:9002");
        assert_eq!(table_str(service, "authority"), "10.10.10.2:9030");
        let trust = service["trust"].as_table().unwrap();
        assert_eq!(table_str(trust, "authority"), "deadbeef");
        assert_eq!(table_str(trust, "guard"), "cafef00d");
        assert_eq!(table_str(trust, "middle"), "f00dcafe");
        assert_eq!(service.get("intro_count").and_then(Value::as_i64), Some(5));
        assert_eq!(service.get("publish_interval").and_then(Value::as_f64), Some(900.0));
        assert_eq!(service.get("timeout").and_then(Value::as_f64), Some(3.5));
        assert_eq!(service.get("retries").and_then(Value::as_i64), Some(4));
        assert_eq!(service.get("keepalive_interval").and_then(Value::as_f64), Some(30.0));
    }
}
