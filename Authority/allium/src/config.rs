//! TOML config-file support for Allium's demo CLI (`allium_cli`).
//!
//! Mirrors `allium/config.py`. Deliberately **not** part of the wire
//! protocol, circuit, or crypto core -- it only turns a TOML file into plain
//! tables that `allium_cli` reads to fill in argument values it didn't get on
//! the command line.
//!
//! This sandbox has no network access to fetch a real TOML crate (see the
//! note atop `allium/Cargo.toml`), so [`parse_toml`] is a small hand-written
//! parser covering the subset of TOML Allium's example config files actually
//! use: top-level and nested `[table]`/`[a.b]` headers, `key = value` pairs,
//! double-quoted strings, integers, floats, booleans, and single-line arrays
//! of those. It is not a general-purpose TOML implementation (no multi-line
//! strings/arrays, no inline tables, no dates) -- swap in a real `toml` crate
//! once one is fetchable.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;

/// A missing, unreadable, malformed, or mis-shaped config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub message: String,
}
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for ConfigError {}
impl ConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

/// A minimal TOML value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    String(String),
    Integer(i64),
    Float(f64),
    Bool(bool),
    Array(Vec<Value>),
    Table(Table),
}

/// A TOML table: an ordered-by-key map from key to [`Value`].
pub type Table = BTreeMap<String, Value>;

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Integer(i) => Some(*i),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_table(&self) -> Option<&Table> {
        match self {
            Value::Table(t) => Some(t),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::String(_) => "str",
            Value::Integer(_) => "int",
            Value::Float(_) => "float",
            Value::Bool(_) => "bool",
            Value::Array(_) => "list",
            Value::Table(_) => "dict",
        }
    }
}

// --------------------------------------------------------------------------
// Parser
// --------------------------------------------------------------------------

/// Parse a small subset of TOML text into a top-level [`Table`].
pub fn parse_toml(text: &str) -> Result<Table, ConfigError> {
    let mut root: Table = Table::new();
    let mut path: Vec<String> = Vec::new();

    for (lineno, raw_line) in text.lines().enumerate() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            if !line.ends_with(']') {
                return Err(ConfigError::new(format!("line {}: malformed table header", lineno + 1)));
            }
            let inner = &line[1..line.len() - 1];
            if inner.is_empty() {
                return Err(ConfigError::new(format!("line {}: empty table header", lineno + 1)));
            }
            path = inner.split('.').map(|s| s.trim().to_string()).collect();
            ensure_table(&mut root, &path)
                .map_err(|e| ConfigError::new(format!("line {}: {e}", lineno + 1)))?;
            continue;
        }
        let eq = line.find('=').ok_or_else(|| {
            ConfigError::new(format!("line {}: expected 'key = value'", lineno + 1))
        })?;
        let key = line[..eq].trim();
        let raw_value = line[eq + 1..].trim();
        if key.is_empty() {
            return Err(ConfigError::new(format!("line {}: empty key", lineno + 1)));
        }
        let value = parse_value(raw_value)
            .map_err(|e| ConfigError::new(format!("line {}: {e}", lineno + 1)))?;
        let table = table_at_mut(&mut root, &path)
            .map_err(|e| ConfigError::new(format!("line {}: {e}", lineno + 1)))?;
        table.insert(key.to_string(), value);
    }
    Ok(root)
}

fn strip_comment(line: &str) -> &str {
    let mut in_string = false;
    for (i, c) in line.char_indices() {
        if c == '"' {
            in_string = !in_string;
        } else if c == '#' && !in_string {
            return &line[..i];
        }
    }
    line
}

fn ensure_table(root: &mut Table, path: &[String]) -> Result<(), String> {
    let mut current = root;
    for (i, seg) in path.iter().enumerate() {
        let entry = current.entry(seg.clone()).or_insert_with(|| Value::Table(Table::new()));
        match entry {
            Value::Table(t) => current = t,
            _ => {
                return Err(format!(
                    "'{}' is not a table",
                    path[..=i].join(".")
                ))
            }
        }
    }
    Ok(())
}

fn table_at_mut<'a>(root: &'a mut Table, path: &[String]) -> Result<&'a mut Table, String> {
    let mut current = root;
    for seg in path {
        let entry = current.entry(seg.clone()).or_insert_with(|| Value::Table(Table::new()));
        match entry {
            Value::Table(t) => current = t,
            _ => return Err(format!("'{seg}' is not a table")),
        }
    }
    Ok(current)
}

fn parse_value(raw: &str) -> Result<Value, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("missing value".to_string());
    }
    if raw == "true" {
        return Ok(Value::Bool(true));
    }
    if raw == "false" {
        return Ok(Value::Bool(false));
    }
    if raw.starts_with('"') {
        if !raw.ends_with('"') || raw.len() < 2 {
            return Err("unterminated string".to_string());
        }
        let inner = &raw[1..raw.len() - 1];
        return Ok(Value::String(unescape(inner)));
    }
    if raw.starts_with('[') {
        if !raw.ends_with(']') {
            return Err("unterminated array".to_string());
        }
        let inner = &raw[1..raw.len() - 1];
        if inner.trim().is_empty() {
            return Ok(Value::Array(Vec::new()));
        }
        let mut items = Vec::new();
        for part in split_top_level(inner, ',') {
            items.push(parse_value(part.trim())?);
        }
        return Ok(Value::Array(items));
    }
    if let Ok(i) = raw.parse::<i64>() {
        return Ok(Value::Integer(i));
    }
    if let Ok(f) = raw.parse::<f64>() {
        return Ok(Value::Float(f));
    }
    Err(format!("could not parse value {raw:?}"))
}

fn split_top_level(s: &str, sep: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '"' => in_string = !in_string,
            '[' if !in_string => depth += 1,
            ']' if !in_string => depth -= 1,
            c if c == sep && depth == 0 && !in_string => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some(other) => out.push(other),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

// --------------------------------------------------------------------------
// File loading
// --------------------------------------------------------------------------

/// Parse an Allium TOML config file into a plain [`Table`].
pub fn load_config(path: &str) -> Result<Table, ConfigError> {
    let meta = fs::metadata(path);
    match meta {
        Ok(m) if m.is_dir() => {
            return Err(ConfigError::new(format!("{path} is a directory, not a config file")));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ConfigError::new(format!("config file not found: {path}")));
        }
        Err(e) => {
            return Err(ConfigError::new(format!("could not read {path}: {e}")));
        }
    }
    let text = fs::read_to_string(path).map_err(|e| ConfigError::new(format!("could not read {path}: {e}")))?;
    parse_toml(&text).map_err(|e| ConfigError::new(format!("{path} is not valid TOML: {e}")))
}

fn table_helper(data: &Table, key: &str, where_: &str) -> Result<Table, ConfigError> {
    match data.get(key) {
        None => Ok(Table::new()),
        Some(Value::Table(t)) => Ok(t.clone()),
        Some(other) => Err(ConfigError::new(format!("[{where_}] must be a table, got {}", other.type_name()))),
    }
}

/// The `[relay]` table: shared by the guard/middle/exit roles.
pub fn relay_section(data: &Table) -> Result<Table, ConfigError> {
    table_helper(data, "relay", "relay")
}

/// The `[relay.exit_policy]` table: read only for the exit role.
pub fn exit_policy_section(data: &Table) -> Result<Table, ConfigError> {
    table_helper(&relay_section(data)?, "exit_policy", "relay.exit_policy")
}

/// The `[relay.trust]` table.
pub fn relay_trust_section(data: &Table) -> Result<Table, ConfigError> {
    table_helper(&relay_section(data)?, "trust", "relay.trust")
}

/// The `[client]` table.
pub fn client_section(data: &Table) -> Result<Table, ConfigError> {
    table_helper(data, "client", "client")
}

/// The `[client.trust]` table.
pub fn client_trust_section(data: &Table) -> Result<Table, ConfigError> {
    table_helper(&client_section(data)?, "trust", "client.trust")
}

/// The `[service]` table.
pub fn service_section(data: &Table) -> Result<Table, ConfigError> {
    table_helper(data, "service", "service")
}

/// The `[service.trust]` table.
pub fn service_trust_section(data: &Table) -> Result<Table, ConfigError> {
    table_helper(&service_section(data)?, "trust", "service.trust")
}

/// Turn a config ports value into the comma string `parse_ports` wants.
///
/// `None` stays `None` so callers can tell "not set in the config" apart
/// from "set to an empty list" (which legitimately means "allow nothing").
pub fn ports_to_flag(value: Option<&Value>, field_name: &str) -> Result<Option<String>, ConfigError> {
    let value = match value {
        None => return Ok(None),
        Some(v) => v,
    };
    match value {
        Value::String(s) => Ok(Some(s.clone())),
        Value::Array(items) => {
            let mut parts = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::Integer(i) => parts.push(i.to_string()),
                    Value::Bool(_) => {
                        return Err(ConfigError::new(format!(
                            "{field_name} must be a list of integers, e.g. [80, 443]"
                        )))
                    }
                    _ => {
                        return Err(ConfigError::new(format!(
                            "{field_name} must be a list of integers, e.g. [80, 443]"
                        )))
                    }
                }
            }
            Ok(Some(parts.join(",")))
        }
        _ => Err(ConfigError::new(format!(
            "{field_name} must be a list of integers or a comma-separated string"
        ))),
    }
}

/// Three-way precedence: an explicit CLI value wins, then the config file's
/// value, then `default`.
pub fn resolve<T>(cli_value: Option<T>, config_value: Option<T>, default: Option<T>) -> Option<T> {
    if cli_value.is_some() {
        return cli_value;
    }
    if config_value.is_some() {
        return config_value;
    }
    default
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_toml(text: &str) -> String {
        let mut path = std::env::temp_dir();
        path.push(format!("allium-config-test-{}.toml", rand_suffix()));
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(text.as_bytes()).unwrap();
        path.to_str().unwrap().to_string()
    }

    fn rand_suffix() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as u64
    }

    // -- load_config -----------------------------------------------------
    #[test]
    fn test_missing_file_raises_configerror_not_a_raw_oserror() {
        let err = load_config("/nonexistent/path/does-not-exist.toml").unwrap_err();
        assert!(err.message.contains("not found"));
    }

    #[test]
    fn test_malformed_toml_raises_configerror() {
        let path = write_toml("this is not [valid toml");
        let err = load_config(&path).unwrap_err();
        assert!(err.message.contains("not valid TOML"));
    }

    #[test]
    fn test_valid_file_loads_as_a_plain_table() {
        let path = write_toml("role = \"guard\"\n\n[relay]\nbind = \"0.0.0.0:9001\"\n");
        let data = load_config(&path).unwrap();
        assert_eq!(data["role"].as_str(), Some("guard"));
        assert_eq!(data["relay"].as_table().unwrap()["bind"].as_str(), Some("0.0.0.0:9001"));
    }

    // -- section helpers -----------------------------------------------------
    #[test]
    fn test_relay_section_defaults_to_empty_when_absent() {
        assert_eq!(relay_section(&Table::new()).unwrap(), Table::new());
    }

    #[test]
    fn test_relay_section_returns_the_table() {
        let mut relay = Table::new();
        relay.insert("bind".to_string(), Value::String("0.0.0.0:9001".to_string()));
        relay.insert("name".to_string(), Value::String("guard1".to_string()));
        let mut data = Table::new();
        data.insert("relay".to_string(), Value::Table(relay.clone()));
        assert_eq!(relay_section(&data).unwrap(), relay);
    }

    #[test]
    fn test_relay_section_wrong_type_raises() {
        let mut data = Table::new();
        data.insert("relay".to_string(), Value::String("not a table".to_string()));
        assert!(relay_section(&data).is_err());
    }

    #[test]
    fn test_exit_policy_section_nests_under_relay() {
        let path = write_toml("[relay]\n[relay.exit_policy]\nallow_ports = [80, 443]\n");
        let data = load_config(&path).unwrap();
        let ep = exit_policy_section(&data).unwrap();
        assert_eq!(
            ep["allow_ports"].as_array().unwrap(),
            &[Value::Integer(80), Value::Integer(443)]
        );
    }

    #[test]
    fn test_exit_policy_section_defaults_empty_when_relay_absent() {
        assert_eq!(exit_policy_section(&Table::new()).unwrap(), Table::new());
    }

    #[test]
    fn test_client_section_and_trust_section() {
        let path = write_toml(
            "[client]\nguard = \"1.2.3.4:9001\"\n[client.trust]\nguard = \"deadbeef\"\n",
        );
        let data = load_config(&path).unwrap();
        assert_eq!(client_section(&data).unwrap()["guard"].as_str(), Some("1.2.3.4:9001"));
        assert_eq!(client_trust_section(&data).unwrap()["guard"].as_str(), Some("deadbeef"));
    }

    // -- ports_to_flag -----------------------------------------------------
    #[test]
    fn test_none_stays_none() {
        assert_eq!(ports_to_flag(None, "x").unwrap(), None);
    }

    #[test]
    fn test_string_passes_through_unchanged() {
        assert_eq!(
            ports_to_flag(Some(&Value::String("80,443".to_string())), "x").unwrap(),
            Some("80,443".to_string())
        );
    }

    #[test]
    fn test_int_list_becomes_comma_string() {
        let v = Value::Array(vec![Value::Integer(80), Value::Integer(443), Value::Integer(8080)]);
        assert_eq!(ports_to_flag(Some(&v), "x").unwrap(), Some("80,443,8080".to_string()));
    }

    #[test]
    fn test_empty_list_becomes_empty_string_not_none() {
        let v = Value::Array(vec![]);
        assert_eq!(ports_to_flag(Some(&v), "x").unwrap(), Some(String::new()));
    }

    #[test]
    fn test_non_int_list_raises() {
        let v = Value::Array(vec![Value::String("80".to_string()), Value::String("443".to_string())]);
        assert!(ports_to_flag(Some(&v), "x").is_err());
    }

    #[test]
    fn test_bool_in_list_rejected() {
        let v = Value::Array(vec![Value::Integer(80), Value::Bool(true)]);
        assert!(ports_to_flag(Some(&v), "x").is_err());
    }

    #[test]
    fn test_other_type_raises() {
        assert!(ports_to_flag(Some(&Value::Integer(80)), "x").is_err());
    }

    // -- resolve -----------------------------------------------------
    #[test]
    fn test_cli_value_wins_over_everything() {
        assert_eq!(resolve(Some("cli"), Some("config"), Some("default")), Some("cli"));
    }

    #[test]
    fn test_config_value_wins_when_cli_is_none() {
        assert_eq!(resolve(None, Some("config"), Some("default")), Some("config"));
    }

    #[test]
    fn test_default_used_when_both_are_none() {
        assert_eq!(resolve(None, None, Some("default")), Some("default"));
    }

    #[test]
    fn test_falsy_but_not_none_cli_value_still_wins() {
        assert_eq!(resolve(Some(0), Some(9), Some(1)), Some(0));
        assert_eq!(resolve(Some(""), Some("config"), Some("default")), Some(""));
        assert_eq!(resolve(Some(false), Some(true), Some(true)), Some(false));
    }
}
