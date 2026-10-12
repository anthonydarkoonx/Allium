//! TOML config-file support for Allium's demo CLI (`allium_cli`), Rust port
//! of `config.py` (175 Python lines).
//!
//! This was Allium's first answer to Tor's `torrc`: instead of retyping
//! every `--flag` on every launch, an operator can keep one small file per
//! role/box and run something like:
//!
//! ```text
//! allium --config guard.toml guard
//! allium --config exit.toml  exit
//! allium --config client.toml client
//! ```
//!
//! For something closer to Tor's own file -- flat `Keyword value` lines
//! instead of `[tables]` -- see [`crate::alliumrc`]: `allium_cli` picks
//! between the two by file extension (anything not ending in `.toml` is
//! read as a flat alliumrc), and both end up producing the exact
//! [`Table`]/[`Value`] shape this module's `*_section` helpers below
//! expect, so nothing past config-application cares which one an operator
//! wrote.
//!
//! Precedence is CLI flag > config file > `allium_cli`'s own hardcoded
//! default -- an explicit `--bind ...` on the command line always wins,
//! even with `--config` also given (see [`resolve`]).
//!
//! This module is deliberately **not** part of the wire protocol, circuit,
//! or crypto core -- it only turns a config file into plain [`Table`]s
//! that `allium_cli` reads to fill in values it didn't get on the command
//! line. Nothing here is imported by [`crate::circuit`], [`crate::onion`],
//! etc.
//!
//! # TOML subset
//!
//! Python's `config.py` hands the whole file to the stdlib `tomllib`
//! parser. This crate avoids vendoring a full TOML implementation (and
//! the `serde` ecosystem it would pull in) for what is, by this module's
//! own admission, a demo-CLI convenience feature -- so [`load_config`]
//! ships a small hand-written reader instead, covering exactly what an
//! Allium config file actually uses: `[section]` and `[section.sub]`
//! table headers, `key = value` assignments (dotted keys included),
//! basic (`"..."`, with `\"`/`\\`/`\n`/`\t`/`\r`/`\b`/`\f`/`\uXXXX`/`\UXXXXXXXX`
//! escapes) and literal (`'...'`, no escapes) strings, integers and
//! floats (with `_` digit separators), `true`/`false`, arrays (which may
//! span multiple lines), and inline tables. Array-of-tables (`[[...]]`),
//! dates/times, and multi-line (triple-quoted) strings are not
//! implemented and are rejected as a parse error, the same way malformed
//! TOML is.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

/// A parsed TOML value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Array(Vec<Value>),
    Table(Table),
}

/// A TOML table: `data["relay"]["bind"]` becomes `data["relay"]` ->
/// `Value::Table` -> `["bind"]` -> `Value::Str`, mirroring the plain
/// nested-dict shape Python's `tomllib.load` returns.
pub type Table = BTreeMap<String, Value>;

impl Value {
    pub fn as_table(&self) -> Option<&Table> {
        match self {
            Value::Table(t) => Some(t),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// An int is accepted where a float is expected (matches Python's
    /// numeric tower: `1` and `1.0` are interchangeable wherever a TOML
    /// value is read as a number).
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Float(f) => Some(*f),
            Value::Int(i) => Some(*i as f64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a.as_slice()),
            _ => None,
        }
    }

    /// Python `type(value).__name__` equivalent, used in error messages.
    fn type_name(&self) -> &'static str {
        match self {
            Value::Str(_) => "str",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::Bool(_) => "bool",
            Value::Array(_) => "list",
            Value::Table(_) => "dict",
        }
    }
}

/// A missing, unreadable, malformed, or mis-shaped config file.
///
/// Callers turn this into a clean exit message -- config errors are
/// operator-facing (a typo in a hand-edited file), not bugs.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ConfigError {}

/// Parse an Allium TOML config file into a [`Table`].
///
/// Always returns [`ConfigError`] on failure (never a raw I/O error), so
/// the caller can print one clean line and exit rather than dumping a
/// panic on an operator who just fat-fingered a config file.
pub fn load_config(path: &Path) -> Result<Table, ConfigError> {
    if path.is_dir() {
        return Err(ConfigError(format!("{} is a directory, not a config file", path.display())));
    }
    let text = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ConfigError(format!("config file not found: {}", path.display())));
        }
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            return Err(ConfigError(format!("{} is not a text file: {e}", path.display())));
        }
        Err(e) => return Err(ConfigError(format!("could not read {}: {e}", path.display()))),
    };
    toml_lite::parse(&text)
        .map_err(|msg| ConfigError(format!("{} is not valid TOML: {msg}", path.display())))
}

fn table_field(data: &Table, key: &str, where_: &str) -> Result<Table, ConfigError> {
    match data.get(key) {
        None => Ok(Table::new()),
        Some(Value::Table(t)) => Ok(t.clone()),
        Some(other) => {
            Err(ConfigError(format!("[{where_}] must be a table, got {}", other.type_name())))
        }
    }
}

/// The `[relay]` table: shared by the guard/middle/exit roles.
pub fn relay_section(data: &Table) -> Result<Table, ConfigError> {
    table_field(data, "relay", "relay")
}

/// The `[relay.exit_policy]` table: read only for the exit role.
pub fn exit_policy_section(data: &Table) -> Result<Table, ConfigError> {
    table_field(&relay_section(data)?, "exit_policy", "relay.exit_policy")
}

/// The `[relay.trust]` table: currently just the directory authority's
/// identity pin, used when a guard/middle/exit publishes to one.
pub fn relay_trust_section(data: &Table) -> Result<Table, ConfigError> {
    table_field(&relay_section(data)?, "trust", "relay.trust")
}

/// The `[client]` table.
pub fn client_section(data: &Table) -> Result<Table, ConfigError> {
    table_field(data, "client", "client")
}

/// The `[client.trust]` table: guard/middle/exit identity pins.
pub fn client_trust_section(data: &Table) -> Result<Table, ConfigError> {
    table_field(&client_section(data)?, "trust", "client.trust")
}

/// The `[service]` table: a hidden service's own settings --
/// `hidden_service_port` (the local `host:port` of the real web server
/// this service forwards rendezvous traffic to), `identity_file` (its
/// long-term address key), `authority`, `intro_count`, and
/// `publish_interval`.
pub fn service_section(data: &Table) -> Result<Table, ConfigError> {
    table_field(data, "service", "service")
}

/// The `[service.trust]` table: guard/middle/authority identity pins, the
/// same shape as `[client.trust]` since a service reaches its own entry
/// hops exactly like a client does.
pub fn service_trust_section(data: &Table) -> Result<Table, ConfigError> {
    table_field(&service_section(data)?, "trust", "service.trust")
}

/// Turn a config ports value into the comma string `parse_ports` wants.
///
/// Accepts a native TOML array of ints (`allow_ports = [80, 443]`, the
/// natural way to write this in TOML) or a comma string (`"80,443"`, for
/// anyone who'd rather match the CLI flag's own syntax exactly). Returns
/// `Ok(None)` unchanged so callers can tell "not set in the config" apart
/// from "set to an empty list", which legitimately means "allow nothing".
pub fn ports_to_flag(value: Option<&Value>, field_name: &str) -> Result<Option<String>, ConfigError> {
    match value {
        None => Ok(None),
        Some(Value::Str(s)) => Ok(Some(s.clone())),
        Some(Value::Array(items)) => {
            let mut parts = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    // `Value::Bool` is a distinct variant from `Value::Int`,
                    // so a stray `true`/`false` in the array can never slip
                    // through here as port 1/0 -- Python needs an explicit
                    // `and not isinstance(item, bool)` check for the same
                    // guarantee, since `bool` is an `int` subclass there.
                    Value::Int(i) => parts.push(i.to_string()),
                    _ => {
                        return Err(ConfigError(format!(
                            "{field_name} must be a list of integers, e.g. [80, 443]"
                        )));
                    }
                }
            }
            Ok(Some(parts.join(",")))
        }
        Some(_) => Err(ConfigError(format!(
            "{field_name} must be a list of integers or a comma-separated string"
        ))),
    }
}

/// Three-way precedence: an explicit CLI value wins, then the config
/// file's value, then `default`.
///
/// `cli_value`/`config_value` of `None` mean "not given there" -- unlike
/// Python (where `0`/`""`/`False` need an explicit `is not None` check to
/// avoid being mistaken for "unset"), `Option::None` already carries that
/// distinction on its own, so this is just three `Option`s chained.
pub fn resolve<T>(cli_value: Option<T>, config_value: Option<T>, default: Option<T>) -> Option<T> {
    cli_value.or(config_value).or(default)
}

/// Set `root["a"]["b"]["c"] = value` for a dotted path `"a.b.c"`, creating
/// each intermediate table as needed. Used by [`crate::alliumrc`] to build
/// the same nested shape this module's TOML reader produces.
pub fn set_path(root: &mut Table, dotted: &str, value: Value) {
    let parts: Vec<&str> = dotted.split('.').collect();
    let mut node = root;
    for part in &parts[..parts.len().saturating_sub(1)] {
        let entry = node.entry((*part).to_string()).or_insert_with(|| Value::Table(Table::new()));
        if !matches!(entry, Value::Table(_)) {
            *entry = Value::Table(Table::new());
        }
        node = match entry {
            Value::Table(t) => t,
            _ => unreachable!(),
        };
    }
    if let Some(last) = parts.last() {
        node.insert((*last).to_string(), value);
    }
}

/// A minimal TOML reader covering the subset [`load_config`] needs. Kept
/// as its own private module (rather than pulled in as a dependency) for
/// the reasons given in this file's module doc.
mod toml_lite {
    use super::{Table, Value};

    struct Parser {
        chars: Vec<char>,
        pos: usize,
        line: usize,
    }

    pub fn parse(input: &str) -> Result<Table, String> {
        let mut p = Parser { chars: input.chars().collect(), pos: 0, line: 1 };
        p.parse_document()
    }

    impl Parser {
        fn peek(&self) -> Option<char> {
            self.chars.get(self.pos).copied()
        }

        fn peek_at(&self, k: usize) -> Option<char> {
            self.chars.get(self.pos + k).copied()
        }

        fn advance(&mut self) -> Option<char> {
            let c = self.peek();
            if let Some(ch) = c {
                self.pos += 1;
                if ch == '\n' {
                    self.line += 1;
                }
            }
            c
        }

        fn err<T>(&self, msg: impl Into<String>) -> Result<T, String> {
            Err(format!("line {}: {}", self.line, msg.into()))
        }

        fn skip_ws_no_newline(&mut self) {
            while matches!(self.peek(), Some(' ') | Some('\t')) {
                self.advance();
            }
        }

        fn skip_ws_and_comments_and_newlines(&mut self) {
            loop {
                match self.peek() {
                    Some(' ') | Some('\t') | Some('\n') | Some('\r') => {
                        self.advance();
                    }
                    Some('#') => {
                        while !matches!(self.peek(), Some('\n') | None) {
                            self.advance();
                        }
                    }
                    _ => break,
                }
            }
        }

        fn expect_line_end(&mut self) -> Result<(), String> {
            self.skip_ws_no_newline();
            match self.peek() {
                None => Ok(()),
                Some('\n') | Some('\r') => {
                    self.advance();
                    Ok(())
                }
                Some('#') => {
                    while !matches!(self.peek(), Some('\n') | None) {
                        self.advance();
                    }
                    Ok(())
                }
                Some(c) => self.err(format!("unexpected trailing character '{c}'")),
            }
        }

        fn parse_document(&mut self) -> Result<Table, String> {
            let mut root: Table = Table::new();
            let mut current_path: Vec<String> = Vec::new();
            loop {
                self.skip_ws_and_comments_and_newlines();
                if self.peek().is_none() {
                    break;
                }
                if self.peek() == Some('[') {
                    self.advance();
                    if self.peek() == Some('[') {
                        return self.err("array-of-tables ([[...]]) is not supported");
                    }
                    let path = self.parse_dotted_key()?;
                    self.skip_ws_no_newline();
                    if self.advance() != Some(']') {
                        return self.err("expected ']' to close a table header");
                    }
                    ensure_table_path(&mut root, &path)?;
                    current_path = path;
                    self.expect_line_end()?;
                    continue;
                }
                let mut key_path = self.parse_dotted_key()?;
                self.skip_ws_no_newline();
                if self.advance() != Some('=') {
                    return self.err("expected '=' after a key");
                }
                self.skip_ws_no_newline();
                let value = self.parse_value()?;
                self.expect_line_end()?;
                let mut full_path = current_path.clone();
                full_path.append(&mut key_path);
                set_path_checked(&root, &full_path)?;
                set_path_value(&mut root, &full_path, value);
            }
            Ok(root)
        }

        fn parse_dotted_key(&mut self) -> Result<Vec<String>, String> {
            let mut parts = Vec::new();
            loop {
                self.skip_ws_no_newline();
                parts.push(self.parse_key_part()?);
                self.skip_ws_no_newline();
                if self.peek() == Some('.') {
                    self.advance();
                    continue;
                }
                break;
            }
            Ok(parts)
        }

        fn parse_key_part(&mut self) -> Result<String, String> {
            match self.peek() {
                Some('"') => self.parse_basic_string(),
                Some('\'') => self.parse_literal_string(),
                _ => {
                    let mut s = String::new();
                    while let Some(c) = self.peek() {
                        if c.is_alphanumeric() || c == '_' || c == '-' {
                            s.push(c);
                            self.advance();
                        } else {
                            break;
                        }
                    }
                    if s.is_empty() {
                        return self.err("expected a key");
                    }
                    Ok(s)
                }
            }
        }

        fn parse_value(&mut self) -> Result<Value, String> {
            match self.peek() {
                Some('"') => Ok(Value::Str(self.parse_basic_string()?)),
                Some('\'') => Ok(Value::Str(self.parse_literal_string()?)),
                Some('[') => self.parse_array(),
                Some('{') => self.parse_inline_table(),
                Some('t') | Some('f') => self.parse_bool(),
                Some(c) if c.is_ascii_digit() || c == '-' || c == '+' => self.parse_number(),
                Some(c) => self.err(format!("unexpected character '{c}' starting a value")),
                None => self.err("unexpected end of input while expecting a value"),
            }
        }

        fn parse_basic_string(&mut self) -> Result<String, String> {
            self.advance(); // opening "
            let mut s = String::new();
            loop {
                match self.advance() {
                    None => return self.err("unterminated string"),
                    Some('"') => break,
                    Some('\\') => match self.advance() {
                        Some('"') => s.push('"'),
                        Some('\\') => s.push('\\'),
                        Some('n') => s.push('\n'),
                        Some('t') => s.push('\t'),
                        Some('r') => s.push('\r'),
                        Some('b') => s.push('\u{8}'),
                        Some('f') => s.push('\u{c}'),
                        Some('u') => {
                            let cp = self.parse_hex_escape(4)?;
                            s.push(char::from_u32(cp).ok_or("invalid \\u escape")?);
                        }
                        Some('U') => {
                            let cp = self.parse_hex_escape(8)?;
                            s.push(char::from_u32(cp).ok_or("invalid \\U escape")?);
                        }
                        Some(other) => return self.err(format!("unknown escape '\\{other}'")),
                        None => return self.err("unterminated escape sequence"),
                    },
                    Some(c) => s.push(c),
                }
            }
            Ok(s)
        }

        fn parse_hex_escape(&mut self, digits: usize) -> Result<u32, String> {
            let mut v: u32 = 0;
            for _ in 0..digits {
                let c = self.advance().ok_or("unterminated unicode escape")?;
                let d = c
                    .to_digit(16)
                    .ok_or_else(|| format!("invalid hex digit '{c}' in unicode escape"))?;
                v = v * 16 + d;
            }
            Ok(v)
        }

        fn parse_literal_string(&mut self) -> Result<String, String> {
            self.advance(); // opening '
            let mut s = String::new();
            loop {
                match self.advance() {
                    None => return self.err("unterminated string"),
                    Some('\'') => break,
                    Some(c) => s.push(c),
                }
            }
            Ok(s)
        }

        fn match_word(&mut self, word: &str) -> bool {
            let wchars: Vec<char> = word.chars().collect();
            for (i, wc) in wchars.iter().enumerate() {
                if self.peek_at(i) != Some(*wc) {
                    return false;
                }
            }
            if let Some(next) = self.peek_at(wchars.len()) {
                if next.is_alphanumeric() || next == '_' {
                    return false;
                }
            }
            for _ in 0..wchars.len() {
                self.advance();
            }
            true
        }

        fn parse_bool(&mut self) -> Result<Value, String> {
            if self.match_word("true") {
                Ok(Value::Bool(true))
            } else if self.match_word("false") {
                Ok(Value::Bool(false))
            } else {
                self.err("expected 'true' or 'false'")
            }
        }

        fn parse_number(&mut self) -> Result<Value, String> {
            let start = self.pos;
            if matches!(self.peek(), Some('+') | Some('-')) {
                self.advance();
            }
            let mut is_float = false;
            while let Some(c) = self.peek() {
                if c.is_ascii_digit() || c == '_' {
                    self.advance();
                } else if c == '.' && !is_float {
                    is_float = true;
                    self.advance();
                } else if c == 'e' || c == 'E' {
                    is_float = true;
                    self.advance();
                    if matches!(self.peek(), Some('+') | Some('-')) {
                        self.advance();
                    }
                } else {
                    break;
                }
            }
            let raw: String = self.chars[start..self.pos].iter().collect();
            let cleaned: String = raw.chars().filter(|&c| c != '_').collect();
            if cleaned.is_empty() || cleaned == "+" || cleaned == "-" {
                return self.err("invalid number");
            }
            if is_float {
                cleaned.parse::<f64>().map(Value::Float).map_err(|_| format!("invalid float '{raw}'"))
            } else {
                cleaned.parse::<i64>().map(Value::Int).map_err(|_| format!("invalid integer '{raw}'"))
            }
        }

        fn parse_array(&mut self) -> Result<Value, String> {
            self.advance(); // consume [
            let mut items = Vec::new();
            loop {
                self.skip_ws_and_comments_and_newlines();
                if self.peek() == Some(']') {
                    self.advance();
                    break;
                }
                items.push(self.parse_value()?);
                self.skip_ws_and_comments_and_newlines();
                match self.peek() {
                    Some(',') => {
                        self.advance();
                    }
                    Some(']') => {
                        self.advance();
                        break;
                    }
                    _ => return self.err("expected ',' or ']' in array"),
                }
            }
            Ok(Value::Array(items))
        }

        fn parse_inline_table(&mut self) -> Result<Value, String> {
            self.advance(); // consume {
            let mut table = Table::new();
            self.skip_ws_no_newline();
            if self.peek() == Some('}') {
                self.advance();
                return Ok(Value::Table(table));
            }
            loop {
                self.skip_ws_no_newline();
                let path = self.parse_dotted_key()?;
                self.skip_ws_no_newline();
                if self.advance() != Some('=') {
                    return self.err("expected '=' in inline table");
                }
                self.skip_ws_no_newline();
                let value = self.parse_value()?;
                set_path_checked(&table, &path)?;
                set_path_value(&mut table, &path, value);
                self.skip_ws_no_newline();
                match self.peek() {
                    Some(',') => {
                        self.advance();
                    }
                    Some('}') => {
                        self.advance();
                        break;
                    }
                    _ => return self.err("expected ',' or '}' in inline table"),
                }
            }
            Ok(Value::Table(table))
        }
    }

    fn ensure_table_path(root: &mut Table, path: &[String]) -> Result<(), String> {
        let mut node = root;
        for part in path {
            let entry = node.entry(part.clone()).or_insert_with(|| Value::Table(Table::new()));
            match entry {
                Value::Table(t) => node = t,
                _ => return Err(format!("cannot redefine '{part}' as a table")),
            }
        }
        Ok(())
    }

    /// TOML forbids redefining a key -- reject a duplicate assignment
    /// before `set_path_value` would silently overwrite it.
    fn set_path_checked(root: &Table, path: &[String]) -> Result<(), String> {
        let mut node = root;
        for part in &path[..path.len().saturating_sub(1)] {
            match node.get(part) {
                Some(Value::Table(t)) => node = t,
                Some(_) => return Err(format!("cannot use '{part}' as both a value and a table")),
                None => return Ok(()),
            }
        }
        if let Some(last) = path.last() {
            if node.contains_key(last) {
                return Err(format!("duplicate key '{last}'"));
            }
        }
        Ok(())
    }

    fn set_path_value(root: &mut Table, path: &[String], value: Value) {
        let mut node = root;
        for part in &path[..path.len().saturating_sub(1)] {
            let entry = node.entry(part.clone()).or_insert_with(|| Value::Table(Table::new()));
            node = match entry {
                Value::Table(t) => t,
                _ => unreachable!("checked by set_path_checked"),
            };
        }
        if let Some(last) = path.last() {
            node.insert(last.clone(), value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A fresh scratch file path under the OS temp dir, unique per test
    /// process/call (this crate avoids a `tempfile` dependency -- see
    /// `hiddenservice.rs`'s own `scratch_dir` helper for the same reasoning).
    fn scratch_toml(text: &str) -> std::path::PathBuf {
        let n = {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            COUNTER.fetch_add(1, Ordering::Relaxed)
        };
        let path = std::env::temp_dir()
            .join(format!("allium-config-test-{}-{n}.toml", std::process::id()));
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn missing_file_raises_configerror_not_a_raw_error() {
        let err = load_config(Path::new("/nonexistent/path/does-not-exist.toml")).unwrap_err();
        assert!(err.0.contains("not found"), "{}", err.0);
    }

    #[test]
    fn malformed_toml_raises_configerror() {
        let path = scratch_toml("this is not [valid toml");
        let err = load_config(&path).unwrap_err();
        assert!(err.0.contains("not valid TOML"), "{}", err.0);
    }

    #[test]
    fn valid_file_loads_as_a_plain_table() {
        let path = scratch_toml("role = \"guard\"\n\n[relay]\nbind = \"0.0.0.0:9001\"\n");
        let data = load_config(&path).unwrap();
        assert_eq!(data.get("role"), Some(&Value::Str("guard".to_string())));
        assert_eq!(
            data.get("relay").unwrap().as_table().unwrap().get("bind"),
            Some(&Value::Str("0.0.0.0:9001".to_string()))
        );
    }

    #[test]
    fn dotted_table_headers_and_arrays_and_inline_tables_parse() {
        let path = scratch_toml(
            "[relay.exit_policy]\nallow_ports = [80, 443, 8080]\n\n\
             [client]\ntrust = { guard = \"deadbeef\", middle = 'cafef00d' }\n\
             ratio = 1.5\nenabled = true\n# a comment\n",
        );
        let data = load_config(&path).unwrap();
        let relay = data.get("relay").unwrap().as_table().unwrap();
        let policy = relay.get("exit_policy").unwrap().as_table().unwrap();
        let ports = policy.get("allow_ports").unwrap().as_array().unwrap();
        assert_eq!(ports, &[Value::Int(80), Value::Int(443), Value::Int(8080)]);
        let client = data.get("client").unwrap().as_table().unwrap();
        assert_eq!(client.get("ratio"), Some(&Value::Float(1.5)));
        assert_eq!(client.get("enabled"), Some(&Value::Bool(true)));
        let trust = client.get("trust").unwrap().as_table().unwrap();
        assert_eq!(trust.get("guard").unwrap().as_str(), Some("deadbeef"));
        assert_eq!(trust.get("middle").unwrap().as_str(), Some("cafef00d"));
    }

    #[test]
    fn relay_section_defaults_to_empty_when_absent() {
        assert_eq!(relay_section(&Table::new()).unwrap(), Table::new());
    }

    #[test]
    fn relay_section_returns_the_table() {
        let mut relay = Table::new();
        relay.insert("bind".to_string(), Value::Str("0.0.0.0:9001".to_string()));
        let mut data = Table::new();
        data.insert("relay".to_string(), Value::Table(relay.clone()));
        assert_eq!(relay_section(&data).unwrap(), relay);
    }

    #[test]
    fn relay_section_wrong_type_raises() {
        let mut data = Table::new();
        data.insert("relay".to_string(), Value::Str("not a table".to_string()));
        assert!(relay_section(&data).is_err());
    }

    #[test]
    fn exit_policy_section_nests_under_relay() {
        let mut policy = Table::new();
        policy.insert("allow_ports".to_string(), Value::Array(vec![Value::Int(80), Value::Int(443)]));
        let mut relay = Table::new();
        relay.insert("exit_policy".to_string(), Value::Table(policy.clone()));
        let mut data = Table::new();
        data.insert("relay".to_string(), Value::Table(relay));
        assert_eq!(exit_policy_section(&data).unwrap(), policy);
    }

    #[test]
    fn exit_policy_section_defaults_empty_when_relay_absent() {
        assert_eq!(exit_policy_section(&Table::new()).unwrap(), Table::new());
    }

    #[test]
    fn client_section_and_trust_section() {
        let mut trust = Table::new();
        trust.insert("guard".to_string(), Value::Str("deadbeef".to_string()));
        let mut client = Table::new();
        client.insert("guard".to_string(), Value::Str("1.2.3.4:9001".to_string()));
        client.insert("trust".to_string(), Value::Table(trust.clone()));
        let mut data = Table::new();
        data.insert("client".to_string(), Value::Table(client));
        assert_eq!(client_section(&data).unwrap().get("guard").unwrap().as_str(), Some("1.2.3.4:9001"));
        assert_eq!(client_trust_section(&data).unwrap(), trust);
    }

    #[test]
    fn ports_to_flag_none_stays_none() {
        assert_eq!(ports_to_flag(None, "x").unwrap(), None);
    }

    #[test]
    fn ports_to_flag_string_passes_through_unchanged() {
        assert_eq!(ports_to_flag(Some(&Value::Str("80,443".to_string())), "x").unwrap(), Some("80,443".to_string()));
    }

    #[test]
    fn ports_to_flag_int_list_becomes_comma_string() {
        let v = Value::Array(vec![Value::Int(80), Value::Int(443), Value::Int(8080)]);
        assert_eq!(ports_to_flag(Some(&v), "x").unwrap(), Some("80,443,8080".to_string()));
    }

    #[test]
    fn ports_to_flag_empty_list_becomes_empty_string_not_none() {
        let v = Value::Array(vec![]);
        assert_eq!(ports_to_flag(Some(&v), "x").unwrap(), Some(String::new()));
    }

    #[test]
    fn ports_to_flag_bool_in_list_rejected() {
        let v = Value::Array(vec![Value::Int(80), Value::Bool(true)]);
        assert!(ports_to_flag(Some(&v), "x").is_err());
    }

    #[test]
    fn ports_to_flag_other_type_raises() {
        assert!(ports_to_flag(Some(&Value::Int(80)), "x").is_err());
    }

    #[test]
    fn resolve_cli_value_wins_over_everything() {
        assert_eq!(resolve(Some("cli"), Some("config"), Some("default")), Some("cli"));
    }

    #[test]
    fn resolve_config_value_wins_when_cli_is_none() {
        assert_eq!(resolve(None, Some("config"), Some("default")), Some("config"));
    }

    #[test]
    fn resolve_default_used_when_both_are_none() {
        assert_eq!(resolve(None::<&str>, None, Some("default")), Some("default"));
    }

    #[test]
    fn resolve_falsy_but_not_none_cli_value_still_wins() {
        assert_eq!(resolve(Some(0), Some(5), Some(9)), Some(0));
        assert_eq!(resolve(Some(""), Some("config"), Some("default")), Some(""));
        assert_eq!(resolve(Some(false), Some(true), Some(true)), Some(false));
    }
}
