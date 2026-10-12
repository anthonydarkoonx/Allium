//! Exit policy and abuse controls: default-deny, rate limits, amplification caps.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Instant;

/// Ports a default-deny exit allows for TCP out of the box.
pub const DEFAULT_ALLOWED_TCP_PORTS: [u16; 4] = [80, 443, 8080, 8443];
/// Ports allowed for UDP by default. Empty on purpose.
pub const DEFAULT_ALLOWED_UDP_PORTS: [u16; 0] = [];

/// Sustained UDP packets per second allowed to a single destination address.
pub const DEFAULT_UDP_RATE: f64 = 50.0;
/// How many datagrams may burst above the sustained rate before throttling.
pub const DEFAULT_UDP_BURST: u32 = 100;
/// Largest response:request byte ratio an exit will relay.
pub const DEFAULT_MAX_AMPLIFICATION: f64 = 10.0;
/// How long an [`AmplificationGuard`] stream may sit untouched before eviction.
pub const DEFAULT_AMPLIFICATION_IDLE_TTL: f64 = 300.0;
/// Default inactivity timeout for a session lease, in seconds.
pub const DEFAULT_LEASE_TIMEOUT: f64 = 30.0;

/// Ports refused even if an operator lists them, unless they opt in knowingly.
pub fn blocked_amplification_ports() -> &'static HashMap<u16, &'static str> {
    use std::sync::OnceLock;
    static MAP: OnceLock<HashMap<u16, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        HashMap::from([
            (53u16, "DNS (amplification factor ~50x)"),
            (123, "NTP monlist (amplification factor ~550x)"),
            (1900, "SSDP (amplification factor ~30x)"),
            (5353, "mDNS"),
            (11211, "memcached (amplification factor ~50000x)"),
            (389, "CLDAP (amplification factor ~70x)"),
            (161, "SNMP"),
        ])
    })
}

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

/// Base class for policy/abuse-control errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    Generic(String),
    Denied(PolicyDenied),
    RateLimit(RateLimitExceeded),
    Amplification(AmplificationExceeded),
}
impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::Generic(s) => write!(f, "{s}"),
            PolicyError::Denied(e) => write!(f, "{e}"),
            PolicyError::RateLimit(e) => write!(f, "{e}"),
            PolicyError::Amplification(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for PolicyError {}
fn generic(msg: impl Into<String>) -> PolicyError {
    PolicyError::Generic(msg.into())
}

/// A destination is not allowed by the exit policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDenied {
    pub message: String,
}
impl fmt::Display for PolicyDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for PolicyDenied {}
impl From<PolicyDenied> for PolicyError {
    fn from(e: PolicyDenied) -> Self {
        PolicyError::Denied(e)
    }
}

/// A destination address is over its rate limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitExceeded {
    pub message: String,
}
impl fmt::Display for RateLimitExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for RateLimitExceeded {}
impl From<RateLimitExceeded> for PolicyError {
    fn from(e: RateLimitExceeded) -> Self {
        PolicyError::RateLimit(e)
    }
}

/// A response is implausibly larger than the request that triggered it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmplificationExceeded {
    pub message: String,
}
impl fmt::Display for AmplificationExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for AmplificationExceeded {}
impl From<AmplificationExceeded> for PolicyError {
    fn from(e: AmplificationExceeded) -> Self {
        PolicyError::Amplification(e)
    }
}

// --------------------------------------------------------------------------
// Address canonicalization
// --------------------------------------------------------------------------

/// Parse a BSD `inet_aton`-style address: 1-4 dot-separated parts, each
/// decimal, octal (leading `0`) or hex (leading `0x`/`0X`), the last part
/// absorbing the remaining bits. Returns `None` if `text` does not parse
/// this way.
fn inet_aton(text: &str) -> Option<u32> {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut values: Vec<u64> = Vec::with_capacity(parts.len());
    for p in &parts {
        if p.is_empty() {
            return None;
        }
        let v = if let Some(hex) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
            if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            u64::from_str_radix(hex, 16).ok()?
        } else if p.len() > 1 && p.starts_with('0') {
            if !p.chars().all(|c| ('0'..='7').contains(&c)) {
                return None;
            }
            u64::from_str_radix(p, 8).ok()?
        } else {
            if !p.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            p.parse::<u64>().ok()?
        };
        values.push(v);
    }
    let n = values.len();
    for (i, &v) in values.iter().enumerate() {
        let is_last = i == n - 1;
        let max = if is_last {
            match n {
                1 => u32::MAX as u64,
                2 => 0x00FF_FFFF,
                3 => 0x0000_FFFF,
                _ => 0xFF,
            }
        } else {
            0xFF
        };
        if v > max {
            return None;
        }
    }
    let addr: u32 = match n {
        1 => values[0] as u32,
        2 => ((values[0] as u32) << 24) | (values[1] as u32),
        3 => ((values[0] as u32) << 24) | ((values[1] as u32) << 16) | (values[2] as u32),
        4 => {
            ((values[0] as u32) << 24)
                | ((values[1] as u32) << 16)
                | ((values[2] as u32) << 8)
                | (values[3] as u32)
        }
        _ => return None,
    };
    Some(addr)
}

/// Normalize a textual address so variants compare equal.
///
/// The plain-hostname fallback below used to return `text` verbatim, so
/// `deny_hosts` (and anything
/// else keying off this function's output, e.g. the rate limiter) treated
/// two different-case spellings of the same hostname as unrelated --
/// `EXAMPLE.com` would sail straight past a `deny_hosts` entry for
/// `example.com`. DNS hostnames are case-insensitive, so this lowercases
/// the fallback branch too, matching the IP-literal branches above (which
/// were already effectively case-insensitive: `Ipv4Addr`/`Ipv6Addr::
/// to_string()` produce fixed-case output regardless of how the input was
/// spelled).
pub fn canonical_host(host: &str) -> String {
    let text = host.trim();
    if text.is_empty() {
        return text.to_string();
    }
    if let Ok(ip) = IpAddr::from_str(text) {
        return ip.to_string();
    }
    // A bracketed and/or zone-qualified IPv6 literal ("[::1]",
    // "fe80::1%eth0", "[fe80::1%eth0]") fails the plain parse above --
    // `IpAddr::from_str` understands neither URI-style brackets nor a
    // zone/scope id (Rust's std has no zone-aware IP parser at all). Strip
    // both and retry before falling through to the opaque-hostname
    // handling below; otherwise these forms silently skip every
    // loopback/private/link-local check instead of being classified
    // correctly (the zone only disambiguates which interface a link-local
    // address routes over, not which address it is, so dropping it here
    // is safe for a private/local classification).
    let stripped = text.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(text);
    let stripped = match stripped.split_once('%') {
        Some((addr, _zone)) => addr,
        None => stripped,
    };
    if stripped != text {
        if let Ok(ip) = IpAddr::from_str(stripped) {
            return ip.to_string();
        }
    }
    if let Some(addr) = inet_aton(text) {
        return Ipv4Addr::from(addr).to_string();
    }
    text.to_lowercase()
}

fn ipv4_is_reserved(ip: &Ipv4Addr) -> bool {
    // 240.0.0.0/4 (class E), excluding the all-ones broadcast address, which
    // Python's `ipaddress.IPv4Address.is_reserved` also excludes.
    let o = ip.octets();
    o[0] >= 240 && *ip != Ipv4Addr::new(255, 255, 255, 255)
}

/// `0.0.0.0/8`, "this network" (RFC 791 §3.2) -- a distinct, older
/// reservation `ipv4_is_reserved` (240.0.0.0/4) doesn't cover, and nothing
/// else here catches besides the single address `0.0.0.0` itself (via
/// `is_unspecified`).
fn ipv4_is_this_network(ip: &Ipv4Addr) -> bool {
    ip.octets()[0] == 0
}

/// `100.64.0.0/10`, the CGNAT "Shared Address Space" block (RFC 6598) --
/// distinct from RFC 1918 private space (`is_private` doesn't cover it),
/// but no less internal: used by ISPs/cloud providers for carrier-grade
/// NAT, so a destination here is never meant to be reachable from outside
/// that operator's own network.
fn ipv4_is_shared_address_space(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (64..=127).contains(&o[1])
}

fn ipv6_is_unique_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn ipv6_is_unicast_link_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// The IPv4 address embedded in an IPv4-*compatible* IPv6 literal
/// (`::a.b.c.d`, the `::/96` prefix), distinct from the IPv4-*mapped*
/// form (`::ffff:a.b.c.d`) `to_ipv4_mapped()` already unwraps below.
/// `to_ipv4_mapped()` returns `None` for this older form, so without this
/// helper `::10.0.0.1`/`::127.0.0.1` skip every private/loopback check
/// entirely and are classified as public.
fn ipv4_compatible(ip: &Ipv6Addr) -> Option<Ipv4Addr> {
    let seg = ip.segments();
    if seg[0..6] == [0, 0, 0, 0, 0, 0] {
        let o = ip.octets();
        Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]))
    } else {
        None
    }
}

/// Whether `host` names a loopback/private/link-local address.
pub fn is_private_or_local(host: &str) -> bool {
    let canon = canonical_host(host);
    match IpAddr::from_str(&canon) {
        Err(_) => false,
        Ok(IpAddr::V4(ip)) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ipv4_is_reserved(&ip)
                || ip.is_multicast()
                || ip.is_unspecified()
                // `ipv4_is_reserved` deliberately excludes the all-ones
                // broadcast address (matching Python's
                // `ipaddress.IPv4Address.is_reserved`), and nothing else
                // here catches it either -- checked separately so
                // 255.255.255.255 is still refused as a destination.
                || ip.is_broadcast()
                || ipv4_is_this_network(&ip)
                || ipv4_is_shared_address_space(&ip)
        }
        Ok(IpAddr::V6(ip)) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ipv6_is_unique_local(&ip)
                || ipv6_is_unicast_link_local(&ip)
                || ip.to_ipv4_mapped().map(|v4| is_private_or_local(&v4.to_string())).unwrap_or(false)
                || ipv4_compatible(&ip).map(|v4| is_private_or_local(&v4.to_string())).unwrap_or(false)
        }
    }
}

// --------------------------------------------------------------------------
// ExitPolicy
// --------------------------------------------------------------------------

/// Default-deny allow-list of destinations an exit will forward to.
#[derive(Debug)]
pub struct ExitPolicy {
    pub allow_amplification_ports: bool,
    pub allow_private: bool,
    pub deny_hosts: HashSet<String>,
    pub allow_tcp: HashSet<u16>,
    pub allow_udp: HashSet<u16>,
}

impl ExitPolicy {
    pub fn new(
        allow_tcp: &[u16],
        allow_udp: &[u16],
        allow_amplification_ports: bool,
        allow_private: bool,
        deny_hosts: &[&str],
    ) -> Result<ExitPolicy, PolicyError> {
        let deny_hosts: HashSet<String> = deny_hosts.iter().map(|h| canonical_host(h)).collect();
        let clean = |ports: &[u16]| -> Result<HashSet<u16>, PolicyError> {
            let mut cleaned = HashSet::new();
            for &port in ports {
                if port == 0 {
                    return Err(generic(format!("port must be in 1..65535, got {port}")));
                }
                if !allow_amplification_ports {
                    if let Some(reason) = blocked_amplification_ports().get(&port) {
                        return Err(generic(format!(
                            "port {port} is a known amplification vector ({reason}); pass \
                             allow_amplification_ports=True to permit it deliberately"
                        )));
                    }
                }
                cleaned.insert(port);
            }
            Ok(cleaned)
        };
        Ok(ExitPolicy {
            allow_amplification_ports,
            allow_private,
            deny_hosts,
            allow_tcp: clean(allow_tcp)?,
            allow_udp: clean(allow_udp)?,
        })
    }

    pub fn with_defaults() -> ExitPolicy {
        ExitPolicy::new(&DEFAULT_ALLOWED_TCP_PORTS, &DEFAULT_ALLOWED_UDP_PORTS, false, false, &[]).unwrap()
    }

    pub fn allowed(&self, host: &str, port: u16, udp: bool) -> bool {
        self.check(host, port, udp).is_ok()
    }

    /// Raise [`PolicyDenied`] if `host` fails the host-level rules.
    pub fn check_host(&self, host: &str) -> Result<(), PolicyDenied> {
        let host = canonical_host(host);
        if self.deny_hosts.contains(&host) {
            return Err(PolicyDenied { message: format!("destination {host} is explicitly denied") });
        }
        if !self.allow_private && is_private_or_local(&host) {
            return Err(PolicyDenied {
                message: format!("destination {host} is private/loopback and allow_private is off"),
            });
        }
        Ok(())
    }

    pub fn host_allowed(&self, host: &str) -> bool {
        self.check_host(host).is_ok()
    }

    /// Raise [`PolicyDenied`] if this destination is not permitted.
    pub fn check(&self, host: &str, port: u16, udp: bool) -> Result<(), PolicyDenied> {
        self.check_host(host)?;
        let allowed = if udp { &self.allow_udp } else { &self.allow_tcp };
        if !allowed.contains(&port) {
            let kind = if udp { "UDP" } else { "TCP" };
            let mut sorted: Vec<u16> = allowed.iter().copied().collect();
            sorted.sort_unstable();
            let list = if sorted.is_empty() { "empty".to_string() } else { format!("{sorted:?}") };
            return Err(PolicyDenied {
                message: format!("{kind} port {port} is not in this exit's allow-list ({list})"),
            });
        }
        Ok(())
    }
}

impl fmt::Display for ExitPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut tcp: Vec<u16> = self.allow_tcp.iter().copied().collect();
        tcp.sort_unstable();
        let mut udp: Vec<u16> = self.allow_udp.iter().copied().collect();
        udp.sort_unstable();
        write!(f, "ExitPolicy(tcp={tcp:?}, udp={udp:?}, private={})", self.allow_private)
    }
}

// --------------------------------------------------------------------------
// Clock
// --------------------------------------------------------------------------

/// An injectable monotonic-seconds clock.
///
/// `+ Send` (2026-09-26, finding MH2): `RateLimiter`/`LeaseTable` embed
/// this, and `nat::NatAgent`/`NatRendezvous` in turn embed a `RateLimiter`
/// -- for either to move into the dedicated OS thread
/// `directory::register_over_circuit`'s blocking `CircuitBuilder` call
/// runs on, every field (transitively) needs to be `Send`. Matches
/// `Directory`'s own `clock: Box<dyn Fn() -> f64 + Send>`.
pub type Clock = Box<dyn Fn() -> f64 + Send>;

fn real_clock() -> Clock {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    Box::new(|| START.get_or_init(Instant::now).elapsed().as_secs_f64())
}

// --------------------------------------------------------------------------
// RateLimiter
// --------------------------------------------------------------------------

/// A per-key token bucket, bounding sustained send rate.
pub struct RateLimiter {
    pub rate: f64,
    pub burst: u32,
    clock: Clock,
    buckets: HashMap<String, (f64, f64)>, // (tokens, last_seen)
    pub throttled: u64,
    pub idle_ttl: f64,
    pub reap_interval: f64,
    last_reap: f64,
    pub expired: u64,
}

impl RateLimiter {
    pub fn new(
        rate: f64,
        burst: u32,
        clock: Option<Clock>,
        idle_ttl: Option<f64>,
        reap_interval: Option<f64>,
    ) -> Result<RateLimiter, PolicyError> {
        if rate <= 0.0 {
            return Err(generic(format!("rate must be positive, got {rate}")));
        }
        if burst < 1 {
            return Err(generic(format!("burst must be at least 1, got {burst}")));
        }
        let clock = clock.unwrap_or_else(real_clock);
        let idle_ttl = idle_ttl.unwrap_or_else(|| (burst as f64 / rate).max(1.0));
        let reap_interval = reap_interval.unwrap_or(idle_ttl);
        let last_reap = clock();
        Ok(RateLimiter { rate, burst, clock, buckets: HashMap::new(), throttled: 0, idle_ttl, reap_interval, last_reap, expired: 0 })
    }

    pub fn with_defaults() -> RateLimiter {
        RateLimiter::new(DEFAULT_UDP_RATE, DEFAULT_UDP_BURST, None, None, None).unwrap()
    }

    #[cfg(test)]
    fn bucket_keys(&self) -> Vec<String> {
        self.buckets.keys().cloned().collect()
    }

    /// Consume `cost` tokens for `key`, returning whether it may proceed.
    pub fn allow(&mut self, key: &str, cost: f64) -> bool {
        let now = (self.clock)();
        self.maybe_reap(now);
        let burst = self.burst as f64;
        let entry = self.buckets.entry(key.to_string()).or_insert((burst, now));
        let elapsed = (now - entry.1).max(0.0);
        entry.0 = burst.min(entry.0 + elapsed * self.rate);
        entry.1 = now;
        if entry.0 >= cost {
            entry.0 -= cost;
            true
        } else {
            self.throttled += 1;
            false
        }
    }

    /// Like [`RateLimiter::allow`], but returns an error on refusal.
    pub fn check(&mut self, key: &str, cost: f64) -> Result<(), RateLimitExceeded> {
        if !self.allow(key, cost) {
            return Err(RateLimitExceeded { message: format!("rate limit exceeded for {key}") });
        }
        Ok(())
    }

    /// The current token count for `key` (refilled, not consumed).
    pub fn tokens(&self, key: &str) -> f64 {
        let burst = self.burst as f64;
        match self.buckets.get(key) {
            None => burst,
            Some(&(tokens, last)) => {
                let elapsed = ((self.clock)() - last).max(0.0);
                burst.min(tokens + elapsed * self.rate)
            }
        }
    }

    fn maybe_reap(&mut self, now: f64) {
        if now - self.last_reap < self.reap_interval {
            return;
        }
        self.last_reap = now;
        self.reap(Some(now));
    }

    /// Evict buckets idle for at least `idle_ttl` seconds.
    pub fn reap(&mut self, now: Option<f64>) -> usize {
        let now = now.unwrap_or_else(|| (self.clock)());
        let cutoff = now - self.idle_ttl;
        let stale: Vec<String> = self.buckets.iter().filter(|(_, &(_, last))| last <= cutoff).map(|(k, _)| k.clone()).collect();
        for k in &stale {
            self.buckets.remove(k);
        }
        self.expired += stale.len() as u64;
        stale.len()
    }
}

impl fmt::Display for RateLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RateLimiter(rate={}/s, burst={}, keys={}, throttled={}, expired={})",
            self.rate, self.burst, self.buckets.len(), self.throttled, self.expired
        )
    }
}

// --------------------------------------------------------------------------
// AmplificationGuard
// --------------------------------------------------------------------------

/// Refuses to relay a response implausibly larger than its trigger.
pub struct AmplificationGuard {
    pub max_ratio: f64,
    pub min_request_bytes: i64,
    pub min_response_bytes: i64,
    pub refused: u64,
    sent: HashMap<String, i64>,
    received: HashMap<String, i64>,
    clock: Clock,
    last_touch: HashMap<String, f64>,
    pub idle_ttl: f64,
    pub reap_interval: f64,
    last_reap: f64,
    pub expired: u64,
}

impl AmplificationGuard {
    pub fn new(
        max_ratio: f64,
        min_request_bytes: i64,
        min_response_bytes: i64,
        clock: Option<Clock>,
        idle_ttl: Option<f64>,
        reap_interval: Option<f64>,
    ) -> Result<AmplificationGuard, PolicyError> {
        if max_ratio < 1.0 {
            return Err(generic(format!("max_ratio must be at least 1.0, got {max_ratio}")));
        }
        let clock = clock.unwrap_or_else(real_clock);
        let idle_ttl = idle_ttl.unwrap_or(DEFAULT_AMPLIFICATION_IDLE_TTL);
        let reap_interval = reap_interval.unwrap_or(idle_ttl);
        let last_reap = clock();
        Ok(AmplificationGuard {
            max_ratio,
            min_request_bytes,
            min_response_bytes,
            refused: 0,
            sent: HashMap::new(),
            received: HashMap::new(),
            clock,
            last_touch: HashMap::new(),
            idle_ttl,
            reap_interval,
            last_reap,
            expired: 0,
        })
    }

    pub fn with_defaults() -> AmplificationGuard {
        AmplificationGuard::new(DEFAULT_MAX_AMPLIFICATION, 64, 512, None, None, None).unwrap()
    }

    #[cfg(test)]
    fn received_for(&self, stream_id: &str) -> Option<i64> {
        self.received.get(stream_id).copied()
    }

    fn touch(&mut self, key: &str, now: f64) {
        self.last_touch.insert(key.to_string(), now);
    }

    /// Record `size` bytes a client sent toward a destination.
    pub fn track_request(&mut self, stream_id: &str, size: i64) {
        let now = (self.clock)();
        self.maybe_reap(now);
        *self.sent.entry(stream_id.to_string()).or_insert(0) += size;
        self.touch(stream_id, now);
    }

    /// Record a response and error if it exceeds the amplification ratio.
    pub fn check_response(&mut self, stream_id: &str, size: i64) -> Result<(), AmplificationExceeded> {
        let now = (self.clock)();
        self.maybe_reap(now);
        let sent = *self.sent.get(stream_id).unwrap_or(&0);
        let projected = self.received.get(stream_id).unwrap_or(&0) + size;
        let enforce = projected >= self.min_response_bytes;
        let effective_sent = sent.max(self.min_request_bytes);
        if enforce && (projected as f64) > (effective_sent as f64) * self.max_ratio {
            self.refused += 1;
            return Err(AmplificationExceeded {
                message: format!("response {projected}B exceeds {}x the {sent}B request; refusing to relay", self.max_ratio),
            });
        }
        self.received.insert(stream_id.to_string(), projected);
        self.touch(stream_id, now);
        Ok(())
    }

    /// Whether a response may be relayed; records it when allowed.
    pub fn allow_response(&mut self, stream_id: &str, size: i64) -> bool {
        self.check_response(stream_id, size).is_ok()
    }

    /// Drop bookkeeping for a finished stream.
    pub fn forget(&mut self, stream_id: &str) {
        self.sent.remove(stream_id);
        self.received.remove(stream_id);
        self.last_touch.remove(stream_id);
    }

    fn maybe_reap(&mut self, now: f64) {
        if now - self.last_reap < self.reap_interval {
            return;
        }
        self.last_reap = now;
        self.reap(Some(now));
    }

    /// Evict streams idle for at least `idle_ttl` seconds.
    pub fn reap(&mut self, now: Option<f64>) -> usize {
        let now = now.unwrap_or_else(|| (self.clock)());
        let cutoff = now - self.idle_ttl;
        let stale: Vec<String> = self.last_touch.iter().filter(|(_, &touched)| touched <= cutoff).map(|(k, _)| k.clone()).collect();
        for key in &stale {
            self.sent.remove(key);
            self.received.remove(key);
            self.last_touch.remove(key);
        }
        self.expired += stale.len() as u64;
        stale.len()
    }
}

impl fmt::Display for AmplificationGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AmplificationGuard(max_ratio={}, streams={}, refused={}, expired={})",
            self.max_ratio, self.sent.len(), self.refused, self.expired
        )
    }
}

// --------------------------------------------------------------------------
// SessionLease / LeaseTable
// --------------------------------------------------------------------------

/// A short-lived grant of exit state to one client's stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLease {
    pub token: Vec<u8>,
    pub client: (String, u16),
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Tracks short-lived session leases, expiring them on inactivity.
pub struct LeaseTable {
    pub timeout: f64,
    clock: Clock,
    leases: HashMap<Vec<u8>, SessionLeaseF>,
    pub expired: u64,
}

// Internal float-timed representation (SessionLease above uses i64 seconds
// for a simpler, hashable public type; internally we keep float precision).
#[derive(Debug, Clone)]
struct SessionLeaseF {
    token: Vec<u8>,
    client: (String, u16),
    issued_at: f64,
    expires_at: f64,
}

impl LeaseTable {
    pub fn new(timeout: f64, clock: Option<Clock>) -> Result<LeaseTable, PolicyError> {
        if timeout <= 0.0 {
            return Err(generic(format!("timeout must be positive, got {timeout}")));
        }
        Ok(LeaseTable { timeout, clock: clock.unwrap_or_else(real_clock), leases: HashMap::new(), expired: 0 })
    }

    pub fn with_defaults() -> LeaseTable {
        LeaseTable::new(DEFAULT_LEASE_TIMEOUT, None).unwrap()
    }

    fn to_public(l: &SessionLeaseF) -> SessionLease {
        SessionLease {
            token: l.token.clone(),
            client: l.client.clone(),
            issued_at: l.issued_at as i64,
            expires_at: l.expires_at as i64,
        }
    }

    /// Grant a fresh lease to `client`, returning it. `token` defaults to 16
    /// random bytes when `None`.
    pub fn issue(&mut self, client: (String, u16), token: Option<Vec<u8>>) -> Result<SessionLease, PolicyError> {
        let now = (self.clock)();
        let token = match token {
            Some(t) => t,
            None => random_16_bytes()?,
        };
        let lease = SessionLeaseF { token: token.clone(), client, issued_at: now, expires_at: now + self.timeout };
        self.leases.insert(token, lease.clone());
        Ok(LeaseTable::to_public(&lease))
    }

    /// Extend a lease on activity, returning it or `None` if lapsed.
    pub fn renew(&mut self, token: &[u8]) -> Option<SessionLease> {
        let now = (self.clock)();
        let expired;
        {
            let lease = self.leases.get(token)?;
            expired = now > lease.expires_at;
        }
        if expired {
            self.leases.remove(token);
            self.expired += 1;
            return None;
        }
        let lease = self.leases.get_mut(token).unwrap();
        lease.expires_at = now + self.timeout;
        Some(LeaseTable::to_public(lease))
    }

    /// Whether `token` names a live (unexpired) lease.
    pub fn valid(&self, token: &[u8]) -> bool {
        match self.leases.get(token) {
            None => false,
            Some(lease) => (self.clock)() <= lease.expires_at,
        }
    }

    /// Drop expired leases, returning how many were removed.
    pub fn reap(&mut self) -> usize {
        let now = (self.clock)();
        let stale: Vec<Vec<u8>> = self.leases.iter().filter(|(_, l)| now > l.expires_at).map(|(t, _)| t.clone()).collect();
        for t in &stale {
            self.leases.remove(t);
        }
        self.expired += stale.len() as u64;
        stale.len()
    }

    /// Drop a lease explicitly, returning whether it existed.
    pub fn release(&mut self, token: &[u8]) -> bool {
        self.leases.remove(token).is_some()
    }

    pub fn len(&self) -> usize {
        self.leases.len()
    }
    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }
}

impl fmt::Display for LeaseTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LeaseTable(active={}, timeout={}s, expired={})", self.leases.len(), self.timeout, self.expired)
    }
}

fn random_16_bytes() -> Result<Vec<u8>, PolicyError> {
    let mut buf = vec![0u8; 16];
    crate::osrand::os_random(&mut buf).map_err(|e| generic(e.to_string()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct FakeClock {
        now: Arc<Mutex<f64>>,
    }
    impl FakeClock {
        fn new(start: f64) -> (FakeClock, Arc<Mutex<f64>>) {
            let now = Arc::new(Mutex::new(start));
            (FakeClock { now: now.clone() }, now)
        }
        fn boxed(&self) -> Clock {
            let now = self.now.clone();
            Box::new(move || *now.lock().unwrap())
        }
    }

    fn advance(now: &Arc<Mutex<f64>>, secs: f64) {
        *now.lock().unwrap() += secs;
    }

    // -- ExitPolicy defaults -----------------------------------------------------
    #[test]
    fn test_tcp_defaults_are_the_web_ports() {
        let set: HashSet<u16> = DEFAULT_ALLOWED_TCP_PORTS.iter().copied().collect();
        assert_eq!(set, HashSet::from([80, 443, 8080, 8443]));
    }

    #[test]
    fn test_udp_defaults_are_empty() {
        assert!(DEFAULT_ALLOWED_UDP_PORTS.is_empty());
    }

    // -- ExitPolicy -----------------------------------------------------
    fn policy() -> ExitPolicy {
        ExitPolicy::new(&[80, 443], &[3478], false, false, &[]).unwrap()
    }

    #[test]
    fn test_allowed_tcp_port_passes() {
        let p = policy();
        assert!(p.allowed("1.2.3.4", 443, false));
        assert!(p.check("1.2.3.4", 443, false).is_ok());
    }

    #[test]
    fn test_unlisted_tcp_port_is_denied() {
        let p = policy();
        assert!(!p.allowed("1.2.3.4", 25, false));
        assert!(p.check("1.2.3.4", 25, false).is_err());
    }

    #[test]
    fn test_udp_uses_its_own_allow_list() {
        let p = policy();
        assert!(p.allowed("1.2.3.4", 3478, true));
        assert!(!p.allowed("1.2.3.4", 3478, false));
        assert!(!p.allowed("1.2.3.4", 443, true));
    }

    #[test]
    fn test_udp_is_denied_by_default() {
        let p = ExitPolicy::new(&[80], &[], false, false, &[]).unwrap();
        assert!(!p.allowed("1.2.3.4", 53, true));
        assert!(!p.allowed("1.2.3.4", 3478, true));
    }

    #[test]
    fn test_dns_port_is_rejected_at_construction() {
        let err = ExitPolicy::new(&[], &[53], false, false, &[]).unwrap_err();
        assert!(err.to_string().contains("amplification"));
    }

    #[test]
    fn test_other_amplification_ports_are_rejected() {
        for &port in blocked_amplification_ports().keys() {
            assert!(ExitPolicy::new(&[], &[port], false, false, &[]).is_err());
        }
    }

    #[test]
    fn test_amplification_ports_need_an_explicit_opt_in() {
        let p = ExitPolicy::new(&[], &[53], true, false, &[]).unwrap();
        assert!(p.allowed("1.2.3.4", 53, true));
    }

    #[test]
    fn test_private_addresses_are_denied_by_default() {
        let p = policy();
        for host in ["127.0.0.1", "192.168.1.1", "10.0.0.5", "169.254.1.1", "::1"] {
            assert!(!p.allowed(host, 443, false));
        }
    }

    #[test]
    fn test_private_addresses_allowed_with_the_switch() {
        let p = ExitPolicy::new(&[443], &[], false, true, &[]).unwrap();
        assert!(p.allowed("192.168.1.1", 443, false));
    }

    #[test]
    fn test_hostnames_are_not_statically_refused() {
        let p = policy();
        assert!(p.allowed("example.com", 443, false));
    }

    #[test]
    fn test_deny_hosts_overrides_an_allowed_port() {
        let p = ExitPolicy::new(&[443], &[], false, false, &["1.2.3.4"]).unwrap();
        assert!(!p.allowed("1.2.3.4", 443, false));
        assert!(p.allowed("5.6.7.8", 443, false));
    }

    #[test]
    fn test_invalid_port_is_rejected() {
        assert!(ExitPolicy::new(&[0], &[], false, false, &[]).is_err());
    }

    #[test]
    fn test_is_private_or_local_helper() {
        assert!(is_private_or_local("127.0.0.1"));
        assert!(is_private_or_local("10.1.2.3"));
        assert!(is_private_or_local("fe80::1"));
        assert!(!is_private_or_local("8.8.8.8"));
        assert!(!is_private_or_local("example.com"));
    }

    #[test]
    fn test_is_private_or_local_ipv4_compatible_ipv6() {
        assert!(is_private_or_local("::127.0.0.1"));
        assert!(is_private_or_local("::10.0.0.1"));
        assert!(is_private_or_local("::ffff:10.0.0.1"));
        assert!(!is_private_or_local("::93.184.216.34"));
    }

    #[test]
    fn test_is_private_or_local_blocks_the_broadcast_address() {
        assert!(is_private_or_local("255.255.255.255"));
    }

    #[test]
    fn test_is_private_or_local_bracketed_and_zone_qualified_ipv6() {
        assert!(is_private_or_local("[::1]"));
        assert!(is_private_or_local("fe80::1%eth0"));
        assert!(is_private_or_local("[fe80::1%eth0]"));
        assert!(is_private_or_local("[::10.0.0.1]"));
        assert!(!is_private_or_local("[2001:4860:4860::8888]"));
        assert!(!is_private_or_local("example.com%eth0"));
    }

    #[test]
    fn test_is_private_or_local_blocks_this_network_and_cgnat() {
        assert!(is_private_or_local("0.0.0.0"));
        assert!(is_private_or_local("0.1.2.3"));
        assert!(is_private_or_local("100.64.0.1"));
        assert!(is_private_or_local("100.127.255.255"));
        assert!(!is_private_or_local("100.63.255.255"));
        assert!(!is_private_or_local("100.128.0.0"));
    }

    #[test]
    fn test_display_reports_the_lists() {
        assert!(format!("{}", policy()).contains("tcp="));
    }

    // -- RateLimiter -----------------------------------------------------
    #[test]
    fn test_burst_then_throttle() {
        let (fc, _now) = FakeClock::new(0.0);
        let mut rl = RateLimiter::new(1.0, 3, Some(fc.boxed()), None, None).unwrap();
        let results: Vec<bool> = (0..5).map(|_| rl.allow("a", 1.0)).collect();
        assert_eq!(results, vec![true, true, true, false, false]);
        assert_eq!(rl.throttled, 2);
    }

    #[test]
    fn test_tokens_refill_over_time() {
        let (fc, now) = FakeClock::new(0.0);
        let mut rl = RateLimiter::new(2.0, 3, Some(fc.boxed()), None, None).unwrap();
        for _ in 0..3 {
            rl.allow("a", 1.0);
        }
        assert!(!rl.allow("a", 1.0));
        advance(&now, 1.0);
        assert!(rl.allow("a", 1.0));
        assert!(rl.allow("a", 1.0));
        assert!(!rl.allow("a", 1.0));
    }

    #[test]
    fn test_refill_is_capped_at_burst() {
        let (fc, now) = FakeClock::new(0.0);
        let mut rl = RateLimiter::new(1.0, 3, Some(fc.boxed()), None, None).unwrap();
        rl.allow("a", 1.0);
        advance(&now, 1000.0);
        assert_eq!(rl.tokens("a"), 3.0);
    }

    #[test]
    fn test_buckets_are_per_key() {
        let (fc, _now) = FakeClock::new(0.0);
        let mut rl = RateLimiter::new(1.0, 1, Some(fc.boxed()), None, None).unwrap();
        assert!(rl.allow("a", 1.0));
        assert!(!rl.allow("a", 1.0));
        assert!(rl.allow("b", 1.0));
    }

    #[test]
    fn test_check_raises_when_throttled() {
        let (fc, _now) = FakeClock::new(0.0);
        let mut rl = RateLimiter::new(1.0, 1, Some(fc.boxed()), None, None).unwrap();
        rl.allow("a", 1.0);
        assert!(rl.check("a", 1.0).is_err());
    }

    #[test]
    fn test_bad_parameters_are_rejected() {
        assert!(RateLimiter::new(0.0, DEFAULT_UDP_BURST, None, None, None).is_err());
        assert!(RateLimiter::new(DEFAULT_UDP_RATE, 0, None, None, None).is_err());
    }

    #[test]
    fn test_display_reports_throttle_count() {
        assert!(format!("{}", RateLimiter::with_defaults()).contains("throttled="));
    }

    #[test]
    fn test_idle_buckets_are_reaped_without_bound() {
        let (fc, now) = FakeClock::new(0.0);
        let mut rl = RateLimiter::new(1.0, 1, Some(fc.boxed()), None, None).unwrap();
        for i in 0..50 {
            rl.allow(&format!("10.0.0.{i}"), 1.0);
            advance(&now, rl.idle_ttl + 1.0);
        }
        assert!(rl.bucket_keys().len() < 50);
        assert!(rl.expired > 0);
    }

    #[test]
    fn test_reap_default_ttl_never_changes_observable_behavior() {
        let (fc, now) = FakeClock::new(0.0);
        let mut rl = RateLimiter::new(2.0, 5, Some(fc.boxed()), None, None).unwrap();
        rl.allow("a", 1.0);
        advance(&now, rl.idle_ttl);
        assert_eq!(rl.tokens("a"), 5.0);
        let evicted = rl.reap(None);
        assert_eq!(evicted, 1);
        assert_eq!(rl.tokens("a"), 5.0);
    }

    #[test]
    fn test_reap_leaves_recently_touched_buckets() {
        let (fc, _now) = FakeClock::new(0.0);
        let mut rl = RateLimiter::new(1.0, 3, Some(fc.boxed()), None, None).unwrap();
        rl.allow("a", 1.0);
        assert_eq!(rl.reap(None), 0);
        assert!(rl.bucket_keys().contains(&"a".to_string()));
    }

    // -- AmplificationGuard -----------------------------------------------------
    #[test]
    fn test_large_amplification_is_refused() {
        let mut guard = AmplificationGuard::new(10.0, 64, 512, None, None, None).unwrap();
        guard.track_request("1", 64);
        assert!(!guard.allow_response("1", 4000));
        assert_eq!(guard.refused, 1);
    }

    #[test]
    fn test_modest_amplification_is_allowed() {
        let mut guard = AmplificationGuard::new(10.0, 64, 512, None, None, None).unwrap();
        guard.track_request("1", 600);
        assert!(guard.allow_response("1", 4000));
    }

    #[test]
    fn test_check_raises_with_details() {
        let mut guard = AmplificationGuard::new(2.0, 64, 512, None, None, None).unwrap();
        guard.track_request("1", 1000);
        assert!(guard.check_response("1", 5000).is_err());
    }

    #[test]
    fn test_small_requests_are_clamped_not_exempted() {
        let mut guard = AmplificationGuard::new(2.0, 64, 512, None, None, None).unwrap();
        guard.track_request("1", 10);
        assert!(!guard.allow_response("1", 4000));
    }

    #[test]
    fn test_small_responses_bypass_the_ratio() {
        let mut guard = AmplificationGuard::new(2.0, 64, 512, None, None, None).unwrap();
        guard.track_request("1", 64);
        assert!(guard.allow_response("1", 100));
    }

    #[test]
    fn test_cumulative_response_volume_is_capped() {
        let mut guard = AmplificationGuard::new(10.0, 64, 100, None, None, None).unwrap();
        guard.track_request("1", 100);
        let mut allowed = 0;
        for _ in 0..20 {
            if guard.allow_response("1", 100) {
                allowed += 1;
            }
        }
        assert!(allowed <= 10);
    }

    #[test]
    fn test_streams_are_independent() {
        let mut guard = AmplificationGuard::new(2.0, 64, 512, None, None, None).unwrap();
        guard.track_request("1", 1000);
        guard.track_request("2", 2000);
        assert!(guard.allow_response("2", 3900));
    }

    #[test]
    fn test_forget_clears_a_stream() {
        let mut guard = AmplificationGuard::new(2.0, 64, 512, None, None, None).unwrap();
        guard.track_request("1", 64);
        guard.forget("1");
        guard.track_request("1", 2000);
        assert!(guard.allow_response("1", 3900));
    }

    #[test]
    fn test_bad_ratio_is_rejected() {
        assert!(AmplificationGuard::new(0.5, 64, 512, None, None, None).is_err());
    }

    #[test]
    fn test_display_reports_refusals() {
        assert!(format!("{}", AmplificationGuard::with_defaults()).contains("refused="));
    }

    #[test]
    fn test_a_refused_chunk_is_not_added_to_the_total() {
        let mut guard = AmplificationGuard::new(10.0, 64, 512, None, None, None).unwrap();
        guard.track_request("1", 100);
        assert!(guard.allow_response("1", 600));
        assert!(!guard.allow_response("1", 600));
        assert_eq!(guard.received_for("1"), Some(600));
    }

    #[test]
    fn test_a_stream_is_not_wedged_by_one_oversized_chunk() {
        let mut guard = AmplificationGuard::new(10.0, 64, 512, None, None, None).unwrap();
        guard.track_request("1", 100);
        assert!(!guard.allow_response("1", 9000));
        assert!(guard.allow_response("1", 100));
    }

    #[test]
    fn test_refusals_are_still_counted() {
        let mut guard = AmplificationGuard::new(10.0, 64, 512, None, None, None).unwrap();
        guard.track_request("1", 100);
        guard.allow_response("1", 9000);
        assert_eq!(guard.refused, 1);
    }

    // -- address canonicalization -----------------------------------------------------
    #[test]
    fn test_inet_aton_short_forms_are_recognised_as_private() {
        let p = ExitPolicy::new(&[80], &[], false, false, &[]).unwrap();
        for host in ["2130706433", "0x7f000001", "0177.0.0.1", "127.1"] {
            assert!(is_private_or_local(host), "{host}");
            assert!(!p.allowed(host, 80, false), "{host}");
        }
    }

    #[test]
    fn test_deny_hosts_cannot_be_dodged_by_whitespace_or_padding() {
        let p = ExitPolicy::new(&[80], &[], false, false, &["1.2.3.4"]).unwrap();
        for host in ["1.2.3.4", " 1.2.3.4", "1.2.3.04"] {
            assert!(!p.allowed(host, 80, false), "{host}");
        }
    }

    #[test]
    fn test_deny_hosts_are_canonicalized_at_construction() {
        let p = ExitPolicy::new(&[80], &[], false, false, &["127.1"]).unwrap();
        assert!(!p.allowed("127.0.0.1", 80, false));
    }

    /// A plain hostname must canonicalize case-insensitively, matching DNS's
    /// own case-insensitivity -- two
    /// different-case spellings of the same hostname are the same
    /// destination and must be treated identically by `deny_hosts` (and
    /// anything else keying off `canonical_host`).
    #[test]
    fn test_canonical_host_lowercases_plain_hostnames() {
        assert_eq!(canonical_host("Example.COM"), "example.com");
        assert_eq!(canonical_host("  Example.COM  "), "example.com");
        // IP-literal forms were already effectively case-insensitive
        // (nothing here to lowercase); confirms this fix doesn't disturb
        // that existing behavior.
        assert_eq!(canonical_host("127.0.0.1"), "127.0.0.1");
    }

    #[test]
    fn test_deny_hosts_cannot_be_dodged_by_letter_case() {
        let p = ExitPolicy::new(&[80], &[], false, false, &["evil.example"]).unwrap();
        for host in ["evil.example", "Evil.Example", "EVIL.EXAMPLE"] {
            assert!(!p.allowed(host, 80, false), "{host}");
        }
    }

    // -- LeaseTable -----------------------------------------------------
    #[test]
    fn test_issue_grants_a_live_lease() {
        let (fc, _now) = FakeClock::new(0.0);
        let mut leases = LeaseTable::new(30.0, Some(fc.boxed())).unwrap();
        let lease = leases.issue(("10.0.0.1".to_string(), 5000), None).unwrap();
        assert!(leases.valid(&lease.token));
        assert_eq!(lease.token.len(), 16);
        assert_eq!(lease.client, ("10.0.0.1".to_string(), 5000));
    }

    #[test]
    fn test_activity_renews_the_lease() {
        let (fc, now) = FakeClock::new(0.0);
        let mut leases = LeaseTable::new(30.0, Some(fc.boxed())).unwrap();
        let lease = leases.issue(("10.0.0.1".to_string(), 5000), None).unwrap();
        advance(&now, 20.0);
        assert!(leases.renew(&lease.token).is_some());
        advance(&now, 20.0);
        assert!(leases.valid(&lease.token));
    }

    #[test]
    fn test_silence_lets_the_lease_lapse() {
        let (fc, now) = FakeClock::new(0.0);
        let mut leases = LeaseTable::new(30.0, Some(fc.boxed())).unwrap();
        let lease = leases.issue(("10.0.0.1".to_string(), 5000), None).unwrap();
        advance(&now, 31.0);
        assert!(!leases.valid(&lease.token));
    }

    #[test]
    fn test_renewing_a_lapsed_lease_returns_none() {
        let (fc, now) = FakeClock::new(0.0);
        let mut leases = LeaseTable::new(30.0, Some(fc.boxed())).unwrap();
        let lease = leases.issue(("10.0.0.1".to_string(), 5000), None).unwrap();
        advance(&now, 31.0);
        assert!(leases.renew(&lease.token).is_none());
        assert_eq!(leases.expired, 1);
    }

    #[test]
    fn test_reap_removes_lapsed_leases() {
        let (fc, now) = FakeClock::new(0.0);
        let mut leases = LeaseTable::new(30.0, Some(fc.boxed())).unwrap();
        leases.issue(("10.0.0.1".to_string(), 5000), None).unwrap();
        leases.issue(("10.0.0.2".to_string(), 5001), None).unwrap();
        assert_eq!(leases.len(), 2);
        advance(&now, 31.0);
        assert_eq!(leases.reap(), 2);
        assert_eq!(leases.len(), 0);
        assert_eq!(leases.expired, 2);
    }

    #[test]
    fn test_reap_keeps_live_leases() {
        let (fc, now) = FakeClock::new(0.0);
        let mut leases = LeaseTable::new(30.0, Some(fc.boxed())).unwrap();
        let live = leases.issue(("10.0.0.1".to_string(), 5000), None).unwrap();
        advance(&now, 10.0);
        leases.issue(("10.0.0.2".to_string(), 5001), None).unwrap();
        assert_eq!(leases.reap(), 0);
        assert!(leases.valid(&live.token));
    }

    #[test]
    fn test_release_drops_a_lease() {
        let (fc, _now) = FakeClock::new(0.0);
        let mut leases = LeaseTable::new(30.0, Some(fc.boxed())).unwrap();
        let lease = leases.issue(("10.0.0.1".to_string(), 5000), None).unwrap();
        assert!(leases.release(&lease.token));
        assert!(!leases.release(&lease.token));
        assert!(!leases.valid(&lease.token));
    }

    #[test]
    fn test_explicit_token_is_honoured() {
        let (fc, _now) = FakeClock::new(0.0);
        let mut leases = LeaseTable::new(30.0, Some(fc.boxed())).unwrap();
        let lease = leases.issue(("10.0.0.1".to_string(), 5000), Some(vec![b'x'; 16])).unwrap();
        assert_eq!(lease.token, vec![b'x'; 16]);
        assert!(leases.valid(&vec![b'x'; 16]));
    }

    #[test]
    fn test_bad_timeout_is_rejected() {
        assert!(LeaseTable::new(0.0, None).is_err());
    }

    #[test]
    fn test_default_timeout_is_aggressive() {
        assert_eq!(DEFAULT_LEASE_TIMEOUT, 30.0);
        assert_eq!(LeaseTable::with_defaults().timeout, 30.0);
    }

    #[test]
    fn test_display_reports_counts() {
        let (fc, _now) = FakeClock::new(0.0);
        let mut leases = LeaseTable::new(30.0, Some(fc.boxed())).unwrap();
        leases.issue(("10.0.0.1".to_string(), 5000), None).unwrap();
        assert!(format!("{leases}").contains("active=1"));
    }
}
