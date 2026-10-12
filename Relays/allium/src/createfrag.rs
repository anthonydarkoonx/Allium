//! Splitting a too-large `CREATE` body across ordinary 1192-byte cells.
//!
//! * **Directly** (client -> guard, or relay -> next hop during EXTEND): each
//!   fragment is a [`Command::CreateFragment`](crate::cell::Command::CreateFragment)
//!   cell whose payload is `msg_id(4) || index(1) || count(1) || chunk`;
//!   [`CreateReassembler`] on the receiving relay puts them back together.
//! * **Through a circuit**: each fragment rides in its own onion-wrapped
//!   EXTEND layer, as `EXTEND_FRAGMENT_MARKER || msg_id || index || count || chunk`.
//!   [`ExtendReassembler`] collects them on the extending relay.

use crate::cell::{Cell, Command, PAYLOAD_SIZE};
use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;

pub const FRAGMENT_HEADER_SIZE: usize = 6;
/// Enough for a hybrid CREATE plus relay link token with room to spare
/// (4 * (PAYLOAD_SIZE - FRAGMENT_HEADER_SIZE) = 4 * 1178 = 4712 bytes);
/// anything claiming more is refused.
pub const MAX_FRAGMENTS: u8 = 4;
pub const EXTEND_FRAGMENT_MARKER: u8 = 0xE5;
const FRAGMENT_TTL_SECS: f64 = 10.0;
/// Entries a relay's `CreateReassembler` holds by default. A worst-case
/// entry is `MAX_FRAGMENTS` full cells (about 4.7 KB), so even full this is a
/// few megabytes; the larger table is what makes flooding it with forged
/// first fragments expensive.
pub const DEFAULT_CREATE_REASSEMBLER_ENTRIES: usize = 1024;
/// Most in-flight entries one *source* (see [`source_prefix`]) may hold. The
/// first fragment of a CREATE arrives before anything is authenticated, so
/// the table is an easy thing to flood; this stops a single source from
/// pushing everyone else's handshakes out of it. A source at its cap can
/// only replace its own oldest entry.
const MAX_PENDING_PER_SOURCE: usize = 16;

/// Error type for this module (mirrors Python's bare `ValueError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateFragError {
    pub message: String,
}
impl fmt::Display for CreateFragError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for CreateFragError {}
fn err(msg: impl Into<String>) -> CreateFragError {
    CreateFragError { message: msg.into() }
}

/// A reassembled CREATE: duck-types as a [`Cell`] (`circuit_id`/`command`/`payload`)
/// but without the 1184-byte cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateMessage {
    pub circuit_id: u32,
    pub command: Command,
    pub payload: Vec<u8>,
}

fn split(body: &[u8], chunk: usize) -> Vec<Vec<u8>> {
    if body.is_empty() {
        return vec![Vec::new()];
    }
    body.chunks(chunk).map(|c| c.to_vec()).collect()
}

/// Cut `body` into `CREATE_FRAGMENT` cells.
pub fn fragment_create(circuit_id: u32, body: &[u8], msg_id: Option<[u8; 4]>) -> Result<Vec<Cell>, CreateFragError> {
    let msg_id = match msg_id {
        Some(id) => id,
        None => random_msg_id()?,
    };
    let chunks = split(body, PAYLOAD_SIZE - FRAGMENT_HEADER_SIZE);
    if chunks.len() > MAX_FRAGMENTS as usize {
        return Err(err(format!("CREATE body of {} bytes needs too many fragments", body.len())));
    }
    let count = chunks.len() as u8;
    let mut cells = Vec::with_capacity(chunks.len());
    for (i, chunk) in chunks.into_iter().enumerate() {
        let mut payload = Vec::with_capacity(FRAGMENT_HEADER_SIZE + chunk.len());
        payload.extend_from_slice(&msg_id);
        payload.push(i as u8);
        payload.push(count);
        payload.extend_from_slice(&chunk);
        cells.push(
            Cell::with_command(circuit_id, Command::CreateFragment, payload)
                .expect("fragment payload always fits within PAYLOAD_SIZE"),
        );
    }
    Ok(cells)
}

/// Cut `body` into EXTEND-layer payloads of at most `budget` bytes.
pub fn fragment_extend_payload(body: &[u8], budget: i64, msg_id: Option<[u8; 4]>) -> Result<Vec<Vec<u8>>, CreateFragError> {
    let msg_id = match msg_id {
        Some(id) => id,
        None => random_msg_id()?,
    };
    let chunk = budget - 1 - FRAGMENT_HEADER_SIZE as i64;
    if chunk <= 0 {
        return Err(err("EXTEND budget too small to carry a fragment"));
    }
    let chunks = split(body, chunk as usize);
    if chunks.len() > (MAX_FRAGMENTS as usize) * 2 {
        return Err(err(format!("CREATE body of {} bytes needs too many EXTEND fragments", body.len())));
    }
    let count = chunks.len() as u8;
    let mut out = Vec::with_capacity(chunks.len());
    for (i, c) in chunks.into_iter().enumerate() {
        let mut payload = Vec::with_capacity(1 + FRAGMENT_HEADER_SIZE + c.len());
        payload.push(EXTEND_FRAGMENT_MARKER);
        payload.extend_from_slice(&msg_id);
        payload.push(i as u8);
        payload.push(count);
        payload.extend_from_slice(&c);
        out.push(payload);
    }
    Ok(out)
}

fn random_msg_id() -> Result<[u8; 4], CreateFragError> {
    let mut buf = [0u8; 4];
    crate::osrand::os_random(&mut buf).map_err(|e| err(e.to_string()))?;
    Ok(buf)
}

// --------------------------------------------------------------------------
// Assembler
// --------------------------------------------------------------------------

/// The "source" an incoming fragment is charged to: its network prefix (/24
/// for IPv4, /48 for IPv6, with IPv4-mapped IPv6 treated as IPv4), not the
/// exact address, so extra addresses on one subnet do not buy extra room.
/// Anything that does not parse as an IP address is used as-is.
fn source_prefix(host: &str) -> String {
    use std::net::IpAddr;
    let v4 = |o: [u8; 4]| format!("{}.{}.{}.0/24", o[0], o[1], o[2]);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => v4(a.octets()),
        Ok(IpAddr::V6(a)) => match a.to_ipv4_mapped() {
            Some(m) => v4(m.octets()),
            None => {
                let s = a.segments();
                format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
            }
        },
        Err(_) => host.to_string(),
    }
}

struct Entry {
    created_at: f64,
    count: u8,
    chunks: HashMap<u8, Vec<u8>>,
    /// Who sent the first fragment, when known (direct CREATEs; `None` for
    /// onion-wrapped EXTENDs, which arrive over an already-authenticated circuit).
    source: Option<String>,
}

struct Assembler<K: Eq + Hash + Clone> {
    max_entries: usize,
    max_count: u8,
    clock: Box<dyn Fn() -> f64>,
    pending: HashMap<K, Entry>,
    /// source -> how many entries it holds, kept in step by `remove_entry`.
    per_source: HashMap<String, usize>,
    pub dropped: u64,
}

impl<K: Eq + Hash + Clone> Assembler<K> {
    fn new(max_entries: usize, max_count: u8, clock: Box<dyn Fn() -> f64>) -> Assembler<K> {
        Assembler { max_entries, max_count, clock, pending: HashMap::new(), per_source: HashMap::new(), dropped: 0 }
    }

    /// Remove one entry and release its source's count.
    fn remove_entry(&mut self, key: &K) -> Option<Entry> {
        let entry = self.pending.remove(key)?;
        if let Some(src) = &entry.source {
            if let Some(n) = self.per_source.get_mut(src) {
                *n -= 1;
                if *n == 0 {
                    self.per_source.remove(src);
                }
            }
        }
        Some(entry)
    }

    fn expire(&mut self) {
        let now = (self.clock)();
        let stale: Vec<K> = self.pending.iter().filter(|(_, v)| now - v.created_at > FRAGMENT_TTL_SECS).map(|(k, _)| k.clone()).collect();
        for k in stale {
            self.remove_entry(&k);
        }
    }

    /// An entry may be evicted only while it holds at most one chunk: one that
    /// already has two or more is part-way through a real handshake.
    fn evictable(entry: &Entry) -> bool {
        entry.chunks.len() <= 1
    }

    /// Evict the oldest evictable entry satisfying `pick`; `false` if none.
    fn evict_oldest(&mut self, pick: impl Fn(&Entry) -> bool) -> bool {
        let victim = self
            .pending
            .iter()
            .filter(|(_, e)| Self::evictable(e) && pick(e))
            .min_by(|a, b| a.1.created_at.partial_cmp(&b.1.created_at).unwrap())
            .map(|(k, _)| k.clone());
        match victim {
            Some(k) => {
                self.remove_entry(&k);
                self.dropped += 1;
                true
            }
            None => false,
        }
    }

    /// Make room in a full table: evict the oldest evictable entry of the
    /// source holding the most entries (the likeliest flooder), never one
    /// with two or more chunks. `false` if every entry is part-way through.
    fn evict_for_room(&mut self) -> bool {
        let victim = self
            .pending
            .iter()
            .filter(|(_, e)| Self::evictable(e))
            .min_by(|a, b| {
                let held = |e: &Entry| e.source.as_ref().and_then(|s| self.per_source.get(s)).copied().unwrap_or(0);
                held(b.1).cmp(&held(a.1)).then(a.1.created_at.partial_cmp(&b.1.created_at).unwrap())
            })
            .map(|(k, _)| k.clone());
        match victim {
            Some(k) => {
                self.remove_entry(&k);
                self.dropped += 1;
                true
            }
            None => false,
        }
    }

    fn push(&mut self, key: K, index: u8, count: u8, chunk: &[u8]) -> Option<Vec<u8>> {
        self.push_from(None, key, index, count, chunk)
    }

    fn push_from(&mut self, source: Option<String>, key: K, index: u8, count: u8, chunk: &[u8]) -> Option<Vec<u8>> {
        self.push_from_gated(source, key, index, count, chunk, true)
    }

    /// [`Self::push_from`], except that with `allow_new` false a fragment may only join
    /// an entry that already exists and never starts one.
    fn push_from_gated(&mut self, source: Option<String>, key: K, index: u8, count: u8, chunk: &[u8], allow_new: bool) -> Option<Vec<u8>> {
        if count < 1 || count > self.max_count || index >= count {
            self.dropped += 1;
            return None;
        }
        self.expire();
        if !self.pending.contains_key(&key) {
            if !allow_new {
                self.dropped += 1;
                return None;
            }
            // A source at its cap can only replace its own oldest entry.
            if let Some(src) = &source {
                if self.per_source.get(src).copied().unwrap_or(0) >= MAX_PENDING_PER_SOURCE
                    && !self.evict_oldest(|e| e.source.as_ref() == Some(src))
                {
                    self.dropped += 1;
                    return None;
                }
            }
            if self.pending.len() >= self.max_entries && !self.evict_for_room() {
                self.dropped += 1;
                return None;
            }
            if let Some(src) = &source {
                *self.per_source.entry(src.clone()).or_insert(0) += 1;
            }
            self.pending.insert(key.clone(), Entry { created_at: (self.clock)(), count, chunks: HashMap::new(), source });
        }
        let entry = self.pending.get_mut(&key).unwrap();
        if entry.count != count {
            self.remove_entry(&key);
            self.dropped += 1;
            return None;
        }
        entry.chunks.insert(index, chunk.to_vec());
        if entry.chunks.len() < count as usize {
            return None;
        }
        let entry = self.remove_entry(&key).unwrap();
        let mut out = Vec::new();
        for i in 0..count {
            out.extend_from_slice(&entry.chunks[&i]);
        }
        Some(out)
    }
}

fn monotonic_clock() -> Box<dyn Fn() -> f64> {
    use std::time::Instant;
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    Box::new(|| {
        let start = *START.get_or_init(Instant::now);
        start.elapsed().as_secs_f64()
    })
}

/// Reassembles `CREATE_FRAGMENT` cells into a [`CreateMessage`].
pub struct CreateReassembler {
    inner: Assembler<(String, u16, u32, [u8; 4])>,
}

impl CreateReassembler {
    pub fn new(max_entries: usize) -> CreateReassembler {
        CreateReassembler { inner: Assembler::new(max_entries, MAX_FRAGMENTS, monotonic_clock()) }
    }

    pub fn with_clock(max_entries: usize, clock: Box<dyn Fn() -> f64>) -> CreateReassembler {
        CreateReassembler { inner: Assembler::new(max_entries, MAX_FRAGMENTS, clock) }
    }

    pub fn dropped(&self) -> u64 {
        self.inner.dropped
    }

    /// The fragment index and data chunk of a `CREATE_FRAGMENT` cell, if it is long enough
    /// to have a header.
    pub fn fragment_parts(cell: &Cell) -> Option<(u8, &[u8])> {
        let payload = &cell.payload;
        if payload.len() < FRAGMENT_HEADER_SIZE {
            return None;
        }
        Some((payload[4], &payload[FRAGMENT_HEADER_SIZE..]))
    }

    /// Entries currently being assembled.
    pub fn len(&self) -> usize {
        self.inner.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.pending.is_empty()
    }

    pub fn push(&mut self, cell: &Cell, peer_addr: (String, u16)) -> Option<CreateMessage> {
        self.push_gated(cell, peer_addr, true)
    }

    /// Like [`Self::push`], but with `allow_new` false a fragment only joins an entry that
    /// already exists; it never starts one (and is counted as dropped if there is none).
    pub fn push_gated(&mut self, cell: &Cell, peer_addr: (String, u16), allow_new: bool) -> Option<CreateMessage> {
        let payload = &cell.payload;
        if payload.len() < FRAGMENT_HEADER_SIZE {
            self.inner.dropped += 1;
            return None;
        }
        let msg_id: [u8; 4] = [payload[0], payload[1], payload[2], payload[3]];
        let index = payload[4];
        let count = payload[5];
        let key = (peer_addr.0, peer_addr.1, cell.circuit_id, msg_id);
        let source = Some(source_prefix(&key.0));
        let body = self.inner.push_from_gated(source, key, index, count, &payload[FRAGMENT_HEADER_SIZE..], allow_new)?;
        Some(CreateMessage { circuit_id: cell.circuit_id, command: Command::Create, payload: body })
    }
}

impl Default for CreateReassembler {
    fn default() -> Self {
        CreateReassembler::new(DEFAULT_CREATE_REASSEMBLER_ENTRIES)
    }
}

/// Reassembles EXTEND-fragment layer payloads for one circuit entry.
///
/// Generic over `K`, the caller's notion of "which circuit entry" (Python
/// accepts any hashable `entry_key`).
pub struct ExtendReassembler<K: Eq + Hash + Clone> {
    inner: Assembler<(K, [u8; 4])>,
}

impl<K: Eq + Hash + Clone> ExtendReassembler<K> {
    pub fn new(max_entries: usize) -> ExtendReassembler<K> {
        ExtendReassembler { inner: Assembler::new(max_entries, MAX_FRAGMENTS * 2, monotonic_clock()) }
    }

    pub fn with_clock(max_entries: usize, clock: Box<dyn Fn() -> f64>) -> ExtendReassembler<K> {
        ExtendReassembler { inner: Assembler::new(max_entries, MAX_FRAGMENTS * 2, clock) }
    }

    pub fn dropped(&self) -> u64 {
        self.inner.dropped
    }

    pub fn is_fragment(plaintext: &[u8]) -> bool {
        !plaintext.is_empty() && plaintext[0] == EXTEND_FRAGMENT_MARKER
    }

    pub fn push(&mut self, entry_key: K, plaintext: &[u8]) -> Option<Vec<u8>> {
        if plaintext.len() < 1 + FRAGMENT_HEADER_SIZE {
            self.inner.dropped += 1;
            return None;
        }
        let msg_id: [u8; 4] = [plaintext[1], plaintext[2], plaintext[3], plaintext[4]];
        let index = plaintext[5];
        let count = plaintext[6];
        self.inner.push((entry_key, msg_id), index, count, &plaintext[1 + FRAGMENT_HEADER_SIZE..])
    }
}

impl<K: Eq + Hash + Clone> Default for ExtendReassembler<K> {
    fn default() -> Self {
        ExtendReassembler::new(1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn fixed_clock(t: Rc<RefCell<f64>>) -> Box<dyn Fn() -> f64> {
        Box::new(move || *t.borrow())
    }

    #[test]
    fn test_fragment_create_single_fragment_small_body() {
        let cells = fragment_create(1, b"tiny body", Some([1, 2, 3, 4])).unwrap();
        assert_eq!(cells.len(), 1);
        assert_eq!(cells[0].command, Command::CreateFragment);
        assert_eq!(&cells[0].payload[..4], &[1, 2, 3, 4]);
        assert_eq!(cells[0].payload[4], 0); // index
        assert_eq!(cells[0].payload[5], 1); // count
    }

    #[test]
    fn test_fragment_create_splits_large_body() {
        let body = vec![7u8; (PAYLOAD_SIZE - FRAGMENT_HEADER_SIZE) * 2 + 10];
        let cells = fragment_create(1, &body, Some([0; 4])).unwrap();
        assert_eq!(cells.len(), 3);
        for (i, cell) in cells.iter().enumerate() {
            assert_eq!(cell.payload[4], i as u8);
            assert_eq!(cell.payload[5], 3);
        }
    }

    #[test]
    fn test_fragment_create_too_large_rejected() {
        let body = vec![0u8; (PAYLOAD_SIZE - FRAGMENT_HEADER_SIZE) * (MAX_FRAGMENTS as usize) + 1];
        assert!(fragment_create(1, &body, Some([0; 4])).is_err());
    }

    #[test]
    fn test_create_reassembler_round_trip() {
        let body = vec![9u8; (PAYLOAD_SIZE - FRAGMENT_HEADER_SIZE) * 2 + 5];
        let cells = fragment_create(42, &body, Some([1, 1, 1, 1])).unwrap();
        let mut r = CreateReassembler::default();
        let addr = ("1.2.3.4".to_string(), 9001u16);
        let mut result = None;
        for cell in &cells {
            result = r.push(cell, addr.clone());
        }
        let msg = result.unwrap();
        assert_eq!(msg.circuit_id, 42);
        assert_eq!(msg.command, Command::Create);
        assert_eq!(msg.payload, body);
    }

    #[test]
    fn test_create_reassembler_out_of_order() {
        let body = vec![3u8; (PAYLOAD_SIZE - FRAGMENT_HEADER_SIZE) * 2 + 5];
        let cells = fragment_create(1, &body, Some([2; 4])).unwrap();
        let mut r = CreateReassembler::default();
        let addr = ("1.2.3.4".to_string(), 9001u16);
        assert!(r.push(&cells[2], addr.clone()).is_none());
        assert!(r.push(&cells[0], addr.clone()).is_none());
        let msg = r.push(&cells[1], addr).unwrap();
        assert_eq!(msg.payload, body);
    }

    #[test]
    fn test_create_reassembler_drops_short_payload() {
        let mut r = CreateReassembler::default();
        let cell = Cell::with_command(1, Command::CreateFragment, vec![1, 2]).unwrap();
        assert!(r.push(&cell, ("1.2.3.4".to_string(), 1)).is_none());
        assert_eq!(r.dropped(), 1);
    }

    #[test]
    fn test_extend_reassembler_round_trip() {
        let body = vec![5u8; 300];
        let payloads = fragment_extend_payload(&body, 100, Some([9; 4])).unwrap();
        let mut r: ExtendReassembler<u32> = ExtendReassembler::default();
        let mut result = None;
        for p in &payloads {
            assert!(ExtendReassembler::<u32>::is_fragment(p));
            result = r.push(1, p);
        }
        assert_eq!(result.unwrap(), body);
    }

    #[test]
    fn test_extend_budget_too_small_rejected() {
        assert!(fragment_extend_payload(b"x", 3, Some([0; 4])).is_err());
    }

    #[test]
    fn test_is_fragment_false_for_regular_payload() {
        assert!(!ExtendReassembler::<u32>::is_fragment(b"\x02not-a-fragment"));
        assert!(!ExtendReassembler::<u32>::is_fragment(b""));
    }

    #[test]
    fn test_assembler_expires_stale_entries() {
        let t = Rc::new(RefCell::new(0.0));
        let mut r = CreateReassembler::with_clock(256, fixed_clock(t.clone()));
        let body = vec![1u8; (PAYLOAD_SIZE - FRAGMENT_HEADER_SIZE) * 2 + 1];
        let cells = fragment_create(1, &body, Some([4; 4])).unwrap();
        let addr = ("1.2.3.4".to_string(), 1u16);
        // Push only the first fragment, then let time pass well beyond the TTL.
        assert!(r.push(&cells[0], addr.clone()).is_none());
        *t.borrow_mut() = 100.0;
        // Pushing a *different* message triggers expiry of the stale one; the
        // remaining fragment of the first message now starts a fresh entry.
        let unrelated = fragment_create(1, b"x", Some([5; 4])).unwrap();
        assert!(r.push(&unrelated[0], addr.clone()).is_some());
        // The original message's second fragment now starts a brand new
        // (expired-then-recreated) entry rather than completing the old one.
        assert!(r.push(&cells[1], addr).is_none());
    }

    #[test]
    fn test_assembler_evicts_oldest_when_full() {
        let mut r = CreateReassembler::new(1);
        let addr = ("1.2.3.4".to_string(), 1u16);
        let a = fragment_create(1, &vec![1u8; (PAYLOAD_SIZE - FRAGMENT_HEADER_SIZE) * 2 + 1], Some([1; 4])).unwrap();
        let b = fragment_create(1, &vec![2u8; (PAYLOAD_SIZE - FRAGMENT_HEADER_SIZE) * 2 + 1], Some([2; 4])).unwrap();
        assert!(r.push(&a[0], addr.clone()).is_none()); // entry for msg [1;4] created
        assert!(r.push(&b[0], addr.clone()).is_none()); // evicts msg [1;4], creates msg [2;4]
        assert_eq!(r.dropped(), 1);
        // msg [1;4] is gone, so its remaining fragment starts a brand new entry
        assert!(r.push(&a[1], addr).is_none());
    }

    // -- flooding the table with forged first fragments --------------------

    fn three_cells(circuit_id: u32, msg_id: [u8; 4]) -> (Vec<u8>, Vec<Cell>) {
        let body = vec![0x5Au8; PAYLOAD_SIZE * 2 + 100];
        let cells = fragment_create(circuit_id, &body, Some(msg_id)).unwrap();
        assert!(cells.len() >= 3, "the tests below need a message of at least three fragments");
        (body, cells)
    }

    fn peer(host: &str) -> (String, u16) {
        (host.to_string(), 9001)
    }

    /// The attack: an honest handshake's first fragment is in the table when
    /// one network sprays far more than a table's worth of forged first
    /// fragments. Before the per-source cap the honest entry became the
    /// oldest and was evicted; now the flooder can only hold a handful.
    #[test]
    fn a_flood_from_one_network_cannot_evict_another_sources_handshake() {
        let mut r = CreateReassembler::new(256);
        let (body, honest) = three_cells(1, [9, 9, 9, 9]);
        r.push(&honest[0], peer("192.0.2.1"));

        for i in 0..5000u32 {
            let (_, forged) = three_cells(1000 + (i % 1000), i.to_be_bytes());
            r.push(&forged[0], (format!("198.51.100.{}", i % 250 + 1), 4000 + (i % 1000) as u16));
        }

        let mut done = None;
        for c in &honest[1..] {
            done = r.push(c, peer("192.0.2.1"));
        }
        assert_eq!(done.expect("the honest handshake must survive the flood").payload, body);
    }

    /// An entry that already has two or more chunks is part-way through a real
    /// handshake and must not be evicted by newcomers.
    #[test]
    fn an_entry_with_two_chunks_is_never_evicted_for_a_newcomer() {
        let mut r = CreateReassembler::new(3);
        let (body, honest) = three_cells(1, [1, 1, 1, 1]);
        r.push(&honest[0], peer("192.0.2.1"));
        r.push(&honest[1], peer("192.0.2.1")); // two of three chunks: now protected
        // newcomers from many different networks, far more than the table holds
        for i in 0..100u32 {
            let (_, other) = three_cells(500 + i, i.to_be_bytes());
            r.push(&other[0], (format!("203.0.{}.1", i % 250), 1));
        }
        let done = r.push(&honest[2], peer("192.0.2.1"));
        assert_eq!(done.expect("a part-way handshake must complete").payload, body);
    }

    /// Eviction must not turn into "refuse when full": against a flood from
    /// many different (spoofed) sources a new handshake still gets in by
    /// replacing the oldest single-chunk entry, and can complete.
    #[test]
    fn a_full_table_still_admits_a_new_handshake_by_evicting_the_oldest_single_chunk_entry() {
        let mut r = CreateReassembler::new(8);
        for i in 0..8u32 {
            let (_, c) = three_cells(10 + i, i.to_be_bytes());
            r.push(&c[0], (format!("203.0.{i}.1"), 1));
        }
        assert_eq!(r.inner.pending.len(), 8);
        let (body, newcomer) = three_cells(99, [7, 7, 7, 7]);
        let mut done = None;
        for c in &newcomer {
            done = r.push(c, peer("192.0.2.77"));
        }
        assert_eq!(done.expect("a full table must not turn away a new handshake").payload, body);
    }

    /// When every entry is already part-way through, there is nothing safe to
    /// evict, so the newcomer is refused rather than hurting a real handshake.
    #[test]
    fn a_table_full_of_part_way_handshakes_refuses_a_newcomer() {
        let mut r = CreateReassembler::new(2);
        for i in 0..2u32 {
            let (_, c) = three_cells(20 + i, i.to_be_bytes());
            r.push(&c[0], (format!("203.0.{i}.1"), 1));
            r.push(&c[1], (format!("203.0.{i}.1"), 1));
        }
        let before = r.dropped();
        let (_, newcomer) = three_cells(77, [4, 4, 4, 4]);
        assert!(r.push(&newcomer[0], peer("192.0.2.9")).is_none());
        assert_eq!(r.inner.pending.len(), 2);
        assert_eq!(r.dropped(), before + 1);
    }

    /// Addresses on one network share one allowance, and a source at its cap
    /// only ever replaces its own entries.
    #[test]
    fn sources_are_grouped_by_network_and_a_capped_source_replaces_only_its_own() {
        let mut r = CreateReassembler::new(1024);
        let (_, honest) = three_cells(1, [8, 8, 8, 8]);
        r.push(&honest[0], peer("192.0.2.1"));
        for i in 0..40u32 {
            let (_, c) = three_cells(300 + i, i.to_be_bytes());
            r.push(&c[0], (format!("10.0.0.{}", i + 1), 1)); // different hosts, one /24
        }
        assert_eq!(r.inner.per_source.get("10.0.0.0/24").copied(), Some(MAX_PENDING_PER_SOURCE));
        assert_eq!(r.inner.per_source.get("192.0.2.0/24").copied(), Some(1), "another network's entry is untouched");
        assert_eq!(r.inner.pending.len(), MAX_PENDING_PER_SOURCE + 1);
    }

    /// The per-source counts must always agree with the table, whatever
    /// removed an entry (completion, expiry, eviction, mismatched count).
    #[test]
    fn per_source_accounting_returns_to_zero() {
        use std::cell::Cell as StdCell;
        use std::rc::Rc;
        let now = Rc::new(StdCell::new(0.0f64));
        let clock_now = now.clone();
        let mut r = CreateReassembler::with_clock(64, Box::new(move || clock_now.get()));

        // completed
        let (_, done) = three_cells(1, [1, 0, 0, 0]);
        for c in &done {
            r.push(c, peer("192.0.2.1"));
        }
        // evicted by the per-source cap
        for i in 0..(MAX_PENDING_PER_SOURCE as u32 + 5) {
            let (_, c) = three_cells(100 + i, i.to_be_bytes());
            r.push(&c[0], (format!("198.51.100.{}", i + 1), 1));
        }
        // a mismatched fragment count removes its entry
        let (_, a) = three_cells(2, [2, 0, 0, 0]);
        r.push(&a[0], peer("203.0.113.5"));
        let mut bad = a[1].clone();
        bad.payload[5] = bad.payload[5].wrapping_add(1); // claims a different fragment count
        r.push(&bad, peer("203.0.113.5"));

        let counted: usize = r.inner.per_source.values().sum();
        assert_eq!(counted, r.inner.pending.len(), "per-source counts must match the table");

        // and expiry empties both
        now.set(FRAGMENT_TTL_SECS + 1.0);
        let (_, late) = three_cells(3, [3, 0, 0, 0]);
        r.push(&late[0], peer("192.0.2.200"));
        assert_eq!(r.inner.pending.len(), 1);
        assert_eq!(r.inner.per_source.values().sum::<usize>(), 1);
    }

    #[test]
    fn source_prefix_groups_by_network() {
        assert_eq!(source_prefix("203.0.113.7"), "203.0.113.0/24");
        assert_eq!(source_prefix("203.0.113.250"), "203.0.113.0/24");
        assert_ne!(source_prefix("203.0.114.7"), source_prefix("203.0.113.7"));
        assert_eq!(source_prefix("2001:db8:1:2::1"), "2001:db8:1::/48");
        assert_eq!(source_prefix("2001:db8:1:ffff::9"), "2001:db8:1::/48");
        assert_eq!(source_prefix("::ffff:203.0.113.7"), source_prefix("203.0.113.7"));
        assert_eq!(source_prefix("not-an-ip"), "not-an-ip");
    }

    /// Fair eviction on its own: with a full table, the victim comes from the
    /// source holding the most entries, even when another source's entry is
    /// older. (Plain "evict the globally oldest" would drop the innocent one.)
    #[test]
    fn a_full_table_evicts_from_the_source_holding_the_most_not_the_globally_oldest() {
        let mut r = CreateReassembler::new(12);
        // the innocent source's entry is the OLDEST in the table
        let (_, innocent) = three_cells(1, [1, 1, 1, 1]);
        r.push(&innocent[0], peer("192.0.2.1"));
        // a heavier source holds ten entries (under the per-source cap)
        for i in 0..10u32 {
            let (_, c) = three_cells(100 + i, i.to_be_bytes());
            r.push(&c[0], (format!("198.51.100.{}", i + 1), 1));
        }
        // one more small source fills the table
        let (_, other) = three_cells(2, [2, 2, 2, 2]);
        r.push(&other[0], peer("203.0.113.5"));
        assert_eq!(r.inner.pending.len(), 12);

        // a newcomer arrives at a full table
        let (_, newcomer) = three_cells(3, [3, 3, 3, 3]);
        r.push(&newcomer[0], peer("192.0.2.200"));

        assert_eq!(r.inner.per_source.get("198.51.100.0/24").copied(), Some(9), "the heaviest source gave up an entry");
        assert!(r.inner.per_source.contains_key("192.0.2.0/24"), "the oldest, innocent entry must survive");
        assert_eq!(r.inner.pending.len(), 12);
    }

    // -- #11: a fragment may be barred from starting an entry --

    #[test]
    fn push_gated_without_permission_never_starts_an_entry_but_joins_one_that_exists() {
        let body: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        let cells = fragment_create(7, &body, Some([1, 2, 3, 4])).unwrap();
        assert_eq!(cells.len(), 3);
        let mut r = CreateReassembler::new(16);
        let peer = ("203.0.113.9".to_string(), 4000u16);

        assert!(r.push_gated(&cells[1], peer.clone(), false).is_none());
        assert!(r.is_empty(), "a barred fragment starts nothing");
        assert_eq!(r.dropped(), 1);

        assert!(r.push_gated(&cells[0], peer.clone(), true).is_none());
        assert_eq!(r.len(), 1);
        assert!(r.push_gated(&cells[1], peer.clone(), false).is_none(), "joins the existing entry");
        assert_eq!(r.len(), 1);
        let done = r.push_gated(&cells[2], peer, false).expect("the last fragment completes it");
        assert_eq!(done.payload, body);
        assert!(r.is_empty());
    }

    #[test]
    fn fragment_parts_reads_the_index_and_chunk() {
        let cells = fragment_create(7, &vec![9u8; 2000], Some([0, 0, 0, 1])).unwrap();
        let (index, chunk) = CreateReassembler::fragment_parts(&cells[1]).unwrap();
        assert_eq!(index, 1);
        assert_eq!(chunk.len(), 2000 - (PAYLOAD_SIZE - FRAGMENT_HEADER_SIZE));
        let short = Cell::with_command(7, Command::CreateFragment, vec![1, 2, 3]).unwrap();
        assert!(CreateReassembler::fragment_parts(&short).is_none());
    }
}
