//! Splitting a too-large CREATE body across ordinary 1192-byte cells.
//!
//! The post-quantum hybrid handshake ([`crate::handshake`], version 3)
//! carries an ML-KEM-768 ciphertext (1088 bytes), so its CREATE body no
//! longer fits one 1184-byte cell payload. Rather than send one oversized
//! UDP datagram (which would break Allium's everything-is-1192-bytes
//! invariant and risk IP fragmentation), the body is cut into a few
//! fragments:
//!
//! * **Directly** (client -> guard, or relay -> next hop during EXTEND):
//!   each fragment is a [`Command::CreateFragment`] cell whose payload is
//!   `msg_id(4) || index(1) || count(1) || chunk`; [`CreateReassembler`]
//!   on the receiving relay puts them back together.
//! * **Through a circuit** (the client's EXTEND request to the last hop
//!   built so far): each fragment rides in its own onion-wrapped EXTEND
//!   layer, as `EXTEND_FRAGMENT_MARKER || msg_id || index || count ||
//!   chunk` -- distinguishable from a whole CREATE body because that
//!   always begins with a handshake version byte (2 or 3).
//!   [`ExtendReassembler`] collects them on the extending relay.
//!
//! Both reassemblers are bounded in entries, fragments per message and
//! age, since the first fragment of a CREATE arrives before anything is
//! authenticated: an attacker spraying first-fragments can at most churn
//! a small, fixed-size table.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

use crate::cell::{Cell, CellError, Command, PAYLOAD_SIZE};
use crate::osrand;
use crate::reliability::{Clock, SystemClock};

pub const FRAGMENT_HEADER_SIZE: usize = 6;
/// Enough for a hybrid CREATE plus relay link token with room to spare
/// (4 * (PAYLOAD_SIZE - FRAGMENT_HEADER_SIZE) = 4 * 1178 = 4712 bytes);
/// anything claiming more is refused.
pub const MAX_FRAGMENTS: u8 = 4;
pub const EXTEND_FRAGMENT_MARKER: u8 = 0xE5;
const FRAGMENT_TTL_SECONDS: f64 = 10.0;

/// A CREATE-fragmentation invariant was violated: too many fragments, or
/// a malformed reassembly key/body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateFragError(pub String);

impl std::fmt::Display for CreateFragError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for CreateFragError {}

impl From<CellError> for CreateFragError {
    fn from(e: CellError) -> Self {
        CreateFragError(e.to_string())
    }
}

/// A reassembled CREATE: duck-types as a [`Cell`] (`circuit_id`/`command`/
/// `payload`) but without the 1184-byte cap.
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

/// Cut `body` into CREATE_FRAGMENT cells.
///
/// # Errors
/// Returns [`CreateFragError`] if `body` needs more than [`MAX_FRAGMENTS`]
/// fragments.
pub fn fragment_create(circuit_id: u32, body: &[u8], msg_id: Option<[u8; 4]>) -> Result<Vec<Cell>, CreateFragError> {
    let msg_id = msg_id.unwrap_or_else(random_msg_id);
    let chunks = split(body, PAYLOAD_SIZE - FRAGMENT_HEADER_SIZE);
    if chunks.len() > MAX_FRAGMENTS as usize {
        return Err(CreateFragError(format!("CREATE body of {} bytes needs too many fragments", body.len())));
    }
    let count = chunks.len() as u8;
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let mut payload = Vec::with_capacity(FRAGMENT_HEADER_SIZE + chunk.len());
            payload.extend_from_slice(&msg_id);
            payload.push(i as u8);
            payload.push(count);
            payload.extend_from_slice(&chunk);
            Ok(Cell::new(circuit_id, Command::CreateFragment, payload)?)
        })
        .collect()
}

/// Cut `body` into EXTEND-layer payloads of at most `budget` bytes.
///
/// # Errors
/// Returns [`CreateFragError`] if `budget` is too small to carry a
/// fragment, or `body` needs more than `2 * MAX_FRAGMENTS` fragments.
pub fn fragment_extend_payload(body: &[u8], budget: usize, msg_id: Option<[u8; 4]>) -> Result<Vec<Vec<u8>>, CreateFragError> {
    let msg_id = msg_id.unwrap_or_else(random_msg_id);
    if budget < 1 + FRAGMENT_HEADER_SIZE + 1 {
        return Err(CreateFragError("EXTEND budget too small to carry a fragment".to_string()));
    }
    let chunk = budget - 1 - FRAGMENT_HEADER_SIZE;
    let chunks = split(body, chunk);
    if chunks.len() > (MAX_FRAGMENTS as usize) * 2 {
        return Err(CreateFragError(format!("CREATE body of {} bytes needs too many EXTEND fragments", body.len())));
    }
    let count = chunks.len() as u8;
    Ok(chunks
        .into_iter()
        .enumerate()
        .map(|(i, c)| {
            let mut out = Vec::with_capacity(1 + FRAGMENT_HEADER_SIZE + c.len());
            out.push(EXTEND_FRAGMENT_MARKER);
            out.extend_from_slice(&msg_id);
            out.push(i as u8);
            out.push(count);
            out.extend_from_slice(&c);
            out
        })
        .collect())
}

fn random_msg_id() -> [u8; 4] {
    let v = osrand::bytes(4);
    let mut out = [0u8; 4];
    out.copy_from_slice(&v);
    out
}

struct PendingEntry {
    created_at: Instant,
    count: u8,
    chunks: HashMap<u8, Vec<u8>>,
}

/// Shared reassembly bookkeeping behind [`CreateReassembler`] and
/// [`ExtendReassembler`] (mirrors the Python original's `_Assembler` base
/// class). `K` is an opaque, hashable identifier for one in-flight
/// message: a `(peer_ip, peer_port, circuit_id, msg_id)` tuple for a
/// direct CREATE, or `(entry_key, msg_id)` for an onion-wrapped EXTEND.
struct Assembler<K: Eq + Hash + Clone> {
    max_entries: usize,
    max_count: u8,
    clock: Box<dyn Clock>,
    pending: HashMap<K, PendingEntry>,
    pub dropped: u64,
}

impl<K: Eq + Hash + Clone> Assembler<K> {
    fn new(max_entries: usize, max_count: u8, clock: Option<Box<dyn Clock>>) -> Self {
        Assembler { max_entries, max_count, clock: clock.unwrap_or_else(|| Box::new(SystemClock)), pending: HashMap::new(), dropped: 0 }
    }

    fn expire(&mut self) {
        let now = self.clock.now();
        let ttl = Duration::from_secs_f64(FRAGMENT_TTL_SECONDS);
        self.pending.retain(|_, v| now.saturating_duration_since(v.created_at) <= ttl);
    }

    fn push(&mut self, key: K, index: u8, count: u8, chunk: &[u8]) -> Option<Vec<u8>> {
        if count < 1 || count > self.max_count || index >= count {
            self.dropped += 1;
            return None;
        }
        self.expire();
        if !self.pending.contains_key(&key) {
            if self.pending.len() >= self.max_entries {
                if let Some(oldest) = self.pending.iter().min_by_key(|(_, v)| v.created_at).map(|(k, _)| k.clone()) {
                    self.pending.remove(&oldest);
                    self.dropped += 1;
                }
            }
            self.pending.insert(key.clone(), PendingEntry { created_at: self.clock.now(), count, chunks: HashMap::new() });
        }
        let entry = self.pending.get_mut(&key).expect("just inserted or already present");
        if entry.count != count {
            self.pending.remove(&key);
            self.dropped += 1;
            return None;
        }
        entry.chunks.insert(index, chunk.to_vec());
        if (entry.chunks.len() as u8) < count {
            return None;
        }
        let entry = self.pending.remove(&key).expect("just matched above");
        let mut out = Vec::new();
        for i in 0..count {
            out.extend_from_slice(entry.chunks.get(&i).expect("every index 0..count was checked present by the length test above"));
        }
        Some(out)
    }
}

/// Reassembles CREATE_FRAGMENT cells into a [`CreateMessage`].
pub struct CreateReassembler {
    inner: Assembler<(String, u16, u32, [u8; 4])>,
}

impl CreateReassembler {
    pub fn new(max_entries: usize, clock: Option<Box<dyn Clock>>) -> Self {
        CreateReassembler { inner: Assembler::new(max_entries, MAX_FRAGMENTS, clock) }
    }

    pub fn dropped(&self) -> u64 {
        self.inner.dropped
    }

    /// Feed one CREATE_FRAGMENT cell; returns the reassembled message once
    /// every fragment of it has arrived.
    pub fn push(&mut self, cell: &Cell, peer_addr: (String, u16)) -> Option<CreateMessage> {
        let payload = &cell.payload;
        if payload.len() < FRAGMENT_HEADER_SIZE {
            self.inner.dropped += 1;
            return None;
        }
        let msg_id: [u8; 4] = payload[0..4].try_into().expect("checked len >= FRAGMENT_HEADER_SIZE (6) above");
        let index = payload[4];
        let count = payload[5];
        let key = (peer_addr.0, peer_addr.1, cell.circuit_id, msg_id);
        let body = self.inner.push(key, index, count, &payload[FRAGMENT_HEADER_SIZE..])?;
        Some(CreateMessage { circuit_id: cell.circuit_id, command: Command::Create, payload: body })
    }
}

/// Reassembles EXTEND-fragment layer payloads for one circuit entry. `K`
/// identifies which circuit entry (hop) this fragment stream belongs to.
pub struct ExtendReassembler<K: Eq + Hash + Clone> {
    inner: Assembler<(K, [u8; 4])>,
}

impl<K: Eq + Hash + Clone> ExtendReassembler<K> {
    pub fn new(max_entries: usize, clock: Option<Box<dyn Clock>>) -> Self {
        ExtendReassembler { inner: Assembler::new(max_entries, MAX_FRAGMENTS * 2, clock) }
    }

    pub fn dropped(&self) -> u64 {
        self.inner.dropped
    }

    pub fn is_fragment(plaintext: &[u8]) -> bool {
        !plaintext.is_empty() && plaintext[0] == EXTEND_FRAGMENT_MARKER
    }

    /// Feed one EXTEND-fragment layer payload; returns the reassembled
    /// body once every fragment of it has arrived.
    pub fn push(&mut self, entry_key: K, plaintext: &[u8]) -> Option<Vec<u8>> {
        if plaintext.len() < 1 + FRAGMENT_HEADER_SIZE {
            self.inner.dropped += 1;
            return None;
        }
        let msg_id: [u8; 4] = plaintext[1..5].try_into().expect("checked len >= 1 + FRAGMENT_HEADER_SIZE above");
        let index = plaintext[5];
        let count = plaintext[6];
        self.inner.push((entry_key, msg_id), index, count, &plaintext[1 + FRAGMENT_HEADER_SIZE..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_create_round_trips_through_create_reassembler() {
        let body = vec![0xABu8; PAYLOAD_SIZE * 2]; // forces multiple fragments
        let cells = fragment_create(7, &body, Some([1, 2, 3, 4])).unwrap();
        assert!(cells.len() > 1);
        let mut r = CreateReassembler::new(16, None);
        let mut result = None;
        for cell in &cells {
            result = r.push(cell, ("10.0.0.1".to_string(), 9001));
        }
        let msg = result.expect("last fragment completes the message");
        assert_eq!(msg.circuit_id, 7);
        assert_eq!(msg.command, Command::Create);
        assert_eq!(msg.payload, body);
    }

    #[test]
    fn fragment_create_out_of_order_still_reassembles() {
        let body = vec![0x11u8; PAYLOAD_SIZE * 2];
        let mut cells = fragment_create(1, &body, Some([9, 9, 9, 9])).unwrap();
        cells.reverse();
        let mut r = CreateReassembler::new(16, None);
        let mut result = None;
        for cell in &cells {
            result = r.push(cell, ("1.2.3.4".to_string(), 1));
        }
        assert_eq!(result.unwrap().payload, body);
    }

    #[test]
    fn fragment_create_too_large_is_rejected() {
        let body = vec![0u8; (PAYLOAD_SIZE - FRAGMENT_HEADER_SIZE) * (MAX_FRAGMENTS as usize + 1)];
        assert!(fragment_create(1, &body, None).is_err());
    }

    #[test]
    fn fragment_create_empty_body_yields_one_fragment() {
        let cells = fragment_create(1, &[], None).unwrap();
        assert_eq!(cells.len(), 1);
        let mut r = CreateReassembler::new(16, None);
        let msg = r.push(&cells[0], ("h".to_string(), 1)).unwrap();
        assert!(msg.payload.is_empty());
    }

    #[test]
    fn fragment_extend_payload_round_trips_through_extend_reassembler() {
        let body = vec![0x22u8; 1000];
        let fragments = fragment_extend_payload(&body, 150, Some([5, 5, 5, 5])).unwrap();
        assert!(fragments.len() > 1);
        for f in &fragments {
            assert!(ExtendReassembler::<u32>::is_fragment(f));
        }
        let mut r: ExtendReassembler<u32> = ExtendReassembler::new(16, None);
        let mut result = None;
        for f in &fragments {
            result = r.push(42, f);
        }
        assert_eq!(result.unwrap(), body);
    }

    #[test]
    fn extend_reassembler_distinguishes_different_entries() {
        let body_a = vec![0xAAu8; 500];
        let body_b = vec![0xBBu8; 500];
        let frags_a = fragment_extend_payload(&body_a, 100, Some([1, 1, 1, 1])).unwrap();
        let frags_b = fragment_extend_payload(&body_b, 100, Some([2, 2, 2, 2])).unwrap();
        let mut r: ExtendReassembler<u32> = ExtendReassembler::new(16, None);
        // Interleave two different entries' fragment streams.
        let mut result_a = None;
        let mut result_b = None;
        for i in 0..frags_a.len().max(frags_b.len()) {
            if let Some(f) = frags_a.get(i) {
                if let Some(m) = r.push(1, f) {
                    result_a = Some(m);
                }
            }
            if let Some(f) = frags_b.get(i) {
                if let Some(m) = r.push(2, f) {
                    result_b = Some(m);
                }
            }
        }
        assert_eq!(result_a.unwrap(), body_a);
        assert_eq!(result_b.unwrap(), body_b);
    }

    #[test]
    fn reassembler_evicts_oldest_entry_when_at_capacity() {
        let mut r: ExtendReassembler<u32> = ExtendReassembler::new(1, None);
        // Start (but don't complete) a message under key 1.
        let frags1 = fragment_extend_payload(&[0u8; 500], 100, Some([1, 1, 1, 1])).unwrap();
        r.push(1, &frags1[0]);
        assert_eq!(r.dropped(), 0);
        // A message under a different key evicts the incomplete one (at capacity 1).
        let frags2 = fragment_extend_payload(&[1u8; 10], 64, Some([2, 2, 2, 2])).unwrap();
        for f in &frags2 {
            r.push(2, f);
        }
        assert_eq!(r.dropped(), 1);
        // Key 1's remaining fragments now start a fresh (empty) entry, so
        // they alone cannot complete it.
        let mut completed = false;
        for f in &frags1[1..] {
            if r.push(1, f).is_some() {
                completed = true;
            }
        }
        assert!(!completed);
    }

    #[test]
    fn mismatched_count_for_same_message_drops_it() {
        let mut r: ExtendReassembler<u32> = ExtendReassembler::new(16, None);
        let frags = fragment_extend_payload(&[0u8; 500], 100, Some([3, 3, 3, 3])).unwrap();
        r.push(1, &frags[0]);
        // A fragment claiming a different count for the same (key, msg_id)
        // is treated as a corrupt/conflicting message and dropped.
        let mut tampered = frags[1].clone();
        tampered[6] = 99; // count field
        assert!(r.push(1, &tampered).is_none());
        assert!(r.dropped() >= 1);
    }
}

#[cfg(test)]
mod python_cross_check {
    use super::*;

    #[test]
    fn fragment_create_wire_bytes_match_python() {
        // python3 -c "
        //   import allium.createfrag as cf
        //   body = bytes(range(200)) * 12
        //   cells = cf.fragment_create(0x12345678, body, msg_id=bytes([1,2,3,4]))
        //   print(len(cells))
        //   for c in cells:
        //       print(c.circuit_id, c.command, len(c.payload), c.payload[:10].hex())
        // "
        //
        // Body length raised from 1000 to 2400 bytes alongside the cell-size
        // upgrade (PAYLOAD_SIZE 504 -> 1184): at the new, larger chunk size
        // (PAYLOAD_SIZE - FRAGMENT_HEADER_SIZE = 1178) the original 1000-byte
        // body fit in a single fragment, no longer exercising the
        // multi-fragment path this test exists to check. 2400 bytes again
        // splits into 3 fragments (1178 + 1178 + 44), the same shape as the
        // original (498 + 498 + 4).
        let body: Vec<u8> = (0..200u32).map(|b| b as u8).cycle().take(2400).collect();
        let cells = fragment_create(0x1234_5678, &body, Some([1, 2, 3, 4])).unwrap();
        assert_eq!(cells.len(), 3);

        let expected = [
            (1184usize, "01020304000300010203"),
            (1184usize, "010203040103b2b3b4b5"),
            (50usize, "0102030402039c9d9e9f"),
        ];
        for (cell, (len, head_hex)) in cells.iter().zip(expected.iter()) {
            assert_eq!(cell.circuit_id, 0x1234_5678);
            assert_eq!(cell.command, Command::CreateFragment);
            assert_eq!(cell.payload.len(), *len);
            let head: String = cell.payload[..10].iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(&head, head_hex);
        }
    }
}
