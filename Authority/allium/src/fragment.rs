//! Cell fragmentation: split a byte stream into cells and reassemble it.
//!
//! Framing (big-endian):
//!
//! ```text
//! +-----------+-----------+--------+--------------+
//! | stream id | offset    | flags  | data         |
//! | 4         | 4         | 1      | variable     |
//! +-----------+-----------+--------+--------------+
//! ```

use std::collections::BTreeMap;
use std::fmt;

/// Fixed size of the fragment header (stream id + offset + flags).
pub const HEADER_SIZE: usize = 4 + 4 + 1;

/// The FIN bit in the flags byte.
pub const FLAG_FIN: u8 = 0x01;

/// Default maximum data bytes per fragment.
///
/// Raised from 256 to 936 alongside the cell-size upgrade (see
/// `cell::PAYLOAD_SIZE`'s own doc comment): the 3-hop per-cell user-data
/// budget grew from 275 to 955 bytes (`sizes::user_data_budget_default`;
/// 1013 since the 0xA4 layer format dropped the per-hop inner header --
/// this MTU was deliberately left where it was, so the margin is now
/// larger), and this was kept exactly 10 bytes under that budget once
/// [`HEADER_SIZE`] is added -- the same fixed safety margin the original
/// 256 left under the old 275-byte budget (266 - 10 = 256; here,
/// 946 - 10 = 936), rather than a newly chosen ratio.
pub const DEFAULT_MTU: usize = 936;

/// A fragment could not be encoded/decoded or a reassembly invariant broke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentError {
    pub message: String,
}
impl fmt::Display for FragmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for FragmentError {}
impl FragmentError {
    fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

/// One decoded fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    pub stream_id: u32,
    pub offset: u32,
    pub fin: bool,
    pub data: Vec<u8>,
}

impl Fragment {
    pub fn new(stream_id: u32, offset: u32, fin: bool, data: Vec<u8>) -> Fragment {
        Fragment { stream_id, offset, fin, data }
    }
}

/// Serialize a [`Fragment`] to wire bytes.
pub fn encode_fragment(fragment: &Fragment) -> Vec<u8> {
    let flags = if fragment.fin { FLAG_FIN } else { 0x00 };
    let mut out = Vec::with_capacity(HEADER_SIZE + fragment.data.len());
    out.extend_from_slice(&fragment.stream_id.to_be_bytes());
    out.extend_from_slice(&fragment.offset.to_be_bytes());
    out.push(flags);
    out.extend_from_slice(&fragment.data);
    out
}

/// Parse wire bytes into a [`Fragment`].
pub fn decode_fragment(data: &[u8]) -> Result<Fragment, FragmentError> {
    if data.len() < HEADER_SIZE {
        return Err(FragmentError::new(format!(
            "fragment is {} bytes, minimum is {HEADER_SIZE}",
            data.len()
        )));
    }
    let stream_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let offset = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let flags = data[8];
    Ok(Fragment { stream_id, offset, fin: flags & FLAG_FIN != 0, data: data[HEADER_SIZE..].to_vec() })
}

/// Splits a byte stream into fixed-size fragments.
pub struct Fragmenter {
    pub mtu: usize,
    pub stream_id: u32,
}

impl Fragmenter {
    pub fn new(mtu: usize, stream_id: u32) -> Result<Fragmenter, FragmentError> {
        if mtu < 1 {
            return Err(FragmentError::new(format!("mtu must be at least 1, got {mtu}")));
        }
        Ok(Fragmenter { mtu, stream_id })
    }

    pub fn with_defaults() -> Fragmenter {
        Fragmenter { mtu: DEFAULT_MTU, stream_id: 0 }
    }

    /// Split `data` into one or more fragments in order.
    ///
    /// An empty `data` yields a single FIN fragment.
    pub fn fragment(&self, data: &[u8]) -> Vec<Fragment> {
        if data.is_empty() {
            return vec![Fragment::new(self.stream_id, 0, true, Vec::new())];
        }
        let mut fragments = Vec::new();
        let mut offset = 0usize;
        while offset < data.len() {
            let end = (offset + self.mtu).min(data.len());
            let chunk = data[offset..end].to_vec();
            fragments.push(Fragment::new(self.stream_id, offset as u32, false, chunk));
            offset = end;
        }
        if let Some(last) = fragments.last_mut() {
            last.fin = true;
        }
        fragments
    }
}

/// Reassembles fragments from one stream into the original byte stream.
pub struct Reassembler {
    pub stream_id: u32,
    pub max_pending: usize,
    chunks: BTreeMap<u32, Vec<u8>>,
    next: u32,
    size: u32,
    seen_fin: bool,
    finished: bool,
}

impl Reassembler {
    pub fn new(stream_id: u32, max_pending: usize) -> Reassembler {
        Reassembler {
            stream_id,
            max_pending,
            chunks: BTreeMap::new(),
            next: 0,
            size: 0,
            seen_fin: false,
            finished: false,
        }
    }

    pub fn with_defaults(stream_id: u32) -> Reassembler {
        Reassembler::new(stream_id, 4096)
    }

    /// The stream's total length once FIN is seen; 0 before then.
    pub fn size(&self) -> u32 {
        self.size
    }

    /// `true` once the FIN fragment has been delivered in order.
    pub fn finished(&self) -> bool {
        self.finished
    }

    /// Offset of the next in-order byte this reassembler is waiting for. A
    /// fragment at exactly this offset is consumed immediately rather than
    /// buffered.
    pub fn expected_offset(&self) -> u32 {
        self.next
    }

    /// Bytes currently buffered out of order, waiting on an earlier gap.
    pub fn pending_bytes(&self) -> usize {
        self.chunks.values().map(Vec::len).sum()
    }

    #[cfg(test)]
    fn next_offset(&self) -> u32 {
        self.next
    }

    #[cfg(test)]
    fn pending_chunks(&self) -> &BTreeMap<u32, Vec<u8>> {
        &self.chunks
    }

    /// Feed one fragment; return the newly contiguous bytes (maybe empty).
    pub fn push(&mut self, fragment: &Fragment) -> Result<Vec<u8>, FragmentError> {
        if fragment.stream_id != self.stream_id {
            return Err(FragmentError::new(format!(
                "fragment stream {} does not match reassembler stream {}",
                fragment.stream_id, self.stream_id
            )));
        }

        if fragment.fin {
            self.seen_fin = true;
            // `offset` is attacker-controlled (straight off the wire, no
            // range check before this point): a plain `+` here overflows
            // for an offset near `u32::MAX`, panicking in a debug build
            // and silently wrapping to a small value in release (no
            // `overflow-checks` override in this crate). Saturating
            // instead: at worst the stream never appears complete from
            // this fragment alone (a safe stall/timeout), never silent
            // corruption -- see `Client/src/fragment.rs`'s matching fix.
            self.size = fragment.offset.saturating_add(fragment.data.len() as u32);
            let stray: Vec<u32> = self.chunks.keys().copied().filter(|&off| off >= self.size).collect();
            for off in stray {
                self.chunks.remove(&off);
            }
        }

        if fragment.offset < self.next || self.chunks.contains_key(&fragment.offset) {
            // duplicate or already consumed
        } else if self.seen_fin && fragment.offset >= self.size {
            // out of range: cannot belong to this stream
        } else {
            self.chunks.insert(fragment.offset, fragment.data.clone());
        }

        let mut out: Vec<u8> = Vec::new();
        while let Some(chunk) = self.chunks.remove(&self.next) {
            // Saturating, not a
            // bare `+=`, matching the `size` fix two lines above -- an
            // attacker-controlled chunk landing at an offset near
            // `u32::MAX` must not panic (debug) or silently wrap `next`
            // back to a small value (release), which would make a later,
            // genuinely low-offset chunk look contiguous and get spliced
            // in out of order.
            self.next = self.next.saturating_add(chunk.len() as u32);
            out.extend_from_slice(&chunk);
        }

        if self.chunks.len() > self.max_pending {
            if let Some(&farthest) = self.chunks.keys().max() {
                self.chunks.remove(&farthest);
            }
        }

        if self.seen_fin && self.next >= self.size && self.chunks.is_empty() {
            self.finished = true;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Fragmentation -----------------------------------------------------
    #[test]
    fn test_single_fragment_when_under_mtu() {
        let fragments = Fragmenter::new(100, 5).unwrap().fragment(b"short");
        assert_eq!(fragments.len(), 1);
        assert!(fragments[0].fin);
        assert_eq!(fragments[0].data, b"short");
        assert_eq!(fragments[0].offset, 0);
    }

    #[test]
    fn test_multiple_fragments_and_fin_on_last() {
        let payload = vec![b'x'; 20];
        let fragments = Fragmenter::new(8, 1).unwrap().fragment(&payload);
        assert_eq!(fragments.len(), 3);
        assert!(!fragments[0].fin);
        assert!(fragments.last().unwrap().fin);
        let total: usize = fragments.iter().map(|f| f.data.len()).sum();
        assert_eq!(total, payload.len());
    }

    #[test]
    fn test_offsets_are_contiguous() {
        let payload = vec![b'y'; 30];
        let fragments = Fragmenter::new(10, 9).unwrap().fragment(&payload);
        let offsets: Vec<u32> = fragments.iter().map(|f| f.offset).collect();
        assert_eq!(offsets, vec![0, 10, 20]);
    }

    #[test]
    fn test_empty_payload_is_one_fin_fragment() {
        let fragments = Fragmenter::new(8, 2).unwrap().fragment(b"");
        assert_eq!(fragments, vec![Fragment::new(2, 0, true, vec![])]);
    }

    #[test]
    fn test_rejects_zero_mtu() {
        assert!(Fragmenter::new(0, 0).is_err());
    }

    // -- Codec -----------------------------------------------------
    #[test]
    fn test_encode_decode_round_trip() {
        let frag = Fragment::new(0xDEADBEEF, 64, true, b"data bytes".to_vec());
        assert_eq!(decode_fragment(&encode_fragment(&frag)).unwrap(), frag);
    }

    #[test]
    fn test_fin_flag_is_single_bit() {
        let frag = Fragment::new(1, 0, true, b"x".to_vec());
        let raw = encode_fragment(&frag);
        assert_eq!(raw[8], FLAG_FIN);
    }

    #[test]
    fn test_non_fin_flag_is_zero() {
        let frag = Fragment::new(1, 0, false, b"x".to_vec());
        assert_eq!(encode_fragment(&frag)[8], 0x00);
    }

    #[test]
    fn test_decode_rejects_short_buffer() {
        assert!(decode_fragment(&vec![0u8; HEADER_SIZE - 1]).is_err());
    }

    #[test]
    fn test_decode_rejects_empty() {
        assert!(decode_fragment(&[]).is_err());
    }

    // -- Reassembler -----------------------------------------------------
    fn round_trip(payload: &[u8], order: Option<&[usize]>, mtu: usize, stream_id: u32) -> (Vec<u8>, Reassembler) {
        let mut fragments = Fragmenter::new(mtu, stream_id).unwrap().fragment(payload);
        if let Some(order) = order {
            fragments = order.iter().map(|&i| fragments[i].clone()).collect();
        }
        let mut r = Reassembler::with_defaults(stream_id);
        let mut out = Vec::new();
        for frag in &fragments {
            out.extend(r.push(frag).unwrap());
        }
        (out, r)
    }

    #[test]
    fn test_in_order() {
        let payload = "hello world".repeat(20).into_bytes();
        let (out, r) = round_trip(&payload, None, 8, 3);
        assert_eq!(out, payload);
        assert!(r.finished());
        assert_eq!(r.size(), payload.len() as u32);
    }

    #[test]
    fn test_out_of_order() {
        let payload: Vec<u8> = (0..=255u8).collect();
        let (out, r) = round_trip(&payload, Some(&[2, 0, 4, 1, 5, 3]), 50, 3);
        assert_eq!(out, payload);
        assert!(r.finished());
    }

    #[test]
    fn test_duplicate_fragment_is_dropped() {
        let payload = b"abcdefgh";
        let fragments = Fragmenter::new(4, 7).unwrap().fragment(payload);
        let mut r = Reassembler::with_defaults(7);
        let mut out = r.push(&fragments[0]).unwrap();
        out.extend(r.push(&fragments[0]).unwrap());
        assert_eq!(out, b"abcd");
        out.extend(r.push(&fragments[1]).unwrap());
        assert!(r.finished());
        assert_eq!(out, payload);
    }

    #[test]
    fn test_wrong_stream_is_rejected() {
        let mut r = Reassembler::with_defaults(1);
        assert!(r.push(&Fragment::new(2, 0, false, b"x".to_vec())).is_err());
    }

    #[test]
    fn test_empty_stream_finishes() {
        let mut r = Reassembler::with_defaults(5);
        r.push(&Fragment::new(5, 0, true, vec![])).unwrap();
        assert!(r.finished());
        assert_eq!(r.size(), 0);
    }

    #[test]
    fn test_not_finished_without_fin() {
        let mut r = Reassembler::with_defaults(6);
        r.push(&Fragment::new(6, 0, false, b"abc".to_vec())).unwrap();
        assert!(!r.finished());
    }

    #[test]
    fn test_default_mtu_is_reasonable() {
        // Checked against `sizes::user_data_budget_default()` directly,
        // not a second hardcoded copy of the 3-hop budget -- exactly the
        // duplication this project's cell-size-upgrade review flagged as
        // a correctness risk in `handshake.rs`'s `MAX_HANDSHAKE_PAYLOAD`
        // (see `cell::PAYLOAD_SIZE`'s doc comment): a future resize that
        // updates the budget but not a second hardcoded number here would
        // silently stop testing anything real.
        assert!(DEFAULT_MTU + HEADER_SIZE <= crate::sizes::user_data_budget_default() as usize);
    }

    #[test]
    fn test_stray_out_of_range_fragment_does_not_block_completion() {
        let mut r = Reassembler::with_defaults(1);
        r.push(&Fragment::new(1, 9999, false, b"junk".to_vec())).unwrap();
        let out = r.push(&Fragment::new(1, 0, true, b"hello".to_vec())).unwrap();
        assert_eq!(out, b"hello");
        assert!(r.finished());
    }

    #[test]
    fn test_stray_fragment_arriving_after_fin_is_dropped() {
        let mut r = Reassembler::with_defaults(1);
        r.push(&Fragment::new(1, 0, true, b"hi".to_vec())).unwrap();
        assert!(r.finished());
        r.push(&Fragment::new(1, 9999, false, b"junk".to_vec())).unwrap();
        assert!(r.finished());
    }

    /// A FIN fragment whose `offset` is near `u32::MAX` must not panic
    /// (debug) or silently wrap `size` to a small value (release, this
    /// crate's actual deployment target -- no `overflow-checks` override).
    /// `offset` is attacker-controlled (decoded straight off the wire), so
    /// this is reachable by either endpoint of a stream.
    #[test]
    fn test_fin_near_u32_max_offset_does_not_overflow() {
        let mut r = Reassembler::with_defaults(1);
        let out = r.push(&Fragment::new(1, u32::MAX - 1, true, vec![0u8; 4])).unwrap();
        assert!(out.is_empty(), "far ahead of `next`, so nothing is contiguous yet");
        // Saturates instead of wrapping: the declared size is clamped to
        // u32::MAX, not wrapped around to something tiny like 2.
        assert_eq!(r.size(), u32::MAX);
        assert!(!r.finished(), "declaring a huge size must not itself mark the stream finished");
    }

    /// Once `size` saturates, a normal in-order prefix must still
    /// reassemble as data arrives.
    #[test]
    fn test_fin_near_u32_max_offset_still_reassembles_prefix() {
        let mut r = Reassembler::with_defaults(1);
        r.push(&Fragment::new(1, u32::MAX - 1, true, vec![0u8; 4])).unwrap();
        let out = r.push(&Fragment::new(1, 0, false, b"abcd".to_vec())).unwrap();
        assert_eq!(out, b"abcd");
        assert!(!r.finished(), "the real end-of-stream chunk is still effectively unreachable at this size");
    }

    /// Consuming a contiguous chunk whose end
    /// offset would overflow `u32` must saturate `next` at `u32::MAX`, not
    /// wrap it back to a small value. A wrap would make a later, genuinely
    /// low-offset chunk falsely look contiguous with `next` and get spliced
    /// into `out` out of order -- this proves that cannot happen.
    #[test]
    fn test_consuming_a_chunk_near_u32_max_does_not_wrap_next() {
        let mut r = Reassembler::with_defaults(1);
        // Directly place `next` near `u32::MAX`, as if it had already
        // legitimately reassembled that much of the stream -- a real
        // 4-billion-byte stream is impractical to construct in a test, but
        // the overflow behavior being tested only depends on `next`'s
        // value at the moment a contiguous chunk is consumed, not on how
        // it got there.
        r.next = u32::MAX - 3;
        // Lands exactly at `next`, so it is consumed immediately; its
        // length pushes the new `next` past `u32::MAX`.
        let out = r.push(&Fragment::new(1, u32::MAX - 3, false, vec![0u8; 8])).unwrap();
        assert_eq!(out.len(), 8, "the chunk starting at `next` must still be consumed");
        assert_eq!(r.next_offset(), u32::MAX, "next must saturate, not wrap");

        // A low-offset chunk arriving afterward must not be treated as
        // contiguous just because a wrapped `next` would have landed there.
        let out2 = r.push(&Fragment::new(1, 2, false, b"ZZ".to_vec())).unwrap();
        assert!(out2.is_empty(), "next is saturated at u32::MAX, so an offset-2 chunk is not contiguous and must stay pending");
    }

    #[test]
    fn test_eviction_prefers_the_farthest_offset_over_the_nearest() {
        let mut r = Reassembler::new(1, 2);
        r.push(&Fragment::new(1, 100, false, vec![b'A'; 100])).unwrap();
        r.push(&Fragment::new(1, 200, false, vec![b'B'; 100])).unwrap();
        r.push(&Fragment::new(1, 300, false, vec![b'C'; 100])).unwrap();
        let out = r.push(&Fragment::new(1, 0, false, vec![b'Z'; 100])).unwrap();
        let mut expected = vec![b'Z'; 100];
        expected.extend(vec![b'A'; 100]);
        expected.extend(vec![b'B'; 100]);
        assert_eq!(out, expected);
        assert_eq!(r.next_offset(), 300);
        assert!(r.pending_chunks().is_empty());
    }
}
