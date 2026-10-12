//! Cell fragmentation: split a byte stream into cells and reassemble it.
//!
//! The one-cell transport carries at most ~1013 user-data bytes through a
//! 3-hop circuit, which caps every real stream at a single message. This
//! module breaks an arbitrary byte stream into fixed-size fragments and
//! puts it back together at the far end, layered *on top of* the
//! reliability primitives ([`crate::reliability`]): reordering is
//! delegated to a [`crate::reliability::ReassemblyBuffer`]-style consumer
//! (this module's own [`Reassembler`] plays that role for a byte stream
//! specifically); loss is a [`crate::reliability::SendWindow`] concern.
//!
//! Framing (big-endian):
//!
//! ```text
//! +-----------+-----------+--------+--------------+
//! | stream id | offset    | flags  | data         |
//! | 4         | 4         | 1      | variable     |
//! +-----------+-----------+--------+--------------+
//! ```
//!
//! * `stream_id` -- 32-bit, distinguishes concurrent streams on one circuit.
//! * `offset` -- byte offset of this fragment within the stream, doubling
//!   as the reordering key.
//! * `flags` -- bit 0 (FIN) marks the final fragment, so an empty final
//!   fragment still signals end-of-stream unambiguously.
//! * `data` -- the fragment's payload, at most `mtu` bytes.
//!
//! This module is deliberately independent of the onion layer and sockets,
//! so both a SOCKS5 CONNECT stream and a future UDP ASSOCIATE can use it,
//! and it is unit-testable without a network.

use std::collections::BTreeMap;

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

/// One decoded fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    /// Which stream this belongs to.
    pub stream_id: u32,
    /// Byte offset within the reassembled stream.
    pub offset: u32,
    /// `true` on the final fragment.
    pub fin: bool,
    /// This fragment's payload bytes.
    pub data: Vec<u8>,
}

/// A fragment could not be encoded/decoded, or a reassembly invariant broke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentError(pub String);

impl std::fmt::Display for FragmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for FragmentError {}

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
///
/// # Errors
/// Returns [`FragmentError`] if the buffer is shorter than the fixed header.
pub fn decode_fragment(data: &[u8]) -> Result<Fragment, FragmentError> {
    if data.len() < HEADER_SIZE {
        return Err(FragmentError(format!("fragment is {} bytes, minimum is {HEADER_SIZE}", data.len())));
    }
    let stream_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let offset = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let flags = data[8];
    Ok(Fragment { stream_id, offset, fin: flags & FLAG_FIN != 0, data: data[HEADER_SIZE..].to_vec() })
}

/// Splits a byte stream into fixed-size fragments.
pub struct Fragmenter {
    /// Maximum data bytes per fragment (exclusive of the 9-byte header).
    pub mtu: usize,
    /// The stream these fragments belong to.
    pub stream_id: u32,
}

impl Fragmenter {
    /// # Errors
    /// Returns [`FragmentError`] if `mtu` is zero.
    pub fn new(mtu: usize, stream_id: u32) -> Result<Self, FragmentError> {
        if mtu < 1 {
            return Err(FragmentError(format!("mtu must be at least 1, got {mtu}")));
        }
        Ok(Fragmenter { mtu, stream_id })
    }

    /// Split `data` into one or more fragments in order.
    ///
    /// An empty `data` yields a single FIN fragment (so an empty stream is
    /// still distinguishable from a stream that never started).
    pub fn fragment(&self, data: &[u8]) -> Vec<Fragment> {
        if data.is_empty() {
            return vec![Fragment { stream_id: self.stream_id, offset: 0, fin: true, data: Vec::new() }];
        }
        let mut fragments = Vec::new();
        let mut offset = 0usize;
        while offset < data.len() {
            let end = (offset + self.mtu).min(data.len());
            fragments.push(Fragment { stream_id: self.stream_id, offset: offset as u32, fin: false, data: data[offset..end].to_vec() });
            offset = end;
        }
        if let Some(last) = fragments.last_mut() {
            last.fin = true;
        }
        fragments
    }
}

/// Reassembles fragments from one stream into the original byte stream.
///
/// Out-of-order fragments are held until the gap before them is filled (the
/// offset is the ordering key). Duplicate offsets are dropped. The stream
/// is complete once the FIN fragment has been delivered in order.
pub struct Reassembler {
    /// The stream this reassembler is bound to.
    pub stream_id: u32,
    /// Bounds memory if a gap is never filled before FIN.
    pub max_pending: usize,
    chunks: BTreeMap<u32, Vec<u8>>,
    next: u32,
    size: u32,
    seen_fin: bool,
    finished: bool,
}

impl Reassembler {
    pub fn new(stream_id: u32, max_pending: usize) -> Self {
        Reassembler { stream_id, max_pending, chunks: BTreeMap::new(), next: 0, size: 0, seen_fin: false, finished: false }
    }

    /// The stream's total length once FIN is seen; `0` before then.
    pub fn size(&self) -> u32 {
        self.size
    }

    /// `true` once the FIN fragment has been delivered in order.
    pub fn finished(&self) -> bool {
        self.finished
    }

    /// Feed one fragment; return the newly contiguous bytes (maybe empty).
    ///
    /// The caller concatenates each non-empty return until [`Self::finished`]
    /// is `true`. A duplicate or already-consumed fragment returns an empty
    /// vector.
    ///
    /// # Errors
    /// Returns [`FragmentError`] if the fragment is for a different stream.
    pub fn push(&mut self, fragment: &Fragment) -> Result<Vec<u8>, FragmentError> {
        if fragment.stream_id != self.stream_id {
            return Err(FragmentError(format!(
                "fragment stream {} does not match reassembler stream {}",
                fragment.stream_id, self.stream_id
            )));
        }

        if fragment.fin {
            self.seen_fin = true;
            // `offset` is attacker-controlled (straight off the wire, no
            // range check before this point): a plain `+` here overflows
            // for an offset near `u32::MAX`, panicking in a debug build
            // and, worse, silently wrapping to a small value in release
            // (this crate has no `overflow-checks` override, so release
            // uses Rust's default wrapping behavior). A wrapped-to-tiny
            // `size` would purge almost every pending chunk as "stray"
            // below and let `finished()` go true before all real data
            // arrived -- a silently truncated stream, not an error.
            // Saturating instead: at worst the stream never appears
            // complete from this fragment alone (a safe stall/timeout),
            // never silent corruption.
            self.size = fragment.offset.saturating_add(fragment.data.len() as u32);
            // Every real fragment's offset is strictly less than the
            // stream's total size, so anything already parked at or past
            // it cannot belong to this stream -- it was stray (or
            // attacker-supplied) data received before the true size was
            // knowable. `finished` requires the pending map to be empty,
            // so leaving such an entry behind would block completion
            // forever even once every real fragment has arrived; purge it
            // now that the size is known.
            let stray: Vec<u32> = self.chunks.range(self.size..).map(|(&k, _)| k).collect();
            for off in stray {
                self.chunks.remove(&off);
            }
        }

        // Record the fragment if it is ahead of (or at) the next expected
        // offset, has not already been seen, and -- once the stream's size
        // is known -- actually fits inside it. Storing an out-of-range
        // offset would otherwise sit in `chunks` forever, since nothing
        // legitimate will ever arrive to occupy that slot; see the
        // FIN-purge above for the symmetric case where such a fragment
        // arrived first.
        if fragment.offset < self.next || self.chunks.contains_key(&fragment.offset) {
            // duplicate or already consumed
        } else if self.seen_fin && fragment.offset >= self.size {
            // out of range: cannot belong to this stream
        } else {
            self.chunks.insert(fragment.offset, fragment.data.clone());
        }

        // Consume every chunk that is now contiguous *before* enforcing
        // the memory bound below: a chunk about to be popped here is
        // never a candidate for eviction, it is simply no longer pending.
        let mut out = Vec::new();
        while let Some(chunk) = self.chunks.remove(&self.next) {
            // `wrapping_add` was strictly worse than the `saturating_add`
            // already used for
            // `size` above, for the same overflow-source (an
            // attacker-controlled offset near `u32::MAX`): wrapping `next`
            // back to a small value would make a later, genuinely
            // low-offset chunk falsely look contiguous and get spliced
            // into `out` out of order -- silent data corruption, not just
            // a stall. Saturating instead only ever stalls, matching
            // `size`'s own fix and its rationale above.
            self.next = self.next.saturating_add(chunk.len() as u32);
            out.extend_from_slice(&chunk);
        }

        // Bound memory: if we are still holding too many un-reassembled
        // chunks after the consumption above, there is a gap that will
        // not be filled soon; drop one rather than grow without bound.
        // Evict the chunk *farthest* from `next`, not the closest: the
        // chunks nearest `next` are exactly the ones that let reassembly
        // progress once the gap ahead of them fills, so discarding the
        // nearest would reliably throw away the data a soon-to-be-filled
        // gap was about to need, silently stalling the stream forever
        // with no signal to the caller. The farthest offset is the least
        // likely to be needed soon and the most likely to be spurious.
        if self.chunks.len() > self.max_pending {
            if let Some((&farthest, _)) = self.chunks.iter().next_back() {
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

    #[test]
    fn encode_decode_round_trips() {
        let f = Fragment { stream_id: 7, offset: 42, fin: true, data: b"hello".to_vec() };
        let bytes = encode_fragment(&f);
        assert_eq!(bytes.len(), HEADER_SIZE + 5);
        let decoded = decode_fragment(&bytes).unwrap();
        assert_eq!(decoded, f);
    }

    #[test]
    fn decode_too_short_is_rejected() {
        let err = decode_fragment(&[0u8; HEADER_SIZE - 1]).unwrap_err();
        assert!(err.0.contains("minimum"));
    }

    #[test]
    fn fragmenter_splits_and_marks_last_fin() {
        let f = Fragmenter::new(4, 1).unwrap();
        let parts = f.fragment(b"abcdefghij");
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].data, b"abcd");
        assert_eq!(parts[1].data, b"efgh");
        assert_eq!(parts[2].data, b"ij");
        assert!(!parts[0].fin);
        assert!(!parts[1].fin);
        assert!(parts[2].fin);
        assert_eq!(parts[0].offset, 0);
        assert_eq!(parts[1].offset, 4);
        assert_eq!(parts[2].offset, 8);
    }

    #[test]
    fn fragmenter_empty_data_yields_single_fin_fragment() {
        let f = Fragmenter::new(4, 9).unwrap();
        let parts = f.fragment(b"");
        assert_eq!(parts, vec![Fragment { stream_id: 9, offset: 0, fin: true, data: Vec::new() }]);
    }

    #[test]
    fn fragmenter_rejects_zero_mtu() {
        assert!(Fragmenter::new(0, 0).is_err());
    }

    #[test]
    fn reassembler_in_order_round_trip() {
        let mut r = Reassembler::new(0, 4096);
        let mut out = Vec::new();
        out.extend(r.push(&Fragment { stream_id: 0, offset: 0, fin: false, data: b"abcd".to_vec() }).unwrap());
        out.extend(r.push(&Fragment { stream_id: 0, offset: 4, fin: true, data: b"ef".to_vec() }).unwrap());
        assert_eq!(out, b"abcdef");
        assert!(r.finished());
        assert_eq!(r.size(), 6);
    }

    #[test]
    fn reassembler_out_of_order_fills_gap() {
        let mut r = Reassembler::new(0, 4096);
        let out1 = r.push(&Fragment { stream_id: 0, offset: 4, fin: true, data: b"ef".to_vec() }).unwrap();
        assert!(out1.is_empty());
        assert!(!r.finished());
        let out2 = r.push(&Fragment { stream_id: 0, offset: 0, fin: false, data: b"abcd".to_vec() }).unwrap();
        assert_eq!(out2, b"abcdef");
        assert!(r.finished());
    }

    #[test]
    fn reassembler_wrong_stream_is_rejected() {
        let mut r = Reassembler::new(0, 4096);
        let err = r.push(&Fragment { stream_id: 1, offset: 0, fin: true, data: Vec::new() }).unwrap_err();
        assert!(err.0.contains("does not match"));
    }

    #[test]
    fn reassembler_duplicate_offset_yields_nothing() {
        let mut r = Reassembler::new(0, 4096);
        r.push(&Fragment { stream_id: 0, offset: 4, fin: false, data: b"ef".to_vec() }).unwrap();
        let out = r.push(&Fragment { stream_id: 0, offset: 4, fin: false, data: b"ZZ".to_vec() }).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn reassembler_purges_stray_chunks_past_fin_size() {
        let mut r = Reassembler::new(0, 4096);
        // A chunk beyond the eventual FIN-declared size arrives first.
        r.push(&Fragment { stream_id: 0, offset: 100, fin: false, data: b"stray".to_vec() }).unwrap();
        // FIN declares the stream is only 6 bytes long.
        let out1 = r.push(&Fragment { stream_id: 0, offset: 4, fin: true, data: b"ef".to_vec() }).unwrap();
        assert!(out1.is_empty());
        let out2 = r.push(&Fragment { stream_id: 0, offset: 0, fin: false, data: b"abcd".to_vec() }).unwrap();
        assert_eq!(out2, b"abcdef");
        assert!(r.finished());
    }

    /// A FIN fragment whose `offset` is near `u32::MAX` must not panic
    /// (debug) or silently wrap `size` to a small value (release, this
    /// crate's actual deployment target -- no `overflow-checks` override).
    /// `offset` is attacker-controlled (decoded straight off the wire), so
    /// this is reachable by either endpoint of a stream.
    #[test]
    fn reassembler_fin_near_u32_max_offset_does_not_overflow() {
        let mut r = Reassembler::new(0, 4096);
        let out = r.push(&Fragment { stream_id: 0, offset: u32::MAX - 1, fin: true, data: vec![0u8; 4] }).unwrap();
        assert!(out.is_empty(), "far ahead of `next`, so nothing is contiguous yet");
        // Saturates instead of wrapping: the declared size is clamped to
        // u32::MAX, not wrapped around to something tiny like 2.
        assert_eq!(r.size(), u32::MAX);
        assert!(!r.finished(), "declaring a huge size must not itself mark the stream finished");
    }

    /// The stray-chunk purge (`reassembler_purges_stray_chunks_past_fin_size`
    /// above) must still behave sanely when `size` saturates: nothing
    /// legitimate sits at/past `u32::MAX`, so nothing should be purged, and
    /// a normal in-order prefix still delivers as data arrives.
    #[test]
    fn reassembler_fin_near_u32_max_offset_still_reassembles_prefix() {
        let mut r = Reassembler::new(0, 4096);
        r.push(&Fragment { stream_id: 0, offset: u32::MAX - 1, fin: true, data: vec![0u8; 4] }).unwrap();
        let out = r.push(&Fragment { stream_id: 0, offset: 0, fin: false, data: b"abcd".to_vec() }).unwrap();
        assert_eq!(out, b"abcd");
        assert!(!r.finished(), "the real end-of-stream chunk is still effectively unreachable at this size");
    }

    /// Consuming a contiguous chunk whose end offset would overflow `u32`
    /// must saturate `next` at `u32::MAX`, not wrap it back to a small
    /// value. A wrap would make a later, genuinely
    /// low-offset chunk falsely look contiguous with `next` and get spliced
    /// into `out` out of order -- this proves that cannot happen.
    #[test]
    fn reassembler_consuming_chunk_near_u32_max_does_not_wrap_next() {
        let mut r = Reassembler::new(0, 4096);
        // Directly place `next` near `u32::MAX`, as if it had already
        // legitimately reassembled that much of the stream -- a real
        // 4-billion-byte stream is impractical to construct in a test, but
        // the overflow behavior being tested only depends on `next`'s
        // value at the moment a contiguous chunk is consumed, not on how
        // it got there.
        r.next = u32::MAX - 3;
        // Lands exactly at `next`, so it is consumed immediately; its
        // length pushes the new `next` past `u32::MAX`.
        let out = r.push(&Fragment { stream_id: 0, offset: u32::MAX - 3, fin: false, data: vec![0u8; 8] }).unwrap();
        assert_eq!(out.len(), 8, "the chunk starting at `next` must still be consumed");
        assert_eq!(r.next, u32::MAX, "next must saturate, not wrap");

        // A low-offset chunk arriving afterward must not be treated as
        // contiguous just because a wrapped `next` would have landed there.
        let out2 = r.push(&Fragment { stream_id: 0, offset: 2, fin: false, data: b"ZZ".to_vec() }).unwrap();
        assert!(out2.is_empty(), "next is saturated at u32::MAX, so an offset-2 chunk is not contiguous and must stay pending");
    }

    #[test]
    fn reassembler_evicts_farthest_chunk_when_over_capacity() {
        let mut r = Reassembler::new(0, 2);
        r.push(&Fragment { stream_id: 0, offset: 10, fin: false, data: b"a".to_vec() }).unwrap();
        r.push(&Fragment { stream_id: 0, offset: 20, fin: false, data: b"b".to_vec() }).unwrap();
        // Over capacity (3 > 2): the farthest (30) must be evicted, not 10.
        r.push(&Fragment { stream_id: 0, offset: 30, fin: false, data: b"c".to_vec() }).unwrap();
        assert!(r.chunks.contains_key(&10));
        assert!(r.chunks.contains_key(&20));
        assert!(!r.chunks.contains_key(&30));
    }
}

#[cfg(test)]
mod python_cross_check {
    use super::*;

    #[test]
    fn encode_fragment_matches_python() {
        // python3 -c "
        //   import allium.fragment as fr
        //   f = fr.Fragment(stream_id=0x01020304, offset=0x05060708, fin=True, data=b'hi')
        //   print(fr.encode_fragment(f).hex())
        // "
        let f = Fragment { stream_id: 0x0102_0304, offset: 0x0506_0708, fin: true, data: b"hi".to_vec() };
        let bytes = encode_fragment(&f);
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "0102030405060708016869");
    }
}
