//! Size arithmetic for Allium onion layers.
//!
//! Every layer takes a plaintext and produces a *larger* sealed field, so
//! the 1184-byte payload has to pay for three layers of framing before any
//! user data fits. Working this out is the difference between a datagram
//! that packs and one that fails at send time, so this module owns the
//! arithmetic.
//!
//! For the default three-hop circuit the budget is derived as follows --
//! these are the real constants, not an illustration:
//!
//! ```text
//! cell payload buffer                                   1184
//! - 3 layers * (header 29 + nonce 12 + tag 16 = 57)  =  -171
//! ------------------------------------------------------------
//! user data budget (user_data_budget(3))             =  1013
//! ```
//!
//! (Raised from a 504-byte cell / 275-byte budget in the pre-public-launch
//! cell-size upgrade -- see `cell::PAYLOAD_SIZE`'s own doc comment.)
//!
//! Each hop costs a full header plus the AEAD nonce and tag:
//!
//! ```text
//! budget = payload_size - hop_count * (ROUTE_HEADER_SIZE + SEAL_OVERHEAD)
//! ```
//!
//! A header is 29 bytes of framing split in two (see [`crate::layer`] for
//! the exact field layout): a [`WIRE_HEADER_SIZE`] (22) cleartext part --
//! `seq` (4) + `length` (2) + 4 reserved bytes + `ver` (1) + an 11-byte
//! truncated MAC -- and a [`SEALED_HEADER_SIZE`] (7) part that travels
//! *inside* the layer's AEAD ciphertext: `kind` (1) + a 6-byte address. A
//! route layer puts the next relay's `(ip, port)` in the address slot and a
//! payload layer puts the exit's `final_addr` there; both are 6 bytes, so
//! the header costs the same whichever way the layer is used.
//!
//! Layer format `0xA3` and earlier carried the address in the cleartext
//! part, and a route layer additionally spent a second full 29-byte header
//! inside its plaintext naming the next relay -- `(hop_count - 1) * 29`
//! extra bytes per onion, which is why the budget used to be 955. Sealing
//! the address made that inner header redundant, so it is gone.

use std::fmt;

use crate::cell::PAYLOAD_SIZE;
use crate::crypto::SEAL_OVERHEAD;

/// Number of relays an Allium circuit uses: Guard, Middle, Exit.
pub const HOP_COUNT: usize = 3;

// Fixed fields in a layer header.
pub const SEQ_SIZE: usize = 4;
pub const KIND_SIZE: usize = 1;
pub const HEADER_LENGTH_SIZE: usize = 2;
pub const HOP_ID_SIZE: usize = 4;
/// IPv4 address (4) + port (2).
pub const NEXT_HOP_SIZE: usize = 6;
/// IPv4 address (4) + port (2).
pub const FINAL_ADDR_SIZE: usize = 6;
const HOP_INDEX_SIZE: usize = 1;

/// Bytes of the HMAC-SHA256 output kept as a layer header's MAC. 11 bytes
/// clears the 8-byte floor NIST SP 800-107 permits for HMAC-SHA256, and the
/// fixed fields (`seq` 4 + `kind` 1 + `length` 2 + `hop_id` 4 + `hop_index`
/// 1 + `addr` 6 = 18) plus an 11-byte MAC land the header on exactly 29
/// bytes.
pub const MAC_TRUNCATED_SIZE: usize = 11;

/// Full digest size built before truncation.
pub const MAC_SIZE: usize = 32;

/// The cleartext part of a layer header, the bytes that precede the AEAD
/// ciphertext on the wire: `seq(4) + length(2) + hop_id(4) + hop_index(1)
/// + mac(11)` = 22. (`hop_id`/`hop_index` are reserved, always-zero slots;
/// the `hop_index` byte now carries the layer protocol version.)
pub const WIRE_HEADER_SIZE: usize =
    SEQ_SIZE + HEADER_LENGTH_SIZE + HOP_ID_SIZE + HOP_INDEX_SIZE + MAC_TRUNCATED_SIZE;

/// The part of a layer header sealed inside the AEAD ciphertext, ahead of
/// the layer's body: `kind(1) + addr(6)` = 7. Nothing on the wire reveals
/// a layer's kind or the address it names.
pub const SEALED_HEADER_SIZE: usize = KIND_SIZE + NEXT_HOP_SIZE;

/// Declared size of a layer header: the cleartext [`WIRE_HEADER_SIZE`]
/// part plus the [`SEALED_HEADER_SIZE`] part, 29 bytes in all.
pub const ROUTE_HEADER_SIZE: usize = WIRE_HEADER_SIZE + SEALED_HEADER_SIZE;

/// A payload header replaces `next_hop` with `final_addr`, so it is the same size.
pub const PAYLOAD_HEADER_SIZE: usize = ROUTE_HEADER_SIZE;

/// Bytes a single layer adds to the plaintext it wraps: frame header + nonce + tag.
pub const PER_LAYER_OVERHEAD: usize = ROUTE_HEADER_SIZE + SEAL_OVERHEAD;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SizesError {
    /// User data plus overhead cannot fit in one cell payload.
    OnionTooLarge(String),
    /// A bad argument (non-positive hop count/payload size, negative
    /// length, out-of-range port, ...).
    Value(String),
}

impl fmt::Display for SizesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SizesError::OnionTooLarge(m) | SizesError::Value(m) => write!(f, "{m}"),
        }
    }
}
impl std::error::Error for SizesError {}

/// Return how many user bytes fit in `payload_size` after `hop_count` layers.
///
/// A layer adds its header (both parts) plus an AEAD nonce and tag, so
/// each hop costs `ROUTE_HEADER_SIZE + SEAL_OVERHEAD`.
///
/// # Errors
/// Returns [`SizesError::Value`] if `hop_count` or `payload_size` is not
/// positive.
pub fn user_data_budget(hop_count: usize, payload_size: usize) -> Result<i64, SizesError> {
    if hop_count < 1 {
        return Err(SizesError::Value(format!(
            "hop_count must be at least 1, got {hop_count}"
        )));
    }
    if payload_size < 1 {
        return Err(SizesError::Value(format!(
            "payload_size must be positive, got {payload_size}"
        )));
    }
    let per_hop = (ROUTE_HEADER_SIZE + SEAL_OVERHEAD) as i64;
    Ok(payload_size as i64 - hop_count as i64 * per_hop)
}

/// [`user_data_budget`] with the Python defaults (`HOP_COUNT`, `PAYLOAD_SIZE`).
pub fn user_data_budget_default() -> i64 {
    user_data_budget(HOP_COUNT, PAYLOAD_SIZE).expect("defaults are always valid")
}

/// Return the sealed onion size for `user_data_len` bytes of user data.
///
/// Lets a caller confirm a message fits *before* encrypting instead of
/// discovering a cell-size error afterwards.
///
/// # Errors
/// Returns [`SizesError::OnionTooLarge`] if `user_data_len` exceeds the
/// budget for `hop_count` layers.
pub fn onion_size(user_data_len: usize, hop_count: usize) -> Result<usize, SizesError> {
    let budget = user_data_budget(hop_count, PAYLOAD_SIZE)?;
    if user_data_len as i64 > budget {
        return Err(SizesError::OnionTooLarge(format!(
            "{user_data_len} user bytes exceed the {budget}-byte budget for {hop_count} layers"
        )));
    }
    // An empty payload still gets every layer of framing, so there is no
    // zero-size special case.
    let per_hop = ROUTE_HEADER_SIZE + SEAL_OVERHEAD;
    Ok(user_data_len + hop_count * per_hop)
}

/// [`onion_size`] with the Python default hop count ([`HOP_COUNT`]).
pub fn onion_size_default(user_data_len: usize) -> Result<usize, SizesError> {
    onion_size(user_data_len, HOP_COUNT)
}

/// Alias for [`user_data_budget`] with cell-first argument order.
pub fn max_user_data(payload_size: usize, hop_count: usize) -> Result<i64, SizesError> {
    user_data_budget(hop_count, payload_size)
}

/// An `(ip, port)` pair naming one relay.
pub type Hop = (String, u16);

/// The relay list for one circuit, with precomputed header positions.
///
/// A relay at index `i` decrypts one layer, reads its own header, and
/// learns only the address of the *next* hop. It never sees the whole hop
/// list -- that exists solely on the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePlan {
    pub hops: Vec<Hop>,
    pub payload_size: usize,
    pub final_addr: Hop,
}

impl RoutePlan {
    /// Build a route plan.
    ///
    /// # Errors
    /// Returns [`SizesError::Value`] if `hops` is empty.
    pub fn new(hops: Vec<Hop>, final_addr: Hop, payload_size: usize) -> Result<Self, SizesError> {
        if hops.is_empty() {
            return Err(SizesError::Value("a route needs at least one hop".into()));
        }
        Ok(RoutePlan {
            hops,
            payload_size,
            final_addr,
        })
    }

    /// [`RoutePlan::new`] with `final_addr = ("127.0.0.1", 0)` and the
    /// default payload size, mirroring the Python constructor's defaults.
    pub fn with_hops(hops: Vec<Hop>) -> Result<Self, SizesError> {
        Self::new(hops, ("127.0.0.1".to_string(), 0), PAYLOAD_SIZE)
    }

    /// Number of relays on this circuit.
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// User bytes this route can carry in one cell.
    pub fn budget(&self) -> i64 {
        user_data_budget(self.hop_count(), self.payload_size).expect("hop_count is always >= 1")
    }

    /// Return the hop after `index`, or `None` when `index` is the last hop.
    ///
    /// # Errors
    /// Returns [`SizesError::Value`] if `index` is out of range.
    pub fn next_hop(&self, index: usize) -> Result<Option<&Hop>, SizesError> {
        if index >= self.hop_count() {
            return Err(SizesError::Value(format!(
                "hop index {index} out of range 0..{}",
                self.hop_count() - 1
            )));
        }
        Ok(self.hops.get(index + 1))
    }

    /// Return the sealed onion size for `user_data_len`, raising if it does not fit.
    pub fn assert_fits(&self, user_data_len: usize) -> Result<usize, SizesError> {
        onion_size(user_data_len, self.hop_count())
    }
}

impl fmt::Display for RoutePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RoutePlan(hops={:?}, final_addr={:?}, budget={})",
            self.hops,
            self.final_addr,
            self.budget()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_hop_budget_matches_documented_constant() {
        assert_eq!(WIRE_HEADER_SIZE, 22);
        assert_eq!(SEALED_HEADER_SIZE, 7);
        assert_eq!(ROUTE_HEADER_SIZE, 29);
        assert_eq!(user_data_budget_default(), 1013);
    }

    #[test]
    fn onion_size_round_trips_with_budget() {
        let budget = user_data_budget_default();
        assert!(onion_size_default(budget as usize).is_ok());
        assert!(onion_size_default(budget as usize + 1).is_err());
    }

    #[test]
    fn route_plan_next_hop_walks_the_circuit() {
        let hops = vec![
            ("1.2.3.4".to_string(), 1000),
            ("5.6.7.8".to_string(), 2000),
            ("9.9.9.9".to_string(), 3000),
        ];
        let plan = RoutePlan::with_hops(hops.clone()).unwrap();
        assert_eq!(plan.hop_count(), 3);
        assert_eq!(plan.next_hop(0).unwrap(), Some(&hops[1]));
        assert_eq!(plan.next_hop(1).unwrap(), Some(&hops[2]));
        assert_eq!(plan.next_hop(2).unwrap(), None);
        assert!(plan.next_hop(3).is_err());
    }

    #[test]
    fn empty_hops_rejected() {
        assert!(RoutePlan::with_hops(vec![]).is_err());
    }
}
