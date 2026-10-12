//! Size arithmetic for Allium onion layers.
//!
//! For the default three-hop circuit the budget is derived as follows:
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
//! A header is 29 bytes split in two (see `crate::layer`): a
//! [`WIRE_HEADER_SIZE`] (22) cleartext part and a [`SEALED_HEADER_SIZE`]
//! (7) part -- the layer's kind and address -- that travels inside the
//! AEAD ciphertext. Layer format `0xA3` and earlier carried the address in
//! the clear and spent a second full 29-byte header inside every ROUTE
//! layer's plaintext naming the next relay, `(hop_count - 1) * 29` extra
//! bytes per onion, which is why the budget used to be 955.

use crate::cell::PAYLOAD_SIZE;
use crate::crypto::SEAL_OVERHEAD;
use std::fmt;

/// Number of relays an Allium circuit uses: Guard, Middle, Exit.
pub const HOP_COUNT: usize = 3;

/// Fixed fields in a layer header.
pub const SEQ_SIZE: usize = 4;
pub const KIND_SIZE: usize = 1;
pub const HEADER_LENGTH_SIZE: usize = 2;
pub const HOP_ID_SIZE: usize = 4;
/// IPv4 address (4) + port (2).
pub const NEXT_HOP_SIZE: usize = 6;
/// IPv4 address (4) + port (2).
pub const FINAL_ADDR_SIZE: usize = 6;

/// Bytes of the HMAC-SHA256 output kept as a layer header's MAC.
pub const MAC_TRUNCATED_SIZE: usize = 11;
/// Full digest size built before truncation.
pub const MAC_SIZE: usize = 32;

/// The wire (cleartext) part of the layer header as a struct format string
/// (for documentation): seq, length, reserved, ver, mac.
pub const HEADER_FORMAT: &str = ">IHIB11s";
/// The sealed part of the layer header as a struct format string: kind, addr.
pub const SEALED_HEADER_FORMAT: &str = ">B6s";

/// The cleartext part of a layer header, the bytes that precede the AEAD
/// ciphertext on the wire: seq(4) + length(2) + hop_id(4) + ver(1) +
/// mac(11) = 22.
pub const WIRE_HEADER_SIZE: usize = SEQ_SIZE + HEADER_LENGTH_SIZE + HOP_ID_SIZE + 1 + MAC_TRUNCATED_SIZE;

/// The part of a layer header sealed inside the AEAD ciphertext, ahead of
/// the layer's body: kind(1) + addr(6) = 7.
pub const SEALED_HEADER_SIZE: usize = KIND_SIZE + FINAL_ADDR_SIZE;

/// Declared size of a layer header: the wire part plus the sealed part = 29.
pub const ROUTE_HEADER_SIZE: usize = WIRE_HEADER_SIZE + SEALED_HEADER_SIZE;

/// A payload header replaces `next_hop` with `final_addr`, so it is the same size.
pub const PAYLOAD_HEADER_SIZE: usize = ROUTE_HEADER_SIZE;

/// Bytes a single layer adds to the plaintext it wraps: frame header + nonce + tag.
pub const PER_LAYER_OVERHEAD: usize = ROUTE_HEADER_SIZE + SEAL_OVERHEAD;

/// Raised when user data plus overhead cannot fit in one cell payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionTooLargeError {
    pub message: String,
}
impl fmt::Display for OnionTooLargeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for OnionTooLargeError {}

/// Errors this module can raise, matching Python's ValueError / OnionTooLargeError split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SizesError {
    Value(String),
    TooLarge(OnionTooLargeError),
}
impl fmt::Display for SizesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SizesError::Value(s) => write!(f, "{s}"),
            SizesError::TooLarge(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for SizesError {}

/// Return how many user bytes fit in `payload_size` after `hop_count` layers.
pub fn user_data_budget(hop_count: i64, payload_size: i64) -> Result<i64, SizesError> {
    if hop_count < 1 {
        return Err(SizesError::Value(format!("hop_count must be at least 1, got {hop_count}")));
    }
    if payload_size < 1 {
        return Err(SizesError::Value(format!("payload_size must be positive, got {payload_size}")));
    }
    let per_hop = ROUTE_HEADER_SIZE as i64 + SEAL_OVERHEAD as i64;
    Ok(payload_size - hop_count * per_hop)
}

/// [`user_data_budget`] with the default hop count ([`HOP_COUNT`]) and payload size
/// ([`PAYLOAD_SIZE`]).
pub fn user_data_budget_default() -> i64 {
    user_data_budget(HOP_COUNT as i64, PAYLOAD_SIZE as i64).unwrap()
}

/// Return the sealed onion size for `user_data_len` bytes of user data.
pub fn onion_size(user_data_len: i64, hop_count: i64) -> Result<i64, SizesError> {
    if user_data_len < 0 {
        return Err(SizesError::Value(format!(
            "user_data_len must not be negative, got {user_data_len}"
        )));
    }
    let budget = user_data_budget(hop_count, PAYLOAD_SIZE as i64)?;
    if user_data_len > budget {
        return Err(SizesError::TooLarge(OnionTooLargeError {
            message: format!(
                "{user_data_len} user bytes exceed the {budget}-byte budget for {hop_count} layers"
            ),
        }));
    }
    let per_hop = ROUTE_HEADER_SIZE as i64 + SEAL_OVERHEAD as i64;
    Ok(user_data_len + hop_count * per_hop)
}

/// Onion size using the default hop count ([`HOP_COUNT`]).
pub fn onion_size_default(user_data_len: i64) -> Result<i64, SizesError> {
    onion_size(user_data_len, HOP_COUNT as i64)
}

/// Alias for [`user_data_budget`] with cell-first argument order.
pub fn max_user_data(payload_size: i64, hop_count: i64) -> Result<i64, SizesError> {
    user_data_budget(hop_count, payload_size)
}

/// One relay hop: `(ip, port)`.
pub type Hop = (String, u16);

/// The relay list for one circuit, with precomputed header positions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePlan {
    pub hops: Vec<Hop>,
    pub payload_size: i64,
    pub final_addr: Hop,
}

impl RoutePlan {
    /// Build a new route plan.
    ///
    /// # Errors
    /// Returns a [`SizesError::Value`] if `hops` is empty.
    pub fn new(hops: Vec<Hop>, final_addr: Hop, payload_size: i64) -> Result<RoutePlan, SizesError> {
        if hops.is_empty() {
            return Err(SizesError::Value("a route needs at least one hop".to_string()));
        }
        Ok(RoutePlan { hops, payload_size, final_addr })
    }

    /// Build with the default final address (`127.0.0.1:0`) and payload size.
    pub fn with_defaults(hops: Vec<Hop>) -> Result<RoutePlan, SizesError> {
        RoutePlan::new(hops, ("127.0.0.1".to_string(), 0), PAYLOAD_SIZE as i64)
    }

    /// Number of relays on this circuit.
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// User bytes this route can carry in one cell.
    pub fn budget(&self) -> i64 {
        user_data_budget(self.hop_count() as i64, self.payload_size).unwrap()
    }

    /// Return the hop after `index`, or `None` when `index` is the last hop.
    ///
    /// # Panics
    /// Panics if `index` is out of range (mirrors Python's `IndexError`; callers
    /// that need a `Result` should bounds-check first).
    pub fn next_hop(&self, index: usize) -> Option<Hop> {
        assert!(index < self.hop_count(), "hop index {index} out of range 0..{}", self.hop_count() - 1);
        self.hops.get(index + 1).cloned()
    }

    /// Return the sealed onion size for `user_data_len`, raising if it does not fit.
    pub fn assert_fits(&self, user_data_len: i64) -> Result<i64, SizesError> {
        onion_size(user_data_len, self.hop_count() as i64)
    }

    pub fn len(&self) -> usize {
        self.hop_count()
    }

    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_header_size_is_29() {
        assert_eq!(WIRE_HEADER_SIZE, 22);
        assert_eq!(SEALED_HEADER_SIZE, 7);
        assert_eq!(ROUTE_HEADER_SIZE, 29);
    }

    #[test]
    fn test_per_layer_overhead() {
        assert_eq!(PER_LAYER_OVERHEAD, 29 + SEAL_OVERHEAD);
    }

    #[test]
    fn test_user_data_budget_default_is_1013() {
        assert_eq!(user_data_budget_default(), 1013);
    }

    #[test]
    fn test_user_data_budget_single_hop() {
        // 504 - 1*(29+28) = 447
        assert_eq!(user_data_budget(1, 504).unwrap(), 504 - 57);
    }

    #[test]
    fn test_user_data_budget_rejects_bad_hop_count() {
        assert!(user_data_budget(0, 504).is_err());
    }

    #[test]
    fn test_user_data_budget_rejects_bad_payload_size() {
        assert!(user_data_budget(3, 0).is_err());
    }

    #[test]
    fn test_onion_size_roundtrips_with_budget() {
        let budget = user_data_budget_default();
        let sealed = onion_size_default(budget).unwrap();
        assert_eq!(sealed, PAYLOAD_SIZE as i64);
    }

    #[test]
    fn test_onion_size_rejects_negative() {
        assert!(onion_size_default(-1).is_err());
    }

    #[test]
    fn test_onion_size_too_large() {
        let budget = user_data_budget_default();
        let err = onion_size_default(budget + 1).unwrap_err();
        assert!(matches!(err, SizesError::TooLarge(_)));
    }

    #[test]
    fn test_max_user_data_alias() {
        assert_eq!(
            max_user_data(PAYLOAD_SIZE as i64, HOP_COUNT as i64).unwrap(),
            user_data_budget_default()
        );
    }

    #[test]
    fn test_route_plan_rejects_empty_hops() {
        assert!(RoutePlan::with_defaults(vec![]).is_err());
    }

    #[test]
    fn test_route_plan_hop_count_and_budget() {
        let hops = vec![
            ("10.0.0.1".to_string(), 1000),
            ("10.0.0.2".to_string(), 1001),
            ("10.0.0.3".to_string(), 1002),
        ];
        let plan = RoutePlan::with_defaults(hops).unwrap();
        assert_eq!(plan.hop_count(), 3);
        assert_eq!(plan.len(), 3);
        assert_eq!(plan.budget(), 1013);
    }

    #[test]
    fn test_route_plan_next_hop() {
        let hops = vec![
            ("10.0.0.1".to_string(), 1000),
            ("10.0.0.2".to_string(), 1001),
            ("10.0.0.3".to_string(), 1002),
        ];
        let plan = RoutePlan::with_defaults(hops).unwrap();
        assert_eq!(plan.next_hop(0), Some(("10.0.0.2".to_string(), 1001)));
        assert_eq!(plan.next_hop(2), None);
    }

    #[test]
    #[should_panic]
    fn test_route_plan_next_hop_out_of_range_panics() {
        let hops = vec![("10.0.0.1".to_string(), 1000)];
        let plan = RoutePlan::with_defaults(hops).unwrap();
        plan.next_hop(5);
    }

    #[test]
    fn test_route_plan_assert_fits() {
        let hops = vec![
            ("10.0.0.1".to_string(), 1000),
            ("10.0.0.2".to_string(), 1001),
            ("10.0.0.3".to_string(), 1002),
        ];
        let plan = RoutePlan::with_defaults(hops).unwrap();
        assert!(plan.assert_fits(1013).is_ok());
        assert!(plan.assert_fits(1014).is_err());
    }
}
