//! Fixed-size UDP cell format for the Allium onion-routing protocol.
//!
//! Wire layout (network byte order / big-endian):
//!
//! ```text
//! +--------------+---------+--------+----------+-----------------+
//! | Field        | Offset  | Size   | Format   | Notes           |
//! +--------------+---------+--------+----------+-----------------+
//! | circuit_id   | 0       | 4      | u32      | big-endian      |
//! | command      | 4       | 1      | u8       | Command         |
//! | length       | 5       | 2      | u16      | big-endian, <=1184
//! | reserved     | 7       | 1      |          | MUST be 0x00    |
//! | payload      | 8       | 1184   |          | zero padded     |
//! +--------------+---------+--------+----------+-----------------+
//! | TOTAL        |         | 1192   |          |                 |
//! +--------------+---------+--------+----------+-----------------+
//! ```
//!
//! Why is there a `reserved` byte? The header is 4 + 1 + 2 = 7 bytes and the
//! payload buffer is 1184 bytes. 7 + 1184 = 1191, so a 1192-byte cell necessarily
//! has exactly one byte of slack. Rather than let that byte be implicit
//! (which would make parsing ambiguous if the layout is ever extended), it
//! is declared explicitly as a reserved byte. It is always written as
//! `0x00` by [`Cell::pack`] and, in strict mode, rejected on receive if it
//! is non-zero. A future cell version can repurpose it without changing the
//! total on-the-wire size.

use std::fmt;

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------

/// Size of the circuit id / command / length prefix, in bytes.
pub const HEADER_SIZE: usize = 4 + 1 + 2;

/// Size of the header plus the reserved byte, in bytes.
pub const HEADER_WITH_RESERVED_SIZE: usize = HEADER_SIZE + 1;

/// Size of the fixed payload buffer, as required by the protocol.
///
/// Raised from the original 504 to 1184 (pre-public-launch cell-size
/// upgrade): at 504, per-hop onion-wrapping overhead (229 bytes fixed,
/// regardless of cell size -- see `sizes.rs`) ate 45% of every cell; at
/// 1184 it's 19%. 1184 was chosen, rather than a rounder number, by
/// working backward from [`IPV6_SAFE_MTU`]: it yields [`CELL_SIZE`] =
/// 1192, a 1220-byte on-wire datagram (see [`datagram_size`]), 12 bytes
/// under the 1232-byte unfragmented ceiling.
pub const PAYLOAD_SIZE: usize = 1184;

/// Largest value the 2-byte length field can express (bounded by the buffer).
pub const MAX_PAYLOAD_SIZE: usize = PAYLOAD_SIZE;

/// Total size of a serialized cell (and the exact size every UDP datagram must be).
pub const CELL_SIZE: usize = HEADER_WITH_RESERVED_SIZE + PAYLOAD_SIZE;

/// Value written into the reserved byte.
const RESERVED_BYTE: u8 = 0x00;

// --------------------------------------------------------------------------
// MTU budget
// --------------------------------------------------------------------------

/// Maximum UDP payload that avoids IP fragmentation on a 1500-byte Ethernet MTU:
/// 1500 minus 20 (IPv4 header) minus 8 (UDP header).
pub const IPV4_SAFE_MTU: usize = 1472;

/// The same budget for IPv6, whose header is 40 bytes: 1280 - 48, since RFC 8200
/// requires every link to carry 1280.
pub const IPV6_SAFE_MTU: usize = 1280 - 48;

/// The largest cell this implementation will accept or emit. Kept equal to
/// [`CELL_SIZE`] -- there is no slack budget above the live wire size, same
/// as before the cell-size upgrade (this was 512 when `CELL_SIZE` was 512).
pub const MAX_CELL_SIZE: usize = 1192;

/// Return the on-wire datagram size for a cell, counting IPv4 and UDP headers.
pub fn datagram_size(cell_size: Option<usize>) -> usize {
    cell_size.unwrap_or(CELL_SIZE) + 28
}

/// Return `true` if a cell of `cell_size` survives `mtu` unfragmented.
pub fn fits_without_fragmentation(cell_size: Option<usize>, mtu: usize) -> bool {
    datagram_size(cell_size) <= mtu
}

/// Return `Err(MtuError)` if `cell_size` would fragment.
///
/// Called from a `#[test]` (mirroring the Python module's import-time
/// assertion), so an edit to the cell layout that breaks the MTU budget
/// fails immediately rather than silently fragmenting every packet.
pub fn assert_mtu_safe(cell_size: Option<usize>, mtu: usize) -> Result<(), CellError> {
    let size = cell_size.unwrap_or(CELL_SIZE);
    let total = datagram_size(Some(size));
    if total > mtu {
        return Err(CellError::Mtu(format!(
            "a {size}-byte cell becomes a {total}-byte datagram, exceeding the \
             {mtu}-byte unfragmented budget; lower CELL_SIZE or MAX_CELL_SIZE"
        )));
    }
    Ok(())
}

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

/// All errors this module can raise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellError {
    /// A buffer was the wrong size, or a field was out of range.
    Size(String),
    /// The command byte was not a known [`Command`].
    InvalidCommand(String),
    /// A cell size would risk IP fragmentation.
    ///
    /// Fragmentation is worse than loss on the wire: if *any* fragment is
    /// dropped the whole datagram is lost, and many middleboxes drop
    /// fragments outright. The cell size is therefore a fixed constant this
    /// module refuses to let drift, rather than a per-connection tunable.
    Mtu(String),
}

impl fmt::Display for CellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CellError::Size(msg) => write!(f, "{msg}"),
            CellError::InvalidCommand(msg) => write!(f, "{msg}"),
            CellError::Mtu(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for CellError {}

// --------------------------------------------------------------------------
// Command
// --------------------------------------------------------------------------

/// Cell command types understood by Allium relays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Command {
    Create = 1,
    Created = 2,
    Extend = 3,
    Data = 4,
    Destroy = 5,
    Ack = 6,
    /// A relayed reply to an onion-carried EXTEND request (see
    /// [`crate::layer::Kind`]). Distinct from `Data` so a relay can dispatch
    /// it to the backward path instead of the forward path. `Extend` above
    /// is reserved but unused at the cell level: a forward EXTEND *request*
    /// travels as an ordinary `Data` cell whose innermost onion layer
    /// happens to be `Kind::Extend` -- only the *reply* needs a distinct
    /// cell command, because only the reply is dispatched differently.
    Extended = 7,
    /// Return-path *data* travelling backward along a circuit from the exit
    /// toward the client. Distinct from `Data` because `Data` only ever
    /// flows forward, but the two are interchangeable on the wire -- a relay
    /// refuses to send a `Relay` cell forward, and refuses to send a `Data`
    /// cell backward, so the command byte is part of the validation that a
    /// cell is travelling in an allowed direction.
    Relay = 8,
    /// Open an end-to-end stream. Sent forward (through the onion, like
    /// `Data`) to the exit; its payload is a
    /// [`crate::socks::StreamRequest`].
    Begin = 9,
    /// The exit's reply to a `Begin`: success (with an attached stream id),
    /// or a failure reason. Travelling backward, dispatched like `Relay`.
    Connected = 10,
    /// A relay's cheap, stateless reply to a `Create` it will not yet spend
    /// DH/Ed25519-signature work on, because the sender has not
    /// demonstrated it can receive replies at its claimed UDP source
    /// address. Carries a challenge body with a short-lived, unforgeable
    /// cookie derived from the source address; a genuine sender echoes it
    /// back in a retried `Create` and only then does the relay commit to
    /// the expensive asymmetric work.
    CreateChallenge = 11,
    /// One piece of a `Create` whose body is too large for a single cell --
    /// the post-quantum hybrid handshake (see [`crate::createfrag`] and
    /// [`crate::handshake`]), whose ML-KEM-768 ciphertext alone is 1088
    /// bytes. Every fragment is still an ordinary fixed 1192-byte cell.
    CreateFragment = 12,
}

impl Command {
    /// Return the [`Command`] for `value`.
    ///
    /// # Errors
    /// Returns [`CellError::InvalidCommand`] if `value` is not a known command.
    pub fn from_int(value: u8) -> Result<Self, CellError> {
        Ok(match value {
            1 => Command::Create,
            2 => Command::Created,
            3 => Command::Extend,
            4 => Command::Data,
            5 => Command::Destroy,
            6 => Command::Ack,
            7 => Command::Extended,
            8 => Command::Relay,
            9 => Command::Begin,
            10 => Command::Connected,
            11 => Command::CreateChallenge,
            12 => Command::CreateFragment,
            other => {
                return Err(CellError::InvalidCommand(format!(
                    "unknown command {other}; expected one of {{CREATE=1, CREATED=2, \
                     EXTEND=3, DATA=4, DESTROY=5, ACK=6, EXTENDED=7, RELAY=8, BEGIN=9, \
                     CONNECTED=10, CREATE_CHALLENGE=11, CREATE_FRAGMENT=12}}"
                )))
            }
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Command::Create => "CREATE",
            Command::Created => "CREATED",
            Command::Extend => "EXTEND",
            Command::Data => "DATA",
            Command::Destroy => "DESTROY",
            Command::Ack => "ACK",
            Command::Extended => "EXTENDED",
            Command::Relay => "RELAY",
            Command::Begin => "BEGIN",
            Command::Connected => "CONNECTED",
            Command::CreateChallenge => "CREATE_CHALLENGE",
            Command::CreateFragment => "CREATE_FRAGMENT",
        }
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.name(), *self as u8)
    }
}

impl From<Command> for u8 {
    fn from(c: Command) -> u8 {
        c as u8
    }
}

// --------------------------------------------------------------------------
// Cell
// --------------------------------------------------------------------------

/// A single 1192-byte Allium UDP cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cell {
    /// 32-bit circuit identifier.
    pub circuit_id: u32,
    pub command: Command,
    /// Up to [`MAX_PAYLOAD_SIZE`] (1184) bytes. Shorter payloads are zero
    /// padded on the wire; the wire `length` field records the real size.
    pub payload: Vec<u8>,
}

impl Cell {
    /// Build a new cell.
    ///
    /// # Errors
    /// Returns [`CellError::Size`] if `payload` is longer than 1184 bytes.
    pub fn new(circuit_id: u32, command: Command, payload: Vec<u8>) -> Result<Self, CellError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(CellError::Size(format!(
                "payload is {} bytes, maximum is {MAX_PAYLOAD_SIZE}",
                payload.len()
            )));
        }
        Ok(Cell {
            circuit_id,
            command,
            payload,
        })
    }

    /// Number of meaningful bytes carried inside the 1184-byte payload buffer.
    pub fn length(&self) -> usize {
        self.payload.len()
    }

    /// Serialize this cell into exactly [`CELL_SIZE`] (1192) bytes.
    ///
    /// The payload is zero padded to the fixed 1184-byte buffer and the
    /// reserved byte is written as `0x00`.
    pub fn pack(&self) -> [u8; CELL_SIZE] {
        let mut out = [0u8; CELL_SIZE];
        out[0..4].copy_from_slice(&self.circuit_id.to_be_bytes());
        out[4] = self.command.into();
        out[5..7].copy_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out[7] = RESERVED_BYTE;
        out[8..8 + self.payload.len()].copy_from_slice(&self.payload);
        // The rest of out[8..] is already zero (padding).
        out
    }

    /// Alias for [`Cell::pack`], mirroring `int.to_bytes` naming.
    pub fn to_bytes(&self) -> [u8; CELL_SIZE] {
        self.pack()
    }

    /// Parse exactly 1192 bytes received from the network into a [`Cell`].
    ///
    /// `strict`: when `true` the reserved byte must be `0x00`. Set to
    /// `false` for forward compatibility with a future cell version that
    /// repurposes that byte.
    ///
    /// # Errors
    /// Returns [`CellError::Size`] if `data` is not exactly 1192 bytes, or if
    /// the declared length exceeds the 1184-byte payload buffer, or (in
    /// strict mode) if the reserved byte is non-zero.
    /// Returns [`CellError::InvalidCommand`] if the command byte is unknown.
    pub fn unpack(data: &[u8], strict: bool) -> Result<Self, CellError> {
        if data.len() != CELL_SIZE {
            return Err(CellError::Size(format!(
                "cell must be exactly {CELL_SIZE} bytes, received {}",
                data.len()
            )));
        }

        let circuit_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let raw_command = data[4];
        let declared_length = u16::from_be_bytes([data[5], data[6]]) as usize;
        let reserved = data[7];
        let payload_buffer = &data[8..8 + PAYLOAD_SIZE];

        if declared_length > PAYLOAD_SIZE {
            return Err(CellError::Size(format!(
                "declared length {declared_length} exceeds the {PAYLOAD_SIZE}-byte payload buffer"
            )));
        }

        if strict && reserved != RESERVED_BYTE {
            return Err(CellError::Size(format!(
                "reserved byte must be 0x{RESERVED_BYTE:02x}, got 0x{reserved:02x}"
            )));
        }

        let command = Command::from_int(raw_command)?;

        // `length` is authoritative: bytes beyond it are padding and are
        // never returned as data.
        let payload = payload_buffer[..declared_length].to_vec();

        Ok(Cell {
            circuit_id,
            command,
            payload,
        })
    }

    /// Lenient parser for relay hot paths.
    ///
    /// Unlike [`Cell::unpack`] this never fails on a wrong datagram size: it
    /// truncates an over-long datagram and zero pads a short one before
    /// parsing. Unknown commands are still rejected.
    pub fn from_bytes(data: &[u8], strict: bool) -> Result<Self, CellError> {
        if data.len() == CELL_SIZE {
            return Self::unpack(data, strict);
        }
        let mut buf = [0u8; CELL_SIZE];
        let n = data.len().min(CELL_SIZE);
        buf[..n].copy_from_slice(&data[..n]);
        Self::unpack(&buf, strict)
    }

    /// Return `true` if the payload fills the entire 1184-byte buffer.
    pub fn is_padding_free(&self) -> bool {
        self.length() == PAYLOAD_SIZE
    }

    /// Build a payload-less cell (handy for DESTROY / control traffic).
    pub fn empty(circuit_id: u32, command: Command) -> Self {
        Cell {
            circuit_id,
            command,
            payload: Vec::new(),
        }
    }
}

impl fmt::Display for Cell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let preview_len = self.length().min(16);
        let preview = &self.payload[..preview_len];
        let ellipsis = if self.length() > 16 { "..." } else { "" };
        write!(
            f,
            "Cell(circuit_id={}, command={}, length={}, payload={:?}{ellipsis})",
            self.circuit_id,
            self.command.name(),
            self.length(),
            preview
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtu_budget_holds_for_the_current_cell_size() {
        // Mirrors the Python module's import-time assertion.
        assert_mtu_safe(Some(CELL_SIZE), IPV4_SAFE_MTU).unwrap();
        assert_mtu_safe(Some(CELL_SIZE), IPV6_SAFE_MTU).unwrap();
    }

    #[test]
    fn pack_and_unpack_round_trip() {
        let cell = Cell::new(42, Command::Data, b"hello".to_vec()).unwrap();
        let packed = cell.pack();
        assert_eq!(packed.len(), CELL_SIZE);
        let parsed = Cell::unpack(&packed, true).unwrap();
        assert_eq!(cell, parsed);
    }

    #[test]
    fn payload_too_large_is_rejected() {
        let payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        assert!(Cell::new(1, Command::Data, payload).is_err());
    }

    #[test]
    fn unknown_command_is_rejected() {
        assert!(Command::from_int(200).is_err());
    }

    #[test]
    fn non_zero_reserved_byte_rejected_in_strict_mode() {
        let cell = Cell::new(1, Command::Data, b"x".to_vec()).unwrap();
        let mut packed = cell.pack();
        packed[7] = 0x01;
        assert!(Cell::unpack(&packed, true).is_err());
        // Lenient mode accepts it.
        assert!(Cell::unpack(&packed, false).is_ok());
    }

    #[test]
    fn from_bytes_pads_short_datagrams() {
        let short = vec![0u8; 10];
        // circuit_id=0, command byte at index 4 is 0 -> invalid command.
        assert!(Cell::from_bytes(&short, false).is_err());
    }

    #[test]
    fn declared_length_over_buffer_is_rejected() {
        let mut packed = Cell::new(1, Command::Data, b"x".to_vec()).unwrap().pack();
        packed[5] = 0xFF;
        packed[6] = 0xFF;
        assert!(Cell::unpack(&packed, true).is_err());
    }
}
