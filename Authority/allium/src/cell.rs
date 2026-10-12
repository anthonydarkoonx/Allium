//! Fixed-size UDP cell format for the Allium onion-routing protocol.
//!
//! Wire layout (network byte order / big-endian):
//!
//! ```text
//! +--------------+---------+--------+----------+-----------------+
//! | Field        | Offset  | Size   | Format   | Notes           |
//! +--------------+---------+--------+----------+-----------------+
//! | circuit_id   | 0       | 4      | u32      | uint32          |
//! | command      | 4       | 1      | u8       | uint8, Command  |
//! | length       | 5       | 2      | u16      | uint16, <= 1184 |
//! | reserved     | 7       | 1      | u8       | MUST be 0x00    |
//! | payload      | 8       | 1184   | [u8;1184]| zero padded     |
//! +--------------+---------+--------+----------+-----------------+
//! | TOTAL        |         | 1192   |          |                 |
//! +--------------+---------+--------+----------+-----------------+
//! ```

use std::fmt;

/// Size of the circuit id / command / length prefix, in bytes.
pub const HEADER_SIZE: usize = 7;
/// Size of the header plus the reserved byte, in bytes.
pub const HEADER_WITH_RESERVED_SIZE: usize = 8;
/// Size of the fixed payload buffer, as required by the protocol.
///
/// Raised from the original 504 to 1184 (pre-public-launch cell-size
/// upgrade): at 504, per-hop onion-wrapping overhead (229 bytes fixed,
/// regardless of cell size -- see `sizes.rs`) ate 45% of every cell; at
/// 1184 it's 19%. 1184 was chosen, rather than a rounder number, by
/// working backward from [`IPV6_SAFE_MTU`]: it yields [`CELL_SIZE`] =
/// 1192, a 1220-byte on-wire datagram (see [`datagram_size`]), 12 bytes
/// under the 1232-byte unfragmented ceiling -- verified by
/// `test_assert_mtu_safe_passes_for_the_current_size` below, not just
/// asserted here.
pub const PAYLOAD_SIZE: usize = 1184;
/// Largest value the 2-byte length field can express.
pub const MAX_PAYLOAD_SIZE: usize = PAYLOAD_SIZE;
/// Total size of a serialized cell (and the exact size every UDP datagram must be).
pub const CELL_SIZE: usize = HEADER_WITH_RESERVED_SIZE + PAYLOAD_SIZE;
/// Value written into the reserved byte.
const RESERVED_BYTE: u8 = 0x00;

/// Maximum UDP payload that avoids IP fragmentation on a 1500-byte Ethernet MTU.
pub const IPV4_SAFE_MTU: i64 = 1472;
/// The same budget for IPv6, whose header is 40 bytes.
pub const IPV6_SAFE_MTU: i64 = 1280 - 48;
/// The largest cell this implementation will accept or emit. Kept equal
/// to [`CELL_SIZE`] -- there is no slack budget above the live wire
/// size, same as before the cell-size upgrade (this was 512 when
/// `CELL_SIZE` was 512).
pub const MAX_CELL_SIZE: usize = 1192;

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

/// Base error type for all Allium cell errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellError {
    Size(CellSizeError),
    InvalidCommand(InvalidCommandError),
    Type(String),
}

impl fmt::Display for CellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CellError::Size(e) => write!(f, "{e}"),
            CellError::InvalidCommand(e) => write!(f, "{e}"),
            CellError::Type(s) => write!(f, "data must be bytes-like, got {s}"),
        }
    }
}
impl std::error::Error for CellError {}

impl From<CellSizeError> for CellError {
    fn from(e: CellSizeError) -> Self {
        CellError::Size(e)
    }
}
impl From<InvalidCommandError> for CellError {
    fn from(e: InvalidCommandError) -> Self {
        CellError::InvalidCommand(e)
    }
}

/// Raised when a buffer is the wrong size, or a field is out of range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellSizeError {
    pub message: String,
}

impl fmt::Display for CellSizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for CellSizeError {}

impl CellSizeError {
    fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

/// Raised when the command byte is not a known [`Command`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidCommandError {
    pub message: String,
}

impl fmt::Display for InvalidCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for InvalidCommandError {}

impl InvalidCommandError {
    fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

/// Raised when a cell size would risk IP fragmentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtuError {
    pub message: String,
}

impl fmt::Display for MtuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for MtuError {}

// --------------------------------------------------------------------------
// MTU budget
// --------------------------------------------------------------------------

/// Return the on-wire datagram size for a cell, counting IPv4 and UDP headers.
pub fn datagram_size(cell_size: Option<i64>) -> i64 {
    cell_size.unwrap_or(CELL_SIZE as i64) + 28
}

/// Return `true` if a cell of `cell_size` survives `mtu` unfragmented.
pub fn fits_without_fragmentation(cell_size: Option<i64>, mtu: i64) -> bool {
    datagram_size(cell_size) <= mtu
}

/// Raise [`MtuError`] if `cell_size` would fragment.
pub fn assert_mtu_safe(cell_size: Option<i64>, mtu: i64) -> Result<(), MtuError> {
    let size = cell_size.unwrap_or(CELL_SIZE as i64);
    let total = datagram_size(Some(size));
    if total > mtu {
        return Err(MtuError {
            message: format!(
                "a {size}-byte cell becomes a {total}-byte datagram, exceeding the \
                 {mtu}-byte unfragmented budget; lower CELL_SIZE or MAX_CELL_SIZE"
            ),
        });
    }
    Ok(())
}

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
    Extended = 7,
    Relay = 8,
    Begin = 9,
    Connected = 10,
    CreateChallenge = 11,
    CreateFragment = 12,
}

impl Command {
    pub const ALL: [Command; 12] = [
        Command::Create,
        Command::Created,
        Command::Extend,
        Command::Data,
        Command::Destroy,
        Command::Ack,
        Command::Extended,
        Command::Relay,
        Command::Begin,
        Command::Connected,
        Command::CreateChallenge,
        Command::CreateFragment,
    ];

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

    /// Return the [`Command`] for `value`.
    pub fn from_int(value: i64) -> Result<Command, InvalidCommandError> {
        for c in Command::ALL {
            if c as i64 == value {
                return Ok(c);
            }
        }
        let known: Vec<String> = Command::ALL.iter().map(|c| format!("{}={}", c.name(), *c as u8)).collect();
        Err(InvalidCommandError::new(format!(
            "unknown command {value:?}; expected one of {{{}}}",
            known.join(", ")
        )))
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
    pub circuit_id: u32,
    pub command: Command,
    pub payload: Vec<u8>,
}

impl Cell {
    /// Build a new cell.
    ///
    /// # Errors
    /// Returns [`CellError`] if `payload` is longer than 1184 bytes or `command`
    /// is not a known command value.
    pub fn new(circuit_id: u32, command: i64, payload: Vec<u8>) -> Result<Cell, CellError> {
        let resolved = Command::from_int(command)?;
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(CellSizeError::new(format!(
                "payload is {} bytes, maximum is {}",
                payload.len(),
                MAX_PAYLOAD_SIZE
            ))
            .into());
        }
        Ok(Cell { circuit_id, command: resolved, payload })
    }

    /// Convenience constructor taking an already-resolved [`Command`].
    pub fn with_command(circuit_id: u32, command: Command, payload: Vec<u8>) -> Result<Cell, CellError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(CellSizeError::new(format!(
                "payload is {} bytes, maximum is {}",
                payload.len(),
                MAX_PAYLOAD_SIZE
            ))
            .into());
        }
        Ok(Cell { circuit_id, command, payload })
    }

    /// Number of meaningful bytes carried inside the 1184-byte payload buffer.
    pub fn length(&self) -> usize {
        self.payload.len()
    }

    /// Serialize this cell into exactly [`CELL_SIZE`] (1192) bytes.
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CELL_SIZE);
        out.extend_from_slice(&self.circuit_id.to_be_bytes());
        out.push(self.command as u8);
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.push(RESERVED_BYTE);
        out.extend_from_slice(&self.payload);
        out.resize(CELL_SIZE, 0);
        out
    }

    /// Alias for [`Cell::pack`], mirroring Python's `to_bytes` naming.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.pack()
    }

    /// Parse exactly 1192 bytes received from the network into a [`Cell`].
    pub fn unpack(data: &[u8], strict: bool) -> Result<Cell, CellError> {
        if data.len() != CELL_SIZE {
            return Err(CellSizeError::new(format!(
                "cell must be exactly {CELL_SIZE} bytes, received {}",
                data.len()
            ))
            .into());
        }
        let circuit_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let raw_command = data[4];
        let declared_length = u16::from_be_bytes([data[5], data[6]]) as usize;
        let reserved = data[7];
        let payload_buffer = &data[8..8 + PAYLOAD_SIZE];

        if declared_length > PAYLOAD_SIZE {
            return Err(CellSizeError::new(format!(
                "declared length {declared_length} exceeds the {PAYLOAD_SIZE}-byte payload buffer"
            ))
            .into());
        }
        if strict && reserved != RESERVED_BYTE {
            return Err(CellSizeError::new(format!(
                "reserved byte must be 0x{RESERVED_BYTE:02x}, got 0x{reserved:02x}"
            ))
            .into());
        }
        let command = Command::from_int(raw_command as i64)?;
        let payload = payload_buffer[..declared_length].to_vec();
        Ok(Cell { circuit_id, command, payload })
    }

    /// Lenient parser for relay hot paths: never fails on a wrong datagram size.
    pub fn from_bytes(data: &[u8], strict: bool) -> Result<Cell, CellError> {
        let fixed: Vec<u8> = if data.len() != CELL_SIZE {
            let mut v = data[..data.len().min(CELL_SIZE)].to_vec();
            v.resize(CELL_SIZE, 0);
            v
        } else {
            data.to_vec()
        };
        Cell::unpack(&fixed, strict)
    }

    /// Return `true` if the payload fills the entire 1184-byte buffer.
    pub fn is_padding_free(&self) -> bool {
        self.length() == PAYLOAD_SIZE
    }

    /// Build a payload-less cell (handy for DESTROY / control traffic).
    pub fn empty(circuit_id: u32, command: Command) -> Cell {
        Cell { circuit_id, command, payload: Vec::new() }
    }

    /// Receive one UDP datagram from `sock` and parse it.
    pub fn read_from_socket(
        sock: &std::net::UdpSocket,
        strict: bool,
    ) -> std::io::Result<(Cell, std::net::SocketAddr)> {
        let mut buf = [0u8; CELL_SIZE];
        let (_n, addr) = sock.recv_from(&mut buf)?;
        let cell = Cell::from_bytes(&buf, strict)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        Ok((cell, addr))
    }

    /// Pack and send this cell to `addr`; returns the bytes sent.
    pub fn send_to(&self, sock: &std::net::UdpSocket, addr: std::net::SocketAddr) -> std::io::Result<usize> {
        sock.send_to(&self.pack(), addr)
    }
}

impl fmt::Display for Cell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let preview_len = self.length().min(16);
        let ellipsis = if self.length() > 16 { "..." } else { "" };
        write!(
            f,
            "Cell(circuit_id={}, command={}, length={}, payload={:?}{})",
            self.circuit_id,
            self.command.name(),
            self.length(),
            &self.payload[..preview_len],
            ellipsis
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- constants -----------------------------------------------------
    #[test]
    fn test_total_size_is_1192() {
        assert_eq!(CELL_SIZE, 1192);
    }

    #[test]
    fn test_payload_buffer_is_1184() {
        assert_eq!(PAYLOAD_SIZE, 1184);
        assert_eq!(MAX_PAYLOAD_SIZE, 1184);
    }

    #[test]
    fn test_header_prefix_is_7_bytes() {
        assert_eq!(HEADER_SIZE, 7);
    }

    // -- mtu budget ------------------------------------------------------
    #[test]
    fn test_cell_fits_the_ipv4_budget() {
        assert!(fits_without_fragmentation(Some(CELL_SIZE as i64), IPV4_SAFE_MTU));
        assert_eq!(datagram_size(Some(CELL_SIZE as i64)), 1220);
    }

    #[test]
    fn test_cell_fits_the_ipv6_budget() {
        assert!(fits_without_fragmentation(Some(CELL_SIZE as i64), IPV6_SAFE_MTU));
        // Verifies the 12-byte margin `PAYLOAD_SIZE`'s own doc comment
        // claims, not just that it fits at all.
        assert_eq!(IPV6_SAFE_MTU - datagram_size(Some(CELL_SIZE as i64)), 12);
    }

    #[test]
    fn test_max_cell_size_is_enforced() {
        assert_eq!(MAX_CELL_SIZE, 1192);
        assert!(CELL_SIZE <= MAX_CELL_SIZE);
    }

    #[test]
    fn test_assert_mtu_safe_passes_for_the_current_size() {
        assert!(assert_mtu_safe(Some(CELL_SIZE as i64), IPV4_SAFE_MTU).is_ok());
        assert!(assert_mtu_safe(Some(CELL_SIZE as i64), IPV6_SAFE_MTU).is_ok());
    }

    #[test]
    fn test_assert_mtu_safe_rejects_an_oversized_cell() {
        assert!(assert_mtu_safe(Some(2048), IPV4_SAFE_MTU).is_err());
    }

    #[test]
    fn test_assert_mtu_safe_rejects_a_1472_byte_datagram() {
        assert!(fits_without_fragmentation(Some(1472 - 28), IPV4_SAFE_MTU));
        assert!(!fits_without_fragmentation(Some(1472 - 27), IPV4_SAFE_MTU));
    }

    #[test]
    fn test_packed_datagram_is_within_budget() {
        let raw = Cell::with_command(1, Command::Data, vec![b'x'; 100]).unwrap().pack();
        assert!(datagram_size(Some(raw.len() as i64)) <= IPV4_SAFE_MTU);
        assert!(datagram_size(Some(raw.len() as i64)) <= IPV6_SAFE_MTU);
    }

    // -- Command -----------------------------------------------------
    #[test]
    fn test_command_values() {
        assert_eq!(Command::Create as u8, 1);
        assert_eq!(Command::Created as u8, 2);
        assert_eq!(Command::Extend as u8, 3);
        assert_eq!(Command::Data as u8, 4);
        assert_eq!(Command::Destroy as u8, 5);
        assert_eq!(Command::Ack as u8, 6);
        assert_eq!(Command::Extended as u8, 7);
    }

    #[test]
    fn test_from_int_roundtrip() {
        for c in Command::ALL {
            assert_eq!(Command::from_int(c as i64).unwrap(), c);
        }
    }

    #[test]
    fn test_from_int_rejects_unknown() {
        for bad in [0, 13, 255, -1] {
            assert!(Command::from_int(bad).is_err());
        }
    }

    // -- pack -----------------------------------------------------
    #[test]
    fn test_pack_returns_exactly_1192_bytes() {
        assert_eq!(Cell::with_command(1, Command::Create, vec![]).unwrap().pack().len(), CELL_SIZE);
    }

    #[test]
    fn test_pack_is_big_endian() {
        let raw = Cell::with_command(0x01020304, Command::Data, b"AB".to_vec()).unwrap().pack();
        assert_eq!(&raw[..4], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(raw[4], Command::Data as u8);
        assert_eq!(&raw[5..7], &[0x00, 0x02]);
        assert_eq!(raw[7], 0);
        assert_eq!(&raw[8..10], b"AB");
        // "AB" is 2 bytes, so the rest of the payload buffer (PAYLOAD_SIZE - 2)
        // is zero padding.
        assert_eq!(&raw[10..], vec![0u8; PAYLOAD_SIZE - 2].as_slice());
    }

    #[test]
    fn test_pack_zero_pads_short_payload() {
        let raw = Cell::with_command(7, Command::Data, b"x".to_vec()).unwrap().pack();
        // "x" is 1 byte, so everything from the byte after it to the end of
        // the cell (PAYLOAD_SIZE - 1 bytes) is zero padding.
        assert_eq!(&raw[raw.len() - (PAYLOAD_SIZE - 1)..], vec![0u8; PAYLOAD_SIZE - 1].as_slice());
    }

    #[test]
    fn test_pack_full_payload_has_no_padding() {
        // At least PAYLOAD_SIZE bytes of non-repeating-in-a-way-that-hides-a-
        // bug content, built by cycling 0..=255 (never all one value, which
        // wouldn't catch an offset error), then cut to exactly PAYLOAD_SIZE.
        let mut payload: Vec<u8> = Vec::new();
        while payload.len() < PAYLOAD_SIZE {
            payload.extend((0..=255u8).take(PAYLOAD_SIZE - payload.len()));
        }
        payload.truncate(PAYLOAD_SIZE);
        let cell = Cell::with_command(7, Command::Data, payload.clone()).unwrap();
        assert!(cell.is_padding_free());
        assert_eq!(Cell::unpack(&cell.pack(), true).unwrap().payload, payload);
    }

    #[test]
    fn test_to_bytes_alias() {
        let cell = Cell::with_command(9, Command::Extend, b"hello".to_vec()).unwrap();
        assert_eq!(cell.pack(), cell.to_bytes());
    }

    #[test]
    fn test_pack_max_circuit_id() {
        let raw = Cell::with_command(0xFFFFFFFF, Command::Destroy, vec![]).unwrap().pack();
        assert_eq!(&raw[..4], &[0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn test_empty_helper() {
        let cell = Cell::empty(42, Command::Destroy);
        assert_eq!(cell.circuit_id, 42);
        assert_eq!(cell.command, Command::Destroy);
        assert_eq!(cell.length(), 0);
    }

    // -- unpack -----------------------------------------------------
    #[test]
    fn test_roundtrip() {
        let original =
            Cell::with_command(0xDEADBEEF, Command::Extend, b"layer-3-onion-ciphertext".to_vec()).unwrap();
        let restored = Cell::unpack(&original.pack(), true).unwrap();
        assert_eq!(restored, original);
        assert_eq!(restored.circuit_id, 0xDEADBEEF);
        assert_eq!(restored.command, Command::Extend);
        assert_eq!(restored.payload, b"layer-3-onion-ciphertext");
    }

    #[test]
    fn test_roundtrip_all_commands() {
        for cmd in Command::ALL {
            let cell = Cell::with_command(123, cmd, b"payload-data".to_vec()).unwrap();
            assert_eq!(Cell::unpack(&cell.pack(), true).unwrap(), cell);
        }
    }

    #[test]
    fn test_roundtrip_empty_payload() {
        let cell = Cell::with_command(5, Command::Create, vec![]).unwrap();
        assert_eq!(Cell::unpack(&cell.pack(), true).unwrap().length(), 0);
    }

    #[test]
    fn test_trailing_bytes_are_not_returned_as_payload() {
        let mut raw = Cell::with_command(1, Command::Data, b"abc".to_vec()).unwrap().pack();
        for b in raw[11..].iter_mut() {
            *b = b'Z';
        }
        raw[5..7].copy_from_slice(&3u16.to_be_bytes());
        assert_eq!(Cell::unpack(&raw, true).unwrap().payload, b"abc");
    }

    #[test]
    fn test_declared_length_zero_hides_a_full_buffer() {
        let mut raw = Cell::with_command(1, Command::Data, vec![b'a'; PAYLOAD_SIZE]).unwrap().pack();
        raw[5..7].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(Cell::unpack(&raw, true).unwrap().payload, Vec::<u8>::new());
    }

    #[test]
    fn test_from_bytes_pads_short_datagrams() {
        let cell = Cell::from_bytes(&[0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00], false).unwrap();
        assert_eq!(cell.circuit_id, 1);
        assert_eq!(cell.command, Command::Create);
    }

    #[test]
    fn test_from_bytes_truncates_long_datagrams() {
        let mut raw = Cell::with_command(3, Command::Data, b"ok".to_vec()).unwrap().pack();
        raw.extend(b"junk".repeat(100));
        assert_eq!(Cell::from_bytes(&raw, false).unwrap().payload, b"ok");
    }

    // -- validation -----------------------------------------------------
    #[test]
    fn test_unpack_rejects_short_datagram() {
        let raw = Cell::with_command(1, Command::Data, b"abc".to_vec()).unwrap().pack();
        for size in [0usize, 1, HEADER_SIZE, CELL_SIZE - 1] {
            let err = Cell::unpack(&raw[..size], true).unwrap_err();
            assert!(err.to_string().contains(&CELL_SIZE.to_string()));
        }
    }

    #[test]
    fn test_unpack_rejects_long_datagram() {
        let mut raw = Cell::with_command(1, Command::Data, b"abc".to_vec()).unwrap().pack();
        raw.push(0);
        assert_eq!(raw.len(), CELL_SIZE + 1);
        assert!(Cell::unpack(&raw, true).is_err());
    }

    #[test]
    fn test_unpack_rejects_unknown_command() {
        let raw = Cell::with_command(1, Command::Data, vec![]).unwrap().pack();
        for bad in [0u8, 13, 99, 255] {
            let mut r = raw.clone();
            r[4] = bad;
            assert!(Cell::unpack(&r, true).is_err());
        }
    }

    #[test]
    fn test_unpack_rejects_length_beyond_buffer() {
        let mut raw = Cell::with_command(1, Command::Data, b"abc".to_vec()).unwrap().pack();
        let over = (PAYLOAD_SIZE + 1) as u16;
        raw[5..7].copy_from_slice(&over.to_be_bytes());
        let err = Cell::unpack(&raw, true).unwrap_err();
        assert!(err.to_string().contains(&over.to_string()));
    }

    #[test]
    fn test_unpack_accepts_max_length_field() {
        let mut raw = Cell::with_command(1, Command::Data, vec![]).unwrap().pack();
        raw[5..7].copy_from_slice(&(PAYLOAD_SIZE as u16).to_be_bytes());
        for b in raw[8..].iter_mut() {
            *b = b'D';
        }
        assert_eq!(Cell::unpack(&raw, true).unwrap().payload, vec![b'D'; PAYLOAD_SIZE]);
    }

    #[test]
    fn test_unpack_rejects_dirty_reserved_byte_in_strict_mode() {
        let mut raw = Cell::with_command(1, Command::Data, b"abc".to_vec()).unwrap().pack();
        raw[7] = 0x01;
        assert!(Cell::unpack(&raw, true).is_err());
        assert_eq!(Cell::unpack(&raw, false).unwrap().payload, b"abc");
    }

    #[test]
    fn test_payload_too_long_is_rejected() {
        assert!(Cell::with_command(1, Command::Data, vec![0u8; PAYLOAD_SIZE + 1]).is_err());
    }

    #[test]
    fn test_constructor_rejects_bad_command() {
        assert!(Cell::new(1, 300, vec![]).is_err());
    }

    // -- misc -----------------------------------------------------
    #[test]
    fn test_repr_and_len() {
        let cell = Cell::with_command(7, Command::Extend, b"0123456789abcdefghij".to_vec()).unwrap();
        assert_eq!(cell.length(), 20);
        let s = format!("{cell}");
        assert!(s.contains("EXTEND"));
        assert!(s.contains("..."));
    }

    #[test]
    fn test_equality_and_hash() {
        let a = Cell::with_command(1, Command::Data, b"x".to_vec()).unwrap();
        let b = Cell::with_command(1, Command::Data, b"x".to_vec()).unwrap();
        let c = Cell::with_command(2, Command::Data, b"x".to_vec()).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
