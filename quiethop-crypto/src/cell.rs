//! Fixed-length wire cells (SECURITY_MODEL §5.10).
//!
//! Every cell is exactly [`CELL_PLAINTEXT_LEN`] bytes before encryption:
//! `type(1) || flags(1) || data_len(2 BE) || payload(509)`. The first
//! `data_len` payload bytes are data and the rest are zero padding. Only
//! `data_len` distinguishes the two, and padding is zero so it carries nothing.
//!
//! Each layer's plaintext is preceded on the wire by a one-byte disposition
//! field ([`crate::wire::DISPOSITION_TO_ME`] or
//! [`crate::wire::DISPOSITION_FORWARD`]). A relay peels its layer and reads
//! that byte to learn whether the remainder is a cell for it or an opaque blob
//! to forward verbatim. A forwarded blob is always exactly the next link's cell
//! size, so it needs no length of its own and none appears on the wire.
//!
//! Link sizes come from [`link_cell_len`] and are never written as literals.

use crate::layers::Layers;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use thiserror::Error;

use crate::noise::{NOISE_MSG_LEN, NOISE_TAG_LEN};
use crate::wire::DISPOSITION_LEN;

/// Innermost cell payload. The one tunable, closed at 509 in
/// docs/DECISIONS.md entry 14 and revisited after the step 5 throughput
/// measurement. Changing it here changes every link size.
pub const CELL_PAYLOAD_LEN: usize = 509;

/// `type(1) || flags(1) || data_len(2 BE)`.
pub const CELL_HEADER_LEN: usize = 4;

/// One cell before encryption.
pub const CELL_PLAINTEXT_LEN: usize = CELL_HEADER_LEN + CELL_PAYLOAD_LEN;

/// Size on a link `layers` hops from the innermost cell.
///
/// Each hop adds one disposition byte and one AEAD tag, so the client-guard
/// link (3 layers) is the widest and the middle-exit link (1 layer) the
/// narrowest. Each link carries this constant in both directions.
pub const fn link_cell_len(layers: Layers) -> usize {
    CELL_PLAINTEXT_LEN + layers.get() * (DISPOSITION_LEN + NOISE_TAG_LEN)
}

/// Bytes a relay peels to, one layer in: disposition plus the inner body.
pub const fn peeled_len(layers: Layers) -> usize {
    link_cell_len(layers) - NOISE_TAG_LEN
}

/// The body carried inside one layer at this depth. For the innermost layer
/// this is exactly one cell; further out it is the adjacent link's cell size.
pub const fn body_len(layers: Layers) -> usize {
    peeled_len(layers) - DISPOSITION_LEN
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellType {
    Extend = 0x01,
    // 0x02 was RELAY. Fixed-size links carry forwarded blobs behind the
    // disposition byte instead, so the type is retired rather than reused.
    Connect = 0x03,
    Data = 0x04,
    CloseRequest = 0x05,
    CloseAck = 0x06,
    /// Circuit-level flow control acknowledgement. A cell type rather than a
    /// link command, so it travels inside the innermost layer between the
    /// client and the exit and a relay that forwards it learns nothing about
    /// the circuit's flow-control cadence (SECURITY_MODEL 6.4).
    Sendme = 0x07,
}

impl TryFrom<u8> for CellType {
    type Error = CellError;
    fn try_from(b: u8) -> Result<Self, Self::Error> {
        match b {
            0x01 => Ok(CellType::Extend),
            0x03 => Ok(CellType::Connect),
            0x04 => Ok(CellType::Data),
            0x05 => Ok(CellType::CloseRequest),
            0x06 => Ok(CellType::CloseAck),
            0x07 => Ok(CellType::Sendme),
            other => Err(CellError::UnknownType(other)),
        }
    }
}

#[derive(Debug, Error)]
pub enum CellError {
    #[error("cell plaintext is {0} bytes, expected {CELL_PLAINTEXT_LEN}")]
    WrongSize(usize),
    #[error("cell payload length {0} exceeds {CELL_PAYLOAD_LEN}")]
    TooLarge(usize),
    #[error("unknown cell type byte 0x{0:02x}")]
    UnknownType(u8),
    #[error("flags byte is reserved and must be zero")]
    ReservedFlags,
    #[error("EXTEND payload malformed: {0}")]
    BadExtend(&'static str),
    #[error("CONNECT payload malformed: {0}")]
    BadConnect(&'static str),
    #[error("address is not valid UTF-8")]
    BadAddress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    pub cell_type: CellType,
    pub payload: Vec<u8>,
}

impl Cell {
    pub fn new(cell_type: CellType, payload: Vec<u8>) -> Result<Self, CellError> {
        if payload.len() > CELL_PAYLOAD_LEN {
            return Err(CellError::TooLarge(payload.len()));
        }
        Ok(Self { cell_type, payload })
    }

    /// Write the cell into a full-size buffer, zeroing the padding.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<(), CellError> {
        if out.len() != CELL_PLAINTEXT_LEN {
            return Err(CellError::WrongSize(out.len()));
        }
        let n = self.payload.len();
        if n > CELL_PAYLOAD_LEN {
            return Err(CellError::TooLarge(n));
        }
        out[0] = self.cell_type as u8;
        out[1] = 0;
        // n <= CELL_PAYLOAD_LEN = 509, so the cast cannot truncate.
        out[2..4].copy_from_slice(&(n as u16).to_be_bytes());
        out[CELL_HEADER_LEN..CELL_HEADER_LEN + n].copy_from_slice(&self.payload);
        for b in out[CELL_HEADER_LEN + n..].iter_mut() {
            *b = 0;
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, CellError> {
        let mut out = vec![0u8; CELL_PLAINTEXT_LEN];
        self.encode_into(&mut out)?;
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CellError> {
        if bytes.len() != CELL_PLAINTEXT_LEN {
            return Err(CellError::WrongSize(bytes.len()));
        }
        let cell_type = CellType::try_from(bytes[0])?;
        if bytes[1] != 0 {
            return Err(CellError::ReservedFlags);
        }
        let n = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if n > CELL_PAYLOAD_LEN {
            return Err(CellError::TooLarge(n));
        }
        Ok(Self {
            cell_type,
            payload: bytes[CELL_HEADER_LEN..CELL_HEADER_LEN + n].to_vec(),
        })
    }
}

/// EXTEND forward payload: `address(16) || port(2 BE) || noise_message_1(48)`.
///
/// The address is a binary literal in a 16-byte slot, IPv4 carried as
/// IPv4-mapped IPv6. No hostname and no length prefix, so nothing here can be
/// resolved and the payload is fixed length.
pub const EXTEND_ADDR_LEN: usize = 16;
pub const EXTEND_FORWARD_LEN: usize = EXTEND_ADDR_LEN + 2 + NOISE_MSG_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendForward {
    pub next_hop: SocketAddr,
    pub noise_msg1: [u8; NOISE_MSG_LEN],
}

impl ExtendForward {
    pub fn encode(&self) -> Vec<u8> {
        let v6 = match self.next_hop.ip() {
            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            IpAddr::V6(v6) => v6,
        };
        let mut out = Vec::with_capacity(EXTEND_FORWARD_LEN);
        out.extend_from_slice(&v6.octets());
        out.extend_from_slice(&self.next_hop.port().to_be_bytes());
        out.extend_from_slice(&self.noise_msg1);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CellError> {
        if bytes.len() != EXTEND_FORWARD_LEN {
            return Err(CellError::BadExtend(
                "payload is not the fixed EXTEND length",
            ));
        }
        let mut octets = [0u8; EXTEND_ADDR_LEN];
        octets.copy_from_slice(&bytes[..EXTEND_ADDR_LEN]);
        let v6 = Ipv6Addr::from(octets);
        let ip = match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        };
        let port = u16::from_be_bytes([bytes[EXTEND_ADDR_LEN], bytes[EXTEND_ADDR_LEN + 1]]);
        let mut noise_msg1 = [0u8; NOISE_MSG_LEN];
        noise_msg1.copy_from_slice(&bytes[EXTEND_ADDR_LEN + 2..]);
        Ok(Self {
            next_hop: SocketAddr::new(ip, port),
            noise_msg1,
        })
    }
}

/// EXTEND backward payload: `noise_message_2(48)`.
pub fn extend_backward_payload(msg2: &[u8; NOISE_MSG_LEN]) -> Vec<u8> {
    msg2.to_vec()
}

pub fn parse_extend_backward(bytes: &[u8]) -> Result<[u8; NOISE_MSG_LEN], CellError> {
    if bytes.len() != NOISE_MSG_LEN {
        return Err(CellError::BadExtend(
            "backward payload is not one Noise message",
        ));
    }
    let mut out = [0u8; NOISE_MSG_LEN];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// CONNECT payload: `host_len(2 BE) || host || port(2 BE)`.
///
/// The host is a destination name resolved by the SOCKS5 proxy at the exit, not
/// by this process. That is destination resolution, not path construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectPayload {
    pub host: String,
    pub port: u16,
}

/// Longest destination host that still fits one cell.
pub const MAX_CONNECT_HOST_LEN: usize = CELL_PAYLOAD_LEN - 4;

impl ConnectPayload {
    pub fn encode(&self) -> Result<Vec<u8>, CellError> {
        let host_bytes = self.host.as_bytes();
        if host_bytes.len() > MAX_CONNECT_HOST_LEN {
            return Err(CellError::BadConnect("host does not fit one cell"));
        }
        let mut out = Vec::with_capacity(2 + host_bytes.len() + 2);
        out.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(host_bytes);
        out.extend_from_slice(&self.port.to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CellError> {
        if bytes.len() < 4 {
            return Err(CellError::BadConnect(
                "payload shorter than length prefix and port",
            ));
        }
        let host_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        if bytes.len() != 2 + host_len + 2 {
            return Err(CellError::BadConnect(
                "payload length does not match host_len and port",
            ));
        }
        let host = std::str::from_utf8(&bytes[2..2 + host_len])
            .map_err(|_| CellError::BadAddress)?
            .to_string();
        let port = u16::from_be_bytes([bytes[2 + host_len], bytes[2 + host_len + 1]]);
        Ok(Self { host, port })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_sizes_match_the_specification() {
        // SECURITY_MODEL §5.10. These are the only places the numbers appear.
        assert_eq!(CELL_PLAINTEXT_LEN, 513);
        assert_eq!(link_cell_len(Layers::new(1)), 530, "middle to exit");
        assert_eq!(link_cell_len(Layers::new(2)), 547, "guard to middle");
        assert_eq!(link_cell_len(Layers::new(3)), 564, "client to guard");
    }

    #[test]
    fn each_hop_costs_a_disposition_byte_and_a_tag() {
        for n in 1..4 {
            assert_eq!(
                link_cell_len(Layers::new(n + 1)) - link_cell_len(Layers::new(n)),
                DISPOSITION_LEN + NOISE_TAG_LEN
            );
        }
    }

    #[test]
    fn body_len_is_the_adjacent_link_size() {
        assert_eq!(
            body_len(Layers::new(1)),
            CELL_PLAINTEXT_LEN,
            "innermost body is one cell"
        );
        assert_eq!(
            body_len(Layers::new(2)),
            link_cell_len(Layers::new(1)),
            "middle body is the exit link cell"
        );
        assert_eq!(
            body_len(Layers::new(3)),
            link_cell_len(Layers::new(2)),
            "guard body is the middle link cell"
        );
    }

    #[test]
    fn peeled_len_is_one_tag_less_than_the_link() {
        assert_eq!(
            peeled_len(Layers::new(3)),
            link_cell_len(Layers::new(3)) - NOISE_TAG_LEN
        );
        assert_eq!(
            peeled_len(Layers::new(1)),
            DISPOSITION_LEN + CELL_PLAINTEXT_LEN
        );
    }

    #[test]
    fn cell_round_trip_is_always_full_size() {
        for n in [0usize, 1, 64, CELL_PAYLOAD_LEN] {
            let c = Cell::new(CellType::Data, vec![0xA5; n]).unwrap();
            let bytes = c.encode().unwrap();
            assert_eq!(
                bytes.len(),
                CELL_PLAINTEXT_LEN,
                "payload {n} did not pad to full size"
            );
            assert_eq!(Cell::decode(&bytes).unwrap(), c);
        }
    }

    #[test]
    fn padding_is_zero() {
        // encode_into must zero the padding itself. Testing through encode()
        // would prove nothing, because encode() starts from a zeroed vec, so a
        // missing zero-fill would still look clean. The relay and the client
        // both call encode_into on a buffer they already own, so a dirty buffer
        // is the case that matters.
        let mut buf = vec![0xFFu8; CELL_PLAINTEXT_LEN];
        let c = Cell::new(CellType::Data, vec![0xA1; 3]).unwrap();
        c.encode_into(&mut buf).unwrap();
        assert_eq!(
            &buf[CELL_HEADER_LEN..CELL_HEADER_LEN + 3],
            &[0xA1, 0xA1, 0xA1]
        );
        assert!(
            buf[CELL_HEADER_LEN + 3..].iter().all(|b| *b == 0),
            "encode_into left {} nonzero padding bytes",
            buf[CELL_HEADER_LEN + 3..]
                .iter()
                .filter(|b| **b != 0)
                .count()
        );
    }

    #[test]
    fn zero_length_data_cell_is_legal() {
        let c = Cell::new(CellType::Data, Vec::new()).unwrap();
        let bytes = c.encode().unwrap();
        assert_eq!(Cell::decode(&bytes).unwrap().payload.len(), 0);
    }

    #[test]
    fn new_rejects_an_oversize_payload() {
        let err = Cell::new(CellType::Data, vec![0u8; CELL_PAYLOAD_LEN + 1]).unwrap_err();
        assert!(matches!(err, CellError::TooLarge(_)));
    }

    #[test]
    fn decode_rejects_a_wrong_size_buffer() {
        for len in [0usize, CELL_PLAINTEXT_LEN - 1, CELL_PLAINTEXT_LEN + 1] {
            let err = Cell::decode(&vec![0u8; len]).unwrap_err();
            assert!(
                matches!(err, CellError::WrongSize(_)),
                "len {len} was accepted"
            );
        }
    }

    #[test]
    fn decode_rejects_nonzero_flags() {
        let mut bytes = Cell::new(CellType::Data, vec![1, 2, 3])
            .unwrap()
            .encode()
            .unwrap();
        bytes[1] = 0x01;
        assert!(matches!(
            Cell::decode(&bytes).unwrap_err(),
            CellError::ReservedFlags
        ));
    }

    #[test]
    fn decode_rejects_a_declared_length_past_the_payload() {
        let mut bytes = Cell::new(CellType::Data, vec![1, 2, 3])
            .unwrap()
            .encode()
            .unwrap();
        bytes[2..4].copy_from_slice(&((CELL_PAYLOAD_LEN + 1) as u16).to_be_bytes());
        assert!(matches!(
            Cell::decode(&bytes).unwrap_err(),
            CellError::TooLarge(_)
        ));
    }

    #[test]
    fn decode_rejects_the_retired_relay_type() {
        let mut bytes = Cell::new(CellType::Data, Vec::new())
            .unwrap()
            .encode()
            .unwrap();
        bytes[0] = 0x02;
        assert!(matches!(
            Cell::decode(&bytes).unwrap_err(),
            CellError::UnknownType(0x02)
        ));
    }

    #[test]
    fn extend_forward_round_trips_v4_and_v6() {
        for addr in ["127.0.0.1:9001", "[2001:db8::1]:443"] {
            let f = ExtendForward {
                next_hop: addr.parse().unwrap(),
                noise_msg1: [7u8; NOISE_MSG_LEN],
            };
            let bytes = f.encode();
            assert_eq!(bytes.len(), EXTEND_FORWARD_LEN);
            assert_eq!(ExtendForward::decode(&bytes).unwrap(), f);
        }
    }

    #[test]
    fn extend_forward_is_66_bytes() {
        assert_eq!(EXTEND_FORWARD_LEN, 66);
        const { assert!(EXTEND_FORWARD_LEN <= CELL_PAYLOAD_LEN) };
    }

    #[test]
    fn extend_forward_rejects_a_wrong_length() {
        for len in [0usize, EXTEND_FORWARD_LEN - 1, EXTEND_FORWARD_LEN + 1] {
            let err = ExtendForward::decode(&vec![0u8; len]).unwrap_err();
            assert!(
                matches!(err, CellError::BadExtend(_)),
                "len {len} was accepted"
            );
        }
    }

    #[test]
    fn extend_backward_round_trips() {
        let msg = [9u8; NOISE_MSG_LEN];
        assert_eq!(
            parse_extend_backward(&extend_backward_payload(&msg)).unwrap(),
            msg
        );
    }

    #[test]
    fn extend_backward_rejects_a_wrong_length() {
        let err = parse_extend_backward(&[0u8; NOISE_MSG_LEN - 1]).unwrap_err();
        assert!(matches!(err, CellError::BadExtend(_)));
    }

    #[test]
    fn connect_round_trips_and_fits_a_cell() {
        let c = ConnectPayload {
            host: "example.com".to_string(),
            port: 443,
        };
        let bytes = c.encode().unwrap();
        assert!(bytes.len() <= CELL_PAYLOAD_LEN);
        assert_eq!(ConnectPayload::decode(&bytes).unwrap(), c);
    }

    #[test]
    fn connect_rejects_a_host_that_does_not_fit() {
        let c = ConnectPayload {
            host: "a".repeat(MAX_CONNECT_HOST_LEN + 1),
            port: 80,
        };
        assert!(matches!(c.encode().unwrap_err(), CellError::BadConnect(_)));
    }

    #[test]
    fn connect_rejects_a_length_mismatch() {
        let mut bytes = vec![];
        bytes.extend_from_slice(&5u16.to_be_bytes());
        bytes.extend_from_slice(b"abc");
        bytes.extend_from_slice(&80u16.to_be_bytes());
        assert!(matches!(
            ConnectPayload::decode(&bytes).unwrap_err(),
            CellError::BadConnect(_)
        ));
    }
}
