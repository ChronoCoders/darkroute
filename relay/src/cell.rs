//! Wire-protocol cells for circuit control and forwarding.
//!
//! Every AES-GCM frame on a client-relay link carries exactly one cell
//! in its decrypted plaintext. The cell has a fixed 9-byte header:
//!
//!     [type: 1][circuit_id: 4 BE][payload_length: 4 BE]
//!
//! followed by `payload_length` payload bytes. No partial reads — the
//! caller decrypts the full frame plaintext first and only then parses
//! it as a cell, so an attacker cannot cause work by sending half a
//! header.
//!
//! Cell types (Phase 4b):
//!
//!   * EXTEND — bidirectional. Forward payload:
//!     `addr_len(2 BE) || addr || client_pk(32)`. Backward payload:
//!     `relay_pk(32)`.
//!   * RELAY — bidirectional. Payload is bytes the receiver must
//!     forward verbatim to its OTHER link (next hop on the forward
//!     path, previous hop on the backward path).
//!   * CONNECT — forward, exit-only. Payload:
//!     `addr_len(2 BE) || addr || port(2 BE)`. Exit decodes and (in
//!     Phase 4c) dials the destination via the Decodo SOCKS5 proxy.
//!   * DATA — bidirectional, exit-only. Payload: opaque bytes to and
//!     from the destination.
//!   * CLOSE_REQUEST — forward, requests circuit teardown.
//!   * CLOSE_ACK — backward, confirms teardown.
//!
//! Cells whose payload exceeds `MAX_CELL_PAYLOAD` are rejected at decode
//! time; the per-frame cap from `crypto.rs` also applies.

use std::convert::TryFrom;
use std::net::SocketAddr;

use thiserror::Error;

pub const CELL_HEADER_LEN: usize = 9;

/// Upper bound on a cell payload, in bytes. The crypto-frame cap is
/// `MAX_FRAME_PLAINTEXT = 64 KiB`; subtract the 9-byte header to leave
/// room for the cell envelope.
pub const MAX_CELL_PAYLOAD: usize = 64 * 1024 - CELL_HEADER_LEN;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellType {
    Extend = 0x01,
    Relay = 0x02,
    Connect = 0x03,
    Data = 0x04,
    CloseRequest = 0x05,
    CloseAck = 0x06,
}

impl TryFrom<u8> for CellType {
    type Error = CellError;
    fn try_from(b: u8) -> Result<Self, Self::Error> {
        match b {
            0x01 => Ok(CellType::Extend),
            0x02 => Ok(CellType::Relay),
            0x03 => Ok(CellType::Connect),
            0x04 => Ok(CellType::Data),
            0x05 => Ok(CellType::CloseRequest),
            0x06 => Ok(CellType::CloseAck),
            other => Err(CellError::UnknownType(other)),
        }
    }
}

#[derive(Debug, Error)]
pub enum CellError {
    #[error("plaintext too short for cell header")]
    TooShort,
    #[error("cell payload length {0} exceeds the per-cell cap")]
    TooLarge(usize),
    #[error("declared payload length {declared} does not match buffer remainder {actual}")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("unknown cell type byte 0x{0:02x}")]
    UnknownType(u8),
    #[error("EXTEND payload malformed: {0}")]
    BadExtend(&'static str),
    #[error("CONNECT payload malformed: {0}")]
    BadConnect(&'static str),
    #[error("address is not valid UTF-8")]
    BadAddress,
    #[error("address does not parse as host:port")]
    UnparseableAddress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    pub cell_type: CellType,
    pub circuit_id: u32,
    pub payload: Vec<u8>,
}

impl Cell {
    pub fn new(cell_type: CellType, circuit_id: u32, payload: Vec<u8>) -> Result<Self, CellError> {
        if payload.len() > MAX_CELL_PAYLOAD {
            return Err(CellError::TooLarge(payload.len()));
        }
        Ok(Self {
            cell_type,
            circuit_id,
            payload,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CELL_HEADER_LEN + self.payload.len());
        out.push(self.cell_type as u8);
        out.extend_from_slice(&self.circuit_id.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CellError> {
        if bytes.len() < CELL_HEADER_LEN {
            return Err(CellError::TooShort);
        }
        let cell_type = CellType::try_from(bytes[0])?;
        let circuit_id = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let payload_len =
            u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;
        if payload_len > MAX_CELL_PAYLOAD {
            return Err(CellError::TooLarge(payload_len));
        }
        let body_remainder = bytes.len() - CELL_HEADER_LEN;
        if body_remainder != payload_len {
            return Err(CellError::LengthMismatch {
                declared: payload_len,
                actual: body_remainder,
            });
        }
        Ok(Self {
            cell_type,
            circuit_id,
            payload: bytes[CELL_HEADER_LEN..].to_vec(),
        })
    }
}

/// EXTEND-forward payload as sent by the client: target relay address +
/// client's ephemeral X25519 public key for the new hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendForward {
    pub next_hop: SocketAddr,
    pub client_pk: [u8; 32],
}

impl ExtendForward {
    /// Client-side mirror of `decode`. Production relays only decode
    /// EXTEND-forward payloads (they receive them from clients); the
    /// encode path lives behind `#[cfg(test)]` because the binary itself
    /// is never a client. A future client library will expose this as
    /// part of its public surface.
    #[cfg(test)]
    pub fn encode(&self) -> Vec<u8> {
        let addr = self.next_hop.to_string();
        let addr_bytes = addr.as_bytes();
        let mut out = Vec::with_capacity(2 + addr_bytes.len() + 32);
        out.extend_from_slice(&(addr_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(addr_bytes);
        out.extend_from_slice(&self.client_pk);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CellError> {
        if bytes.len() < 2 {
            return Err(CellError::BadExtend("payload shorter than address length prefix"));
        }
        let addr_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        if bytes.len() < 2 + addr_len + 32 {
            return Err(CellError::BadExtend("payload shorter than addr+pubkey"));
        }
        let addr_str = std::str::from_utf8(&bytes[2..2 + addr_len])
            .map_err(|_| CellError::BadAddress)?;
        let next_hop: SocketAddr = addr_str
            .parse()
            .map_err(|_| CellError::UnparseableAddress)?;
        let mut client_pk = [0u8; 32];
        client_pk.copy_from_slice(&bytes[2 + addr_len..2 + addr_len + 32]);
        Ok(Self { next_hop, client_pk })
    }
}

/// EXTEND-backward payload: just the next-hop relay's ephemeral pubkey.
pub fn extend_backward_payload(relay_pk: &[u8; 32]) -> Vec<u8> {
    relay_pk.to_vec()
}

/// Client-side mirror of `extend_backward_payload`. Gated to test builds
/// for the same reason as `ExtendForward::encode`.
#[cfg(test)]
pub fn parse_extend_backward(bytes: &[u8]) -> Result<[u8; 32], CellError> {
    if bytes.len() != 32 {
        return Err(CellError::BadExtend("backward payload must be exactly 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// CONNECT payload: target host:port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectPayload {
    pub host: String,
    pub port: u16,
}

impl ConnectPayload {
    /// Client-side mirror of `decode`. Gated to test builds for the same
    /// reason as `ExtendForward::encode`.
    #[cfg(test)]
    pub fn encode(&self) -> Vec<u8> {
        let host_bytes = self.host.as_bytes();
        let mut out = Vec::with_capacity(2 + host_bytes.len() + 2);
        out.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(host_bytes);
        out.extend_from_slice(&self.port.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CellError> {
        if bytes.len() < 4 {
            return Err(CellError::BadConnect("payload shorter than length prefix + port"));
        }
        let host_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        if bytes.len() != 2 + host_len + 2 {
            return Err(CellError::BadConnect("payload length does not match host_len + port"));
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
    fn cell_encode_decode_round_trip() {
        let c = Cell::new(CellType::Relay, 42, vec![1, 2, 3, 4]).unwrap();
        let bytes = c.encode();
        assert_eq!(bytes.len(), CELL_HEADER_LEN + 4);
        let back = Cell::decode(&bytes).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn cell_decode_rejects_short_header() {
        let err = Cell::decode(&[0x01, 0x00, 0x00]).unwrap_err();
        assert!(matches!(err, CellError::TooShort));
    }

    #[test]
    fn cell_decode_rejects_unknown_type() {
        let mut bytes = vec![0xFF];
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        let err = Cell::decode(&bytes).unwrap_err();
        assert!(matches!(err, CellError::UnknownType(0xFF)));
    }

    #[test]
    fn cell_decode_rejects_length_mismatch() {
        let mut bytes = vec![CellType::Data as u8];
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&(8u32).to_be_bytes()); // claims 8 payload bytes
        bytes.extend_from_slice(&[1, 2, 3]); // only 3 supplied
        let err = Cell::decode(&bytes).unwrap_err();
        assert!(matches!(err, CellError::LengthMismatch { declared: 8, actual: 3 }));
    }

    #[test]
    fn cell_new_rejects_oversize_payload() {
        let big = vec![0u8; MAX_CELL_PAYLOAD + 1];
        let err = Cell::new(CellType::Data, 0, big).unwrap_err();
        assert!(matches!(err, CellError::TooLarge(_)));
    }

    #[test]
    fn extend_forward_round_trip() {
        let pk = [7u8; 32];
        let f = ExtendForward {
            next_hop: "127.0.0.1:9001".parse().unwrap(),
            client_pk: pk,
        };
        let bytes = f.encode();
        let back = ExtendForward::decode(&bytes).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn extend_forward_decode_rejects_truncated() {
        let err = ExtendForward::decode(&[0x00]).unwrap_err();
        assert!(matches!(err, CellError::BadExtend(_)));
    }

    #[test]
    fn extend_forward_decode_rejects_garbage_address() {
        let mut bytes = vec![];
        let addr = b"not-an-addr";
        bytes.extend_from_slice(&(addr.len() as u16).to_be_bytes());
        bytes.extend_from_slice(addr);
        bytes.extend_from_slice(&[0u8; 32]);
        let err = ExtendForward::decode(&bytes).unwrap_err();
        assert!(matches!(err, CellError::UnparseableAddress));
    }

    #[test]
    fn extend_backward_round_trip() {
        let pk = [9u8; 32];
        let payload = extend_backward_payload(&pk);
        assert_eq!(parse_extend_backward(&payload).unwrap(), pk);
    }

    #[test]
    fn extend_backward_rejects_wrong_length() {
        let err = parse_extend_backward(&[0u8; 31]).unwrap_err();
        assert!(matches!(err, CellError::BadExtend(_)));
    }

    #[test]
    fn connect_round_trip() {
        let c = ConnectPayload {
            host: "example.com".to_string(),
            port: 443,
        };
        let bytes = c.encode();
        let back = ConnectPayload::decode(&bytes).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn connect_rejects_length_mismatch() {
        // Claim host_len = 5, supply 3 host bytes + 2 port bytes
        let mut bytes = vec![];
        bytes.extend_from_slice(&(5u16).to_be_bytes());
        bytes.extend_from_slice(b"abc");
        bytes.extend_from_slice(&(80u16).to_be_bytes());
        let err = ConnectPayload::decode(&bytes).unwrap_err();
        assert!(matches!(err, CellError::BadConnect(_)));
    }
}
