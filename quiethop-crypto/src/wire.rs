//! Wire protocol constants shared by relay and client.

pub const PROTO_CLIENT: u8 = 0x01;
pub const PROTO_RELAY: u8 = 0x02;

pub const M_RAW_LEN: usize = 32;
pub const TOKEN_LEN: usize = 256;
pub const PRESENTATION_LEN: usize = M_RAW_LEN + TOKEN_LEN;

/// One byte in front of each layer's plaintext, telling the relay that peeled
/// it whether the remainder is a cell for it or a blob to forward verbatim.
pub const DISPOSITION_LEN: usize = 1;
pub const DISPOSITION_TO_ME: u8 = 0x01;
pub const DISPOSITION_FORWARD: u8 = 0x02;
