//! Wire protocol constants shared by relay and client.

pub const PROTO_CLIENT: u8 = 0x01;
pub const PROTO_RELAY: u8 = 0x02;

pub const CIRCUIT_START: u8 = 0xC1;

pub const M_RAW_LEN: usize = 32;
pub const TOKEN_LEN: usize = 256;
pub const PRESENTATION_LEN: usize = M_RAW_LEN + TOKEN_LEN;

pub const X25519_PK_LEN: usize = 32;
pub const CIRCUIT_ID: u32 = 1;
