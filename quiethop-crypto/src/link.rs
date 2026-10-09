//! Link framing: many circuits over one long-lived link.
//!
//! Every frame on a link is the same length whatever its command, so an
//! observer outside TLS cannot tell a circuit opening or closing from a data
//! cell by size. DATA fills its body exactly and every control command is
//! zero-padded up to that, so one length per link serves all of them and the
//! only cost is the five byte header.
//!
//! ```text
//! circ_id (4, big endian) || command (1) || body (link_cell_len(layers))
//! ```
//!
//! The header is cleartext inside TLS and outside the Noise layers. A relay
//! cannot peel a frame before it knows which circuit's transport to peel with,
//! and a create arrives before any transport exists, so the id has to be
//! readable first. End-to-end control is a cell type inside the innermost layer
//! instead, which is why SENDME is a cell and DESTROY is a link command
//! (ARCHITECTURE 5.5, SECURITY_MODEL 5.10).

use thiserror::Error;

use crate::cell::link_cell_len;
use crate::circid::{CircId, CircIdError, LinkRole, CIRC_ID_LEN};
use crate::noise::NOISE_MSG_LEN;
use crate::wire::PRESENTATION_LEN;

pub const LINK_COMMAND_LEN: usize = 1;
pub const LINK_HEADER_LEN: usize = CIRC_ID_LEN + LINK_COMMAND_LEN;

/// Frame size on a link `layers` hops from the innermost cell.
///
/// 569 client to guard, 552 guard to middle, 535 middle to exit.
pub const fn link_frame_len(layers: usize) -> usize {
    LINK_HEADER_LEN + link_cell_len(layers)
}

/// CREATE body on the client link: the token presentation then the first Noise
/// message. The token is presented per circuit, not per connection, so one
/// token buys one circuit.
pub const CREATE_CLIENT_BODY_LEN: usize = PRESENTATION_LEN + NOISE_MSG_LEN;

/// CREATE body on a relay link: the first Noise message alone. No token
/// appears on a relay link.
pub const CREATE_RELAY_BODY_LEN: usize = NOISE_MSG_LEN;

/// CREATED body, either kind of link.
pub const CREATED_BODY_LEN: usize = NOISE_MSG_LEN;

/// DESTROY body: one reason byte.
pub const DESTROY_BODY_LEN: usize = 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LinkError {
    #[error("frame is {got} bytes, not the link's {want}")]
    WrongSize { got: usize, want: usize },
    #[error("unknown link command {0:#04x}")]
    UnknownCommand(u8),
    #[error("circuit id: {0}")]
    CircId(#[from] CircIdError),
    #[error("body for this command is {want} bytes but the frame carries {got} of payload")]
    BodyTooShort { got: usize, want: usize },
    #[error("payload is {got} bytes, more than the {max} byte body of this link's frame")]
    PayloadTooLong { got: usize, max: usize },
    #[error("padding after a {0} byte body is not zero")]
    DirtyPadding(usize),
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkCommand {
    Create = 0x01,
    Created = 0x02,
    Data = 0x03,
    Destroy = 0x04,
    /// Reserved so link padding can be added later without a wire change.
    ///
    /// Nothing sends it in this step. A receiver accepts it and ignores it, but
    /// its body must be entirely zero: an unchecked body on a command every hop
    /// forwards is a covert channel, which is the same reason [`payload`]
    /// checks the padding after a short control body.
    Padding = 0x05,
}

impl TryFrom<u8> for LinkCommand {
    type Error = LinkError;
    fn try_from(b: u8) -> Result<Self, Self::Error> {
        match b {
            0x01 => Ok(LinkCommand::Create),
            0x02 => Ok(LinkCommand::Created),
            0x03 => Ok(LinkCommand::Data),
            0x04 => Ok(LinkCommand::Destroy),
            0x05 => Ok(LinkCommand::Padding),
            other => Err(LinkError::UnknownCommand(other)),
        }
    }
}

/// Why a circuit was destroyed. Carried in the DESTROY body for operators and
/// logs; no behaviour depends on it, so an unknown value is not an error.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestroyReason {
    Requested = 0x00,
    Protocol = 0x01,
    Resource = 0x02,
    LinkLost = 0x03,
    FlowControl = 0x04,
    Internal = 0x05,
}

/// A frame read off a link. `body` is the whole padded body; what counts as
/// payload depends on the command, which [`payload`] applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    pub circ_id: CircId,
    pub command: LinkCommand,
    pub body: &'a [u8],
}

/// Write a frame, zero-padding the body to the link's size.
///
/// `payload` may be shorter than the body; everything after it is zeroed, so a
/// short command cannot leak whatever was in the buffer before.
pub fn encode_into(
    out: &mut [u8],
    layers: usize,
    circ_id: CircId,
    command: LinkCommand,
    payload: &[u8],
) -> Result<(), LinkError> {
    let want = link_frame_len(layers);
    if out.len() != want {
        return Err(LinkError::WrongSize {
            got: out.len(),
            want,
        });
    }
    let body = link_cell_len(layers);
    if payload.len() > body {
        return Err(LinkError::PayloadTooLong {
            got: payload.len(),
            max: body,
        });
    }
    out[..CIRC_ID_LEN].copy_from_slice(&circ_id.to_bytes());
    out[CIRC_ID_LEN] = command as u8;
    out[LINK_HEADER_LEN..LINK_HEADER_LEN + payload.len()].copy_from_slice(payload);
    for b in out[LINK_HEADER_LEN + payload.len()..].iter_mut() {
        *b = 0;
    }
    Ok(())
}

/// Allocate and write a frame. Convenience over [`encode_into`].
pub fn encode(
    layers: usize,
    circ_id: CircId,
    command: LinkCommand,
    payload: &[u8],
) -> Result<Vec<u8>, LinkError> {
    let mut out = vec![0u8; link_frame_len(layers)];
    encode_into(&mut out, layers, circ_id, command, payload)?;
    Ok(out)
}

/// Read a frame, validating its length, its command and the peer's half of the
/// id space.
///
/// `peer` is the peer's role on this link, so the id is checked against the half
/// that peer is allowed to choose from.
pub fn decode(wire: &[u8], layers: usize, peer: LinkRole) -> Result<Frame<'_>, LinkError> {
    let want = link_frame_len(layers);
    if wire.len() != want {
        return Err(LinkError::WrongSize {
            got: wire.len(),
            want,
        });
    }
    let raw = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]);
    let command = LinkCommand::try_from(wire[CIRC_ID_LEN])?;
    // A DATA frame's id was chosen by whichever side created the circuit, which
    // is not necessarily this peer, so only a create is held to the peer's half.
    // Holding every frame to it would refuse the responder's own DATA frames.
    let circ_id = match command {
        LinkCommand::Create => CircId::from_peer(raw, peer)?,
        _ => CircId::new(raw)?,
    };
    let body = &wire[LINK_HEADER_LEN..];
    // A PADDING frame carries nothing, so its whole body must be zero. Checked
    // here rather than left to the caller, because the one thing a caller does
    // with PADDING is ignore it, and an ignored frame is exactly where an
    // unchecked body would go unnoticed.
    if command == LinkCommand::Padding {
        payload(body, 0)?;
    }
    Ok(Frame {
        circ_id,
        command,
        body,
    })
}

/// The first `want` bytes of a body, after checking the rest is zero.
///
/// The padding check matters: without it a sender could carry `body - want`
/// bytes of anything past a control command's payload, which is a covert
/// channel through a frame every hop forwards.
pub fn payload(body: &[u8], want: usize) -> Result<&[u8], LinkError> {
    if body.len() < want {
        return Err(LinkError::BodyTooShort {
            got: body.len(),
            want,
        });
    }
    if body[want..].iter().any(|b| *b != 0) {
        return Err(LinkError::DirtyPadding(want));
    }
    Ok(&body[..want])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell::CELL_PLAINTEXT_LEN;
    use crate::noise::NOISE_TAG_LEN;
    use crate::wire::DISPOSITION_LEN;

    const CLIENT_GUARD: usize = 3;
    const GUARD_MIDDLE: usize = 2;
    const MIDDLE_EXIT: usize = 1;

    fn id() -> CircId {
        CircId::new(0x8000_00ab).unwrap()
    }

    /// The hard requirement, asserted as literal numbers rather than recomputed
    /// from the same function the code uses. Recomputing would make this test
    /// agree with any arithmetic the implementation happened to choose.
    #[test]
    fn frame_sizes_are_569_552_and_535() {
        assert_eq!(link_frame_len(CLIENT_GUARD), 569);
        assert_eq!(link_frame_len(GUARD_MIDDLE), 552);
        assert_eq!(link_frame_len(MIDDLE_EXIT), 535);

        // And the arithmetic they come from, so a change to any term is visible
        // here rather than only in the totals.
        assert_eq!(CELL_PLAINTEXT_LEN, 513);
        assert_eq!(DISPOSITION_LEN + NOISE_TAG_LEN, 17);
        assert_eq!(LINK_HEADER_LEN, 5);
        // Written as sums rather than products so each layer's 17 bytes is
        // visible, and because a unit multiplier trips clippy's identity_op.
        assert_eq!(5 + 513 + 17 + 17 + 17, 569);
        assert_eq!(5 + 513 + 17 + 17, 552);
        assert_eq!(5 + 513 + 17, 535);
    }

    /// Every command on every link encodes to the one length. This is what
    /// makes a create indistinguishable from a data cell outside TLS.
    #[test]
    fn every_command_encodes_to_the_links_one_length() {
        let cases = [
            (CLIENT_GUARD, 569usize),
            (GUARD_MIDDLE, 552),
            (MIDDLE_EXIT, 535),
        ];
        let data = vec![0x5Au8; link_cell_len(CLIENT_GUARD)];
        for (layers, want) in cases {
            let full = vec![0x5Au8; link_cell_len(layers)];
            let payloads: [(LinkCommand, &[u8]); 5] = [
                (LinkCommand::Create, &data[..CREATE_RELAY_BODY_LEN]),
                (LinkCommand::Created, &data[..CREATED_BODY_LEN]),
                (LinkCommand::Data, &full),
                (LinkCommand::Destroy, &data[..DESTROY_BODY_LEN]),
                (LinkCommand::Padding, &[]),
            ];
            for (command, bytes) in payloads {
                let frame = encode(layers, id(), command, bytes).expect("encode");
                assert_eq!(
                    frame.len(),
                    want,
                    "{command:?} on a {layers} layer link was not {want} bytes"
                );
            }
        }
    }

    /// The client CREATE body is the largest control payload and must still fit
    /// with room to spare, which is what lets the key_id arrive later without
    /// moving any frame size.
    #[test]
    fn the_client_create_body_fits_with_slack() {
        assert_eq!(CREATE_CLIENT_BODY_LEN, 288 + 48);
        let body = link_cell_len(CLIENT_GUARD);
        assert_eq!(body, 564);
        assert!(CREATE_CLIENT_BODY_LEN < body);
        assert_eq!(body - CREATE_CLIENT_BODY_LEN, 228);
    }

    #[test]
    fn a_frame_round_trips() {
        let msg = [0xA1u8; CREATED_BODY_LEN];
        let wire = encode(MIDDLE_EXIT, id(), LinkCommand::Created, &msg).unwrap();
        let f = decode(&wire, MIDDLE_EXIT, LinkRole::Initiator).unwrap();
        assert_eq!(f.circ_id, id());
        assert_eq!(f.command, LinkCommand::Created);
        assert_eq!(payload(f.body, CREATED_BODY_LEN).unwrap(), &msg);
    }

    #[test]
    fn a_wrong_length_frame_is_refused() {
        let wire = encode(MIDDLE_EXIT, id(), LinkCommand::Data, &[]).unwrap();
        for bad in [&wire[..wire.len() - 1], &wire[..1]] {
            assert!(matches!(
                decode(bad, MIDDLE_EXIT, LinkRole::Initiator),
                Err(LinkError::WrongSize { .. })
            ));
        }
        // And a frame sized for the wrong link.
        assert!(matches!(
            decode(&wire, CLIENT_GUARD, LinkRole::Initiator),
            Err(LinkError::WrongSize { .. })
        ));
    }

    #[test]
    fn an_unknown_command_is_refused() {
        let mut wire = encode(MIDDLE_EXIT, id(), LinkCommand::Data, &[]).unwrap();
        wire[CIRC_ID_LEN] = 0x7F;
        assert_eq!(
            decode(&wire, MIDDLE_EXIT, LinkRole::Initiator),
            Err(LinkError::UnknownCommand(0x7F))
        );
    }

    #[test]
    fn circuit_id_zero_is_refused_on_the_wire() {
        let mut wire = encode(MIDDLE_EXIT, id(), LinkCommand::Data, &[]).unwrap();
        wire[..CIRC_ID_LEN].copy_from_slice(&0u32.to_be_bytes());
        assert!(matches!(
            decode(&wire, MIDDLE_EXIT, LinkRole::Initiator),
            Err(LinkError::CircId(CircIdError::Zero))
        ));
    }

    /// A create is held to the peer's half of the id space. Other commands are
    /// not, because a circuit's id was chosen once by whichever side created it.
    #[test]
    fn a_create_from_the_wrong_half_is_refused() {
        let responder_id = CircId::new(0x0000_0007).unwrap();
        let wire = encode(MIDDLE_EXIT, responder_id, LinkCommand::Create, &[]).unwrap();
        assert!(matches!(
            decode(&wire, MIDDLE_EXIT, LinkRole::Initiator),
            Err(LinkError::CircId(CircIdError::WrongHalf(_)))
        ));
        // The same id is fine on a create from the responder, and fine on any
        // other command from either side.
        assert!(decode(&wire, MIDDLE_EXIT, LinkRole::Responder).is_ok());
        let data = encode(MIDDLE_EXIT, responder_id, LinkCommand::Data, &[]).unwrap();
        assert!(decode(&data, MIDDLE_EXIT, LinkRole::Initiator).is_ok());
    }

    #[test]
    fn padding_after_a_short_body_must_be_zero() {
        let mut wire = encode(MIDDLE_EXIT, id(), LinkCommand::Destroy, &[0x02]).unwrap();
        let f = decode(&wire, MIDDLE_EXIT, LinkRole::Initiator).unwrap();
        assert_eq!(payload(f.body, DESTROY_BODY_LEN).unwrap(), &[0x02]);

        // One nonzero byte anywhere in the padding is refused.
        let last = wire.len() - 1;
        wire[last] = 0x01;
        let f = decode(&wire, MIDDLE_EXIT, LinkRole::Initiator).unwrap();
        assert_eq!(
            payload(f.body, DESTROY_BODY_LEN),
            Err(LinkError::DirtyPadding(DESTROY_BODY_LEN))
        );
    }

    #[test]
    fn encode_zeroes_padding_it_did_not_write() {
        let mut out = vec![0xFFu8; link_frame_len(MIDDLE_EXIT)];
        encode_into(&mut out, MIDDLE_EXIT, id(), LinkCommand::Destroy, &[0x03]).unwrap();
        assert_eq!(out[LINK_HEADER_LEN], 0x03);
        assert!(
            out[LINK_HEADER_LEN + 1..].iter().all(|b| *b == 0),
            "padding was not zeroed over a dirty buffer"
        );
    }

    /// An over-long payload on encode is its own error, kept distinct from the
    /// decode-side BodyTooShort so a failure says which side was wrong.
    #[test]
    fn a_payload_longer_than_the_body_is_refused() {
        let body = link_cell_len(MIDDLE_EXIT);
        let too_long = vec![0u8; body + 1];
        assert_eq!(
            encode(MIDDLE_EXIT, id(), LinkCommand::Data, &too_long),
            Err(LinkError::PayloadTooLong {
                got: body + 1,
                max: body
            })
        );
        // Exactly the body length is fine, so the refusal is the extra byte.
        assert!(encode(MIDDLE_EXIT, id(), LinkCommand::Data, &too_long[..body]).is_ok());
    }

    /// A PADDING frame carries nothing, so a non-zero body is refused. Without
    /// the check it would be a covert channel through a command every hop
    /// forwards and every receiver ignores.
    #[test]
    fn a_padding_frame_with_a_non_zero_body_is_refused() {
        let clean = encode(MIDDLE_EXIT, id(), LinkCommand::Padding, &[]).unwrap();
        assert!(
            decode(&clean, MIDDLE_EXIT, LinkRole::Initiator).is_ok(),
            "an all zero PADDING frame must be accepted"
        );

        // One non-zero byte anywhere in the body is refused, first and last.
        for pos in [LINK_HEADER_LEN, clean.len() - 1] {
            let mut dirty = clean.clone();
            dirty[pos] = 0x01;
            assert_eq!(
                decode(&dirty, MIDDLE_EXIT, LinkRole::Initiator),
                Err(LinkError::DirtyPadding(0)),
                "a non-zero byte at {pos} was accepted"
            );
        }

        // And the same byte in a DATA frame is fine, so the refusal is the
        // command rather than the content.
        let mut data = encode(MIDDLE_EXIT, id(), LinkCommand::Data, &[]).unwrap();
        data[CIRC_ID_LEN] = LinkCommand::Data as u8;
        data[LINK_HEADER_LEN] = 0x01;
        assert!(decode(&data, MIDDLE_EXIT, LinkRole::Initiator).is_ok());
    }
}
