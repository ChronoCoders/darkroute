//! Layered framing: one AEAD layer per hop, fixed size on every link.
//!
//! Both the relay and the client go through here, so the padding rule, the
//! disposition byte and the size arithmetic exist once.
//!
//! A layer's plaintext is `disposition(1) || body`, where `body` is
//! [`body_len`] bytes for that link position. `TO_ME` means the body starts
//! with a full cell and the remainder is zero padding. `FORWARD` means the body
//! is the adjacent link's complete cell, passed on verbatim.
//!
//! Sealing a cell for hop `i` uses [`seal_to_me`] with that hop's layer count,
//! then [`seal_forward`] once per hop nearer the client. Peeling is the
//! reverse: [`peel`] until it returns [`Peeled::ToMe`].

use crate::cell::{body_len, link_cell_len, Cell, CellError, CELL_PLAINTEXT_LEN};
use crate::noise::{NoiseError, Transport, NOISE_TAG_LEN};
use crate::wire::{DISPOSITION_FORWARD, DISPOSITION_LEN, DISPOSITION_TO_ME};

#[derive(Debug, thiserror::Error)]
pub enum LayerError {
    #[error("noise: {0}")]
    Noise(#[from] NoiseError),
    #[error("cell: {0}")]
    Cell(#[from] CellError),
    #[error("unknown disposition byte 0x{0:02x}")]
    UnknownDisposition(u8),
    #[error("a TO_ME body carries nonzero padding")]
    DirtyPadding,
    #[error("wire frame is {got} bytes, expected {want}")]
    WrongSize { got: usize, want: usize },
    #[error("FORWARD is not legal on the innermost layer")]
    ForwardAtInnermost,
}

/// What one peeled layer turned out to hold.
#[derive(Debug)]
pub enum Peeled {
    /// A cell for the peeling party.
    ToMe(Cell),
    /// The adjacent link's complete cell, to pass on unchanged.
    Forward(Vec<u8>),
}

/// Seal `cell` as the innermost layer for a hop `layers` deep.
///
/// Returns exactly `link_cell_len(layers)` bytes. The body is zero-padded, so
/// the output size never depends on the payload.
pub fn seal_to_me(tx: &mut Transport, cell: &Cell, layers: usize) -> Result<Vec<u8>, LayerError> {
    let body = body_len(layers);
    let mut plain = vec![0u8; DISPOSITION_LEN + body];
    plain[0] = DISPOSITION_TO_ME;
    cell.encode_into(&mut plain[DISPOSITION_LEN..DISPOSITION_LEN + CELL_PLAINTEXT_LEN])?;
    // The rest of the body is already zero from the allocation.
    let mut out = vec![0u8; plain.len() + NOISE_TAG_LEN];
    tx.encrypt(&plain, &mut out)?;
    debug_assert_eq!(out.len(), link_cell_len(layers));
    Ok(out)
}

/// Seal `blob` for forwarding. `blob` must be the adjacent link's full cell.
pub fn seal_forward(tx: &mut Transport, blob: &[u8]) -> Result<Vec<u8>, LayerError> {
    let mut plain = vec![0u8; DISPOSITION_LEN + blob.len()];
    plain[0] = DISPOSITION_FORWARD;
    plain[DISPOSITION_LEN..].copy_from_slice(blob);
    let mut out = vec![0u8; plain.len() + NOISE_TAG_LEN];
    tx.encrypt(&plain, &mut out)?;
    Ok(out)
}

/// Peel one layer off a frame read from a link `layers` deep.
///
/// `wire` must be exactly `link_cell_len(layers)` bytes; the caller reads that
/// many because the size is fixed and no length appears on the wire.
pub fn peel(tx: &mut Transport, wire: &[u8], layers: usize) -> Result<Peeled, LayerError> {
    let want = link_cell_len(layers);
    if wire.len() != want {
        return Err(LayerError::WrongSize {
            got: wire.len(),
            want,
        });
    }
    let body = body_len(layers);
    let mut plain = vec![0u8; DISPOSITION_LEN + body];
    tx.decrypt(wire, &mut plain)?;

    match plain[0] {
        DISPOSITION_TO_ME => {
            let cell = Cell::decode(&plain[DISPOSITION_LEN..DISPOSITION_LEN + CELL_PLAINTEXT_LEN])?;
            // Padding beyond the cell must be zero. A sender that leaves bytes
            // there has a channel the design does not grant it.
            if plain[DISPOSITION_LEN + CELL_PLAINTEXT_LEN..]
                .iter()
                .any(|b| *b != 0)
            {
                return Err(LayerError::DirtyPadding);
            }
            Ok(Peeled::ToMe(cell))
        }
        DISPOSITION_FORWARD => {
            if layers == 1 {
                return Err(LayerError::ForwardAtInnermost);
            }
            Ok(Peeled::Forward(plain[DISPOSITION_LEN..].to_vec()))
        }
        other => Err(LayerError::UnknownDisposition(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell::CellType;
    use crate::noise::{generate_static_keypair, respond, Initiator};

    fn pair() -> (Transport, Transport) {
        let kp = generate_static_keypair().unwrap();
        let (init, msg1) = Initiator::start(&kp.public).unwrap();
        let (relay_tx, msg2) = respond(kp.private(), &msg1).unwrap();
        (init.finish(&msg2).unwrap(), relay_tx)
    }

    #[test]
    fn to_me_round_trips_at_every_depth() {
        for layers in 1..=3 {
            let (mut client, mut relay) = pair();
            let cell = Cell::new(CellType::Data, vec![0x5A; 100]).unwrap();
            let wire = seal_to_me(&mut client, &cell, layers).unwrap();
            assert_eq!(wire.len(), link_cell_len(layers), "layers {layers}");
            match peel(&mut relay, &wire, layers).unwrap() {
                Peeled::ToMe(got) => assert_eq!(got, cell),
                Peeled::Forward(_) => panic!("layers {layers}: expected ToMe"),
            }
        }
    }

    #[test]
    fn on_wire_size_is_constant_regardless_of_payload() {
        for layers in 1..=3 {
            let want = link_cell_len(layers);
            for n in [0usize, 1, 7, 200, crate::cell::CELL_PAYLOAD_LEN] {
                let (mut client, _) = pair();
                let cell = Cell::new(CellType::Data, vec![1u8; n]).unwrap();
                let wire = seal_to_me(&mut client, &cell, layers).unwrap();
                assert_eq!(
                    wire.len(),
                    want,
                    "layers {layers}, payload {n} produced {} bytes",
                    wire.len()
                );
            }
        }
    }

    #[test]
    fn forward_round_trips_and_sizes_telescope() {
        // middle->exit cell forwarded by the middle, wrapped for guard->middle.
        let (mut client, mut relay) = pair();
        let blob = vec![0xC3; link_cell_len(1)];
        let wire = seal_forward(&mut client, &blob).unwrap();
        assert_eq!(wire.len(), link_cell_len(2));
        match peel(&mut relay, &wire, 2).unwrap() {
            Peeled::Forward(got) => assert_eq!(got, blob),
            Peeled::ToMe(_) => panic!("expected Forward"),
        }
    }

    #[test]
    fn three_hop_onion_telescopes_to_564() {
        let (mut k_exit, mut exit_rx) = pair();
        let (mut k_mid, mut mid_rx) = pair();
        let (mut k_guard, mut guard_rx) = pair();

        let cell = Cell::new(CellType::Data, b"payload".to_vec()).unwrap();
        let inner = seal_to_me(&mut k_exit, &cell, 1).unwrap();
        assert_eq!(inner.len(), 530);
        let mid = seal_forward(&mut k_mid, &inner).unwrap();
        assert_eq!(mid.len(), 547);
        let outer = seal_forward(&mut k_guard, &mid).unwrap();
        assert_eq!(outer.len(), 564);

        // Guard peels and forwards, middle peels and forwards, exit reads.
        let fwd1 = match peel(&mut guard_rx, &outer, 3).unwrap() {
            Peeled::Forward(b) => b,
            Peeled::ToMe(_) => panic!("guard got ToMe"),
        };
        assert_eq!(fwd1.len(), 547);
        let fwd2 = match peel(&mut mid_rx, &fwd1, 2).unwrap() {
            Peeled::Forward(b) => b,
            Peeled::ToMe(_) => panic!("middle got ToMe"),
        };
        assert_eq!(fwd2.len(), 530);
        match peel(&mut exit_rx, &fwd2, 1).unwrap() {
            Peeled::ToMe(got) => assert_eq!(got, cell),
            Peeled::Forward(_) => panic!("exit got Forward"),
        }
    }

    #[test]
    fn peel_rejects_a_wrong_size_frame() {
        let (mut client, mut relay) = pair();
        let cell = Cell::new(CellType::Data, Vec::new()).unwrap();
        let wire = seal_to_me(&mut client, &cell, 3).unwrap();
        for bad in [&wire[..wire.len() - 1], &wire[..1]] {
            match peel(&mut relay, bad, 3) {
                Err(LayerError::WrongSize { want, .. }) => assert_eq!(want, link_cell_len(3)),
                other => panic!("short frame accepted: {other:?}"),
            }
        }
    }

    #[test]
    fn peel_rejects_a_tampered_frame() {
        let (mut client, mut relay) = pair();
        let cell = Cell::new(CellType::Data, b"x".to_vec()).unwrap();
        let mut wire = seal_to_me(&mut client, &cell, 3).unwrap();
        wire[20] ^= 0x01;
        assert!(matches!(
            peel(&mut relay, &wire, 3),
            Err(LayerError::Noise(_))
        ));
    }

    #[test]
    fn peel_rejects_dirty_padding() {
        // Build a TO_ME plaintext by hand with a nonzero padding byte.
        let (mut client, mut relay) = pair();
        let layers = 3;
        let body = body_len(layers);
        let mut plain = vec![0u8; DISPOSITION_LEN + body];
        plain[0] = DISPOSITION_TO_ME;
        Cell::new(CellType::Data, Vec::new())
            .unwrap()
            .encode_into(&mut plain[DISPOSITION_LEN..DISPOSITION_LEN + CELL_PLAINTEXT_LEN])
            .unwrap();
        *plain.last_mut().unwrap() = 0xFF;

        let mut wire = vec![0u8; plain.len() + NOISE_TAG_LEN];
        client.encrypt(&plain, &mut wire).unwrap();
        assert!(matches!(
            peel(&mut relay, &wire, layers),
            Err(LayerError::DirtyPadding)
        ));
    }

    #[test]
    fn peel_rejects_an_unknown_disposition() {
        let (mut client, mut relay) = pair();
        let layers = 3;
        let mut plain = vec![0u8; DISPOSITION_LEN + body_len(layers)];
        plain[0] = 0x7F;
        let mut wire = vec![0u8; plain.len() + NOISE_TAG_LEN];
        client.encrypt(&plain, &mut wire).unwrap();
        assert!(matches!(
            peel(&mut relay, &wire, layers),
            Err(LayerError::UnknownDisposition(0x7F))
        ));
    }

    #[test]
    fn forward_is_illegal_at_the_innermost_layer() {
        let (mut client, mut relay) = pair();
        let mut plain = vec![0u8; DISPOSITION_LEN + body_len(1)];
        plain[0] = DISPOSITION_FORWARD;
        let mut wire = vec![0u8; plain.len() + NOISE_TAG_LEN];
        client.encrypt(&plain, &mut wire).unwrap();
        assert!(matches!(
            peel(&mut relay, &wire, 1),
            Err(LayerError::ForwardAtInnermost)
        ));
    }

    #[test]
    fn replayed_frame_is_rejected_at_the_layer() {
        let (mut client, mut relay) = pair();
        let cell = Cell::new(CellType::Data, b"once".to_vec()).unwrap();
        let wire = seal_to_me(&mut client, &cell, 3).unwrap();
        assert!(peel(&mut relay, &wire, 3).is_ok());
        assert!(matches!(
            peel(&mut relay, &wire, 3),
            Err(LayerError::Noise(_))
        ));
    }
}
