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

/// Accumulates fixed-length frames across cancellations.
///
/// `AsyncReadExt::read_exact` is not cancel safe: used directly as a
/// `tokio::select!` branch, bytes already moved into its buffer are lost when
/// another branch completes first. Under fixed-length framing that shifts every
/// later read off a cell boundary, so the next frame fails authentication and
/// the circuit tears down.
///
/// `read` is cancel safe, so the caller performs one `read` per select
/// iteration and hands the bytes here. All partial state lives in this struct,
/// outside the future that select may drop, so a cancelled branch loses
/// nothing.
#[derive(Debug)]
pub struct FrameAccumulator {
    frame_len: usize,
    buf: Vec<u8>,
}

impl FrameAccumulator {
    pub fn new(frame_len: usize) -> Self {
        Self {
            frame_len,
            buf: Vec::with_capacity(frame_len),
        }
    }

    /// Add freshly read bytes. A single read may carry part of a frame, a whole
    /// frame, or several, so the caller drains with `next_frame` afterwards.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Take one complete frame, if one has accumulated.
    pub fn next_frame(&mut self) -> Option<Vec<u8>> {
        if self.buf.len() < self.frame_len {
            return None;
        }
        let rest = self.buf.split_off(self.frame_len);
        Some(std::mem::replace(&mut self.buf, rest))
    }

    /// Bytes held that do not yet make a frame. Used by tests to show that a
    /// partial frame survives a cancelled branch.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

/// A read half plus its partial-frame buffer, yielding only whole frames.
///
/// This is the type the relay and the client both use in their `select!`
/// loops. `next_frame` is cancel safe: its only await point is `read`, which
/// tokio documents as cancel safe, and every byte already read lives in this
/// struct rather than in the future, so a dropped branch loses nothing.
///
/// Below TLS a partial plaintext read is rare, because rustls hands up whole
/// records and a cell is normally written as one record. It is not impossible.
/// In tokio-rustls 0.26.4, the version this workspace locks, `poll_write` ends
/// with
///
/// ```text
/// return match (pos, would_block) {
///     (0, true) => Poll::Pending,
///     (n, true) => Poll::Ready(Ok(n)),
///     (_, false) => continue,
/// };
/// ```
///
/// so when the socket would block after some bytes are buffered it returns a
/// short write. `write_all` then calls `poll_write` again with the remainder,
/// which enters the rustls writer as a separate plaintext write after the
/// first part has already been encrypted and emitted. One cell can therefore
/// span two records, and the reader on the other side sees a partial cell.
///
/// Tokio makes no cancel-safety guarantee for `read_exact` in any case, so this
/// code does not depend on record boundaries.
#[derive(Debug)]
pub struct FrameReader<R> {
    inner: R,
    acc: FrameAccumulator,
    scratch: Vec<u8>,
}

impl<R: tokio::io::AsyncRead + Unpin> FrameReader<R> {
    pub fn new(inner: R, frame_len: usize) -> Self {
        Self {
            inner,
            acc: FrameAccumulator::new(frame_len),
            scratch: vec![0u8; frame_len],
        }
    }

    /// Yield the next whole frame. Safe to use as a `tokio::select!` branch.
    pub async fn next_frame(&mut self) -> std::io::Result<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        loop {
            if let Some(frame) = self.acc.next_frame() {
                return Ok(frame);
            }
            // Read only as far as the end of the frame being assembled.
            // Sizing this to the whole scratch buffer would let one read take
            // the rest of the frame plus the bytes after it, and those bytes
            // would then be dropped along with this reader. On a multiplexed
            // link they are the start of another circuit's frame, and losing
            // them would misalign every frame after it. `pending` is below
            // frame_len here, because a full frame was already drained above,
            // so room is at least 1.
            let room = self.scratch.len() - self.acc.pending();
            let n = self.inner.read(&mut self.scratch[..room]).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "peer closed mid-frame",
                ));
            }
            self.acc.push(&self.scratch[..n]);
        }
    }

    /// Bytes buffered that do not yet make a frame.
    ///
    /// A caller that intends to hand the underlying stream to someone else must
    /// check this first: those bytes belong to the current reader's stream
    /// position and would surface as a corrupt frame for whoever reads next.
    pub fn pending(&self) -> usize {
        self.acc.pending()
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

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

/// Seal `blob` for forwarding at a link `layers` deep.
///
/// `blob` must be exactly the adjacent link's cell size. Accepting any length
/// would let a caller emit a frame that is not the fixed size for its link,
/// which is the one property the whole layout exists to hold.
pub fn seal_forward(tx: &mut Transport, blob: &[u8], layers: usize) -> Result<Vec<u8>, LayerError> {
    let want = link_cell_len(layers - 1);
    if blob.len() != want {
        return Err(LayerError::WrongSize {
            got: blob.len(),
            want,
        });
    }
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
        let wire = seal_forward(&mut client, &blob, 2).unwrap();
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
        let mid = seal_forward(&mut k_mid, &inner, 2).unwrap();
        assert_eq!(mid.len(), 547);
        let outer = seal_forward(&mut k_guard, &mid, 3).unwrap();
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
    fn seal_forward_rejects_a_blob_that_is_not_the_adjacent_link_size() {
        let (mut client, _) = pair();
        let right = vec![0u8; link_cell_len(1)];
        // Control: the correct size is accepted at this depth.
        assert!(seal_forward(&mut client, &right, 2).is_ok());

        for bad in [
            link_cell_len(1) - 1,
            link_cell_len(1) + 1,
            0,
            link_cell_len(2),
        ] {
            let (mut c, _) = pair();
            let blob = vec![0u8; bad];
            match seal_forward(&mut c, &blob, 2) {
                Err(LayerError::WrongSize { got, want }) => {
                    assert_eq!(got, bad);
                    assert_eq!(want, link_cell_len(1));
                }
                other => panic!("blob of {bad} bytes was accepted at depth 2: {other:?}"),
            }
        }
    }

    #[test]
    fn seal_forward_wants_the_depth_specific_size() {
        // The same blob is right at one depth and wrong at another, so the
        // parameter is doing work rather than being decorative.
        let blob = vec![0u8; link_cell_len(2)];
        let (mut a, _) = pair();
        assert!(seal_forward(&mut a, &blob, 3).is_ok());
        let (mut b, _) = pair();
        assert!(matches!(
            seal_forward(&mut b, &blob, 2),
            Err(LayerError::WrongSize { .. })
        ));
    }

    #[test]
    fn accumulator_yields_whole_frames_from_dribbled_bytes() {
        let n = link_cell_len(3);
        let mut acc = FrameAccumulator::new(n);
        let frame: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();

        // One to seven bytes at a time, the shape a chunking transport gives.
        let mut sent = 0;
        let mut got = None;
        let mut chunk = 1;
        while sent < n {
            let take = chunk.min(n - sent);
            acc.push(&frame[sent..sent + take]);
            sent += take;
            chunk = if chunk == 7 { 1 } else { chunk + 1 };
            if let Some(f) = acc.next_frame() {
                got = Some(f);
            }
        }
        assert_eq!(got.expect("no frame assembled"), frame);
        assert_eq!(acc.pending(), 0);
    }

    #[test]
    fn accumulator_keeps_a_partial_frame_and_splits_several() {
        let n = link_cell_len(1);
        let mut acc = FrameAccumulator::new(n);
        acc.push(&vec![1u8; n - 1]);
        assert!(acc.next_frame().is_none(), "a partial frame must not yield");
        assert_eq!(acc.pending(), n - 1, "the partial frame must be retained");

        // Complete the first and deliver two more in one push.
        acc.push(&vec![2u8; 1 + 2 * n]);
        let first = acc.next_frame().expect("first frame");
        assert_eq!(first.len(), n);
        assert_eq!(first[0], 1, "the retained bytes must lead the first frame");
        assert!(acc.next_frame().is_some(), "second frame");
        assert!(acc.next_frame().is_some(), "third frame");
        assert!(acc.next_frame().is_none());
        assert_eq!(acc.pending(), 0);
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

#[cfg(test)]
mod cancel_safety {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const FRAME: usize = 8;

    /// Drive two sources with controlled timing: a partial frame on A, then a
    /// byte on B to make the other branch win, then the rest of A.
    async fn feed(mut a: tokio::io::DuplexStream, mut b: tokio::io::DuplexStream) {
        a.write_all(&[1, 2, 3]).await.unwrap();
        a.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        b.write_all(&[9]).await.unwrap();
        b.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        a.write_all(&[4, 5, 6, 7, 8]).await.unwrap();
        a.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    /// The defect: read_exact as a select branch. Shows that bytes already
    /// taken into its buffer are lost when the other branch completes first.
    #[tokio::test]
    async fn read_exact_in_select_loses_partial_bytes() {
        let (a_tx, mut a_rx) = tokio::io::duplex(64);
        let (b_tx, mut b_rx) = tokio::io::duplex(64);
        tokio::spawn(feed(a_tx, b_tx));

        let mut got: Vec<u8> = Vec::new();
        let mut bbuf = [0u8; 1];
        let outcome = tokio::time::timeout(Duration::from_millis(600), async {
            while got.len() < FRAME {
                tokio::select! {
                    biased;
                    r = async {
                        let mut f = [0u8; FRAME];
                        a_rx.read_exact(&mut f).await.map(|_| f)
                    } => {
                        match r {
                            Ok(f) => got.extend_from_slice(&f),
                            // An early eof here is the loss itself: the first
                            // three bytes went into the dropped buffer, so the
                            // source runs out before a whole frame arrives.
                            Err(e) => return Err(e),
                        }
                    }
                    _ = b_rx.read(&mut bbuf) => {}
                }
            }
            Ok(())
        })
        .await;

        let intact = matches!(outcome, Ok(Ok(()))) && got == vec![1, 2, 3, 4, 5, 6, 7, 8];
        assert!(
            !intact,
            "read_exact as a select branch delivered the frame intact, so the \
             cancellation loss this guard exists for was not reproduced here"
        );
    }

    /// The fix, exercised through FrameReader itself, which is the exact type
    /// the relay and the client use in production. Same controlled timing as
    /// the control test above: partial bytes on A, the other branch wins, the
    /// rest arrives, and the frame must come through intact.
    #[tokio::test]
    async fn frame_reader_in_select_keeps_partial_bytes() {
        let (a_tx, a_rx) = tokio::io::duplex(64);
        let (b_tx, mut b_rx) = tokio::io::duplex(64);
        tokio::spawn(feed(a_tx, b_tx));

        let mut reader = super::FrameReader::new(a_rx, FRAME);
        let mut bbuf = [0u8; 1];
        let frame = tokio::time::timeout(Duration::from_millis(600), async {
            loop {
                tokio::select! {
                    biased;
                    r = reader.next_frame() => {
                        return r.expect("FrameReader must assemble the frame");
                    }
                    _ = b_rx.read(&mut bbuf) => {}
                }
            }
        })
        .await
        .expect("FrameReader should assemble the frame within the deadline");

        assert_eq!(frame, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    /// A read must never reach past the end of the frame being assembled.
    ///
    /// With a partial frame buffered, a read sized to the whole scratch buffer
    /// can take the rest of the frame plus the bytes that follow it. Those
    /// trailing bytes then live inside the reader, and anything that drops the
    /// reader drops them. On a multiplexed link the bytes after a frame are the
    /// start of another circuit's frame.
    #[tokio::test]
    async fn next_frame_never_reads_past_the_frame_it_returns() {
        let (mut tx, rx) = tokio::io::duplex(1024);

        // Three bytes of the frame are available before the first read, so the
        // reader buffers a partial frame without needing a cancellation.
        tx.write_all(&[1, 2, 3]).await.unwrap();
        tx.flush().await.unwrap();
        let mut reader = super::FrameReader::new(rx, FRAME);

        // The remaining five bytes and three trailing bytes arrive together, so
        // one read has more available than the frame needs.
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            tx.write_all(&[4, 5, 6, 7, 8, 0xAA, 0xBB, 0xCC])
                .await
                .unwrap();
            tx.flush().await.unwrap();
            // Hold the stream open while the test reads the trailing bytes.
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        let frame = reader.next_frame().await.expect("frame");
        assert_eq!(frame, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            reader.pending(),
            0,
            "the reader swallowed {} bytes that belong after the frame",
            reader.pending()
        );

        // The trailing bytes must still be in the stream, not inside the reader.
        let mut inner = reader.into_inner();
        let mut trailing = [0u8; 3];
        inner
            .read_exact(&mut trailing)
            .await
            .expect("the bytes after the frame must still be readable");
        assert_eq!(trailing, [0xAA, 0xBB, 0xCC]);
        writer.abort();
    }

    /// A cancelled `next_frame` retains the partial frame, and `pending`
    /// reports it. This is the predicate the relay checks before handing a
    /// stream back to the pool: those bytes belong to the circuit that is
    /// closing, and pooling the stream would surface them as a corrupt frame
    /// for whichever circuit picks it up next.
    #[tokio::test]
    async fn cancelled_next_frame_retains_the_partial_and_reports_it() {
        let (mut a_tx, a_rx) = tokio::io::duplex(64);
        let (mut b_tx, mut b_rx) = tokio::io::duplex(64);

        // Three bytes of a frame on A, and a byte on B so the other branch is
        // ready and wins while next_frame is still short of a frame.
        a_tx.write_all(&[1, 2, 3]).await.unwrap();
        a_tx.flush().await.unwrap();
        b_tx.write_all(&[9]).await.unwrap();
        b_tx.flush().await.unwrap();

        let mut reader = super::FrameReader::new(a_rx, FRAME);
        let mut bbuf = [0u8; 1];
        // biased is load bearing: next_frame must be polled first so it takes
        // the three bytes before the other branch wins. Unbiased, the runtime
        // may pick the other branch, nothing is read, and the assertion below
        // would hold for the wrong reason.
        tokio::select! {
            biased;
            r = reader.next_frame() => {
                panic!("a whole frame appeared from three bytes: {r:?}");
            }
            _ = b_rx.read(&mut bbuf) => {}
        }
        assert_eq!(
            reader.pending(),
            3,
            "the partial frame must survive the cancelled branch"
        );
    }
}
