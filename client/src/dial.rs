//! Three-hop telescoping circuit dialer and CircuitStream.
//!
//! One Noise NK handshake per hop, against the static public key the authority
//! published for that hop, so each hop proves it holds the key the registry
//! names (SECURITY_MODEL §6.1).
//!
//! No name is resolved anywhere here. Each hop arrives as an IP literal plus a
//! separate TLS name, and the literal is what gets dialed.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use quiethop_crypto::cell::{
    parse_extend_backward, Cell, CellType, ConnectPayload, ExtendForward, CELL_PAYLOAD_LEN,
};
use quiethop_crypto::circid::{self, CircId, LinkRole};
use quiethop_crypto::flow::{AfterDelivery, FlowError, Windows};
use quiethop_crypto::layer::{peel, seal_forward, seal_to_me, FrameReader, Peeled};
use quiethop_crypto::layers::Layers;
use quiethop_crypto::link::{self as link_frame, DestroyReason, LinkCommand};
use quiethop_crypto::noise::{Initiator, Transport, NOISE_MSG_LEN};
use quiethop_crypto::wire::PROTO_CLIENT;

use crate::error::ClientError;
use crate::path::SelectedPath;
use crate::tls;
use quiethop_crypto::registry::RelayEntry;

/// The client-guard link carries one layer per hop.
const CLIENT_LAYERS: Layers = Layers::new(3);

/// Size of every frame on the client-guard link, both directions.
const LINK_FRAME_LEN: usize = link_frame::link_frame_len(CLIENT_LAYERS);

/// Decode one inbound link frame and hand back the sealed cell in its body.
///
/// A frame naming another circuit cannot be meant for this one, and the client
/// opens a single circuit per link, so it is a protocol violation rather than
/// something to skip. DESTROY is the relay ending the circuit.
fn inbound_body(wire: &[u8], circ_id: CircId) -> Result<&[u8], ClientError> {
    let frame = link_frame::decode(wire, CLIENT_LAYERS, LinkRole::Responder)?;
    if frame.circ_id != circ_id {
        return Err(ClientError::ForeignCircuit(frame.circ_id.raw()));
    }
    match frame.command {
        LinkCommand::Data => Ok(frame.body),
        LinkCommand::Destroy => Err(ClientError::CircuitDestroyed),
        other => Err(ClientError::UnexpectedLinkCommand(other)),
    }
}

/// Read from the user in whole cells. Each cell carries at most
/// CELL_PAYLOAD_LEN bytes, so a larger write is split across cells.
///
/// Never read more than the package window can carry: a read is sized by what
/// the user wrote, not by the window, so reading 32 cells with room for three
/// would mean either dropping data or sending past the window.
const USER_READ_BUF: usize = CELL_PAYLOAD_LEN * 32;

/// The DESTROY reason a flow-control violation names.
///
/// Exhaustive on purpose, so a new `FlowError` fails to compile here rather
/// than inheriting a reason that may not fit it. It has to agree with
/// `destroy_reason_for` on the relay side, and the two are separate only until
/// the shared link code moves into its own crate (docs/DECISIONS.md entry 37).
fn destroy_reason_for(err: &FlowError) -> DestroyReason {
    match err {
        FlowError::PackageWindowExhausted
        | FlowError::DeliverWindowNegative(_)
        | FlowError::UnexpectedSendme(_) => DestroyReason::Protocol,
    }
}

const DUPLEX_BUF: usize = 64 * 1024;

pub struct CircuitStream {
    inner: tokio::io::DuplexStream,
}

/// The three per-hop transports, outermost first.
struct Hops {
    guard: Transport,
    middle: Transport,
    exit: Transport,
}

impl Hops {
    /// Seal a cell for the exit and wrap it for the middle and the guard.
    fn seal_for_exit(&mut self, cell: &Cell) -> Result<Vec<u8>, ClientError> {
        let inner = seal_to_me(&mut self.exit, cell, Layers::new(1))?;
        let mid = seal_forward(&mut self.middle, &inner, CLIENT_LAYERS.peeled())?;
        Ok(seal_forward(&mut self.guard, &mid, CLIENT_LAYERS)?)
    }

    /// Peel every layer off an inbound frame until a cell appears.
    fn peel_inbound(&mut self, wire: &[u8]) -> Result<Cell, ClientError> {
        let mut blob = match peel(&mut self.guard, wire, CLIENT_LAYERS)? {
            Peeled::ToMe(cell) => return Ok(cell),
            Peeled::Forward(b) => b,
        };
        blob = match peel(&mut self.middle, &blob, CLIENT_LAYERS.peeled())? {
            Peeled::ToMe(cell) => return Ok(cell),
            Peeled::Forward(b) => b,
        };
        match peel(&mut self.exit, &blob, Layers::new(1))? {
            Peeled::ToMe(cell) => Ok(cell),
            Peeled::Forward(_) => Err(ClientError::UnexpectedCell(CellType::Data)),
        }
    }
}

pub async fn dial(
    connector: &TlsConnector,
    route: &SelectedPath,
    m_raw: &[u8; 32],
    token: &[u8],
    dest_host: &str,
    dest_port: u16,
) -> Result<CircuitStream, ClientError> {
    let guard_addr = route.guard.addr()?;
    let guard_key = route.guard.static_key()?;

    let mut tls = tls::dial(connector, guard_addr, &route.guard.tls_name).await?;

    // This side opened the link, so the id comes from the initiator half. The
    // link is new and carries one circuit, so nothing is in use yet.
    let circ_id = circid::allocate(&mut rand::rngs::OsRng, LinkRole::Initiator, |_| false)?;

    tls.write_all(&[PROTO_CLIENT]).await?;

    // Hop 1: the guard, directly on this connection. The token is presented in
    // the CREATE rather than once per connection, so one token buys one
    // circuit rather than a link's worth (SECURITY_MODEL 5.10).
    let (init, msg1) = Initiator::start(&guard_key)?;
    let mut create = Vec::with_capacity(link_frame::CREATE_CLIENT_BODY_LEN);
    create.extend_from_slice(m_raw);
    create.extend_from_slice(token);
    create.extend_from_slice(&msg1);
    let frame = link_frame::encode(CLIENT_LAYERS, circ_id, LinkCommand::Create, &create)?;
    tls.write_all(&frame).await?;
    tls.flush().await?;

    let mut back = vec![0u8; LINK_FRAME_LEN];
    tls.read_exact(&mut back).await?;
    let created = link_frame::decode(&back, CLIENT_LAYERS, LinkRole::Responder)?;
    if created.circ_id != circ_id {
        return Err(ClientError::ForeignCircuit(created.circ_id.raw()));
    }
    if created.command != LinkCommand::Created {
        return Err(ClientError::UnexpectedLinkCommand(created.command));
    }
    let mut msg2 = [0u8; NOISE_MSG_LEN];
    msg2.copy_from_slice(link_frame::payload(created.body, NOISE_MSG_LEN)?);
    let mut guard_tx = init.finish(&msg2)?;

    // Hop 2: the middle, acted on by the guard.
    let mut middle_tx = extend_hop(&mut tls, &mut guard_tx, None, &route.middle, circ_id).await?;
    // Hop 3: the exit, acted on by the middle.
    let exit_tx = extend_hop(
        &mut tls,
        &mut guard_tx,
        Some(&mut middle_tx),
        &route.exit,
        circ_id,
    )
    .await?;

    let mut hops = Hops {
        guard: guard_tx,
        middle: middle_tx,
        exit: exit_tx,
    };

    // CONNECT, sealed for the exit.
    let connect = ConnectPayload {
        host: dest_host.to_string(),
        port: dest_port,
    };
    let cell = Cell::new(CellType::Connect, connect.encode()?)?;
    let wire = hops.seal_for_exit(&cell)?;
    let frame = link_frame::encode(CLIENT_LAYERS, circ_id, LinkCommand::Data, &wire)?;
    tls.write_all(&frame).await?;
    tls.flush().await?;

    let (user_side, internal_side) = tokio::io::duplex(DUPLEX_BUF);
    tokio::spawn(circuit_task(tls, hops, internal_side, circ_id));
    Ok(CircuitStream { inner: user_side })
}

/// Extend the circuit by one hop.
///
/// `middle` is None while the guard is the deepest hop, in which case the guard
/// acts on the EXTEND. Once the middle exists it is the one that acts, and the
/// cell is wrapped for the guard to forward.
async fn extend_hop(
    tls: &mut TlsStream<TcpStream>,
    guard: &mut Transport,
    middle: Option<&mut Transport>,
    next: &RelayEntry,
    circ_id: CircId,
) -> Result<Transport, ClientError> {
    let (init, msg1) = Initiator::start(&next.static_key()?)?;
    let extend = ExtendForward {
        next_hop: next.addr()?,
        noise_msg1: msg1,
    };
    let cell = Cell::new(CellType::Extend, extend.encode())?;

    let (wire, middle) = match middle {
        None => (seal_to_me(guard, &cell, CLIENT_LAYERS)?, None),
        Some(mid) => {
            let inner = seal_to_me(mid, &cell, CLIENT_LAYERS.peeled())?;
            (seal_forward(guard, &inner, CLIENT_LAYERS)?, Some(mid))
        }
    };
    let frame = link_frame::encode(CLIENT_LAYERS, circ_id, LinkCommand::Data, &wire)?;
    tls.write_all(&frame).await?;
    tls.flush().await?;

    let mut back = vec![0u8; LINK_FRAME_LEN];
    tls.read_exact(&mut back).await?;
    let body = inbound_body(&back, circ_id)?;

    let reply = match (peel(guard, body, CLIENT_LAYERS)?, middle) {
        (Peeled::ToMe(c), None) => c,
        (Peeled::Forward(blob), Some(mid)) => match peel(mid, &blob, CLIENT_LAYERS.peeled())? {
            Peeled::ToMe(c) => c,
            Peeled::Forward(_) => return Err(ClientError::UnexpectedCell(CellType::Extend)),
        },
        (Peeled::ToMe(c), Some(_)) => return Err(ClientError::UnexpectedCell(c.cell_type)),
        (Peeled::Forward(_), None) => return Err(ClientError::UnexpectedCell(CellType::Extend)),
    };
    if reply.cell_type != CellType::Extend {
        return Err(ClientError::UnexpectedCell(reply.cell_type));
    }
    let msg2 = parse_extend_backward(&reply.payload)?;
    Ok(init.finish(&msg2)?)
}

/// Owns the three transports and both halves of the TLS stream.
///
/// A single task rather than a writer plus a reader: one Noise transport
/// carries both directions and needs mutable access for each, so splitting the
/// work across tasks would mean sharing it behind a lock for no gain.
async fn circuit_task(
    tls: TlsStream<TcpStream>,
    mut hops: Hops,
    internal: tokio::io::DuplexStream,
    circ_id: CircId,
) {
    let (tls_read, mut tls_write) = tokio::io::split(tls);
    let (mut from_user, mut to_user) = tokio::io::split(internal);
    // Cancel safe: FrameReader keeps any partial frame when the user-write
    // branch wins the race. read_exact would drop those bytes and leave every
    // later read starting mid-cell.
    let mut inbound = FrameReader::new(tls_read, LINK_FRAME_LEN);
    let mut user_buf = vec![0u8; USER_READ_BUF];
    // One pair of windows per circuit, the same module the exit uses, so the
    // two ends cannot drift into two rules (SECURITY_MODEL 6.4).
    let mut windows = Windows::new();
    // Set when this side ends the circuit for a flow-control violation, so the
    // teardown below names it to the guard instead of closing quietly.
    let mut violation: Option<DestroyReason> = None;

    loop {
        // Read at most what the window can carry, and nothing at all once it is
        // empty: the window is the backpressure, so a user that writes faster
        // than the exit acknowledges waits in its own socket rather than here.
        let room = windows.package().max(0) as usize * CELL_PAYLOAD_LEN;
        let room = room.min(USER_READ_BUF);

        tokio::select! {
            res = async {
                if room == 0 {
                    std::future::pending().await
                } else {
                    from_user.read(&mut user_buf[..room]).await
                }
            } => {
                let n = match res {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                // Split anything larger than one payload across cells. Order
                // is guaranteed by the Noise counter, so no sequence number
                // and no reassembly buffer is needed.
                let mut failed = false;
                for chunk in user_buf[..n].chunks(CELL_PAYLOAD_LEN) {
                    // Cannot fail: the read above was capped at the window, so
                    // there is room for every chunk it produced.
                    if let Err(e) = windows.on_data_sent() {
                        violation = Some(destroy_reason_for(&e));
                        failed = true;
                        break;
                    }
                    let cell = match Cell::new(CellType::Data, chunk.to_vec()) {
                        Ok(c) => c,
                        Err(_) => { failed = true; break; }
                    };
                    let wire = match hops.seal_for_exit(&cell) {
                        Ok(w) => w,
                        Err(_) => { failed = true; break; }
                    };
                    let framed =
                        match link_frame::encode(CLIENT_LAYERS, circ_id, LinkCommand::Data, &wire) {
                            Ok(f) => f,
                            Err(_) => { failed = true; break; }
                        };
                    if tls_write.write_all(&framed).await.is_err() {
                        failed = true;
                        break;
                    }
                }
                if failed || tls_write.flush().await.is_err() {
                    break;
                }
            }

            res = inbound.next_frame() => {
                let frame = match res {
                    Ok(f) => f,
                    Err(_) => break,
                };
                // A foreign id, a DESTROY or an authentication failure all
                // tear the circuit down.
                let Ok(body) = inbound_body(&frame, circ_id) else {
                    break;
                };
                let cell = match hops.peel_inbound(body) {
                    Ok(c) => c,
                    Err(_) => break,
                };
                match cell.cell_type {
                    CellType::Data => {
                        // Accounted before the write, as the exit does, so the
                        // SENDME is owed on delivery rather than on the user
                        // having taken the bytes.
                        let owed = match windows.on_data_delivered() {
                            Ok(o) => o,
                            Err(e) => {
                                violation = Some(destroy_reason_for(&e));
                                break;
                            }
                        };
                        if owed == AfterDelivery::SendmeOwed {
                            let Ok(sendme) = Cell::new(CellType::Sendme, Vec::new()) else {
                                break;
                            };
                            let Ok(wire) = hops.seal_for_exit(&sendme) else {
                                break;
                            };
                            let Ok(frame) = link_frame::encode(
                                CLIENT_LAYERS,
                                circ_id,
                                LinkCommand::Data,
                                &wire,
                            ) else {
                                break;
                            };
                            if tls_write.write_all(&frame).await.is_err()
                                || tls_write.flush().await.is_err()
                            {
                                break;
                            }
                            // Credit on send, never on delivery: a consumer that
                            // stops reading stops granting credit, which is the
                            // whole point of the window.
                            windows.on_sendme_sent();
                        }
                        // A zero-length DATA cell is legal and is a no-op. It
                        // still counts against the window above.
                        if cell.payload.is_empty() {
                            continue;
                        }
                        if to_user.write_all(&cell.payload).await.is_err() {
                            break;
                        }
                    }
                    CellType::Sendme => {
                        // A SENDME this side did not owe is a violation rather
                        // than something to absorb: crediting it would take the
                        // package window past its start (SECURITY_MODEL 6.4).
                        if let Err(e) = windows.on_sendme_received() {
                            violation = Some(destroy_reason_for(&e));
                            break;
                        }
                    }
                    CellType::CloseAck => break,
                    _ => break,
                }
            }
        }
    }

    // A flow-control violation is named to the guard, which releases the
    // circuit and tells the hops beyond it. Anything else is an ordinary close.
    if let Some(reason) = violation {
        if let Ok(frame) = link_frame::encode(
            CLIENT_LAYERS,
            circ_id,
            LinkCommand::Destroy,
            &[reason as u8],
        ) {
            let _ = tls_write.write_all(&frame).await;
            let _ = tls_write.flush().await;
        }
        let _ = tls_write.shutdown().await;
        let _ = to_user.shutdown().await;
        return;
    }

    // Best effort teardown: ask the exit to close, then drop everything.
    if let Ok(cell) = Cell::new(CellType::CloseRequest, Vec::new()) {
        if let Ok(wire) = hops.seal_for_exit(&cell) {
            if let Ok(frame) = link_frame::encode(CLIENT_LAYERS, circ_id, LinkCommand::Data, &wire)
            {
                let _ = tls_write.write_all(&frame).await;
                let _ = tls_write.flush().await;
            }
        }
    }
    let _ = tls_write.shutdown().await;
    let _ = to_user.shutdown().await;
}

impl AsyncRead for CircuitStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for CircuitStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
