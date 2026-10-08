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
    link_cell_len, parse_extend_backward, Cell, CellType, ConnectPayload, ExtendForward,
    CELL_PAYLOAD_LEN,
};
use quiethop_crypto::layer::{peel, seal_forward, seal_to_me, FrameReader, Peeled};
use quiethop_crypto::noise::{Initiator, Transport, NOISE_MSG_LEN};
use quiethop_crypto::wire::PROTO_CLIENT;

use crate::error::ClientError;
use crate::path::SelectedPath;
use crate::tls;
use quiethop_crypto::registry::RelayEntry;

/// The client-guard link carries one layer per hop.
const CLIENT_LAYERS: usize = 3;

/// Read from the user in whole cells. Each cell carries at most
/// CELL_PAYLOAD_LEN bytes, so a larger write is split across cells.
const USER_READ_BUF: usize = CELL_PAYLOAD_LEN * 32;

const DUPLEX_BUF: usize = 64 * 1024;

pub struct CircuitStream {
    inner: tokio::io::DuplexStream,
}

/// The three per-hop transports, outermost first.
struct Layers {
    guard: Transport,
    middle: Transport,
    exit: Transport,
}

impl Layers {
    /// Seal a cell for the exit and wrap it for the middle and the guard.
    fn seal_for_exit(&mut self, cell: &Cell) -> Result<Vec<u8>, ClientError> {
        let inner = seal_to_me(&mut self.exit, cell, 1)?;
        let mid = seal_forward(&mut self.middle, &inner, CLIENT_LAYERS - 1)?;
        Ok(seal_forward(&mut self.guard, &mid, CLIENT_LAYERS)?)
    }

    /// Peel every layer off an inbound frame until a cell appears.
    fn peel_inbound(&mut self, wire: &[u8]) -> Result<Cell, ClientError> {
        let mut blob = match peel(&mut self.guard, wire, CLIENT_LAYERS)? {
            Peeled::ToMe(cell) => return Ok(cell),
            Peeled::Forward(b) => b,
        };
        blob = match peel(&mut self.middle, &blob, CLIENT_LAYERS - 1)? {
            Peeled::ToMe(cell) => return Ok(cell),
            Peeled::Forward(b) => b,
        };
        match peel(&mut self.exit, &blob, 1)? {
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

    tls.write_all(&[PROTO_CLIENT]).await?;
    tls.write_all(m_raw).await?;
    tls.write_all(token).await?;

    // Hop 1: the guard, directly on this connection.
    let (init, msg1) = Initiator::start(&guard_key)?;
    tls.write_all(&msg1).await?;
    tls.flush().await?;
    let mut msg2 = [0u8; NOISE_MSG_LEN];
    tls.read_exact(&mut msg2).await?;
    let guard_tx = init.finish(&msg2)?;

    let mut guard_tx = guard_tx;
    // Hop 2: the middle, acted on by the guard.
    let mut middle_tx = extend_hop(&mut tls, &mut guard_tx, None, &route.middle).await?;
    // Hop 3: the exit, acted on by the middle.
    let exit_tx = extend_hop(&mut tls, &mut guard_tx, Some(&mut middle_tx), &route.exit).await?;

    let mut layers = Layers {
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
    let wire = layers.seal_for_exit(&cell)?;
    tls.write_all(&wire).await?;
    tls.flush().await?;

    let (user_side, internal_side) = tokio::io::duplex(DUPLEX_BUF);
    tokio::spawn(circuit_task(tls, layers, internal_side));
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
            let inner = seal_to_me(mid, &cell, CLIENT_LAYERS - 1)?;
            (seal_forward(guard, &inner, CLIENT_LAYERS)?, Some(mid))
        }
    };
    tls.write_all(&wire).await?;
    tls.flush().await?;

    let mut back = vec![0u8; link_cell_len(CLIENT_LAYERS)];
    tls.read_exact(&mut back).await?;

    let reply = match (peel(guard, &back, CLIENT_LAYERS)?, middle) {
        (Peeled::ToMe(c), None) => c,
        (Peeled::Forward(blob), Some(mid)) => match peel(mid, &blob, CLIENT_LAYERS - 1)? {
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
    mut layers: Layers,
    internal: tokio::io::DuplexStream,
) {
    let (tls_read, mut tls_write) = tokio::io::split(tls);
    let (mut from_user, mut to_user) = tokio::io::split(internal);
    // Cancel safe: FrameReader keeps any partial frame when the user-write
    // branch wins the race. read_exact would drop those bytes and leave every
    // later read starting mid-cell.
    let mut inbound = FrameReader::new(tls_read, link_cell_len(CLIENT_LAYERS));
    let mut user_buf = vec![0u8; USER_READ_BUF];

    loop {
        tokio::select! {
            res = from_user.read(&mut user_buf) => {
                let n = match res {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                // Split anything larger than one payload across cells. Order
                // is guaranteed by the Noise counter, so no sequence number
                // and no reassembly buffer is needed.
                let mut failed = false;
                for chunk in user_buf[..n].chunks(CELL_PAYLOAD_LEN) {
                    let cell = match Cell::new(CellType::Data, chunk.to_vec()) {
                        Ok(c) => c,
                        Err(_) => { failed = true; break; }
                    };
                    let wire = match layers.seal_for_exit(&cell) {
                        Ok(w) => w,
                        Err(_) => { failed = true; break; }
                    };
                    if tls_write.write_all(&wire).await.is_err() {
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
                let cell = match layers.peel_inbound(&frame) {
                    Ok(c) => c,
                    // Any authentication failure tears the circuit down.
                    Err(_) => break,
                };
                match cell.cell_type {
                    CellType::Data => {
                        // A zero-length DATA cell is legal and is a no-op.
                        if cell.payload.is_empty() {
                            continue;
                        }
                        if to_user.write_all(&cell.payload).await.is_err() {
                            break;
                        }
                    }
                    CellType::CloseAck => break,
                    _ => break,
                }
            }
        }
    }

    // Best effort teardown: ask the exit to close, then drop everything.
    if let Ok(cell) = Cell::new(CellType::CloseRequest, Vec::new()) {
        if let Ok(wire) = layers.seal_for_exit(&cell) {
            let _ = tls_write.write_all(&wire).await;
            let _ = tls_write.flush().await;
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
