//! Three-hop telescoping circuit dialer + CircuitStream.

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand_core::OsRng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::{lookup_host, TcpStream};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use x25519_dalek::{EphemeralSecret, PublicKey};

use darkroute_crypto::cell::{
    parse_extend_backward, Cell, CellType, ConnectPayload, ExtendForward,
};
use darkroute_crypto::crypto::{
    decrypt_frame, derive_session_key, encrypt_frame, read_frame, SessionKey,
};
use darkroute_crypto::wire::{CIRCUIT_ID, PROTO_CLIENT};

use crate::circuits::CircuitRoute;
use crate::error::ClientError;
use crate::tls;

const CELL_CHUNK: usize = 16 * 1024;
const DUPLEX_BUF: usize = 64 * 1024;

pub struct CircuitStream {
    inner: tokio::io::DuplexStream,
}

pub async fn dial(
    connector: &TlsConnector,
    route: &CircuitRoute,
    m_raw: &[u8; 32],
    token: &[u8],
    dest_host: &str,
    dest_port: u16,
) -> Result<CircuitStream, ClientError> {
    let (guard_host, guard_port) = route.guard.split()?;
    let (middle_host, middle_port) = route.middle.split()?;
    let (exit_host, exit_port) = route.exit.split()?;

    let guard_addr = resolve_one(&guard_host, guard_port).await?;
    let middle_addr = resolve_one(&middle_host, middle_port).await?;
    let exit_addr = resolve_one(&exit_host, exit_port).await?;

    let mut tls = tls::dial(connector, guard_addr, &guard_host).await?;

    tls.write_all(&[PROTO_CLIENT]).await?;
    tls.write_all(m_raw).await?;
    tls.write_all(token).await?;

    let client_secret_guard = EphemeralSecret::random_from_rng(OsRng);
    let client_pk_guard = PublicKey::from(&client_secret_guard);
    tls.write_all(client_pk_guard.as_bytes()).await?;
    tls.flush().await?;
    let mut guard_pk_bytes = [0u8; 32];
    tls.read_exact(&mut guard_pk_bytes).await?;
    let k_guard = derive_session_key(
        client_secret_guard
            .diffie_hellman(&PublicKey::from(guard_pk_bytes))
            .as_bytes(),
    );

    let k_middle = extend_hop(&mut tls, &k_guard, &[], middle_addr).await?;
    let k_exit = extend_hop(
        &mut tls,
        &k_guard,
        std::slice::from_ref(&k_middle),
        exit_addr,
    )
    .await?;

    let inner_layers = [k_middle.clone(), k_exit.clone()];
    send_layered(
        &mut tls,
        &k_guard,
        &inner_layers,
        Cell::new(
            CellType::Connect,
            CIRCUIT_ID,
            ConnectPayload {
                host: dest_host.to_string(),
                port: dest_port,
            }
            .encode(),
        )?,
    )
    .await?;

    let (user_side, internal_side) = tokio::io::duplex(DUPLEX_BUF);
    let (tls_read, tls_write) = tokio::io::split(tls);
    let (internal_read, internal_write) = tokio::io::split(internal_side);
    let layers = vec![k_guard, k_middle, k_exit];

    tokio::spawn(writer_task(internal_read, tls_write, layers.clone()));
    tokio::spawn(reader_task(tls_read, internal_write, layers));

    Ok(CircuitStream { inner: user_side })
}

async fn resolve_one(host: &str, port: u16) -> Result<SocketAddr, ClientError> {
    lookup_host((host, port)).await?.next().ok_or_else(|| {
        ClientError::InvalidEndpoint(format!("{host}:{port}"), "no DNS records".into())
    })
}

async fn extend_hop(
    tls: &mut TlsStream<TcpStream>,
    k_guard: &SessionKey,
    inner_layers: &[SessionKey],
    next_hop: SocketAddr,
) -> Result<SessionKey, ClientError> {
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_pk = PublicKey::from(&client_secret);
    let extend = ExtendForward {
        next_hop,
        client_pk: *client_pk.as_bytes(),
    };
    let inner_cell = Cell::new(CellType::Extend, CIRCUIT_ID, extend.encode())?;
    send_layered(tls, k_guard, inner_layers, inner_cell).await?;

    let back_plain = read_frame(tls, k_guard).await?;
    let mut back_cell = Cell::decode(&back_plain)?;
    for layer in inner_layers {
        if back_cell.cell_type != CellType::Relay {
            return Err(ClientError::UnexpectedCell(back_cell.cell_type));
        }
        let inner = decrypt_frame(layer, &back_cell.payload)?;
        back_cell = Cell::decode(&inner)?;
    }
    if back_cell.cell_type != CellType::Extend {
        return Err(ClientError::UnexpectedCell(back_cell.cell_type));
    }
    let peer_pk = parse_extend_backward(&back_cell.payload)?;
    Ok(derive_session_key(
        client_secret
            .diffie_hellman(&PublicKey::from(peer_pk))
            .as_bytes(),
    ))
}

async fn send_layered(
    tls: &mut TlsStream<TcpStream>,
    k_guard: &SessionKey,
    inner_layers: &[SessionKey],
    inner_cell: Cell,
) -> Result<(), ClientError> {
    let frame = layer_encrypt(k_guard, inner_layers, &inner_cell.encode())?;
    tls.write_all(&frame).await?;
    tls.flush().await?;
    Ok(())
}

fn layer_encrypt(
    k_guard: &SessionKey,
    inner_layers: &[SessionKey],
    inner_plain: &[u8],
) -> Result<Vec<u8>, ClientError> {
    let mut payload = inner_plain.to_vec();
    if let Some(innermost) = inner_layers.last() {
        payload = encrypt_frame(innermost, &payload)?;
        for layer in inner_layers.iter().rev().skip(1) {
            let wrap = Cell::new(CellType::Relay, CIRCUIT_ID, payload)?;
            payload = encrypt_frame(layer, &wrap.encode())?;
        }
        let wrap = Cell::new(CellType::Relay, CIRCUIT_ID, payload)?;
        payload = wrap.encode();
    }
    Ok(encrypt_frame(k_guard, &payload)?)
}

async fn writer_task(
    mut from_user: ReadHalf<tokio::io::DuplexStream>,
    mut tls_write: WriteHalf<TlsStream<TcpStream>>,
    layers: Vec<SessionKey>,
) {
    let mut buf = vec![0u8; CELL_CHUNK];
    let k_guard = &layers[0];
    let inner_layers = &layers[1..];
    loop {
        let n = match from_user.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        let cell = match Cell::new(CellType::Data, CIRCUIT_ID, buf[..n].to_vec()) {
            Ok(c) => c,
            Err(_) => break,
        };
        let frame = match layer_encrypt(k_guard, inner_layers, &cell.encode()) {
            Ok(f) => f,
            Err(_) => break,
        };
        if tls_write.write_all(&frame).await.is_err() {
            break;
        }
        if tls_write.flush().await.is_err() {
            break;
        }
    }
    let _ = tls_write.shutdown().await;
}

async fn reader_task(
    mut tls_read: ReadHalf<TlsStream<TcpStream>>,
    mut to_user: WriteHalf<tokio::io::DuplexStream>,
    layers: Vec<SessionKey>,
) {
    let k_guard = &layers[0];
    let inner_layers = &layers[1..];
    loop {
        let plain = match read_frame(&mut tls_read, k_guard).await {
            Ok(p) => p,
            Err(_) => break,
        };
        let mut cell = match Cell::decode(&plain) {
            Ok(c) => c,
            Err(_) => break,
        };
        let mut peel_ok = true;
        for layer in inner_layers {
            if cell.cell_type != CellType::Relay {
                peel_ok = false;
                break;
            }
            let inner = match decrypt_frame(layer, &cell.payload) {
                Ok(p) => p,
                Err(_) => {
                    peel_ok = false;
                    break;
                }
            };
            cell = match Cell::decode(&inner) {
                Ok(c) => c,
                Err(_) => {
                    peel_ok = false;
                    break;
                }
            };
        }
        if !peel_ok {
            break;
        }
        match cell.cell_type {
            CellType::Data => {
                if to_user.write_all(&cell.payload).await.is_err() {
                    break;
                }
            }
            _ => break,
        }
    }
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
