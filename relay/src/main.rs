#![deny(warnings)]
#![forbid(unsafe_code)]

mod authority;
mod cell;
mod circuit;
mod config;
mod crypto;
mod heartbeat;
mod metrics;
mod pool;
mod token;

#[cfg(test)]
mod integration_test;

use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::sync::Notify;
use tracing::{error, info, warn};

use crate::authority::AuthorityClient;
use crate::cell::{Cell, CellType, ConnectPayload, ExtendForward};
use crate::config::{RelayConfig, Role};
use crate::pool::{ConnectionPool, PooledConn};
use crate::token::ReplayWindow;

/// Protocol byte sent as the first byte of any inbound TCP. Distinguishes
/// a client circuit setup from a relay-to-relay link. The role of this
/// relay determines which bytes are accepted: guard accepts only Client,
/// middle and exit accept only Relay.
const PROTO_CLIENT: u8 = 0x01;
const PROTO_RELAY: u8 = 0x02;

const M_RAW_LEN: usize = 32;
const TOKEN_LEN: usize = 256;
const PRESENTATION_LEN: usize = M_RAW_LEN + TOKEN_LEN;
const PRESENTATION_READ_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_secs(10);
const CELL_READ_TIMEOUT: Duration = Duration::from_secs(120);
const POOL_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
const POOL_IDLE_TTL: Duration = Duration::from_secs(300);
const X25519_PK_LEN: usize = 32;
const CIRCUIT_ID: u32 = 1;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    let cfg = match RelayConfig::from_env() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            error!(error = %e, "config validation failed");
            return ExitCode::from(1);
        }
    };
    info!(
        role = %cfg.role,
        node_id = %cfg.node_id,
        relay_port = cfg.relay_port,
        metrics_port = cfg.metrics_port,
        max_circuits = cfg.max_circuits,
        replay_window_ttl_seconds = cfg.replay_window_ttl,
        allowed_exit_ports = ?cfg.allowed_exit_ports,
        peer_allowlist_size = cfg.peer_allowlist.len(),
        "config loaded"
    );
    if cfg.role == Role::Exit {
        if let Some(redacted) = cfg.decodo_proxy_url.as_deref().map(redact_proxy_url) {
            info!(decodo_endpoint = %redacted, "exit proxy configured");
        }
    }

    let authority = match AuthorityClient::fetch_and_pin(&cfg.authority_pubkey_url).await {
        Ok(a) => Arc::new(a),
        Err(e) => {
            error!(error = %e, "failed to pin authority public key");
            return ExitCode::from(1);
        }
    };
    info!("authority public key pinned");

    let replay = Arc::new(ReplayWindow::new(Duration::from_secs(cfg.replay_window_ttl)));
    info!(ttl_seconds = cfg.replay_window_ttl, "replay window initialized");
    metrics::init();

    let outbound_pool = Arc::new(ConnectionPool::new());

    let relay_addr = format!("0.0.0.0:{}", cfg.relay_port);
    let relay_listener = match TcpListener::bind(&relay_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, addr = %relay_addr, "failed to bind relay port");
            return ExitCode::from(1);
        }
    };
    info!(addr = %relay_addr, "relay listener bound");

    let metrics_addr = format!("0.0.0.0:{}", cfg.metrics_port);
    let metrics_listener = match TcpListener::bind(&metrics_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, addr = %metrics_addr, "failed to bind metrics port");
            return ExitCode::from(1);
        }
    };
    info!(addr = %metrics_addr, "metrics listener bound");

    let heartbeat_client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "failed to build heartbeat http client");
            return ExitCode::from(1);
        }
    };

    let shutdown = Arc::new(Notify::new());
    let hb_handle = heartbeat::spawn(cfg.clone(), heartbeat_client, shutdown.clone());

    let accept_handle = tokio::spawn(accept_loop(
        relay_listener,
        shutdown.clone(),
        cfg.clone(),
        authority.clone(),
        replay.clone(),
        outbound_pool.clone(),
    ));
    let metrics_handle = tokio::spawn(metrics_accept_loop(metrics_listener, shutdown.clone()));
    let pool_sweep_handle = tokio::spawn(pool_sweep_loop(outbound_pool.clone(), shutdown.clone()));

    match signal::ctrl_c().await {
        Ok(()) => info!("shutdown signal received"),
        Err(e) => error!(error = %e, "signal listener failed"),
    }

    shutdown.notify_waiters();
    let _ = hb_handle.await;
    let _ = accept_handle.await;
    let _ = metrics_handle.await;
    let _ = pool_sweep_handle.await;
    info!("shutdown complete");
    ExitCode::SUCCESS
}

fn redact_proxy_url(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(u) => {
            let host = u.host_str().unwrap_or("");
            match u.port() {
                Some(p) => format!("{}://{}:{}", u.scheme(), host, p),
                None => format!("{}://{}", u.scheme(), host),
            }
        }
        Err(_) => "<unparseable>".to_string(),
    }
}

async fn accept_loop(
    listener: TcpListener,
    shutdown: Arc<Notify>,
    cfg: Arc<RelayConfig>,
    authority: Arc<AuthorityClient>,
    replay: Arc<ReplayWindow>,
    pool: Arc<ConnectionPool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                info!("relay accept loop shutting down");
                return;
            }
            res = listener.accept() => match res {
                Ok((sock, peer)) => {
                    let cfg = cfg.clone();
                    let auth = authority.clone();
                    let rep = replay.clone();
                    let pl = pool.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(sock, peer, cfg, auth, rep, pl).await {
                            warn!(peer = %peer, reason = %e, "connection rejected");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "accept failed");
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum HandleError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("read timeout")]
    Timeout,
    #[error("token verification failed: {0}")]
    Token(token::TokenError),
    #[error("crypto: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("circuit: {0}")]
    Circuit(#[from] circuit::CircuitError),
    #[error("cell: {0}")]
    Cell(#[from] cell::CellError),
    #[error("unexpected protocol byte 0x{0:02x}")]
    UnexpectedProtocol(u8),
    #[error("peer IP not in relay allowlist")]
    PeerNotAllowed,
    #[error("cell type {0:?} not legal for role {1}")]
    IllegalCellForRole(CellType, Role),
    #[error("circuit teardown by peer")]
    PeerClosed,
}

async fn handle_connection(
    mut sock: TcpStream,
    peer: SocketAddr,
    cfg: Arc<RelayConfig>,
    authority: Arc<AuthorityClient>,
    replay: Arc<ReplayWindow>,
    pool: Arc<ConnectionPool>,
) -> Result<(), HandleError> {
    sock.set_nodelay(true)?;

    let mut proto = [0u8; 1];
    match tokio::time::timeout(PRESENTATION_READ_TIMEOUT, sock.read_exact(&mut proto)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(HandleError::Io(e)),
        Err(_) => return Err(HandleError::Timeout),
    }

    match (proto[0], cfg.role) {
        (PROTO_CLIENT, Role::Guard) => {
            handle_client_connection(sock, peer, cfg, authority, replay, pool).await
        }
        (PROTO_RELAY, Role::Middle) | (PROTO_RELAY, Role::Exit) => {
            handle_relay_connection(sock, peer, cfg, pool).await
        }
        (b, _) => Err(HandleError::UnexpectedProtocol(b)),
    }
}

/// Phase 3 + 4a: client presents token, ECDH handshake, then the cell
/// loop on a guard relay. After accepting one EXTEND, this relay also
/// runs a backward task on the outbound link to wrap inbound frames as
/// RELAY cells back to the client.
async fn handle_client_connection(
    mut sock: TcpStream,
    peer: SocketAddr,
    _cfg: Arc<RelayConfig>,
    authority: Arc<AuthorityClient>,
    replay: Arc<ReplayWindow>,
    pool: Arc<ConnectionPool>,
) -> Result<(), HandleError> {
    let mut buf = [0u8; PRESENTATION_LEN];
    match tokio::time::timeout(PRESENTATION_READ_TIMEOUT, sock.read_exact(&mut buf)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(HandleError::Io(e)),
        Err(_) => return Err(HandleError::Timeout),
    }
    let m_raw = &buf[..M_RAW_LEN];
    let token = &buf[M_RAW_LEN..];
    if let Err(e) = token::verify(m_raw, token, authority.pubkey(), &replay) {
        metrics::record_rejected(&e);
        return Err(HandleError::Token(e));
    }
    metrics::record_verified();

    drive_cell_loop(sock, peer, Role::Guard, pool).await
}

/// Relay-mode inbound (middle or exit). Peer IP must be in the
/// configured allowlist; once accepted, the link performs the ECDH
/// handshake and enters the cell loop with role-specific dispatch.
async fn handle_relay_connection(
    sock: TcpStream,
    peer: SocketAddr,
    cfg: Arc<RelayConfig>,
    pool: Arc<ConnectionPool>,
) -> Result<(), HandleError> {
    let peer_ip = match peer {
        SocketAddr::V4(a) => IpAddr::V4(*a.ip()),
        SocketAddr::V6(a) => IpAddr::V6(*a.ip()),
    };
    if !cfg.peer_allowlist.contains(&peer_ip) {
        return Err(HandleError::PeerNotAllowed);
    }
    drive_cell_loop(sock, peer, cfg.role, pool).await
}

/// Shared cell loop: ECDH handshake, activate the circuit, then
/// dispatch incoming cells until CLOSE_REQUEST or any error.
async fn drive_cell_loop(
    mut sock: TcpStream,
    peer: SocketAddr,
    role: Role,
    pool: Arc<ConnectionPool>,
) -> Result<(), HandleError> {
    let mut circuit = circuit::Circuit::new();
    let (mut read_half, mut write_half) = sock.split();

    let session_key = match tokio::time::timeout(
        HANDSHAKE_READ_TIMEOUT,
        crypto::relay_handshake(&mut read_half, &mut write_half),
    )
    .await
    {
        Ok(Ok(k)) => k,
        Ok(Err(e)) => {
            circuit.fail();
            return Err(HandleError::Crypto(e));
        }
        Err(_) => {
            circuit.fail();
            return Err(HandleError::Timeout);
        }
    };
    if let Err(e) = circuit.activate(session_key) {
        circuit.fail();
        return Err(HandleError::Circuit(e));
    }
    info!(peer = %peer, role = %role, state = %circuit.state(), "circuit active");

    let outcome =
        run_cell_loop(&mut read_half, &mut write_half, &mut circuit, role, pool).await;

    match &outcome {
        Ok(()) => {
            if let Err(e) = circuit.close() {
                // close() is infallible from Active; if we reach this branch
                // it means state was already Closed/Failed which is benign.
                warn!(error = %e, "circuit.close from terminal state");
            }
            info!(peer = %peer, role = %role, state = %circuit.state(), "circuit closed");
        }
        Err(_) => circuit.fail(),
    }
    outcome
}

async fn run_cell_loop<R, W>(
    reader: &mut R,
    writer: &mut W,
    circuit: &mut circuit::Circuit,
    role: Role,
    pool: Arc<ConnectionPool>,
) -> Result<(), HandleError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    // Outbound link state for this circuit. Populated by EXTEND; from
    // that point on, RELAY cells write payloads here and a backward
    // task wraps inbound frames as RELAY cells for the client.
    let mut next_link: Option<NextLink> = None;

    loop {
        let key = circuit.session_key().expect(
            "drive_cell_loop only enters run_cell_loop after activate, \
             so session_key() returns Some for the entire loop",
        );
        let frame = match tokio::time::timeout(
            CELL_READ_TIMEOUT,
            crypto::read_frame(reader, key),
        )
        .await
        {
            Ok(Ok(f)) => f,
            Ok(Err(e)) => return Err(HandleError::Crypto(e)),
            Err(_) => return Err(HandleError::Timeout),
        };
        let cell = Cell::decode(&frame)?;

        match (cell.cell_type, role) {
            (CellType::Extend, Role::Guard) | (CellType::Extend, Role::Middle) => {
                if next_link.is_some() {
                    // Phase 4b: one EXTEND per circuit. A second EXTEND
                    // is a protocol error from the client.
                    return Err(HandleError::IllegalCellForRole(CellType::Extend, role));
                }
                let extend = ExtendForward::decode(&cell.payload)?;
                let nl = open_next_link(&extend, &pool).await?;
                // Reply EXTEND-backward to client with the next hop's pubkey.
                let reply = Cell::new(
                    CellType::Extend,
                    CIRCUIT_ID,
                    cell::extend_backward_payload(&nl.peer_pk),
                )?;
                crypto::write_frame(writer, key, &reply.encode()).await?;
                next_link = Some(nl);
            }
            (CellType::Relay, Role::Guard) | (CellType::Relay, Role::Middle) => {
                let nl = next_link
                    .as_mut()
                    .ok_or(HandleError::IllegalCellForRole(CellType::Relay, role))?;
                nl.stream.write_all(&cell.payload).await?;
                nl.stream.flush().await?;
                // Read one frame back from next_link and wrap it as a
                // RELAY cell for the client. This is the "backward step"
                // that pairs with this forward RELAY.
                let back_bytes = match tokio::time::timeout(
                    CELL_READ_TIMEOUT,
                    crypto::read_frame_bytes(&mut nl.stream),
                )
                .await
                {
                    Ok(Ok(b)) => b,
                    Ok(Err(e)) => return Err(HandleError::Crypto(e)),
                    Err(_) => return Err(HandleError::Timeout),
                };
                let wrap = Cell::new(CellType::Relay, CIRCUIT_ID, back_bytes)?;
                crypto::write_frame(writer, key, &wrap.encode()).await?;
            }
            (CellType::Connect, Role::Exit) => {
                let payload = ConnectPayload::decode(&cell.payload)?;
                // Phase 4c will dial via Decodo SOCKS5; in Phase 4b we
                // record the destination so the integration test can
                // assert it reached exit untouched, and so the test hook
                // (set via cfg(test)) can publish it to the test.
                info!(host = %payload.host, port = payload.port, "exit received CONNECT");
                publish_connect_for_tests(payload);
            }
            (CellType::Data, Role::Exit) => {
                // Phase 4c forwards DATA to the destination via the SOCKS5
                // proxy. In Phase 4b, DATA at the exit is recorded only.
                info!(bytes = cell.payload.len(), "exit received DATA");
            }
            (CellType::CloseRequest, _) => {
                let ack = Cell::new(CellType::CloseAck, CIRCUIT_ID, Vec::new())?;
                crypto::write_frame(writer, key, &ack.encode()).await?;
                if let Some(nl) = next_link.take() {
                    drop(nl);
                }
                return Ok(());
            }
            (CellType::CloseAck, _) => {
                // CLOSE_ACK on a forward path is unusual; treat as a peer-
                // initiated teardown and exit cleanly.
                return Err(HandleError::PeerClosed);
            }
            (t, r) => {
                return Err(HandleError::IllegalCellForRole(t, r));
            }
        }
    }
}

struct NextLink {
    stream: TcpStream,
    peer_pk: [u8; X25519_PK_LEN],
}

/// Open a fresh outbound TCP to `next_hop` via the pool. If an idle
/// connection is available we reuse it (consuming the pool's protocol-
/// handshake state implicitly — Phase 4b establishes a new handshake on
/// every dial, so the pool only hits warm-but-unhandshaked sockets in
/// practice). Otherwise dial fresh and run the relay-mode handshake.
async fn open_next_link(
    extend: &ExtendForward,
    pool: &ConnectionPool,
) -> Result<NextLink, HandleError> {
    let mut stream = match pool.acquire(&extend.next_hop) {
        Some(PooledConn { stream, .. }) => stream,
        None => TcpStream::connect(extend.next_hop).await?,
    };
    stream.set_nodelay(true)?;
    stream.write_all(&[PROTO_RELAY]).await?;
    stream.write_all(&extend.client_pk).await?;
    stream.flush().await?;
    let mut peer_pk = [0u8; X25519_PK_LEN];
    match tokio::time::timeout(HANDSHAKE_READ_TIMEOUT, stream.read_exact(&mut peer_pk)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(HandleError::Io(e)),
        Err(_) => return Err(HandleError::Timeout),
    }
    Ok(NextLink { stream, peer_pk })
}

/// Test-only sink: when the exit relay receives a CONNECT cell, publish
/// the destination on a oneshot-channel-style hook so the integration
/// test can assert. Production builds compile this to a no-op.
#[cfg(test)]
fn publish_connect_for_tests(p: ConnectPayload) {
    test_hooks::publish_connect(p);
}

#[cfg(not(test))]
fn publish_connect_for_tests(_p: ConnectPayload) {}

#[cfg(test)]
mod test_hooks {
    use std::sync::Mutex;
    use std::sync::OnceLock;
    use tokio::sync::mpsc;

    use crate::cell::ConnectPayload;

    static SINK: OnceLock<Mutex<Option<mpsc::UnboundedSender<ConnectPayload>>>> = OnceLock::new();

    fn cell() -> &'static Mutex<Option<mpsc::UnboundedSender<ConnectPayload>>> {
        SINK.get_or_init(|| Mutex::new(None))
    }

    pub fn install_sender(tx: mpsc::UnboundedSender<ConnectPayload>) {
        *cell().lock().expect("test hook mutex") = Some(tx);
    }

    pub fn publish_connect(p: ConnectPayload) {
        if let Some(tx) = cell().lock().expect("test hook mutex").as_ref() {
            let _ = tx.send(p);
        }
    }
}

async fn pool_sweep_loop(pool: Arc<ConnectionPool>, shutdown: Arc<Notify>) {
    let mut ticker = tokio::time::interval(POOL_SWEEP_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                info!("pool sweep shutting down");
                return;
            }
            _ = ticker.tick() => {
                let evicted = pool.evict_older_than(POOL_IDLE_TTL);
                if evicted > 0 {
                    info!(evicted, remaining = pool.len(), "pool sweep");
                }
            }
        }
    }
}

async fn metrics_accept_loop(listener: TcpListener, shutdown: Arc<Notify>) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                info!("metrics accept loop shutting down");
                return;
            }
            res = listener.accept() => match res {
                Ok((sock, _peer)) => {
                    tokio::spawn(async move {
                        if let Err(e) = metrics::serve(sock).await {
                            warn!(error = %e, "metrics request failed");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "metrics accept failed");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_proxy_url_strips_userinfo() {
        let r = redact_proxy_url("socks5://user:pass@proxy.example.com:1080");
        assert_eq!(r, "socks5://proxy.example.com:1080");
    }

    #[test]
    fn redact_proxy_url_handles_no_port() {
        let r = redact_proxy_url("socks5://user:pass@proxy.example.com");
        assert_eq!(r, "socks5://proxy.example.com");
    }

    #[test]
    fn redact_proxy_url_handles_garbage() {
        assert_eq!(redact_proxy_url("not a url"), "<unparseable>");
    }
}
