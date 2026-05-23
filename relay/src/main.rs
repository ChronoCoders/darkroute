#![deny(warnings)]
#![forbid(unsafe_code)]

mod authority;
mod cell;
mod circuit;
mod config;
mod crypto;
mod exit;
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
use crate::crypto::SessionKey;
use crate::pool::{ConnectionPool, PooledConn};
use crate::token::ReplayWindow;

/// First byte of any inbound TCP. PROTO_CLIENT proceeds to a Phase-3
/// token presentation (guard only); PROTO_RELAY proceeds to the
/// circuit-start signal stream (middle and exit, peer-allowlisted).
const PROTO_CLIENT: u8 = 0x01;
const PROTO_RELAY: u8 = 0x02;

/// Per-circuit signal byte on a relay-to-relay link. The dialer writes
/// this before each new circuit's client pubkey; the listener reads it
/// to know whether the link is starting another circuit (`CIRCUIT_START`)
/// or shutting down (any other byte / EOF).
const CIRCUIT_START: u8 = 0xC1;

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
const DEST_READ_BUF: usize = 16 * 1024;

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

    let replay = Arc::new(ReplayWindow::new(Duration::from_secs(
        cfg.replay_window_ttl,
    )));
    info!(
        ttl_seconds = cfg.replay_window_ttl,
        "replay window initialized"
    );
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
                            warn!(peer = %peer, reason = %e, "connection terminated");
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
    #[error("exit: {0}")]
    Exit(#[from] exit::ExitError),
    #[error("unexpected protocol byte 0x{0:02x}")]
    UnexpectedProtocol(u8),
    #[error("peer IP not in relay allowlist")]
    PeerNotAllowed,
    #[error("cell type {0:?} not legal for role {1}")]
    IllegalCellForRole(CellType, Role),
    #[error("circuit teardown by peer")]
    PeerClosed,
    #[error("missing decodo proxy url at exit role")]
    MissingDecodoUrl,
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

/// Client-mode inbound on the guard role. One circuit per TCP; after
/// CLOSE_REQUEST the TCP is closed (clients reconnect for a new
/// circuit). Token verification runs first; only then does the
/// per-hop ECDH and cell loop start.
async fn handle_client_connection(
    mut sock: TcpStream,
    peer: SocketAddr,
    cfg: Arc<RelayConfig>,
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

    drive_circuit(&mut sock, peer, Role::Guard, cfg, pool).await
}

/// Relay-mode inbound (middle or exit). Peer IP must be in the
/// configured allowlist; once accepted, the link supports multiple
/// circuits in sequence, each preceded by a `CIRCUIT_START` byte. The
/// outer loop returns when the dialer either closes the TCP or sends a
/// non-CIRCUIT_START byte.
async fn handle_relay_connection(
    mut sock: TcpStream,
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

    loop {
        let mut signal = [0u8; 1];
        match sock.read_exact(&mut signal).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(HandleError::Io(e)),
        }
        if signal[0] != CIRCUIT_START {
            // Any byte other than CIRCUIT_START terminates the link.
            return Ok(());
        }
        drive_circuit(&mut sock, peer, cfg.role, cfg.clone(), pool.clone()).await?;
    }
}

/// Bring up one circuit on `sock`: run the per-hop X25519 handshake,
/// activate the state machine, run the bidirectional cell loop. On
/// CLOSE_REQUEST: send CLOSE_ACK, release the next-link to the pool
/// (if any), drop the destination link (if any), close the circuit.
async fn drive_circuit(
    sock: &mut TcpStream,
    peer: SocketAddr,
    role: Role,
    cfg: Arc<RelayConfig>,
    pool: Arc<ConnectionPool>,
) -> Result<(), HandleError> {
    let mut circuit = circuit::Circuit::new();

    let session_key = {
        let (mut read_half, mut write_half) = sock.split();
        match tokio::time::timeout(
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
        }
    };
    if let Err(e) = circuit.activate(session_key) {
        circuit.fail();
        return Err(HandleError::Circuit(e));
    }
    info!(peer = %peer, role = %role, state = %circuit.state(), "circuit active");

    let key: SessionKey = circuit
        .session_key()
        .expect(
            "drive_circuit just activated the circuit, so session_key() returns Some \
             — this invariant is enforced by the state machine",
        )
        .clone();

    let outcome = run_circuit_io(sock, &key, role, cfg, pool).await;
    match &outcome {
        Ok(()) => {
            if let Err(e) = circuit.close() {
                warn!(error = %e, "circuit.close from terminal state");
            }
            info!(peer = %peer, role = %role, state = %circuit.state(), "circuit closed");
        }
        Err(_) => circuit.fail(),
    }
    outcome
}

/// One circuit's bidirectional control + data loop. Reads from three
/// sources via `tokio::select!`:
///
///   1. `sock` (cells from the previous-hop client/relay)
///   2. `next_link.stream` (raw frame bytes from the next-hop relay,
///      forwarded as RELAY cells back toward the client)
///   3. `dest_link` (bytes from the SOCKS5 destination, wrapped as
///      DATA cells back toward the client; exit role only)
///
/// CLOSE_REQUEST triggers: send CLOSE_ACK, release next_link to the
/// pool (so the underlying TCP can carry another circuit), drop
/// dest_link, return. Any other error path drops both, terminating
/// the dialer side cleanly via TCP FIN.
async fn run_circuit_io(
    sock: &mut TcpStream,
    key: &SessionKey,
    role: Role,
    cfg: Arc<RelayConfig>,
    pool: Arc<ConnectionPool>,
) -> Result<(), HandleError> {
    let (mut sock_read, mut sock_write) = sock.split();
    let mut next_link: Option<NextLinkState> = None;
    let mut dest_link: Option<TcpStream> = None;

    loop {
        tokio::select! {
            biased;
            res = tokio::time::timeout(CELL_READ_TIMEOUT, crypto::read_frame(&mut sock_read, key)) => {
                let frame = match res {
                    Ok(Ok(f)) => f,
                    Ok(Err(e)) => return Err(HandleError::Crypto(e)),
                    Err(_) => return Err(HandleError::Timeout),
                };
                let cell = Cell::decode(&frame)?;
                match (cell.cell_type, role) {
                    (CellType::Extend, Role::Guard) | (CellType::Extend, Role::Middle) => {
                        if next_link.is_some() {
                            return Err(HandleError::IllegalCellForRole(CellType::Extend, role));
                        }
                        let extend = ExtendForward::decode(&cell.payload)?;
                        let nl = open_next_link(&extend, &pool).await?;
                        let reply = Cell::new(
                            CellType::Extend,
                            CIRCUIT_ID,
                            cell::extend_backward_payload(&nl.peer_pk),
                        )?;
                        crypto::write_frame(&mut sock_write, key, &reply.encode()).await?;
                        next_link = Some(nl);
                    }
                    (CellType::Relay, Role::Guard) | (CellType::Relay, Role::Middle) => {
                        let nl = next_link
                            .as_mut()
                            .ok_or(HandleError::IllegalCellForRole(CellType::Relay, role))?;
                        nl.stream.write_all(&cell.payload).await?;
                        nl.stream.flush().await?;
                    }
                    (CellType::Connect, Role::Exit) => {
                        if dest_link.is_some() {
                            return Err(HandleError::IllegalCellForRole(CellType::Connect, role));
                        }
                        let payload = ConnectPayload::decode(&cell.payload)?;
                        publish_connect_for_test(&payload);
                        let proxy_url = cfg
                            .decodo_proxy_url
                            .as_deref()
                            .ok_or(HandleError::MissingDecodoUrl)?;
                        // Port validation happens inside dial_via_socks5
                        // BEFORE any network I/O; the destination host
                        // and port are deliberately not logged.
                        let dest = exit::dial_via_socks5(
                            proxy_url,
                            &payload.host,
                            payload.port,
                            &cfg.allowed_exit_ports,
                        )
                        .await?;
                        info!(role = %role, "exit dialed destination via SOCKS5");
                        dest_link = Some(dest);
                    }
                    (CellType::Data, Role::Exit) => {
                        let dl = dest_link
                            .as_mut()
                            .ok_or(HandleError::IllegalCellForRole(CellType::Data, role))?;
                        dl.write_all(&cell.payload).await?;
                        dl.flush().await?;
                    }
                    (CellType::CloseRequest, _) => {
                        let ack = Cell::new(CellType::CloseAck, CIRCUIT_ID, Vec::new())?;
                        crypto::write_frame(&mut sock_write, key, &ack.encode()).await?;
                        if let Some(nl) = next_link.take() {
                            // The link is in "listener waiting for next
                            // CIRCUIT_START" state because the inner
                            // CLOSE_REQUESTs were processed before this
                            // outer CLOSE_REQUEST. Release to the pool
                            // so a subsequent circuit can reuse it.
                            pool.release(nl.addr, PooledConn::new(nl.stream));
                        }
                        drop(dest_link.take());
                        return Ok(());
                    }
                    (CellType::CloseAck, _) => {
                        // CLOSE_ACK on the forward path is unexpected;
                        // treat as a peer-initiated teardown.
                        return Err(HandleError::PeerClosed);
                    }
                    (t, r) => return Err(HandleError::IllegalCellForRole(t, r)),
                }
            }

            res = async {
                match next_link.as_mut() {
                    Some(nl) => crypto::read_frame_bytes(&mut nl.stream).await,
                    None => std::future::pending().await,
                }
            } => {
                let back_bytes = res?;
                let wrap = Cell::new(CellType::Relay, CIRCUIT_ID, back_bytes)?;
                crypto::write_frame(&mut sock_write, key, &wrap.encode()).await?;
            }

            res = async {
                match dest_link.as_mut() {
                    Some(dl) => {
                        let mut buf = vec![0u8; DEST_READ_BUF];
                        let n = dl.read(&mut buf).await?;
                        buf.truncate(n);
                        Ok::<_, std::io::Error>(buf)
                    }
                    None => std::future::pending().await,
                }
            } => {
                let bytes = res?;
                if bytes.is_empty() {
                    // Destination closed its write half. Stop reading
                    // from it but keep the circuit alive in case the
                    // client still has bytes to send before CLOSE.
                    drop(dest_link.take());
                    continue;
                }
                let data_cell = Cell::new(CellType::Data, CIRCUIT_ID, bytes)?;
                crypto::write_frame(&mut sock_write, key, &data_cell.encode()).await?;
            }
        }
    }
}

struct NextLinkState {
    stream: TcpStream,
    peer_pk: [u8; X25519_PK_LEN],
    addr: SocketAddr,
}

/// Acquire (or dial) an outbound TCP to `next_hop` and run the
/// per-circuit bootstrap: write CIRCUIT_START + client pubkey, read
/// peer pubkey. A fresh TCP gets the PROTO_RELAY prefix once; pooled
/// streams are already past PROTO_RELAY and ready for the next
/// CIRCUIT_START.
async fn open_next_link(
    extend: &ExtendForward,
    pool: &ConnectionPool,
) -> Result<NextLinkState, HandleError> {
    let mut stream = match pool.acquire(&extend.next_hop) {
        Some(PooledConn { stream, .. }) => stream,
        None => {
            let s = TcpStream::connect(extend.next_hop).await?;
            s.set_nodelay(true)?;
            let mut s = s;
            s.write_all(&[PROTO_RELAY]).await?;
            s
        }
    };
    stream.write_all(&[CIRCUIT_START]).await?;
    stream.write_all(&extend.client_pk).await?;
    stream.flush().await?;
    let mut peer_pk = [0u8; X25519_PK_LEN];
    match tokio::time::timeout(HANDSHAKE_READ_TIMEOUT, stream.read_exact(&mut peer_pk)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(HandleError::Io(e)),
        Err(_) => return Err(HandleError::Timeout),
    }
    Ok(NextLinkState {
        stream,
        peer_pk,
        addr: extend.next_hop,
    })
}

#[cfg(test)]
pub(crate) mod test_hooks {
    use std::sync::Mutex;
    use std::sync::OnceLock;
    use tokio::sync::mpsc;

    use crate::cell::ConnectPayload;

    static CONNECT_SINK: OnceLock<Mutex<Option<mpsc::UnboundedSender<ConnectPayload>>>> =
        OnceLock::new();

    fn cell_sink() -> &'static Mutex<Option<mpsc::UnboundedSender<ConnectPayload>>> {
        CONNECT_SINK.get_or_init(|| Mutex::new(None))
    }

    pub fn install_sender(tx: mpsc::UnboundedSender<ConnectPayload>) {
        *cell_sink().lock().expect("test hook mutex") = Some(tx);
    }

    fn publish_connect_inner(p: ConnectPayload) {
        if let Some(tx) = cell_sink().lock().expect("test hook mutex").as_ref() {
            let _ = tx.send(p);
        }
    }

    /// Called from the exit's CONNECT handler in test builds only.
    /// Clones the payload because the handler still needs its own copy
    /// to drive the SOCKS5 dial.
    pub fn publish_connect(p: &ConnectPayload) {
        publish_connect_inner(p.clone());
    }
}

#[cfg(test)]
fn publish_connect_for_test(p: &ConnectPayload) {
    test_hooks::publish_connect(p);
}

#[cfg(not(test))]
fn publish_connect_for_test(_p: &ConnectPayload) {}

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
                if pool.is_empty() {
                    continue;
                }
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
