#![deny(warnings)]
#![forbid(unsafe_code)]

mod authority;
mod circuit;
mod config;
mod exit;
mod heartbeat;
mod metrics;
mod pool;
mod port80;
mod static_key;
mod tls;
mod token;

#[cfg(test)]
mod integration_test;

use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::sync::Notify;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::TlsConnector;
use tracing::{error, info, warn};

use quiethop_crypto::cell::{self, Cell, CellType, ConnectPayload, ExtendForward};
use quiethop_crypto::layer;
use quiethop_crypto::noise::{self, StaticKeypair, Transport, NOISE_MSG_LEN};
use quiethop_crypto::wire::{
    CIRCUIT_START, M_RAW_LEN, PRESENTATION_LEN, PROTO_CLIENT, PROTO_RELAY,
};

use crate::authority::AuthorityClient;
use crate::config::{RelayConfig, Role};
use crate::pool::{ConnectionPool, PooledConn};
use crate::token::ReplayWindow;

const PRESENTATION_READ_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CELL_READ_TIMEOUT: Duration = Duration::from_secs(120);
const POOL_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
const POOL_IDLE_TTL: Duration = Duration::from_secs(300);
// Read in whole cells. 32 payloads per read keeps the syscall count near the
// old 16 KiB buffer while every cell on the wire stays CELL_PAYLOAD_LEN.
const DEST_READ_BUF: usize = cell::CELL_PAYLOAD_LEN * 32;

pub type InboundStream = ServerTlsStream<TcpStream>;
pub type OutboundStream = ClientTlsStream<TcpStream>;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    // `quiethop-relay keygen` writes the static keypair and exits. It runs
    // before any config or TLS work because it needs neither, and a relay must
    // never generate a key on the serving path (ARCHITECTURE §5.2 step 3).
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("keygen") {
        return run_keygen(args.get(1).map(String::as_str));
    }
    if !args.is_empty() {
        error!(
            "unknown arguments; usage: quiethop-relay [keygen [path]] with all other \
             configuration in the environment"
        );
        return ExitCode::from(2);
    }

    // rustls 0.23 panics on first ClientConfig/ServerConfig build if
    // no process-global CryptoProvider is installed. Install ring once
    // here so later rustls/rustls-acme calls do not panic.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        warn!("rustls crypto provider was already installed");
    }

    let cfg = match RelayConfig::from_env() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            error!(error = %e, "config validation failed");
            return ExitCode::from(1);
        }
    };
    // ARCHITECTURE §5.2 step 3. Exit on any failure: missing, unreadable, a
    // mode looser than 0600, the wrong length, or halves that do not match.
    let static_key = match static_key::load(&cfg.static_key_path) {
        Ok(kp) => Arc::new(kp),
        Err(e) => {
            error!(error = %e, "static key load failed");
            return ExitCode::from(1);
        }
    };
    info!(
        static_pubkey_len = static_key.public.len(),
        "static key loaded"
    );

    info!(
        role = %cfg.role,
        node_id = %cfg.node_id,
        relay_port = cfg.relay_port,
        metrics_bind = %cfg.metrics_bind,
        max_circuits = cfg.max_circuits,
        replay_window_ttl_seconds = cfg.replay_window_ttl,
        allowed_exit_ports = ?cfg.allowed_exit_ports,
        peer_allowlist_size = cfg.peer_allowlist.len(),
        relay_hostname = %cfg.relay_hostname,
        acme_staging = cfg.acme_staging,
        peer_hostnames_size = cfg.peer_hostnames.len(),
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

    let outbound_pool: Arc<ConnectionPool<OutboundStream>> = Arc::new(ConnectionPool::new());

    let acme = match tls::acme_setup(&cfg) {
        Ok(a) => a,
        Err(e) => {
            error!(error = %e, "failed to start acme acceptor");
            return ExitCode::from(1);
        }
    };
    info!(
        hostname = %cfg.relay_hostname,
        acme_dir = %cfg.acme_dir.display(),
        staging = cfg.acme_staging,
        "acme acceptor ready (issuance happens on first inbound TLS handshake)"
    );

    let outbound_connector = match tls::outbound_connector() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            error!(error = %e, "failed to build outbound tls connector");
            return ExitCode::from(1);
        }
    };
    info!("outbound tls connector ready (native root store)");

    let relay_addr = format!("0.0.0.0:{}", cfg.relay_port);
    let relay_listener = match TcpListener::bind(&relay_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, addr = %relay_addr, "failed to bind relay port");
            return ExitCode::from(1);
        }
    };
    info!(addr = %relay_addr, "relay listener bound");

    let metrics_listener = match TcpListener::bind(cfg.metrics_bind).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, addr = %cfg.metrics_bind, "failed to bind metrics listener");
            return ExitCode::from(1);
        }
    };
    info!(addr = %cfg.metrics_bind, "metrics listener bound");

    let port80_listener = match TcpListener::bind("0.0.0.0:80").await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, "failed to bind port 80 redirector");
            return ExitCode::from(1);
        }
    };
    info!("port 80 redirector bound");

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
    let hb_handle = heartbeat::spawn(
        cfg.clone(),
        heartbeat_client,
        heartbeat::pubkey_hex(&static_key.public),
        shutdown.clone(),
    );

    let accept_handle = tokio::spawn(accept_loop(
        relay_listener,
        acme.default_config,
        acme.challenge_config,
        shutdown.clone(),
        cfg.clone(),
        authority.clone(),
        replay.clone(),
        outbound_pool.clone(),
        outbound_connector.clone(),
        static_key.clone(),
    ));
    let metrics_handle = tokio::spawn(metrics_accept_loop(metrics_listener, shutdown.clone()));
    let pool_sweep_handle = tokio::spawn(pool_sweep_loop(outbound_pool.clone(), shutdown.clone()));
    let port80_handle = tokio::spawn(port80::redirect_loop(
        port80_listener,
        cfg.relay_hostname.clone(),
        shutdown.clone(),
    ));

    match signal::ctrl_c().await {
        Ok(()) => info!("shutdown signal received"),
        Err(e) => error!(error = %e, "signal listener failed"),
    }

    shutdown.notify_waiters();
    let _ = hb_handle.await;
    let _ = accept_handle.await;
    let _ = metrics_handle.await;
    let _ = pool_sweep_handle.await;
    let _ = port80_handle.await;
    acme.driver.abort();
    let _ = acme.driver.await;
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

#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    listener: TcpListener,
    default_config: std::sync::Arc<rustls::ServerConfig>,
    challenge_config: std::sync::Arc<rustls::ServerConfig>,
    shutdown: Arc<Notify>,
    cfg: Arc<RelayConfig>,
    authority: Arc<AuthorityClient>,
    replay: Arc<ReplayWindow>,
    pool: Arc<ConnectionPool<OutboundStream>>,
    connector: Arc<TlsConnector>,
    static_key: Arc<StaticKeypair>,
) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                info!("relay accept loop shutting down");
                return;
            }
            res = listener.accept() => match res {
                Ok((tcp, peer)) => {
                    let ctx = ConnCtx {
                        cfg: cfg.clone(),
                        authority: authority.clone(),
                        replay: replay.clone(),
                        pool: pool.clone(),
                        connector: connector.clone(),
                        static_key: static_key.clone(),
                    };
                    let dc = default_config.clone();
                    let cc = challenge_config.clone();
                    tokio::spawn(async move {
                        let _ = tcp.set_nodelay(true);
                        let routed = tokio::time::timeout(
                            TLS_HANDSHAKE_TIMEOUT,
                            tls::accept_routed(tcp, dc, cc),
                        )
                        .await;
                        let tls = match routed {
                            // Ok(None) means ACME-TLS-ALPN-01 challenge
                            // probe, handshake completed with the
                            // challenge cert, must not enter relay path
                            // (RFC 8737 §3).
                            Ok(Ok(Some(s))) => s,
                            Ok(Ok(None)) => return,
                            Ok(Err(e)) => {
                                warn!(peer = %peer, error = %e, "tls handshake failed");
                                return;
                            }
                            Err(_) => {
                                warn!(peer = %peer, "tls handshake timeout");
                                return;
                            }
                        };
                        if let Err(e) = handle_connection(tls, peer, ctx).await {
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

/// Per-connection dependencies, cloned once per accepted connection.
///
/// These travel together through every layer of the connection handler, so
/// they move as one value rather than as six positional arguments.
#[derive(Clone)]
struct ConnCtx {
    cfg: Arc<RelayConfig>,
    authority: Arc<AuthorityClient>,
    replay: Arc<ReplayWindow>,
    pool: Arc<ConnectionPool<OutboundStream>>,
    connector: Arc<TlsConnector>,
    static_key: Arc<StaticKeypair>,
}

/// Write a fresh static keypair and print only the public half.
///
/// The private half never leaves the file. Nothing about it is logged, so a
/// shell transcript or a log shipper cannot carry it off the host.
fn run_keygen(path_arg: Option<&str>) -> ExitCode {
    let path = match path_arg {
        Some(p) => std::path::PathBuf::from(p),
        None => match std::env::var("RELAY_STATIC_KEY_PATH") {
            Ok(v) if !v.is_empty() => std::path::PathBuf::from(v),
            _ => {
                error!("keygen needs a path argument or RELAY_STATIC_KEY_PATH");
                return ExitCode::from(2);
            }
        },
    };
    match static_key::generate(&path) {
        Ok(public_hex) => {
            info!(path = %path.display(), "static keypair written with mode 0600");
            // The operator passes this to /admin/relays/provision.
            println!("{public_hex}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!(error = %e, "keygen failed");
            ExitCode::from(1)
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
    #[error("noise handshake failed")]
    Handshake,
    #[error("layer: {0}")]
    Layer(#[from] layer::LayerError),
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
    #[error("no peer hostname configured for next-hop {0}")]
    PeerHostnameMissing(SocketAddr),
    #[error("FORWARD cell arrived at role {0} with no next link")]
    ForwardWithoutNextLink(Role),
    #[error("tls error: {0}")]
    Tls(#[from] tls::TlsError),
}

async fn handle_connection(
    sock: InboundStream,
    peer: SocketAddr,
    ctx: ConnCtx,
) -> Result<(), HandleError> {
    let (mut r, mut w) = tokio::io::split(sock);

    let mut proto = [0u8; 1];
    match tokio::time::timeout(PRESENTATION_READ_TIMEOUT, r.read_exact(&mut proto)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(HandleError::Io(e)),
        Err(_) => return Err(HandleError::Timeout),
    }

    match (proto[0], ctx.cfg.role) {
        (PROTO_CLIENT, Role::Guard) => handle_client_connection(r, w, peer, ctx).await,
        (PROTO_RELAY, Role::Middle) | (PROTO_RELAY, Role::Exit) => {
            handle_relay_connection(r, w, peer, ctx).await
        }
        (b, _) => {
            // Ignore shutdown errors since we're already rejecting.
            let _ = w.shutdown().await;
            Err(HandleError::UnexpectedProtocol(b))
        }
    }
}

/// Client-mode inbound on the guard role. One circuit per TLS stream;
/// after CLOSE_REQUEST the stream is closed (clients reconnect for a
/// new circuit). Token verification runs first; only then does the
/// per-hop ECDH and cell loop start.
async fn handle_client_connection(
    mut r: ReadHalf<InboundStream>,
    mut w: WriteHalf<InboundStream>,
    peer: SocketAddr,
    ctx: ConnCtx,
) -> Result<(), HandleError> {
    let mut buf = [0u8; PRESENTATION_LEN];
    match tokio::time::timeout(PRESENTATION_READ_TIMEOUT, r.read_exact(&mut buf)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(HandleError::Io(e)),
        Err(_) => return Err(HandleError::Timeout),
    }
    let m_raw = &buf[..M_RAW_LEN];
    let token = &buf[M_RAW_LEN..];
    if let Err(e) = token::verify(m_raw, token, ctx.authority.pubkey(), &ctx.replay) {
        metrics::record_rejected(&e);
        return Err(HandleError::Token(e));
    }
    metrics::record_verified();

    drive_circuit(&mut r, &mut w, peer, Role::Guard, ctx).await
}

/// Relay-mode inbound (middle or exit). Peer IP must be in the
/// configured allowlist; once accepted, the link supports multiple
/// circuits in sequence, each preceded by a `CIRCUIT_START` byte. The
/// outer loop returns when the dialer either closes the stream or
/// sends a non-CIRCUIT_START byte.
async fn handle_relay_connection(
    mut r: ReadHalf<InboundStream>,
    mut w: WriteHalf<InboundStream>,
    peer: SocketAddr,
    ctx: ConnCtx,
) -> Result<(), HandleError> {
    let peer_ip = match peer {
        SocketAddr::V4(a) => IpAddr::V4(*a.ip()),
        SocketAddr::V6(a) => IpAddr::V6(*a.ip()),
    };
    if !ctx.cfg.peer_allowlist.contains(&peer_ip) {
        return Err(HandleError::PeerNotAllowed);
    }

    loop {
        let mut signal = [0u8; 1];
        match r.read_exact(&mut signal).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(HandleError::Io(e)),
        }
        if signal[0] != CIRCUIT_START {
            // Any byte other than CIRCUIT_START terminates the link.
            return Ok(());
        }
        drive_circuit(&mut r, &mut w, peer, ctx.cfg.role, ctx.clone()).await?;
    }
}

/// Bring up one circuit: run the Noise NK responder handshake against this
/// relay's static key, activate the state machine, run the bidirectional cell
/// loop. On CLOSE_REQUEST: send CLOSE_ACK, release the next link to the pool
/// (if any), drop the destination link (if any), close the circuit.
///
/// Every failure below takes the same path: close the connection, fail the
/// circuit, send nothing back. The peer cannot tell a bad handshake from a bad
/// cell from a bad size, because in all three cases it receives a closed
/// connection and no bytes.
async fn drive_circuit(
    r: &mut ReadHalf<InboundStream>,
    w: &mut WriteHalf<InboundStream>,
    peer: SocketAddr,
    role: Role,
    ctx: ConnCtx,
) -> Result<(), HandleError> {
    let mut circuit = circuit::Circuit::new();

    let mut msg1 = [0u8; NOISE_MSG_LEN];
    match tokio::time::timeout(HANDSHAKE_READ_TIMEOUT, r.read_exact(&mut msg1)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            circuit.fail();
            return Err(HandleError::Io(e));
        }
        Err(_) => {
            circuit.fail();
            return Err(HandleError::Timeout);
        }
    }

    let (mut transport, msg2) = match noise::respond(ctx.static_key.private(), &msg1) {
        Ok(pair) => pair,
        Err(_) => {
            circuit.fail();
            return Err(HandleError::Handshake);
        }
    };

    if let Err(e) = w.write_all(&msg2).await {
        circuit.fail();
        return Err(HandleError::Io(e));
    }
    if let Err(e) = w.flush().await {
        circuit.fail();
        return Err(HandleError::Io(e));
    }

    if let Err(e) = circuit.activate() {
        circuit.fail();
        return Err(HandleError::Circuit(e));
    }
    info!(peer = %peer, role = %role, state = %circuit.state(), "circuit active");

    let outcome = run_circuit_io(r, w, &mut transport, role, &ctx).await;
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

/// How many AEAD layers this role's inbound link carries. The client wraps one
/// layer per hop, so the guard sees three and the exit one.
fn inbound_layers(role: Role) -> usize {
    match role {
        Role::Guard => 3,
        Role::Middle => 2,
        Role::Exit => 1,
    }
}

/// Cell size on this role's inbound link. Derived, never a literal.
fn inbound_len(role: Role) -> usize {
    cell::link_cell_len(inbound_layers(role))
}

/// Cell size on this role's outbound relay link, if it has one.
fn outbound_len(role: Role) -> Option<usize> {
    match role {
        Role::Exit => None,
        other => Some(cell::link_cell_len(inbound_layers(other) - 1)),
    }
}

/// One circuit's bidirectional control and data loop.
///
/// Reads from three sources via `tokio::select!`:
///
///   1. the inbound read half, a fixed `inbound_len(role)` bytes per cell
///   2. the next link, a fixed `outbound_len(role)` bytes per cell, wrapped
///      back toward the client behind a FORWARD disposition
///   3. the destination socket, split into DATA cells (exit only)
///
/// No length appears on the wire in either direction: both sizes come from the
/// role, so a reader always knows how many bytes one cell is.
async fn run_circuit_io(
    sock_read: &mut ReadHalf<InboundStream>,
    sock_write: &mut WriteHalf<InboundStream>,
    transport: &mut Transport,
    role: Role,
    ctx: &ConnCtx,
) -> Result<(), HandleError> {
    let mut next_link: Option<NextLinkState> = None;
    let mut dest_link: Option<TcpStream> = None;

    let layers = inbound_layers(role);
    let out_len = outbound_len(role);
    // Cancel safe: FrameReader keeps any partial frame across a select branch
    // that loses the race. read_exact would drop those bytes and every later
    // read would start mid-cell.
    let mut inbound = layer::FrameReader::new(&mut *sock_read, inbound_len(role));

    loop {
        tokio::select! {
            biased;
            res = tokio::time::timeout(CELL_READ_TIMEOUT, inbound.next_frame()) => {
                let wire = match res {
                    Ok(Ok(b)) => b,
                    Ok(Err(e)) => return Err(HandleError::Io(e)),
                    Err(_) => return Err(HandleError::Timeout),
                };

                match layer::peel(transport, &wire, layers)? {
                    layer::Peeled::Forward(blob) => {
                        let nl = next_link
                            .as_mut()
                            .ok_or(HandleError::ForwardWithoutNextLink(role))?;
                        nl.write.write_all(&blob).await?;
                        nl.write.flush().await?;
                    }
                    layer::Peeled::ToMe(cell) => match (cell.cell_type, role) {
                        (CellType::Extend, Role::Guard) | (CellType::Extend, Role::Middle) => {
                            if next_link.is_some() {
                                return Err(HandleError::IllegalCellForRole(CellType::Extend, role));
                            }
                            let extend = ExtendForward::decode(&cell.payload)?;
                            let out = out_len.ok_or(
                                HandleError::IllegalCellForRole(CellType::Extend, role),
                            )?;
                            let nl = open_next_link(
                                &extend,
                                &ctx.pool,
                                &ctx.cfg,
                                &ctx.connector,
                                out,
                            )
                            .await?;
                            let reply = Cell::new(
                                CellType::Extend,
                                cell::extend_backward_payload(&nl.noise_msg2),
                            )?;
                            let framed = layer::seal_to_me(transport, &reply, layers)?;
                            sock_write.write_all(&framed).await?;
                            sock_write.flush().await?;
                            next_link = Some(nl);
                        }
                        (CellType::Connect, Role::Exit) => {
                            if dest_link.is_some() {
                                return Err(HandleError::IllegalCellForRole(CellType::Connect, role));
                            }
                            let payload = ConnectPayload::decode(&cell.payload)?;
                            publish_connect_for_test(&payload);
                            let proxy_url = ctx
                                .cfg
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
                                &ctx.cfg.allowed_exit_ports,
                            )
                            .await?;
                            info!(role = %role, "exit dialed destination via SOCKS5");
                            dest_link = Some(dest);
                        }
                        (CellType::Data, Role::Exit) => {
                            // A zero-length DATA cell is legal and is a no-op,
                            // which is the hook cover traffic will use.
                            if cell.payload.is_empty() {
                                continue;
                            }
                            let dl = dest_link
                                .as_mut()
                                .ok_or(HandleError::IllegalCellForRole(CellType::Data, role))?;
                            dl.write_all(&cell.payload).await?;
                            dl.flush().await?;
                        }
                        (CellType::CloseRequest, _) => {
                            let ack = Cell::new(CellType::CloseAck, Vec::new())?;
                            let framed = layer::seal_to_me(transport, &ack, layers)?;
                            sock_write.write_all(&framed).await?;
                            sock_write.flush().await?;
                            if let Some(nl) = next_link.take() {
                                // The inner CLOSE_REQUESTs ran before this
                                // outer one, so the next-hop link is back
                                // in "waiting for CIRCUIT_START" state and
                                // safe to reuse, provided its reader holds
                                // nothing belonging to this circuit.
                                release_or_discard(&ctx.pool, nl.addr, nl.read, nl.write);
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
                    },
                }
            }

            res = async {
                match next_link.as_mut() {
                    Some(nl) => nl.read.next_frame().await,
                    None => std::future::pending().await,
                }
            } => {
                let blob = res?;
                // Wrap the next hop's cell in this relay's own layer. No RELAY
                // cell and no header: the client peels until it reaches TO_ME.
                let framed = layer::seal_forward(transport, &blob, layers)?;
                sock_write.write_all(&framed).await?;
                sock_write.flush().await?;
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
                for chunk in bytes.chunks(cell::CELL_PAYLOAD_LEN) {
                    let data_cell = Cell::new(CellType::Data, chunk.to_vec())?;
                    let framed = layer::seal_to_me(transport, &data_cell, layers)?;
                    sock_write.write_all(&framed).await?;
                }
                sock_write.flush().await?;
            }
        }
    }
}

/// Hand a finished next link back to the pool, or drop it.
///
/// A reader still holding a partial frame holds bytes that belong to the
/// circuit just closing. Pooling that stream would surface them as a corrupt
/// frame for whichever circuit acquires it next, so it is discarded instead.
/// Losing a pooled connection costs one TLS handshake; pooling a dirty one
/// breaks the next circuit.
fn release_or_discard<S>(
    pool: &ConnectionPool<S>,
    addr: SocketAddr,
    read: layer::FrameReader<ReadHalf<S>>,
    write: WriteHalf<S>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let pending = read.pending();
    if pending != 0 {
        warn!(
            peer = %addr,
            pending,
            "discarding a next-hop link rather than pooling it: its reader holds a partial frame"
        );
        return;
    }
    let stream = read.into_inner().unsplit(write);
    pool.release(addr, PooledConn::new(stream));
}

struct NextLinkState {
    read: layer::FrameReader<ReadHalf<OutboundStream>>,
    write: WriteHalf<OutboundStream>,
    noise_msg2: [u8; NOISE_MSG_LEN],
    addr: SocketAddr,
}

/// Acquire (or dial and TLS-handshake) an outbound link to `next_hop` and act
/// as courier for the client's handshake with that hop: write CIRCUIT_START
/// and the client's Noise message 1, read the hop's message 2 back.
///
/// This relay is not a party to that handshake. It cannot read either message,
/// and the next hop authenticates to the client, not to this relay.
///
/// A fresh outbound stream gets the PROTO_RELAY prefix once; pooled streams are
/// already past PROTO_RELAY and ready for the next CIRCUIT_START.
async fn open_next_link(
    extend: &ExtendForward,
    pool: &ConnectionPool<OutboundStream>,
    cfg: &RelayConfig,
    connector: &TlsConnector,
    frame_len: usize,
) -> Result<NextLinkState, HandleError> {
    let stream: OutboundStream = match pool.acquire(&extend.next_hop) {
        Some(PooledConn { stream, .. }) => stream,
        None => {
            let sni = cfg
                .peer_hostnames
                .get(&extend.next_hop)
                .ok_or(HandleError::PeerHostnameMissing(extend.next_hop))?;
            let mut s = tls::dial_tls(connector, extend.next_hop, sni).await?;
            s.write_all(&[PROTO_RELAY]).await?;
            s
        }
    };
    let (mut read, mut write) = tokio::io::split(stream);
    write.write_all(&[CIRCUIT_START]).await?;
    write.write_all(&extend.noise_msg1).await?;
    write.flush().await?;
    let mut noise_msg2 = [0u8; NOISE_MSG_LEN];
    match tokio::time::timeout(HANDSHAKE_READ_TIMEOUT, read.read_exact(&mut noise_msg2)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(HandleError::Io(e)),
        Err(_) => return Err(HandleError::Timeout),
    }
    Ok(NextLinkState {
        read: layer::FrameReader::new(read, frame_len),
        write,
        noise_msg2,
        addr: extend.next_hop,
    })
}

#[cfg(test)]
pub(crate) mod test_hooks {
    use std::sync::Mutex;
    use std::sync::OnceLock;
    use tokio::sync::mpsc;

    use quiethop_crypto::cell::ConnectPayload;

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

async fn pool_sweep_loop(pool: Arc<ConnectionPool<OutboundStream>>, shutdown: Arc<Notify>) {
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

    /// A clean reader gives its stream back to the pool.
    ///
    /// This is the positive half of the pooling decision: without it, a test
    /// that only checks the discard path would pass even if nothing were ever
    /// pooled.
    #[tokio::test]
    async fn clean_next_link_is_returned_to_the_pool() {
        let pool: ConnectionPool<tokio::io::DuplexStream> = ConnectionPool::new();
        let addr: SocketAddr = "127.0.0.1:9001".parse().expect("addr");
        let (near, mut far) = tokio::io::duplex(256);

        const FRAME: usize = 8;
        far.write_all(&[5u8; FRAME]).await.expect("write a frame");
        far.flush().await.expect("flush");

        let (read, write) = tokio::io::split(near);
        let mut reader = layer::FrameReader::new(read, FRAME);
        let frame = reader.next_frame().await.expect("frame");
        assert_eq!(frame.len(), FRAME);
        assert_eq!(reader.pending(), 0, "nothing should be left over");

        release_or_discard(&pool, addr, reader, write);
        assert_eq!(pool.len(), 1, "a clean link must be pooled");
        assert!(
            pool.acquire(&addr).is_some(),
            "and must be acquirable again"
        );
    }

    /// A reader holding a partial frame must not be pooled. Those bytes belong
    /// to the circuit that is closing and would corrupt the next one's framing.
    #[tokio::test]
    async fn next_link_holding_a_partial_frame_is_discarded() {
        let pool: ConnectionPool<tokio::io::DuplexStream> = ConnectionPool::new();
        let addr: SocketAddr = "127.0.0.1:9002".parse().expect("addr");
        let (near, mut far) = tokio::io::duplex(256);

        const FRAME: usize = 8;
        // Three bytes of a frame, and a competing branch that is ready at once,
        // so next_frame is cancelled with a partial frame retained.
        far.write_all(&[1, 2, 3])
            .await
            .expect("write a partial frame");
        far.flush().await.expect("flush");

        let (read, write) = tokio::io::split(near);
        let mut reader = layer::FrameReader::new(read, FRAME);
        let (other_tx, mut other_rx) = tokio::io::duplex(8);
        drop(other_tx);
        let mut obuf = [0u8; 1];
        // biased so next_frame is polled first and takes the three bytes
        // before the other branch wins. Unbiased, the runtime may never poll
        // it and the retained-partial assertion would pass vacuously.
        tokio::select! {
            biased;
            r = reader.next_frame() => panic!("a frame appeared from three bytes: {r:?}"),
            _ = other_rx.read(&mut obuf) => {}
        }
        assert_eq!(reader.pending(), 3, "the partial frame must be retained");

        release_or_discard(&pool, addr, reader, write);
        assert!(
            pool.is_empty(),
            "a link whose reader holds {} buffered bytes must be discarded, not pooled",
            3
        );
    }

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
