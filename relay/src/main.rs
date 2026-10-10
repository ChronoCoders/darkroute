#![deny(warnings)]
#![forbid(unsafe_code)]

mod authority;
mod config;
mod exit;
mod heartbeat;
mod link;
mod linkreg;
mod metrics;
mod port80;
mod registry;
mod static_key;
mod tls;
mod token;

#[cfg(test)]
mod integration_test;

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::sync::{mpsc, watch, Notify};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::TlsConnector;
use tracing::{error, info, warn};

use quiethop_crypto::cell::{self, Cell, CellType, ConnectPayload, ExtendForward};
use quiethop_crypto::circid::{CircId, LinkRole};
use quiethop_crypto::flow::{AfterDelivery, FlowError};
use quiethop_crypto::layer;
use quiethop_crypto::layers::Layers;
use quiethop_crypto::link::{self as link_frame, DestroyReason};
use quiethop_crypto::noise::{self, StaticKeypair, Transport, NOISE_MSG_LEN};
use quiethop_crypto::wire::{M_RAW_LEN, PRESENTATION_LEN, PROTO_CLIENT, PROTO_RELAY};

use crate::authority::AuthorityClient;
use crate::config::{RelayConfig, Role};
use crate::registry::RegistryHandle;
use crate::token::ReplayWindow;
use quiethop_crypto::registry_cache::RegistryCache;

const PRESENTATION_READ_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CELL_READ_TIMEOUT: Duration = Duration::from_secs(120);
/// How long one socket write or flush may make no progress.
///
/// The same 120 seconds as CELL_READ_TIMEOUT, because both answer whether the
/// peer is still there, one from each direction. A second constant tuned
/// separately would have nothing to be tuned against. A 569 byte frame that has
/// made no progress for two minutes, on a connection whose peer is still
/// sending, is not a slow peer (docs/DECISIONS.md entry 26).
const CELL_WRITE_TIMEOUT: Duration = Duration::from_secs(120);
/// How long the exit may spend writing to its destination.
///
/// Shorter than CELL_WRITE_TIMEOUT on purpose. A next hop is a known party in
/// the signed registry whose link carries many circuits, so patience is right.
/// A destination is one circuit's own connection to a host the customer chose,
/// nothing else depends on it, and the failure this bound exists for is a host
/// that accepts and never reads (SECURITY_MODEL 6.7). Provisional.
const DEST_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
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
        relay_hostname = %cfg.relay_hostname,
        acme_staging = cfg.acme_staging,
        registry_url = %cfg.registry_url,
        pinned_registry_keys = cfg.registry_signing_pubkeys.len(),
        registry_state_dir = %cfg.registry_state_dir.display(),
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

    // The registry trust root, established before anything is bound. A relay
    // that cannot verify the registry must not start (ARCHITECTURE 5.2 step 4,
    // SECURITY_MODEL 10), so this returns rather than binding the listener.
    let mut registry_cache = match RegistryCache::new(
        cfg.registry_url.clone(),
        cfg.registry_state_dir.clone(),
        cfg.registry_signing_pubkeys.clone(),
        1,
    ) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "registry cache could not be built");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = registry_cache.prime(now_unix()).await {
        error!(error = %e, "registry fetch or verification failed, refusing to start");
        return ExitCode::from(1);
    }
    let registry = RegistryHandle::new();
    match registry_cache.usable(now_unix()) {
        Ok(v) => {
            info!(
                version = v.document.version,
                relays = v.document.relays.len(),
                "registry verified"
            );
            registry.publish(Arc::new(v.clone()));
        }
        Err(e) => {
            error!(error = %e, "verified registry is not usable, refusing to start");
            return ExitCode::from(1);
        }
    }
    // Refreshed on its own schedule. A failed refresh keeps the last verified
    // document in service until its valid_until, after which the handle still
    // holds it but every consumer refuses, because the document is then outside
    // its window. That is the fail-closed point (ARCHITECTURE 5.5).
    {
        let registry = registry.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(REGISTRY_REFRESH_POLL);
            loop {
                tick.tick().await;
                match registry_cache.refresh_if_stale(now_unix()).await {
                    Ok(true) => match registry_cache.usable(now_unix()) {
                        Ok(v) => {
                            info!(version = v.document.version, "registry refreshed");
                            registry.publish(Arc::new(v.clone()));
                        }
                        Err(e) => error!(error = %e, "refreshed registry is not usable"),
                    },
                    Ok(false) => {}
                    Err(e) => error!(
                        error = %e,
                        "registry refresh failed, serving the last verified document until it expires"
                    ),
                }
            }
        });
    }

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
        outbound_connector.clone(),
        static_key.clone(),
        registry.clone(),
        link::Budget::new(),
        Arc::new(OutboundRegistry::new()),
    ));
    let metrics_handle = tokio::spawn(metrics_accept_loop(metrics_listener, shutdown.clone()));
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

/// How often the registry refresh task wakes. The document's own fresh window
/// decides whether a fetch happens, so this only bounds how late one can be.
const REGISTRY_REFRESH_POLL: std::time::Duration = std::time::Duration::from_secs(60);

/// Seconds since the Unix epoch.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// Every argument is a distinct piece of per-process state the accept loop hands
// to each connection, and a struct wrapping them would be the same list behind
// one name with nothing checking that a caller filled it correctly.
#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    listener: TcpListener,
    default_config: std::sync::Arc<rustls::ServerConfig>,
    challenge_config: std::sync::Arc<rustls::ServerConfig>,
    shutdown: Arc<Notify>,
    cfg: Arc<RelayConfig>,
    authority: Arc<AuthorityClient>,
    replay: Arc<ReplayWindow>,
    connector: Arc<TlsConnector>,
    static_key: Arc<StaticKeypair>,
    registry: RegistryHandle,
    budget: link::Budget,
    links: Arc<OutboundRegistry>,
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
                        budget: budget.clone(),
                        links: links.clone(),
                        authority: authority.clone(),
                        replay: replay.clone(),
                        connector: connector.clone(),
                        static_key: static_key.clone(),
                        registry: registry.clone(),
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
/// they move as one value rather than as five positional arguments.
#[derive(Clone)]
struct ConnCtx {
    cfg: Arc<RelayConfig>,
    /// One per relay process, shared by every link (ARCHITECTURE 5.9).
    budget: link::Budget,
    /// The outbound links this relay holds, one per next hop
    /// (ARCHITECTURE 5.10).
    links: Arc<OutboundRegistry>,
    authority: Arc<AuthorityClient>,
    replay: Arc<ReplayWindow>,
    connector: Arc<TlsConnector>,
    static_key: Arc<StaticKeypair>,
    registry: RegistryHandle,
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
    #[error("the link control queue filled, so the link was closed")]
    ControlQueueFull,
    #[error("the peer destroyed this circuit")]
    DestroyedByPeer,
    #[error("the next hop destroyed this circuit")]
    DestroyedByNextHop,
    #[error("a socket write made no progress inside CELL_WRITE_TIMEOUT")]
    WriteTimeout,
    #[error("the destination made no progress inside DEST_WRITE_TIMEOUT")]
    DestWriteTimeout,
    #[error("next hop: {0}")]
    NextHop(#[from] linkreg::AcquireError),
    #[error("the peer sent past its flow-control window")]
    PeerPastItsWindow,
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
    #[error("link frame: {0}")]
    LinkFrame(#[from] link_frame::LinkError),
    #[error("flow control: {0}")]
    Flow(#[from] quiethop_crypto::flow::FlowError),
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
            // bounded: TLS_HANDSHAKE_TIMEOUT. Errors are ignored because the
            // connection is already being rejected; the bound is so a peer that
            // never reads cannot hold the task.
            // bounded: TLS_HANDSHAKE_TIMEOUT
            let _ = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, w.shutdown()).await;
            Err(HandleError::UnexpectedProtocol(b))
        }
    }
}

/// Client-mode inbound on the guard role. One circuit per TLS stream;
/// after CLOSE_REQUEST the stream is closed (clients reconnect for a
/// new circuit). Token verification runs first; only then does the
/// per-hop ECDH and cell loop start.
async fn handle_client_connection(
    r: ReadHalf<InboundStream>,
    w: WriteHalf<InboundStream>,
    peer: SocketAddr,
    ctx: ConnCtx,
) -> Result<(), HandleError> {
    // No preamble. The token is presented in each CREATE instead of once per
    // connection, so one token buys one circuit rather than a link's worth
    // (SECURITY_MODEL 5.10).
    run_link(r, w, peer, Role::Guard, ctx).await
}

/// Relay-mode inbound (middle or exit). The peer must be the role directly
/// upstream in the verified registry. Once accepted the link carries many
/// circuits at once, each named by a circuit id on the link.
async fn handle_relay_connection(
    r: ReadHalf<InboundStream>,
    w: WriteHalf<InboundStream>,
    peer: SocketAddr,
    ctx: ConnCtx,
) -> Result<(), HandleError> {
    let peer_ip = match peer {
        SocketAddr::V4(a) => IpAddr::V4(*a.ip()),
        SocketAddr::V6(a) => IpAddr::V6(*a.ip()),
    };
    // The upstream role for this relay, taken from the verified registry. An
    // absent registry refuses, so a relay with none published serves nothing
    // (ARCHITECTURE 5.5).
    let Some(doc) = ctx.registry.usable(now_unix()) else {
        return Err(HandleError::PeerNotAllowed);
    };
    if !registry::admits_inbound(&doc, ctx.cfg.role, peer_ip) {
        return Err(HandleError::PeerNotAllowed);
    }

    let role = ctx.cfg.role;
    run_link(r, w, peer, role, ctx).await
}

/// How many AEAD layers this role's inbound link carries. The client wraps one
/// layer per hop, so the guard sees three and the exit one.
fn inbound_layers(role: Role) -> Layers {
    match role {
        Role::Guard => Layers::new(3),
        Role::Middle => Layers::new(2),
        Role::Exit => Layers::new(1),
    }
}

/// How many AEAD layers this role's outbound relay link carries, if it has
/// one. One fewer than inbound, because this role peeled its own.
///
/// `Layers` rather than a bare count, so a byte length cannot be passed here
/// or taken from here (quiethop-crypto `layers`).
fn outbound_layers(role: Role) -> Option<Layers> {
    match role {
        Role::Exit => None,
        other => Some(inbound_layers(other).peeled()),
    }
}

/// Shared per-link state.
///
/// The table and the per-circuit senders live under one lock so there is no
/// lock order to get wrong. Every hold is a few map operations with no await
/// inside it (ARCHITECTURE 5.4, 5.5).
struct LinkState {
    table: link::LinkTable,
    handles: HashMap<CircId, CircuitHandle>,
    /// Link level frames, ahead of circuit data in the writer.
    ///
    /// DESTROY lives here rather than in the named circuit's queue, because it
    /// is sent as that circuit is discarded and the queue goes with it. It also
    /// has to carry a DESTROY for a CREATE that was refused, where there is no
    /// circuit to queue against at all.
    control: VecDeque<link::Queued>,
}

struct LinkShared {
    state: std::sync::Mutex<LinkState>,
    /// Raised when a circuit queues a frame. Carries no frames itself: frames
    /// live in per-circuit queues so one busy circuit cannot push the others
    /// behind it in a shared FIFO.
    wake: Notify,
    /// Raised to end the link. A circuit task cannot close the socket itself,
    /// so it asks the reader to, and the reader owns the teardown.
    close: Notify,
    closing: AtomicBool,
    /// Shared with every other link on this relay, and it carries the
    /// admitting state too, which is relay-wide (ARCHITECTURE 5.9).
    budget: link::Budget,
}

/// What the link reader holds for one circuit.
///
/// The destroy signal is deliberately not a message on `frames`. On that
/// channel it would be dropped whenever the queue is full, which a peer inside
/// its 1000 cell window can legitimately cause against a 1024 slot queue, and
/// even when it fit it would wait behind every frame already queued while the
/// circuit went on forwarding data the peer had already destroyed.
///
/// A `watch` keeps the signal after its sender is dropped, so removing the
/// circuit from the table cannot lose a signal already sent.
struct CircuitHandle {
    frames: mpsc::Sender<link::Queued>,
    destroy: watch::Sender<bool>,
}

impl LinkShared {
    fn new(role: LinkRole, budget: link::Budget) -> Self {
        Self {
            state: std::sync::Mutex::new(LinkState {
                table: link::LinkTable::new(role, budget.clone()),
                handles: HashMap::new(),
                control: VecDeque::new(),
            }),
            wake: Notify::new(),
            close: Notify::new(),
            closing: AtomicBool::new(false),
            budget,
        }
    }

    /// Ask the link to end. Idempotent, and safe from any circuit task.
    ///
    /// Both notifications matter: the reader is what tears the link down, and
    /// the writer is woken so it stops waiting on a queue nothing will fill.
    fn request_close(&self) {
        self.closing.store(true, Ordering::Relaxed);
        self.close.notify_one();
        self.wake.notify_one();
    }

    fn closing(&self) -> bool {
        self.closing.load(Ordering::Relaxed)
    }

    /// Release every circuit on the link, as a link loss does. Returns how
    /// many were released.
    fn release_all(&self) -> usize {
        let mut st = self.lock();
        st.handles.clear();
        st.table.destroy_all(Instant::now())
    }

    /// A poisoned lock means a holder panicked. The state is a plain map, so
    /// taking it anyway is safe and refusing would strand the link.
    fn lock(&self) -> std::sync::MutexGuard<'_, LinkState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Queue a frame for this circuit and wake the writer.
    fn push_out(&self, id: CircId, frame: Vec<u8>) -> Result<(), link::QueueFull> {
        let r = self.lock().table.push_out(id, frame);
        if r.is_ok() {
            self.wake.notify_one();
        }
        r
    }

    /// Queue a link level frame and wake the writer.
    fn push_control(&self, frame: Vec<u8>) -> bool {
        {
            let mut st = self.lock();
            if st.control.len() >= link::MAX_CONTROL_QUEUE {
                return false;
            }
            // Counted like any other queued frame. It is bounded per link at
            // MAX_CONTROL_QUEUE, and the number of inbound links is not
            // bounded, so leaving it out would have left the budget covering
            // the per-circuit queues and not these (ARCHITECTURE 5.9).
            st.control.push_back(link::Queued::new(frame, &self.budget));
        }
        self.wake.notify_one();
        true
    }

    /// Control frames first, then one data frame from the next circuit in turn.
    ///
    /// Control frames cannot starve the circuits: each circuit contributes at
    /// most one, and a circuit that has contributed one is gone.
    fn pop_next_out(&self) -> Option<Vec<u8>> {
        let mut st = self.lock();
        if let Some(frame) = st.control.pop_front() {
            return Some(frame.take());
        }
        st.table.pop_next_out().map(|(_, frame)| frame)
    }

    /// Account for a DATA cell delivered to this circuit's consumer, and say
    /// whether a SENDME is owed. Windows live in the table so they are
    /// unit-testable; the lock is the same one push_out already takes.
    fn on_data_delivered(&self, id: CircId) -> Option<Result<AfterDelivery, FlowError>> {
        self.lock().table.on_data_delivered(id)
    }

    fn on_sendme_sent(&self, id: CircId) {
        self.lock().table.on_sendme_sent(id);
    }

    fn on_sendme_received(&self, id: CircId) -> Option<Result<(), FlowError>> {
        self.lock().table.on_sendme_received(id)
    }

    fn may_send(&self, id: CircId) -> bool {
        self.lock().table.may_send(id)
    }

    fn on_data_sent(&self, id: CircId) -> Option<Result<(), FlowError>> {
        self.lock().table.on_data_sent(id)
    }

    /// Take a circuit id on this link and register its channels, all under one
    /// hold of the link's lock so no other caller can take the same id.
    fn open_outbound_circuit(
        &self,
        cap: usize,
    ) -> Option<(CircId, mpsc::Receiver<link::Queued>, watch::Receiver<bool>)> {
        let mut st = self.lock();
        if st.table.len() >= cap {
            return None;
        }
        let id = st
            .table
            .allocate(&mut rand::rngs::OsRng, Instant::now())
            .ok()?;
        st.table.insert_pending(id).ok()?;
        let (tx, rx) = mpsc::channel::<link::Queued>(link::MAX_CIRCUIT_QUEUE);
        let (dtx, drx) = watch::channel(false);
        st.handles.insert(
            id,
            CircuitHandle {
                frames: tx,
                destroy: dtx,
            },
        );
        Some((id, rx, drx))
    }

    /// Remove a circuit and quarantine its id. Returns whether it was there.
    fn forget(&self, id: CircId) -> bool {
        let mut st = self.lock();
        st.handles.remove(&id);
        st.table.destroy(id, Instant::now())
    }
}

/// Serve one inbound link: read frames, dispatch by circuit id.
///
/// Replaces drive_circuit, which drove exactly one circuit per connection.
async fn run_link(
    r: ReadHalf<InboundStream>,
    w: WriteHalf<InboundStream>,
    peer: SocketAddr,
    role: Role,
    ctx: ConnCtx,
) -> Result<(), HandleError> {
    let layers = inbound_layers(role);
    let frame_len = link_frame::link_frame_len(layers);
    // This side did not open the inbound link, so the peer owns the half of the
    // id space with the top bit set and this side validates creates against it.
    let shared = Arc::new(LinkShared::new(LinkRole::Responder, ctx.budget.clone()));

    let writer = tokio::spawn(run_link_writer(shared.clone(), w));

    // Cancel safe: FrameReader keeps any partial frame across a select branch
    // that loses the race.
    let mut inbound = layer::FrameReader::new(r, frame_len);
    let outcome = loop {
        if shared.closing() {
            break Err(HandleError::ControlQueueFull);
        }
        // Cancel safe on the read branch: FrameReader keeps any partial frame
        // when the close branch wins, so nothing is read half way and lost.
        let wire = tokio::select! {
            biased;
            _ = shared.close.notified() => break Err(HandleError::ControlQueueFull),
            read = tokio::time::timeout(CELL_READ_TIMEOUT, inbound.next_frame()) => match read {
                Ok(Ok(b)) => b,
                Ok(Err(e)) => break Err(HandleError::Io(e)),
                Err(_) => break Err(HandleError::Timeout),
            },
        };
        if let Err(e) = dispatch_frame(&shared, &wire, layers, peer, role, &ctx).await {
            break Err(e);
        }
    };

    // The link is going. Every circuit on it fails, and each task forwards
    // DESTROY on its own downstream link as it winds up (SECURITY_MODEL 6.3).
    let released = shared.release_all();
    writer.abort();
    if released > 0 {
        info!(peer = %peer, role = %role, released, "link closed, circuits released");
    }
    outcome
}

/// Drain per-circuit queues in round-robin order.
///
/// One frame per circuit per turn, so a circuit with a large backlog cannot
/// hold the link while others wait.
async fn run_link_writer<W: AsyncWrite + Unpin>(shared: Arc<LinkShared>, mut w: W) {
    loop {
        let mut wrote = false;
        // The lock is taken and released once per frame, never across the write.
        while let Some(frame) = shared.pop_next_out() {
            // bounded: CELL_WRITE_TIMEOUT
            match tokio::time::timeout(CELL_WRITE_TIMEOUT, w.write_all(&frame)).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return,
                Err(_) => return stalled_write(&shared),
            }
            wrote = true;
        }
        if wrote {
            // bounded: CELL_WRITE_TIMEOUT
            match tokio::time::timeout(CELL_WRITE_TIMEOUT, w.flush()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return,
                Err(_) => return stalled_write(&shared),
            }
        }
        // A notify_one between the drain and here leaves a permit, so a frame
        // queued in that window is not missed.
        shared.wake.notified().await;
    }
}

/// A write that made no progress for CELL_WRITE_TIMEOUT. The peer is not
/// reading, so the link ends.
///
/// `request_close` is what the inbound reader watches. An outbound link has no
/// such reader waiting on frames from a client, so its own task watches the
/// same flag, which is why both directions end the same way: every circuit on
/// the link is released and each forwards DESTROY upstream with LinkLost
/// (ARCHITECTURE 5.10, 5.11).
fn stalled_write(shared: &Arc<LinkShared>) {
    metrics::record_frame_dropped(metrics::DropReason::WriteTimeout);
    warn!("a link write made no progress inside the write timeout, closing the link");
    shared.request_close();
}

/// One shared outbound link to a next hop (ARCHITECTURE 5.10).
///
/// It reuses the inbound machinery: `LinkShared` holds the circuit table, the
/// per-circuit queues, the round-robin writer and the control queue, and the
/// relay-wide byte budget runs through it the same way.
struct OutboundLink {
    shared: Arc<LinkShared>,
    /// Frames on this link, one layer fewer than the inbound side.
    layers: Layers,
    /// Taken once, by whichever caller dialed, to start the link's own task.
    reader: std::sync::Mutex<Option<layer::FrameReader<ReadHalf<OutboundStream>>>>,
    /// Aborted when the link ends, so the writer does not outlive the socket.
    writer: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

type OutboundRegistry = linkreg::Registry<OutboundLink>;
type OutboundShared = Arc<linkreg::Shared<OutboundLink>>;

/// Dial a next hop and start its writer. The reader is left for the caller
/// that dialed, because only it may take it.
async fn dial_outbound_link(
    connector: &TlsConnector,
    addr: SocketAddr,
    tls_name: &str,
    layers: Layers,
    budget: &link::Budget,
) -> Result<OutboundLink, HandleError> {
    let mut stream = tls::dial_tls(connector, addr, tls_name, TLS_HANDSHAKE_TIMEOUT).await?;
    // bounded: TLS_HANDSHAKE_TIMEOUT, the same deadline as the dial. One byte,
    // but a peer that accepts and never reads would hang the dialer and with it
    // every circuit waiting for this hop (ARCHITECTURE 5.11).
    match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, async {
        // bounded: TLS_HANDSHAKE_TIMEOUT, by the block around this
        stream.write_all(&[PROTO_RELAY]).await?;
        // bounded: TLS_HANDSHAKE_TIMEOUT
        stream.flush().await
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(HandleError::Io(e)),
        Err(_) => return Err(HandleError::Timeout),
    }
    let (read, write) = tokio::io::split(stream);

    let shared = Arc::new(LinkShared::new(LinkRole::Initiator, budget.clone()));
    let writer = tokio::spawn(run_link_writer(shared.clone(), write));
    Ok(OutboundLink {
        shared,
        layers,
        reader: std::sync::Mutex::new(Some(layer::FrameReader::new(
            read,
            link_frame::link_frame_len(layers),
        ))),
        writer: std::sync::Mutex::new(Some(writer)),
    })
}

/// Serve one shared outbound link: read frames, dispatch by circuit id, and
/// close the link once it has been idle for its jittered timeout.
async fn run_outbound_link(registry: Arc<OutboundRegistry>, link: OutboundShared) {
    let Some(mut reader) = link
        .link
        .reader
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .take()
    else {
        return;
    };
    let layers = link.link.layers;
    let shared = link.link.shared.clone();

    // Armed only while nothing is on the link, and the draw is fresh each time
    // so the close does not reveal when the last circuit ended.
    let mut idle: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;

    loop {
        if link.circuits() == 0 {
            if idle.is_none() {
                let budget = linkreg::idle_deadline(&mut rand::rngs::OsRng);
                idle = Some(Box::pin(tokio::time::sleep(budget)));
            }
        } else {
            idle = None;
        }

        if shared.closing() {
            // The writer gave up on a stalled peer, so this link ends and
            // every circuit on it is released (ARCHITECTURE 5.11).
            break;
        }

        tokio::select! {
            biased;
            // Raised by the writer when a write made no progress, and by a
            // full control queue.
            _ = shared.close.notified() => break,
            () = async {
                match idle.as_mut() {
                    Some(s) => s.as_mut().await,
                    None => std::future::pending().await,
                }
            } => {
                if registry.close_if_idle(&link) {
                    break;
                }
                // Either a circuit arrived while the timer was running, in
                // which case stand down, or this link is no longer the one the
                // key points at and nothing more will use it.
                if link.circuits() == 0 {
                    break;
                }
                idle = None;
            }
            // The last circuit left, so the next turn arms the timer.
            _ = link.idle.notified() => {}
            read = tokio::time::timeout(CELL_READ_TIMEOUT, reader.next_frame()) => {
                match read {
                    Ok(Ok(wire)) => dispatch_outbound(&shared, &wire, layers),
                    _ => break,
                }
            }
        }
    }

    registry.retire(&link);
    let released = end_outbound_link(&shared);
    if let Some(w) = link
        .link
        .writer
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .take()
    {
        w.abort();
    }
    info!(
        key = ?link.key(),
        released,
        links = registry.len(),
        "outbound link closed"
    );
}

/// Write one cell's payload to the destination, bounded.
///
/// A destination that accepts and never reads would otherwise hold this
/// circuit for ever, and the customer chooses the destination, so one customer
/// could point many circuits at such a host and use up an exit's capacity
/// (SECURITY_MODEL 6.7).
async fn write_to_destination<W: AsyncWrite + Unpin>(
    dl: &mut W,
    payload: &[u8],
) -> Result<(), HandleError> {
    // bounded: DEST_WRITE_TIMEOUT
    match tokio::time::timeout(DEST_WRITE_TIMEOUT, async {
        // bounded: DEST_WRITE_TIMEOUT, by the block around this
        dl.write_all(payload).await?;
        // bounded: DEST_WRITE_TIMEOUT
        dl.flush().await
    })
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(HandleError::Io(e)),
        Err(_) => {
            metrics::record_frame_dropped(metrics::DropReason::WriteTimeout);
            Err(HandleError::DestWriteTimeout)
        }
    }
}

/// Wind up a shared outbound link: mark it closing, then release its circuits.
///
/// The order is the point. A circuit learns its link is gone when its frame
/// channel closes, and the only way it can tell a stalled link from an ordinary
/// one is the flag being set by then. Released after, so no circuit can see a
/// closed channel on a link that is not yet marked (ARCHITECTURE 5.11).
fn end_outbound_link(shared: &Arc<LinkShared>) -> usize {
    shared.request_close();
    shared.release_all()
}

/// Act on one frame from a next hop.
///
/// CREATED and DATA both go to the circuit as whole frames, because the circuit
/// is the side that knows which it is waiting for. DESTROY is out of band for
/// the same reason it is on the inbound side: it must not wait behind queued
/// data (docs/DECISIONS.md entry 25).
fn dispatch_outbound(shared: &Arc<LinkShared>, wire: &[u8], layers: Layers) {
    let Ok(frame) = link_frame::decode(wire, layers, LinkRole::Responder) else {
        metrics::record_frame_dropped(metrics::DropReason::NotOpen);
        return;
    };
    let id = frame.circ_id;
    match frame.command {
        link_frame::LinkCommand::Created | link_frame::LinkCommand::Data => {
            let tx = {
                let st = shared.lock();
                st.handles.get(&id).map(|h| h.frames.clone())
            };
            let Some(tx) = tx else {
                metrics::record_frame_dropped(metrics::DropReason::NotOpen);
                return;
            };
            if tx
                .try_send(link::Queued::new(wire.to_vec(), &shared.budget))
                .is_err()
            {
                metrics::record_frame_dropped(metrics::DropReason::QueueFull);
            }
        }
        link_frame::LinkCommand::Destroy => {
            let signalled = {
                let st = shared.lock();
                st.handles.get(&id).map(|h| h.destroy.send(true).is_ok())
            };
            match signalled {
                Some(true) => {}
                Some(false) => {
                    metrics::record_frame_dropped(metrics::DropReason::DestroySignalLost)
                }
                None => metrics::record_frame_dropped(metrics::DropReason::NotOpen),
            }
        }
        // A next hop does not create circuits on a link this side opened.
        link_frame::LinkCommand::Create => {
            metrics::record_frame_dropped(metrics::DropReason::NotOpen)
        }
        link_frame::LinkCommand::Padding => {}
    }
}

/// Act on one inbound link frame.
async fn dispatch_frame(
    shared: &Arc<LinkShared>,
    wire: &[u8],
    layers: Layers,
    peer: SocketAddr,
    role: Role,
    ctx: &ConnCtx,
) -> Result<(), HandleError> {
    let frame = link_frame::decode(wire, layers, LinkRole::Initiator)?;
    let id = frame.circ_id;
    match frame.command {
        link_frame::LinkCommand::Create => {
            open_inbound_circuit(shared, id, frame.body, layers, peer, role, ctx).await
        }
        link_frame::LinkCommand::Data => {
            let (disposition, sender) = {
                let st = shared.lock();
                (
                    st.table.disposition_for_data(id),
                    st.handles.get(&id).map(|h| h.frames.clone()),
                )
            };
            match disposition {
                link::Disposition::NotOpen => {
                    metrics::record_frame_dropped(metrics::DropReason::NotOpen);
                    Ok(())
                }
                link::Disposition::BeforeCreated => {
                    metrics::record_frame_dropped(metrics::DropReason::BeforeCreated);
                    Ok(())
                }
                link::Disposition::Deliver => {
                    let Some(tx) = sender else {
                        metrics::record_frame_dropped(metrics::DropReason::NotOpen);
                        return Ok(());
                    };
                    // try_send only. Waiting here would stall every circuit on
                    // the link behind one slow circuit, which is the head of
                    // line blocking multiplexing exists to remove.
                    match tx.try_send(link::Queued::new(frame.body.to_vec(), &shared.budget)) {
                        Ok(()) => Ok(()),
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            metrics::record_frame_dropped(metrics::DropReason::NotOpen);
                            Ok(())
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            // A well behaved peer cannot fill this: the deliver
                            // window is 1000 cells against a 1024 queue. A full
                            // queue means the peer exceeded its window, so the
                            // circuit goes and the link does not.
                            metrics::record_frame_dropped(metrics::DropReason::QueueFull);
                            destroy_circuit(shared, id, layers, DestroyReason::Protocol);
                            Ok(())
                        }
                    }
                }
            }
        }
        link_frame::LinkCommand::Destroy => {
            let signalled = {
                let st = shared.lock();
                // send only fails when every receiver is gone, which means the
                // task has already ended and the circuit with it.
                st.handles.get(&id).map(|h| h.destroy.send(true).is_ok())
            };
            match signalled {
                Some(true) => {
                    shared.forget(id);
                }
                Some(false) => {
                    metrics::record_frame_dropped(metrics::DropReason::DestroySignalLost);
                    shared.forget(id);
                }
                None => metrics::record_frame_dropped(metrics::DropReason::NotOpen),
            }
            Ok(())
        }
        link_frame::LinkCommand::Created => {
            // Nothing on an inbound link ever awaits a CREATED: this side does
            // not create circuits here.
            metrics::record_frame_dropped(metrics::DropReason::NotOpen);
            Ok(())
        }
        link_frame::LinkCommand::Padding => {
            // Accepted and ignored. decode already required its body to be zero.
            Ok(())
        }
    }
}

/// Handle a CREATE: verify the token on a client link, complete the handshake,
/// insert the circuit and start its task.
async fn open_inbound_circuit(
    shared: &Arc<LinkShared>,
    id: CircId,
    body: &[u8],
    layers: Layers,
    peer: SocketAddr,
    role: Role,
    ctx: &ConnCtx,
) -> Result<(), HandleError> {
    // A guard's inbound link is from a client and carries the token per create,
    // so one token buys one circuit. A relay link carries the handshake alone.
    let msg1_bytes = if role == Role::Guard {
        let payload = link_frame::payload(body, link_frame::CREATE_CLIENT_BODY_LEN)?;
        let (presentation, msg1) = payload.split_at(PRESENTATION_LEN);
        let m_raw = &presentation[..M_RAW_LEN];
        let token_bytes = &presentation[M_RAW_LEN..];
        if let Err(e) = token::verify(m_raw, token_bytes, ctx.authority.pubkey(), &ctx.replay) {
            metrics::record_rejected(&e);
            return Err(HandleError::Token(e));
        }
        metrics::record_verified();
        msg1
    } else {
        link_frame::payload(body, link_frame::CREATE_RELAY_BODY_LEN)?
    };

    let mut msg1 = [0u8; NOISE_MSG_LEN];
    msg1.copy_from_slice(msg1_bytes);
    let (transport, msg2) = match noise::respond(ctx.static_key.private(), &msg1) {
        Ok(pair) => pair,
        Err(_) => return Err(HandleError::Handshake),
    };

    // The relay-wide budget is checked here and nowhere else. A circuit
    // already open keeps its full queue allowance whatever the total reaches,
    // so what this bounds is growth (ARCHITECTURE 5.9).
    if !shared.budget.may_admit(ctx.cfg.max_link_buffer_bytes) {
        metrics::record_frame_dropped(metrics::DropReason::BufferBudget);
        send_destroy(shared, id, layers, DestroyReason::Resource);
        return Ok(());
    }

    let (tx, rx) = mpsc::channel::<link::Queued>(link::MAX_CIRCUIT_QUEUE);
    let (destroy_tx, destroy_rx) = watch::channel(false);
    {
        let mut st = shared.lock();
        match st.table.accept_create(id, transport, Instant::now()) {
            Ok(()) => {
                st.handles.insert(
                    id,
                    CircuitHandle {
                        frames: tx,
                        destroy: destroy_tx,
                    },
                );
            }
            Err(link::CreateRefusal::Collision) => {
                // Silence. A DESTROY naming this id would be read as the live
                // circuit being torn down, so any peer could end any circuit by
                // sending a CREATE for its id (DECISIONS 22).
                drop(st);
                metrics::record_frame_dropped(metrics::DropReason::CreateCollision);
                return Ok(());
            }
            Err(link::CreateRefusal::Quarantined) => {
                drop(st);
                metrics::record_frame_dropped(metrics::DropReason::CreateQuarantined);
                return Ok(());
            }
            Err(link::CreateRefusal::LinkFull) => {
                drop(st);
                metrics::record_frame_dropped(metrics::DropReason::LinkFull);
                send_destroy(shared, id, layers, DestroyReason::Resource);
                return Ok(());
            }
        }
    }

    // The transport went into the table on accept_create; take it back out for
    // the task, which is the only place it is used.
    let transport = {
        let mut st = shared.lock();
        st.table.get_mut(id).and_then(|c| c.transport.take())
    };
    let Some(transport) = transport else {
        shared.forget(id);
        return Err(HandleError::Handshake);
    };

    let created = link_frame::encode(layers, id, link_frame::LinkCommand::Created, &msg2)?;
    if shared.push_out(id, created).is_err() {
        shared.forget(id);
        return Ok(());
    }

    let task_shared = shared.clone();
    let task_ctx = ctx.clone();
    tokio::spawn(async move {
        let id_for_log = id.raw();
        if let Err(e) = run_circuit(
            &task_shared,
            id,
            transport,
            rx,
            destroy_rx,
            layers,
            role,
            task_ctx,
        )
        .await
        {
            warn!(circ_id = id_for_log, error = %e, "circuit ended with an error");
        }
        task_shared.forget(id);
    });
    let on_link = shared.lock().table.len();
    info!(
        peer = %peer,
        role = %role,
        circ_id = id.raw(),
        circuits_on_link = on_link,
        "circuit open"
    );
    Ok(())
}

/// Queue a DESTROY for `id` without touching the circuit table.
///
/// It goes on the link's control queue, not the circuit's. The two callers
/// both destroy or refuse the circuit immediately afterwards, so a frame left
/// in the circuit's queue would be discarded with it and the peer would be
/// told nothing.
fn send_destroy(shared: &Arc<LinkShared>, id: CircId, layers: Layers, reason: DestroyReason) {
    if let Ok(frame) = link_frame::encode(
        layers,
        id,
        link_frame::LinkCommand::Destroy,
        &[reason as u8],
    ) {
        if !shared.push_control(frame) {
            // The peer has not read MAX_CONTROL_QUEUE control frames, so the
            // link is already dead. Dropping this DESTROY would leave the peer
            // believing every circuit it names is alive. Closing the link
            // releases them all on both sides and the peer sees a link loss
            // (DECISIONS 23).
            metrics::record_frame_dropped(metrics::DropReason::ControlQueueFull);
            warn!(
                circ_id = id.raw(),
                "the link control queue filled, so the link is being closed"
            );
            shared.request_close();
        }
    }
}

/// Destroy a circuit this side is ending: tell the peer, end the task.
fn destroy_circuit(shared: &Arc<LinkShared>, id: CircId, layers: Layers, reason: DestroyReason) {
    send_destroy(shared, id, layers, reason);
    shared.forget(id);
}

/// The reason this side names upstream when it ends a circuit.
///
/// Separate from the teardown so it can be asserted directly: the mapping is
/// the part a reader has to trust and the part a mutant would change.
fn destroy_reason_for_outcome(result: &Result<(), HandleError>) -> DestroyReason {
    match result {
        Err(HandleError::Flow(e)) => link::destroy_reason_for(e),
        Err(HandleError::Layer(_)) | Err(HandleError::Cell(_)) | Err(HandleError::LinkFrame(_)) => {
            DestroyReason::Protocol
        }
        Err(HandleError::IllegalCellForRole(_, _)) => DestroyReason::Protocol,
        // The next hop stopped reading, which is a link loss toward it.
        Err(HandleError::WriteTimeout) => DestroyReason::LinkLost,
        // The destination stopped reading. Not Protocol, the peer did nothing
        // wrong, and not Resource, which would say the relay is out of capacity
        // when tearing down is what frees it (ARCHITECTURE 5.11).
        Err(HandleError::DestWriteTimeout) => DestroyReason::Internal,
        // A full per-circuit queue means the peer exceeded its window.
        Err(HandleError::PeerPastItsWindow) => DestroyReason::Protocol,
        Err(HandleError::PeerClosed) => DestroyReason::Requested,
        // Both are returned above, before a reason is chosen here.
        Err(HandleError::DestroyedByPeer) | Err(HandleError::DestroyedByNextHop) => {
            DestroyReason::Destroyed
        }
        Err(_) => DestroyReason::Internal,
        Ok(()) => DestroyReason::Requested,
    }
}

/// One circuit's traffic: inbound frames, the next hop, the destination.
///
/// Replaces run_circuit_io, which held the only circuit on a connection. The
/// shape is the same three branch select; what changed is that inbound frames
/// arrive on a channel and outbound frames go to a per-circuit queue.
// The arguments are this circuit's own state: its id, its transport, its two
// inbound channels, its layer count and its role. Grouping them into a struct
// would hide which of them the task takes ownership of.
#[allow(clippy::too_many_arguments)]
async fn run_circuit(
    shared: &Arc<LinkShared>,
    id: CircId,
    mut transport: Transport,
    mut rx: mpsc::Receiver<link::Queued>,
    mut destroy_rx: watch::Receiver<bool>,
    layers: Layers,
    role: Role,
    ctx: ConnCtx,
) -> Result<(), HandleError> {
    /// What the next hop did, so one future covers both of its channels.
    enum NextEvent {
        Destroyed,
        /// The link ended because a write to it made no progress, so this
        /// circuit forwards DESTROY upstream with LinkLost rather than the
        /// Requested a normal close would give (ARCHITECTURE 5.11).
        LinkLost,
        LinkGone,
        Frame(link::Queued),
    }

    let mut next_link: Option<NextLinkState> = None;
    let mut dest_link: Option<TcpStream> = None;
    let out_layers = outbound_layers(role);

    // The loop body lives in an async block so that `?` inside it ends the
    // loop rather than the function. Returning straight out of run_circuit
    // would skip the teardown below, and with it the DESTROY this side owes
    // its peer for a protocol violation (SECURITY_MODEL 6.4).
    let result: Result<(), HandleError> = async {
        loop {
        tokio::select! {
            biased;
            // First, so a destroyed circuit stops forwarding at the next turn
            // of the loop rather than after the queue behind it drains.
            changed = destroy_rx.changed() => {
                match changed {
                    // The reader saw a DESTROY for this circuit.
                    Ok(()) if *destroy_rx.borrow_and_update() => {
                        break Err(HandleError::DestroyedByPeer);
                    }
                    // Every handle went, so the link did.
                    _ => break Err(HandleError::PeerClosed),
                }
            }
            msg = rx.recv() => {
                let Some(wire) = msg else {
                    // The link went or the reader dropped the sender.
                    break Err(HandleError::PeerClosed);
                };
                let wire = wire.take();
                match layer::peel(&mut transport, &wire, layers)? {
                    layer::Peeled::Forward(blob) => {
                        let nl = next_link
                            .as_mut()
                            .ok_or(HandleError::ForwardWithoutNextLink(role))?;
                        let out = out_layers.ok_or(HandleError::ForwardWithoutNextLink(role))?;
                        let framed =
                            link_frame::encode(out, nl.circ_id, link_frame::LinkCommand::Data, &blob)?;
                        // Onto the shared link's queue for this circuit. The
                        // link's own writer drains it, bounded by
                        // CELL_WRITE_TIMEOUT, and a stall there closes the link
                        // and releases every circuit on it (ARCHITECTURE 5.10).
                        if nl.link.link.shared.push_out(nl.circ_id, framed).is_err() {
                            // A per-circuit queue can only fill if the upstream
                            // peer sent past its window: the end to end window
                            // allows 1010 frames in steady state against a 1024
                            // slot queue (docs/DECISIONS.md entry 31). A stalled
                            // next hop is the other case and is caught by the
                            // link's write timeout, not here.
                            break Err(HandleError::PeerPastItsWindow);
                        }
                    }
                    layer::Peeled::ToMe(cell) => match (cell.cell_type, role) {
                        (CellType::Extend, Role::Guard) | (CellType::Extend, Role::Middle) => {
                            if next_link.is_some() {
                                break Err(HandleError::IllegalCellForRole(CellType::Extend, role));
                            }
                            let extend = ExtendForward::decode(&cell.payload)?;
                            let out = out_layers.ok_or(
                                HandleError::IllegalCellForRole(CellType::Extend, role),
                            )?;
                            let (nl, noise_msg2) =
                                extend_to_next_hop(&extend, &ctx, out).await?;
                            let reply = Cell::new(
                                CellType::Extend,
                                cell::extend_backward_payload(&noise_msg2),
                            )?;
                            let framed = layer::seal_to_me(&mut transport, &reply, layers)?;
                            if queue_or_end(shared, id, layers, framed).is_err() {
                                break Err(HandleError::PeerClosed);
                            }
                            next_link = Some(nl);
                        }
                        (CellType::Connect, Role::Exit) => {
                            if dest_link.is_some() {
                                break Err(HandleError::IllegalCellForRole(CellType::Connect, role));
                            }
                            let payload = ConnectPayload::decode(&cell.payload)?;
                            publish_connect_for_test(&payload);
                            let proxy_url = ctx
                                .cfg
                                .decodo_proxy_url
                                .as_deref()
                                .ok_or(HandleError::MissingDecodoUrl)?;
                            let dest = exit::dial_via_socks5(
                                proxy_url,
                                &payload.host,
                                payload.port,
                                &ctx.cfg.allowed_exit_ports,
                            )
                            .await?;
                            info!(role = %role, circ_id = id.raw(), "exit dialed destination via SOCKS5");
                            dest_link = Some(dest);
                        }
                        (CellType::Data, Role::Exit) => {
                            // Flow control is end to end between the client and
                            // the exit, so only the exit's windows engage: a
                            // middle forwards and never originates or consumes
                            // (SECURITY_MODEL 6.4).
                            if let Some(outcome) = shared.on_data_delivered(id) {
                                match outcome? {
                                    AfterDelivery::SendmeOwed => {
                                        let sendme = Cell::new(CellType::Sendme, Vec::new())?;
                                        let framed =
                                            layer::seal_to_me(&mut transport, &sendme, layers)?;
                                        if queue_or_end(shared, id, layers, framed).is_err() {
                                            break Err(HandleError::PeerClosed);
                                        }
                                        shared.on_sendme_sent(id);
                                    }
                                    AfterDelivery::Nothing => {}
                                }
                            }
                            // A zero length DATA cell is legal and is a no-op,
                            // which is what cover traffic will use. It still
                            // counts against the window above.
                            if cell.payload.is_empty() {
                                continue;
                            }
                            let dl = dest_link
                                .as_mut()
                                .ok_or(HandleError::IllegalCellForRole(CellType::Data, role))?;
                            if let Err(e) = write_to_destination(dl, &cell.payload).await {
                                break Err(e);
                            }
                        }
                        (CellType::Sendme, Role::Exit) => {
                            // An unowed SENDME is a protocol violation and the
                            // circuit goes, rather than the window being capped
                            // (SECURITY_MODEL 6.4, Tor parity).
                            if let Some(outcome) = shared.on_sendme_received(id) {
                                outcome?;
                            }
                        }
                        (CellType::CloseRequest, _) => {
                            let ack = Cell::new(CellType::CloseAck, Vec::new())?;
                            let framed = layer::seal_to_me(&mut transport, &ack, layers)?;
                            let _ = queue_or_end(shared, id, layers, framed);
                            forward_destroy(&mut next_link);
                            drop(dest_link.take());
                            return Ok(());
                        }
                        (CellType::CloseAck, _) => break Err(HandleError::PeerClosed),
                        (t, r) => break Err(HandleError::IllegalCellForRole(t, r)),
                    },
                }
            }

            // The next hop destroyed this circuit. First, so it does not wait
            // behind frames already queued for this circuit.
            // One future over the next hop, so `next_link` is borrowed once.
            // The destroy signal is first inside it, so it does not wait behind
            // frames already queued for this circuit.
            event = async {
                let Some(nl) = next_link.as_mut() else {
                    return std::future::pending().await;
                };
                tokio::select! {
                    biased;
                    changed = nl.destroy.changed() => match changed {
                        Ok(()) if *nl.destroy.borrow_and_update() => NextEvent::Destroyed,
                        _ => NextEvent::LinkGone,
                    },
                    frame = nl.frames.recv() => match frame {
                        Some(q) => NextEvent::Frame(q),
                        None if nl.link.link.shared.closing() => NextEvent::LinkLost,
                        None => NextEvent::LinkGone,
                    },
                }
            } => {
                let queued = match event {
                    NextEvent::Destroyed => break Err(HandleError::DestroyedByNextHop),
                    NextEvent::LinkLost => break Err(HandleError::WriteTimeout),
                    NextEvent::LinkGone => break Err(HandleError::PeerClosed),
                    NextEvent::Frame(q) => q,
                };
                let wire = queued.take();
                let out = out_layers.ok_or(HandleError::ForwardWithoutNextLink(role))?;
                // This side opened the downstream link, so it is the initiator
                // there and the peer answers from the other half.
                let back = link_frame::decode(&wire, out, LinkRole::Responder)?;
                match back.command {
                    link_frame::LinkCommand::Data => {
                        let framed = layer::seal_forward(&mut transport, back.body, layers)?;
                        if queue_or_end(shared, id, layers, framed).is_err() {
                            break Err(HandleError::PeerClosed);
                        }
                    }
                    link_frame::LinkCommand::Destroy => {
                        // The next hop ended the circuit. Its reason is never
                        // propagated, so the DESTROY this side sends upstream
                        // carries DESTROYED like any other forwarded one.
                        break Err(HandleError::DestroyedByNextHop);
                    }
                    _ => {
                        metrics::record_frame_dropped(metrics::DropReason::NotOpen);
                    }
                }
            }

            res = async {
                // The window is the backpressure. With the package window at
                // zero this branch is pending, so the relay stops reading the
                // destination until a SENDME arrives rather than buffering
                // without bound (SECURITY_MODEL 6.4).
                match dest_link.as_mut() {
                    Some(dl) if shared.may_send(id) => {
                        let mut buf = vec![0u8; DEST_READ_BUF];
                        let n = dl.read(&mut buf).await?;
                        buf.truncate(n);
                        Ok::<_, std::io::Error>(buf)
                    }
                    _ => std::future::pending().await,
                }
            } => {
                let bytes = res?;
                if bytes.is_empty() {
                    drop(dest_link.take());
                    continue;
                }
                for chunk in bytes.chunks(cell::CELL_PAYLOAD_LEN) {
                    if let Some(outcome) = shared.on_data_sent(id) {
                        outcome?;
                    }
                    let data_cell = Cell::new(CellType::Data, chunk.to_vec())?;
                    let framed = layer::seal_to_me(&mut transport, &data_cell, layers)?;
                    if queue_or_end(shared, id, layers, framed).is_err() {
                        break;
                    }
                }
            }
        }
        }
    }
    .await;

    // This side is ending the circuit, so it names its own reason upstream and
    // forwards DESTROYED downstream.
    // Every violation a peer can cause maps to Protocol: a frame that does not
    // parse, a cell that does not decode, a layer that does not peel, and every
    // FlowError through destroy_reason_for (SECURITY_MODEL 6.4).
    // The peer destroyed this circuit, so it already knows. Forward DESTROYED
    // downstream, discard anything still queued by dropping the receiver, and
    // send nothing back upstream (SECURITY_MODEL 6.3). Before this was its own
    // outcome, the branch returned Ok and fell through to the send below, which
    // answered the peer with a DESTROY carrying Requested.
    if matches!(result, Err(HandleError::DestroyedByPeer)) {
        forward_destroy(&mut next_link);
        return Ok(());
    }

    // The next hop destroyed it, so the same rule applies in the other
    // direction: DESTROYED upstream, never the reason that arrived, and nothing
    // downstream because that link is the one that ended.
    if matches!(result, Err(HandleError::DestroyedByNextHop)) {
        send_destroy(shared, id, layers, DestroyReason::Destroyed);
        drop(next_link.take());
        return Ok(());
    }

    let reason = destroy_reason_for_outcome(&result);
    send_destroy(shared, id, layers, reason);
    forward_destroy(&mut next_link);
    result
}

/// Wrap one outbound frame for this circuit, or report that the circuit is gone.
fn queue_or_end(
    shared: &Arc<LinkShared>,
    id: CircId,
    layers: Layers,
    body: Vec<u8>,
) -> Result<(), link::QueueFull> {
    let frame = link_frame::encode(layers, id, link_frame::LinkCommand::Data, &body)
        .map_err(|_| link::QueueFull::NoCircuit)?;
    shared.push_out(id, frame)
}

/// Forward DESTROY to the next hop, always with DESTROYED.
///
/// tor-spec: "Reasons in DESTROY cell SHOULD NOT be propagated downward or
/// upward, due to potential side channel risk", and "An OR receiving a DESTROY
/// command should use the DESTROYED reason for its next cell."
fn forward_destroy(next_link: &mut Option<NextLinkState>) {
    let Some(nl) = next_link.take() else {
        return;
    };
    // On the shared link's control queue, not this circuit's, because the
    // circuit is going and its queue goes with it (docs/DECISIONS.md entry 23).
    // Dropping nl releases the reservation, so the link can go idle.
    send_destroy(
        &nl.link.link.shared,
        nl.circ_id,
        nl.link.link.layers,
        DestroyReason::Destroyed,
    );
}

struct NextLinkState {
    link: OutboundShared,
    /// Keeps this circuit counted on the shared link. Dropping it releases the
    /// count, which is how a circuit that ends lets the link go idle.
    _reservation: linkreg::Reservation<OutboundLink>,
    /// The id this side chose for the circuit on the shared link.
    circ_id: CircId,
    /// Frames from the next hop for this circuit, whole, so the circuit decides
    /// whether it is waiting for CREATED or carrying DATA.
    frames: mpsc::Receiver<link::Queued>,
    /// Raised when the next hop destroys this circuit, out of band so it cannot
    /// wait behind queued data (docs/DECISIONS.md entry 25).
    destroy: watch::Receiver<bool>,
}

/// Put this circuit on the shared link to its next hop, opening that link if
/// nobody has yet, and courier the client's handshake over it.
///
/// This relay is not a party to that handshake. It cannot read either message,
/// and the next hop authenticates to the client, not to this relay.
async fn extend_to_next_hop(
    extend: &ExtendForward,
    ctx: &ConnCtx,
    frame_layers: Layers,
) -> Result<(NextLinkState, [u8; NOISE_MSG_LEN]), HandleError> {
    // The next hop must be published for the role directly downstream of this
    // one, at exactly this address and port, and its SNI is the name the
    // registry carries for it. Nothing here comes from configuration.
    let (relay_id, addr, tls_name) = {
        let doc = ctx
            .registry
            .usable(now_unix())
            .ok_or(HandleError::PeerHostnameMissing(extend.next_hop))?;
        let entry = registry::extend_target(&doc, ctx.cfg.role, extend.next_hop)
            .ok_or(HandleError::PeerHostnameMissing(extend.next_hop))?;
        (entry.id.clone(), extend.next_hop, entry.tls_name.clone())
    };

    let key = linkreg::LinkKey {
        relay_id,
        addr,
        tls_name: tls_name.clone(),
    };
    let cap = ctx.cfg.max_circuits_per_relay_link as usize;
    let connector = ctx.connector.clone();
    let budget = ctx.budget.clone();

    let acquired = ctx
        .links
        .acquire(key, cap, move || async move {
            dial_outbound_link(&connector, addr, &tls_name, frame_layers, &budget).await
        })
        .await
        .map_err(HandleError::NextHop)?;

    // Only the caller that dialed may start the link's own task, because only
    // it can take the read half out of the payload.
    if acquired.dialed {
        info!(addr = %addr, links = ctx.links.len(), "outbound link opened");
        tokio::spawn(run_outbound_link(ctx.links.clone(), acquired.link.clone()));
    }

    let shared = acquired.link.link.shared.clone();
    let (circ_id, mut frames, destroy) = shared
        .open_outbound_circuit(cap)
        .ok_or(HandleError::NextHop(linkreg::AcquireError::LinkFull))?;

    let create = link_frame::encode(
        frame_layers,
        circ_id,
        link_frame::LinkCommand::Create,
        &extend.noise_msg1,
    )?;
    if shared.push_out(circ_id, create).is_err() {
        shared.forget(circ_id);
        return Err(HandleError::Handshake);
    }

    let wire = match tokio::time::timeout(HANDSHAKE_READ_TIMEOUT, frames.recv()).await {
        Ok(Some(w)) => w.take(),
        // The link went, or the hop never answered.
        _ => {
            shared.forget(circ_id);
            return Err(HandleError::Handshake);
        }
    };
    let back = link_frame::decode(&wire, frame_layers, LinkRole::Responder)?;
    if back.command != link_frame::LinkCommand::Created || back.circ_id != circ_id {
        shared.forget(circ_id);
        return Err(HandleError::Handshake);
    }
    let mut noise_msg2 = [0u8; NOISE_MSG_LEN];
    noise_msg2.copy_from_slice(link_frame::payload(back.body, NOISE_MSG_LEN)?);

    // No transport here: this hop's session belongs to the client and this
    // relay only couriers the handshake, so the phase moves to Open with none.
    shared.lock().table.open_pending(circ_id, None);

    Ok((
        NextLinkState {
            link: acquired.link,
            _reservation: acquired.reservation,
            circ_id,
            frames,
            destroy,
        },
        noise_msg2,
    ))
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

    /// The outbound link carries one layer fewer than the inbound one, because
    /// this hop peeled its own.
    ///
    /// This used to also assert the value was not in byte range, which was the
    /// best a `usize` allowed. `Layers` makes that unrepresentable, so what is
    /// left to check is the arithmetic.
    #[test]
    fn an_outbound_link_carries_one_layer_fewer() {
        assert_eq!(outbound_layers(Role::Guard), Some(Layers::new(2)));
        assert_eq!(outbound_layers(Role::Middle), Some(Layers::new(1)));
        assert_eq!(
            outbound_layers(Role::Exit),
            None,
            "an exit has no next hop to carry layers for"
        );
        for role in [Role::Guard, Role::Middle] {
            let out = outbound_layers(role).expect("a relay role has a next hop");
            assert_eq!(out, inbound_layers(role).peeled());
        }
    }

    /// The control queue takes its bound and refuses one past it. The writer
    /// is never blocked and the reader is never blocked, so the only thing a
    /// full queue can do is refuse, and the caller counts the refusal.
    #[test]
    fn the_control_queue_fills_at_its_bound_and_refuses_past_it() {
        let shared = Arc::new(LinkShared::new(LinkRole::Responder, link::Budget::new()));
        for i in 0..link::MAX_CONTROL_QUEUE {
            assert!(
                shared.push_control(vec![i as u8]),
                "control frame {i} within the bound was refused"
            );
        }
        assert!(
            !shared.push_control(vec![0xFF]),
            "the bound did not hold at one past MAX_CONTROL_QUEUE"
        );
        assert_eq!(shared.lock().control.len(), link::MAX_CONTROL_QUEUE);
    }

    /// At the bound the link carries on. Nothing has gone wrong yet: 64
    /// control frames queued is a peer that is behind, not a peer that is gone.
    #[test]
    fn the_control_queue_at_its_bound_does_not_close_the_link() {
        let shared = Arc::new(LinkShared::new(LinkRole::Responder, link::Budget::new()));
        for i in 0..link::MAX_CONTROL_QUEUE {
            assert!(shared.push_control(vec![i as u8]));
        }
        assert!(
            !shared.closing(),
            "the link closed at the bound rather than past it"
        );
    }

    /// One past the bound the link closes. A peer that has not read 64 control
    /// frames is gone, and dropping this DESTROY would leave it believing the
    /// circuits those frames name are still alive (DECISIONS 23).
    #[test]
    fn a_refused_destroy_closes_the_link_and_is_counted() {
        let shared = Arc::new(LinkShared::new(LinkRole::Responder, link::Budget::new()));
        let id = CircId::new(0x4000_0002).expect("a nonzero id");
        for i in 0..link::MAX_CONTROL_QUEUE {
            assert!(shared.push_control(vec![i as u8]));
        }
        let before = metrics::dropped_count("control_queue_full");
        send_destroy(&shared, id, Layers::new(3), DestroyReason::Protocol);

        assert!(
            shared.closing(),
            "a DESTROY was refused and the link was left open"
        );
        assert_eq!(
            metrics::dropped_count("control_queue_full"),
            before + 1,
            "a DESTROY did not reach the peer without the counter moving"
        );
        assert_eq!(shared.lock().control.len(), link::MAX_CONTROL_QUEUE);
    }

    /// Closing the link releases every circuit on it and quarantines each id,
    /// which is what a link loss does. A reconnecting peer must not be able to
    /// reach for an id this side has just let go.
    #[test]
    fn closing_the_link_releases_every_circuit_and_quarantines_its_id() {
        let shared = Arc::new(LinkShared::new(LinkRole::Responder, link::Budget::new()));
        let ids: Vec<CircId> = (1..=3)
            .map(|i| CircId::new(0x4000_0010 + i).expect("a nonzero id"))
            .collect();
        {
            let mut st = shared.lock();
            for id in &ids {
                st.table
                    .accept_create(*id, test_transport(), Instant::now())
                    .expect("room on the link");
            }
        }
        assert_eq!(shared.lock().table.len(), ids.len());

        assert_eq!(shared.release_all(), ids.len());

        let now = Instant::now();
        let st = shared.lock();
        assert_eq!(st.table.len(), 0, "a circuit survived the link closing");
        assert!(st.handles.is_empty());
        for id in &ids {
            assert!(
                st.table.quarantined(*id, now),
                "{:#010x} was released without being quarantined",
                id.raw()
            );
        }
    }

    /// Draining one frame makes room for exactly one more, so a refusal is
    /// backpressure rather than a permanent close.
    #[test]
    fn a_drained_control_frame_frees_one_slot() {
        let shared = Arc::new(LinkShared::new(LinkRole::Responder, link::Budget::new()));
        for i in 0..link::MAX_CONTROL_QUEUE {
            assert!(shared.push_control(vec![i as u8]));
        }
        assert_eq!(
            shared.pop_next_out(),
            Some(vec![0]),
            "control drains in order"
        );
        assert!(
            shared.push_control(vec![0xFF]),
            "the freed slot was not reusable"
        );
        assert!(
            !shared.push_control(vec![0xFE]),
            "the bound stopped holding"
        );
    }

    /// Control frames go out ahead of circuit data, because a DESTROY is owed
    /// to the peer while the circuit it names is already gone.
    #[test]
    fn control_frames_precede_circuit_data() {
        let shared = Arc::new(LinkShared::new(LinkRole::Responder, link::Budget::new()));
        let id = CircId::new(0x4000_0001).expect("a nonzero id");
        {
            let mut st = shared.lock();
            st.table
                .accept_create(id, test_transport(), Instant::now())
                .expect("room on the link");
        }
        shared.push_out(id, vec![b'd']).expect("queue data");
        assert!(shared.push_control(vec![b'c']));
        assert_eq!(shared.pop_next_out(), Some(vec![b'c']));
        assert_eq!(shared.pop_next_out(), Some(vec![b'd']));
        assert_eq!(shared.pop_next_out(), None);
    }

    use std::future::Future;

    /// A writer that never takes a byte, which is what a peer that has stopped
    /// reading looks like from here.
    struct StalledWriter;

    impl tokio::io::AsyncWrite for StalledWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Pending
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// A writer that takes the bytes once a delay has passed, so the test can
    /// put the delay either side of the deadline.
    struct SlowWriter {
        delay: std::pin::Pin<Box<tokio::time::Sleep>>,
        ready: bool,
    }

    impl SlowWriter {
        fn after(d: Duration) -> Self {
            Self {
                delay: Box::pin(tokio::time::sleep(d)),
                ready: false,
            }
        }
    }

    impl tokio::io::AsyncWrite for SlowWriter {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if !self.ready {
                match self.delay.as_mut().poll(cx) {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(()) => self.ready = true,
                }
            }
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// A write that makes no progress closes the link once the deadline passes.
    ///
    /// Time is paused, so the 120 seconds are accounted and not waited for.
    #[tokio::test(start_paused = true)]
    async fn a_write_that_never_progresses_closes_the_link() {
        let shared = Arc::new(LinkShared::new(LinkRole::Responder, link::Budget::new()));
        assert!(shared.push_control(vec![0xAA; 8]));
        assert!(!shared.closing(), "nothing has stalled yet");

        // The budget is the assertion, not a hang: without the write timeout
        // run_link_writer never returns, and this reports that as a failure
        // rather than stopping the suite.
        let ended = tokio::time::timeout(
            CELL_WRITE_TIMEOUT * 3,
            run_link_writer(shared.clone(), StalledWriter),
        )
        .await;

        assert!(
            ended.is_ok(),
            "the writer never gave up on a write that made no progress"
        );
        assert!(
            shared.closing(),
            "a write that never progressed left the link open"
        );
    }

    /// Every byte queued on a shared outbound link is counted, and the count
    /// returns to zero when the queues drain.
    ///
    /// Both structures a frame can wait in are covered: the per-circuit queue
    /// and the link level control queue. The control queue was missed on the
    /// first pass, which would have left the budget covering the per-circuit
    /// queues and not these, and the number of inbound links is not bounded
    /// (docs/DECISIONS.md entry 31).
    #[test]
    fn every_byte_queued_on_an_outbound_link_is_counted() {
        const FRAME: usize = 547;
        const PER_CIRCUIT: usize = 6;
        const CONTROL: usize = 4;

        let budget = link::Budget::new();
        let shared = Arc::new(LinkShared::new(LinkRole::Initiator, budget.clone()));
        let ids: Vec<CircId> = (1..=3)
            .map(|i| CircId::new(0x8000_0300 + i).expect("a nonzero id"))
            .collect();
        {
            let mut st = shared.lock();
            for id in &ids {
                st.table
                    .accept_create(*id, test_transport(), Instant::now())
                    .expect("room on the link");
            }
        }
        assert_eq!(budget.held(), 0, "an empty link holds nothing");

        for id in &ids {
            for _ in 0..PER_CIRCUIT {
                shared
                    .push_out(*id, vec![0u8; FRAME])
                    .expect("room in the queue");
            }
        }
        let circuit_bytes = (ids.len() * PER_CIRCUIT * FRAME) as u64;
        assert_eq!(
            budget.held(),
            circuit_bytes,
            "the per-circuit queues are not counted exactly"
        );

        for _ in 0..CONTROL {
            assert!(shared.push_control(vec![0u8; FRAME]));
        }
        assert_eq!(
            budget.held(),
            circuit_bytes + (CONTROL * FRAME) as u64,
            "the control queue is not counted"
        );

        // Draining hands the bytes out and releases them.
        let mut drained = 0;
        while shared.pop_next_out().is_some() {
            drained += 1;
        }
        assert_eq!(drained, ids.len() * PER_CIRCUIT + CONTROL);
        assert_eq!(
            budget.held(),
            0,
            "the counter did not return to zero, so queued bytes leaked"
        );
    }

    /// Winding up an outbound link marks it closing before its circuits see
    /// their channels close, which is what lets them name LinkLost.
    ///
    /// Without the order, a circuit sees a closed channel on a link that is not
    /// marked and reports Requested, which says the peer asked when the truth
    /// is the link stalled.
    #[test]
    fn ending_an_outbound_link_marks_it_before_releasing_its_circuits() {
        let shared = Arc::new(LinkShared::new(LinkRole::Initiator, link::Budget::new()));
        let id = CircId::new(0x8000_0400).expect("a nonzero id");
        let rx = {
            let mut st = shared.lock();
            st.table
                .accept_create(id, test_transport(), Instant::now())
                .expect("room on the link");
            let (tx, rx) = mpsc::channel::<link::Queued>(4);
            let (dtx, _drx) = watch::channel(false);
            st.handles.insert(
                id,
                CircuitHandle {
                    frames: tx,
                    destroy: dtx,
                },
            );
            rx
        };
        assert!(!shared.closing());

        let released = end_outbound_link(&shared);

        assert_eq!(released, 1, "the circuit was not released");
        assert!(
            shared.closing(),
            "the link was not marked closing, so its circuits cannot tell a stalled \
             link from an ordinary close and would report Requested instead of LinkLost"
        );
        assert!(
            rx.is_closed(),
            "the circuit's channel outlived the link, so it would never notice"
        );
    }

    /// A stalled shared outbound link closes and releases every circuit on it.
    ///
    /// The writer gives up on a peer that takes no bytes, raises the link's
    /// close, and the link's own task releases its circuits. Each of those
    /// circuits then sees its channel close on a link marked closing, which is
    /// what makes it name LinkLost upstream rather than the Requested an
    /// ordinary close gives (ARCHITECTURE 5.11).
    #[tokio::test(start_paused = true)]
    async fn a_stalled_outbound_link_closes_and_releases_its_circuits() {
        let shared = Arc::new(LinkShared::new(LinkRole::Initiator, link::Budget::new()));
        let ids: Vec<CircId> = (1..=3)
            .map(|i| CircId::new(0x8000_0200 + i).expect("a nonzero id"))
            .collect();
        {
            let mut st = shared.lock();
            for id in &ids {
                st.table
                    .accept_create(*id, test_transport(), Instant::now())
                    .expect("room on the link");
            }
        }
        // Something to write, so the writer reaches the stalled socket.
        shared.push_out(ids[0], vec![0xEE; 8]).expect("queue");
        assert_eq!(shared.lock().table.len(), 3);
        assert!(!shared.closing());

        let ended = tokio::time::timeout(
            CELL_WRITE_TIMEOUT * 3,
            run_link_writer(shared.clone(), StalledWriter),
        )
        .await;
        assert!(ended.is_ok(), "the writer never gave up on a stalled peer");
        assert!(
            shared.closing(),
            "a stalled outbound write left the link open"
        );

        // What the link's own task then does: release everything.
        let released = shared.release_all();
        assert_eq!(released, 3, "every circuit on the link must be released");
        assert_eq!(shared.lock().table.len(), 0);
        let now = Instant::now();
        for id in &ids {
            assert!(
                shared.lock().table.quarantined(*id, now),
                "{:#010x} was released without being quarantined",
                id.raw()
            );
        }
    }

    /// Find every socket write in one source that carries no bounded marker.
    ///
    /// The three tokens are methods of `AsyncWrite` and `AsyncWriteExt`, which
    /// is why a refactor cannot slip past this: renaming a variable, a field, a
    /// helper or a type leaves the method name alone, because the name belongs
    /// to the trait and not to this code. Writing to a socket without one of
    /// them means implementing `poll_write` by hand.
    ///
    /// Shared by the check and its control, so the control exercises the same
    /// code the check runs (docs/DECISIONS.md entry 30).
    fn unbounded_writes(name: &str, src: &str) -> Vec<String> {
        // Assembled at runtime so this never matches its own source.
        let tokens = [
            ["write", "_all("].concat(),
            ["flush", "()"].concat(),
            ["shutdown", "()"].concat(),
        ];
        let marker = ["bounded", ":"].concat();

        // Test code writes freely and bounding it would prove nothing, so the
        // scan stops where the test module starts.
        let code = match src.find("\nmod tests {") {
            Some(at) => &src[..at],
            None => src,
        };
        let lines: Vec<&str> = code.lines().collect();
        let mut out = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            if !tokens.iter().any(|t| line.contains(t.as_str())) {
                continue;
            }
            let above = i.checked_sub(1).map(|j| lines[j]).unwrap_or("");
            if line.contains(&marker) || above.contains(&marker) {
                continue;
            }
            out.push(format!("{name}:{} {}", i + 1, line.trim()));
        }
        out
    }

    /// No socket write or flush anywhere in the relay is unbounded.
    ///
    /// The previous version searched for one literal, `write.write_all`, and
    /// missed the exit's write to its destination, the protocol byte on a new
    /// outbound connection, the three writes in the port 80 redirect and the
    /// unbounded dial. An empty result here is only worth something because of
    /// the control below.
    #[test]
    fn no_socket_write_is_unbounded() {
        let sources: [(&str, &str); 3] = [
            ("main.rs", include_str!("main.rs")),
            ("port80.rs", include_str!("port80.rs")),
            ("tls.rs", include_str!("tls.rs")),
        ];
        let mut unbounded = Vec::new();
        for (name, src) in sources {
            unbounded.extend(unbounded_writes(name, src));
        }
        assert!(
            unbounded.is_empty(),
            "these socket writes carry no bounded marker: {unbounded:#?}"
        );
    }

    /// The check catches each of the eight writes the relay actually has, one
    /// at a time, in the shape each one has in the source.
    ///
    /// Eight, not the two that were reported: the exit's two to its
    /// destination, the protocol byte and its flush, the port 80 pair and its
    /// shutdown, and the shutdown that rejects an unexpected protocol byte.
    #[test]
    fn the_write_check_catches_every_shape_it_has_to() {
        let shapes: [(&str, &str); 8] = [
            ("exit payload", "        dl.write_all(payload).await?;"),
            ("exit flush", "        dl.flush().await"),
            ("preamble", "        stream.write_all(&[PROTO_RELAY]).await?;"),
            ("preamble flush", "        stream.flush().await"),
            ("port 80 head", "        sock.write_all(response.as_bytes()).await?;"),
            ("port 80 body", "        sock.write_all(body).await?;"),
            ("port 80 shutdown", "        sock.shutdown().await"),
            (
                "reject shutdown",
                "            let _ = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, w.shutdown()).await;",
            ),
        ];

        for (what, line) in shapes {
            let planted = format!("fn f() {{\n{line}\n}}\n");
            let found = unbounded_writes("planted.rs", &planted);
            assert_eq!(
                found.len(),
                1,
                "the check did not catch the {what} write: {found:?}"
            );

            // And with the marker it is accepted, so the check is not simply
            // flagging everything.
            let marked = format!("fn f() {{\n    // bounded: SOME_TIMEOUT\n{line}\n}}\n");
            assert!(
                unbounded_writes("planted.rs", &marked).is_empty(),
                "the {what} write was flagged even with a marker"
            );
        }
    }

    /// A write that lands one second inside the deadline does not close it.    /// A write that lands one second inside the deadline does not close it.    /// A write that lands one second inside the deadline does not close it.
    #[tokio::test(start_paused = true)]
    async fn a_write_that_lands_inside_the_deadline_does_not_close_the_link() {
        let shared = Arc::new(LinkShared::new(LinkRole::Responder, link::Budget::new()));
        assert!(shared.push_control(vec![0xBB; 8]));

        let w = SlowWriter::after(CELL_WRITE_TIMEOUT - Duration::from_secs(1));
        // The writer parks on its queue once the frame is out, so the only way
        // out of run_link_writer here is this budget expiring.
        let _ =
            tokio::time::timeout(CELL_WRITE_TIMEOUT * 3, run_link_writer(shared.clone(), w)).await;

        assert!(
            !shared.closing(),
            "a write that completed inside the deadline closed the link"
        );
    }

    /// A writer that takes exactly one frame per tick and records what it took.
    ///
    /// The tick is what makes the writer come back for each frame separately,
    /// as a real socket does, instead of draining the whole queue inside one
    /// uninterrupted loop. Under a paused clock the ticks cost no wall time.
    struct OneFramePerTick {
        taken: Arc<std::sync::Mutex<Vec<u8>>>,
        gate: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    }

    impl OneFramePerTick {
        const TICK: Duration = Duration::from_millis(1);

        fn new(taken: Arc<std::sync::Mutex<Vec<u8>>>) -> Self {
            Self { taken, gate: None }
        }
    }

    impl tokio::io::AsyncWrite for OneFramePerTick {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if let Some(gate) = self.gate.as_mut() {
                match gate.as_mut().poll(cx) {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(()) => self.gate = None,
                }
            }
            // The first byte of each queued frame is the circuit that owns it,
            // which is how the service order is read back.
            self.taken
                .lock()
                .expect("recorder mutex")
                .push(buf.first().copied().unwrap_or(0xFF));
            self.gate = Some(Box::pin(tokio::time::sleep(Self::TICK)));
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// The writer serves circuits in strict rotation, one frame each per turn.
    ///
    /// This is the primary guard for fairness. The end to end test depends on
    /// socket buffers to build a backlog and on a frame count bound with 1.37
    /// times margin to a writer that abandons the rotation; this one depends on
    /// nothing outside the table and the writer, so it fails a drain-one-first
    /// writer on every run (docs/DECISIONS.md entry 27).
    #[tokio::test(start_paused = true)]
    async fn the_writer_serves_circuits_in_strict_rotation() {
        const CIRCUITS: u8 = 4;
        const ROTATIONS: usize = 8;

        let shared = Arc::new(LinkShared::new(LinkRole::Responder, link::Budget::new()));
        let ids: Vec<CircId> = (0..CIRCUITS)
            .map(|i| CircId::new(0x4000_0100 + i as u32).expect("a nonzero id"))
            .collect();
        {
            let mut st = shared.lock();
            for id in &ids {
                st.table
                    .accept_create(*id, test_transport(), Instant::now())
                    .expect("room on the link");
            }
        }

        // Filled in blocks, one circuit at a time, which is the point. Filling
        // them interleaved puts the frames in rotation order on arrival, so a
        // writer serving one shared FIFO in arrival order produces the same
        // output as a fair one and passes. In blocks, arrival order is
        // 0 eight times then 1 eight times, and only a writer that rotates
        // produces the order asserted below.
        for (i, id) in ids.iter().enumerate() {
            for _ in 0..ROTATIONS {
                shared
                    .push_out(*id, vec![i as u8; 4])
                    .expect("room in the queue");
            }
        }

        let taken = Arc::new(std::sync::Mutex::new(Vec::new()));
        // The writer parks on its queue once drained, so the budget is how this
        // returns. Paused time means it costs nothing.
        let _ = tokio::time::timeout(
            Duration::from_secs(60),
            run_link_writer(shared.clone(), OneFramePerTick::new(taken.clone())),
        )
        .await;

        let order = taken.lock().expect("recorder mutex").clone();
        let want: Vec<u8> = (0..ROTATIONS).flat_map(|_| 0..CIRCUITS).collect();
        assert_eq!(
            order, want,
            "the writer did not serve the circuits in strict rotation"
        );
    }

    /// A completed Noise session, so a circuit can occupy a table slot without
    /// a link. Both halves are generated here and the initiator is discarded.
    fn test_transport() -> Transport {
        let kp = quiethop_crypto::noise::generate_static_keypair().expect("keygen");
        let (initiator, msg1) =
            quiethop_crypto::noise::Initiator::start(&kp.public).expect("nk start");
        let (responder, msg2) =
            quiethop_crypto::noise::respond(kp.private(), &msg1).expect("nk respond");
        let _ = initiator.finish(&msg2).expect("nk finish");
        responder
    }
}
