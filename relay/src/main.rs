#![deny(warnings)]
#![forbid(unsafe_code)]

mod authority;
mod config;
mod exit;
mod heartbeat;
mod link;
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

use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::sync::{mpsc, Notify};
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
    senders: HashMap<CircId, mpsc::Sender<ToCircuit>>,
    /// Link level frames, ahead of circuit data in the writer.
    ///
    /// DESTROY lives here rather than in the named circuit's queue, because it
    /// is sent as that circuit is discarded and the queue goes with it. It also
    /// has to carry a DESTROY for a CREATE that was refused, where there is no
    /// circuit to queue against at all.
    control: VecDeque<Vec<u8>>,
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
}

/// What the link reader sends a circuit task.
enum ToCircuit {
    /// A DATA frame's body, still sealed.
    Frame(Vec<u8>),
    /// The peer destroyed this circuit. The task forwards DESTROY onward with
    /// DestroyReason::Destroyed and does not answer upstream, because the peer
    /// already knows.
    Destroyed,
}

impl LinkShared {
    fn new(role: LinkRole) -> Self {
        Self {
            state: std::sync::Mutex::new(LinkState {
                table: link::LinkTable::new(role),
                senders: HashMap::new(),
                control: VecDeque::new(),
            }),
            wake: Notify::new(),
            close: Notify::new(),
            closing: AtomicBool::new(false),
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
        st.senders.clear();
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
            st.control.push_back(frame);
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
            return Some(frame);
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

    /// Remove a circuit and quarantine its id. Returns whether it was there.
    fn forget(&self, id: CircId) -> bool {
        let mut st = self.lock();
        st.senders.remove(&id);
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
    let shared = Arc::new(LinkShared::new(LinkRole::Responder));

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
async fn run_link_writer(shared: Arc<LinkShared>, mut w: WriteHalf<InboundStream>) {
    loop {
        let mut wrote = false;
        // The lock is taken and released once per frame, never across the write.
        while let Some(frame) = shared.pop_next_out() {
            if w.write_all(&frame).await.is_err() {
                return;
            }
            wrote = true;
        }
        if wrote && w.flush().await.is_err() {
            return;
        }
        // A notify_one between the drain and here leaves a permit, so a frame
        // queued in that window is not missed.
        shared.wake.notified().await;
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
                    st.senders.get(&id).cloned(),
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
                    match tx.try_send(ToCircuit::Frame(frame.body.to_vec())) {
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
            let sender = {
                let st = shared.lock();
                st.senders.get(&id).cloned()
            };
            match sender {
                Some(tx) => {
                    // Tell the task the peer destroyed it, so it forwards
                    // DESTROYED downstream and sends nothing back upstream.
                    let _ = tx.try_send(ToCircuit::Destroyed);
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

    let (tx, rx) = mpsc::channel::<ToCircuit>(link::MAX_CIRCUIT_QUEUE);
    {
        let mut st = shared.lock();
        match st.table.accept_create(id, transport, Instant::now()) {
            Ok(()) => {
                st.senders.insert(id, tx);
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
        if let Err(e) = run_circuit(&task_shared, id, transport, rx, layers, role, task_ctx).await {
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

/// One circuit's traffic: inbound frames, the next hop, the destination.
///
/// Replaces run_circuit_io, which held the only circuit on a connection. The
/// shape is the same three branch select; what changed is that inbound frames
/// arrive on a channel and outbound frames go to a per-circuit queue.
#[allow(clippy::too_many_arguments)]
async fn run_circuit(
    shared: &Arc<LinkShared>,
    id: CircId,
    mut transport: Transport,
    mut rx: mpsc::Receiver<ToCircuit>,
    layers: Layers,
    role: Role,
    ctx: ConnCtx,
) -> Result<(), HandleError> {
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
            msg = rx.recv() => {
                let Some(msg) = msg else {
                    // The link went or the reader dropped the sender.
                    break Err(HandleError::PeerClosed);
                };
                let wire = match msg {
                    ToCircuit::Frame(w) => w,
                    ToCircuit::Destroyed => {
                        // The peer destroyed this circuit. Forward onward with
                        // DESTROYED, never the reason received, and say nothing
                        // back upstream (SECURITY_MODEL 6.3).
                        forward_destroy(&mut next_link, out_layers).await;
                        return Ok(());
                    }
                };
                match layer::peel(&mut transport, &wire, layers)? {
                    layer::Peeled::Forward(blob) => {
                        let nl = next_link
                            .as_mut()
                            .ok_or(HandleError::ForwardWithoutNextLink(role))?;
                        let out = out_layers.ok_or(HandleError::ForwardWithoutNextLink(role))?;
                        let framed =
                            link_frame::encode(out, nl.circ_id, link_frame::LinkCommand::Data, &blob)?;
                        nl.write.write_all(&framed).await?;
                        nl.write.flush().await?;
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
                            let nl = open_next_link(
                                &extend, &ctx.cfg, &ctx.registry, &ctx.connector, out,
                            )
                            .await?;
                            let reply = Cell::new(
                                CellType::Extend,
                                cell::extend_backward_payload(&nl.noise_msg2),
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
                            dl.write_all(&cell.payload).await?;
                            dl.flush().await?;
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
                            forward_destroy(&mut next_link, out_layers).await;
                            drop(dest_link.take());
                            return Ok(());
                        }
                        (CellType::CloseAck, _) => break Err(HandleError::PeerClosed),
                        (t, r) => break Err(HandleError::IllegalCellForRole(t, r)),
                    },
                }
            }

            res = async {
                match next_link.as_mut() {
                    Some(nl) => nl.read.next_frame().await,
                    None => std::future::pending().await,
                }
            } => {
                let wire = res?;
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
                        // The next hop ended the circuit. Tell the client by
                        // ending this circuit; the reason is not propagated.
                        break Err(HandleError::PeerClosed);
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
    let reason = match &result {
        Err(HandleError::Flow(e)) => link::destroy_reason_for(e),
        Err(HandleError::Layer(_)) | Err(HandleError::Cell(_)) | Err(HandleError::LinkFrame(_)) => {
            DestroyReason::Protocol
        }
        Err(HandleError::IllegalCellForRole(_, _)) => DestroyReason::Protocol,
        Err(HandleError::PeerClosed) => DestroyReason::Requested,
        Err(_) => DestroyReason::Internal,
        Ok(()) => DestroyReason::Requested,
    };
    send_destroy(shared, id, layers, reason);
    forward_destroy(&mut next_link, out_layers).await;
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
async fn forward_destroy(next_link: &mut Option<NextLinkState>, out_layers: Option<Layers>) {
    let (Some(nl), Some(out)) = (next_link.as_mut(), out_layers) else {
        return;
    };
    if let Ok(frame) = link_frame::encode(
        out,
        nl.circ_id,
        link_frame::LinkCommand::Destroy,
        &[DestroyReason::Destroyed as u8],
    ) {
        let _ = nl.write.write_all(&frame).await;
        let _ = nl.write.flush().await;
    }
    drop(next_link.take());
}

struct NextLinkState {
    read: layer::FrameReader<ReadHalf<OutboundStream>>,
    write: WriteHalf<OutboundStream>,
    noise_msg2: [u8; NOISE_MSG_LEN],
    /// The id this side chose for the circuit on the downstream link. This side
    /// opened that link, so the id carries the top bit set.
    circ_id: CircId,
}

/// Dial an outbound link to `next_hop` and act as courier for the client's
/// handshake with that hop: send CREATE carrying the client's Noise message 1,
/// read CREATED with the hop's message 2 back.
///
/// This relay is not a party to that handshake. It cannot read either message,
/// and the next hop authenticates to the client, not to this relay.
///
/// The link starts at PROTO_RELAY and then speaks link frames. CIRCUIT_START is
/// gone: a circuit is named by its id, not by a byte in front of it. In this
/// commit each circuit still opens its own outbound link, so the id is drawn
/// from an empty table and no collision is possible; the shared outbound
/// registry is the next commit.
async fn open_next_link(
    extend: &ExtendForward,
    cfg: &RelayConfig,
    registry: &RegistryHandle,
    connector: &TlsConnector,
    frame_layers: Layers,
) -> Result<NextLinkState, HandleError> {
    // The next hop must be published for the role directly downstream of this
    // one, at exactly this address and port, and its SNI is the name the
    // registry carries for it. Nothing here comes from configuration.
    let doc = registry
        .usable(now_unix())
        .ok_or(HandleError::PeerHostnameMissing(extend.next_hop))?;
    let entry = registry::extend_target(&doc, cfg.role, extend.next_hop)
        .ok_or(HandleError::PeerHostnameMissing(extend.next_hop))?;

    // Allocated through the same table the inbound side uses, so the id rules
    // and the quarantine are one implementation rather than two. The table is
    // empty here because the link is new.
    let mut table = link::LinkTable::new(LinkRole::Initiator);
    let circ_id = table
        .allocate(&mut rand::rngs::OsRng, Instant::now())
        .map_err(|_| HandleError::Handshake)?;
    // Pending until CREATED arrives. On this link that state has nothing to
    // protect yet, because the link carries one circuit and is new, but the
    // transition runs through the same code the multiplexed outbound side will
    // use so there is one implementation of it rather than two.
    table
        .insert_pending(circ_id)
        .map_err(|_| HandleError::Handshake)?;

    let mut stream = tls::dial_tls(connector, extend.next_hop, &entry.tls_name).await?;
    stream.write_all(&[PROTO_RELAY]).await?;
    let (read, mut write) = tokio::io::split(stream);

    let create = link_frame::encode(
        frame_layers,
        circ_id,
        link_frame::LinkCommand::Create,
        &extend.noise_msg1,
    )?;
    write.write_all(&create).await?;
    write.flush().await?;

    let mut reader = layer::FrameReader::new(read, link_frame::link_frame_len(frame_layers));
    let wire = match tokio::time::timeout(HANDSHAKE_READ_TIMEOUT, reader.next_frame()).await {
        Ok(Ok(w)) => w,
        Ok(Err(e)) => return Err(HandleError::Io(e)),
        Err(_) => return Err(HandleError::Timeout),
    };
    let back = link_frame::decode(&wire, frame_layers, LinkRole::Responder)?;
    if back.command != link_frame::LinkCommand::Created || back.circ_id != circ_id {
        return Err(HandleError::Handshake);
    }
    let mut noise_msg2 = [0u8; NOISE_MSG_LEN];
    noise_msg2.copy_from_slice(link_frame::payload(back.body, NOISE_MSG_LEN)?);

    // No transport here: this hop's session belongs to the client and this
    // relay only couriers the handshake, so the phase moves to Open with none.
    table.open_pending(circ_id, None);

    Ok(NextLinkState {
        read: reader,
        write,
        noise_msg2,
        circ_id,
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
        let shared = Arc::new(LinkShared::new(LinkRole::Responder));
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
        let shared = Arc::new(LinkShared::new(LinkRole::Responder));
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
        let shared = Arc::new(LinkShared::new(LinkRole::Responder));
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
        let shared = Arc::new(LinkShared::new(LinkRole::Responder));
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
        assert!(st.senders.is_empty());
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
        let shared = Arc::new(LinkShared::new(LinkRole::Responder));
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
        let shared = Arc::new(LinkShared::new(LinkRole::Responder));
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
