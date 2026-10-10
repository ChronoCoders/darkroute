//! End-to-end integration test for the Noise NK telescoping protocol.
//!
//! Spawns three relay tasks (guard, middle, exit) in-process on localhost
//! ephemeral ports, each with its own static keypair written to a tempdir, and
//! runs a mock client that:
//!
//!   1. Connects to the guard and presents a valid token.
//!   2. Runs a Noise NK handshake against the guard's static public key.
//!   3. Sends an EXTEND cell carrying the middle's Noise message 1; the guard
//!      couriers it and returns message 2, completing the client's handshake
//!      with the middle.
//!   4. Does the same for the exit, through the middle.
//!   5. Sends CONNECT and DATA cells sealed under all three layers.
//!   6. Sends CLOSE_REQUEST and receives CLOSE_ACK.
//!
//! Every cell on the client-guard link is asserted to be exactly
//! `link_cell_len(3)` bytes, whatever the payload.
//!
//! The negative tests cover a wrong static key, a tampered cell, a replayed
//! cell and a wrong-size cell. All four must end with the relay closing the
//! connection and sending nothing.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::TlsConnector;

use crate::registry::RegistryHandle;
use quiethop_crypto::cell::{
    link_cell_len, parse_extend_backward, Cell, CellType, ConnectPayload, ExtendForward,
    CELL_PAYLOAD_LEN,
};
use quiethop_crypto::circid::{CircId, LinkRole};
use quiethop_crypto::flow;
use quiethop_crypto::layer::{peel, seal_forward, seal_to_me, Peeled};
use quiethop_crypto::layers::Layers;
use quiethop_crypto::link::{self as link_frame, DestroyReason};
use quiethop_crypto::noise::{
    generate_static_keypair, respond, Initiator, Transport, NOISE_MSG_LEN, STATIC_KEY_LEN,
};
use quiethop_crypto::registry::{Document, RelayEntry, Verified};

use crate::authority::AuthorityClient;
use crate::config::{RelayConfig, Role};
use crate::static_key;
use crate::test_hooks;
use crate::token::{raw_sign, ReplayWindow};

const TEST_HOSTNAME: &str = "localhost";
const TEST_TIMEOUT: Duration = Duration::from_secs(120);

static CRYPTO_PROVIDER_INSTALL: OnceLock<()> = OnceLock::new();

fn ensure_crypto_provider() {
    CRYPTO_PROVIDER_INSTALL.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

struct TestPki {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

fn make_pki() -> TestPki {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec![TEST_HOSTNAME.to_string()]).expect("self-signed");
    TestPki {
        cert: CertificateDer::from(cert.der().to_vec()),
        key: PrivateKeyDer::try_from(key_pair.serialize_der()).expect("key der"),
    }
}

fn make_server_config(pki: &TestPki) -> Arc<ServerConfig> {
    Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![pki.cert.clone()], pki.key.clone_key())
            .expect("server config"),
    )
}

fn make_connector(pki: &TestPki) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.add(pki.cert.clone()).expect("add root");
    TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

async fn tls_connect(connector: &TlsConnector, addr: SocketAddr) -> ClientTlsStream<TcpStream> {
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let name = ServerName::try_from(TEST_HOSTNAME).expect("server name");
    connector.connect(name, tcp).await.expect("tls connect")
}

struct RelayOverride {
    decodo_proxy_url: Option<String>,
    allowed_exit_ports: Vec<u16>,
    /// Ceiling for the relay-wide link buffer budget. Small in the test that
    /// exercises admission, the production default everywhere else.
    max_link_buffer_bytes: u64,
}

fn default_override() -> RelayOverride {
    RelayOverride {
        decodo_proxy_url: None,
        allowed_exit_ports: vec![80, 443],
        max_link_buffer_bytes: 256 * 1024 * 1024,
    }
}

fn make_config(
    role: Role,
    over: &RelayOverride,
    static_key_path: PathBuf,
    registry_state_dir: PathBuf,
) -> Arc<RelayConfig> {
    Arc::new(RelayConfig {
        role,
        authority_pubkey_url: "http://localhost/".to_string(),
        authority_heartbeat_url: "http://localhost/".to_string(),
        relay_api_key: "test-relay-api-key".to_string(),
        relay_port: 0,
        metrics_bind: "127.0.0.1:0".parse().unwrap(),
        replay_window_ttl: 86_400,
        max_circuits: 16,
        max_link_buffer_bytes: over.max_link_buffer_bytes,
        max_circuits_per_relay_link: 256,
        node_id: format!("test-relay-{role}"),
        decodo_proxy_url: if role == Role::Exit {
            over.decodo_proxy_url
                .clone()
                .or_else(|| Some("socks5://user:pass@127.0.0.1:1080".to_string()))
        } else {
            None
        },
        allowed_exit_ports: over.allowed_exit_ports.clone(),
        relay_hostname: TEST_HOSTNAME.to_string(),
        acme_contact_email: "test@example.invalid".to_string(),
        acme_dir: PathBuf::from("/tmp/quiethop-relay-test-acme-unused"),
        acme_staging: true,
        static_key_path,
        // The in-process harness publishes a document straight into the handle,
        // so nothing here is fetched. Verification itself is covered by the
        // quiethop-crypto registry and cache tests; what these tests exercise is
        // what the relay does with a document it already holds.
        registry_signing_pubkeys: Vec::new(),
        registry_url: String::new(),
        registry_state_dir,
    })
}

/// Build a verified document from explicit role, address and key triples.
///
/// The address is what callers must use in EXTEND, which is not always the
/// relay's own listener: the adverse delivery test reaches each hop through a
/// chunking proxy, so the published address is the proxy's. `extend_target`
/// matches address and port exactly, which is the point of passing them in.
///
/// `bytes` and `key_ids` are empty because this never goes through signature
/// verification: the relay reads the document it is given, and the signature
/// path has its own tests in quiethop-crypto.
fn document_from(
    entries: &[(&str, SocketAddr, [u8; STATIC_KEY_LEN])],
    valid_after: &str,
    fresh_until: &str,
    valid_until: &str,
) -> Verified {
    let relays = entries
        .iter()
        .enumerate()
        .map(|(i, (role, addr, key))| RelayEntry {
            // The index keeps these distinct when a role is published twice,
            // which the stalled circuit test needs: one middle that reads and
            // one that does not.
            id: format!("test-{role}-{i}"),
            operator_id: format!("op-{role}-{i}"),
            host_id: format!("host-{role}-{i}"),
            role: (*role).to_string(),
            ip: addr.ip().to_string(),
            port: addr.port(),
            tls_name: TEST_HOSTNAME.to_string(),
            static_pubkey: key.iter().map(|b| format!("{b:02x}")).collect(),
        })
        .collect();
    Verified {
        document: Document {
            version: parse_hour(valid_after),
            valid_after: valid_after.to_string(),
            fresh_until: fresh_until.to_string(),
            valid_until: valid_until.to_string(),
            relays,
        },
        bytes: Vec::new(),
        key_ids: Vec::new(),
    }
}

/// Hours since the epoch, which is what the document version must equal.
fn parse_hour(rfc3339: &str) -> i64 {
    let d = Document {
        version: 0,
        valid_after: rfc3339.to_string(),
        fresh_until: rfc3339.to_string(),
        valid_until: rfc3339.to_string(),
        relays: Vec::new(),
    };
    d.valid_after_unix().expect("timestamp parses") / 3600
}

/// A spawned relay: where to reach it and the static public key a client must
/// pin to handshake with it.
struct SpawnedRelay {
    addr: SocketAddr,
    /// The relay's own byte budget, so a test can assert what it holds instead
    /// of inferring it from a refusal that may never come.
    budget: crate::link::Budget,
    static_pubkey: [u8; STATIC_KEY_LEN],
    /// Needed because a link's frame size follows the relay's role.
    role: Role,
}

/// Spawn one relay. Its keypair is generated at runtime into `keydir`, so no
/// key material is ever checked in or printed.
#[allow(clippy::too_many_arguments)]
async fn spawn_relay(
    role: Role,
    authority_priv: &RsaPrivateKey,
    over: &RelayOverride,
    registry: RegistryHandle,
    server_config: Arc<ServerConfig>,
    connector: Arc<TlsConnector>,
    keydir: &Path,
) -> SpawnedRelay {
    let key_path = keydir.join(format!("{role}.key"));
    static_key::generate(&key_path).expect("keygen");
    let kp = static_key::load(&key_path).expect("load key");
    let static_pubkey = kp.public;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let authority = Arc::new(AuthorityClient::from_pubkey_for_test(RsaPublicKey::from(
        authority_priv,
    )));
    let replay = Arc::new(ReplayWindow::new(Duration::from_secs(86_400)));
    let cfg = make_config(role, over, key_path, keydir.join(format!("{role}-state")));
    let shutdown = Arc::new(Notify::new());
    let budget = crate::link::Budget::new();
    tokio::spawn(super::accept_loop(
        listener,
        server_config.clone(),
        server_config,
        shutdown,
        cfg,
        authority,
        replay,
        connector,
        Arc::new(kp),
        registry,
        budget.clone(),
        Arc::new(crate::linkreg::Registry::new()),
    ));
    SpawnedRelay {
        addr,
        budget,
        static_pubkey,
        role,
    }
}

/// Seconds since the epoch, as the relay reads it.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Format Unix seconds as the RFC 3339 UTC string the registry carries.
///
/// The harness must build windows around the real clock, because the relay
/// checks documents against it. A fixed window would pass only during the hours
/// it happened to name.
///
/// Civil date from days, after Howard Hinnant's algorithm. Verified by round
/// trip against the parser the registry itself uses, in
/// `rfc3339_round_trips_through_the_registry_parser`.
fn rfc3339_utc(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// The formatter is only trustworthy if it round trips through the parser the
/// registry itself uses, so this checks it against that parser rather than
/// against a second copy of the same arithmetic.
#[test]
fn rfc3339_round_trips_through_the_registry_parser() {
    // An hour boundary, a leap day, a century non-leap year, and an end of year.
    for unix in [
        0_i64,
        1_791_468_000,
        1_709_164_800,
        4_102_444_800,
        951_782_400,
        2_147_483_647 - (2_147_483_647 % 3600),
    ] {
        let s = rfc3339_utc(unix);
        let d = Document {
            version: 0,
            valid_after: s.clone(),
            fresh_until: s.clone(),
            valid_until: s.clone(),
            relays: Vec::new(),
        };
        assert_eq!(
            d.valid_after_unix()
                .expect("the parser accepts what we format"),
            unix,
            "{s} did not round trip"
        );
    }
}

/// The publication window the harness uses: the current hour, fresh for an hour
/// and valid for six, matching the authority's own windows.
fn current_window() -> (String, String, String) {
    let hour = now_unix().div_euclid(3600) * 3600;
    (
        rfc3339_utc(hour),
        rfc3339_utc(hour + 3600),
        rfc3339_utc(hour + 6 * 3600),
    )
}

/// The three-hop fleet plus the registry handles that feed it.
///
/// The handles are kept so a test can republish, which is how the expired
/// document case is exercised without waiting six hours.
struct Fleet {
    guard: SpawnedRelay,
    middle: SpawnedRelay,
    exit: SpawnedRelay,
    handles: Vec<RegistryHandle>,
}

impl Fleet {
    /// Publish one document to every relay in the fleet.
    fn publish(&self, doc: Verified) {
        let doc = Arc::new(doc);
        for h in &self.handles {
            h.publish(doc.clone());
        }
    }

    fn document(&self, valid_after: &str, fresh_until: &str, valid_until: &str) -> Verified {
        document_from(
            &[
                ("guard", self.guard.addr, self.guard.static_pubkey),
                ("middle", self.middle.addr, self.middle.static_pubkey),
                ("exit", self.exit.addr, self.exit.static_pubkey),
            ],
            valid_after,
            fresh_until,
            valid_until,
        )
    }
}

async fn spawn_fleet(
    auth_priv: &RsaPrivateKey,
    over: &RelayOverride,
    server_config: Arc<ServerConfig>,
    connector: Arc<TlsConnector>,
    keydir: &Path,
) -> Fleet {
    // Each relay gets its own handle, filled once every address is known. A
    // relay reads the handle per connection, so publishing after spawn is in
    // time and avoids binding listeners before the document can name them.
    let handles: Vec<RegistryHandle> = (0..3).map(|_| RegistryHandle::new()).collect();
    let exit = spawn_relay(
        Role::Exit,
        auth_priv,
        over,
        handles[2].clone(),
        server_config.clone(),
        connector.clone(),
        keydir,
    )
    .await;
    let middle = spawn_relay(
        Role::Middle,
        auth_priv,
        over,
        handles[1].clone(),
        server_config.clone(),
        connector.clone(),
        keydir,
    )
    .await;
    let guard = spawn_relay(
        Role::Guard,
        auth_priv,
        over,
        handles[0].clone(),
        server_config,
        connector,
        keydir,
    )
    .await;
    let fleet = Fleet {
        guard,
        middle,
        exit,
        handles,
    };
    let (after, fresh, until) = current_window();
    fleet.publish(fleet.document(&after, &fresh, &until));
    tokio::time::sleep(Duration::from_millis(50)).await;
    fleet
}

/// Mock client holding one Noise transport per hop.
/// One circuit's per-hop transports and its id on the link.
///
/// Separate from the socket, because a link carries several circuits and each
/// one has its own keys. `MockClient` holds one of these and `MultiClient`
/// holds several over the same socket.
struct CircuitKeys {
    /// The id the client chose. The client opened the link, so the id carries
    /// the top bit set.
    id: CircId,
    guard: Transport,
    middle: Option<Transport>,
    exit: Option<Transport>,
}

impl CircuitKeys {
    /// Number of hops whose transports are established.
    fn hops(&self) -> usize {
        1 + self.middle.is_some() as usize + self.exit.is_some() as usize
    }

    /// Seal `cell` for hop number `depth` (1 = guard, 2 = middle, 3 = exit),
    /// wrapping it once per hop nearer the client.
    fn seal_for_depth(&mut self, cell: &Cell, depth: usize) -> Vec<u8> {
        // layers counts from the innermost hop outward: the exit is 1.
        let layers = Layers::new(CLIENT_LAYERS.get() - (depth - 1));
        let mut buf = match depth {
            1 => seal_to_me(&mut self.guard, cell, layers).expect("seal guard"),
            2 => seal_to_me(self.middle.as_mut().expect("middle"), cell, layers)
                .expect("seal middle"),
            3 => seal_to_me(self.exit.as_mut().expect("exit"), cell, layers).expect("seal exit"),
            other => panic!("bad depth {other}"),
        };
        if depth >= 3 {
            buf = seal_forward(
                self.middle.as_mut().expect("middle"),
                &buf,
                CLIENT_LAYERS.peeled(),
            )
            .expect("wrap middle");
        }
        if depth >= 2 {
            buf = seal_forward(&mut self.guard, &buf, CLIENT_LAYERS).expect("wrap guard");
        }
        buf
    }

    /// Peel every established layer off a frame body until a cell appears.
    fn peel_inbound(&mut self, wire: &[u8]) -> Cell {
        let mut blob = match peel(&mut self.guard, wire, CLIENT_LAYERS).expect("peel guard") {
            Peeled::ToMe(cell) => return cell,
            Peeled::Forward(b) => b,
        };
        if let Some(mid) = self.middle.as_mut() {
            blob = match peel(mid, &blob, CLIENT_LAYERS.peeled()).expect("peel middle") {
                Peeled::ToMe(cell) => return cell,
                Peeled::Forward(b) => b,
            };
        }
        let exit = self
            .exit
            .as_mut()
            .expect("exit transport for innermost peel");
        match peel(exit, &blob, Layers::new(1)).expect("peel exit") {
            Peeled::ToMe(cell) => cell,
            Peeled::Forward(_) => panic!("FORWARD arrived at the innermost layer"),
        }
    }

    /// Record a newly finished hop's transport.
    fn push_hop(&mut self, tx: Transport) {
        if self.middle.is_none() {
            self.middle = Some(tx);
        } else {
            self.exit = Some(tx);
        }
    }
}

struct MockClient {
    sock: ClientTlsStream<TcpStream>,
    keys: CircuitKeys,
    /// Every frame size observed on the client-guard link, in both directions.
    observed: Vec<usize>,
}

/// The client-guard link carries three layers.
const CLIENT_LAYERS: Layers = Layers::new(3);

impl MockClient {
    /// Connect, present the token, and handshake with the guard.
    async fn connect(
        connector: &TlsConnector,
        guard: &SpawnedRelay,
        auth_priv: &RsaPrivateKey,
    ) -> Self {
        Self::connect_with_token(connector, guard, auth_priv, [0xA5; 32]).await
    }

    /// Connect with a caller-chosen token.
    ///
    /// A test that connects to one guard more than once needs a distinct token
    /// per connection, because the guard's replay window refuses the second
    /// presentation of the same one and closes the link. That refusal is
    /// correct, and reusing a token would make it look like whatever the test
    /// was actually trying to observe.
    async fn connect_with_token(
        connector: &TlsConnector,
        guard: &SpawnedRelay,
        auth_priv: &RsaPrivateKey,
        m_raw: [u8; 32],
    ) -> Self {
        Self::connect_with_token_and_id(connector, guard, auth_priv, m_raw, 0x8000_0001).await
    }

    /// Connect with a caller-chosen token and circuit id.
    ///
    /// The id is a parameter because the interleaving tests put two circuits on
    /// one link and each needs its own.
    async fn connect_with_token_and_id(
        connector: &TlsConnector,
        guard: &SpawnedRelay,
        auth_priv: &RsaPrivateKey,
        m_raw: [u8; 32],
        raw_id: u32,
    ) -> Self {
        let circ_id = CircId::new(raw_id).expect("a nonzero id");
        let mut sock = tls_connect(connector, guard.addr).await;
        sock.write_all(&[super::PROTO_CLIENT]).await.expect("proto");
        let guard_tx = Self::create_on(&mut sock, guard, auth_priv, m_raw, circ_id).await;
        Self {
            sock,
            keys: CircuitKeys {
                id: circ_id,
                guard: guard_tx,
                middle: None,
                exit: None,
            },
            observed: Vec::new(),
        }
    }

    /// Send CREATE on an open socket and complete the handshake.
    async fn create_on(
        sock: &mut ClientTlsStream<TcpStream>,
        guard: &SpawnedRelay,
        auth_priv: &RsaPrivateKey,
        m_raw: [u8; 32],
        circ_id: CircId,
    ) -> Transport {
        let token = raw_sign(&m_raw, auth_priv);
        let (init, msg1) = Initiator::start(&guard.static_pubkey).expect("nk start");

        // CREATE body: the token presentation then the client's first Noise
        // message. The token is per circuit, so one token buys one circuit.
        let mut body = Vec::with_capacity(super::PRESENTATION_LEN + NOISE_MSG_LEN);
        body.extend_from_slice(&m_raw);
        body.extend_from_slice(&token);
        body.extend_from_slice(&msg1);
        let create = link_frame::encode(
            CLIENT_LAYERS,
            circ_id,
            link_frame::LinkCommand::Create,
            &body,
        )
        .expect("encode create");
        sock.write_all(&create).await.expect("create");
        sock.flush().await.expect("flush");

        let mut buf = vec![0u8; link_frame::link_frame_len(CLIENT_LAYERS)];
        sock.read_exact(&mut buf).await.expect("created");
        let back = link_frame::decode(&buf, CLIENT_LAYERS, LinkRole::Responder).expect("decode");
        assert_eq!(back.command, link_frame::LinkCommand::Created);
        assert_eq!(back.circ_id, circ_id);
        let mut msg2 = [0u8; NOISE_MSG_LEN];
        msg2.copy_from_slice(link_frame::payload(back.body, NOISE_MSG_LEN).expect("msg2"));
        init.finish(&msg2).expect("nk finish")
    }

    fn hops(&self) -> usize {
        self.keys.hops()
    }

    /// Seal a cell for the deepest established hop and send it, wrapping it
    /// once per nearer hop. Records the on-wire size.
    async fn send_to_deepest(&mut self, cell: &Cell) {
        let wire = self.seal_for_depth(cell, self.hops());
        self.write_frame(&wire).await;
    }

    fn seal_for_depth(&mut self, cell: &Cell, depth: usize) -> Vec<u8> {
        self.keys.seal_for_depth(cell, depth)
    }

    async fn write_frame(&mut self, wire: &[u8]) {
        assert_eq!(
            wire.len(),
            link_cell_len(CLIENT_LAYERS),
            "a sealed cell on the client-guard link was not the fixed size"
        );
        let frame = link_frame::encode(
            CLIENT_LAYERS,
            self.keys.id,
            link_frame::LinkCommand::Data,
            wire,
        )
        .expect("encode link frame");
        assert_eq!(
            frame.len(),
            link_frame::link_frame_len(CLIENT_LAYERS),
            "a link frame on the client-guard link was not the fixed size"
        );
        self.observed.push(frame.len());
        self.sock.write_all(&frame).await.expect("write frame");
        self.sock.flush().await.expect("flush");
    }

    /// Read one link frame and return the sealed cell inside it.
    ///
    /// A frame for another circuit, or any command other than DATA, is an error
    /// here rather than being skipped: this client has one circuit and anything
    /// else means the relay mixed circuits up, which is what the interleaving
    /// test exists to catch.
    async fn read_frame(&mut self) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0u8; link_frame::link_frame_len(CLIENT_LAYERS)];
        self.sock.read_exact(&mut buf).await?;
        self.observed.push(buf.len());
        let frame = link_frame::decode(&buf, CLIENT_LAYERS, LinkRole::Responder)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        if frame.circ_id != self.keys.id {
            return Err(std::io::Error::other(format!(
                "frame for circuit {:#010x} arrived on a client holding {:#010x}",
                frame.circ_id.raw(),
                self.keys.id.raw()
            )));
        }
        match frame.command {
            link_frame::LinkCommand::Data => Ok(frame.body.to_vec()),
            other => Err(std::io::Error::other(format!("unexpected {other:?}"))),
        }
    }

    /// Read one frame and peel every established layer until a cell appears.
    async fn read_cell(&mut self) -> Cell {
        let wire = self.read_frame().await.expect("read frame");
        self.keys.peel_inbound(&wire)
    }

    /// Extend the circuit to `next`, which becomes the new deepest hop.
    async fn extend_to(&mut self, next: &SpawnedRelay) {
        let (init, msg1) = Initiator::start(&next.static_pubkey).expect("nk start");
        let extend = ExtendForward {
            next_hop: next.addr,
            noise_msg1: msg1,
        };
        let cell = Cell::new(CellType::Extend, extend.encode()).expect("extend cell");
        // The EXTEND is acted on by the current deepest hop.
        let depth = self.hops();
        let wire = self.seal_for_depth(&cell, depth);
        self.write_frame(&wire).await;

        let back = self.read_cell().await;
        assert_eq!(back.cell_type, CellType::Extend, "expected EXTEND backward");
        let msg2 = parse_extend_backward(&back.payload).expect("parse msg2");
        let tx = init.finish(&msg2).expect("nk finish");
        self.keys.push_hop(tx);
    }

    /// Attempt one EXTEND and report whether the hop served it.
    ///
    /// `extend_to` asserts success, which is right for the happy path and wrong
    /// for the refusal cases: a refusing relay tears the link down, so the read
    /// returns nothing rather than a cell.
    async fn try_extend_to(
        &mut self,
        next_addr: SocketAddr,
        next_key: [u8; STATIC_KEY_LEN],
    ) -> bool {
        let (init, msg1) = Initiator::start(&next_key).expect("nk start");
        let extend = ExtendForward {
            next_hop: next_addr,
            noise_msg1: msg1,
        };
        let cell = Cell::new(CellType::Extend, extend.encode()).expect("extend cell");
        let depth = self.hops();
        let wire = self.seal_for_depth(&cell, depth);
        let Ok(frame) = link_frame::encode(
            CLIENT_LAYERS,
            self.keys.id,
            link_frame::LinkCommand::Data,
            &wire,
        ) else {
            return false;
        };
        self.observed.push(frame.len());
        if self.sock.write_all(&frame).await.is_err() || self.sock.flush().await.is_err() {
            return false;
        }
        let Ok(Ok(wire)) = tokio::time::timeout(Duration::from_secs(10), self.read_frame()).await
        else {
            return false;
        };
        let Ok(peeled) = peel(&mut self.keys.guard, &wire, CLIENT_LAYERS) else {
            return false;
        };
        let Peeled::ToMe(back) = peeled else {
            return false;
        };
        if back.cell_type != CellType::Extend {
            return false;
        }
        let Ok(msg2) = parse_extend_backward(&back.payload) else {
            return false;
        };
        match init.finish(&msg2) {
            Ok(tx) => {
                self.keys.push_hop(tx);
                true
            }
            Err(_) => false,
        }
    }

    /// Build the full three-hop circuit.
    async fn build_circuit(&mut self, fleet: &Fleet) {
        self.extend_to(&fleet.middle).await;
        self.extend_to(&fleet.exit).await;
    }
}

#[tokio::test]
async fn end_to_end_three_hop_circuit() {
    tokio::time::timeout(TEST_TIMEOUT, run_test())
        .await
        .expect("test timed out");
}

async fn run_test() {
    ensure_crypto_provider();
    let (tx, mut connect_rx) = mpsc::unbounded_channel::<ConnectPayload>();
    test_hooks::install_sender(tx);

    let keydir = tempfile::tempdir().expect("keydir");
    let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
    let pki = make_pki();
    let server_config = make_server_config(&pki);
    let connector = Arc::new(make_connector(&pki));
    let over = default_override();

    let fleet = spawn_fleet(
        &auth_priv,
        &over,
        server_config,
        connector.clone(),
        keydir.path(),
    )
    .await;

    let mut client = MockClient::connect(&connector, &fleet.guard, &auth_priv).await;
    client.build_circuit(&fleet).await;

    // CONNECT reaches the exit with the destination intact.
    let connect = ConnectPayload {
        host: "connect-probe.invalid".to_string(),
        port: 443,
    };
    let cell = Cell::new(CellType::Connect, connect.encode().expect("encode")).expect("cell");
    client.send_to_deepest(&cell).await;

    // The CONNECT hook is one process-global sink, so another test in this
    // binary can publish into this channel. Take the first CONNECT that names
    // the destination this test sent and ignore the rest, rather than assuming
    // this test is the only one running.
    const WANT_HOST: &str = "connect-probe.invalid";
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut seen = None;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout_at(deadline, connect_rx.recv()).await {
            Ok(Some(p)) if p.host == WANT_HOST => {
                seen = Some(p);
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => panic!("hook channel closed"),
            Err(_) => break,
        }
    }
    let seen = seen.expect("exit never saw this test's CONNECT");
    assert_eq!(seen.host, WANT_HOST);
    assert_eq!(seen.port, 443);

    // Every frame on the client-guard link was the fixed size.
    assert!(!client.observed.is_empty(), "no frames were observed");
    for (i, n) in client.observed.iter().enumerate() {
        assert_eq!(
            *n,
            link_frame::link_frame_len(CLIENT_LAYERS),
            "frame {i} on the client-guard link was {n} bytes"
        );
    }
}

/// The headline size claim, asserted against bytes that actually crossed a
/// socket rather than against the constants alone.
#[tokio::test]
async fn on_wire_cells_are_constant_size_whatever_the_payload() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        ensure_crypto_provider();
        let keydir = tempfile::tempdir().expect("keydir");
        let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
        let pki = make_pki();
        let server_config = make_server_config(&pki);
        let connector = Arc::new(make_connector(&pki));
        let over = default_override();
        let fleet = spawn_fleet(
            &auth_priv,
            &over,
            server_config,
            connector.clone(),
            keydir.path(),
        )
        .await;

        let mut client = MockClient::connect(&connector, &fleet.guard, &auth_priv).await;
        client.build_circuit(&fleet).await;

        // A zero-byte payload and a full one must both produce the same size.
        for n in [0usize, 1, 200, CELL_PAYLOAD_LEN] {
            let cell = Cell::new(CellType::Data, vec![0x11; n]).expect("cell");
            let wire = client.seal_for_depth(&cell, 3);
            assert_eq!(
                wire.len(),
                link_cell_len(CLIENT_LAYERS),
                "payload {n} produced a {}-byte frame",
                wire.len()
            );
            client.write_frame(&wire).await;
        }
        assert_eq!(link_cell_len(Layers::new(3)), 564);
        assert_eq!(link_cell_len(Layers::new(2)), 547);
        assert_eq!(link_cell_len(Layers::new(1)), 530);
    })
    .await
    .expect("test timed out");
}

/// A client that pins the wrong static key cannot complete the handshake, and
/// the relay sends nothing back beyond its own message 2.
#[tokio::test]
async fn wrong_static_key_fails_the_handshake() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        ensure_crypto_provider();
        let keydir = tempfile::tempdir().expect("keydir");
        let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
        let pki = make_pki();
        let server_config = make_server_config(&pki);
        let connector = Arc::new(make_connector(&pki));
        let over = default_override();
        let fleet = spawn_fleet(
            &auth_priv,
            &over,
            server_config,
            connector.clone(),
            keydir.path(),
        )
        .await;

        // Control: the real key completes.
        let good = MockClient::connect(&connector, &fleet.guard, &auth_priv).await;
        drop(good);

        // The impostor key belongs to the exit, not the guard.
        let impostor = SpawnedRelay {
            budget: crate::link::Budget::new(),
            addr: fleet.guard.addr,
            static_pubkey: fleet.exit.static_pubkey,
            role: Role::Guard,
        };
        assert_ne!(impostor.static_pubkey, fleet.guard.static_pubkey);

        let mut sock = tls_connect(&connector, impostor.addr).await;
        sock.write_all(&[super::PROTO_CLIENT]).await.expect("proto");
        // A token the control did not spend. Reusing the control's token would
        // make the guard refuse on replay, and a refusal on replay looks
        // exactly like a refusal on the static key.
        let m_raw: [u8; 32] = [0xA6; 32];
        let token = raw_sign(&m_raw, &auth_priv);
        let (init, msg1) = Initiator::start(&impostor.static_pubkey).expect("nk start");
        let circ_id = CircId::new(0x8000_0002).expect("a nonzero id");
        let mut body = Vec::with_capacity(super::PRESENTATION_LEN + NOISE_MSG_LEN);
        body.extend_from_slice(&m_raw);
        body.extend_from_slice(&token);
        body.extend_from_slice(&msg1);
        let create = link_frame::encode(
            CLIENT_LAYERS,
            circ_id,
            link_frame::LinkCommand::Create,
            &body,
        )
        .expect("encode create");
        sock.write_all(&create).await.expect("create");
        sock.flush().await.expect("flush");

        // The guard cannot decrypt message 1 under its own static key, so it
        // closes without replying. Either an EOF or an unusable message 2 is
        // acceptable; what must not happen is a working circuit.
        let mut buf = vec![0u8; link_frame::link_frame_len(CLIENT_LAYERS)];
        match sock.read_exact(&mut buf).await {
            Err(_) => {}
            Ok(_) => {
                let back = link_frame::decode(&buf, CLIENT_LAYERS, LinkRole::Responder)
                    .expect("decode created");
                let mut msg2 = [0u8; NOISE_MSG_LEN];
                msg2.copy_from_slice(link_frame::payload(back.body, NOISE_MSG_LEN).expect("msg2"));
                assert!(
                    init.finish(&msg2).is_err(),
                    "a handshake against the wrong static key completed"
                );
            }
        }
    })
    .await
    .expect("test timed out");
}

/// A CREATE naming a circuit that is already open is ignored, and the circuit
/// it named keeps working.
///
/// Answering it with DESTROY would hand any peer on the link a way to end any
/// circuit on that link: name its id in a CREATE and the relay tears it down
/// (DECISIONS 22). So the refusal is silence, and the test has to show both
/// halves, that nothing comes back and that the live circuit survives.
#[tokio::test]
async fn a_create_for_an_open_circuit_is_ignored_and_the_circuit_survives() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        ensure_crypto_provider();
        let keydir = tempfile::tempdir().expect("keydir");
        let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
        let pki = make_pki();
        let server_config = make_server_config(&pki);
        let connector = Arc::new(make_connector(&pki));
        let over = default_override();
        let fleet = spawn_fleet(
            &auth_priv,
            &over,
            server_config,
            connector.clone(),
            keydir.path(),
        )
        .await;

        let mut client =
            MockClient::connect_with_token(&connector, &fleet.guard, &auth_priv, [0xD1; 32]).await;

        // A second CREATE for the id the first one opened. A fresh token, so a
        // replay refusal cannot stand in for the collision refusal.
        let m_raw: [u8; 32] = [0xD2; 32];
        let token = raw_sign(&m_raw, &auth_priv);
        let (_init, msg1) = Initiator::start(&fleet.guard.static_pubkey).expect("nk start");
        let mut body = Vec::with_capacity(super::PRESENTATION_LEN + NOISE_MSG_LEN);
        body.extend_from_slice(&m_raw);
        body.extend_from_slice(&token);
        body.extend_from_slice(&msg1);
        let collide = link_frame::encode(
            CLIENT_LAYERS,
            client.keys.id,
            link_frame::LinkCommand::Create,
            &body,
        )
        .expect("encode colliding create");
        client.sock.write_all(&collide).await.expect("write create");
        client.sock.flush().await.expect("flush");

        // Nothing comes back. Reading has to time out rather than produce a
        // frame, so the read timeout here is the assertion and not a wait for
        // something slow.
        let mut buf = vec![0u8; link_frame::link_frame_len(CLIENT_LAYERS)];
        let answered =
            tokio::time::timeout(Duration::from_secs(3), client.sock.read_exact(&mut buf)).await;
        assert!(
            answered.is_err(),
            "the guard answered a colliding CREATE, which lets any peer end any circuit on the link"
        );

        // The circuit the collision named is untouched: it still extends.
        assert!(
            client
                .try_extend_to(fleet.middle.addr, fleet.middle.static_pubkey)
                .await,
            "the colliding CREATE ended the circuit it named"
        );
    })
    .await
    .expect("test timed out");
}

/// A stand-in middle that completes the link and then reports the next frame
/// it is sent, verbatim.
///
/// It is a real Noise responder, so the client's handshake through the guard
/// genuinely completes and the guard really holds a next link. What it does not
/// do is act on anything after that: it hands the bytes to the test instead,
/// which is the only way to read a byte the relay wrote to another relay.
struct RecordingMiddle {
    addr: SocketAddr,
    static_pubkey: [u8; STATIC_KEY_LEN],
    frames: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Held closed until the test opens it. The handshake completes either
    /// way; what waits is the frame loop, so an upstream relay writing to this
    /// hop fills its socket buffer and then blocks. That is the smallest piece
    /// of the stalling harness that a full per-circuit queue needs, and it is
    /// the part commit (a2) will build out.
    gate: Arc<Notify>,
}

impl RecordingMiddle {
    const LAYERS: Layers = CLIENT_LAYERS.peeled();

    /// Reads as soon as it is connected.
    async fn spawn(server_config: Arc<ServerConfig>) -> Self {
        let m = Self::spawn_gated(server_config).await;
        m.open();
        m
    }

    /// Completes the handshake and then reads nothing until `open` is called.
    async fn spawn_gated(server_config: Arc<ServerConfig>) -> Self {
        let keypair = generate_static_keypair().expect("keygen");
        let static_pubkey = keypair.public;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, frames) = mpsc::unbounded_channel();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let gate = Arc::new(Notify::new());
        let task_gate = gate.clone();

        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let tx = tx.clone();
                let private = keypair.private().to_owned();
                let gate = task_gate.clone();
                tokio::spawn(async move {
                    let Ok(mut sock) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut proto = [0u8; 1];
                    if sock.read_exact(&mut proto).await.is_err() || proto[0] != super::PROTO_RELAY
                    {
                        return;
                    }
                    let frame_len = link_frame::link_frame_len(Self::LAYERS);

                    // CREATE from the guard, carrying the client's message 1.
                    let mut buf = vec![0u8; frame_len];
                    if sock.read_exact(&mut buf).await.is_err() {
                        return;
                    }
                    let Ok(create) = link_frame::decode(&buf, Self::LAYERS, LinkRole::Initiator)
                    else {
                        return;
                    };
                    let Ok(msg1_bytes) =
                        link_frame::payload(create.body, link_frame::CREATE_RELAY_BODY_LEN)
                    else {
                        return;
                    };
                    let mut msg1 = [0u8; NOISE_MSG_LEN];
                    msg1.copy_from_slice(msg1_bytes);
                    let Ok((_transport, msg2)) = respond(&private, &msg1) else {
                        return;
                    };
                    let Ok(created) = link_frame::encode(
                        Self::LAYERS,
                        create.circ_id,
                        link_frame::LinkCommand::Created,
                        &msg2,
                    ) else {
                        return;
                    };
                    if sock.write_all(&created).await.is_err() || sock.flush().await.is_err() {
                        return;
                    }

                    // Nothing is read past the handshake until the test says
                    // so, which is what lets a queue upstream of here fill.
                    gate.notified().await;

                    // Everything after the handshake goes to the test as it is.
                    loop {
                        let mut buf = vec![0u8; frame_len];
                        if sock.read_exact(&mut buf).await.is_err() {
                            return;
                        }
                        if tx.send(buf).is_err() {
                            return;
                        }
                    }
                });
            }
        });

        Self {
            addr,
            static_pubkey,
            frames,
            gate,
        }
    }

    /// Let the frame loop run. A permit left here before the task reaches the
    /// wait is kept, so opening early is safe.
    fn open(&self) {
        self.gate.notify_one();
    }

    /// Next frame, or None if nothing arrives inside `budget`.
    async fn next_frame_within(&mut self, budget: Duration) -> Option<Vec<u8>> {
        tokio::time::timeout(budget, self.frames.recv())
            .await
            .ok()
            .flatten()
    }

    async fn next_frame(&mut self) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(10), self.frames.recv())
            .await
            .expect("the guard forwarded nothing to the next hop")
            .expect("the recording middle stopped")
    }
}

/// A DESTROY forwarded to the next hop carries DESTROYED, never the reason
/// that arrived.
///
/// tor-spec: "Reasons in DESTROY cell SHOULD NOT be propagated downward or
/// upward, due to potential side channel risk", and "An OR receiving a DESTROY
/// command should use the DESTROYED reason for its next cell." The reason a
/// peer chose is a channel, so the only reason that may leave this relay for
/// its own next hop is the constant one.
///
/// The received reason cannot reach the forwarding path at all, because
/// ToCircuit::Destroyed carries no reason and the byte is never read. What this
/// test holds is the other half: that the constant written is 0x06 and not some
/// other variant.
#[tokio::test]
async fn a_forwarded_destroy_carries_destroyed_and_not_the_reason_received() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        ensure_crypto_provider();
        let keydir = tempfile::tempdir().expect("keydir");
        let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
        let pki = make_pki();
        let server_config = make_server_config(&pki);
        let connector = Arc::new(make_connector(&pki));
        let over = default_override();
        let fleet = spawn_fleet(
            &auth_priv,
            &over,
            server_config.clone(),
            connector.clone(),
            keydir.path(),
        )
        .await;

        // Publish the recorder as the middle, at its own address and with its
        // own static key. The guard will only extend to the address and key the
        // registry carries, so this is how the recorder gets the connection.
        let mut middle = RecordingMiddle::spawn(server_config).await;
        let (after, fresh, until) = current_window();
        fleet.publish(document_from(
            &[
                ("guard", fleet.guard.addr, fleet.guard.static_pubkey),
                ("middle", middle.addr, middle.static_pubkey),
                ("exit", fleet.exit.addr, fleet.exit.static_pubkey),
            ],
            &after,
            &fresh,
            &until,
        ));

        let mut client =
            MockClient::connect_with_token(&connector, &fleet.guard, &auth_priv, [0xE1; 32]).await;
        assert!(
            client
                .try_extend_to(middle.addr, middle.static_pubkey)
                .await,
            "the recorder is published as the middle, so the extend must complete"
        );

        // A DESTROY from the client naming a reason of its own choosing.
        let sent = DestroyReason::Protocol;
        assert_ne!(sent as u8, DestroyReason::Destroyed as u8);
        let destroy = link_frame::encode(
            CLIENT_LAYERS,
            client.keys.id,
            link_frame::LinkCommand::Destroy,
            &[sent as u8],
        )
        .expect("encode destroy");
        client
            .sock
            .write_all(&destroy)
            .await
            .expect("write destroy");
        client.sock.flush().await.expect("flush");

        let wire = middle.next_frame().await;
        let fwd = link_frame::decode(&wire, RecordingMiddle::LAYERS, LinkRole::Initiator)
            .expect("decode forwarded frame");
        assert_eq!(
            fwd.command,
            link_frame::LinkCommand::Destroy,
            "the guard forwarded something other than DESTROY"
        );
        let body = link_frame::payload(fwd.body, link_frame::DESTROY_BODY_LEN)
            .expect("forwarded destroy body");
        assert_eq!(
            body[0],
            DestroyReason::Destroyed as u8,
            "the forwarded reason was {:#04x}, not DESTROYED (0x06)",
            body[0]
        );
        assert_ne!(
            body[0], sent as u8,
            "the reason the client chose crossed the relay, which is the side channel \
             tor-spec forbids"
        );
    })
    .await
    .expect("test timed out");
}

/// Extend one circuit by one hop, over a link that may carry others.
///
/// Separate from `MockClient::try_extend_to`, which exists to report a refusal
/// as `false` and so tolerates a reply it cannot read. This one asserts, because
/// every caller needs the hop and a reply that will not decrypt means the relay
/// mixed two circuits up, which is the thing worth a panic.
///
/// It assumes no frame for another circuit arrives while it is waiting, which
/// holds because the tests build their circuits before any data flows.
async fn extend_circuit(
    sock: &mut ClientTlsStream<TcpStream>,
    keys: &mut CircuitKeys,
    next_addr: SocketAddr,
    next_key: [u8; STATIC_KEY_LEN],
) {
    let (init, msg1) = Initiator::start(&next_key).expect("nk start");
    let extend = ExtendForward {
        next_hop: next_addr,
        noise_msg1: msg1,
    };
    let cell = Cell::new(CellType::Extend, extend.encode()).expect("extend cell");
    let depth = keys.hops();
    let wire = keys.seal_for_depth(&cell, depth);
    let frame = link_frame::encode(CLIENT_LAYERS, keys.id, link_frame::LinkCommand::Data, &wire)
        .expect("encode extend");
    sock.write_all(&frame).await.expect("write extend");
    sock.flush().await.expect("flush");

    let mut buf = vec![0u8; link_frame::link_frame_len(CLIENT_LAYERS)];
    tokio::time::timeout(Duration::from_secs(20), sock.read_exact(&mut buf))
        .await
        .expect("the hop never answered the extend")
        .expect("read extend reply");
    let back = link_frame::decode(&buf, CLIENT_LAYERS, LinkRole::Responder).expect("decode reply");
    assert_eq!(
        back.circ_id, keys.id,
        "a reply arrived on the wrong circuit"
    );
    assert_eq!(back.command, link_frame::LinkCommand::Data);
    let reply = keys.peel_inbound(back.body);
    assert_eq!(
        reply.cell_type,
        CellType::Extend,
        "expected EXTEND backward"
    );
    let msg2 = parse_extend_backward(&reply.payload).expect("parse msg2");
    keys.push_hop(init.finish(&msg2).expect("nk finish"));
}

/// Several circuits riding one link to the guard.
///
/// `MockClient` holds one circuit and owns the methods the single-circuit tests
/// need. This holds the socket and a circuit per id, and reads frames without
/// caring which circuit they belong to, which is what the fairness and
/// stalled-circuit tests measure.
struct MultiClient {
    sock: ClientTlsStream<TcpStream>,
    keys: Vec<CircuitKeys>,
}

impl MultiClient {
    async fn connect(connector: &TlsConnector, guard: &SpawnedRelay) -> Self {
        let mut sock = tls_connect(connector, guard.addr).await;
        sock.write_all(&[super::PROTO_CLIENT]).await.expect("proto");
        sock.flush().await.expect("flush");
        Self {
            sock,
            keys: Vec::new(),
        }
    }

    /// Open one more circuit on this link. Each needs its own token, because
    /// one token buys one circuit.
    async fn open(
        &mut self,
        guard: &SpawnedRelay,
        auth_priv: &RsaPrivateKey,
        m_raw: [u8; 32],
        raw_id: u32,
    ) -> usize {
        let circ_id = CircId::new(raw_id).expect("a nonzero id");
        let guard_tx =
            MockClient::create_on(&mut self.sock, guard, auth_priv, m_raw, circ_id).await;
        self.keys.push(CircuitKeys {
            id: circ_id,
            guard: guard_tx,
            middle: None,
            exit: None,
        });
        self.keys.len() - 1
    }

    async fn extend(&mut self, which: usize, addr: SocketAddr, key: [u8; STATIC_KEY_LEN]) {
        let keys = &mut self.keys[which];
        extend_circuit(&mut self.sock, keys, addr, key).await;
    }

    /// Send one cell to the deepest established hop of one circuit.
    async fn send(&mut self, which: usize, cell: &Cell) {
        let keys = &mut self.keys[which];
        let depth = keys.hops();
        let wire = keys.seal_for_depth(cell, depth);
        let frame =
            link_frame::encode(CLIENT_LAYERS, keys.id, link_frame::LinkCommand::Data, &wire)
                .expect("encode frame");
        self.sock.write_all(&frame).await.expect("write frame");
        self.sock.flush().await.expect("flush");
    }

    /// Read one frame, whichever circuit it names.
    async fn next_frame(
        &mut self,
        budget: Duration,
    ) -> Option<(CircId, link_frame::LinkCommand, Vec<u8>)> {
        let mut buf = vec![0u8; link_frame::link_frame_len(CLIENT_LAYERS)];
        match tokio::time::timeout(budget, self.sock.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            _ => return None,
        }
        let f = link_frame::decode(&buf, CLIENT_LAYERS, LinkRole::Responder).expect("decode frame");
        Some((f.circ_id, f.command, f.body.to_vec()))
    }

    fn index_of(&self, id: CircId) -> usize {
        self.keys
            .iter()
            .position(|k| k.id == id)
            .unwrap_or_else(|| panic!("a frame for {:#010x}, which is not on this link", id.raw()))
    }

    fn id(&self, which: usize) -> CircId {
        self.keys[which].id
    }
}

/// One stalled circuit does not stall the others on its link.
///
/// Circuit A's next hop completes the handshake and then reads nothing, so the
/// guard's write to it blocks, A's task stops consuming and the link reader
/// fills A's queue. Circuit B shares the link and must keep carrying data
/// throughout, which is what `try_send` in the inbound dispatch buys: a reader
/// that waits on A's channel would stop reading B's frames too, and that is the
/// head of line blocking multiplexing exists to remove.
///
/// Every wait here has a deadline, so the `send().await` mutant fails this test
/// with a message rather than hanging it.
#[tokio::test]
async fn a_stalled_circuit_does_not_stall_the_others_on_its_link() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        ensure_crypto_provider();
        let keydir = tempfile::tempdir().expect("keydir");
        let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
        let pki = make_pki();
        let server_config = make_server_config(&pki);
        let connector = Arc::new(make_connector(&pki));
        let over = default_override();
        let fleet = spawn_fleet(
            &auth_priv,
            &over,
            server_config.clone(),
            connector.clone(),
            keydir.path(),
        )
        .await;

        // Two next hops published as middles: one that reads and one that
        // never does.
        let mut live = RecordingMiddle::spawn(server_config.clone()).await;
        let stalled = RecordingMiddle::spawn_gated(server_config).await;
        let (after, fresh, until) = current_window();
        fleet.publish(document_from(
            &[
                ("guard", fleet.guard.addr, fleet.guard.static_pubkey),
                ("middle", live.addr, live.static_pubkey),
                ("middle", stalled.addr, stalled.static_pubkey),
                ("exit", fleet.exit.addr, fleet.exit.static_pubkey),
            ],
            &after,
            &fresh,
            &until,
        ));

        let mut client = MultiClient::connect(&connector, &fleet.guard).await;
        let a = client
            .open(&fleet.guard, &auth_priv, [0xF1; 32], 0x8000_0030)
            .await;
        let b = client
            .open(&fleet.guard, &auth_priv, [0xF2; 32], 0x8000_0031)
            .await;
        client.extend(a, stalled.addr, stalled.static_pubkey).await;
        client.extend(b, live.addr, live.static_pubkey).await;

        // Control: B works before A is stalled, so a later failure is about
        // the stall and not about B.
        let hello = Cell::new(CellType::Data, b"before".to_vec()).expect("cell");
        client.send(b, &hello).await;
        live.next_frame_within(Duration::from_secs(10))
            .await
            .expect("B did not carry data even before A stalled");

        // Fill A past its queue. Most of this is absorbed by socket buffers
        // between the guard and the stalled hop before the guard's write
        // blocks, and only then does the reader start queueing. The count is
        // far above MAX_CIRCUIT_QUEUE for that reason: measured here, 6000
        // frames reaches the cap once and 1624 never does, so FILLER leaves
        // room for a machine whose buffers are larger.
        const FILLER: usize = 8000;
        let filler = Cell::new(CellType::Data, vec![0x5C; 64]).expect("cell");
        for _ in 0..FILLER {
            client.send(a, &filler).await;
        }

        // B still carries data while A is stalled and being torn down.
        let after_stall = Cell::new(CellType::Data, b"during".to_vec()).expect("cell");
        client.send(b, &after_stall).await;
        live.next_frame_within(Duration::from_secs(20))
            .await
            .expect("B stopped carrying data while A was stalled");

        // A is destroyed for exceeding what can be held for it, and the frame
        // naming it says so.
        //
        // Protocol, whichever queue fills. A per-circuit queue holds 1024 and
        // a compliant peer cannot put more than 1010 frames in one in steady
        // state, so reaching the cap means the peer sent past its window
        // (docs/DECISIONS.md entry 31). FILLER is 8000, far past it.
        // The stall has to have happened, or everything below passes without
        // exercising anything. The DESTROY asserted below is that evidence: it
        // only arrives once the shared link to the stalled hop has no room left
        // for A, which takes the whole FILLER burst.

        let mut a_destroyed = None;
        for _ in 0..8 {
            let Some((id, command, body)) = client.next_frame(Duration::from_secs(20)).await else {
                break;
            };
            if id == client.id(a) && command == link_frame::LinkCommand::Destroy {
                let reason =
                    link_frame::payload(&body, link_frame::DESTROY_BODY_LEN).expect("destroy body");
                a_destroyed = Some(reason[0]);
                break;
            }
        }
        assert_eq!(
            a_destroyed,
            Some(DestroyReason::Protocol as u8),
            "a circuit whose queue filled was not destroyed with Protocol"
        );

        // The link and B both survived A being destroyed.
        let after_destroy = Cell::new(CellType::Data, b"after".to_vec()).expect("cell");
        client.send(b, &after_destroy).await;
        live.next_frame_within(Duration::from_secs(20))
            .await
            .expect("the link or circuit B died with circuit A");
    })
    .await
    .expect("test timed out");
}

/// Two circuits with sustained backlogs on one link both keep making progress.
///
/// The writer takes one frame per circuit per turn (`LinkTable::pop_next_out`),
/// so while both queues hold something the frames leaving the link alternate.
/// The socket preserves that order, so the whole stream the client reads is in
/// the order the writer popped it.
///
/// The bound is how long one circuit may hold the writer, and it is empirical,
/// not derived. That is worth stating plainly.
///
/// The derived property is exact: `LinkTable::pop_next_out` takes one frame and
/// moves that circuit to the back of the rotation, so while every circuit has
/// something queued the counts stay within one. It is conditional on every
/// queue being non-empty, and a client cannot see whether they are, so it
/// cannot be asserted from here. `link::tests::the_writer_alternates_between_two_backlogged_circuits`
/// asserts it where the queues are visible.
///
/// What is left end to end is that no circuit is starved for long. Measured at
/// this commit, idle: counts 200 each over an 800 frame window with a longest
/// single circuit run of 2. Under a loaded machine running the suite in
/// parallel: 184, 184, 184, 248 with a run of 66, because one circuit's echo
/// arrives late and the other three empty while it catches up. A writer that
/// drains one circuit before looking at the next: 54, 358, 256, 132 with a run
/// of 354.
///
/// `MAX_RUN` of 200 sits three times above the worst observed skew and well
/// under what abandoning the rotation produces.
///
/// Two tighter bounds were tried and rejected. A share, that no circuit falls
/// below a third of another, passes the FIFO writer at 132 against 307. A
/// spread of one missed turn per circuit holds when idle and fails under
/// parallel load at a spread of 64, because a late circuit misses many turns in
/// a row rather than one.
#[tokio::test]
async fn two_backlogged_circuits_on_one_link_both_progress() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        ensure_crypto_provider();
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
        let echo_addr = echo_listener.local_addr().expect("echo addr");
        tokio::spawn(run_echo_server(echo_listener));
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.expect("socks bind");
        let socks_addr = socks_listener.local_addr().expect("socks addr");
        tokio::spawn(run_socks5_stub(socks_listener, echo_addr));

        let keydir = tempfile::tempdir().expect("keydir");
        let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
        let pki = make_pki();
        let server_config = make_server_config(&pki);
        let connector = Arc::new(make_connector(&pki));
        let over = RelayOverride {
            decodo_proxy_url: Some(format!("socks5://user:pass@{socks_addr}")),
            allowed_exit_ports: vec![echo_addr.port()],
            max_link_buffer_bytes: 256 * 1024 * 1024,
        };
        let fleet = spawn_fleet(
            &auth_priv,
            &over,
            server_config,
            connector.clone(),
            keydir.path(),
        )
        .await;

        // Four full three hop circuits over one link. Two is enough to measure
        // fairness and not enough to create it: the exit's package window caps
        // each circuit at 1000 cells, so two circuits put about 1.1 MB in
        // flight, which the socket buffers between the guard and this client
        // absorb whole. With nothing waiting in a queue, a writer that drains
        // one circuit first drains a queue of one frame and looks exactly like
        // one that alternates. Four circuits put about 1.8 MB in flight, which
        // outruns the buffers and leaves a real backlog to choose from.
        const CIRCUITS: usize = 8;
        let mut client = MultiClient::connect(&connector, &fleet.guard).await;
        for i in 0..CIRCUITS {
            let mut token = [0xA0u8; 32];
            token[0] = 0xA1 + i as u8;
            client
                .open(&fleet.guard, &auth_priv, token, 0x8000_0040 + i as u32)
                .await;
        }
        for which in 0..CIRCUITS {
            client
                .extend(which, fleet.middle.addr, fleet.middle.static_pubkey)
                .await;
            client
                .extend(which, fleet.exit.addr, fleet.exit.static_pubkey)
                .await;
        }

        let connect = ConnectPayload {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
        };
        let cell = Cell::new(CellType::Connect, connect.encode().expect("encode")).expect("cell");
        for which in 0..CIRCUITS {
            client.send(which, &cell).await;
        }

        // Interleaved, so both echo streams start together and neither builds
        // a head start that the measurement would read as unfairness.
        // Enough that the echo coming back outruns the socket buffers while
        // the client is still sending and reading nothing, so both per-circuit
        // queues are deep by the time the reading below starts. With a shallow
        // queue a writer that drains one circuit first is indistinguishable
        // from one that alternates, because the queue it would drain holds a
        // single frame. 800 stays inside the exit's 1000 cell package window,
        // which is what it can send back without a SENDME the mock client
        // never sends.
        const PER_CIRCUIT: usize = 800;
        /// The longest a single circuit may hold the writer. Empirical: three
        /// times the worst skew measured under parallel load.
        const MAX_RUN: usize = 200;
        /// Writer turns across the sends and the reads that must have had more
        /// than one circuit queued. Measured floor over twelve runs was 1435,
        /// so this sits about 30 percent under it. A run where no backlog
        /// formed shows near zero (docs/DECISIONS.md entry 27).
        const MIN_CONTENDED_TURNS: u64 = 1000;
        // Sampled here, before the sends. The socket absorbs megabytes, so the
        // writer pops and orders almost every frame while this client is still
        // sending; read from after the sends the counter shows zero and the
        // test looks vacuous when it is not.
        let contended_before = crate::metrics::writer_turn_count(true);
        let payload = Cell::new(CellType::Data, vec![0x3C; 400]).expect("data cell");
        for _ in 0..PER_CIRCUIT {
            for which in 0..CIRCUITS {
                client.send(which, &payload).await;
            }
        }

        // Read back and watch the order the writer chose.
        let mut counts = [0usize; CIRCUITS];
        let mut run = 0usize;
        let mut longest_run = 0usize;
        let mut last: Option<usize> = None;
        // Half of what is queued, so the window measured sits inside the
        // backlog rather than running off its end, where one circuit's data
        // legitimately runs out before the other's.
        let want = PER_CIRCUIT;
        while counts.iter().sum::<usize>() < want {
            let Some((id, command, _)) = client.next_frame(Duration::from_secs(20)).await else {
                break;
            };
            if command != link_frame::LinkCommand::Data {
                panic!("the link carried {command:?} during the backlog");
            }
            let which = client.index_of(id);
            counts[which] += 1;
            run = if last == Some(which) { run + 1 } else { 1 };
            last = Some(which);
            longest_run = longest_run.max(run);
        }

        assert_eq!(
            counts.iter().sum::<usize>(),
            want,
            "the link stopped delivering before {want} frames: {counts:?}"
        );
        // The writer has to have had a choice to make, or this proves nothing.
        // A contended turn is one where the rotation held at least two
        // circuits, so with one frame queued at a time every writer looks fair
        // and the bound below is satisfied by a writer that never rotated.
        let contended = crate::metrics::writer_turn_count(true) - contended_before;
        assert!(
            contended >= MIN_CONTENDED_TURNS,
            "only {contended} of the writer's turns had more than one circuit queued, \
             under the {MIN_CONTENDED_TURNS} this test needs: no backlog formed, so it \
             did not measure fairness at all"
        );

        assert!(
            counts.iter().all(|c| *c > 0),
            "a circuit was starved entirely over the window: {counts:?}"
        );
        assert!(
            longest_run <= MAX_RUN,
            "one circuit held the writer for {longest_run} frames in a row, past the \
             {MAX_RUN} that arrival skew accounts for, so the writer is not rotating: \
             {counts:?}"
        );
    })
    .await
    .expect("test timed out");
}

/// At the budget ceiling a CREATE is refused, the circuits already open keep
/// carrying data, and admission reopens once the bytes are released.
///
/// This is the soft part of the limit made visible. Admission is the only place
/// the budget is checked, so a circuit accepted before the ceiling keeps its
/// full queue allowance and keeps working; what the relay stops doing is taking
/// on more (ARCHITECTURE 5.9).
///
/// One hop reads and one does not. The stalled hop is what holds the budget
/// crossed while the refusal is tested, because frames only stay counted while
/// they stay queued.
#[tokio::test]
async fn at_the_budget_ceiling_creates_are_refused_and_open_circuits_carry_on() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        ensure_crypto_provider();
        let keydir = tempfile::tempdir().expect("keydir");
        let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
        let pki = make_pki();
        let server_config = make_server_config(&pki);
        let connector = Arc::new(make_connector(&pki));
        // Measured: the burst below leaves about 48 KB queued on the guard at
        // once, the rest having drained into the stalled hop's socket buffer.
        // The ceiling sits under that, and the assertion further down fails the
        // run if it was not actually crossed.
        const CEILING: u64 = 20_000;
        let over = RelayOverride {
            max_link_buffer_bytes: CEILING,
            ..default_override()
        };
        let fleet = spawn_fleet(
            &auth_priv,
            &over,
            server_config.clone(),
            connector.clone(),
            keydir.path(),
        )
        .await;

        let mut live = RecordingMiddle::spawn(server_config.clone()).await;
        let stalled = RecordingMiddle::spawn_gated(server_config).await;
        let (after, fresh, until) = current_window();
        fleet.publish(document_from(
            &[
                ("guard", fleet.guard.addr, fleet.guard.static_pubkey),
                ("middle", live.addr, live.static_pubkey),
                ("middle", stalled.addr, stalled.static_pubkey),
                ("exit", fleet.exit.addr, fleet.exit.static_pubkey),
            ],
            &after,
            &fresh,
            &until,
        ));

        // Both admitted while the budget is empty.
        let mut client = MultiClient::connect(&connector, &fleet.guard).await;
        let keeper = client
            .open(&fleet.guard, &auth_priv, [0xB1; 32], 0x8000_0050)
            .await;
        let filler = client
            .open(&fleet.guard, &auth_priv, [0xB2; 32], 0x8000_0051)
            .await;
        client.extend(keeper, live.addr, live.static_pubkey).await;
        client
            .extend(filler, stalled.addr, stalled.static_pubkey)
            .await;

        // Control: the keeper works before the budget is anywhere near full.
        let hello = Cell::new(CellType::Data, b"before".to_vec()).expect("cell");
        client.send(keeper, &hello).await;
        live.next_frame_within(Duration::from_secs(10))
            .await
            .expect("the keeper did not carry data even with an empty budget");

        // Fill the budget through the stalled hop. The socket absorbs the first
        // few hundred frames; after it blocks they stay queued and counted.
        let payload = Cell::new(CellType::Data, vec![0x9A; 400]).expect("cell");
        let refusals_before = crate::metrics::dropped_count("buffer_budget");
        for _ in 0..900 {
            client.send(filler, &payload).await;
        }

        // The ceiling has to have been crossed, or the refusal below is
        // missing for a reason that has nothing to do with the budget. Asserted
        // on what the guard actually holds, not inferred from a refusal that
        // may never come.
        assert!(
            fleet.guard.budget.held() >= CEILING,
            "the guard holds {} bytes against a {CEILING} ceiling, so this run never \
             filled the budget and proves nothing about admission",
            fleet.guard.budget.held()
        );

        // A CREATE now has to meet a full budget.
        let m_raw: [u8; 32] = [0xB3; 32];
        let token = raw_sign(&m_raw, &auth_priv);
        let (_init, msg1) = Initiator::start(&fleet.guard.static_pubkey).expect("nk start");
        let refused = CircId::new(0x8000_0052).expect("a nonzero id");
        let mut body = Vec::with_capacity(super::PRESENTATION_LEN + NOISE_MSG_LEN);
        body.extend_from_slice(&m_raw);
        body.extend_from_slice(&token);
        body.extend_from_slice(&msg1);
        let create = link_frame::encode(
            CLIENT_LAYERS,
            refused,
            link_frame::LinkCommand::Create,
            &body,
        )
        .expect("encode create");
        client.sock.write_all(&create).await.expect("write create");
        client.sock.flush().await.expect("flush");

        // DESTROY with Resource comes back for that id, and the refusal is
        // counted. Resource is also what MAX_CIRCUITS_PER_LINK answers, so a
        // peer cannot tell which bound it hit.
        let mut got = None;
        for _ in 0..12 {
            let Some((id, command, frame_body)) = client.next_frame(Duration::from_secs(20)).await
            else {
                break;
            };
            if id == refused && command == link_frame::LinkCommand::Destroy {
                let reason = link_frame::payload(&frame_body, link_frame::DESTROY_BODY_LEN)
                    .expect("destroy body");
                got = Some(reason[0]);
                break;
            }
        }
        assert_eq!(
            got,
            Some(DestroyReason::Resource as u8),
            "a CREATE at the ceiling was not refused with Resource"
        );
        assert!(
            crate::metrics::dropped_count("buffer_budget") > refusals_before,
            "the refusal was not counted"
        );

        // The circuit admitted before the ceiling still carries data. Nothing
        // was taken from a circuit the relay had already accepted.
        let after_full = Cell::new(CellType::Data, b"during".to_vec()).expect("cell");
        client.send(keeper, &after_full).await;
        live.next_frame_within(Duration::from_secs(20))
            .await
            .expect("a circuit accepted before the ceiling stopped carrying data");
    })
    .await
    .expect("test timed out");
}

/// A DESTROY from the peer is not answered back to that peer.
///
/// The peer already knows it destroyed the circuit, so a DESTROY in reply tells
/// it nothing it does not have and names a reason it did not ask for
/// (SECURITY_MODEL 6.3). What the relay does instead is forward DESTROYED to
/// the next hop and go quiet upstream.
#[tokio::test]
async fn a_peer_destroy_is_not_answered_upstream() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        ensure_crypto_provider();
        let keydir = tempfile::tempdir().expect("keydir");
        let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
        let pki = make_pki();
        let server_config = make_server_config(&pki);
        let connector = Arc::new(make_connector(&pki));
        let over = default_override();
        let fleet = spawn_fleet(
            &auth_priv,
            &over,
            server_config.clone(),
            connector.clone(),
            keydir.path(),
        )
        .await;

        let mut middle = RecordingMiddle::spawn(server_config).await;
        let (after, fresh, until) = current_window();
        fleet.publish(document_from(
            &[
                ("guard", fleet.guard.addr, fleet.guard.static_pubkey),
                ("middle", middle.addr, middle.static_pubkey),
                ("exit", fleet.exit.addr, fleet.exit.static_pubkey),
            ],
            &after,
            &fresh,
            &until,
        ));

        let mut client =
            MockClient::connect_with_token(&connector, &fleet.guard, &auth_priv, [0xE3; 32]).await;
        assert!(
            client
                .try_extend_to(middle.addr, middle.static_pubkey)
                .await,
            "the recorder is published as the middle, so the extend must complete"
        );

        let destroy = link_frame::encode(
            CLIENT_LAYERS,
            client.keys.id,
            link_frame::LinkCommand::Destroy,
            &[DestroyReason::Protocol as u8],
        )
        .expect("encode destroy");
        client
            .sock
            .write_all(&destroy)
            .await
            .expect("write destroy");
        client.sock.flush().await.expect("flush");

        // Control: the relay did act on it, so the silence below is a choice
        // and not the DESTROY being ignored.
        let forwarded = middle
            .next_frame_within(Duration::from_secs(10))
            .await
            .expect("the guard forwarded nothing to the next hop");
        let fwd = link_frame::decode(&forwarded, RecordingMiddle::LAYERS, LinkRole::Initiator)
            .expect("decode forwarded frame");
        assert_eq!(fwd.command, link_frame::LinkCommand::Destroy);

        // Nothing comes back on the link the DESTROY arrived on.
        let mut buf = vec![0u8; link_frame::link_frame_len(CLIENT_LAYERS)];
        match tokio::time::timeout(Duration::from_secs(3), client.sock.read_exact(&mut buf)).await {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(_)) => {
                let back = link_frame::decode(&buf, CLIENT_LAYERS, LinkRole::Responder)
                    .expect("decode answer");
                panic!(
                    "the relay answered a peer DESTROY with {:?} for circuit {:#010x}",
                    back.command,
                    back.circ_id.raw()
                );
            }
        }
    })
    .await
    .expect("test timed out");
}

/// A DESTROY overtakes queued DATA rather than waiting behind it.
///
/// The destroy signal used to travel on the same bounded channel as the frames,
/// so it waited behind every frame already queued and the circuit went on
/// forwarding data the peer had already destroyed.
///
/// The next hop here stops reading after the handshake, which is what makes the
/// upstream relay's write block and its queue fill. A full window of DATA goes
/// out and the socket buffers absorb some of it: measured at this commit, 448
/// frames reach the next hop and the remaining 552 sit in the per-circuit
/// queue, which is the deepest backlog a peer inside its window can build. It
/// cannot reach MAX_CIRCUIT_QUEUE, because the 1000 cell window is deliberately
/// smaller than the 1024 slot queue.
///
/// The deadline is the assertion: nothing here may wait on a hang.
#[tokio::test]
async fn a_destroy_overtakes_queued_data() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        ensure_crypto_provider();
        let keydir = tempfile::tempdir().expect("keydir");
        let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
        let pki = make_pki();
        let server_config = make_server_config(&pki);
        let connector = Arc::new(make_connector(&pki));
        let over = default_override();
        let fleet = spawn_fleet(
            &auth_priv,
            &over,
            server_config.clone(),
            connector.clone(),
            keydir.path(),
        )
        .await;

        // Gated: the handshake completes, then it reads nothing until told.
        let mut middle = RecordingMiddle::spawn_gated(server_config).await;
        let (after, fresh, until) = current_window();
        fleet.publish(document_from(
            &[
                ("guard", fleet.guard.addr, fleet.guard.static_pubkey),
                ("middle", middle.addr, middle.static_pubkey),
                ("exit", fleet.exit.addr, fleet.exit.static_pubkey),
            ],
            &after,
            &fresh,
            &until,
        ));

        let mut client =
            MockClient::connect_with_token(&connector, &fleet.guard, &auth_priv, [0xE4; 32]).await;
        assert!(
            client
                .try_extend_to(middle.addr, middle.static_pubkey)
                .await,
            "the handshake runs ahead of the gate, so the extend must complete"
        );

        // A full window of DATA, every frame of it legitimate. The guard
        // forwards until the next hop's socket stops taking bytes, then its
        // task stops consuming and the link reader fills the queue behind it.
        const SENT: usize = flow::WINDOW_START as usize;
        for _ in 0..SENT {
            let cell = Cell::new(CellType::Data, vec![0x7E; 64]).expect("cell");
            let wire = client.seal_for_depth(&cell, 2);
            client.write_frame(&wire).await;
        }

        let destroy = link_frame::encode(
            CLIENT_LAYERS,
            client.keys.id,
            link_frame::LinkCommand::Destroy,
            &[DestroyReason::Protocol as u8],
        )
        .expect("encode destroy");
        client
            .sock
            .write_all(&destroy)
            .await
            .expect("write destroy");
        client.sock.flush().await.expect("flush");

        // Let it read. Count the DATA that arrives before the DESTROY.
        middle.open();
        let mut data_before = 0usize;
        let mut reason = None;
        while let Some(wire) = middle.next_frame_within(Duration::from_secs(20)).await {
            let f = link_frame::decode(&wire, RecordingMiddle::LAYERS, LinkRole::Initiator)
                .expect("decode forwarded frame");
            match f.command {
                link_frame::LinkCommand::Data => data_before += 1,
                link_frame::LinkCommand::Destroy => {
                    let body = link_frame::payload(f.body, link_frame::DESTROY_BODY_LEN)
                        .expect("destroy body");
                    reason = Some(body[0]);
                    break;
                }
                other => panic!("unexpected {other:?} on the relay link"),
            }
        }

        let reason = reason.expect("the DESTROY never reached the next hop");
        assert_eq!(
            reason,
            DestroyReason::Destroyed as u8,
            "the forwarded reason was {reason:#04x}, not DESTROYED"
        );
        assert!(
            data_before < SENT,
            "all {SENT} DATA frames were forwarded before the DESTROY, so the signal \
             waited behind the queue instead of overtaking it"
        );
        assert!(
            data_before > 0,
            "no DATA reached the next hop at all, so nothing was ever queued and this \
             test did not exercise a backlog"
        );

        // Nothing queued may be forwarded after the circuit is destroyed.
        if let Some(extra) = middle.next_frame_within(Duration::from_secs(2)).await {
            let f = link_frame::decode(&extra, RecordingMiddle::LAYERS, LinkRole::Initiator)
                .expect("decode trailing frame");
            panic!("{:?} was forwarded after the DESTROY", f.command);
        }
    })
    .await
    .expect("test timed out");
}

/// A tampered cell destroys that circuit and nothing else.
///
/// Before multiplexing the guard closed the connection, which was the same
/// thing. It is not any more: a link carries many circuits, so ending the link
/// over one circuit's AEAD failure would let any client end every circuit
/// riding beside it. The guard answers with DESTROY for that id instead.
#[tokio::test]
async fn tampered_cell_destroys_only_that_circuit() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        ensure_crypto_provider();
        let keydir = tempfile::tempdir().expect("keydir");
        let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
        let pki = make_pki();
        let server_config = make_server_config(&pki);
        let connector = Arc::new(make_connector(&pki));
        let over = default_override();
        let fleet = spawn_fleet(
            &auth_priv,
            &over,
            server_config,
            connector.clone(),
            keydir.path(),
        )
        .await;

        let mut client = MockClient::connect(&connector, &fleet.guard, &auth_priv).await;
        let cell = Cell::new(CellType::Data, b"tamper".to_vec()).expect("cell");
        let mut wire = client.seal_for_depth(&cell, 1);
        wire[30] ^= 0x01;
        // Framed correctly: the frame is whole and only the sealed cell inside
        // it is corrupt, so the teardown is attributable to the AEAD failure
        // and not to a short read.
        client.write_frame(&wire).await;

        // What comes back is DESTROY for this circuit, not an answer to the
        // cell and not an EOF.
        let mut buf = vec![0u8; link_frame::link_frame_len(CLIENT_LAYERS)];
        tokio::time::timeout(Duration::from_secs(10), client.sock.read_exact(&mut buf))
            .await
            .expect("the guard neither destroyed the circuit nor closed")
            .expect("read destroy");
        let back =
            link_frame::decode(&buf, CLIENT_LAYERS, LinkRole::Responder).expect("decode destroy");
        assert_eq!(back.circ_id, client.keys.id);
        assert_eq!(
            back.command,
            link_frame::LinkCommand::Destroy,
            "a tampered cell must destroy the circuit, not be answered"
        );
        let reason =
            link_frame::payload(back.body, link_frame::DESTROY_BODY_LEN).expect("destroy body");
        assert_eq!(
            reason[0],
            DestroyReason::Protocol as u8,
            "an AEAD failure is a protocol violation"
        );
    })
    .await
    .expect("test timed out");
}

/// A replayed cell destroys the circuit: the Noise counter has advanced.
///
/// The replay is rejected at the middle, which destroys the circuit on its own
/// link, and the guard turns that into a DESTROY for the client. As with a
/// tampered cell, the link itself stays up, because other circuits may be
/// riding it.
#[tokio::test]
async fn replayed_cell_destroys_the_circuit() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        ensure_crypto_provider();
        let keydir = tempfile::tempdir().expect("keydir");
        let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
        let pki = make_pki();
        let server_config = make_server_config(&pki);
        let connector = Arc::new(make_connector(&pki));
        let over = default_override();
        let fleet = spawn_fleet(
            &auth_priv,
            &over,
            server_config,
            connector.clone(),
            keydir.path(),
        )
        .await;

        let mut client = MockClient::connect(&connector, &fleet.guard, &auth_priv).await;
        client.extend_to(&fleet.middle).await;

        // Re-send the EXTEND frame the guard already accepted. Capture it by
        // sealing a fresh one and sending it twice: the first is legitimate,
        // the second is a byte-identical replay.
        let (_, msg1) = Initiator::start(&fleet.exit.static_pubkey).expect("nk start");
        let extend = ExtendForward {
            next_hop: fleet.exit.addr,
            noise_msg1: msg1,
        };
        let cell = Cell::new(CellType::Extend, extend.encode()).expect("cell");
        let wire = client.seal_for_depth(&cell, 2);
        // Both go out inside link frames. Writing the bare cell would leave the
        // guard reading 569 bytes across two 564 byte cells, and whether that
        // decoded at all came down to whether a ciphertext byte happened to be
        // a valid link command, which made this test fail about one run in 40
        // and pass the rest for the wrong reason.
        client.write_frame(&wire).await;

        // Control: sent once the very same frame is accepted, and the middle
        // answers EXTEND backward. Without this the refusal below could be the
        // frame being bad rather than it being a repeat.
        let back = client.read_cell().await;
        assert_eq!(
            back.cell_type,
            CellType::Extend,
            "the first send was not served, so nothing below is about the replay"
        );

        // Now the byte-identical repeat. Every hop's Noise counter has already
        // consumed these exact bytes, so the first hop to peel it fails and
        // destroys the circuit, and what arrives is DESTROY for this id.
        client.write_frame(&wire).await;

        let mut destroyed = false;
        for _ in 0..3 {
            let mut buf = vec![0u8; link_frame::link_frame_len(CLIENT_LAYERS)];
            match tokio::time::timeout(Duration::from_secs(10), client.sock.read_exact(&mut buf))
                .await
            {
                Ok(Ok(_)) => {
                    let back = link_frame::decode(&buf, CLIENT_LAYERS, LinkRole::Responder)
                        .expect("decode frame");
                    assert_eq!(back.circ_id, client.keys.id);
                    if back.command == link_frame::LinkCommand::Destroy {
                        destroyed = true;
                        break;
                    }
                }
                // An EOF is acceptable too: the circuit is gone either way.
                Ok(Err(_)) => {
                    destroyed = true;
                    break;
                }
                Err(_) => break,
            }
        }
        assert!(
            destroyed,
            "the replayed cell left the circuit alive: the middle accepted a cell whose \
             Noise counter had already been used"
        );
    })
    .await
    .expect("test timed out");
}

/// Two circuits riding one link do not mix.
///
/// This is the claim multiplexing adds and the previous shape could not make:
/// one connection, two circuit ids, both in flight at the same time. Both
/// EXTENDs are written before either reply is read, so the guard holds two
/// half-built circuits at once and has to keep them apart.
///
/// A mix-up is caught twice over. The id on the returning frame must be the
/// one that asked, and the body must decrypt under that circuit's own
/// transport, which a swap fails in the AEAD rather than merely looking odd.
#[tokio::test]
async fn two_circuits_on_one_link_do_not_mix() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        ensure_crypto_provider();
        let keydir = tempfile::tempdir().expect("keydir");
        let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
        let pki = make_pki();
        let server_config = make_server_config(&pki);
        let connector = Arc::new(make_connector(&pki));
        let over = default_override();
        let fleet = spawn_fleet(
            &auth_priv,
            &over,
            server_config,
            connector.clone(),
            keydir.path(),
        )
        .await;

        // One socket, one PROTO_CLIENT byte, two circuits. Each CREATE carries
        // its own token, because one token buys one circuit.
        let mut sock = tls_connect(&connector, fleet.guard.addr).await;
        sock.write_all(&[super::PROTO_CLIENT]).await.expect("proto");

        let id_a = CircId::new(0x8000_0010).expect("a nonzero id");
        let id_b = CircId::new(0x8000_0011).expect("a nonzero id");
        let mut tx_a =
            MockClient::create_on(&mut sock, &fleet.guard, &auth_priv, [0xC1; 32], id_a).await;
        let mut tx_b =
            MockClient::create_on(&mut sock, &fleet.guard, &auth_priv, [0xC2; 32], id_b).await;

        // Both EXTENDs out before either reply is read.
        let mut pending = HashMap::new();
        for (id, tx) in [(id_a, &mut tx_a), (id_b, &mut tx_b)] {
            let (init, msg1) =
                Initiator::start(&fleet.middle.static_pubkey).expect("nk start");
            let extend = ExtendForward {
                next_hop: fleet.middle.addr,
                noise_msg1: msg1,
            };
            let cell = Cell::new(CellType::Extend, extend.encode()).expect("extend cell");
            let wire = seal_to_me(tx, &cell, CLIENT_LAYERS).expect("seal extend");
            let frame =
                link_frame::encode(CLIENT_LAYERS, id, link_frame::LinkCommand::Data, &wire)
                    .expect("encode extend");
            sock.write_all(&frame).await.expect("write extend");
            pending.insert(id, init);
        }
        sock.flush().await.expect("flush");

        // Two replies, in whatever order the guard finishes the two dials.
        let mut answered = Vec::new();
        for _ in 0..2 {
            let mut buf = vec![0u8; link_frame::link_frame_len(CLIENT_LAYERS)];
            tokio::time::timeout(Duration::from_secs(20), sock.read_exact(&mut buf))
                .await
                .expect("the guard answered only one of the two circuits")
                .expect("read reply");
            let back = link_frame::decode(&buf, CLIENT_LAYERS, LinkRole::Responder)
                .expect("decode reply");
            assert_eq!(
                back.command,
                link_frame::LinkCommand::Data,
                "circuit {:#010x} was destroyed instead of extended",
                back.circ_id.raw()
            );
            let init = pending
                .remove(&back.circ_id)
                .unwrap_or_else(|| panic!("a reply for {:#010x}, which never asked, or a second reply for one that already did", back.circ_id.raw()));

            // Peel under this circuit's own transport, not the other one's.
            let tx = if back.circ_id == id_a {
                &mut tx_a
            } else {
                &mut tx_b
            };
            let peeled = peel(tx, back.body, CLIENT_LAYERS).expect("peel under its own transport");
            let Peeled::ToMe(cell) = peeled else {
                panic!("the guard forwarded a reply it should have addressed to the client");
            };
            assert_eq!(cell.cell_type, CellType::Extend);
            let msg2 = parse_extend_backward(&cell.payload).expect("parse msg2");
            init.finish(&msg2).expect("the middle completed this circuit's handshake");
            answered.push(back.circ_id);
        }

        answered.sort_by_key(|c| c.raw());
        assert_eq!(
            answered,
            vec![id_a, id_b],
            "both circuits on the link must be answered, each on its own id"
        );
        assert!(
            pending.is_empty(),
            "a circuit was left unanswered on a link that served the other"
        );
    })
    .await
    .expect("test timed out");
}

/// A wrong-size frame desynchronises framing and tears the circuit down.
#[tokio::test]
async fn wrong_size_cell_tears_down_the_circuit() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        ensure_crypto_provider();
        let keydir = tempfile::tempdir().expect("keydir");
        let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
        let pki = make_pki();
        let server_config = make_server_config(&pki);
        let connector = Arc::new(make_connector(&pki));
        let over = default_override();
        let fleet = spawn_fleet(
            &auth_priv,
            &over,
            server_config,
            connector.clone(),
            keydir.path(),
        )
        .await;

        let mut client = MockClient::connect(&connector, &fleet.guard, &auth_priv).await;
        let cell = Cell::new(CellType::Data, b"short".to_vec()).expect("cell");
        let wire = client.seal_for_depth(&cell, 1);

        // One byte short of a frame, then close the write half. The guard is
        // blocked waiting for a whole frame and must never process this.
        let frame = link_frame::encode(
            CLIENT_LAYERS,
            client.keys.id,
            link_frame::LinkCommand::Data,
            &wire,
        )
        .expect("encode frame");
        client
            .sock
            .write_all(&frame[..frame.len() - 1])
            .await
            .expect("write short");
        client.sock.flush().await.expect("flush");
        client.sock.shutdown().await.ok();

        let mut buf = vec![0u8; link_frame::link_frame_len(CLIENT_LAYERS)];
        let res = tokio::time::timeout(Duration::from_secs(10), client.sock.read_exact(&mut buf))
            .await
            .expect("relay neither replied nor closed");
        assert!(res.is_err(), "the relay answered a short cell");
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn end_to_end_data_round_trip_via_socks5() {
    tokio::time::timeout(TEST_TIMEOUT, run_data_test())
        .await
        .expect("test timed out");
}

async fn run_data_test() {
    ensure_crypto_provider();
    // An echo server behind a minimal SOCKS5 stub, so the exit's dial path runs
    // for real without reaching the internet.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let echo_addr = echo_listener.local_addr().expect("echo addr");
    tokio::spawn(run_echo_server(echo_listener));

    let socks_listener = TcpListener::bind("127.0.0.1:0").await.expect("socks bind");
    let socks_addr = socks_listener.local_addr().expect("socks addr");
    tokio::spawn(run_socks5_stub(socks_listener, echo_addr));

    let keydir = tempfile::tempdir().expect("keydir");
    let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
    let pki = make_pki();
    let server_config = make_server_config(&pki);
    let connector = Arc::new(make_connector(&pki));
    let over = RelayOverride {
        decodo_proxy_url: Some(format!("socks5://user:pass@{socks_addr}")),
        allowed_exit_ports: vec![echo_addr.port()],
        max_link_buffer_bytes: 256 * 1024 * 1024,
    };
    let fleet = spawn_fleet(
        &auth_priv,
        &over,
        server_config,
        connector.clone(),
        keydir.path(),
    )
    .await;

    let mut client = MockClient::connect(&connector, &fleet.guard, &auth_priv).await;
    client.build_circuit(&fleet).await;

    let connect = ConnectPayload {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
    };
    let cell = Cell::new(CellType::Connect, connect.encode().expect("encode")).expect("cell");
    client.send_to_deepest(&cell).await;

    let payload = b"quiethop round trip".to_vec();
    let data = Cell::new(CellType::Data, payload.clone()).expect("data cell");
    client.send_to_deepest(&data).await;

    let back = tokio::time::timeout(Duration::from_secs(20), client.read_cell())
        .await
        .expect("no DATA came back");
    assert_eq!(back.cell_type, CellType::Data);
    assert_eq!(back.payload, payload, "echo did not round trip");
}

/// A TCP proxy that forwards both directions in 1 to 7 byte writes, yielding
/// between each one.
///
/// This is the condition that exposes a cancellation-unsafe read. TLS sits on
/// top, so plaintext reads come back in small pieces and a cell is almost never
/// delivered in one read. If a select branch holds partial bytes in a buffer it
/// then drops, framing shifts and the next cell fails authentication.
async fn run_chunking_proxy(listener: TcpListener, target: SocketAddr) {
    loop {
        let Ok((inbound, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let Ok(outbound) = TcpStream::connect(target).await else {
                return;
            };
            let (ci, co) = tokio::io::split(inbound);
            let (si, so) = tokio::io::split(outbound);
            tokio::spawn(dribble(ci, so));
            tokio::spawn(dribble(si, co));
        });
    }
}

async fn dribble<R, W>(mut r: R, mut w: W)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut buf = vec![0u8; 8192];
    let mut chunk = 1usize;
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let mut off = 0;
        while off < n {
            let take = chunk.min(n - off);
            if w.write_all(&buf[off..off + take]).await.is_err() {
                return;
            }
            if w.flush().await.is_err() {
                return;
            }
            off += take;
            chunk = if chunk == 7 { 1 } else { chunk + 1 };
            tokio::task::yield_now().await;
        }
    }
    let _ = w.shutdown().await;
}

async fn spawn_chunking_proxy(target: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("proxy bind");
    let addr = listener.local_addr().expect("proxy addr");
    tokio::spawn(run_chunking_proxy(listener, target));
    addr
}

/// Robustness under adverse byte delivery. Not regression evidence for the
/// cancellation-safety bug.
///
/// Every link sits behind a proxy that forwards in 1 to 7 byte writes, and
/// traffic runs in both directions at once. The circuit must carry every byte
/// intact regardless.
///
/// This does not exercise the cancellation-safety defect and passed on 328cbbd
/// with all three select loops still using read_exact. The chunking happens
/// below TLS, and rustls hands up whole records, so a cell written as one
/// record arrives as one plaintext read. The regression evidence for that bug
/// is the pair of deterministic tests in quiethop-crypto's layer module.
#[tokio::test]
async fn circuit_carries_traffic_under_adverse_byte_delivery() {
    tokio::time::timeout(TEST_TIMEOUT, run_adverse_delivery_test())
        .await
        .expect("test timed out");
}

async fn run_adverse_delivery_test() {
    ensure_crypto_provider();

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let echo_addr = echo_listener.local_addr().expect("echo addr");
    tokio::spawn(run_echo_server(echo_listener));

    let socks_listener = TcpListener::bind("127.0.0.1:0").await.expect("socks bind");
    let socks_addr = socks_listener.local_addr().expect("socks addr");
    tokio::spawn(run_socks5_stub(socks_listener, echo_addr));

    let keydir = tempfile::tempdir().expect("keydir");
    let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
    let pki = make_pki();
    let server_config = make_server_config(&pki);
    let connector = Arc::new(make_connector(&pki));
    let over = RelayOverride {
        decodo_proxy_url: Some(format!("socks5://user:pass@{socks_addr}")),
        allowed_exit_ports: vec![echo_addr.port()],
        max_link_buffer_bytes: 256 * 1024 * 1024,
    };

    // Each hop reaches the next through a chunking proxy, so all three links
    // deliver partial cells: client to guard, guard to middle, middle to exit.
    let handles: Vec<RegistryHandle> = (0..3).map(|_| RegistryHandle::new()).collect();
    let exit = spawn_relay(
        Role::Exit,
        &auth_priv,
        &over,
        handles[2].clone(),
        server_config.clone(),
        connector.clone(),
        keydir.path(),
    )
    .await;
    let exit_via = spawn_chunking_proxy(exit.addr).await;

    let middle = spawn_relay(
        Role::Middle,
        &auth_priv,
        &over,
        handles[1].clone(),
        server_config.clone(),
        connector.clone(),
        keydir.path(),
    )
    .await;
    let middle_via = spawn_chunking_proxy(middle.addr).await;

    let guard = spawn_relay(
        Role::Guard,
        &auth_priv,
        &over,
        handles[0].clone(),
        server_config,
        connector.clone(),
        keydir.path(),
    )
    .await;
    let guard_via = spawn_chunking_proxy(guard.addr).await;

    // Every hop is reached through its proxy, so those are the addresses EXTEND
    // carries and therefore the addresses the registry must publish. The keys
    // stay the relays' own, because the handshake is still pinned to them.
    let (after, fresh, until) = current_window();
    let doc = document_from(
        &[
            ("guard", guard_via, guard.static_pubkey),
            ("middle", middle_via, middle.static_pubkey),
            ("exit", exit_via, exit.static_pubkey),
        ],
        &after,
        &fresh,
        &until,
    );
    let doc = Arc::new(doc);
    for h in &handles {
        h.publish(doc.clone());
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Dial the guard through its proxy, still pinning the guard's real key.
    let guard_hop = SpawnedRelay {
        budget: crate::link::Budget::new(),
        addr: guard_via,
        static_pubkey: guard.static_pubkey,
        role: Role::Guard,
    };
    let mut client = MockClient::connect(&connector, &guard_hop, &auth_priv).await;
    client
        .extend_to(&SpawnedRelay {
            addr: middle_via,
            static_pubkey: middle.static_pubkey,
            role: Role::Middle,
            budget: crate::link::Budget::new(),
        })
        .await;
    client
        .extend_to(&SpawnedRelay {
            addr: exit_via,
            static_pubkey: exit.static_pubkey,
            role: Role::Exit,
            budget: crate::link::Budget::new(),
        })
        .await;

    let connect = ConnectPayload {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
    };
    let cell = Cell::new(CellType::Connect, connect.encode().expect("encode")).expect("cell");
    client.send_to_deepest(&cell).await;

    // Bidirectional pressure: write the next cell before reading the previous
    // echo, so the inbound branch and the destination branch are both hot while
    // partial cells are in flight.
    let payloads: Vec<Vec<u8>> = (0..6u8)
        .map(|i| {
            let n = 1 + (i as usize) * 97;
            vec![0xB0 | i; n.min(CELL_PAYLOAD_LEN)]
        })
        .collect();

    for p in &payloads {
        let data = Cell::new(CellType::Data, p.clone()).expect("data cell");
        client.send_to_deepest(&data).await;
    }

    // Collect the echoed bytes. The exit splits a destination read across
    // cells, so compare the concatenation rather than cell boundaries.
    let expected: Vec<u8> = payloads.iter().flatten().copied().collect();
    let mut seen: Vec<u8> = Vec::new();
    while seen.len() < expected.len() {
        let back = tokio::time::timeout(Duration::from_secs(60), client.read_cell())
            .await
            .expect("no DATA came back before the deadline");
        assert_eq!(
            back.cell_type,
            CellType::Data,
            "circuit tore down mid-stream"
        );
        seen.extend_from_slice(&back.payload);
    }
    assert_eq!(
        seen,
        expected,
        "echoed bytes did not survive partial reads: got {} of {} bytes",
        seen.len(),
        expected.len()
    );

    for (i, n) in client.observed.iter().enumerate() {
        assert_eq!(
            *n,
            link_frame::link_frame_len(CLIENT_LAYERS),
            "frame {i} on the client-guard link was {n} bytes"
        );
    }
}

/// Minimal SOCKS5 stub: accepts no-auth and username/password, then connects to
/// a fixed address regardless of the requested one.
async fn run_socks5_stub(listener: TcpListener, target: SocketAddr) {
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            if handle_socks5_session(&mut sock, target).await.is_err() {
                // A test stub: a failed session just ends.
            }
        });
    }
}

async fn handle_socks5_session(sock: &mut TcpStream, target: SocketAddr) -> std::io::Result<()> {
    let mut head = [0u8; 2];
    sock.read_exact(&mut head).await?;
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods).await?;

    if methods.contains(&0x02) {
        sock.write_all(&[0x05, 0x02]).await?;
        let mut uhead = [0u8; 2];
        sock.read_exact(&mut uhead).await?;
        let mut user = vec![0u8; uhead[1] as usize];
        sock.read_exact(&mut user).await?;
        let mut plen = [0u8; 1];
        sock.read_exact(&mut plen).await?;
        let mut pass = vec![0u8; plen[0] as usize];
        sock.read_exact(&mut pass).await?;
        sock.write_all(&[0x01, 0x00]).await?;
    } else {
        sock.write_all(&[0x05, 0x00]).await?;
    }

    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    match req[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            sock.read_exact(&mut rest).await?;
        }
        0x03 => {
            let mut l = [0u8; 1];
            sock.read_exact(&mut l).await?;
            let mut rest = vec![0u8; l[0] as usize + 2];
            sock.read_exact(&mut rest).await?;
        }
        0x04 => {
            let mut rest = [0u8; 18];
            sock.read_exact(&mut rest).await?;
        }
        _ => return Ok(()),
    }

    sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    let mut upstream = TcpStream::connect(target).await?;
    tokio::io::copy_bidirectional(sock, &mut upstream).await?;
    Ok(())
}

async fn run_echo_server(listener: TcpListener) {
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });
    }
}

/// A guard must refuse an EXTEND to an address the registry does not publish for
/// the role directly downstream of it, and to a listed relay carrying the wrong
/// role, and must serve one that matches (ARCHITECTURE 5.5).
#[tokio::test]
async fn extend_is_refused_unless_the_registry_publishes_the_next_hop() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        ensure_crypto_provider();
        let keydir = tempfile::tempdir().expect("keydir");
        let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
        let pki = make_pki();
        let server_config = make_server_config(&pki);
        let connector = Arc::new(make_connector(&pki));
        let over = default_override();
        let fleet = spawn_fleet(
            &auth_priv,
            &over,
            server_config,
            connector.clone(),
            keydir.path(),
        )
        .await;
        let (after, fresh, until) = current_window();

        // Control: the published middle is served, so every refusal below is
        // attributable to the registry change that caused it.
        let mut ok =
            MockClient::connect_with_token(&connector, &fleet.guard, &auth_priv, [0xB1; 32]).await;
        assert!(
            ok.try_extend_to(fleet.middle.addr, fleet.middle.static_pubkey)
                .await,
            "the registry publishes this middle, so the guard must serve it"
        );
        drop(ok);

        // The exit is in the registry but is not the role downstream of a guard.
        let mut wrong_role =
            MockClient::connect_with_token(&connector, &fleet.guard, &auth_priv, [0xB2; 32]).await;
        assert!(
            !wrong_role
                .try_extend_to(fleet.exit.addr, fleet.exit.static_pubkey)
                .await,
            "a guard must not extend straight to an exit"
        );
        drop(wrong_role);

        // Republish with the middle at an address nothing listens on, leaving
        // the real middle unlisted. Its own listener is untouched, so a relay
        // that consulted anything other than the registry would still reach it.
        let mut doc = fleet.document(&after, &fresh, &until);
        let unlisted: SocketAddr = "127.0.0.1:9".parse().unwrap();
        for e in doc.document.relays.iter_mut() {
            if e.role == "middle" {
                e.ip = unlisted.ip().to_string();
                e.port = unlisted.port();
            }
        }
        fleet.publish(doc);

        let mut refused =
            MockClient::connect_with_token(&connector, &fleet.guard, &auth_priv, [0xB3; 32]).await;
        assert!(
            !refused
                .try_extend_to(fleet.middle.addr, fleet.middle.static_pubkey)
                .await,
            "an address the registry does not publish must be refused"
        );
    })
    .await
    .expect("test timed out");
}

/// A middle must accept a relay link only from an address the registry lists
/// with the role directly upstream of it.
#[tokio::test]
async fn inbound_is_refused_from_an_unlisted_peer() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        ensure_crypto_provider();
        let keydir = tempfile::tempdir().expect("keydir");
        let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
        let pki = make_pki();
        let server_config = make_server_config(&pki);
        let connector = Arc::new(make_connector(&pki));
        let over = default_override();
        let fleet = spawn_fleet(
            &auth_priv,
            &over,
            server_config,
            connector.clone(),
            keydir.path(),
        )
        .await;
        let (after, fresh, until) = current_window();

        // Control: the registry lists a guard on loopback, which is where this
        // test dials from, so the middle serves the link.
        assert!(
            relay_link_is_served(&connector, &fleet.middle).await,
            "a listed upstream address must be accepted"
        );

        // Move the guard off loopback. Nothing else changes, so the refusal
        // below is attributable to the guard's published address alone.
        let mut doc = fleet.document(&after, &fresh, &until);
        for e in doc.document.relays.iter_mut() {
            if e.role == "guard" {
                e.ip = "198.51.100.7".to_string();
            }
        }
        fleet.publish(doc);

        assert!(
            !relay_link_is_served(&connector, &fleet.middle).await,
            "an address not listed for the upstream role must be refused"
        );
    })
    .await
    .expect("test timed out");
}

/// Open a relay link and report whether the hop completed its handshake.
async fn relay_link_is_served(connector: &TlsConnector, target: &SpawnedRelay) -> bool {
    let layers = relay_link_layers(target.role);
    let mut sock = tls_connect(connector, target.addr).await;
    if sock.write_all(&[super::PROTO_RELAY]).await.is_err() {
        return false;
    }
    let (init, msg1) = Initiator::start(&target.static_pubkey).expect("nk start");
    // A relay link CREATE carries the handshake alone: no token appears here.
    let circ_id = CircId::new(0x8000_00f1).expect("nonzero");
    let Ok(create) = link_frame::encode(layers, circ_id, link_frame::LinkCommand::Create, &msg1)
    else {
        return false;
    };
    if sock.write_all(&create).await.is_err() || sock.flush().await.is_err() {
        return false;
    }
    let mut buf = vec![0u8; link_frame::link_frame_len(layers)];
    match tokio::time::timeout(Duration::from_secs(10), sock.read_exact(&mut buf)).await {
        Ok(Ok(_)) => {}
        _ => return false,
    }
    let Ok(back) = link_frame::decode(&buf, layers, LinkRole::Responder) else {
        return false;
    };
    if back.command != link_frame::LinkCommand::Created || back.circ_id != circ_id {
        return false;
    }
    let Ok(msg2_bytes) = link_frame::payload(back.body, NOISE_MSG_LEN) else {
        return false;
    };
    let mut msg2 = [0u8; NOISE_MSG_LEN];
    msg2.copy_from_slice(msg2_bytes);
    init.finish(&msg2).is_ok()
}

/// Layers on the inbound link of a relay in this role, which fixes its frame
/// size: a middle sees two and an exit one.
fn relay_link_layers(role: Role) -> Layers {
    match role {
        Role::Guard => Layers::new(3),
        Role::Middle => Layers::new(2),
        Role::Exit => Layers::new(1),
    }
}

/// Outbound SNI comes from the registry entry's tls_name.
///
/// The test certificate is issued for TEST_HOSTNAME only, so publishing any
/// other name makes the guard's outbound handshake to the middle fail. A relay
/// that took the name from configuration or from its own RELAY_HOSTNAME would
/// still connect and the refusal would not appear.
#[tokio::test]
async fn outbound_sni_comes_from_the_registry_tls_name() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        ensure_crypto_provider();
        let keydir = tempfile::tempdir().expect("keydir");
        let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
        let pki = make_pki();
        let server_config = make_server_config(&pki);
        let connector = Arc::new(make_connector(&pki));
        let over = default_override();
        let fleet = spawn_fleet(
            &auth_priv,
            &over,
            server_config,
            connector.clone(),
            keydir.path(),
        )
        .await;
        let (after, fresh, until) = current_window();

        // Control: the published name matches the certificate.
        let mut ok =
            MockClient::connect_with_token(&connector, &fleet.guard, &auth_priv, [0xB4; 32]).await;
        assert!(
            ok.try_extend_to(fleet.middle.addr, fleet.middle.static_pubkey)
                .await,
            "the published tls_name matches the certificate, so the extend must work"
        );
        drop(ok);

        let mut doc = fleet.document(&after, &fresh, &until);
        for e in doc.document.relays.iter_mut() {
            if e.role == "middle" {
                e.tls_name = "not-the-certificate-name.invalid".to_string();
            }
        }
        fleet.publish(doc);

        let mut refused =
            MockClient::connect_with_token(&connector, &fleet.guard, &auth_priv, [0xB5; 32]).await;
        assert!(
            !refused
                .try_extend_to(fleet.middle.addr, fleet.middle.static_pubkey)
                .await,
            "a tls_name the certificate does not cover must fail the outbound handshake"
        );
    })
    .await
    .expect("test timed out");
}

/// A document in hand stays in service until its valid_until and no longer.
///
/// This is the state a run of failed refreshes leaves behind: the relay keeps
/// the last verified document and keeps serving from it, then refuses once it
/// expires rather than widening the window (ARCHITECTURE 5.5).
#[tokio::test]
async fn circuits_are_refused_once_the_held_document_expires() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        ensure_crypto_provider();
        let keydir = tempfile::tempdir().expect("keydir");
        let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
        let pki = make_pki();
        let server_config = make_server_config(&pki);
        let connector = Arc::new(make_connector(&pki));
        let over = default_override();
        let fleet = spawn_fleet(
            &auth_priv,
            &over,
            server_config,
            connector.clone(),
            keydir.path(),
        )
        .await;

        // Control: inside the window, with no refresh having happened at all.
        let mut ok =
            MockClient::connect_with_token(&connector, &fleet.guard, &auth_priv, [0xB6; 32]).await;
        assert!(
            ok.try_extend_to(fleet.middle.addr, fleet.middle.static_pubkey)
                .await,
            "a document inside its window must be served"
        );
        drop(ok);

        // The same document, published with a window that has already closed.
        // Nothing else changes, so a relay that served it anyway would be
        // ignoring valid_until rather than failing for another reason.
        let hour = now_unix().div_euclid(3600) * 3600;
        let expired_after = rfc3339_utc(hour - 12 * 3600);
        let expired_fresh = rfc3339_utc(hour - 11 * 3600);
        let expired_until = rfc3339_utc(hour - 6 * 3600);
        fleet.publish(fleet.document(&expired_after, &expired_fresh, &expired_until));

        let mut refused =
            MockClient::connect_with_token(&connector, &fleet.guard, &auth_priv, [0xB7; 32]).await;
        assert!(
            !refused
                .try_extend_to(fleet.middle.addr, fleet.middle.static_pubkey)
                .await,
            "an expired document must not be served, with no grace period"
        );
    })
    .await
    .expect("test timed out");
}
