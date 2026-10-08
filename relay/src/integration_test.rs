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
use quiethop_crypto::layer::{peel, seal_forward, seal_to_me, Peeled};
use quiethop_crypto::noise::{Initiator, Transport, NOISE_MSG_LEN, STATIC_KEY_LEN};
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
}

fn default_override() -> RelayOverride {
    RelayOverride {
        decodo_proxy_url: None,
        allowed_exit_ports: vec![80, 443],
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
        .map(|(role, addr, key)| RelayEntry {
            id: format!("test-{role}"),
            operator_id: format!("op-{role}"),
            host_id: format!("host-{role}"),
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
    static_pubkey: [u8; STATIC_KEY_LEN],
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
    ));
    SpawnedRelay {
        addr,
        static_pubkey,
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
struct MockClient {
    sock: ClientTlsStream<TcpStream>,
    guard: Transport,
    middle: Option<Transport>,
    exit: Option<Transport>,
    /// Every frame size observed on the client-guard link, in both directions.
    observed: Vec<usize>,
}

/// The client-guard link carries three layers.
const CLIENT_LAYERS: usize = 3;

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
        let mut sock = tls_connect(connector, guard.addr).await;
        sock.write_all(&[super::PROTO_CLIENT]).await.expect("proto");
        let token = raw_sign(&m_raw, auth_priv);
        sock.write_all(&m_raw).await.expect("m_raw");
        sock.write_all(&token).await.expect("token");

        let (init, msg1) = Initiator::start(&guard.static_pubkey).expect("nk start");
        sock.write_all(&msg1).await.expect("msg1");
        sock.flush().await.expect("flush");
        let mut msg2 = [0u8; NOISE_MSG_LEN];
        sock.read_exact(&mut msg2).await.expect("msg2");
        let guard_tx = init.finish(&msg2).expect("nk finish");

        Self {
            sock,
            guard: guard_tx,
            middle: None,
            exit: None,
            observed: Vec::new(),
        }
    }

    /// Number of hops whose transports are established.
    fn hops(&self) -> usize {
        1 + self.middle.is_some() as usize + self.exit.is_some() as usize
    }

    /// Seal a cell for the deepest established hop and send it, wrapping it
    /// once per nearer hop. Records the on-wire size.
    async fn send_to_deepest(&mut self, cell: &Cell) {
        let wire = self.seal_for_depth(cell, self.hops());
        self.write_frame(&wire).await;
    }

    /// Seal `cell` for hop number `depth` (1 = guard, 2 = middle, 3 = exit).
    fn seal_for_depth(&mut self, cell: &Cell, depth: usize) -> Vec<u8> {
        // layers counts from the innermost hop outward: the exit is 1.
        let layers = CLIENT_LAYERS - (depth - 1);
        let mut buf = match depth {
            1 => seal_to_me(&mut self.guard, cell, layers).expect("seal guard"),
            2 => seal_to_me(self.middle.as_mut().expect("middle"), cell, layers)
                .expect("seal middle"),
            3 => seal_to_me(self.exit.as_mut().expect("exit"), cell, layers).expect("seal exit"),
            other => panic!("bad depth {other}"),
        };
        // Wrap once per hop nearer the client.
        if depth >= 3 {
            buf = seal_forward(
                self.middle.as_mut().expect("middle"),
                &buf,
                CLIENT_LAYERS - 1,
            )
            .expect("wrap middle");
        }
        if depth >= 2 {
            buf = seal_forward(&mut self.guard, &buf, CLIENT_LAYERS).expect("wrap guard");
        }
        buf
    }

    async fn write_frame(&mut self, wire: &[u8]) {
        assert_eq!(
            wire.len(),
            link_cell_len(CLIENT_LAYERS),
            "a frame on the client-guard link was not the fixed size"
        );
        self.observed.push(wire.len());
        self.sock.write_all(wire).await.expect("write frame");
        self.sock.flush().await.expect("flush");
    }

    /// Read exactly one fixed-size frame. No length prefix exists on the wire.
    async fn read_frame(&mut self) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0u8; link_cell_len(CLIENT_LAYERS)];
        self.sock.read_exact(&mut buf).await?;
        self.observed.push(buf.len());
        Ok(buf)
    }

    /// Read one frame and peel every established layer until a cell appears.
    async fn read_cell(&mut self) -> Cell {
        let wire = self.read_frame().await.expect("read frame");
        let mut blob = match peel(&mut self.guard, &wire, CLIENT_LAYERS).expect("peel guard") {
            Peeled::ToMe(cell) => return cell,
            Peeled::Forward(b) => b,
        };
        if let Some(mid) = self.middle.as_mut() {
            blob = match peel(mid, &blob, CLIENT_LAYERS - 1).expect("peel middle") {
                Peeled::ToMe(cell) => return cell,
                Peeled::Forward(b) => b,
            };
        }
        let exit = self
            .exit
            .as_mut()
            .expect("exit transport for innermost peel");
        match peel(exit, &blob, 1).expect("peel exit") {
            Peeled::ToMe(cell) => cell,
            Peeled::Forward(_) => panic!("FORWARD arrived at the innermost layer"),
        }
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
        if self.middle.is_none() {
            self.middle = Some(tx);
        } else {
            self.exit = Some(tx);
        }
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
        if self.sock.write_all(&wire).await.is_err() || self.sock.flush().await.is_err() {
            return false;
        }
        let Ok(Ok(wire)) = tokio::time::timeout(Duration::from_secs(10), self.read_frame()).await
        else {
            return false;
        };
        let Ok(peeled) = peel(&mut self.guard, &wire, CLIENT_LAYERS) else {
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
                if self.middle.is_none() {
                    self.middle = Some(tx);
                } else {
                    self.exit = Some(tx);
                }
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
            link_cell_len(CLIENT_LAYERS),
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
        assert_eq!(link_cell_len(3), 564);
        assert_eq!(link_cell_len(2), 547);
        assert_eq!(link_cell_len(1), 530);
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
            addr: fleet.guard.addr,
            static_pubkey: fleet.exit.static_pubkey,
        };
        assert_ne!(impostor.static_pubkey, fleet.guard.static_pubkey);

        let mut sock = tls_connect(&connector, impostor.addr).await;
        sock.write_all(&[super::PROTO_CLIENT]).await.expect("proto");
        let m_raw: [u8; 32] = [0xA5; 32];
        let token = raw_sign(&m_raw, &auth_priv);
        sock.write_all(&m_raw).await.expect("m_raw");
        sock.write_all(&token).await.expect("token");
        let (init, msg1) = Initiator::start(&impostor.static_pubkey).expect("nk start");
        sock.write_all(&msg1).await.expect("msg1");
        sock.flush().await.expect("flush");

        // The guard cannot decrypt message 1 under its own static key, so it
        // closes without replying. Either an EOF or an unusable message 2 is
        // acceptable; what must not happen is a working circuit.
        let mut msg2 = [0u8; NOISE_MSG_LEN];
        match sock.read_exact(&mut msg2).await {
            Err(_) => {}
            Ok(_) => {
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

/// A tampered cell tears the circuit down with no reply.
#[tokio::test]
async fn tampered_cell_tears_down_the_circuit() {
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
        client.sock.write_all(&wire).await.expect("write");
        client.sock.flush().await.expect("flush");

        // The guard closes. Reading must reach EOF rather than a frame.
        let mut buf = vec![0u8; link_cell_len(CLIENT_LAYERS)];
        let res = tokio::time::timeout(Duration::from_secs(10), client.sock.read_exact(&mut buf))
            .await
            .expect("relay neither replied nor closed");
        assert!(res.is_err(), "the relay answered a tampered cell");
    })
    .await
    .expect("test timed out");
}

/// A replayed cell tears the circuit down: the Noise counter has advanced.
#[tokio::test]
async fn replayed_cell_tears_down_the_circuit() {
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
        client.sock.write_all(&wire).await.expect("first send");
        client.sock.flush().await.expect("flush");
        client.sock.write_all(&wire).await.expect("replay");
        client.sock.flush().await.expect("flush");

        // The middle rejects the replay, which tears down the whole circuit,
        // so the client eventually sees the guard close.
        let mut buf = vec![0u8; link_cell_len(CLIENT_LAYERS)];
        let mut closed = false;
        for _ in 0..3 {
            match tokio::time::timeout(Duration::from_secs(10), client.sock.read_exact(&mut buf))
                .await
            {
                Ok(Err(_)) => {
                    closed = true;
                    break;
                }
                Ok(Ok(_)) => continue,
                Err(_) => break,
            }
        }
        assert!(closed, "the replayed cell did not tear the circuit down");
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

        // One byte short of a cell, then close the write half. The guard is
        // blocked in read_exact for a full cell and must never process this.
        client
            .sock
            .write_all(&wire[..wire.len() - 1])
            .await
            .expect("write short");
        client.sock.flush().await.expect("flush");
        client.sock.shutdown().await.ok();

        let mut buf = vec![0u8; link_cell_len(CLIENT_LAYERS)];
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

/// A relay link carries exactly one circuit, so a second CIRCUIT_START after a
/// finished circuit is not served and the link is closed (DECISIONS 15).
///
/// The control is the first circuit in the same test: it completes its
/// handshake on the same link, so a failure to serve the second one cannot be
/// explained by the relay refusing circuits in general.
#[tokio::test]
async fn a_second_circuit_start_on_a_finished_link_is_not_served() {
    tokio::time::timeout(TEST_TIMEOUT, run_one_circuit_per_link_test())
        .await
        .expect("test timed out");
}

async fn run_one_circuit_per_link_test() {
    ensure_crypto_provider();
    let keydir = tempfile::tempdir().expect("keydir");
    let auth_priv = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
    let pki = make_pki();
    let server_config = make_server_config(&pki);
    let connector = Arc::new(make_connector(&pki));
    let over = default_override();

    let registry = RegistryHandle::new();
    let exit = spawn_relay(
        Role::Exit,
        &auth_priv,
        &over,
        registry.clone(),
        server_config,
        connector.clone(),
        keydir.path(),
    )
    .await;
    // This test opens the relay link itself, so the registry must list a middle
    // at the address it dials from, which is loopback.
    let (after, fresh, until) = current_window();
    registry.publish(Arc::new(document_from(
        &[
            (
                "middle",
                "127.0.0.1:1".parse().unwrap(),
                [0u8; STATIC_KEY_LEN],
            ),
            ("exit", exit.addr, exit.static_pubkey),
        ],
        &after,
        &fresh,
        &until,
    )));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let frame_len = link_cell_len(1);
    let mut sock = tls_connect(&connector, exit.addr).await;
    sock.write_all(&[super::PROTO_RELAY]).await.expect("proto");

    // Control: the first circuit on this link completes its handshake.
    let (init1, msg1) = Initiator::start(&exit.static_pubkey).expect("nk start");
    sock.write_all(&[super::CIRCUIT_START])
        .await
        .expect("start");
    sock.write_all(&msg1).await.expect("msg1");
    sock.flush().await.expect("flush");
    let mut msg2 = [0u8; NOISE_MSG_LEN];
    sock.read_exact(&mut msg2)
        .await
        .expect("the first circuit must be served");
    let mut tx1 = init1.finish(&msg2).expect("nk finish");

    // End the first circuit cleanly.
    let close = Cell::new(CellType::CloseRequest, Vec::new()).expect("close cell");
    let close_wire = seal_to_me(&mut tx1, &close, 1).expect("seal close");
    sock.write_all(&close_wire).await.expect("close request");
    sock.flush().await.expect("flush");

    let mut ack = vec![0u8; frame_len];
    sock.read_exact(&mut ack).await.expect("close ack");
    match peel(&mut tx1, &ack, 1).expect("peel ack") {
        Peeled::ToMe(c) => assert_eq!(c.cell_type, CellType::CloseAck, "expected CLOSE_ACK"),
        Peeled::Forward(_) => panic!("FORWARD at the innermost layer"),
    }

    // A second CIRCUIT_START must not be served. The relay has closed the link,
    // so either the write fails or the read reaches EOF. What must not happen is
    // a usable handshake reply.
    let (init2, msg1_b) = Initiator::start(&exit.static_pubkey).expect("nk start 2");
    let _ = sock.write_all(&[super::CIRCUIT_START]).await;
    let _ = sock.write_all(&msg1_b).await;
    let _ = sock.flush().await;

    let mut msg2_b = [0u8; NOISE_MSG_LEN];
    let outcome = tokio::time::timeout(Duration::from_secs(10), sock.read_exact(&mut msg2_b)).await;
    match outcome {
        Err(_) => {}
        Ok(Err(_)) => {}
        Ok(Ok(_)) => {
            assert!(
                init2.finish(&msg2_b).is_err(),
                "a second circuit was served on a link that had already finished one"
            );
        }
    }
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
        addr: guard_via,
        static_pubkey: guard.static_pubkey,
    };
    let mut client = MockClient::connect(&connector, &guard_hop, &auth_priv).await;
    client
        .extend_to(&SpawnedRelay {
            addr: middle_via,
            static_pubkey: middle.static_pubkey,
        })
        .await;
    client
        .extend_to(&SpawnedRelay {
            addr: exit_via,
            static_pubkey: exit.static_pubkey,
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
            link_cell_len(CLIENT_LAYERS),
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
    let mut sock = tls_connect(connector, target.addr).await;
    if sock.write_all(&[super::PROTO_RELAY]).await.is_err() {
        return false;
    }
    let (init, msg1) = Initiator::start(&target.static_pubkey).expect("nk start");
    if sock.write_all(&[super::CIRCUIT_START]).await.is_err()
        || sock.write_all(&msg1).await.is_err()
        || sock.flush().await.is_err()
    {
        return false;
    }
    let mut msg2 = [0u8; NOISE_MSG_LEN];
    match tokio::time::timeout(Duration::from_secs(10), sock.read_exact(&mut msg2)).await {
        Ok(Ok(_)) => init.finish(&msg2).is_ok(),
        _ => false,
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
