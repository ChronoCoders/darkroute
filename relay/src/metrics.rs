//! Prometheus metrics endpoint for the relay.
//!
//! Exposes a `/metrics` HTTP endpoint on the metrics port (see
//! ARCHITECTURE.md §5.1). The relay registers two counters at startup:
//!
//!   * `quiethop_tokens_verified_total`: tokens that passed verify()
//!   * `quiethop_tokens_rejected_total{reason}`: tokens that failed verify(),
//!     labelled by failure reason (`invalid_signature`, `replayed`,
//!     `token_too_short`).
//!
//! The HTTP server is intentionally minimal: it parses just the request
//! line, serves the prometheus text format for GET /metrics, and returns
//! 404 for everything else. This avoids pulling a full HTTP framework on
//! a port that handles low-rate operator traffic only.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use prometheus::{Encoder, IntCounter, IntCounterVec, Opts, Registry, TextEncoder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::token::TokenError;

const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_HEAD: usize = 4096;

static REGISTRY: OnceLock<Registry> = OnceLock::new();
static TOKENS_VERIFIED: OnceLock<IntCounter> = OnceLock::new();
static TOKENS_REJECTED: OnceLock<IntCounterVec> = OnceLock::new();

fn registry() -> &'static Registry {
    REGISTRY.get_or_init(Registry::new)
}

fn tokens_verified() -> &'static IntCounter {
    TOKENS_VERIFIED.get_or_init(|| {
        // IntCounter::new only fails on invalid metric names; the literal
        // here is a valid prometheus identifier so the panic path is
        // unreachable.
        let c = IntCounter::new(
            "quiethop_tokens_verified_total",
            "Tokens that passed verify() since startup",
        )
        .expect("static counter name is valid");
        // register only fails on duplicate registration; OnceLock ensures
        // this closure runs at most once per process.
        registry()
            .register(Box::new(c.clone()))
            .expect("static counter registration is unique");
        c
    })
}

fn tokens_rejected() -> &'static IntCounterVec {
    TOKENS_REJECTED.get_or_init(|| {
        let opts = Opts::new(
            "quiethop_tokens_rejected_total",
            "Tokens rejected by verify() since startup, labelled by reason",
        );
        let c = IntCounterVec::new(opts, &["reason"])
            .expect("static counter vec name and labels are valid");
        registry()
            .register(Box::new(c.clone()))
            .expect("static counter vec registration is unique");
        // Pre-create label series so /metrics output is stable even with
        // no traffic yet (prometheus skips uninitialized vectors).
        c.with_label_values(&["invalid_signature"]);
        c.with_label_values(&["replayed"]);
        c.with_label_values(&["token_too_short"]);
        c
    })
}

static FRAMES_DROPPED: OnceLock<IntCounterVec> = OnceLock::new();
static WRITER_TURNS: OnceLock<IntCounterVec> = OnceLock::new();
static CIRCUIT_SENDMES: OnceLock<IntCounterVec> = OnceLock::new();

/// Turns the link writer took, split by whether more than one circuit had a
/// frame waiting at that moment.
///
/// A contended turn is one where the rotation held at least two circuits, so
/// the writer had a real choice of which to serve. It is the only way to tell a
/// fair writer from a writer that was never tested: with one circuit queued at
/// a time, every writer looks fair. The fairness test asserts this rose, so a
/// run where no backlog formed fails rather than passing on nothing
/// (docs/DECISIONS.md entry 27).
fn writer_turns() -> &'static IntCounterVec {
    WRITER_TURNS.get_or_init(|| {
        let opts = Opts::new(
            "quiethop_link_writer_turns_total",
            "Link writer turns since startup, labelled by whether the choice was contended",
        );
        let c = IntCounterVec::new(opts, &["contended"])
            .expect("static counter vec name and labels are valid");
        registry()
            .register(Box::new(c.clone()))
            .expect("static counter vec registration is unique");
        for v in ["true", "false"] {
            c.with_label_values(&[v]);
        }
        c
    })
}

/// One relay's writer turns, which record to the process counter as they count.
///
/// Same reason as `SendmeTally`: the exported counter is per process and every
/// relay a test binary starts feeds it, so a test that reads the metric cannot
/// tell its own links' turns from another test's.
#[derive(Clone, Default)]
pub struct WriterTurnTally {
    counts: Arc<WriterTurnCounts>,
}

#[derive(Default)]
struct WriterTurnCounts {
    contended: AtomicU64,
    uncontended: AtomicU64,
}

impl WriterTurnTally {
    pub fn new() -> Self {
        Self::default()
    }

    /// One writer turn. `contended` means another circuit also had a frame
    /// waiting.
    pub fn record(&self, contended: bool) {
        self.slot(contended).fetch_add(1, Ordering::Relaxed);
        writer_turns()
            .with_label_values(&[if contended { "true" } else { "false" }])
            .inc();
    }

    /// Turns this relay has recorded. Test only.
    #[cfg(test)]
    pub fn count(&self, contended: bool) -> u64 {
        self.slot(contended).load(Ordering::Relaxed)
    }

    fn slot(&self, contended: bool) -> &AtomicU64 {
        if contended {
            &self.counts.contended
        } else {
            &self.counts.uncontended
        }
    }
}

/// Circuit-level SENDMEs this relay sent and received, which is how an operator
/// sees whether flow control is engaging at all.
///
/// Only the exit's windows engage, so these count the exit's end of every
/// circuit through this relay (SECURITY_MODEL 6.4).
fn circuit_sendmes() -> &'static IntCounterVec {
    CIRCUIT_SENDMES.get_or_init(|| {
        let opts = Opts::new(
            "quiethop_circuit_sendmes_total",
            "Circuit-level SENDMEs since startup, labelled by direction",
        );
        let c = IntCounterVec::new(opts, &["direction"])
            .expect("static counter vec name and labels are valid");
        registry()
            .register(Box::new(c.clone()))
            .expect("static counter vec registration is unique");
        for v in ["sent", "received"] {
            c.with_label_values(&[v]);
        }
        c
    })
}

/// Which way a SENDME went, from this relay's point of view.
#[derive(Debug, Clone, Copy)]
pub enum SendmeDirection {
    /// Owed for data this relay delivered, so it acknowledges the peer's data.
    Sent,
    /// Received from the peer, acknowledging data this relay sent.
    Received,
}

fn sendme_label(direction: SendmeDirection) -> &'static str {
    match direction {
        SendmeDirection::Sent => "sent",
        SendmeDirection::Received => "received",
    }
}

/// One relay's SENDME tally, which records to the process counter as it counts.
///
/// The exported counter is per process, which is what an operator wants and
/// what a test cannot attribute: every relay a test binary starts adds to the
/// same counter, so a before and after delta can be another test's traffic.
/// A tally belongs to one relay, and going through it is the only path to the
/// metric, so the two cannot drift apart.
#[derive(Clone, Default)]
pub struct SendmeTally {
    counts: Arc<SendmeCounts>,
}

#[derive(Default)]
struct SendmeCounts {
    sent: AtomicU64,
    received: AtomicU64,
}

impl SendmeTally {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, direction: SendmeDirection) {
        self.slot(direction).fetch_add(1, Ordering::Relaxed);
        circuit_sendmes()
            .with_label_values(&[sendme_label(direction)])
            .inc();
    }

    /// SENDMEs this relay has recorded in one direction. Test only.
    ///
    /// The full-window test asserts both directions moved on the exit it
    /// started, so a run that carried the bytes without crossing a window
    /// boundary fails rather than passing on nothing.
    #[cfg(test)]
    pub fn count(&self, direction: SendmeDirection) -> u64 {
        self.slot(direction).load(Ordering::Relaxed)
    }

    fn slot(&self, direction: SendmeDirection) -> &AtomicU64 {
        match direction {
            SendmeDirection::Sent => &self.counts.sent,
            SendmeDirection::Received => &self.counts.received,
        }
    }
}

/// Link frames dropped without being delivered, labelled by why.
///
/// A dropped frame is routine rather than alarming: a DESTROY this relay sent
/// and a DATA the peer already had in flight cross on the wire, and on a link
/// carrying many circuits that must not be fatal. The counter is what keeps the
/// drop visible instead of silent (ARCHITECTURE 5.5).
fn frames_dropped() -> &'static IntCounterVec {
    FRAMES_DROPPED.get_or_init(|| {
        let opts = Opts::new(
            "quiethop_link_frames_dropped_total",
            "Link frames dropped since startup, labelled by reason",
        );
        let c = IntCounterVec::new(opts, &["reason"])
            .expect("static counter vec name and labels are valid");
        registry()
            .register(Box::new(c.clone()))
            .expect("static counter vec registration is unique");
        for r in [
            "not_open",
            "before_created",
            "create_collision",
            "create_quarantined",
            "link_full",
            "queue_full",
        ] {
            c.with_label_values(&[r]);
        }
        c
    })
}

/// Reasons a frame was dropped. One per rule in ARCHITECTURE 5.5, so a reader
/// of /metrics can tell a routine crossing from a peer exceeding its window.
#[derive(Debug, Clone, Copy)]
pub enum DropReason {
    /// The circuit id is not open on this link.
    NotOpen,
    /// DATA on a circuit still awaiting CREATED.
    BeforeCreated,
    /// A CREATE naming an id already open.
    CreateCollision,
    /// A CREATE naming an id still in quarantine.
    CreateQuarantined,
    /// A CREATE beyond MAX_CIRCUITS_PER_LINK.
    LinkFull,
    /// The circuit is at MAX_CIRCUIT_QUEUE, so the peer exceeded its window.
    QueueFull,
    /// The link is at MAX_CONTROL_QUEUE, so a DESTROY went unsent.
    ControlQueueFull,
    /// A peer DESTROY arrived for a circuit whose task had already ended, so
    /// the signal had no receiver left.
    DestroySignalLost,
    /// A socket write made no progress inside CELL_WRITE_TIMEOUT.
    WriteTimeout,
    /// A CREATE refused because the relay-wide link buffer budget was reached.
    BufferBudget,
}

pub fn record_frame_dropped(reason: DropReason) {
    let label = match reason {
        DropReason::NotOpen => "not_open",
        DropReason::BeforeCreated => "before_created",
        DropReason::CreateCollision => "create_collision",
        DropReason::CreateQuarantined => "create_quarantined",
        DropReason::LinkFull => "link_full",
        DropReason::QueueFull => "queue_full",
        DropReason::ControlQueueFull => "control_queue_full",
        DropReason::DestroySignalLost => "destroy_signal_lost",
        DropReason::WriteTimeout => "write_timeout",
        DropReason::BufferBudget => "buffer_budget",
    };
    frames_dropped().with_label_values(&[label]).inc();
}

/// Eager registration of all metric families. Called once at startup so
/// the /metrics endpoint always returns a populated payload, even before
/// the first connection arrives.
/// Current value of the dropped-frame counter for one reason label.
///
/// Test only. A dropped DESTROY is allowed to be lost but not to be lost
/// quietly, and that is only true if something reads this back.
#[cfg(test)]
pub fn dropped_count(reason: &str) -> u64 {
    frames_dropped().with_label_values(&[reason]).get()
}

pub fn init() {
    let _ = tokens_verified();
    let _ = frames_dropped();
    let _ = tokens_rejected();
}

pub fn record_verified() {
    tokens_verified().inc();
}

pub fn record_rejected(err: &TokenError) {
    let reason = match err {
        TokenError::InvalidSignature => "invalid_signature",
        TokenError::Replayed => "replayed",
        TokenError::TokenTooShort => "token_too_short",
    };
    tokens_rejected().with_label_values(&[reason]).inc();
}

/// Serve one request on the metrics socket. The caller spawns this per
/// accepted connection. Errors are surfaced to the caller for logging;
/// the connection is closed regardless.
pub async fn serve(mut sock: TcpStream) -> io::Result<()> {
    let path = match read_request_path(&mut sock).await {
        Ok(p) => p,
        Err(e) => {
            // Best-effort 400, then close.
            let _ = sock
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            let _ = sock.shutdown().await;
            return Err(e);
        }
    };

    if path == "/metrics" {
        let body = encode_metrics()?;
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            TextEncoder::new().format_type(),
            body.len()
        );
        sock.write_all(header.as_bytes()).await?;
        sock.write_all(&body).await?;
    } else {
        sock.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await?;
    }
    sock.shutdown().await?;
    Ok(())
}

async fn read_request_path(sock: &mut TcpStream) -> io::Result<String> {
    let mut buf = vec![0u8; MAX_REQUEST_HEAD];
    let mut read = 0usize;
    loop {
        let n = match timeout(REQUEST_READ_TIMEOUT, sock.read(&mut buf[read..])).await {
            Ok(r) => r?,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "request read timeout",
                ))
            }
        };
        if n == 0 {
            break;
        }
        read += n;
        if buf[..read].windows(2).any(|w| w == b"\r\n") {
            break;
        }
        if read == buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request line exceeds buffer",
            ));
        }
    }
    let head = &buf[..read];
    let line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no request line"))?;
    let line = std::str::from_utf8(&head[..line_end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-utf8 request line"))?;
    let mut parts = line.split(' ');
    let _method = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing method"))?;
    let path = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing path"))?;
    Ok(path.to_string())
}

fn encode_metrics() -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1024);
    let encoder = TextEncoder::new();
    let families = registry().gather();
    encoder
        .encode(&families, &mut out)
        .map_err(io::Error::other)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_initialize_and_record() {
        init();
        record_verified();
        record_rejected(&TokenError::InvalidSignature);
        record_rejected(&TokenError::Replayed);
        record_rejected(&TokenError::TokenTooShort);

        let body = encode_metrics().expect("encode");
        let text = String::from_utf8(body).expect("utf8");
        assert!(text.contains("quiethop_tokens_verified_total"));
        assert!(text.contains("quiethop_tokens_rejected_total"));
        assert!(text.contains("reason=\"invalid_signature\""));
        assert!(text.contains("reason=\"replayed\""));
        assert!(text.contains("reason=\"token_too_short\""));
    }
}
