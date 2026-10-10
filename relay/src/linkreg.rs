//! One outbound link per next hop (ARCHITECTURE 5.10, docs/DECISIONS.md entry 29).
//!
//! The registry decides which circuits share a connection, which caller dials
//! it, and when it closes. It does not look inside the link itself: the payload
//! is a type parameter, so the lifecycle here is testable without a socket.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use rand::Rng;
use tokio::sync::{watch, Notify};
use tracing::{info, warn};

/// How long a link with no circuits waits before closing.
pub const IDLE_LINK_TTL: Duration = Duration::from_secs(600);

/// The most that is added to it, drawn fresh on every arming.
///
/// A fixed timeout makes the close a deterministic function of the last
/// circuit's end: an observer sees the connection go, subtracts the constant
/// and learns when that circuit finished. Fresh per arming rather than once per
/// link, because a per-link constant is a fingerprint across a long-lived
/// link's repeated arm and disarm cycles (ARCHITECTURE 5.10).
pub const IDLE_LINK_JITTER: Duration = Duration::from_secs(300);

/// The base plus a uniform draw from the jitter window.
pub fn idle_deadline<R: Rng>(rng: &mut R) -> Duration {
    let extra = rng.gen_range(0..=IDLE_LINK_JITTER.as_millis() as u64);
    IDLE_LINK_TTL + Duration::from_millis(extra)
}

/// A next hop's identity in the registry, and the key a link is shared on.
///
/// All three parts, because the id survives a renumbering, the address is what
/// gets dialed, and the name is what the certificate was checked against. The
/// static public key is not here: this relay never authenticates the next hop
/// with it, so it is not a property of this connection (ARCHITECTURE 5.10).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkKey {
    pub relay_id: String,
    pub addr: SocketAddr,
    pub tls_name: String,
}

/// A link and the registry's accounting for it.
pub struct Shared<T> {
    /// The link itself. The registry never reads it.
    pub link: T,
    key: LinkKey,
    /// Circuits currently on this link.
    ///
    /// The increment and the idle timer's zero-check are serialised under the
    /// registry lock. The decrement is not and does not need to be: it can only
    /// make a link look emptier than it is, never make an empty one look
    /// occupied, so it cannot cause a live link to close
    /// (docs/DECISIONS.md entry 29).
    circuits: AtomicUsize,
    closing: AtomicBool,
    /// Raised when the last circuit leaves, so the link's own task can arm its
    /// idle timer.
    pub idle: Notify,
}

impl<T> Shared<T> {
    pub fn key(&self) -> &LinkKey {
        &self.key
    }

    pub fn circuits(&self) -> usize {
        self.circuits.load(Ordering::Acquire)
    }

    pub fn closing(&self) -> bool {
        self.closing.load(Ordering::Acquire)
    }
}

impl<T> fmt::Debug for Shared<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shared")
            .field("key", &self.key)
            .field("circuits", &self.circuits())
            .field("closing", &self.closing())
            .finish()
    }
}

/// One circuit's claim on a link, released when dropped.
///
/// Taken in the same critical section that hands the link out, so the idle
/// timer cannot decide to close a link between the handout and the claim. Drop
/// takes no lock, which is what lets a circuit that fails to open release its
/// claim with no chance of deadlock.
pub struct Reservation<T> {
    link: Arc<Shared<T>>,
}

impl<T> Drop for Reservation<T> {
    fn drop(&mut self) {
        if self.link.circuits.fetch_sub(1, Ordering::AcqRel) == 1 {
            // Last one out: the link's task arms its idle timer.
            self.link.idle.notify_one();
        }
    }
}

/// A link, this circuit's claim on it, and whether this caller is the one that
/// dialed it. The dialer is responsible for starting the link's own task,
/// because only it can take the read half out of the payload.
pub struct Acquired<T> {
    pub link: Arc<Shared<T>>,
    pub reservation: Reservation<T>,
    pub dialed: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum AcquireError {
    #[error("the link to this hop could not be opened: {0}")]
    Dial(String),
    #[error("the link to this hop is at its circuit cap")]
    LinkFull,
    #[error("the link was taken away between opening and use")]
    Raced,
}

/// What the dialer publishes to whoever is waiting on the same key.
enum OpenState<T> {
    Pending,
    Ready(Arc<Shared<T>>),
    Failed(String),
}

// Hand written so the payload does not have to be Clone.
impl<T> Clone for OpenState<T> {
    fn clone(&self) -> Self {
        match self {
            Self::Pending => Self::Pending,
            Self::Ready(l) => Self::Ready(l.clone()),
            Self::Failed(e) => Self::Failed(e.clone()),
        }
    }
}

enum Slot<T> {
    Opening(watch::Receiver<OpenState<T>>),
    Open(Arc<Shared<T>>),
}

/// The links this relay holds, one per next hop.
pub struct Registry<T> {
    links: Mutex<HashMap<LinkKey, Slot<T>>>,
}

impl<T> Default for Registry<T> {
    fn default() -> Self {
        Self {
            links: Mutex::new(HashMap::new()),
        }
    }
}

impl<T> Registry<T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// A poisoned lock means a holder panicked. The state is a map, so taking
    /// it anyway is safe and refusing would strand every link.
    fn lock(&self) -> MutexGuard<'_, HashMap<LinkKey, Slot<T>>> {
        self.links.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// A link for this hop, dialing one if nobody else is.
    ///
    /// Exactly one caller per key dials, because inserting the opening slot is
    /// the election and it happens under the lock every caller passes through.
    /// The lock is released before anything that waits.
    pub async fn acquire<F, Fut, E>(
        &self,
        key: LinkKey,
        cap: usize,
        dial: F,
    ) -> Result<Acquired<T>, AcquireError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: fmt::Display,
    {
        enum Role<T> {
            Dial(watch::Sender<OpenState<T>>),
            Wait(watch::Receiver<OpenState<T>>),
            Have(Arc<Shared<T>>, Reservation<T>),
        }

        let role = {
            let mut links = self.lock();
            match links.get(&key) {
                Some(Slot::Open(link)) if !link.closing() => {
                    let have = Arc::clone(link);
                    // Counted here, under the same lock that found it, so the
                    // idle timer cannot close it between now and first use.
                    match reserve(&have, cap) {
                        Some(r) => Role::Have(have, r),
                        None => return Err(AcquireError::LinkFull),
                    }
                }
                Some(Slot::Opening(rx)) => Role::Wait(rx.clone()),
                // Absent, or present and closing: this caller dials.
                _ => {
                    let (tx, rx) = watch::channel(OpenState::Pending);
                    links.insert(key.clone(), Slot::Opening(rx));
                    Role::Dial(tx)
                }
            }
        };

        match role {
            Role::Have(link, reservation) => Ok(Acquired {
                link,
                reservation,
                dialed: false,
            }),
            Role::Dial(tx) => self.dial_and_publish(key, cap, dial, tx).await,
            Role::Wait(mut rx) => {
                loop {
                    let state = rx.borrow_and_update().clone();
                    match state {
                        OpenState::Ready(link) => return self.join(link, cap),
                        OpenState::Failed(e) => return Err(AcquireError::Dial(e)),
                        OpenState::Pending => {}
                    }
                    if rx.changed().await.is_err() {
                        // The dialer went without publishing, which it does not
                        // do, so treat it as the link being gone.
                        return Err(AcquireError::Raced);
                    }
                }
            }
        }
    }

    async fn dial_and_publish<F, Fut, E>(
        &self,
        key: LinkKey,
        cap: usize,
        dial: F,
        tx: watch::Sender<OpenState<T>>,
    ) -> Result<Acquired<T>, AcquireError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: fmt::Display,
    {
        match dial().await {
            Ok(payload) => {
                let link = Arc::new(Shared {
                    link: payload,
                    key: key.clone(),
                    circuits: AtomicUsize::new(0),
                    closing: AtomicBool::new(false),
                    idle: Notify::new(),
                });
                let reservation = {
                    let mut links = self.lock();
                    links.insert(key, Slot::Open(Arc::clone(&link)));
                    // Cannot be full: the link is new and this is its first.
                    reserve(&link, cap).ok_or(AcquireError::LinkFull)?
                };
                // Published after the slot is open, so a waiter that wakes and
                // takes the lock finds the link there.
                let _ = tx.send(OpenState::Ready(Arc::clone(&link)));
                Ok(Acquired {
                    link,
                    reservation,
                    dialed: true,
                })
            }
            Err(e) => {
                let msg = e.to_string();
                // Failure is published and the slot removed, so every waiter
                // errors for its own circuit and the next caller dials fresh.
                // Nothing retries here: a retry storm against a hop that is
                // down turns one failing relay into a load problem.
                self.lock().remove(&key);
                let _ = tx.send(OpenState::Failed(msg.clone()));
                warn!(%msg, "dialing the next hop failed");
                Err(AcquireError::Dial(msg))
            }
        }
    }

    /// Count a waiter's circuit onto a link the dialer opened.
    fn join(&self, link: Arc<Shared<T>>, cap: usize) -> Result<Acquired<T>, AcquireError> {
        let links = self.lock();
        // Still the link this key points at. A link retired between the
        // publish and here would need the whole idle timeout to have elapsed
        // while the dialer held its own claim, so this is vanishingly rare and
        // reported rather than retried.
        let current =
            matches!(links.get(link.key()), Some(Slot::Open(cur)) if Arc::ptr_eq(cur, &link));
        if !current || link.closing() {
            return Err(AcquireError::Raced);
        }
        match reserve(&link, cap) {
            Some(r) => {
                drop(links);
                Ok(Acquired {
                    link,
                    reservation: r,
                    dialed: false,
                })
            }
            None => Err(AcquireError::LinkFull),
        }
    }

    /// Close this link if nothing is on it. Returns whether it closed.
    ///
    /// The zero-check and the removal happen under the same lock an adopter's
    /// increment takes, so either the increment lands first and this stands
    /// down, or the removal lands first and the adopter's lookup misses and it
    /// dials fresh. No caller can receive a link already committed to closing.
    pub fn close_if_idle(&self, me: &Arc<Shared<T>>) -> bool {
        let mut links = self.lock();
        if me.circuits() != 0 {
            return false;
        }
        if !Self::is_current(&links, me) {
            return false;
        }
        me.closing.store(true, Ordering::Release);
        links.remove(me.key());
        info!(key = ?me.key(), "idle outbound link closed");
        true
    }

    /// Drop this link's slot because the link itself is finished, whatever the
    /// circuit count.
    ///
    /// Guarded on identity, so a link closing late cannot delete the slot of a
    /// newer link opened under the same key.
    pub fn retire(&self, me: &Arc<Shared<T>>) {
        let mut links = self.lock();
        if !Self::is_current(&links, me) {
            return;
        }
        me.closing.store(true, Ordering::Release);
        links.remove(me.key());
    }

    fn is_current(links: &HashMap<LinkKey, Slot<T>>, me: &Arc<Shared<T>>) -> bool {
        matches!(links.get(me.key()), Some(Slot::Open(cur)) if Arc::ptr_eq(cur, me))
    }
}

/// Claim a circuit slot on a link, if it is under the cap.
fn reserve<T>(link: &Arc<Shared<T>>, cap: usize) -> Option<Reservation<T>> {
    let mut held = link.circuits.load(Ordering::Acquire);
    loop {
        if held >= cap {
            return None;
        }
        match link.circuits.compare_exchange_weak(
            held,
            held + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                return Some(Reservation {
                    link: Arc::clone(link),
                })
            }
            Err(now) => held = now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    /// A payload the registry does not look inside, which is the point: the
    /// lifecycle here is testable without a socket.
    #[derive(Debug)]
    struct Fake(u32);

    fn key(port: u16) -> LinkKey {
        LinkKey {
            relay_id: "test-middle".into(),
            addr: format!("10.0.0.1:{port}").parse().expect("addr"),
            tls_name: "middle.example".into(),
        }
    }

    const CAP: usize = 8;

    async fn open(reg: &Registry<Fake>, k: LinkKey, n: u32) -> Acquired<Fake> {
        reg.acquire(k, CAP, || async move { Ok::<_, String>(Fake(n)) })
            .await
            .expect("a fresh dial succeeds")
    }

    /// A link closing late must not delete the slot of a newer link that has
    /// taken its key, or the newer link's circuits lose their entry while they
    /// are still running.
    #[tokio::test]
    async fn an_old_link_closing_does_not_remove_a_newer_links_slot() {
        let reg = Registry::<Fake>::new();
        let k = key(1);

        let old = open(&reg, k.clone(), 1).await;
        // The old link goes, by its own hand, and a new one takes the key.
        reg.retire(&old.link);
        let new = open(&reg, k.clone(), 2).await;
        assert_eq!(reg.len(), 1);

        // The old link tidies up late. Twice, because neither path may touch a
        // slot that is not its own.
        reg.retire(&old.link);
        drop(old.reservation);
        assert!(!reg.close_if_idle(&old.link));

        assert_eq!(reg.len(), 1, "the newer link lost its slot");
        let again = open(&reg, k, 3).await;
        assert!(
            Arc::ptr_eq(&again.link, &new.link),
            "the key points at some third link, so the slot was replaced"
        );
        assert_eq!(
            new.link.link.0, 2,
            "the registry handed back another payload"
        );
    }

    /// A circuit counted under the registry lock survives the idle timer
    /// firing at the worst moment, which is between the handout and first use.
    #[tokio::test]
    async fn a_link_adopted_under_the_lock_survives_the_idle_timer_firing() {
        let reg = Registry::<Fake>::new();
        let adopted = open(&reg, key(2), 1).await;

        // The timer fires here, with the circuit counted but nothing sent yet.
        assert!(
            !reg.close_if_idle(&adopted.link),
            "a link with a circuit on it must not close"
        );
        assert_eq!(reg.len(), 1);
        assert!(!adopted.link.closing());

        // Once the claim goes, it closes.
        drop(adopted.reservation);
        assert_eq!(adopted.link.circuits(), 0);
        assert!(reg.close_if_idle(&adopted.link));
        assert_eq!(reg.len(), 0);
        assert!(adopted.link.closing());
    }

    /// Several callers wanting the same hop at once produce one connection.
    #[tokio::test(start_paused = true)]
    async fn simultaneous_callers_produce_exactly_one_connection() {
        let reg = Arc::new(Registry::<Fake>::new());
        let dials = Arc::new(AtomicU32::new(0));
        let k = key(3);

        let mut tasks = Vec::new();
        for _ in 0..16 {
            let reg = reg.clone();
            let dials = dials.clone();
            let k = k.clone();
            tasks.push(tokio::spawn(async move {
                reg.acquire(k, CAP, || async move {
                    dials.fetch_add(1, Ordering::AcqRel);
                    // Long enough that every other caller reaches the slot
                    // while this one is still dialing.
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    Ok::<_, String>(Fake(7))
                })
                .await
                .map(|a| a.dialed)
            }));
        }

        let mut dialed = 0;
        let mut got = 0;
        for t in tasks {
            let r = t.await.expect("task").expect("every caller gets the link");
            got += 1;
            if r {
                dialed += 1;
            }
        }
        assert_eq!(got, 16, "every caller must get the link");
        assert_eq!(dials.load(Ordering::Acquire), 1, "more than one dial");
        assert_eq!(dialed, 1, "more than one caller believed it dialed");
        assert_eq!(reg.len(), 1);
    }

    /// A dial that fails errors every waiter and leaves nothing behind.
    #[tokio::test(start_paused = true)]
    async fn when_the_dial_fails_every_waiter_errors_and_the_next_caller_dials_fresh() {
        let reg = Arc::new(Registry::<Fake>::new());
        let dials = Arc::new(AtomicU32::new(0));
        let k = key(4);

        let mut tasks = Vec::new();
        for _ in 0..6 {
            let reg = reg.clone();
            let dials = dials.clone();
            let k = k.clone();
            tasks.push(tokio::spawn(async move {
                reg.acquire(k, CAP, || async move {
                    dials.fetch_add(1, Ordering::AcqRel);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    Err::<Fake, String>("connection refused".into())
                })
                .await
                .map(|_| ())
            }));
        }
        for t in tasks {
            let r = t.await.expect("task");
            assert!(
                matches!(r, Err(AcquireError::Dial(ref m)) if m.contains("connection refused")),
                "a waiter got {r:?} rather than the dial error"
            );
        }
        assert_eq!(dials.load(Ordering::Acquire), 1, "only one caller dialed");
        assert_eq!(reg.len(), 0, "the failed slot was left behind");

        // Removed rather than cached as failed, so the next caller tries again.
        let later = open(&reg, k, 9).await;
        assert!(later.dialed, "the next caller must dial fresh");
        assert_eq!(
            dials.load(Ordering::Acquire),
            1,
            "the retry used its own dial"
        );
    }

    /// The idle deadline is the base plus a draw inside the jitter window, and
    /// it is a fresh draw each time.
    #[tokio::test(start_paused = true)]
    async fn the_idle_timer_fires_inside_its_window() {
        let mut rng = rand::rngs::OsRng;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..512 {
            let d = idle_deadline(&mut rng);
            assert!(
                d >= IDLE_LINK_TTL && d <= IDLE_LINK_TTL + IDLE_LINK_JITTER,
                "{d:?} is outside [600 s, 900 s]"
            );
            seen.insert(d.as_millis());
        }
        assert!(
            seen.len() > 1,
            "every draw was the same, so the timeout is fixed and the close time \
             reveals when the last circuit ended"
        );

        // And it is a real deadline: under a paused clock the wait elapses
        // inside the window and not before the base.
        let d = idle_deadline(&mut rng);
        let started = tokio::time::Instant::now();
        tokio::time::sleep(d).await;
        let waited = started.elapsed();
        assert!(
            waited >= IDLE_LINK_TTL && waited <= IDLE_LINK_TTL + IDLE_LINK_JITTER,
            "the timer waited {waited:?}, outside [600 s, 900 s]"
        );
    }

    /// A registry change to the address or the name is a different hop, so it
    /// gets its own link and the old one keeps serving what is on it.
    #[tokio::test]
    async fn a_changed_address_or_tls_name_opens_a_second_link() {
        let reg = Registry::<Fake>::new();
        let before = key(5);
        let first = open(&reg, before.clone(), 1).await;

        // Same relay, new address.
        let moved = LinkKey {
            addr: "10.0.0.1:9999".parse().expect("addr"),
            ..before.clone()
        };
        let second = open(&reg, moved, 2).await;
        assert!(!Arc::ptr_eq(&first.link, &second.link));
        assert_eq!(reg.len(), 2, "the old link was replaced instead of kept");
        assert_eq!(
            first.link.circuits(),
            1,
            "the old link still carries its circuit"
        );

        // Same relay and address, new name.
        let renamed = LinkKey {
            tls_name: "middle2.example".into(),
            ..before
        };
        let third = open(&reg, renamed, 3).await;
        assert!(!Arc::ptr_eq(&third.link, &first.link));
        assert_eq!(reg.len(), 3);
        assert_eq!(first.link.circuits(), 1);
    }
}
