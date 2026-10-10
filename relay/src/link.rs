//! Per-link circuit table: ids, bounds, quarantine and the round-robin writer.
//!
//! One link carries many circuits, so everything that was per-connection state
//! becomes a table entry here. The structure holds no I/O and takes the clock as
//! an argument, which is what makes the bounds and the quarantine testable
//! without standing up a link.
//!
//! The rules it enforces are in ARCHITECTURE 5.5 and SECURITY_MODEL 6.3, and the
//! reasoning behind the id lifecycle is docs/DECISIONS.md entry 22.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quiethop_crypto::circid::{self, CircId, CircIdError, LinkRole};
use quiethop_crypto::flow::{self, AfterDelivery, FlowError, Windows};
use quiethop_crypto::link::DestroyReason;
use quiethop_crypto::noise::Transport;
use tracing::{info, warn};

/// Circuits one client link will carry. A create beyond it is answered with
/// DESTROY. Provisional until the step 5 measurement (ARCHITECTURE 5.8).
///
/// Relay-to-relay links carry `MAX_CIRCUITS_PER_RELAY_LINK` instead, which is
/// configured and defaults to the whole of `MAX_CIRCUITS`, because one relay
/// link stands in for every client behind the relay on the other end
/// (ARCHITECTURE 5.10).
pub const MAX_CIRCUITS_PER_LINK: usize = 64;

/// Frames one circuit may have queued for one direction. Over it, that circuit
/// is destroyed rather than any data being dropped. Must stay at or above the
/// flow-control window or a correct fast circuit would be torn down.
pub const MAX_CIRCUIT_QUEUE: usize = 1024;

/// EXTEND frames in one circuit's life: one for the middle hop, one for the
/// exit. The first hop is reached by CREATE, not EXTEND.
const EXTENDS_PER_CIRCUIT: usize = 2;

/// Frames a circuit sends exactly once: CREATE when this side opens it on an
/// outbound link, CONNECT at the exit, and CLOSE_REQUEST at the end.
const ONE_SHOT_FRAMES_PER_CIRCUIT: usize = 3;

/// The most frames one circuit can have queued for one direction while its
/// peer stays inside the flow-control window.
///
/// DATA is bounded by the window, SENDMEs by how many may be outstanding at
/// once, and the rest are the control frames above, each sent once in the
/// circuit's life. The margin to `MAX_CIRCUIT_QUEUE` is what makes a full
/// queue mean the peer sent past its window, which is why that answers DESTROY
/// with Protocol rather than Resource (docs/DECISIONS.md entry 31).
pub const WORST_CASE_CIRCUIT_QUEUE: usize = flow::WINDOW_START as usize
    + flow::MAX_OUTSTANDING_SENDMES
    + EXTENDS_PER_CIRCUIT
    + ONE_SHOT_FRAMES_PER_CIRCUIT;

/// Adding a frame type or widening the window must fail the build rather than
/// quietly erode that margin, because the Protocol reason depends on it.
const _: () = assert!(
    WORST_CASE_CIRCUIT_QUEUE < MAX_CIRCUIT_QUEUE,
    "a compliant peer can now fill a circuit queue, so a full queue no longer \
     means the peer sent past its window and Protocol is the wrong reason"
);

/// Bytes held in per-circuit queues, shared by every link on one relay.
///
/// Relay-wide, because every other bound here is per circuit or per link and
/// nothing bounded their product (ARCHITECTURE 5.9). Control frames are
/// counted too: they are bounded per link at the link's circuit capacity while
/// the number of links is not bounded at all.
///
/// Handed to each link rather than kept in a static, so a test gets its own and
/// can assert exact byte counts while the rest of the suite runs beside it.
#[derive(Debug, Clone, Default)]
pub struct Budget(Arc<BudgetState>);

#[derive(Debug)]
struct BudgetState {
    held: AtomicU64,
    /// Whether the relay is admitting circuits, relay-wide rather than per
    /// link. The counter is one number for the whole relay, so a per-link
    /// answer lets a link that never saw the ceiling keep admitting between the
    /// resume mark and the ceiling while another refuses (ARCHITECTURE 5.9).
    admitting: AtomicBool,
}

impl Default for BudgetState {
    fn default() -> Self {
        Self {
            held: AtomicU64::new(0),
            admitting: AtomicBool::new(true),
        }
    }
}

impl Budget {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes held in per-circuit queues right now.
    pub fn held(&self) -> u64 {
        self.0.held.load(Ordering::Relaxed)
    }

    /// Whether a new circuit may be admitted.
    ///
    /// Admission closes at the ceiling and reopens under the resume mark, nine
    /// tenths of it, so a relay sitting at the limit does not admit and refuse
    /// alternately as single frames come and go. Each transition is claimed by
    /// a compare and exchange, so with several links asking at once exactly one
    /// of them makes the change and logs it.
    pub fn may_admit(&self, ceiling: u64) -> bool {
        let held = self.held();
        let admitting = self.0.admitting.load(Ordering::Relaxed);

        if admitting && held >= ceiling {
            if self
                .0
                .admitting
                .compare_exchange(true, false, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                warn!(
                    held,
                    ceiling, "link buffer budget reached, refusing new circuits"
                );
            }
            return false;
        }

        if !admitting && held < resume_mark(ceiling) {
            if self
                .0
                .admitting
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                info!(
                    held,
                    "link buffer budget recovered, admitting circuits again"
                );
            }
            return true;
        }

        admitting
    }

    fn take(&self, n: usize) {
        self.0.held.fetch_add(n as u64, Ordering::Relaxed);
    }

    fn release(&self, n: usize) {
        self.0.held.fetch_sub(n as u64, Ordering::Relaxed);
    }
}

/// Where admission reopens: nine tenths of the ceiling.
fn resume_mark(ceiling: u64) -> u64 {
    ceiling / 10 * 9
}

/// A frame counted against the relay-wide budget for as long as it is queued.
///
/// The count is taken when the frame enters a queue and released when this is
/// dropped, which includes a queue discarded with frames still in it. That is
/// why it is a guard and not an add at one site and a subtract at another: a
/// circuit torn down with a full queue must not leak its bytes, and matched
/// calls at every site are exactly the shape that eventually misses one.
#[derive(Debug)]
pub struct Queued {
    bytes: Vec<u8>,
    budget: Budget,
}

impl Queued {
    pub fn new(bytes: Vec<u8>, budget: &Budget) -> Self {
        budget.take(bytes.len());
        Self {
            bytes,
            budget: budget.clone(),
        }
    }

    /// Hand the bytes out of the queue and release their count.
    pub fn take(mut self) -> Vec<u8> {
        let bytes = std::mem::take(&mut self.bytes);
        self.budget.release(bytes.len());
        bytes
    }
}

impl Drop for Queued {
    fn drop(&mut self) {
        self.budget.release(self.bytes.len());
    }
}

/// How long a destroyed id is held before it can be reallocated on that link.
///
/// Shares the relay's CELL_READ_TIMEOUT value. The timer narrows the window in
/// which a stale frame could be misattributed; it does not close it, and the
/// mechanism that does is dropping DATA that arrives before CREATED. With ids
/// drawn at random from 31 bits the chance an allocation lands on a recently
/// destroyed id is about 2^-31 anyway (docs/DECISIONS.md entry 22).
pub const ID_QUARANTINE: Duration = Duration::from_secs(120);

/// Quarantined ids held per link, oldest evicted first.
///
/// A memory bound rather than an availability one: with 64 circuits and 256
/// quarantine slots the allocator still draws from about 2^31 minus 320 ids.
/// Tor bug 12184 is the failure mode this bound exists against, where ids that
/// stayed blocked led to "0 circuit IDs in use by circuits and 64 with pending
/// destroy cells" and then "Failing a circuit".
pub const QUARANTINE_CAP: usize = 256;

/// Where a circuit is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// This side sent CREATE and is waiting for CREATED. A DATA frame arriving
    /// now belongs to whatever used this id before and is dropped.
    Pending,
    /// Handshake complete, carrying traffic.
    Open,
}

/// One circuit on a link.
pub struct Circuit {
    pub phase: Phase,
    /// The Noise session. Absent while a locally created circuit is Pending,
    /// because the responder's message has not arrived to complete it.
    pub transport: Option<Transport>,
    pub windows: Windows,
    out: VecDeque<Queued>,
}

impl Circuit {
    fn new(phase: Phase, transport: Option<Transport>) -> Self {
        Self {
            phase,
            transport,
            windows: Windows::new(),
            out: VecDeque::new(),
        }
    }
}

/// What the dispatch should do with a frame.
///
/// Every variant that drops also counts, and none of them touch the link. The
/// names say what happened rather than what to log, so a caller cannot conflate
/// two different reasons for the same action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Deliver to this circuit.
    Deliver,
    /// Not open on this link: drop and count.
    NotOpen,
    /// DATA on a circuit still awaiting CREATED: drop and count.
    BeforeCreated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateRefusal {
    /// This link's circuit capacity is reached. The caller answers DESTROY.
    LinkFull,
    /// The id is already open. The caller sends nothing.
    Collision,
    /// The id is in quarantine, so it cannot name a new circuit yet.
    Quarantined,
}

/// Circuits on one link, with their ids and their outbound queues.
pub struct LinkTable {
    role: LinkRole,
    /// Circuits this link will carry at once. Fixed when the link is accepted
    /// or dialed, from the link's type rather than from a single constant
    /// (ARCHITECTURE 5.10).
    capacity: usize,
    circuits: HashMap<CircId, Circuit>,
    /// Destroyed ids and when they were destroyed, oldest first.
    quarantine: VecDeque<(CircId, Instant)>,
    /// Ids with queued frames, in service order. Round-robin comes from taking
    /// one frame from the front and putting the id back at the back.
    rotation: VecDeque<CircId>,
    /// Shared with every other link on this relay.
    budget: Budget,
}

impl LinkTable {
    /// `role` is this side's role on the link, which fixes the half of the id
    /// space this side allocates from. `capacity` is how many circuits this
    /// link carries, which differs between a client link and a relay link.
    pub fn new(role: LinkRole, capacity: usize, budget: Budget) -> Self {
        Self {
            role,
            capacity,
            circuits: HashMap::new(),
            quarantine: VecDeque::new(),
            rotation: VecDeque::new(),
            budget,
        }
    }

    pub fn len(&self) -> usize {
        self.circuits.len()
    }

    /// Circuits this link carries at once, which also bounds its control
    /// queue: each circuit is destroyed once and a refused CREATE answers
    /// once, so one control frame per circuit slot is the ceiling.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn get_mut(&mut self, id: CircId) -> Option<&mut Circuit> {
        self.circuits.get_mut(&id)
    }

    /// Whether `id` is still held back from reallocation at `now`.
    pub fn quarantined(&self, id: CircId, now: Instant) -> bool {
        self.quarantine
            .iter()
            .any(|(q, at)| *q == id && now.duration_since(*at) < ID_QUARANTINE)
    }

    /// Drop quarantine entries whose time has passed.
    pub fn expire_quarantine(&mut self, now: Instant) {
        while let Some((_, at)) = self.quarantine.front() {
            if now.duration_since(*at) >= ID_QUARANTINE {
                self.quarantine.pop_front();
            } else {
                break;
            }
        }
    }

    /// Allocate an id for a circuit this side is creating.
    ///
    /// Quarantined ids are skipped and count toward the collision bound exactly
    /// as ids in use do, so a link whose id space is crowded fails the create
    /// rather than scanning.
    pub fn allocate<R: rand::Rng>(
        &mut self,
        rng: &mut R,
        now: Instant,
    ) -> Result<CircId, CircIdError> {
        self.expire_quarantine(now);
        let circuits = &self.circuits;
        let quarantine = &self.quarantine;
        circid::allocate(rng, self.role, |id| {
            circuits.contains_key(&id)
                || quarantine
                    .iter()
                    .any(|(q, at)| *q == id && now.duration_since(*at) < ID_QUARANTINE)
        })
    }

    /// Open a circuit this side created, in Pending until CREATED arrives.
    pub fn insert_pending(&mut self, id: CircId) -> Result<(), CreateRefusal> {
        self.insert(id, Phase::Pending, None)
    }

    /// Accept a CREATE from the peer, which arrives with its handshake already
    /// complete on this side, so it opens directly.
    pub fn accept_create(
        &mut self,
        id: CircId,
        transport: Transport,
        now: Instant,
    ) -> Result<(), CreateRefusal> {
        if self.quarantined(id, now) {
            return Err(CreateRefusal::Quarantined);
        }
        self.insert(id, Phase::Open, Some(transport))
    }

    fn insert(
        &mut self,
        id: CircId,
        phase: Phase,
        transport: Option<Transport>,
    ) -> Result<(), CreateRefusal> {
        if self.circuits.contains_key(&id) {
            return Err(CreateRefusal::Collision);
        }
        if self.circuits.len() >= self.capacity {
            return Err(CreateRefusal::LinkFull);
        }
        self.circuits.insert(id, Circuit::new(phase, transport));
        Ok(())
    }

    /// Complete a locally created circuit when its CREATED arrives.
    ///
    /// `transport` is `None` where this side holds no session for the circuit,
    /// which is the case on a downstream link: that handshake belongs to the
    /// client and this relay only couriers it (SECURITY_MODEL 6.1).
    pub fn open_pending(&mut self, id: CircId, transport: Option<Transport>) -> bool {
        match self.circuits.get_mut(&id) {
            Some(c) if c.phase == Phase::Pending => {
                c.phase = Phase::Open;
                if transport.is_some() {
                    c.transport = transport;
                }
                true
            }
            _ => false,
        }
    }

    /// What to do with an arriving DATA frame for `id`.
    pub fn disposition_for_data(&self, id: CircId) -> Disposition {
        match self.circuits.get(&id) {
            None => Disposition::NotOpen,
            Some(c) if c.phase == Phase::Pending => Disposition::BeforeCreated,
            Some(_) => Disposition::Deliver,
        }
    }

    /// Remove a circuit and quarantine its id.
    ///
    /// Returns whether a circuit was there, so a DESTROY for an id not open can
    /// be counted as such rather than silently succeeding.
    /// Release every circuit on the link at once, quarantining each id.
    ///
    /// What a link loss does, done deliberately. Each id goes to quarantine on
    /// the same terms as a single destroy, because a peer that reconnects can
    /// reach for an id this side has just let go (DECISIONS 22).
    ///
    /// Returns how many circuits were released.
    pub fn destroy_all(&mut self, now: Instant) -> usize {
        let ids: Vec<CircId> = self.circuits.keys().copied().collect();
        for id in &ids {
            self.destroy(*id, now);
        }
        ids.len()
    }

    pub fn destroy(&mut self, id: CircId, now: Instant) -> bool {
        let existed = self.circuits.remove(&id).is_some();
        self.rotation.retain(|r| *r != id);
        if existed {
            self.quarantine.push_back((id, now));
            while self.quarantine.len() > QUARANTINE_CAP {
                self.quarantine.pop_front();
            }
        }
        existed
    }

    /// Queue a frame for writing on this link.
    ///
    /// `Err` means the circuit is at MAX_CIRCUIT_QUEUE and the caller destroys
    /// it. No frame is dropped: on a shared link the alternative to ending one
    /// circuit is stalling every circuit on it.
    pub fn push_out(&mut self, id: CircId, frame: Vec<u8>) -> Result<(), QueueFull> {
        let Some(c) = self.circuits.get_mut(&id) else {
            return Err(QueueFull::NoCircuit);
        };
        if c.out.len() >= MAX_CIRCUIT_QUEUE {
            return Err(QueueFull::AtCap);
        }
        let was_empty = c.out.is_empty();
        c.out.push_back(Queued::new(frame, &self.budget));
        if was_empty {
            self.rotation.push_back(id);
        }
        Ok(())
    }

    /// Account for a DATA cell delivered to this circuit's consumer.
    ///
    /// `None` means the circuit is not open, which the caller has already
    /// handled through [`Self::disposition_for_data`]; it is not an error here.
    pub fn on_data_delivered(&mut self, id: CircId) -> Option<Result<AfterDelivery, FlowError>> {
        self.circuits
            .get_mut(&id)
            .map(|c| c.windows.on_data_delivered())
    }

    /// Credit this circuit's deliver window for a SENDME just sent.
    pub fn on_sendme_sent(&mut self, id: CircId) {
        if let Some(c) = self.circuits.get_mut(&id) {
            c.windows.on_sendme_sent();
        }
    }

    /// Account for a SENDME arriving on this circuit.
    pub fn on_sendme_received(&mut self, id: CircId) -> Option<Result<(), FlowError>> {
        self.circuits
            .get_mut(&id)
            .map(|c| c.windows.on_sendme_received())
    }

    /// Whether this circuit may send another DATA cell.
    pub fn may_send(&self, id: CircId) -> bool {
        self.circuits.get(&id).is_some_and(|c| c.windows.may_send())
    }

    /// Account for a DATA cell sent on this circuit.
    pub fn on_data_sent(&mut self, id: CircId) -> Option<Result<(), FlowError>> {
        self.circuits.get_mut(&id).map(|c| c.windows.on_data_sent())
    }

    /// Take one frame from the circuit whose turn it is.
    ///
    /// One frame rather than one circuit's whole queue, so a circuit with a
    /// large backlog cannot hold the writer while others wait. The id goes to
    /// the back of the rotation if it still has frames.
    pub fn pop_next_out(&mut self) -> Option<(CircId, Vec<u8>)> {
        // Counted before the pop, because the rotation holds one entry per
        // circuit with something queued, so its length here is how many
        // circuits the writer could have chosen between.
        if !self.rotation.is_empty() {
            crate::metrics::record_writer_turn(self.rotation.len() > 1);
        }
        while let Some(id) = self.rotation.pop_front() {
            let Some(c) = self.circuits.get_mut(&id) else {
                continue;
            };
            let Some(frame) = c.out.pop_front() else {
                continue;
            };
            if !c.out.is_empty() {
                self.rotation.push_back(id);
            }
            return Some((id, frame.take()));
        }
        None
    }
}

/// The DESTROY reason a peer's flow-control violation maps to.
///
/// Every variant maps to Protocol, and the match is exhaustive on purpose: a new
/// FlowError will fail to compile here rather than silently inherit a reason
/// that may not fit it. This is the mapping STATUS_REPORT carries as a
/// requirement for the multiplexer commits (SECURITY_MODEL 6.4).
pub fn destroy_reason_for(err: &FlowError) -> DestroyReason {
    match err {
        FlowError::PackageWindowExhausted
        | FlowError::DeliverWindowNegative(_)
        | FlowError::UnexpectedSendme(_) => DestroyReason::Protocol,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueFull {
    /// The circuit is at its queue cap: destroy it.
    AtCap,
    /// No such circuit, which is a caller bug rather than a peer's fault.
    NoCircuit,
}

#[cfg(test)]
mod tests {
    use super::*;
    use quiethop_crypto::noise::{generate_static_keypair, respond, Initiator};

    fn table() -> LinkTable {
        LinkTable::new(LinkRole::Responder, MAX_CIRCUITS_PER_LINK, Budget::new())
    }

    /// An RNG that returns a scripted sequence of u32 values.
    ///
    /// Needed because the allocator draws from 31 bits: a random RNG would
    /// essentially never produce a specific quarantined id, so a test built on
    /// one cannot tell a working skip from a deleted one. `circid::allocate`
    /// masks off the top bit and sets the role's, so a scripted value's low 31
    /// bits are what decide the id.
    struct ScriptedRng {
        values: VecDeque<u32>,
        drawn: usize,
    }

    impl ScriptedRng {
        fn new(values: &[u32]) -> Self {
            Self {
                values: values.iter().copied().collect(),
                drawn: 0,
            }
        }
    }

    impl rand::RngCore for ScriptedRng {
        fn next_u32(&mut self) -> u32 {
            self.drawn += 1;
            self.values
                .pop_front()
                .expect("the script ran out of values")
        }
        fn next_u64(&mut self) -> u64 {
            u64::from(self.next_u32())
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(4) {
                let v = self.next_u32().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    /// A completed Noise session, so a circuit can be opened in tests without
    /// a link. Both halves are generated here and discarded.
    fn transport() -> Transport {
        let kp = generate_static_keypair().expect("keygen");
        let (initiator, msg1) = Initiator::start(&kp.public).expect("nk start");
        let (responder, msg2) = respond(kp.private(), &msg1).expect("nk respond");
        let _ = initiator.finish(&msg2).expect("nk finish");
        responder
    }

    fn id(raw: u32) -> CircId {
        CircId::new(raw).unwrap()
    }

    /// The budget refuses at the ceiling and admits again under the resume
    /// mark, not at the ceiling itself (ARCHITECTURE 5.9).
    #[test]
    fn the_budget_refuses_at_its_ceiling_and_resumes_at_ninety_percent() {
        // A 1000 byte ceiling, so the resume mark is 900. Frames of 50 bytes,
        // so the level can be put either side of both marks exactly.
        const CEILING: u64 = 1000;
        const FRAME: usize = 50;
        let budget = Budget::new();
        let mut t = LinkTable::new(LinkRole::Responder, MAX_CIRCUITS_PER_LINK, budget.clone());
        let x = id(0x70);
        t.accept_create(x, transport(), Instant::now())
            .expect("room on the link");

        assert!(budget.may_admit(CEILING), "empty, so there is room");

        for _ in 0..19 {
            t.push_out(x, vec![0u8; FRAME]).expect("room in the queue");
        }
        assert_eq!(budget.held(), 950);
        assert!(
            budget.may_admit(CEILING),
            "950 under a 1000 ceiling still admits, because the ceiling is what closes it"
        );

        for _ in 0..2 {
            t.push_out(x, vec![0u8; FRAME]).expect("room in the queue");
        }
        assert_eq!(budget.held(), 1050);
        assert!(!budget.may_admit(CEILING), "1050 is past the ceiling");

        // Back to 950. Above the 900 resume mark, so it stays closed: this is
        // the gap, and without it admission would reopen here.
        for _ in 0..2 {
            assert!(t.pop_next_out().is_some());
        }
        assert_eq!(budget.held(), 950);
        assert!(
            !budget.may_admit(CEILING),
            "950 is above the 900 resume mark, so admission stays closed"
        );

        // Under the mark, admission reopens.
        for _ in 0..2 {
            assert!(t.pop_next_out().is_some());
        }
        assert_eq!(budget.held(), 850);
        assert!(
            budget.may_admit(CEILING),
            "850 is under the resume mark, so admission reopens"
        );
    }

    /// The admitting state is one answer for the whole relay, not one per link.
    ///
    /// The counter is relay-wide, so a per-link flag would let a link that
    /// never saw the ceiling keep admitting between the resume mark and the
    /// ceiling while another link refused, and a link opened after the refusal
    /// would start by admitting. The relay would flap as a whole even though no
    /// single link did (ARCHITECTURE 5.9).
    #[test]
    fn the_admitting_state_is_relay_wide_and_not_per_link() {
        const CEILING: u64 = 1000;
        const FRAME: usize = 50;
        let budget = Budget::new();

        // Link A crosses the ceiling and starts refusing.
        let mut a = LinkTable::new(LinkRole::Responder, MAX_CIRCUITS_PER_LINK, budget.clone());
        let x = id(0x90);
        a.accept_create(x, transport(), Instant::now())
            .expect("room on the link");
        for _ in 0..21 {
            a.push_out(x, vec![0u8; FRAME]).expect("room in the queue");
        }
        assert_eq!(budget.held(), 1050);
        assert!(!budget.may_admit(CEILING), "A is past the ceiling");

        // Held falls to 950, which is 95 percent of the ceiling.
        for _ in 0..2 {
            assert!(a.pop_next_out().is_some());
        }
        assert_eq!(budget.held(), 950);

        // A second link, opened only now, after the refusal began. Its own
        // view of the budget is the same view, so it refuses too.
        let mut b = LinkTable::new(LinkRole::Responder, MAX_CIRCUITS_PER_LINK, budget.clone());
        let y = id(0x91);
        b.accept_create(y, transport(), Instant::now())
            .expect("room on the link");
        assert!(
            !b.budget.may_admit(CEILING),
            "a link opened after the refusal began must not admit at 95 percent"
        );
        assert!(
            !budget.may_admit(CEILING),
            "and neither does the link that was already refusing"
        );

        // Under the resume mark, both links admit again.
        for _ in 0..2 {
            assert!(a.pop_next_out().is_some());
        }
        assert_eq!(budget.held(), 850);
        assert!(
            b.budget.may_admit(CEILING),
            "the newer link admits again once the relay is under the mark"
        );
        assert!(budget.may_admit(CEILING), "and so does the older one");
    }

    /// Every byte a circuit held is released when it is destroyed, including
    /// frames still queued. A leak here would refuse circuits forever.
    #[test]
    fn destroying_a_circuit_releases_the_bytes_it_held() {
        let budget = Budget::new();
        let mut t = LinkTable::new(LinkRole::Responder, MAX_CIRCUITS_PER_LINK, budget.clone());
        let x = id(0x71);
        t.accept_create(x, transport(), Instant::now())
            .expect("room on the link");
        for _ in 0..16 {
            t.push_out(x, vec![0u8; 500]).expect("room in the queue");
        }
        assert_eq!(budget.held(), 16 * 500, "queued frames are counted");

        assert!(t.destroy(x, Instant::now()), "the circuit was there");
        assert_eq!(
            budget.held(),
            0,
            "destroying a circuit with a full queue left bytes counted"
        );
    }

    /// The whole table going releases everything too, which is the link loss
    /// path.
    #[test]
    fn releasing_every_circuit_returns_the_counter_to_zero() {
        let budget = Budget::new();
        let mut t = LinkTable::new(LinkRole::Responder, MAX_CIRCUITS_PER_LINK, budget.clone());
        for i in 0..8u32 {
            let c = id(0x80 + i);
            t.accept_create(c, transport(), Instant::now())
                .expect("room on the link");
            for _ in 0..4 {
                t.push_out(c, vec![0u8; 300]).expect("room in the queue");
            }
        }
        assert_eq!(budget.held(), 8 * 4 * 300);

        assert_eq!(t.destroy_all(Instant::now()), 8);
        assert_eq!(
            budget.held(),
            0,
            "the counter did not return to zero, so bytes leaked"
        );
    }

    #[test]
    fn a_frame_for_an_id_not_open_is_not_delivered() {
        let t = table();
        assert_eq!(t.disposition_for_data(id(1)), Disposition::NotOpen);
    }

    /// DATA arriving on a circuit still awaiting CREATED belongs to whatever
    /// used the id before, so it is dropped rather than decrypted. This is the
    /// mechanism that makes id reallocation safe (DECISIONS 22).
    #[test]
    fn data_before_created_is_dropped_and_after_it_is_delivered() {
        let mut t = table();
        let x = id(0x40);
        t.insert_pending(x).expect("room on the link");
        assert_eq!(t.disposition_for_data(x), Disposition::BeforeCreated);

        assert!(t.open_pending(x, Some(transport())), "CREATED must open it");
        assert_eq!(t.disposition_for_data(x), Disposition::Deliver);
    }

    /// A CREATE naming an id already open is refused as a collision, which the
    /// caller answers with silence.
    #[test]
    fn a_create_for_an_open_id_is_a_collision() {
        let mut t = table();
        let x = id(0x41);
        t.accept_create(x, transport(), Instant::now())
            .expect("first create");
        assert_eq!(
            t.accept_create(x, transport(), Instant::now()),
            Err(CreateRefusal::Collision)
        );
        // Still there: a third create for the same id is refused the same way,
        // which it would not be if the collision had removed the circuit.
        assert_eq!(
            t.accept_create(x, transport(), Instant::now()),
            Err(CreateRefusal::Collision)
        );
    }

    /// A relay link carries its own configured capacity, not the client link's
    /// 64, and the bound is enforced at its limit and one past it.
    ///
    #[test]
    fn a_relay_link_is_full_at_its_own_capacity_not_the_client_links() {
        /// Above the client link cap on purpose: a table that fell back to the
        /// constant refuses before reaching this.
        const RELAY_CAP: usize = 100;
        const _: () = assert!(RELAY_CAP > MAX_CIRCUITS_PER_LINK);
        let mut t = LinkTable::new(LinkRole::Responder, RELAY_CAP, Budget::new());

        for i in 0..RELAY_CAP {
            t.accept_create(id(i as u32 + 1), transport(), Instant::now())
                .unwrap_or_else(|e| {
                    panic!("circuit {i} within this link's capacity was refused: {e:?}")
                });
        }
        assert_eq!(t.len(), RELAY_CAP);
        assert_eq!(
            t.accept_create(id(RELAY_CAP as u32 + 1), transport(), Instant::now()),
            Err(CreateRefusal::LinkFull)
        );
        assert_eq!(t.capacity(), RELAY_CAP, "the link reports its own capacity");
    }

    /// The client link bound is enforced at its limit and one past it.
    #[test]
    fn the_link_is_full_at_max_circuits_per_link() {
        let mut t = table();
        for i in 0..MAX_CIRCUITS_PER_LINK {
            t.accept_create(id(i as u32 + 1), transport(), Instant::now())
                .unwrap_or_else(|e| panic!("circuit {i} within the bound was refused: {e:?}"));
        }
        assert_eq!(t.len(), MAX_CIRCUITS_PER_LINK);
        assert_eq!(
            t.accept_create(
                id(MAX_CIRCUITS_PER_LINK as u32 + 1),
                transport(),
                Instant::now()
            ),
            Err(CreateRefusal::LinkFull)
        );
        assert_eq!(
            t.len(),
            MAX_CIRCUITS_PER_LINK,
            "a refused create adds nothing"
        );
    }

    /// The queue bound is enforced at its limit and one past it, and the frame
    /// is never dropped: the caller destroys the circuit instead.
    #[test]
    fn the_queue_is_full_at_max_circuit_queue() {
        let mut t = table();
        let x = id(0x42);
        t.accept_create(x, transport(), Instant::now()).unwrap();
        for i in 0..MAX_CIRCUIT_QUEUE {
            t.push_out(x, vec![0u8; 4])
                .unwrap_or_else(|e| panic!("frame {i} within the bound was refused: {e:?}"));
        }
        assert_eq!(t.push_out(x, vec![0u8; 4]), Err(QueueFull::AtCap));
        // Still exactly at the cap: draining one frame makes room for exactly
        // one more, which it would not if the refused frame had been added.
        assert!(t.pop_next_out().is_some());
        assert!(t.push_out(x, vec![0u8; 4]).is_ok());
        assert_eq!(t.push_out(x, vec![0u8; 4]), Err(QueueFull::AtCap));
    }

    /// A destroyed id is held back, and released once the quarantine passes.
    #[test]
    fn a_destroyed_id_is_quarantined_then_released() {
        let mut t = table();
        let x = id(0x43);
        let t0 = Instant::now();
        t.accept_create(x, transport(), t0).unwrap();
        assert!(t.destroy(x, t0));

        assert!(t.quarantined(x, t0), "held immediately after destroy");
        assert!(
            t.quarantined(x, t0 + ID_QUARANTINE - Duration::from_millis(1)),
            "still held one millisecond before the quarantine ends"
        );
        assert!(
            !t.quarantined(x, t0 + ID_QUARANTINE),
            "released once the quarantine has passed"
        );

        // And a create for it is refused while held, accepted after.
        assert_eq!(
            t.accept_create(x, transport(), t0),
            Err(CreateRefusal::Quarantined)
        );
        assert!(t.accept_create(x, transport(), t0 + ID_QUARANTINE).is_ok());
    }

    /// A quarantined id is not handed out by the allocator.
    ///
    /// The RNG is scripted to offer the held id first and a free one second.
    /// A random RNG draws from 31 bits and would essentially never produce the
    /// held id, which would let a deleted skip pass unnoticed.
    #[test]
    fn the_allocator_skips_a_quarantined_id() {
        let mut t = LinkTable::new(LinkRole::Initiator, MAX_CIRCUITS_PER_LINK, Budget::new());
        let t0 = Instant::now();

        let held = id(0x8000_0005);
        t.insert_pending(held).unwrap();
        assert!(t.destroy(held, t0));
        assert!(t.quarantined(held, t0));

        let mut r = ScriptedRng::new(&[0x05, 0x09]);
        let got = t.allocate(&mut r, t0).expect("the second draw is free");
        assert_eq!(
            got,
            id(0x8000_0009),
            "the allocator returned the quarantined id instead of skipping it"
        );
        assert_eq!(r.drawn, 2, "the held id must consume a draw");
    }

    /// A quarantined id consumes an attempt, so a link crowded by held ids
    /// fails the create rather than scanning for a free one.
    #[test]
    fn a_quarantined_id_counts_toward_the_collision_bound() {
        let mut t = LinkTable::new(LinkRole::Initiator, MAX_CIRCUITS_PER_LINK, Budget::new());
        let t0 = Instant::now();
        let held = id(0x8000_0005);
        t.insert_pending(held).unwrap();
        assert!(t.destroy(held, t0));

        let script = vec![0x05u32; circid::MAX_ID_COLLISIONS];
        let mut r = ScriptedRng::new(&script);
        assert_eq!(t.allocate(&mut r, t0), Err(CircIdError::Exhausted));
        assert_eq!(
            r.drawn,
            circid::MAX_ID_COLLISIONS,
            "every held draw must count toward the bound"
        );
    }

    /// Destroying an id that is not open reports false, so the caller can count
    /// it as a frame for an unknown circuit rather than a successful teardown.
    #[test]
    fn destroying_an_unknown_id_reports_nothing_was_there() {
        let mut t = table();
        assert!(!t.destroy(id(0x44), Instant::now()));
    }

    /// The quarantine set is bounded, so churn cannot grow it without limit.
    #[test]
    fn the_quarantine_set_is_capped() {
        let mut t = table();
        let t0 = Instant::now();
        for i in 0..(QUARANTINE_CAP * 2) {
            let x = id(i as u32 + 1);
            t.accept_create(x, transport(), t0).ok();
            t.destroy(x, t0);
        }
        assert_eq!(t.quarantine.len(), QUARANTINE_CAP);
        // Oldest first means the earliest ids were the ones evicted.
        assert!(!t.quarantined(id(1), t0), "the oldest entry was evicted");
        assert!(
            t.quarantined(id((QUARANTINE_CAP * 2) as u32), t0),
            "the newest entry is still held"
        );
    }

    /// Every flow-control violation a peer can cause maps to Protocol. One
    /// assertion per variant, because the requirement is a mapping per
    /// violation rather than a default.
    #[test]
    fn every_flow_violation_maps_to_destroy_protocol() {
        for err in [
            FlowError::PackageWindowExhausted,
            FlowError::DeliverWindowNegative(-1),
            FlowError::UnexpectedSendme(1000),
        ] {
            assert_eq!(
                destroy_reason_for(&err),
                DestroyReason::Protocol,
                "{err:?} did not map to Protocol"
            );
        }
    }

    /// Flow accounting reaches the right circuit's windows, and a peer sending
    /// past its window surfaces the violation the caller destroys on.
    #[test]
    fn flow_accounting_is_per_circuit() {
        let mut t = table();
        let a = id(0x80);
        let b = id(0x81);
        t.accept_create(a, transport(), Instant::now()).unwrap();
        t.accept_create(b, transport(), Instant::now()).unwrap();

        // Deliveries on a do not touch b.
        for _ in 0..100 {
            match t.on_data_delivered(a).expect("a is open") {
                Ok(AfterDelivery::SendmeOwed) => t.on_sendme_sent(a),
                Ok(AfterDelivery::Nothing) => {}
                Err(e) => panic!("within the window: {e:?}"),
            }
        }
        assert!(t.may_send(a) && t.may_send(b));

        // b's window is untouched, so it absorbs a full window of its own.
        for _ in 0..1000 {
            t.on_data_sent(b)
                .expect("b is open")
                .expect("within window");
        }
        assert!(!t.may_send(b), "b stopped at its own window");
        assert!(t.may_send(a), "a is unaffected by b");
    }

    /// An unowed SENDME surfaces as a violation through the table, which is how
    /// the dispatch learns to destroy the circuit.
    #[test]
    fn an_unowed_sendme_surfaces_as_a_violation() {
        let mut t = table();
        let x = id(0x82);
        t.accept_create(x, transport(), Instant::now()).unwrap();
        let err = t
            .on_sendme_received(x)
            .expect("x is open")
            .expect_err("nothing was owed");
        assert_eq!(err, FlowError::UnexpectedSendme(1000));
        assert_eq!(destroy_reason_for(&err), DestroyReason::Protocol);
    }

    /// Flow calls for a circuit that is not open report absence rather than
    /// inventing a violation, because the frame was already dropped as NotOpen.
    #[test]
    fn flow_calls_for_an_unknown_circuit_report_absence() {
        let mut t = table();
        let x = id(0x83);
        assert!(t.on_data_delivered(x).is_none());
        assert!(t.on_sendme_received(x).is_none());
        assert!(t.on_data_sent(x).is_none());
        assert!(!t.may_send(x));
    }

    /// Both circuits backlogged: the writer must strictly alternate, which is
    /// what round-robin means. Each holds six frames, so the first eight picks
    /// are a, b, a, b, a, b, a, b and neither runs out.
    #[test]
    fn the_writer_alternates_between_two_backlogged_circuits() {
        let mut t = table();
        let a = id(0x50);
        let b = id(0x51);
        t.accept_create(a, transport(), Instant::now()).unwrap();
        t.accept_create(b, transport(), Instant::now()).unwrap();
        for _ in 0..6 {
            t.push_out(a, vec![0xAA]).unwrap();
            t.push_out(b, vec![0xBB]).unwrap();
        }

        let order: Vec<CircId> = (0..8)
            .filter_map(|_| t.pop_next_out().map(|(i, _)| i))
            .collect();
        assert_eq!(
            order,
            vec![a, b, a, b, a, b, a, b],
            "expected strict alternation, got {order:?}"
        );
    }

    /// The uneven case, labelled for what it is. a holds ten frames and b holds
    /// exactly one, so b runs out after its first turn and a is served alone
    /// from then on. The property under test is only that b was served on its
    /// turn rather than behind a's whole backlog.
    #[test]
    fn a_circuit_that_runs_out_stops_taking_turns() {
        let mut t = table();
        let a = id(0x52);
        let b = id(0x53);
        t.accept_create(a, transport(), Instant::now()).unwrap();
        t.accept_create(b, transport(), Instant::now()).unwrap();
        for _ in 0..10 {
            t.push_out(a, vec![0xAA]).unwrap();
        }
        t.push_out(b, vec![0xBB]).unwrap();

        let order: Vec<CircId> = (0..4)
            .filter_map(|_| t.pop_next_out().map(|(i, _)| i))
            .collect();
        assert_eq!(
            order,
            vec![a, b, a, a],
            "b second, then a alone once b is empty, got {order:?}"
        );
    }

    /// A stalled circuit, one that queues nothing, does not hold the writer.
    #[test]
    fn a_circuit_with_nothing_queued_does_not_hold_the_writer() {
        let mut t = table();
        let busy = id(0x60);
        let idle = id(0x61);
        t.accept_create(busy, transport(), Instant::now()).unwrap();
        t.accept_create(idle, transport(), Instant::now()).unwrap();

        for _ in 0..5 {
            t.push_out(busy, vec![0x01]).unwrap();
        }
        let mut served = 0;
        while let Some((who, _)) = t.pop_next_out() {
            assert_eq!(who, busy, "only the busy circuit had frames");
            served += 1;
        }
        assert_eq!(served, 5, "the idle circuit neither blocked nor was served");
    }

    /// Destroying a circuit removes it from the rotation, so the writer does
    /// not spin on an id that no longer exists.
    #[test]
    fn destroying_a_circuit_clears_its_queued_frames() {
        let mut t = table();
        let x = id(0x70);
        t.accept_create(x, transport(), Instant::now()).unwrap();
        t.push_out(x, vec![0x01]).unwrap();
        t.destroy(x, Instant::now());
        assert!(t.pop_next_out().is_none());
    }
}
