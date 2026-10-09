//! Circuit identifiers on a multiplexed link.
//!
//! Four bytes, following the Tor link protocol rule for link protocol 4 and
//! above: the id is chosen by the side that sends the create, the side that
//! initiated the link sets the most significant bit to 1 and the other side
//! sets it to 0, and zero is never used. Splitting the space by who opened the
//! link is what lets both ends allocate without coordinating.
//!
//! Ids are drawn at random among unused values rather than counted up. A
//! counter would make a link's circuit history readable from any one id, and
//! Tor's spec asks new implementations to draw randomly for the same reason.
//! Allocation gives up after [`MAX_ID_COLLISIONS`] misses and fails the create
//! rather than scanning for a free id, because a scan would reveal how full the
//! link is.

use thiserror::Error;

/// Width on the wire.
pub const CIRC_ID_LEN: usize = 4;

/// Attempts before a create fails. Tor's figure.
pub const MAX_ID_COLLISIONS: usize = 64;

const MSB: u32 = 1 << 31;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CircIdError {
    #[error("circuit id 0 is reserved and never names a circuit")]
    Zero,
    #[error("circuit id {0:#010x} is from the other side's half of the id space")]
    WrongHalf(u32),
    #[error("no unused circuit id found in {MAX_ID_COLLISIONS} attempts")]
    Exhausted,
}

/// Which end of the link this is. The end that opened the connection is the
/// initiator and owns the half of the id space with the top bit set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkRole {
    Initiator,
    Responder,
}

impl LinkRole {
    /// The top bit this side must set on ids it chooses.
    fn msb(self) -> u32 {
        match self {
            LinkRole::Initiator => MSB,
            LinkRole::Responder => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CircId(u32);

impl CircId {
    /// Accept an id from the wire, rejecting zero.
    pub fn new(raw: u32) -> Result<Self, CircIdError> {
        if raw == 0 {
            return Err(CircIdError::Zero);
        }
        Ok(Self(raw))
    }

    /// Accept an id a peer chose, rejecting zero and the wrong half.
    ///
    /// `peer` is the peer's role on this link, so a responder validating an id
    /// the initiator chose passes `LinkRole::Initiator`.
    pub fn from_peer(raw: u32, peer: LinkRole) -> Result<Self, CircIdError> {
        let id = Self::new(raw)?;
        if (raw & MSB) != peer.msb() {
            return Err(CircIdError::WrongHalf(raw));
        }
        Ok(id)
    }

    pub fn raw(self) -> u32 {
        self.0
    }

    pub fn to_bytes(self) -> [u8; CIRC_ID_LEN] {
        self.0.to_be_bytes()
    }

    /// Whether this id belongs to the half owned by the link's initiator.
    pub fn is_initiator_half(self) -> bool {
        self.0 & MSB != 0
    }
}

/// Draw an unused id for this side of the link.
///
/// `in_use` answers whether an id is already taken. The generator is passed in
/// so a test can be deterministic while production uses the OS RNG.
pub fn allocate<R, F>(rng: &mut R, role: LinkRole, in_use: F) -> Result<CircId, CircIdError>
where
    R: rand::Rng,
    F: Fn(CircId) -> bool,
{
    for _ in 0..MAX_ID_COLLISIONS {
        // The low 31 bits are drawn and the top bit is the role's. A responder
        // drawing all zeros would produce id 0, which is rejected rather than
        // retried into a bias, because one wasted attempt out of 2^31 costs
        // nothing and special-casing it would complicate the draw.
        let low = rng.gen::<u32>() & !MSB;
        let raw = low | role.msb();
        let Ok(id) = CircId::new(raw) else {
            continue;
        };
        if !in_use(id) {
            return Ok(id);
        }
    }
    Err(CircIdError::Exhausted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::collections::BTreeSet;

    #[test]
    fn id_zero_is_rejected_everywhere_it_can_arrive() {
        assert_eq!(CircId::new(0), Err(CircIdError::Zero));
        assert_eq!(
            CircId::from_peer(0, LinkRole::Initiator),
            Err(CircIdError::Zero)
        );
        assert_eq!(
            CircId::from_peer(0, LinkRole::Responder),
            Err(CircIdError::Zero)
        );
    }

    #[test]
    fn the_initiator_half_is_the_top_bit() {
        let init = CircId::from_peer(0x8000_0001, LinkRole::Initiator).unwrap();
        assert!(init.is_initiator_half());
        let resp = CircId::from_peer(0x0000_0001, LinkRole::Responder).unwrap();
        assert!(!resp.is_initiator_half());

        // Each side's id is refused when it arrives claiming the other half.
        assert_eq!(
            CircId::from_peer(0x0000_0001, LinkRole::Initiator),
            Err(CircIdError::WrongHalf(0x0000_0001))
        );
        assert_eq!(
            CircId::from_peer(0x8000_0001, LinkRole::Responder),
            Err(CircIdError::WrongHalf(0x8000_0001))
        );
    }

    #[test]
    fn allocation_stays_in_its_half() {
        let mut rng = StdRng::seed_from_u64(0x9c1d);
        for _ in 0..200 {
            let i = allocate(&mut rng, LinkRole::Initiator, |_| false).unwrap();
            assert!(i.is_initiator_half(), "{:#010x}", i.raw());
            let r = allocate(&mut rng, LinkRole::Responder, |_| false).unwrap();
            assert!(!r.is_initiator_half(), "{:#010x}", r.raw());
            assert_ne!(r.raw(), 0);
        }
    }

    #[test]
    fn allocation_skips_ids_already_in_use() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut taken: BTreeSet<CircId> = BTreeSet::new();
        for _ in 0..64 {
            let id = allocate(&mut rng, LinkRole::Initiator, |c| taken.contains(&c)).unwrap();
            assert!(taken.insert(id), "allocate returned an id already taken");
        }
    }

    /// A full id space must fail the create after a bounded number of attempts
    /// rather than looping, which is what the bound exists for.
    #[test]
    fn allocation_gives_up_after_the_collision_bound() {
        let mut rng = StdRng::seed_from_u64(11);
        assert_eq!(
            allocate(&mut rng, LinkRole::Initiator, |_| true),
            Err(CircIdError::Exhausted)
        );
    }

    /// The bound is the number of draws, so exactly MAX_ID_COLLISIONS are made
    /// before giving up. A test that only checked the error could pass with an
    /// implementation that gave up after one.
    #[test]
    fn the_collision_bound_is_the_number_of_attempts() {
        let mut rng = StdRng::seed_from_u64(13);
        // A Cell rather than a mut binding, because in_use is Fn: a predicate
        // that answers a question should not need to mutate to answer it, and
        // loosening the bound to FnMut for one test would be the wrong trade.
        let attempts = std::cell::Cell::new(0usize);
        let err = allocate(&mut rng, LinkRole::Initiator, |_| {
            attempts.set(attempts.get() + 1);
            true
        })
        .unwrap_err();
        assert_eq!(err, CircIdError::Exhausted);
        assert_eq!(attempts.get(), MAX_ID_COLLISIONS);
    }

    #[test]
    fn bytes_are_big_endian() {
        assert_eq!(
            CircId::new(0x8000_0102).unwrap().to_bytes(),
            [0x80, 0x00, 0x01, 0x02]
        );
    }
}
