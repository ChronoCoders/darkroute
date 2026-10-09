//! How many AEAD layers a frame carries.
//!
//! A count, never a byte length. Both were `usize` until this type existed, and
//! passing a length where a count belonged produced a 9817 byte frame in place
//! of a 552 byte one: the relay wrote it, then waited to read 9817 bytes back
//! that no peer would ever send (docs/DECISIONS.md entry 23, STATUS_REPORT
//! section 5). The compiler now refuses that call.

/// A layer count on one link.
///
/// The client wraps one layer per hop, so a guard's inbound link carries three
/// and an exit's carries one. Every length function in this crate takes this
/// type rather than a bare `usize`.
///
/// A count is what these functions take:
///
/// ```
/// use quiethop_crypto::cell::link_cell_len;
/// use quiethop_crypto::layers::Layers;
/// use quiethop_crypto::link::link_frame_len;
///
/// assert_eq!(link_cell_len(Layers::new(2)), 547);
/// assert_eq!(link_frame_len(Layers::new(2)), 552);
/// ```
///
/// A byte length is not, even though both were `usize` before this type. This
/// is the call that hung a circuit, and it no longer compiles:
///
/// ```compile_fail
/// use quiethop_crypto::cell::link_cell_len;
/// use quiethop_crypto::layers::Layers;
/// use quiethop_crypto::link::link_frame_len;
///
/// // 547 bytes, the cell size on a guard-to-middle link.
/// let cell_len: usize = link_cell_len(Layers::new(2));
/// // Passing it as a layer count asked for a 9817 byte frame.
/// let _ = link_frame_len(cell_len);
/// ```
///
/// A bare integer is refused the same way, so a literal cannot slip in either:
///
/// ```compile_fail
/// use quiethop_crypto::link::link_frame_len;
///
/// let _ = link_frame_len(2);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Layers(usize);

impl Layers {
    /// `const` so callers can keep their counts in `const` items, which is what
    /// makes the frame length constants possible.
    pub const fn new(n: usize) -> Self {
        Self(n)
    }

    pub const fn get(self) -> usize {
        self.0
    }

    /// One layer fewer, which is what the next link outward carries after this
    /// hop has peeled its own.
    ///
    /// Saturating, so an exit asking for its next hop gets zero rather than
    /// wrapping to `usize::MAX` and producing a length no allocation can meet.
    pub const fn peeled(self) -> Self {
        Self(self.0.saturating_sub(1))
    }
}

impl std::fmt::Display for Layers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_count_round_trips() {
        assert_eq!(Layers::new(3).get(), 3);
    }

    #[test]
    fn peeling_takes_one_and_stops_at_zero() {
        assert_eq!(Layers::new(3).peeled(), Layers::new(2));
        assert_eq!(Layers::new(1).peeled(), Layers::new(0));
        assert_eq!(
            Layers::new(0).peeled(),
            Layers::new(0),
            "peeling past the innermost layer must not wrap"
        );
    }

    /// Ordering exists so a bound can be written against a count, and it
    /// compares counts rather than the lengths they produce.
    #[test]
    fn counts_order_as_numbers() {
        let mut v = [Layers::new(3), Layers::new(1), Layers::new(2)];
        v.sort();
        assert_eq!(v, [Layers::new(1), Layers::new(2), Layers::new(3)]);
    }

    #[test]
    fn a_count_displays_as_its_number() {
        assert_eq!(Layers::new(2).to_string(), "2");
    }
}
