//! Circuit-level flow control.
//!
//! A link carries many circuits, so one circuit that stops reading must not
//! stall the others. The scheme is Tor's original fixed-window one, read from
//! the tor-spec flow control page: each endpoint keeps a package window and a
//! deliver window starting at 1000 DATA cells, a SENDME is sent each time the
//! deliver window has fallen by 100 and adds 100 back to it, a received SENDME
//! adds 100 to the package window, a package window at 0 stops sending, and a
//! deliver window below zero tears the circuit down.
//!
//! Windows are end to end between the client and the exit. With one stream per
//! circuit those are the only endpoints that originate or consume cells, so a
//! middle relay only forwards and its own windows never engage
//! (SECURITY_MODEL 6.4).
//!
//! Only DATA counts. A SENDME that decremented a window would make the windows
//! unable to recover, which is why [`Windows`] has no method that takes one.
//!
//! The credit on the receiving side is deliberately not automatic. A SENDME says
//! "I have consumed 100 cells, send 100 more", so the deliver window is credited
//! when the caller actually sends one, which it does once the data has been
//! handed on. Crediting inside the delivery call instead would refill the window
//! whether or not anything read the data, and then a deliver window could never
//! go below zero and the rule that tears the circuit down would be unreachable.
//! That is the whole point of the window: a stalled consumer stops granting
//! credit, and a peer that keeps sending anyway is caught.

use thiserror::Error;

/// Starting value of both windows, in DATA cells.
pub const WINDOW_START: i32 = 1000;

/// How far the deliver window falls before a SENDME, and how much a SENDME
/// adds back.
pub const WINDOW_INCREMENT: i32 = 100;

/// Most SENDMEs that can be outstanding, which bounds the receipts an exit has
/// to remember: a full window divided by the increment.
pub const MAX_OUTSTANDING_SENDMES: usize = (WINDOW_START / WINDOW_INCREMENT) as usize;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FlowError {
    #[error("tried to send a DATA cell with the package window at zero")]
    PackageWindowExhausted,
    #[error("peer sent more DATA than its window allowed, deliver window at {0}")]
    DeliverWindowNegative(i32),
}

/// What to do after delivering a cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterDelivery {
    /// Nothing to send.
    Nothing,
    /// A full increment has been consumed, so a SENDME is owed. The caller
    /// sends it and then calls [`Windows::on_sendme_sent`], which is what
    /// credits the window.
    SendmeOwed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Windows {
    package: i32,
    deliver: i32,
    /// Cells delivered since the last SENDME was sent. A SENDME is owed once
    /// this reaches a full increment.
    pending: i32,
}

impl Default for Windows {
    fn default() -> Self {
        Self::new()
    }
}

impl Windows {
    pub fn new() -> Self {
        Self {
            package: WINDOW_START,
            deliver: WINDOW_START,
            pending: 0,
        }
    }

    pub fn package(self) -> i32 {
        self.package
    }

    pub fn deliver(self) -> i32 {
        self.deliver
    }

    /// Whether a DATA cell may be sent now.
    pub fn may_send(self) -> bool {
        self.package > 0
    }

    /// Account for sending one DATA cell.
    ///
    /// An error here is a local bug rather than a peer's fault: the caller was
    /// supposed to consult [`Self::may_send`] first. It is returned rather than
    /// ignored so the circuit fails instead of sending past the window.
    pub fn on_data_sent(&mut self) -> Result<(), FlowError> {
        if self.package <= 0 {
            return Err(FlowError::PackageWindowExhausted);
        }
        self.package -= 1;
        Ok(())
    }

    /// Credit the package window on a received SENDME.
    ///
    /// Capped at the starting value, so a peer that sends more SENDMEs than it
    /// owes cannot inflate the window without bound. An uncapped window is the
    /// same cost attack authenticated SENDMEs exist for, reached by a different
    /// route, so the cap holds whether or not the receipt checks out.
    pub fn on_sendme_received(&mut self) {
        self.package = (self.package + WINDOW_INCREMENT).min(WINDOW_START);
    }

    /// Account for delivering one DATA cell, and say whether a SENDME is owed.
    ///
    /// A deliver window below zero means the peer sent more than it was allowed
    /// and the circuit is torn down (SECURITY_MODEL 6.4). This is reachable only
    /// because the credit is not applied here: see the module docs.
    pub fn on_data_delivered(&mut self) -> Result<AfterDelivery, FlowError> {
        self.deliver -= 1;
        if self.deliver < 0 {
            return Err(FlowError::DeliverWindowNegative(self.deliver));
        }
        self.pending += 1;
        if self.pending >= WINDOW_INCREMENT {
            return Ok(AfterDelivery::SendmeOwed);
        }
        Ok(AfterDelivery::Nothing)
    }

    /// Credit the deliver window for a SENDME this side has just sent.
    ///
    /// Only an owed increment is credited, so a caller that sends a SENDME it
    /// did not owe cannot inflate its own window.
    pub fn on_sendme_sent(&mut self) {
        if self.pending >= WINDOW_INCREMENT {
            self.pending -= WINDOW_INCREMENT;
            self.deliver += WINDOW_INCREMENT;
        }
    }

    /// Cells consumed since the last SENDME was sent.
    pub fn pending(self) -> i32 {
        self.pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_start_at_one_thousand() {
        let w = Windows::new();
        assert_eq!(w.package(), 1000);
        assert_eq!(w.deliver(), 1000);
        assert_eq!(WINDOW_INCREMENT, 100);
        assert_eq!(MAX_OUTSTANDING_SENDMES, 10);
    }

    /// The sender stops exactly at the window and not before, so the stop is
    /// the window rather than an off-by-one somewhere else.
    #[test]
    fn the_sender_stops_at_window_zero_and_resumes_on_sendme() {
        let mut w = Windows::new();
        for i in 0..WINDOW_START {
            assert!(w.may_send(), "stopped early at {i}");
            w.on_data_sent().expect("within the window");
        }
        assert_eq!(w.package(), 0);
        assert!(!w.may_send(), "did not stop at the window");
        assert_eq!(w.on_data_sent(), Err(FlowError::PackageWindowExhausted));

        w.on_sendme_received();
        assert_eq!(w.package(), WINDOW_INCREMENT);
        assert!(w.may_send());
        for _ in 0..WINDOW_INCREMENT {
            w.on_data_sent().expect("within the credited window");
        }
        assert!(!w.may_send(), "did not stop again after the credit ran out");
    }

    /// A peer that over-credits cannot inflate the window past its start.
    #[test]
    fn the_package_window_is_capped_at_its_start() {
        let mut w = Windows::new();
        for _ in 0..100 {
            w.on_sendme_received();
        }
        assert_eq!(w.package(), WINDOW_START);
    }

    /// A SENDME is owed every 100 delivered cells, and the window is credited
    /// only when the caller sends one.
    #[test]
    fn a_sendme_is_owed_every_hundred_delivered_cells() {
        let mut w = Windows::new();
        let mut owed = 0usize;
        for i in 1..=1000 {
            match w.on_data_delivered().expect("within the window") {
                AfterDelivery::SendmeOwed => {
                    owed += 1;
                    assert_eq!(i % 100, 0, "a SENDME came owed at cell {i}");
                    w.on_sendme_sent();
                }
                AfterDelivery::Nothing => assert_ne!(i % 100, 0, "no SENDME at cell {i}"),
            }
        }
        assert_eq!(owed, 10);
        assert_eq!(
            w.deliver(),
            WINDOW_START,
            "a consumer that keeps up holds the window at its start"
        );
    }

    /// A consumer that never sends its owed SENDMEs lets the window drain. This
    /// is the case the window exists for, and the reason the credit is not
    /// applied inside the delivery call.
    #[test]
    fn a_stalled_consumer_drains_the_deliver_window() {
        let mut w = Windows::new();
        for _ in 0..WINDOW_START {
            w.on_data_delivered()
                .expect("a well behaved peer stops here");
        }
        assert_eq!(w.deliver(), 0, "the window drained with no credit given");
        assert_eq!(
            w.pending(),
            WINDOW_START,
            "every cell is still unacknowledged"
        );
    }

    /// A peer that ignores its package window and sends one cell past the
    /// window drives the deliver window below zero, which tears the circuit
    /// down. Control: exactly a window's worth is accepted first.
    #[test]
    fn one_cell_past_the_window_is_an_error() {
        let mut w = Windows::new();
        for i in 0..WINDOW_START {
            w.on_data_delivered()
                .unwrap_or_else(|e| panic!("cell {i} within the window was refused: {e:?}"));
        }
        assert_eq!(
            w.on_data_delivered(),
            Err(FlowError::DeliverWindowNegative(-1))
        );
    }

    /// A caller that sends a SENDME it does not owe cannot inflate its own
    /// window, so the credit tracks consumption rather than calls.
    #[test]
    fn an_unowed_sendme_credits_nothing() {
        let mut w = Windows::new();
        w.on_sendme_sent();
        w.on_sendme_sent();
        assert_eq!(w.deliver(), WINDOW_START);
        for _ in 0..50 {
            w.on_data_delivered().unwrap();
        }
        w.on_sendme_sent();
        assert_eq!(
            w.deliver(),
            WINDOW_START - 50,
            "a half increment credited nothing"
        );
    }
}
