//! Per-connection circuit state machine.
//!
//! ARCHITECTURE.md §5.4 specifies the legal transitions:
//!
//!   Pending → Active → Closed
//!   Pending → Failed
//!   Active  → Failed
//!
//! Each accepted TCP connection on the relay's data port owns one
//! `Circuit`. The state advances explicitly via `activate`, `close`, and
//! `fail`; illegal transitions are programmer errors and return a typed
//! error rather than panicking.
//!
//! The state machine does NOT own the underlying TCP socket — that lives
//! in the connection handler. A `Circuit` is just a small piece of state
//! the handler advances as the handshake and frame loop progress.

use std::fmt;

use thiserror::Error;
use tracing::warn;

use crate::crypto::SessionKey;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CircuitError {
    #[error("illegal state transition from {from} to {to}")]
    IllegalTransition { from: State, to: State },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Pending,
    Active,
    Closed,
    Failed,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            State::Pending => write!(f, "pending"),
            State::Active => write!(f, "active"),
            State::Closed => write!(f, "closed"),
            State::Failed => write!(f, "failed"),
        }
    }
}

/// A per-connection circuit. Constructed in `Pending`; advances to
/// `Active` once the ECDH handshake succeeds and the session key is
/// derived; ends in `Closed` (graceful) or `Failed` (any error path).
pub struct Circuit {
    state: State,
    session_key: Option<SessionKey>,
}

impl Circuit {
    pub fn new() -> Self {
        Self {
            state: State::Pending,
            session_key: None,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Transition Pending → Active, storing the derived session key.
    pub fn activate(&mut self, key: SessionKey) -> Result<(), CircuitError> {
        if self.state != State::Pending {
            return Err(CircuitError::IllegalTransition {
                from: self.state,
                to: State::Active,
            });
        }
        self.state = State::Active;
        self.session_key = Some(key);
        Ok(())
    }

    /// Borrow the session key. Returns None if the circuit is not Active.
    pub fn session_key(&self) -> Option<&SessionKey> {
        match self.state {
            State::Active => self.session_key.as_ref(),
            _ => None,
        }
    }

    /// Transition to Closed. Legal from Pending or Active.
    pub fn close(&mut self) -> Result<(), CircuitError> {
        match self.state {
            State::Pending | State::Active => {
                self.state = State::Closed;
                self.session_key = None;
                Ok(())
            }
            _ => Err(CircuitError::IllegalTransition {
                from: self.state,
                to: State::Closed,
            }),
        }
    }

    /// Transition to Failed. Legal from Pending or Active. Idempotent
    /// from Failed itself so error-handling paths can call this without
    /// checking state.
    pub fn fail(&mut self) {
        match self.state {
            State::Pending | State::Active => {
                self.state = State::Failed;
                self.session_key = None;
            }
            State::Failed => {}
            State::Closed => {
                // Terminal state; emit a debug log and stay in Closed.
                warn!(
                    state = %self.state,
                    "circuit.fail() called after Close — ignoring"
                );
            }
        }
    }
}

impl Default for Circuit {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SessionKey;

    fn dummy_key() -> SessionKey {
        SessionKey::from_raw([0u8; 32])
    }

    #[test]
    fn starts_pending() {
        let c = Circuit::new();
        assert_eq!(c.state(), State::Pending);
        assert!(c.session_key().is_none());
    }

    #[test]
    fn pending_to_active_to_closed() {
        let mut c = Circuit::new();
        c.activate(dummy_key()).unwrap();
        assert_eq!(c.state(), State::Active);
        assert!(c.session_key().is_some());
        c.close().unwrap();
        assert_eq!(c.state(), State::Closed);
        assert!(c.session_key().is_none());
    }

    #[test]
    fn pending_to_failed() {
        let mut c = Circuit::new();
        c.fail();
        assert_eq!(c.state(), State::Failed);
    }

    #[test]
    fn active_to_failed_clears_key() {
        let mut c = Circuit::new();
        c.activate(dummy_key()).unwrap();
        c.fail();
        assert_eq!(c.state(), State::Failed);
        assert!(c.session_key().is_none());
    }

    #[test]
    fn double_activate_rejected() {
        let mut c = Circuit::new();
        c.activate(dummy_key()).unwrap();
        let err = c.activate(dummy_key()).unwrap_err();
        assert_eq!(
            err,
            CircuitError::IllegalTransition {
                from: State::Active,
                to: State::Active
            }
        );
    }

    #[test]
    fn close_from_failed_is_rejected() {
        let mut c = Circuit::new();
        c.fail();
        let err = c.close().unwrap_err();
        assert_eq!(
            err,
            CircuitError::IllegalTransition {
                from: State::Failed,
                to: State::Closed
            }
        );
    }

    #[test]
    fn fail_is_idempotent() {
        let mut c = Circuit::new();
        c.fail();
        c.fail(); // must not panic, must not transition
        assert_eq!(c.state(), State::Failed);
    }
}
