//! Per-hop Noise NK handshake and transport framing (SECURITY_MODEL §5.10, §6.1).
//!
//! Each hop runs one `Noise_NK_25519_ChaChaPoly_SHA256` handshake against the
//! relay's long-term static X25519 key. The client is the initiator and is
//! ephemeral only; the relay is the responder and proves possession of the
//! static key the registry names for it.
//!
//! Both sides bind the fixed prologue [`NOISE_PROLOGUE`]. NK authenticates the
//! responder's static key but nothing about the surrounding context, so without
//! a prologue a transcript would be valid for any deployment reusing the same
//! pattern and relay key.
//!
//! Handshake messages are 48 bytes in each direction: a 32-byte ephemeral
//! public key plus a 16-byte tag over an empty payload.
//!
//! Transport nonces are snow's implicit counters. They never appear on the wire
//! and advance only on a successful decrypt, which is what gives per-hop replay
//! and ordering protection.

use snow::{Builder, TransportState};

/// The one permitted suite, closed in docs/DECISIONS.md entry 14.
pub const NOISE_PARAMS: &str = "Noise_NK_25519_ChaChaPoly_SHA256";

/// Bound by both sides. A mismatch fails the handshake.
pub const NOISE_PROLOGUE: &[u8] = b"quiethop/v1/nk";

/// AEAD tag length. Matches snow's `TAGLEN`.
pub const NOISE_TAG_LEN: usize = 16;

/// Length of each NK handshake message with an empty payload.
pub const NOISE_MSG_LEN: usize = 48;

/// X25519 key length, for both halves of the static keypair.
pub const STATIC_KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum NoiseError {
    #[error("noise handshake failed")]
    Handshake,
    #[error("noise transport authentication failed")]
    Transport,
    #[error("static key material is not {STATIC_KEY_LEN} bytes")]
    KeyLength,
    #[error("buffer length {got} does not match the expected {want}")]
    Length { got: usize, want: usize },
}

/// A freshly generated long-term static keypair.
///
/// The private half is zeroed on drop. It is never logged, never written to a
/// test fixture and never committed (SECURITY_MODEL §8).
pub struct StaticKeypair {
    pub public: [u8; STATIC_KEY_LEN],
    private: [u8; STATIC_KEY_LEN],
}

impl StaticKeypair {
    /// Borrow the private half. Callers must not copy it into a log or an error.
    pub fn private(&self) -> &[u8; STATIC_KEY_LEN] {
        &self.private
    }

    /// Rebuild a keypair from the two halves as stored on disk.
    ///
    /// snow exposes no way to derive a public key from a private one, and
    /// ARCHITECTURE §5.1 removes the bare x25519-dalek path, so the halves are
    /// stored together and checked against each other here: a full NK handshake
    /// against the stored public key must complete with the stored private key.
    /// Mismatched halves cannot pass, so a truncated or edited key file fails at
    /// load rather than at the first client connection.
    pub fn from_parts(
        private: [u8; STATIC_KEY_LEN],
        public: [u8; STATIC_KEY_LEN],
    ) -> Result<Self, NoiseError> {
        let (initiator, msg1) = Initiator::start(&public)?;
        let (_, msg2) = respond(&private, &msg1)?;
        initiator.finish(&msg2)?;
        Ok(Self { public, private })
    }
}

impl core::fmt::Debug for StaticKeypair {
    /// Prints the public half only. A derived Debug would print the private
    /// key into any log line or panic message that formatted this type.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StaticKeypair")
            .field("public", &self.public)
            .field("private", &"<redacted>")
            .finish()
    }
}

impl Drop for StaticKeypair {
    fn drop(&mut self) {
        for b in self.private.iter_mut() {
            *b = 0;
        }
    }
}

fn params() -> Result<snow::params::NoiseParams, NoiseError> {
    NOISE_PARAMS.parse().map_err(|_| NoiseError::Handshake)
}

/// Generate a static keypair. Used only by the `keygen` subcommand, never at
/// relay startup: a relay with a missing key must fail rather than invent one,
/// because a new key silently invalidates its registry entry.
pub fn generate_static_keypair() -> Result<StaticKeypair, NoiseError> {
    let kp = Builder::new(params()?)
        .generate_keypair()
        .map_err(|_| NoiseError::Handshake)?;
    let private: [u8; STATIC_KEY_LEN] = kp
        .private
        .as_slice()
        .try_into()
        .map_err(|_| NoiseError::KeyLength)?;
    let public: [u8; STATIC_KEY_LEN] = kp
        .public
        .as_slice()
        .try_into()
        .map_err(|_| NoiseError::KeyLength)?;
    Ok(StaticKeypair { public, private })
}

/// An established per-hop transport session.
pub struct Transport {
    inner: TransportState,
}

impl Transport {
    /// Encrypt `plaintext` into `out`, which must be exactly
    /// `plaintext.len() + NOISE_TAG_LEN` bytes.
    pub fn encrypt(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<(), NoiseError> {
        let want = plaintext.len() + NOISE_TAG_LEN;
        if out.len() != want {
            return Err(NoiseError::Length {
                got: out.len(),
                want,
            });
        }
        let n = self
            .inner
            .write_message(plaintext, out)
            .map_err(|_| NoiseError::Transport)?;
        if n != want {
            return Err(NoiseError::Length { got: n, want });
        }
        Ok(())
    }

    /// Decrypt `ciphertext` into `out`, which must be exactly
    /// `ciphertext.len() - NOISE_TAG_LEN` bytes.
    ///
    /// On failure the caller must tear the circuit down. Continuing would read
    /// later cells against a counter that no longer matches the sender's.
    pub fn decrypt(&mut self, ciphertext: &[u8], out: &mut [u8]) -> Result<(), NoiseError> {
        if ciphertext.len() < NOISE_TAG_LEN {
            return Err(NoiseError::Length {
                got: ciphertext.len(),
                want: NOISE_TAG_LEN,
            });
        }
        let want = ciphertext.len() - NOISE_TAG_LEN;
        if out.len() != want {
            return Err(NoiseError::Length {
                got: out.len(),
                want,
            });
        }
        let n = self
            .inner
            .read_message(ciphertext, out)
            .map_err(|_| NoiseError::Transport)?;
        if n != want {
            return Err(NoiseError::Length { got: n, want });
        }
        Ok(())
    }
}

/// Client side. Produces message 1, then consumes message 2.
pub struct Initiator {
    inner: snow::HandshakeState,
}

impl Initiator {
    /// Start a handshake against `remote_static`, returning message 1.
    pub fn start(
        remote_static: &[u8; STATIC_KEY_LEN],
    ) -> Result<(Self, [u8; NOISE_MSG_LEN]), NoiseError> {
        let mut inner = Builder::new(params()?)
            .prologue(NOISE_PROLOGUE)
            .map_err(|_| NoiseError::Handshake)?
            .remote_public_key(remote_static)
            .map_err(|_| NoiseError::KeyLength)?
            .build_initiator()
            .map_err(|_| NoiseError::Handshake)?;
        let mut msg1 = [0u8; NOISE_MSG_LEN];
        let n = inner
            .write_message(&[], &mut msg1)
            .map_err(|_| NoiseError::Handshake)?;
        if n != NOISE_MSG_LEN {
            return Err(NoiseError::Length {
                got: n,
                want: NOISE_MSG_LEN,
            });
        }
        Ok((Self { inner }, msg1))
    }

    /// Consume message 2 and enter transport mode.
    pub fn finish(mut self, msg2: &[u8; NOISE_MSG_LEN]) -> Result<Transport, NoiseError> {
        let mut scratch = [0u8; NOISE_MSG_LEN];
        self.inner
            .read_message(msg2, &mut scratch)
            .map_err(|_| NoiseError::Handshake)?;
        let inner = self
            .inner
            .into_transport_mode()
            .map_err(|_| NoiseError::Handshake)?;
        Ok(Transport { inner })
    }
}

/// Relay side. Consumes message 1 and produces message 2 in one step, because
/// NK gives the responder nothing to decide in between.
pub fn respond(
    static_private: &[u8; STATIC_KEY_LEN],
    msg1: &[u8; NOISE_MSG_LEN],
) -> Result<(Transport, [u8; NOISE_MSG_LEN]), NoiseError> {
    let mut hs = Builder::new(params()?)
        .prologue(NOISE_PROLOGUE)
        .map_err(|_| NoiseError::Handshake)?
        .local_private_key(static_private)
        .map_err(|_| NoiseError::KeyLength)?
        .build_responder()
        .map_err(|_| NoiseError::Handshake)?;

    let mut scratch = [0u8; NOISE_MSG_LEN];
    hs.read_message(msg1, &mut scratch)
        .map_err(|_| NoiseError::Handshake)?;

    let mut msg2 = [0u8; NOISE_MSG_LEN];
    let n = hs
        .write_message(&[], &mut msg2)
        .map_err(|_| NoiseError::Handshake)?;
    if n != NOISE_MSG_LEN {
        return Err(NoiseError::Length {
            got: n,
            want: NOISE_MSG_LEN,
        });
    }

    let inner = hs
        .into_transport_mode()
        .map_err(|_| NoiseError::Handshake)?;
    Ok((Transport { inner }, msg2))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake() -> (Transport, Transport) {
        let server = generate_static_keypair().unwrap();
        let (init, msg1) = Initiator::start(&server.public).unwrap();
        let (resp_tx, msg2) = respond(server.private(), &msg1).unwrap();
        (init.finish(&msg2).unwrap(), resp_tx)
    }

    #[test]
    fn handshake_messages_are_the_declared_length() {
        let server = generate_static_keypair().unwrap();
        let (_, msg1) = Initiator::start(&server.public).unwrap();
        let (_, msg2) = respond(server.private(), &msg1).unwrap();
        assert_eq!(msg1.len(), NOISE_MSG_LEN);
        assert_eq!(msg2.len(), NOISE_MSG_LEN);
    }

    #[test]
    fn transport_round_trips_both_directions() {
        let (mut client, mut relay) = handshake();
        let plain = b"one cell's worth of plaintext";
        let mut ct = vec![0u8; plain.len() + NOISE_TAG_LEN];
        client.encrypt(plain, &mut ct).unwrap();
        let mut out = vec![0u8; plain.len()];
        relay.decrypt(&ct, &mut out).unwrap();
        assert_eq!(out, plain);

        let back = b"and the reply";
        let mut ct2 = vec![0u8; back.len() + NOISE_TAG_LEN];
        relay.encrypt(back, &mut ct2).unwrap();
        let mut out2 = vec![0u8; back.len()];
        client.decrypt(&ct2, &mut out2).unwrap();
        assert_eq!(out2, back);
    }

    #[test]
    fn wrong_static_key_fails_the_handshake() {
        let server = generate_static_keypair().unwrap();
        let impostor = generate_static_keypair().unwrap();
        assert_ne!(
            server.public, impostor.public,
            "control: the two keys differ"
        );

        // Control: the right key completes.
        let (_, good) = Initiator::start(&server.public).unwrap();
        assert!(respond(server.private(), &good).is_ok());

        // The initiator addresses the impostor's key, the real relay answers.
        // Transport holds cipher state and has no Debug impl on purpose, so the
        // variant is matched rather than unwrapped.
        let (_, bad) = Initiator::start(&impostor.public).unwrap();
        match respond(server.private(), &bad) {
            Err(NoiseError::Handshake) => {}
            Err(other) => panic!("wrong error for a mismatched static key: {other}"),
            Ok(_) => panic!("a handshake against the wrong static key completed"),
        }
    }

    #[test]
    fn prologue_mismatch_fails_the_handshake() {
        let server = generate_static_keypair().unwrap();

        // Control: matching prologues complete, which is the handshake() helper.
        let (_, msg1) = Initiator::start(&server.public).unwrap();
        assert!(respond(server.private(), &msg1).is_ok());

        // A responder bound to a different prologue rejects the same message.
        let mut hs = Builder::new(params().unwrap())
            .prologue(b"quiethop/v1/nk-other")
            .unwrap()
            .local_private_key(server.private())
            .unwrap()
            .build_responder()
            .unwrap();
        let mut scratch = [0u8; NOISE_MSG_LEN];
        assert!(hs.read_message(&msg1, &mut scratch).is_err());
    }

    #[test]
    fn replayed_frame_is_rejected() {
        let (mut client, mut relay) = handshake();
        let plain = b"replay me";
        let mut ct = vec![0u8; plain.len() + NOISE_TAG_LEN];
        client.encrypt(plain, &mut ct).unwrap();

        let mut out = vec![0u8; plain.len()];
        relay.decrypt(&ct, &mut out).unwrap();

        // The counter has advanced, so the identical bytes no longer verify.
        let mut again = vec![0u8; plain.len()];
        assert!(matches!(
            relay.decrypt(&ct, &mut again),
            Err(NoiseError::Transport)
        ));
    }

    #[test]
    fn reordered_frames_are_rejected() {
        let (mut client, mut relay) = handshake();
        let mut first = vec![0u8; 4 + NOISE_TAG_LEN];
        let mut second = vec![0u8; 4 + NOISE_TAG_LEN];
        client.encrypt(b"aaaa", &mut first).unwrap();
        client.encrypt(b"bbbb", &mut second).unwrap();

        // Delivering the second frame first fails: its counter is not the one
        // the receiver expects.
        let mut out = vec![0u8; 4];
        assert!(matches!(
            relay.decrypt(&second, &mut out),
            Err(NoiseError::Transport)
        ));
    }

    #[test]
    fn tampered_frame_is_rejected() {
        let (mut client, mut relay) = handshake();
        let plain = b"integrity";
        let mut ct = vec![0u8; plain.len() + NOISE_TAG_LEN];
        client.encrypt(plain, &mut ct).unwrap();
        ct[0] ^= 0x01;
        let mut out = vec![0u8; plain.len()];
        assert!(matches!(
            relay.decrypt(&ct, &mut out),
            Err(NoiseError::Transport)
        ));
    }

    #[test]
    fn decrypt_rejects_a_mismatched_output_buffer() {
        let (mut client, mut relay) = handshake();
        let mut ct = vec![0u8; 8 + NOISE_TAG_LEN];
        client.encrypt(b"12345678", &mut ct).unwrap();
        let mut too_small = vec![0u8; 4];
        assert!(matches!(
            relay.decrypt(&ct, &mut too_small),
            Err(NoiseError::Length { .. })
        ));
    }

    #[test]
    fn static_keypair_round_trips_from_parts() {
        let kp = generate_static_keypair().unwrap();
        let again = StaticKeypair::from_parts(*kp.private(), kp.public).unwrap();
        assert_eq!(kp.public, again.public);
    }

    #[test]
    fn from_parts_rejects_halves_that_do_not_correspond() {
        let a = generate_static_keypair().unwrap();
        let b = generate_static_keypair().unwrap();
        // Control: each keypair's own halves load.
        assert!(StaticKeypair::from_parts(*a.private(), a.public).is_ok());
        assert!(StaticKeypair::from_parts(*b.private(), b.public).is_ok());
        // Crossed halves do not.
        assert!(matches!(
            StaticKeypair::from_parts(*a.private(), b.public),
            Err(NoiseError::Handshake)
        ));
    }
}
