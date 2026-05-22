//! Blind RSA token verification (relay side).
//!
//! Implements SECURITY_MODEL.md §5.4 exactly. The previous implementation
//! of this system shipped without step 4 (the RSA check); that omission is
//! the reason this protocol is being rebuilt. The verify() function in this
//! file MUST:
//!
//!   1. Compute m = SHA-256(m_raw).
//!   2. Compute check = token^e mod n using the pinned authority public key.
//!   3. Reject if check != m.       <-- RSA signature check FIRST.
//!   4. Compute token_hash = SHA-256(token).
//!   5. Reject if token_hash is in the replay window.
//!   6. Insert token_hash into the replay window.
//!   7. Return Ok.
//!
//! There is no bypass path. If verify() returns Err, the connection is
//! dropped before any circuit state exists.
//!
//! The big-integer arithmetic uses `num-bigint` per ARCHITECTURE.md §5.1.
//! The rsa crate's higher-level signature primitives are not used because
//! they apply PKCS#1 padding, which is incompatible with raw blind RSA.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use num_bigint::BigUint;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("token bytes shorter than modulus size")]
    TokenTooShort,
    #[error("RSA signature check failed")]
    InvalidSignature,
    #[error("token replayed within replay window TTL")]
    Replayed,
}

/// Time-bounded set of recently-seen token hashes. Inserts and contains
/// checks evict any entries older than `ttl` before operating, so the map
/// size is bounded by the relay's traffic rate.
pub struct ReplayWindow {
    ttl: Duration,
    inner: Mutex<HashMap<[u8; 32], Instant>>,
}

impl ReplayWindow {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(HashMap::new()),
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().expect("replay window mutex poisoned").len()
    }
}

/// Verify that `token` is a valid blind-RSA signature over SHA-256(m_raw)
/// under `pubkey`, and that it has not been presented before within the
/// replay window's TTL.
///
/// On success, `token_hash` is inserted into the window. On failure, the
/// window is not modified by the replay branch (an invalid token must
/// never block a future valid one), but expired entries are still evicted.
pub fn verify(
    m_raw: &[u8],
    token: &[u8],
    pubkey: &RsaPublicKey,
    window: &ReplayWindow,
) -> Result<(), TokenError> {
    // ----- Step 1: RSA signature check (mandatory FIRST per §5.4). -----
    let modulus_bytes = pubkey.n().bits().div_ceil(8);
    if token.len() < modulus_bytes {
        return Err(TokenError::TokenTooShort);
    }

    let m_hash = Sha256::digest(m_raw);
    let m_int = BigUint::from_bytes_be(&m_hash);

    let token_int = BigUint::from_bytes_be(token);

    // Convert pubkey n and e (which the rsa crate exposes via its own
    // num-bigint-dig type) into num-bigint values for the verification.
    let n_bytes = pubkey.n().to_bytes_be();
    let e_bytes = pubkey.e().to_bytes_be();
    let n = BigUint::from_bytes_be(&n_bytes);
    let e = BigUint::from_bytes_be(&e_bytes);

    if token_int >= n {
        // token must be a residue mod n
        return Err(TokenError::InvalidSignature);
    }

    let check = token_int.modpow(&e, &n);
    if check != m_int {
        return Err(TokenError::InvalidSignature);
    }

    // ----- Step 2: replay check (mandatory SECOND). -----
    let token_hash: [u8; 32] = Sha256::digest(token).into();
    let mut map = window
        .inner
        .lock()
        .expect("replay window mutex poisoned");

    // Evict expired entries before checking.
    let now = Instant::now();
    let ttl = window.ttl;
    map.retain(|_, t| now.duration_since(*t) < ttl);

    if map.contains_key(&token_hash) {
        return Err(TokenError::Replayed);
    }
    map.insert(token_hash, now);
    Ok(())
}

/// Compute s = m^d mod n using num-bigint, bypassing the rsa crate's
/// padded sign path. This is the raw operation a client would perform
/// (in production, with blinding) when redeeming a Chaum signature.
/// Used by the integration test and the in-module unit tests below.
#[cfg(test)]
pub(crate) fn raw_sign(m_raw: &[u8], priv_key: &rsa::RsaPrivateKey) -> Vec<u8> {
    use num_bigint::BigUint as NbBigUint;
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    let m_hash = Sha256::digest(m_raw);
    let m_int = NbBigUint::from_bytes_be(&m_hash);
    let n = NbBigUint::from_bytes_be(&priv_key.n().to_bytes_be());
    let d = NbBigUint::from_bytes_be(&priv_key.d().to_bytes_be());
    let s = m_int.modpow(&d, &n);

    let modsize = priv_key.n().bits().div_ceil(8);
    let mut out = vec![0u8; modsize];
    let s_bytes = s.to_bytes_be();
    out[modsize - s_bytes.len()..].copy_from_slice(&s_bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::{RsaPrivateKey, RsaPublicKey};

    fn fresh_keypair() -> (RsaPrivateKey, RsaPublicKey) {
        // 1024-bit for test speed. The verify() code path is identical for
        // any modulus size; only test setup time differs.
        let mut rng = rand_core::OsRng;
        let priv_key =
            RsaPrivateKey::new(&mut rng, 1024).expect("test rsa keygen");
        let pub_key = RsaPublicKey::from(&priv_key);
        (priv_key, pub_key)
    }

    #[test]
    fn valid_token_passes() {
        let (priv_key, pub_key) = fresh_keypair();
        let window = ReplayWindow::new(Duration::from_secs(60));
        let m_raw = b"this is exactly thirty-two bytes";
        let token = raw_sign(m_raw, &priv_key);
        verify(m_raw, &token, &pub_key, &window).expect("valid token must pass");
        assert_eq!(window.len(), 1, "valid token should be inserted into window");
    }

    #[test]
    fn wrong_signature_rejected_before_replay_check() {
        let (_priv_key, pub_key) = fresh_keypair();
        let window = ReplayWindow::new(Duration::from_secs(60));
        let m_raw = b"this is exactly thirty-two bytes";
        // Construct a token that is the right length but garbage content.
        let modsize = pub_key.n().bits().div_ceil(8);
        let bad_token = vec![0x42u8; modsize];

        let err1 = verify(m_raw, &bad_token, &pub_key, &window).unwrap_err();
        assert_eq!(
            err1,
            TokenError::InvalidSignature,
            "bad signature must be rejected before any replay logic runs"
        );
        // The window must not have been polluted by the failed attempt:
        assert_eq!(window.len(), 0, "invalid tokens must not enter the replay window");

        // Submit the same garbage again. If the implementation accidentally
        // checked replay before RSA, this second call would return Replayed
        // (because the first call would have inserted the hash). It must
        // still return InvalidSignature, proving order.
        let err2 = verify(m_raw, &bad_token, &pub_key, &window).unwrap_err();
        assert_eq!(
            err2,
            TokenError::InvalidSignature,
            "RSA check must run BEFORE replay check on every call"
        );
    }

    #[test]
    fn replayed_token_rejected() {
        let (priv_key, pub_key) = fresh_keypair();
        let window = ReplayWindow::new(Duration::from_secs(60));
        let m_raw = b"replay-test-message-preimage-32!";
        let token = raw_sign(m_raw, &priv_key);

        verify(m_raw, &token, &pub_key, &window).expect("first use ok");
        let err = verify(m_raw, &token, &pub_key, &window).unwrap_err();
        assert_eq!(err, TokenError::Replayed);
    }

    #[test]
    fn token_shorter_than_modulus_rejected() {
        let (_priv_key, pub_key) = fresh_keypair();
        let window = ReplayWindow::new(Duration::from_secs(60));
        let m_raw = b"any-m-raw-value";
        let modsize = pub_key.n().bits().div_ceil(8);

        let short_token = vec![0xFFu8; modsize - 1];
        let err = verify(m_raw, &short_token, &pub_key, &window).unwrap_err();
        assert_eq!(err, TokenError::TokenTooShort);

        let empty: &[u8] = &[];
        let err = verify(m_raw, empty, &pub_key, &window).unwrap_err();
        assert_eq!(err, TokenError::TokenTooShort);
    }

    #[test]
    fn replay_window_evicts_expired_entries() {
        let (priv_key, pub_key) = fresh_keypair();
        let window = ReplayWindow::new(Duration::from_millis(50));
        let m_raw = b"evict-test-message-preimage-32-b";
        let token = raw_sign(m_raw, &priv_key);

        verify(m_raw, &token, &pub_key, &window).expect("first use ok");
        std::thread::sleep(Duration::from_millis(80));
        // After TTL, the same token should pass again because the entry
        // has been evicted.
        verify(m_raw, &token, &pub_key, &window).expect("post-eviction reuse ok");
        assert_eq!(window.len(), 1);
    }
}
