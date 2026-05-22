//! Per-hop key exchange and authenticated framing.
//!
//! Implements the cryptographic primitives required by SECURITY_MODEL §4
//! and §6:
//!
//!   * Per-hop key exchange: X25519 ECDH between an ephemeral relay
//!     keypair and the client's ephemeral public key. The shared secret
//!     feeds HKDF-SHA256 to derive a 256-bit symmetric key.
//!   * Per-hop traffic encryption: AES-256-GCM with a random 96-bit nonce
//!     per frame. The wire frame is `nonce(12) || length(4 BE) || ciphertext+tag`.
//!
//! Ephemeral keypairs use the OS RNG (`getrandom`) and are dropped at the
//! end of the circuit, so a compromised relay cannot decrypt past traffic
//! recorded by a passive observer (forward secrecy on the per-hop key).

use std::io;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub const X25519_PUBKEY_LEN: usize = 32;
pub const AES_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Upper bound on a single frame's plaintext, in bytes. Sized to comfortably
/// hold a relay control cell while preventing a peer from forcing the
/// relay to allocate megabytes per frame.
pub const MAX_FRAME_PLAINTEXT: usize = 64 * 1024;
const MAX_FRAME_CIPHERTEXT: usize = MAX_FRAME_PLAINTEXT + TAG_LEN;

const HKDF_INFO_SESSION_KEY: &[u8] = b"darkroute/v1/session-key";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("authenticated decryption failed")]
    Aead,
    #[error("declared frame ciphertext length {0} exceeds the per-frame cap")]
    FrameTooLarge(u32),
    #[error("declared frame ciphertext length is shorter than the authentication tag")]
    FrameTooShort,
}

/// A derived AES-256-GCM session key. The bytes are kept on the stack via
/// a fixed-size array; `Drop` zeroes them so the key does not persist in
/// the relay's memory beyond the circuit's lifetime.
pub struct SessionKey([u8; AES_KEY_LEN]);

impl SessionKey {
    fn cipher(&self) -> Aes256Gcm {
        // `new_from_slice` only fails on incorrect length; the array is
        // exactly AES_KEY_LEN so the unwrap path is unreachable.
        Aes256Gcm::new_from_slice(&self.0).expect("session key is exactly 32 bytes")
    }

    #[cfg(test)]
    pub(crate) fn from_raw(k: [u8; AES_KEY_LEN]) -> Self {
        Self(k)
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        // Best-effort zeroization. The compiler is permitted to elide
        // writes to dead memory; `std::ptr::write_volatile` would harden
        // this further but is unnecessary for the v1 threat model
        // (SECURITY_MODEL §11: physical-memory inspection of the relay
        // host is explicitly out of scope).
        for b in self.0.iter_mut() {
            *b = 0;
        }
    }
}

/// Perform the relay side of the per-hop X25519 handshake.
///
/// 1. Read the client's ephemeral public key (32 bytes).
/// 2. Generate the relay's own ephemeral keypair.
/// 3. Send the relay's ephemeral public key (32 bytes).
/// 4. Derive the AES-256-GCM session key via X25519 + HKDF-SHA256.
pub async fn relay_handshake<R, W>(
    reader: &mut R,
    writer: &mut W,
) -> Result<SessionKey, CryptoError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut peer_pk_bytes = [0u8; X25519_PUBKEY_LEN];
    reader.read_exact(&mut peer_pk_bytes).await?;
    let peer_pk = PublicKey::from(peer_pk_bytes);

    let our_secret = EphemeralSecret::random_from_rng(OsRng);
    let our_pk = PublicKey::from(&our_secret);

    writer.write_all(our_pk.as_bytes()).await?;
    writer.flush().await?;

    let shared = our_secret.diffie_hellman(&peer_pk);
    Ok(derive_session_key(shared.as_bytes()))
}

/// Derive a 32-byte AES-256-GCM key from a raw X25519 shared secret via
/// HKDF-SHA256 with an empty salt and the protocol-versioned info string.
pub fn derive_session_key(shared_secret: &[u8]) -> SessionKey {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; AES_KEY_LEN];
    // HKDF::expand only fails when the requested length exceeds 255 * HashLen;
    // 32 bytes is far below that bound.
    hk.expand(HKDF_INFO_SESSION_KEY, &mut key)
        .expect("HKDF expand of 32 bytes is within bounds");
    SessionKey(key)
}

/// Encrypt `plaintext` under `key` and write the frame to `writer`.
///
/// Wire format: `nonce(12) || ciphertext_length(4 BE) || ciphertext+tag`.
pub async fn write_frame<W>(
    writer: &mut W,
    key: &SessionKey,
    plaintext: &[u8],
) -> Result<(), CryptoError>
where
    W: AsyncWrite + Unpin,
{
    debug_assert!(plaintext.len() <= MAX_FRAME_PLAINTEXT);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = key
        .cipher()
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::Aead)?;

    let len = u32::try_from(ciphertext.len()).map_err(|_| {
        // ciphertext.len() <= MAX_FRAME_PLAINTEXT + TAG_LEN which fits in
        // u32 by a wide margin; unreachable in practice but mapped to a
        // typed error rather than panicking.
        CryptoError::FrameTooLarge(u32::MAX)
    })?;

    writer.write_all(&nonce_bytes).await?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&ciphertext).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one frame from `reader` and decrypt it under `key`. Returns the
/// plaintext on success. Frames whose declared length exceeds the per-frame
/// cap are rejected before any allocation, so a peer cannot force unbounded
/// memory use by lying about length.
pub async fn read_frame<R>(reader: &mut R, key: &SessionKey) -> Result<Vec<u8>, CryptoError>
where
    R: AsyncRead + Unpin,
{
    let mut nonce_bytes = [0u8; NONCE_LEN];
    reader.read_exact(&mut nonce_bytes).await?;

    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let ct_len = u32::from_be_bytes(len_bytes);
    if (ct_len as usize) < TAG_LEN {
        return Err(CryptoError::FrameTooShort);
    }
    if (ct_len as usize) > MAX_FRAME_CIPHERTEXT {
        return Err(CryptoError::FrameTooLarge(ct_len));
    }

    let mut ciphertext = vec![0u8; ct_len as usize];
    reader.read_exact(&mut ciphertext).await?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    key.cipher()
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| CryptoError::Aead)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn handshake_round_trip() {
        // Both sides simulate the relay-handshake by exchanging X25519
        // pubkeys over a duplex pipe; the derived session keys must be
        // bytewise identical so a later frame can decrypt either way.
        let (a, b) = duplex(1024);

        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_pk = PublicKey::from(&client_secret);

        let server = tokio::spawn(async move {
            let (mut a_reader, mut a_writer) = tokio::io::split(a);
            relay_handshake(&mut a_reader, &mut a_writer).await.unwrap()
        });

        let (mut b_reader, mut b_writer) = tokio::io::split(b);
        b_writer.write_all(client_pk.as_bytes()).await.unwrap();
        b_writer.flush().await.unwrap();
        let mut their_pk = [0u8; X25519_PUBKEY_LEN];
        b_reader.read_exact(&mut their_pk).await.unwrap();
        let their_pk = PublicKey::from(their_pk);
        let shared = client_secret.diffie_hellman(&their_pk);
        let client_key = derive_session_key(shared.as_bytes());

        let server_key = server.await.unwrap();
        assert_eq!(client_key.0, server_key.0);
    }

    #[tokio::test]
    async fn frame_round_trip() {
        let key = SessionKey::from_raw([7u8; AES_KEY_LEN]);
        let (mut a, mut b) = duplex(8192);
        let plaintext = b"darkroute control cell test payload";

        write_frame(&mut a, &key, plaintext).await.unwrap();

        let got = read_frame(&mut b, &key).await.unwrap();
        assert_eq!(got, plaintext);
    }

    #[tokio::test]
    async fn frame_rejects_bit_flip() {
        let key = SessionKey::from_raw([7u8; AES_KEY_LEN]);
        let (mut a, mut b) = duplex(8192);
        write_frame(&mut a, &key, b"hello world").await.unwrap();

        // Read the full transmitted frame, flip one bit in the ciphertext,
        // and attempt to decrypt.
        let mut head = [0u8; NONCE_LEN + 4];
        b.read_exact(&mut head).await.unwrap();
        let ct_len = u32::from_be_bytes(head[NONCE_LEN..].try_into().unwrap()) as usize;
        let mut ct = vec![0u8; ct_len];
        b.read_exact(&mut ct).await.unwrap();
        ct[0] ^= 0x01;

        // Reassemble and feed to read_frame via a fresh duplex pipe.
        let (mut x, mut y) = duplex(8192);
        x.write_all(&head).await.unwrap();
        x.write_all(&ct).await.unwrap();
        drop(x);

        let err = read_frame(&mut y, &key).await.unwrap_err();
        assert!(matches!(err, CryptoError::Aead));
    }

    #[tokio::test]
    async fn frame_rejects_oversize_length() {
        let key = SessionKey::from_raw([7u8; AES_KEY_LEN]);
        let (mut a, mut b) = duplex(64);
        // Write a nonce and a declared length that exceeds the cap. We
        // must not block on writing the (non-existent) ciphertext, so
        // close the writer immediately.
        a.write_all(&[0u8; NONCE_LEN]).await.unwrap();
        let bogus_len: u32 = (MAX_FRAME_CIPHERTEXT as u32) + 1;
        a.write_all(&bogus_len.to_be_bytes()).await.unwrap();
        drop(a);

        let err = read_frame(&mut b, &key).await.unwrap_err();
        assert!(matches!(err, CryptoError::FrameTooLarge(_)));
    }

    #[tokio::test]
    async fn frame_rejects_too_short_length() {
        let key = SessionKey::from_raw([7u8; AES_KEY_LEN]);
        let (mut a, mut b) = duplex(64);
        a.write_all(&[0u8; NONCE_LEN]).await.unwrap();
        a.write_all(&(8u32).to_be_bytes()).await.unwrap();
        drop(a);

        let err = read_frame(&mut b, &key).await.unwrap_err();
        assert!(matches!(err, CryptoError::FrameTooShort));
    }
}
