//! Chaum blind RSA per SECURITY_MODEL §5.2.
//!
//! Raw textbook RSA — no padding. The authority publishes (e, n) and
//! signs `b = m * r^e mod n` returning `s = b^d mod n`. The client
//! unblinds `token = s * r^-1 mod n` and verifies `token^e mod n == m`.

use num_bigint_dig::traits::ModInverse;
use num_bigint_dig::{BigUint, RandBigInt};
use num_traits::One;
use rand::rngs::OsRng;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};

use crate::error::ClientError;

pub struct BlindedRequest {
    pub blinded: BigUint,
    pub r_inv: BigUint,
    pub m: BigUint,
}

pub fn blind(pubkey: &RsaPublicKey, m_raw: &[u8; 32]) -> BlindedRequest {
    let n = pubkey.n();
    let e = pubkey.e();
    let m = BigUint::from_bytes_be(&Sha256::digest(m_raw)) % n;
    let mut rng = OsRng;
    let one = BigUint::one();
    loop {
        let r = rng.gen_biguint_below(n);
        if r < BigUint::from(2u32) {
            continue;
        }
        let Some(r_inv_signed) = r.clone().mod_inverse(n) else {
            continue;
        };
        let Some(r_inv) = r_inv_signed.to_biguint() else {
            continue;
        };
        if r_inv == one {
            continue;
        }
        let blinded = (&m * r.modpow(e, n)) % n;
        return BlindedRequest { blinded, r_inv, m };
    }
}

pub fn unblind_and_verify(
    pubkey: &RsaPublicKey,
    req: &BlindedRequest,
    s_blind: &BigUint,
) -> Result<BigUint, ClientError> {
    let n = pubkey.n();
    let e = pubkey.e();
    if s_blind >= n {
        return Err(ClientError::BlindOversized);
    }
    let token = (s_blind * &req.r_inv) % n;
    if token.modpow(e, n) != req.m {
        return Err(ClientError::BlindVerifyFailed);
    }
    Ok(token)
}

/// Left-pad `token` to exactly `modulus_bytes` big-endian bytes for wire format.
pub fn token_to_wire(token: &BigUint, modulus_bytes: usize) -> Vec<u8> {
    let raw = token.to_bytes_be();
    if raw.len() >= modulus_bytes {
        return raw;
    }
    let mut out = vec![0u8; modulus_bytes - raw.len()];
    out.extend_from_slice(&raw);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PrivateKeyParts;
    use rsa::RsaPrivateKey;

    #[test]
    fn round_trip_with_test_key() {
        let mut rng = OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let pubkey = RsaPublicKey::from(&priv_key);

        let m_raw = [0xAB; 32];
        let req = blind(&pubkey, &m_raw);

        // Authority side: s = b^d mod n
        let d = priv_key.d();
        let n = pubkey.n();
        let s_blind = req.blinded.modpow(d, n);

        let token = unblind_and_verify(&pubkey, &req, &s_blind).expect("unblind verifies");
        // token^e mod n == m must hold
        assert_eq!(token.modpow(pubkey.e(), n), req.m);
    }

    #[test]
    fn rejects_oversized_signed() {
        let mut rng = OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let pubkey = RsaPublicKey::from(&priv_key);
        let m_raw = [0xCD; 32];
        let req = blind(&pubkey, &m_raw);
        let too_big = pubkey.n() + BigUint::one();
        let err = unblind_and_verify(&pubkey, &req, &too_big).unwrap_err();
        assert!(matches!(err, ClientError::BlindOversized));
    }

    #[test]
    fn rejects_wrong_signed() {
        let mut rng = OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let pubkey = RsaPublicKey::from(&priv_key);
        let m_raw = [0xEF; 32];
        let req = blind(&pubkey, &m_raw);
        let bogus = req.blinded.clone() % pubkey.n();
        let err = unblind_and_verify(&pubkey, &req, &bogus).unwrap_err();
        assert!(matches!(err, ClientError::BlindVerifyFailed));
    }

    #[test]
    fn token_pads_to_modulus_size() {
        let small = BigUint::from(7u32);
        let padded = token_to_wire(&small, 256);
        assert_eq!(padded.len(), 256);
        assert_eq!(padded[255], 7);
        assert!(padded[..255].iter().all(|&b| b == 0));
    }
}
