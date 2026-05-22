use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use thiserror::Error;
use tracing::info;

#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error("http fetch failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("authority returned non-success status: {0}")]
    BadStatus(u16),
    #[error("authority returned empty body")]
    EmptyBody,
    #[error("could not parse RSA public key (tried PKCS#8 SPKI and PKCS#1)")]
    ParseFailure,
}

/// `AuthorityClient` holds the pinned RSA public key of the authority. The key
/// is fetched exactly once at startup. SECURITY_MODEL §5.1 forbids re-fetching
/// during operation — rotation requires a relay restart.
#[derive(Debug)]
pub struct AuthorityClient {
    // Consumed in Phase 3 by token verification. Field is populated and pinned
    // here so the relay refuses to start without a valid authority key.
    #[allow(dead_code)]
    pubkey: RsaPublicKey,
}

impl AuthorityClient {
    pub async fn fetch_and_pin(url: &str) -> Result<Self, AuthorityError> {
        let resp = reqwest::Client::builder()
            .https_only(false) // dev environments may use http://localhost
            .build()?
            .get(url)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(AuthorityError::BadStatus(status.as_u16()));
        }
        let body = resp.text().await?;
        if body.trim().is_empty() {
            return Err(AuthorityError::EmptyBody);
        }

        let pubkey = parse_pubkey(body.trim())?;
        info!(modulus_bits = pubkey_bits(&pubkey), "authority pubkey parsed");
        Ok(Self { pubkey })
    }

    #[allow(dead_code)] // wired into token verification in Phase 3
    pub fn pubkey(&self) -> &RsaPublicKey {
        &self.pubkey
    }
}

fn parse_pubkey(body: &str) -> Result<RsaPublicKey, AuthorityError> {
    if let Ok(k) = RsaPublicKey::from_public_key_pem(body) {
        return Ok(k);
    }
    if let Ok(k) = RsaPublicKey::from_pkcs1_pem(body) {
        return Ok(k);
    }
    Err(AuthorityError::ParseFailure)
}

fn pubkey_bits(k: &RsaPublicKey) -> usize {
    use rsa::traits::PublicKeyParts;
    k.n().bits()
}
