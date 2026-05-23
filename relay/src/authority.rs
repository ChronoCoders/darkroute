use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use thiserror::Error;
use tracing::info;

#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error("http fetch failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("authority pubkey url is not a valid URL: {0}")]
    BadUrl(String),
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
    pubkey: RsaPublicKey,
}

impl AuthorityClient {
    pub async fn fetch_and_pin(url: &str) -> Result<Self, AuthorityError> {
        // Derive transport policy from the URL scheme: if the configured
        // AUTHORITY_PUBKEY_URL is https, refuse redirects to plaintext; if
        // it is http (development against a local authority), allow it.
        // The operator controls this entirely via the env var.
        let parsed = ::url::Url::parse(url).map_err(|e| AuthorityError::BadUrl(e.to_string()))?;
        let https_only = parsed.scheme().eq_ignore_ascii_case("https");

        let resp = reqwest::Client::builder()
            .https_only(https_only)
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
        info!(
            modulus_bits = pubkey_bits(&pubkey),
            "authority pubkey parsed"
        );
        Ok(Self { pubkey })
    }

    pub fn pubkey(&self) -> &RsaPublicKey {
        &self.pubkey
    }

    /// Test-only constructor. Production code MUST pin via fetch_and_pin
    /// over HTTPS so a misconfigured relay cannot start with a forged key.
    /// This entry point exists solely so the in-process integration tests
    /// can wire up three relays without standing up an HTTP server.
    #[cfg(test)]
    pub fn from_pubkey_for_test(pubkey: RsaPublicKey) -> Self {
        Self { pubkey }
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
