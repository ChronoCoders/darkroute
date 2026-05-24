use num_bigint_dig::BigUint;
use reqwest::Client as HttpClient;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::auth::Session;
use crate::blind::{blind, token_to_wire, unblind_and_verify};
use crate::error::ClientError;

pub async fn fetch_pubkey(http: &HttpClient, authority: &Url) -> Result<RsaPublicKey, ClientError> {
    let url = authority
        .join("/api/v1/authority/pubkey")
        .map_err(|e| ClientError::InvalidResponse(format!("authority url join /pubkey: {e}")))?;
    let resp = http.get(url).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(ClientError::AuthorityStatus(status.as_u16(), body));
    }
    let pem = resp.text().await?;
    RsaPublicKey::from_public_key_pem(&pem).map_err(|e| ClientError::InvalidPubkey(e.to_string()))
}

#[derive(Serialize)]
struct IssueRequest<'a> {
    blinded: &'a str,
}

#[derive(Deserialize)]
struct IssueResponse {
    signed: String,
}

pub async fn issue(
    http: &HttpClient,
    authority: &Url,
    session: &Session,
    pubkey: &RsaPublicKey,
) -> Result<([u8; 32], Vec<u8>), ClientError> {
    let mut m_raw = [0u8; 32];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut m_raw);

    let req = blind(pubkey, &m_raw);
    let blinded_hex = hex_lower(&req.blinded.to_bytes_be());

    let url = authority
        .join("/api/v1/tokens/issue")
        .map_err(|e| ClientError::InvalidResponse(format!("authority url join /issue: {e}")))?;
    let resp = http
        .post(url)
        .bearer_auth(&session.jwt)
        .json(&IssueRequest {
            blinded: &blinded_hex,
        })
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(ClientError::AuthorityStatus(status.as_u16(), body));
    }
    let body: IssueResponse = resp.json().await?;
    let signed_bytes = hex_decode(&body.signed)?;
    let s_blind = BigUint::from_bytes_be(&signed_bytes);

    let token_int = unblind_and_verify(pubkey, &req, &s_blind)?;
    let modulus_bytes = pubkey.n().bits().div_ceil(8);
    let token = token_to_wire(&token_int, modulus_bytes);
    Ok((m_raw, token))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(nibble(b >> 4));
        s.push(nibble(b & 0x0f));
    }
    s
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => '?',
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ClientError> {
    if !s.len().is_multiple_of(2) {
        return Err(ClientError::InvalidResponse("hex length odd".into()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks_exact(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, ClientError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(ClientError::InvalidResponse(format!(
            "bad hex byte 0x{c:02x}"
        ))),
    }
}
