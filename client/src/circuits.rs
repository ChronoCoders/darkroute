use std::net::{IpAddr, SocketAddr};

use reqwest::Client as HttpClient;
use serde::Deserialize;
use url::Url;

use quiethop_crypto::noise::STATIC_KEY_LEN;

use crate::auth::Session;
use crate::error::ClientError;

/// One hop as the authority publishes it.
///
/// `ip` and `port` are where to connect. `tls_name` is what to send as SNI and
/// verify the certificate against. They are separate fields precisely so the
/// client never resolves a name while building a path (SECURITY_MODEL §5.3):
/// a resolver that saw those lookups would learn the route.
#[derive(Debug, Clone, Deserialize)]
pub struct CircuitHop {
    pub id: String,
    pub ip: String,
    pub port: u16,
    pub tls_name: String,
    pub region: String,
    /// X25519 static public key, hex. The NK handshake is pinned to it.
    pub static_pubkey: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CircuitRoute {
    pub guard: CircuitHop,
    pub middle: CircuitHop,
    pub exit: CircuitHop,
}

pub async fn get(
    http: &HttpClient,
    authority: &Url,
    session: &Session,
) -> Result<CircuitRoute, ClientError> {
    let url = authority
        .join("/api/v1/circuits/route")
        .map_err(|e| ClientError::InvalidResponse(format!("authority url join /route: {e}")))?;
    let resp = http.get(url).bearer_auth(&session.jwt).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(ClientError::AuthorityStatus(status.as_u16(), body));
    }
    let route: CircuitRoute = resp.json().await?;
    Ok(route)
}

impl CircuitHop {
    /// The socket address to dial. Parsed as a literal, never resolved.
    pub fn addr(&self) -> Result<SocketAddr, ClientError> {
        let ip: IpAddr = self.ip.parse().map_err(|_| {
            ClientError::InvalidEndpoint(self.ip.clone(), "not an IP literal".into())
        })?;
        Ok(SocketAddr::new(ip, self.port))
    }

    /// The pinned static public key.
    pub fn pubkey(&self) -> Result<[u8; STATIC_KEY_LEN], ClientError> {
        let raw = decode_hex(&self.static_pubkey)
            .ok_or_else(|| ClientError::InvalidPubkey(self.id.clone()))?;
        raw.try_into()
            .map_err(|_| ClientError::InvalidPubkey(self.id.clone()))
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        // Each digit is below 16, so the combination fits a u8.
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(ip: &str, port: u16, key: &str) -> CircuitHop {
        CircuitHop {
            id: "hop-1".to_string(),
            ip: ip.to_string(),
            port,
            tls_name: "node01.example".to_string(),
            region: "us-east".to_string(),
            static_pubkey: key.to_string(),
        }
    }

    #[test]
    fn addr_parses_v4_and_v6_literals() {
        assert_eq!(
            hop("10.0.0.1", 443, "").addr().unwrap(),
            "10.0.0.1:443".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            hop("2001:db8::1", 443, "").addr().unwrap(),
            "[2001:db8::1]:443".parse::<SocketAddr>().unwrap()
        );
    }

    /// The guarantee under test is that a hostname is never resolved. A hop
    /// whose ip field holds a name must fail rather than fall back to DNS.
    #[test]
    fn addr_refuses_a_hostname() {
        for name in ["node01.example", "localhost", ""] {
            let err = hop(name, 443, "").addr().unwrap_err();
            assert!(
                matches!(err, ClientError::InvalidEndpoint(_, _)),
                "{name:?} was accepted as an address"
            );
        }
    }

    #[test]
    fn pubkey_decodes_exactly_32_bytes() {
        let key = "ab".repeat(STATIC_KEY_LEN);
        assert_eq!(
            hop("10.0.0.1", 443, &key).pubkey().unwrap(),
            [0xABu8; STATIC_KEY_LEN]
        );
    }

    #[test]
    fn pubkey_rejects_wrong_length_and_bad_hex() {
        for bad in [
            "ab".repeat(STATIC_KEY_LEN - 1),
            "zz".repeat(STATIC_KEY_LEN),
            "abc".to_string(),
        ] {
            let err = hop("10.0.0.1", 443, &bad).pubkey().unwrap_err();
            assert!(
                matches!(err, ClientError::InvalidPubkey(_)),
                "{bad} was accepted"
            );
        }
    }

    #[test]
    fn decode_hex_round_trips() {
        assert_eq!(decode_hex("00ff10"), Some(vec![0x00, 0xFF, 0x10]));
        assert_eq!(decode_hex("f"), None);
        assert_eq!(decode_hex("gg"), None);
    }
}
