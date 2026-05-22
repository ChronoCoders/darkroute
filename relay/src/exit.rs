//! Exit-role outbound dialer.
//!
//! Per ARCHITECTURE.md §5.7, exit relays do not connect to external
//! destinations directly. Every outbound connection is routed through a
//! Decodo residential dedicated SOCKS5 proxy. The exit relay:
//!
//!   1. Receives a CONNECT cell from the client (via middle).
//!   2. Validates the destination port against `ALLOWED_EXIT_PORTS`.
//!      Ports outside the allowlist are rejected BEFORE any SOCKS5 dial
//!      attempt, so a malicious client cannot use the relay to probe
//!      arbitrary ports on the Decodo egress IP.
//!   3. Parses `DECODO_PROXY_URL` (`socks5://user:pass@host:port`).
//!   4. Opens a SOCKS5 connection through the proxy to (host, port) with
//!      username/password authentication using the embedded credentials.
//!
//! The destination host:port is never logged. SOCKS5 dial errors are
//! surfaced as a single opaque variant so an attacker cannot probe the
//! proxy's state by observing differential error messages.

use std::time::Duration;

use thiserror::Error;
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;
use tokio_socks::TargetAddr;

const SOCKS5_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Error)]
pub enum ExitError {
    #[error("destination port not allowed by ALLOWED_EXIT_PORTS")]
    PortNotAllowed,
    #[error("DECODO_PROXY_URL is malformed")]
    BadProxyUrl,
    #[error("SOCKS5 dial failed")]
    DialFailed,
    #[error("SOCKS5 dial timed out")]
    DialTimeout,
}

/// Dial the destination `(host, port)` via the SOCKS5 proxy described by
/// `proxy_url`. The port allowlist is checked first; on a disallowed
/// port the function returns `PortNotAllowed` and no network I/O happens.
pub async fn dial_via_socks5(
    proxy_url: &str,
    host: &str,
    port: u16,
    allowed_ports: &[u16],
) -> Result<TcpStream, ExitError> {
    if !allowed_ports.contains(&port) {
        return Err(ExitError::PortNotAllowed);
    }

    let proxy = ::url::Url::parse(proxy_url).map_err(|_| ExitError::BadProxyUrl)?;
    if !proxy.scheme().eq_ignore_ascii_case("socks5") {
        return Err(ExitError::BadProxyUrl);
    }
    let proxy_host = proxy.host_str().ok_or(ExitError::BadProxyUrl)?;
    let proxy_port = proxy.port().ok_or(ExitError::BadProxyUrl)?;
    let proxy_addr = format!("{proxy_host}:{proxy_port}");

    let target = TargetAddr::Domain(host.into(), port);

    let dial = async {
        if !proxy.username().is_empty() {
            let user = proxy.username().to_string();
            let pass = proxy.password().unwrap_or("").to_string();
            Socks5Stream::connect_with_password(proxy_addr.as_str(), target, &user, &pass).await
        } else {
            Socks5Stream::connect(proxy_addr.as_str(), target).await
        }
    };

    let socks_stream = match tokio::time::timeout(SOCKS5_CONNECT_TIMEOUT, dial).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => return Err(ExitError::DialFailed),
        Err(_) => return Err(ExitError::DialTimeout),
    };

    Ok(socks_stream.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn port_not_in_allowlist_is_rejected_without_dial() {
        // Proxy URL is intentionally garbage; the port check runs first
        // so the URL is never parsed and no network I/O occurs.
        let err = dial_via_socks5("garbage", "example.com", 22, &[80, 443])
            .await
            .unwrap_err();
        assert!(matches!(err, ExitError::PortNotAllowed));
    }

    #[tokio::test]
    async fn malformed_proxy_url_is_rejected() {
        let err = dial_via_socks5("not-a-url", "example.com", 443, &[80, 443])
            .await
            .unwrap_err();
        assert!(matches!(err, ExitError::BadProxyUrl));
    }

    #[tokio::test]
    async fn non_socks5_scheme_is_rejected() {
        let err = dial_via_socks5(
            "http://user:pass@proxy:1080",
            "example.com",
            443,
            &[80, 443],
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ExitError::BadProxyUrl));
    }

    #[tokio::test]
    async fn proxy_url_missing_port_is_rejected() {
        let err = dial_via_socks5(
            "socks5://user:pass@proxy",
            "example.com",
            443,
            &[80, 443],
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ExitError::BadProxyUrl));
    }
}
