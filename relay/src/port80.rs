//! Port-80 HTTP redirector.
//!
//! A box silent on 80 but answering on 443 reads as anomalous to
//! provider-side NetFlow because every conventional HTTPS host also
//! serves a 301 on 80 (SESSION_LOG 2026-05-22 deployment-surface
//! hardening entry; ARCHITECTURE §5.8, §8.1).
//!
//! Bounded read (4 KiB) and a 5s read timeout cap the resources a
//! hostile peer can tie up. No keepalive, no header parsing — this is
//! the smallest correct redirector, not an HTTP server.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tracing::{info, warn};

const READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_HEAD: usize = 4096;

pub async fn redirect_loop(listener: TcpListener, hostname: String, shutdown: Arc<Notify>) {
    let hostname = Arc::new(hostname);
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                info!("port 80 redirector shutting down");
                return;
            }
            res = listener.accept() => match res {
                Ok((sock, _peer)) => {
                    let host = hostname.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve_redirect(sock, &host).await {
                            warn!(error = %e, "port 80 redirect failed");
                        }
                    });
                }
                Err(e) => warn!(error = %e, "port 80 accept failed"),
            }
        }
    }
}

async fn serve_redirect(mut sock: TcpStream, hostname: &str) -> std::io::Result<()> {
    let mut buf = [0u8; MAX_REQUEST_HEAD];
    let mut filled = 0usize;
    loop {
        if filled == buf.len() {
            break;
        }
        let read = match tokio::time::timeout(READ_TIMEOUT, sock.read(&mut buf[filled..])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "request-line read timeout",
                ))
            }
        };
        filled += read;
        if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf[..filled].contains(&b'\n') {
            break;
        }
    }

    let path = parse_request_path(&buf[..filled]);
    let location = format!("https://{hostname}{path}");
    let body = b"Redirecting to HTTPS\n";
    let response = format!(
        "HTTP/1.1 301 Moved Permanently\r\n\
         Location: {location}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n",
        len = body.len()
    );
    sock.write_all(response.as_bytes()).await?;
    sock.write_all(body).await?;
    sock.shutdown().await?;
    Ok(())
}

fn parse_request_path(buf: &[u8]) -> String {
    // Malformed input falls back to "/" — this is a courtesy redirect,
    // not an HTTP server, so we trade conformance for safety.
    let line_end = buf
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(buf.len())
        .min(buf.len());
    let line = &buf[..line_end];
    let line = if line.ends_with(b"\r") {
        &line[..line.len() - 1]
    } else {
        line
    };
    let mut parts = line.split(|&b| b == b' ');
    let _method = parts.next();
    let target = parts.next().unwrap_or(b"/");
    // Non-printable bytes in the path would be reflected into the
    // Location header — that's header injection (CRLF, NUL). Reject.
    if !target.iter().all(|&b| (0x21..=0x7e).contains(&b)) {
        return "/".to_string();
    }
    // Printable-ASCII guard above makes from_utf8 infallible here.
    String::from_utf8(target.to_vec()).unwrap_or_else(|_| "/".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_path_extracts_target() {
        assert_eq!(
            parse_request_path(b"GET /foo/bar HTTP/1.1\r\nHost: x\r\n\r\n"),
            "/foo/bar"
        );
    }

    #[test]
    fn parse_request_path_handles_root() {
        assert_eq!(parse_request_path(b"GET / HTTP/1.1\r\n"), "/");
    }

    #[test]
    fn parse_request_path_handles_query() {
        assert_eq!(
            parse_request_path(b"GET /a?b=c&d=e HTTP/1.1\r\n"),
            "/a?b=c&d=e"
        );
    }

    #[test]
    fn parse_request_path_rejects_control_bytes() {
        assert_eq!(parse_request_path(b"GET /\x00\x01 HTTP/1.1\r\n"), "/");
    }

    #[test]
    fn parse_request_path_defaults_on_garbage() {
        assert_eq!(parse_request_path(b""), "/");
    }

    #[tokio::test]
    async fn end_to_end_redirect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(Notify::new());
        let handle = tokio::spawn(redirect_loop(
            listener,
            "example.test".to_string(),
            shutdown.clone(),
        ));

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: foo\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("301 Moved Permanently"), "got: {text}");
        assert!(
            text.contains("Location: https://example.test/healthz"),
            "got: {text}"
        );

        shutdown.notify_waiters();
        let _ = handle.await;
    }
}
