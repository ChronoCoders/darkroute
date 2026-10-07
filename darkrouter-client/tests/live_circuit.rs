//! Live end-to-end integration test against a running deployment.
//!
//! Spawns the SOCKS5 daemon binary against the authority named by AUTHORITY_URL,
//! signs in with the account in CLIENT_EMAIL and CLIENT_PASSWORD, then performs
//! an HTTP GET to https://api.ipify.org through the SOCKS5 proxy and asserts the
//! returned public IP matches EXPECTED_EXIT_IP.
//!
//! Every one of those four values comes from the environment and none has a
//! default. A default authority would silently point the test at whatever host
//! was baked in here, and a baked-in exit IP goes stale the moment the upstream
//! provider rotates it or the exit relay changes supplier. See
//! client/.env.example.
//!
//! Gated `#[ignore]` so `cargo test` never runs it; only
//! `cargo test -p darkrouter-client -- --ignored` exercises this path.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

const SOCKS_BIND: &str = "127.0.0.1:11080";
const DAEMON_READY_LOG: &str = "socks5 listener bound";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

#[tokio::test]
#[ignore]
async fn live_circuit_returns_expected_exit_ip() {
    let email =
        std::env::var("CLIENT_EMAIL").expect("CLIENT_EMAIL must be set (see client/.env.example)");
    let password = std::env::var("CLIENT_PASSWORD")
        .expect("CLIENT_PASSWORD must be set (see client/.env.example)");
    let authority = std::env::var("AUTHORITY_URL")
        .expect("AUTHORITY_URL must be set (see client/.env.example); this test has no default");
    let expected_exit_ip = std::env::var("EXPECTED_EXIT_IP").expect(
        "EXPECTED_EXIT_IP must be set to the exit address this deployment is expected to leave from",
    );

    let bin = env!("CARGO_BIN_EXE_darkrouter-client");
    let mut child = Command::new(bin)
        .env("AUTHORITY_URL", authority)
        .env("CLIENT_EMAIL", email)
        .env("CLIENT_PASSWORD", password)
        .env("SOCKS5_BIND", SOCKS_BIND)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn darkrouter-client");

    // tracing_subscriber::fmt writes to stdout by default; the daemon's
    // ready marker comes through there.
    let stdout = child.stdout.take().expect("stdout captured");
    let mut lines = BufReader::new(stdout).lines();
    let ready = tokio::time::timeout(STARTUP_TIMEOUT, async {
        while let Ok(Some(line)) = lines.next_line().await {
            if line.contains(DAEMON_READY_LOG) {
                return true;
            }
        }
        false
    })
    .await
    .expect("daemon startup timed out");
    assert!(ready, "daemon never logged its ready marker");

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("socks5h://{SOCKS_BIND}")).expect("proxy url"))
        .timeout(REQUEST_TIMEOUT)
        .build()
        .expect("reqwest client");

    let resp = client
        .get("https://api.ipify.org")
        .send()
        .await
        .expect("ipify request via SOCKS5");
    assert!(
        resp.status().is_success(),
        "ipify status: {}",
        resp.status()
    );
    let body = resp.text().await.expect("ipify body");
    let observed = body.trim();

    let _ = child.kill().await;

    assert_eq!(
        observed, expected_exit_ip,
        "exit IP mismatch: got {observed:?}, expected {expected_exit_ip:?}. The exit relay \
         may have changed upstream, or EXPECTED_EXIT_IP may be stale."
    );
}
