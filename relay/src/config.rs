use std::env;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use quiethop_crypto::registry::PinnedKey;

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Guard,
    Middle,
    Exit,
}

impl Role {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        match s {
            "guard" => Ok(Role::Guard),
            "middle" => Ok(Role::Middle),
            "exit" => Ok(Role::Exit),
            other => Err(ConfigError::InvalidRole(other.to_string())),
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Guard => write!(f, "guard"),
            Role::Middle => write!(f, "middle"),
            Role::Exit => write!(f, "exit"),
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("environment variable {0} is required")]
    Missing(&'static str),
    #[error("environment variable {var} has invalid value: {reason}")]
    Invalid { var: &'static str, reason: String },
    #[error("RELAY_ROLE must be one of guard|middle|exit, got {0:?}")]
    InvalidRole(String),
    #[error("DECODO_PROXY_URL is required when RELAY_ROLE=exit")]
    ExitRequiresDecodoProxy,
}

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub role: Role,
    pub authority_pubkey_url: String,
    pub authority_heartbeat_url: String,
    pub relay_api_key: String,
    pub relay_port: u16,
    /// `host:port` the metrics HTTP server binds to. Defaults to
    /// `127.0.0.1:9091` so Prometheus scraping must happen over an SSH
    /// tunnel or local sidecar, because the metrics surface must not be
    /// reachable from the public internet (SESSION_LOG 2026-05-22
    /// deployment-surface hardening, §8.1).
    pub metrics_bind: SocketAddr,
    pub replay_window_ttl: u64,
    pub max_circuits: u32,
    /// Relay-wide ceiling on bytes held in per-circuit queues. A soft limit,
    /// checked only when a CREATE arrives (ARCHITECTURE 5.9).
    pub max_link_buffer_bytes: u64,
    pub node_id: String,
    /// Required when role == Exit.
    pub decodo_proxy_url: Option<String>,
    /// Required when role == Exit. Defaults to `[80, 443]` if unset.
    pub allowed_exit_ports: Vec<u16>,
    /// Fully-qualified DNS name this relay answers on. Used as the
    /// rustls-acme cert subject (one cert per relay), as the redirect
    /// target on the port-80 redirector, and as the expected SNI
    /// presented to clients. ARCHITECTURE §5.8.
    pub relay_hostname: String,
    /// ACME registration contact email (RFC 8555 §7.3). Let's Encrypt
    /// uses this for expiry warnings and policy notifications.
    pub acme_contact_email: String,
    /// Filesystem directory where rustls-acme persists account keys,
    /// issued certs, and challenge state across restarts.
    pub acme_dir: PathBuf,
    /// When true, ACME issuance uses the Let's Encrypt *staging*
    /// directory (rate limits are looser; certs are not browser-trusted).
    /// Defaults to false (production directory).
    pub acme_staging: bool,
    /// Path to the long-term X25519 static key, `private(32) || public(32)`,
    /// mode 0600. Written by the `keygen` subcommand and never generated at
    /// startup (ARCHITECTURE §5.2 step 3).
    pub static_key_path: PathBuf,
    /// Pinned Ed25519 registry signing public keys.
    ///
    /// The registry's integrity rests on these rather than on the transport, so
    /// a relay with none configured does not start (SECURITY_MODEL §10).
    pub registry_signing_pubkeys: Vec<PinnedKey>,
    /// Where the signed registry is fetched from.
    pub registry_url: String,
    /// Directory holding the highest registry version this relay has accepted
    /// and the bytes of that document, for rollback protection across restarts.
    pub registry_state_dir: PathBuf,
}

impl RelayConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_source(|k| env::var(k).ok())
    }

    /// Internal constructor used by tests with a custom env source.
    pub fn from_source<F>(get: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let role_raw = required(&get, "RELAY_ROLE")?;
        let role = Role::parse(&role_raw)?;
        let authority_pubkey_url = required(&get, "AUTHORITY_PUBKEY_URL")?;
        let authority_heartbeat_url = required(&get, "AUTHORITY_HEARTBEAT_URL")?;
        let relay_api_key = required(&get, "RELAY_API_KEY")?;
        let relay_port = parse_port(&get, "RELAY_PORT", 9001)?;
        let metrics_bind = parse_socket_addr(&get, "METRICS_BIND", "127.0.0.1:9091")?;
        let replay_window_ttl = parse_u64(&get, "REPLAY_WINDOW_TTL", 86_400)?;
        let max_circuits = parse_u32_required(&get, "MAX_CIRCUITS")?;
        let max_link_buffer_bytes = parse_u64_required(&get, "MAX_LINK_BUFFER_BYTES")?;
        let node_id = required(&get, "NODE_ID")?;

        let decodo_proxy_url = get("DECODO_PROXY_URL");
        let allowed_exit_ports = match get("ALLOWED_EXIT_PORTS") {
            None => vec![80, 443],
            Some(s) => parse_port_list(&s)?,
        };
        let relay_hostname = required(&get, "RELAY_HOSTNAME")?;
        let acme_contact_email = required(&get, "ACME_CONTACT_EMAIL")?;
        let acme_dir = match get("ACME_DIR") {
            Some(s) if !s.is_empty() => PathBuf::from(s),
            _ => PathBuf::from("/opt/quiethop/secrets/acme-cache"),
        };
        let acme_staging = parse_bool(&get, "ACME_STAGING", false)?;
        let static_key_path = match get("RELAY_STATIC_KEY_PATH") {
            Some(s) if !s.is_empty() => PathBuf::from(s),
            _ => PathBuf::from("/opt/quiethop/secrets/static.key"),
        };
        let registry_signing_pubkeys =
            parse_pinned_keys(&required(&get, "REGISTRY_SIGNING_PUBKEY")?)?;
        let registry_url = required(&get, "REGISTRY_URL")?;
        let registry_state_dir = match get("REGISTRY_STATE_DIR") {
            Some(s) if !s.is_empty() => PathBuf::from(s),
            _ => PathBuf::from("/opt/quiethop/state"),
        };

        if role == Role::Exit {
            let raw = decodo_proxy_url.as_deref().unwrap_or("");
            if raw.is_empty() {
                return Err(ConfigError::ExitRequiresDecodoProxy);
            }
            // Validate the URL is parseable and uses socks5 scheme with a
            // host:port, and anything else means the exit cannot dial and
            // must refuse to start. Phase 4c security requirement.
            let parsed = ::url::Url::parse(raw).map_err(|e| ConfigError::Invalid {
                var: "DECODO_PROXY_URL",
                reason: format!("not a valid URL: {e}"),
            })?;
            // socks5h = proxy-side DNS; required for exits so destination lookups don't leak locally.
            let scheme = parsed.scheme();
            if !scheme.eq_ignore_ascii_case("socks5") && !scheme.eq_ignore_ascii_case("socks5h") {
                return Err(ConfigError::Invalid {
                    var: "DECODO_PROXY_URL",
                    reason: format!("scheme must be socks5 or socks5h, got {scheme}"),
                });
            }
            if parsed.host_str().is_none_or(str::is_empty) {
                return Err(ConfigError::Invalid {
                    var: "DECODO_PROXY_URL",
                    reason: "missing host".to_string(),
                });
            }
            if parsed.port().is_none() {
                return Err(ConfigError::Invalid {
                    var: "DECODO_PROXY_URL",
                    reason: "missing port".to_string(),
                });
            }
        }

        Ok(Self {
            role,
            authority_pubkey_url,
            authority_heartbeat_url,
            relay_api_key,
            relay_port,
            metrics_bind,
            replay_window_ttl,
            max_circuits,
            max_link_buffer_bytes,
            node_id,
            decodo_proxy_url,
            allowed_exit_ports,
            relay_hostname,
            acme_contact_email,
            acme_dir,
            acme_staging,
            static_key_path,
            registry_signing_pubkeys,
            registry_url,
            registry_state_dir,
        })
    }
}

fn parse_bool<F: Fn(&str) -> Option<String>>(
    get: &F,
    key: &'static str,
    default: bool,
) -> Result<bool, ConfigError> {
    match get(key) {
        None => Ok(default),
        Some(s) if s.is_empty() => Ok(default),
        Some(s) => match s.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => Err(ConfigError::Invalid {
                var: key,
                reason: format!("expected boolean, got {other:?}"),
            }),
        },
    }
}

/// The pinned registry signing keys, as inline hex or as a path to a file of
/// hex, one key per line or comma separated.
///
/// Hex because `authority registry-keygen` prints hex, so the operator pins the
/// string the tool handed them. A value of exactly the hex length of a key is
/// read inline; anything else is treated as a path, so the two forms cannot be
/// confused for one another (ARCHITECTURE 5.8).
fn parse_pinned_keys(raw: &str) -> Result<Vec<PinnedKey>, ConfigError> {
    const HEX_LEN: usize = 64;
    let trimmed = raw.trim();
    let body = if trimmed.len() == HEX_LEN && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        trimmed.to_string()
    } else {
        std::fs::read_to_string(trimmed).map_err(|e| ConfigError::Invalid {
            var: "REGISTRY_SIGNING_PUBKEY",
            reason: format!(
                "{trimmed:?} is neither {HEX_LEN} hex characters nor a readable file: {e}"
            ),
        })?
    };
    let mut out = Vec::new();
    for piece in body.split([',', '\n']) {
        let t = piece.trim();
        if t.is_empty() {
            continue;
        }
        out.push(PinnedKey::from_hex(t).map_err(|e| ConfigError::Invalid {
            var: "REGISTRY_SIGNING_PUBKEY",
            reason: e.to_string(),
        })?);
    }
    if out.is_empty() {
        return Err(ConfigError::Invalid {
            var: "REGISTRY_SIGNING_PUBKEY",
            reason: "no key found in the value".to_string(),
        });
    }
    Ok(out)
}

fn required<F: Fn(&str) -> Option<String>>(
    get: &F,
    key: &'static str,
) -> Result<String, ConfigError> {
    match get(key) {
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(ConfigError::Missing(key)),
    }
}

fn parse_port<F: Fn(&str) -> Option<String>>(
    get: &F,
    key: &'static str,
    default: u16,
) -> Result<u16, ConfigError> {
    match get(key) {
        None => Ok(default),
        Some(s) if s.is_empty() => Ok(default),
        Some(s) => s.parse::<u16>().map_err(|e| ConfigError::Invalid {
            var: key,
            reason: e.to_string(),
        }),
    }
}

fn parse_u64<F: Fn(&str) -> Option<String>>(
    get: &F,
    key: &'static str,
    default: u64,
) -> Result<u64, ConfigError> {
    match get(key) {
        None => Ok(default),
        Some(s) if s.is_empty() => Ok(default),
        Some(s) => s.parse::<u64>().map_err(|e| ConfigError::Invalid {
            var: key,
            reason: e.to_string(),
        }),
    }
}

fn parse_u64_required<F: Fn(&str) -> Option<String>>(
    get: &F,
    key: &'static str,
) -> Result<u64, ConfigError> {
    let raw = required(get, key)?;
    raw.parse::<u64>().map_err(|e| ConfigError::Invalid {
        var: key,
        reason: e.to_string(),
    })
}

fn parse_u32_required<F: Fn(&str) -> Option<String>>(
    get: &F,
    key: &'static str,
) -> Result<u32, ConfigError> {
    let raw = required(get, key)?;
    raw.parse::<u32>().map_err(|e| ConfigError::Invalid {
        var: key,
        reason: e.to_string(),
    })
}

fn parse_socket_addr<F: Fn(&str) -> Option<String>>(
    get: &F,
    key: &'static str,
    default: &'static str,
) -> Result<SocketAddr, ConfigError> {
    let raw = match get(key) {
        Some(s) if !s.is_empty() => s,
        _ => default.to_string(),
    };
    raw.parse::<SocketAddr>().map_err(|e| ConfigError::Invalid {
        var: key,
        reason: format!("not a valid host:port: {e}"),
    })
}

fn parse_port_list(raw: &str) -> Result<Vec<u16>, ConfigError> {
    let mut out = Vec::new();
    for piece in raw.split(',') {
        let t = piece.trim();
        if t.is_empty() {
            continue;
        }
        out.push(t.parse::<u16>().map_err(|e| ConfigError::Invalid {
            var: "ALLOWED_EXIT_PORTS",
            reason: e.to_string(),
        })?);
    }
    if out.is_empty() {
        return Err(ConfigError::Invalid {
            var: "ALLOWED_EXIT_PORTS",
            reason: "no ports".to_string(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A valid Ed25519 public key, hex. This is the RFC 8032 section 7.1 TEST-1
    /// public key, which this repository already carries in
    /// testdata/ed25519_rfc8032.json. A published vector, never a secret, and a
    /// real curve point, which matters because PinnedKey rejects anything that
    /// is not one: 32 bytes of 0xAB, for instance, is not a valid key.
    const TEST_REGISTRY_PUBKEY: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn base_env() -> HashMap<&'static str, &'static str> {
        let mut m = HashMap::new();
        m.insert("RELAY_ROLE", "guard");
        m.insert("AUTHORITY_PUBKEY_URL", "https://authority.example/pubkey");
        m.insert(
            "AUTHORITY_HEARTBEAT_URL",
            "https://authority.example/api/v1/relay/heartbeat",
        );
        m.insert("RELAY_API_KEY", "key-xyz");
        m.insert("MAX_CIRCUITS", "256");
        m.insert("MAX_LINK_BUFFER_BYTES", "268435456");
        m.insert("NODE_ID", "relay-001");
        m.insert("RELAY_HOSTNAME", "node01.example");
        m.insert("ACME_CONTACT_EMAIL", "ops@example.com");
        // A well formed but meaningless key. Ed25519 verifying keys are checked
        // for validity on construction, so this must be a real point.
        m.insert("REGISTRY_SIGNING_PUBKEY", TEST_REGISTRY_PUBKEY);
        m.insert("REGISTRY_URL", "https://authority.example/api/v1/registry");
        m
    }

    fn lookup<'a>(
        m: &'a HashMap<&'static str, &'static str>,
    ) -> impl Fn(&str) -> Option<String> + 'a {
        move |k: &str| m.get(k).map(|v| (*v).to_string())
    }

    #[test]
    fn accepts_valid_guard_config() {
        let env = base_env();
        let cfg = RelayConfig::from_source(lookup(&env)).expect("valid config");
        assert_eq!(cfg.role, Role::Guard);
        assert_eq!(cfg.relay_port, 9001);
        assert_eq!(
            cfg.metrics_bind,
            "127.0.0.1:9091".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(cfg.replay_window_ttl, 86_400);
        assert_eq!(cfg.allowed_exit_ports, vec![80, 443]);
        assert!(cfg.decodo_proxy_url.is_none());
    }

    #[test]
    fn rejects_missing_role() {
        let mut env = base_env();
        env.remove("RELAY_ROLE");
        let err = RelayConfig::from_source(lookup(&env)).unwrap_err();
        assert!(matches!(err, ConfigError::Missing("RELAY_ROLE")));
    }

    #[test]
    fn rejects_invalid_role() {
        let mut env = base_env();
        env.insert("RELAY_ROLE", "admin");
        let err = RelayConfig::from_source(lookup(&env)).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRole(_)));
    }

    #[test]
    fn exit_role_requires_decodo_proxy_url() {
        let mut env = base_env();
        env.insert("RELAY_ROLE", "exit");
        let err = RelayConfig::from_source(lookup(&env)).unwrap_err();
        assert!(matches!(err, ConfigError::ExitRequiresDecodoProxy));
    }

    #[test]
    fn exit_role_accepts_with_decodo_proxy_url() {
        let mut env = base_env();
        env.insert("RELAY_ROLE", "exit");
        env.insert("DECODO_PROXY_URL", "socks5://user:pass@host:1080");
        let cfg = RelayConfig::from_source(lookup(&env)).expect("valid exit config");
        assert_eq!(cfg.role, Role::Exit);
        assert_eq!(
            cfg.decodo_proxy_url.as_deref(),
            Some("socks5://user:pass@host:1080")
        );
    }

    #[test]
    fn exit_role_rejects_garbage_decodo_url() {
        let mut env = base_env();
        env.insert("RELAY_ROLE", "exit");
        env.insert("DECODO_PROXY_URL", "not a url at all");
        let err = RelayConfig::from_source(lookup(&env)).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                var: "DECODO_PROXY_URL",
                ..
            }
        ));
    }

    #[test]
    fn exit_role_accepts_socks5h_scheme() {
        let mut env = base_env();
        env.insert("RELAY_ROLE", "exit");
        env.insert("DECODO_PROXY_URL", "socks5h://user:pass@proxy:1080");
        let cfg = RelayConfig::from_source(lookup(&env)).expect("socks5h must validate");
        assert_eq!(cfg.role, Role::Exit);
    }

    #[test]
    fn exit_role_rejects_wrong_scheme() {
        let mut env = base_env();
        env.insert("RELAY_ROLE", "exit");
        env.insert("DECODO_PROXY_URL", "http://user:pass@host:1080");
        let err = RelayConfig::from_source(lookup(&env)).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                var: "DECODO_PROXY_URL",
                ..
            }
        ));
    }

    #[test]
    fn exit_role_rejects_missing_port() {
        let mut env = base_env();
        env.insert("RELAY_ROLE", "exit");
        env.insert("DECODO_PROXY_URL", "socks5://user:pass@host");
        let err = RelayConfig::from_source(lookup(&env)).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                var: "DECODO_PROXY_URL",
                ..
            }
        ));
    }

    #[test]
    fn rejects_missing_authority_pubkey_url() {
        let mut env = base_env();
        env.remove("AUTHORITY_PUBKEY_URL");
        let err = RelayConfig::from_source(lookup(&env)).unwrap_err();
        assert!(matches!(err, ConfigError::Missing("AUTHORITY_PUBKEY_URL")));
    }

    #[test]
    fn rejects_missing_relay_api_key() {
        let mut env = base_env();
        env.remove("RELAY_API_KEY");
        let err = RelayConfig::from_source(lookup(&env)).unwrap_err();
        assert!(matches!(err, ConfigError::Missing("RELAY_API_KEY")));
    }

    #[test]
    fn rejects_missing_node_id() {
        let mut env = base_env();
        env.remove("NODE_ID");
        let err = RelayConfig::from_source(lookup(&env)).unwrap_err();
        assert!(matches!(err, ConfigError::Missing("NODE_ID")));
    }

    #[test]
    fn rejects_missing_max_circuits() {
        let mut env = base_env();
        env.remove("MAX_CIRCUITS");
        let err = RelayConfig::from_source(lookup(&env)).unwrap_err();
        assert!(matches!(err, ConfigError::Missing("MAX_CIRCUITS")));
    }

    #[test]
    fn parses_custom_relay_port_and_metrics_bind() {
        let mut env = base_env();
        env.insert("RELAY_PORT", "12345");
        env.insert("METRICS_BIND", "10.0.0.5:23456");
        let cfg = RelayConfig::from_source(lookup(&env)).expect("valid");
        assert_eq!(cfg.relay_port, 12345);
        assert_eq!(
            cfg.metrics_bind,
            "10.0.0.5:23456".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn rejects_garbage_metrics_bind() {
        let mut env = base_env();
        env.insert("METRICS_BIND", "not-a-socket-addr");
        let err = RelayConfig::from_source(lookup(&env)).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                var: "METRICS_BIND",
                ..
            }
        ));
    }

    #[test]
    fn rejects_missing_relay_hostname() {
        let mut env = base_env();
        env.remove("RELAY_HOSTNAME");
        let err = RelayConfig::from_source(lookup(&env)).unwrap_err();
        assert!(matches!(err, ConfigError::Missing("RELAY_HOSTNAME")));
    }

    #[test]
    fn rejects_missing_acme_contact_email() {
        let mut env = base_env();
        env.remove("ACME_CONTACT_EMAIL");
        let err = RelayConfig::from_source(lookup(&env)).unwrap_err();
        assert!(matches!(err, ConfigError::Missing("ACME_CONTACT_EMAIL")));
    }

    #[test]
    fn acme_dir_default_when_unset() {
        let env = base_env();
        let cfg = RelayConfig::from_source(lookup(&env)).expect("valid");
        assert_eq!(
            cfg.acme_dir,
            std::path::PathBuf::from("/opt/quiethop/secrets/acme-cache")
        );
    }

    #[test]
    fn acme_staging_parses_truthy() {
        let mut env = base_env();
        env.insert("ACME_STAGING", "true");
        let cfg = RelayConfig::from_source(lookup(&env)).expect("valid");
        assert!(cfg.acme_staging);
    }

    #[test]
    fn acme_staging_rejects_garbage() {
        let mut env = base_env();
        env.insert("ACME_STAGING", "maybe");
        let err = RelayConfig::from_source(lookup(&env)).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                var: "ACME_STAGING",
                ..
            }
        ));
    }

    #[test]
    fn registry_pubkey_is_read_inline_as_hex() {
        let env = base_env();
        let cfg = RelayConfig::from_source(lookup(&env)).expect("valid");
        assert_eq!(cfg.registry_signing_pubkeys.len(), 1);
    }

    #[test]
    fn registry_pubkey_is_read_from_a_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.pub");
        std::fs::write(&path, format!("{TEST_REGISTRY_PUBKEY}\n")).unwrap();
        let mut env = base_env();
        // Leaked because the fixture map holds &'static str. A test process that
        // ends immediately after is the whole lifetime that matters.
        let p: &'static str = Box::leak(path.to_string_lossy().into_owned().into_boxed_str());
        env.insert("REGISTRY_SIGNING_PUBKEY", p);
        let cfg = RelayConfig::from_source(lookup(&env)).expect("valid");
        assert_eq!(cfg.registry_signing_pubkeys.len(), 1);
    }

    #[test]
    fn registry_pubkey_rejects_garbage_and_a_missing_file() {
        // 62 hex characters, two short of a key, so neither the inline form nor
        // the path form can accept it.
        const SHORT: &str = "ababababababababababababababababababababababababababababababab";
        for bad in ["zz", "/nonexistent/registry.pub", SHORT] {
            let mut env = base_env();
            env.insert("REGISTRY_SIGNING_PUBKEY", bad);
            let err = RelayConfig::from_source(lookup(&env)).unwrap_err();
            assert!(
                matches!(
                    err,
                    ConfigError::Invalid {
                        var: "REGISTRY_SIGNING_PUBKEY",
                        ..
                    }
                ),
                "{bad:?} was accepted"
            );
        }
    }

    #[test]
    fn registry_url_and_pubkey_are_required() {
        for var in ["REGISTRY_SIGNING_PUBKEY", "REGISTRY_URL"] {
            let mut env = base_env();
            env.remove(var);
            assert!(
                RelayConfig::from_source(lookup(&env)).is_err(),
                "{var} was not required"
            );
        }
    }

    #[test]
    fn metrics_bind_empty_falls_back_to_default() {
        let mut env = base_env();
        env.insert("METRICS_BIND", "");
        let cfg = RelayConfig::from_source(lookup(&env)).expect("valid");
        assert_eq!(
            cfg.metrics_bind,
            "127.0.0.1:9091".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn rejects_garbage_port() {
        let mut env = base_env();
        env.insert("RELAY_PORT", "not-a-number");
        let err = RelayConfig::from_source(lookup(&env)).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                var: "RELAY_PORT",
                ..
            }
        ));
    }
}
