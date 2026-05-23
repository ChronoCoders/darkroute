use std::collections::HashMap;
use std::env;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

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
    /// tunnel or local sidecar — the metrics surface must not be
    /// reachable from the public internet (SESSION_LOG 2026-05-22
    /// deployment-surface hardening, §8.1).
    pub metrics_bind: SocketAddr,
    pub replay_window_ttl: u64,
    pub max_circuits: u32,
    pub node_id: String,
    /// Required when role == Exit.
    pub decodo_proxy_url: Option<String>,
    /// Required when role == Exit. Defaults to `[80, 443]` if unset.
    pub allowed_exit_ports: Vec<u16>,
    /// IPs allowed to initiate relay-to-relay (protocol byte 0x02)
    /// connections to this relay. Consulted only by middle and exit
    /// roles, where inbound peer relays bypass the client token check.
    /// Empty list = no peer relay is accepted (guard runs this way).
    pub peer_allowlist: Vec<IpAddr>,
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
    /// Map from next-hop relay socket address to the hostname the
    /// outbound TLS client must present as SNI and verify against the
    /// peer's certificate. Required because the EXTEND wire payload
    /// carries only a SocketAddr but TLS verification requires a
    /// hostname. Empty for `guard` (guard never extends outward via
    /// another relay-to-relay link in the current topology) but
    /// validated for `middle`.
    pub peer_hostnames: HashMap<SocketAddr, String>,
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
        let node_id = required(&get, "NODE_ID")?;

        let decodo_proxy_url = get("DECODO_PROXY_URL");
        let allowed_exit_ports = match get("ALLOWED_EXIT_PORTS") {
            None => vec![80, 443],
            Some(s) => parse_port_list(&s)?,
        };
        let peer_allowlist = match get("RELAY_PEER_ALLOWLIST") {
            None => Vec::new(),
            Some(s) => parse_ip_list(&s)?,
        };
        let relay_hostname = required(&get, "RELAY_HOSTNAME")?;
        let acme_contact_email = required(&get, "ACME_CONTACT_EMAIL")?;
        let acme_dir = match get("ACME_DIR") {
            Some(s) if !s.is_empty() => PathBuf::from(s),
            _ => PathBuf::from("/opt/darkroute/secrets/acme-cache"),
        };
        let acme_staging = parse_bool(&get, "ACME_STAGING", false)?;
        let peer_hostnames = match get("PEER_HOSTNAMES") {
            None => HashMap::new(),
            Some(s) => parse_peer_hostnames(&s)?,
        };

        if role == Role::Exit {
            let raw = decodo_proxy_url.as_deref().unwrap_or("");
            if raw.is_empty() {
                return Err(ConfigError::ExitRequiresDecodoProxy);
            }
            // Validate the URL is parseable and uses socks5 scheme with a
            // host:port — anything else means the exit cannot dial and
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
            node_id,
            decodo_proxy_url,
            allowed_exit_ports,
            peer_allowlist,
            relay_hostname,
            acme_contact_email,
            acme_dir,
            acme_staging,
            peer_hostnames,
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

fn parse_peer_hostnames(raw: &str) -> Result<HashMap<SocketAddr, String>, ConfigError> {
    let mut out = HashMap::new();
    for piece in raw.split(',') {
        let t = piece.trim();
        if t.is_empty() {
            continue;
        }
        let (addr_str, host_str) = t.split_once('=').ok_or(ConfigError::Invalid {
            var: "PEER_HOSTNAMES",
            reason: format!("entry {t:?} missing '='"),
        })?;
        let addr = addr_str
            .parse::<SocketAddr>()
            .map_err(|e| ConfigError::Invalid {
                var: "PEER_HOSTNAMES",
                reason: format!("{addr_str:?} is not host:port: {e}"),
            })?;
        let host = host_str.trim();
        if host.is_empty() {
            return Err(ConfigError::Invalid {
                var: "PEER_HOSTNAMES",
                reason: format!("entry {t:?} has empty hostname"),
            });
        }
        out.insert(addr, host.to_string());
    }
    Ok(out)
}

fn parse_ip_list(raw: &str) -> Result<Vec<IpAddr>, ConfigError> {
    let mut out = Vec::new();
    for piece in raw.split(',') {
        let t = piece.trim();
        if t.is_empty() {
            continue;
        }
        out.push(t.parse::<IpAddr>().map_err(|e| ConfigError::Invalid {
            var: "RELAY_PEER_ALLOWLIST",
            reason: e.to_string(),
        })?);
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
        m.insert("NODE_ID", "relay-001");
        m.insert("RELAY_HOSTNAME", "node01.example");
        m.insert("ACME_CONTACT_EMAIL", "ops@example.com");
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
            std::path::PathBuf::from("/opt/darkroute/secrets/acme-cache")
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
    fn peer_hostnames_parses_pairs() {
        let mut env = base_env();
        env.insert(
            "PEER_HOSTNAMES",
            "10.0.0.5:443=node02.example, 10.0.0.6:443=node03.example",
        );
        let cfg = RelayConfig::from_source(lookup(&env)).expect("valid");
        assert_eq!(cfg.peer_hostnames.len(), 2);
        assert_eq!(
            cfg.peer_hostnames
                .get(&"10.0.0.5:443".parse::<SocketAddr>().unwrap())
                .map(String::as_str),
            Some("node02.example")
        );
    }

    #[test]
    fn peer_hostnames_rejects_missing_equals() {
        let mut env = base_env();
        env.insert("PEER_HOSTNAMES", "10.0.0.5:443");
        let err = RelayConfig::from_source(lookup(&env)).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                var: "PEER_HOSTNAMES",
                ..
            }
        ));
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
