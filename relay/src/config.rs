use std::env;
use std::fmt;
use std::net::IpAddr;

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
    pub metrics_port: u16,
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
        let metrics_port = parse_port(&get, "METRICS_PORT", 9091)?;
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

        if role == Role::Exit && decodo_proxy_url.as_deref().unwrap_or("").is_empty() {
            return Err(ConfigError::ExitRequiresDecodoProxy);
        }

        Ok(Self {
            role,
            authority_pubkey_url,
            authority_heartbeat_url,
            relay_api_key,
            relay_port,
            metrics_port,
            replay_window_ttl,
            max_circuits,
            node_id,
            decodo_proxy_url,
            allowed_exit_ports,
            peer_allowlist,
        })
    }
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

fn required<F: Fn(&str) -> Option<String>>(get: &F, key: &'static str) -> Result<String, ConfigError> {
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
        m.insert("AUTHORITY_HEARTBEAT_URL", "https://authority.example/api/v1/relay/heartbeat");
        m.insert("RELAY_API_KEY", "key-xyz");
        m.insert("MAX_CIRCUITS", "256");
        m.insert("NODE_ID", "relay-001");
        m
    }

    fn lookup<'a>(m: &'a HashMap<&'static str, &'static str>) -> impl Fn(&str) -> Option<String> + 'a {
        move |k: &str| m.get(k).map(|v| (*v).to_string())
    }

    #[test]
    fn accepts_valid_guard_config() {
        let env = base_env();
        let cfg = RelayConfig::from_source(lookup(&env)).expect("valid config");
        assert_eq!(cfg.role, Role::Guard);
        assert_eq!(cfg.relay_port, 9001);
        assert_eq!(cfg.metrics_port, 9091);
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
        // DECODO_PROXY_URL not set
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
        assert_eq!(cfg.decodo_proxy_url.as_deref(), Some("socks5://user:pass@host:1080"));
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
    fn parses_custom_ports() {
        let mut env = base_env();
        env.insert("RELAY_PORT", "12345");
        env.insert("METRICS_PORT", "23456");
        let cfg = RelayConfig::from_source(lookup(&env)).expect("valid");
        assert_eq!(cfg.relay_port, 12345);
        assert_eq!(cfg.metrics_port, 23456);
    }

    #[test]
    fn rejects_garbage_port() {
        let mut env = base_env();
        env.insert("RELAY_PORT", "not-a-number");
        let err = RelayConfig::from_source(lookup(&env)).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid { var: "RELAY_PORT", .. }));
    }
}
