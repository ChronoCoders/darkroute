#![deny(warnings)]
#![forbid(unsafe_code)]

//! QuietHop client SDK: login, blind-token issuance, circuit dialer.

mod auth;
mod blind;
mod dial;
mod error;
pub mod path;
mod tls;
mod tokens;

pub use auth::Session;
pub use dial::CircuitStream;
pub use error::ClientError;
pub use path::{NoPathReason, PathRules, SelectedPath};
pub use quiethop_crypto::registry;
pub use quiethop_crypto::registry::{Document, PinnedKey, RegistryError, RelayEntry, Verified};
pub use quiethop_crypto::registry_cache::RegistryCache;
pub use quiethop_crypto::state;
pub use quiethop_crypto::state::RegistryState;

use std::path::PathBuf;
use std::sync::Arc;

use reqwest::Client as HttpClient;
use rsa::RsaPublicKey;
use tokio_rustls::TlsConnector;
use url::Url;

pub struct QuietHopConfig {
    pub authority_url: Url,
    pub email: String,
    pub password: String,
    /// Ed25519 registry signing keys this client will accept, pinned out of
    /// band. The registry's integrity rests on these rather than on transport.
    pub pinned_registry_keys: Vec<PinnedKey>,
    /// How many pinned keys must sign. 1 today, raised when operators co-sign.
    pub registry_threshold: usize,
    /// Where the accepted registry version and bytes persist, for rollback
    /// protection across restarts.
    pub state_dir: PathBuf,
    /// Enforce distinct operators across a path. Client configuration only,
    /// never a registry field (docs/DECISIONS.md entry 5).
    pub require_operator_diversity: bool,
}

pub struct QuietHopClient {
    cfg: QuietHopConfig,
    http: HttpClient,
    tls: Arc<TlsConnector>,
    session: Option<Session>,
    pubkey: Option<RsaPublicKey>,
    registry: RegistryCache,
}

impl QuietHopClient {
    pub fn new(cfg: QuietHopConfig) -> Result<Self, ClientError> {
        let http = HttpClient::builder()
            .cookie_store(true)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(ClientError::HttpClientBuild)?;
        let tls = Arc::new(tls::outbound_connector()?);
        let registry_url = cfg
            .authority_url
            .join("/api/v1/registry")
            .map_err(|e| ClientError::InvalidResponse(format!("authority url join registry: {e}")))?
            .to_string();
        let registry = RegistryCache::new(
            registry_url,
            cfg.state_dir.clone(),
            cfg.pinned_registry_keys.clone(),
            cfg.registry_threshold,
        )?;
        Ok(Self {
            cfg,
            http,
            tls,
            session: None,
            pubkey: None,
            registry,
        })
    }

    /// Which path rules this client enforces.
    pub fn path_rules(&self) -> PathRules {
        PathRules {
            require_operator_diversity: self.cfg.require_operator_diversity,
        }
    }

    /// Fetch and verify the registry if none is held, reusing the stored copy
    /// while it is fresh. Call this at startup, not inside a circuit build.
    pub async fn prime_registry(&mut self, now_unix: i64) -> Result<(), ClientError> {
        self.registry.prime(now_unix).await?;
        Ok(())
    }

    /// Refresh the registry when its fresh window has passed.
    ///
    /// A failure is returned but is not fatal: the previously verified document
    /// stays usable until its own valid_until, after which [`Self::build_path`]
    /// refuses rather than building from an expired relay set.
    pub async fn refresh_registry(&mut self, now_unix: i64) -> Result<bool, ClientError> {
        Ok(self.registry.refresh_if_stale(now_unix).await?)
    }

    /// Choose a path from the verified registry.
    ///
    /// This performs no network request. The registry is fetched on its own
    /// schedule, because a fetch per circuit would tell the authority when this
    /// address builds circuits and give back the timing the removal of the route
    /// endpoint was meant to stop producing.
    pub fn build_path(&self, now_unix: i64) -> Result<SelectedPath, ClientError> {
        let verified = self.registry.usable(now_unix)?;
        path::select(&verified.document, self.path_rules(), now_unix)
    }

    pub async fn login(&mut self) -> Result<(), ClientError> {
        let session = auth::login(
            &self.http,
            &self.cfg.authority_url,
            &self.cfg.email,
            &self.cfg.password,
        )
        .await?;
        self.session = Some(session);
        Ok(())
    }

    pub async fn issue_token(&mut self) -> Result<([u8; 32], Vec<u8>), ClientError> {
        let session = self.session.as_ref().ok_or(ClientError::NotLoggedIn)?;
        if self.pubkey.is_none() {
            self.pubkey = Some(tokens::fetch_pubkey(&self.http, &self.cfg.authority_url).await?);
        }
        let pubkey = self.pubkey.as_ref().expect("just populated");
        tokens::issue(&self.http, &self.cfg.authority_url, session, pubkey).await
    }

    pub async fn dial(
        &self,
        destination_host: &str,
        destination_port: u16,
        m_raw: &[u8; 32],
        token: &[u8],
        route: &SelectedPath,
    ) -> Result<CircuitStream, ClientError> {
        dial::dial(
            &self.tls,
            route,
            m_raw,
            token,
            destination_host,
            destination_port,
        )
        .await
    }
}
