#![deny(warnings)]
#![forbid(unsafe_code)]

//! darkroute client SDK: login, blind-token issuance, circuit dialer.

mod auth;
mod blind;
mod circuits;
mod dial;
mod error;
mod tls;
mod tokens;

pub use auth::Session;
pub use circuits::{CircuitHop, CircuitRoute};
pub use dial::CircuitStream;
pub use error::ClientError;

use std::sync::Arc;

use reqwest::Client as HttpClient;
use rsa::RsaPublicKey;
use tokio_rustls::TlsConnector;
use url::Url;

pub struct DarkrouteConfig {
    pub authority_url: Url,
    pub email: String,
    pub password: String,
}

pub struct DarkrouteClient {
    cfg: DarkrouteConfig,
    http: HttpClient,
    tls: Arc<TlsConnector>,
    session: Option<Session>,
    pubkey: Option<RsaPublicKey>,
}

impl DarkrouteClient {
    pub fn new(cfg: DarkrouteConfig) -> Result<Self, ClientError> {
        let http = HttpClient::builder()
            .cookie_store(true)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(ClientError::HttpClientBuild)?;
        let tls = Arc::new(tls::outbound_connector()?);
        Ok(Self {
            cfg,
            http,
            tls,
            session: None,
            pubkey: None,
        })
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

    pub async fn get_circuit(&self) -> Result<CircuitRoute, ClientError> {
        let session = self.session.as_ref().ok_or(ClientError::NotLoggedIn)?;
        circuits::get(&self.http, &self.cfg.authority_url, session).await
    }

    pub async fn dial(
        &self,
        destination_host: &str,
        destination_port: u16,
        m_raw: &[u8; 32],
        token: &[u8],
        route: &CircuitRoute,
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
