use reqwest::Client as HttpClient;
use serde::Deserialize;
use url::Url;

use crate::auth::Session;
use crate::error::ClientError;

#[derive(Debug, Clone, Deserialize)]
pub struct CircuitHop {
    pub id: String,
    /// `host:port` form, e.g. `node01.darkrouter.com:443`.
    pub endpoint: String,
    pub region: String,
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
    /// Split `host:port`. The port goes to TCP; the host is both SNI and resolution target.
    pub fn split(&self) -> Result<(String, u16), ClientError> {
        let (host, port_str) = self
            .endpoint
            .rsplit_once(':')
            .ok_or_else(|| ClientError::InvalidEndpoint(self.endpoint.clone(), "no port".into()))?;
        let port = port_str
            .parse::<u16>()
            .map_err(|e| ClientError::InvalidEndpoint(self.endpoint.clone(), e.to_string()))?;
        Ok((host.to_string(), port))
    }
}
