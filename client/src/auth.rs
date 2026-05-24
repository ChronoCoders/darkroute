use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::ClientError;

pub struct Session {
    pub jwt: String,
}

#[derive(Serialize)]
struct LoginRequest<'a> {
    email: &'a str,
    password: &'a str,
}

#[derive(Deserialize)]
struct LoginResponse {
    token: String,
}

pub async fn login(
    http: &HttpClient,
    authority: &Url,
    email: &str,
    password: &str,
) -> Result<Session, ClientError> {
    let url = authority
        .join("/api/v1/auth/login")
        .map_err(|e| ClientError::InvalidResponse(format!("authority url join /login: {e}")))?;
    let resp = http
        .post(url)
        .json(&LoginRequest { email, password })
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(ClientError::AuthorityStatus(status.as_u16(), body));
    }
    let body: LoginResponse = resp.json().await?;
    if body.token.is_empty() {
        return Err(ClientError::MissingField("token"));
    }
    Ok(Session { jwt: body.token })
}
