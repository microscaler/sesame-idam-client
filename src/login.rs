use brrtrouter::http::{fetch_post, HttpFetchOptions};

use crate::config::SesameIdamClientConfig;
use crate::types::{LoginRequest, TokenResponse};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginError {
    Unauthorized,
    Upstream { status: u16, body: String },
    Transport(String),
    Decode(String),
}

/// Password login against sesame `POST /idam/v1/auth/login`.
///
/// # Errors
///
/// See [`LoginError`].
pub fn auth_login(
    config: &SesameIdamClientConfig,
    request: &LoginRequest,
) -> Result<TokenResponse, LoginError> {
    let body = login_body(config, request)?;
    let options = HttpFetchOptions {
        timeout: config.timeout,
        extra_headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Tenant-ID".to_string(), config.tenant_id.clone()),
        ],
        ..HttpFetchOptions::default()
    };

    let url = config.login_url();
    let (status, bytes) =
        fetch_post(&url, &body, &options).map_err(|e| LoginError::Transport(e.to_string()))?;

    let text = String::from_utf8(bytes).unwrap_or_default();
    if status == 401 {
        return Err(LoginError::Unauthorized);
    }
    if !(200..300).contains(&status) {
        return Err(LoginError::Upstream { status, body: text });
    }

    serde_json::from_str(&text).map_err(|e| LoginError::Decode(format!("{e}; body={text}")))
}

fn login_body(
    config: &SesameIdamClientConfig,
    request: &LoginRequest,
) -> Result<Vec<u8>, LoginError> {
    let mut body = serde_json::json!({
        "client_id": config.client_id,
        "email": request.email,
        "password": request.password,
    });
    if let Some(organization_id) = request.organization_id.as_ref() {
        body["organization_id"] = serde_json::Value::String(organization_id.clone());
    }
    serde_json::to_vec(&body)
    .map_err(|e| LoginError::Transport(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_posts_to_the_login_base_verbatim() {
        let cfg = SesameIdamClientConfig::new(
            "https://api.sesameidentity.dev.local/idam/v1",
            "https://org-mgmt.internal.example/idam/v1",
            "https://session.internal.example/idam/v1",
            "hauliage",
            "hauliage-web",
        )
        .expect("valid config");
        assert_eq!(
            cfg.login_url(),
            "https://api.sesameidentity.dev.local/idam/v1/auth/login"
        );
    }

    #[test]
    fn login_body_carries_registered_client_id() {
        let cfg = SesameIdamClientConfig::new(
            "https://api.sesameidentity.dev.local/idam/v1",
            "https://org-mgmt.internal.example/idam/v1",
            "https://session.internal.example/idam/v1",
            "hauliage",
            "hauliage-web",
        )
        .expect("valid config");
        let request = LoginRequest {
            email: "alice@example.com".to_string(),
            password: "password".to_string(),
            organization_id: None,
        };
        let body: serde_json::Value =
            serde_json::from_slice(&login_body(&cfg, &request).expect("body")).expect("json");
        assert_eq!(body["client_id"], "hauliage-web");
        assert!(body.get("organization_id").is_none());
    }
}

/// Refresh-token rotation against sesame identity-session-service
/// `POST {session_base}/session/refresh`.
///
/// The session service owns rotation; the login-service `/auth/token`
/// endpoint handles the OAuth grants only (authorization_code,
/// client_credentials, token-exchange) and answers **empty-200** for
/// `grant_type=refresh_token` — its `auth_token.rs` says so and it was
/// verified live (2026-09-03). Consumers that hand-rolled refresh against
/// `{login_base}/auth/token` were silently logging users out at
/// access-token expiry; this export replaces those.
///
/// Sesame also answers 200 with empty token fields for an unknown or
/// expired refresh token — mapped to [`LoginError::Unauthorized`].
///
/// # Errors
///
/// See [`LoginError`].
pub fn auth_refresh(
    config: &SesameIdamClientConfig,
    refresh_token: &str,
) -> Result<TokenResponse, LoginError> {
    let body = serde_json::to_vec(&serde_json::json!({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": config.client_id,
    }))
    .map_err(|e| LoginError::Transport(e.to_string()))?;
    let options = HttpFetchOptions {
        timeout: config.timeout,
        extra_headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Tenant-ID".to_string(), config.tenant_id.clone()),
        ],
        ..HttpFetchOptions::default()
    };
    let url = format!("{}/session/refresh", config.session_base());
    let (status, bytes) =
        fetch_post(&url, &body, &options).map_err(|e| LoginError::Transport(e.to_string()))?;
    let text = String::from_utf8(bytes).unwrap_or_default();
    if status == 401 {
        return Err(LoginError::Unauthorized);
    }
    if !(200..300).contains(&status) {
        return Err(LoginError::Upstream { status, body: text });
    }
    let tokens: TokenResponse =
        serde_json::from_str(&text).map_err(|e| LoginError::Decode(format!("{e}; body={text}")))?;
    if tokens.access_token.is_empty() {
        return Err(LoginError::Unauthorized);
    }
    Ok(tokens)
}
