use brrtrouter::http::{fetch_get, fetch_post, HttpFetchOptions};

use crate::config::SesameIdamClientConfig;
use crate::types::{RegisterRequest, SignupValidationResponse, TokenResponse};

pub use crate::login::LoginError;

fn auth_url(config: &SesameIdamClientConfig, path: &str) -> String {
    config
        .login_url
        .trim_end_matches('/')
        .strip_suffix("/auth/login")
        .map(|base| format!("{base}{path}"))
        .unwrap_or_else(|| format!("{}{path}", config.login_url.trim_end_matches('/')))
}

fn tenant_headers(config: &SesameIdamClientConfig) -> Vec<(String, String)> {
    vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("X-Tenant-ID".to_string(), config.tenant_id.clone()),
    ]
}

fn post_json(
    config: &SesameIdamClientConfig,
    url: &str,
    body: &[u8],
) -> Result<(u16, String), LoginError> {
    let options = HttpFetchOptions {
        timeout: config.timeout,
        extra_headers: tenant_headers(config),
        ..HttpFetchOptions::default()
    };
    let (status, bytes) =
        fetch_post(url, body, &options).map_err(|e| LoginError::Transport(e.to_string()))?;
    Ok((status, String::from_utf8(bytes).unwrap_or_default()))
}

/// Register against sesame `POST /idam/v1/auth/register`.
pub fn auth_register(
    config: &SesameIdamClientConfig,
    request: &RegisterRequest,
) -> Result<TokenResponse, LoginError> {
    let url = auth_url(config, "/auth/register");
    let body = serde_json::to_vec(request).map_err(|e| LoginError::Transport(e.to_string()))?;
    let (status, text) = post_json(config, &url, &body)?;

    if status == 400 || status == 409 {
        return Err(LoginError::Upstream { status, body: text });
    }
    if !(200..300).contains(&status) {
        return Err(LoginError::Upstream { status, body: text });
    }

    serde_json::from_str(&text).map_err(|e| LoginError::Decode(format!("{e}; body={text}")))
}

/// Check signup eligibility via sesame `GET /idam/v1/auth/signup/validate`.
pub fn signup_validate(
    config: &SesameIdamClientConfig,
    email: &str,
) -> Result<SignupValidationResponse, LoginError> {
    let base = auth_url(config, "/auth/signup/validate");
    let url = format!("{base}?email={}", urlencoding::encode(email));
    let options = HttpFetchOptions {
        timeout: config.timeout,
        extra_headers: tenant_headers(config),
        ..HttpFetchOptions::default()
    };
    let (status, bytes) =
        fetch_get(&url, &options).map_err(|e| LoginError::Transport(e.to_string()))?;
    let text = String::from_utf8(bytes).unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(LoginError::Upstream { status, body: text });
    }
    serde_json::from_str(&text).map_err(|e| LoginError::Decode(format!("{e}; body={text}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn register_url_derived_from_login_url() {
        let cfg = SesameIdamClientConfig {
            login_url: "http://identity-login-service:8080/idam/v1/auth/login".to_string(),
            org_mgmt_url: None,
            session_url: None,
            tenant_id: "hauliage".to_string(),
            timeout: Duration::from_secs(30),
        };
        assert_eq!(
            auth_url(&cfg, "/auth/register"),
            "http://identity-login-service:8080/idam/v1/auth/register"
        );
    }
}
