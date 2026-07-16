use std::time::Duration;

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
    let body = serde_json::to_vec(request).map_err(|e| LoginError::Transport(e.to_string()))?;
    let options = HttpFetchOptions {
        timeout: config.timeout,
        extra_headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Tenant-ID".to_string(), config.tenant_id.clone()),
        ],
        ..HttpFetchOptions::default()
    };

    let (status, bytes) = fetch_post(&config.login_url, &body, &options)
        .map_err(|e| LoginError::Transport(e.to_string()))?;

    let text = String::from_utf8(bytes).unwrap_or_default();
    if status == 401 {
        return Err(LoginError::Unauthorized);
    }
    if !(200..300).contains(&status) {
        return Err(LoginError::Upstream { status, body: text });
    }

    serde_json::from_str(&text).map_err(|e| LoginError::Decode(format!("{e}; body={text}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_timeout_allows_slow_bcrypt() {
        let cfg = SesameIdamClientConfig::default();
        assert!(cfg.timeout >= Duration::from_secs(30));
    }
}
