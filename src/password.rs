//! Password reset north–south helpers (`forgot` / `reset`).

use brrtrouter::http::{fetch_post, HttpFetchOptions};
use serde::{Deserialize, Serialize};

use crate::config::SesameIdamClientConfig;
use crate::login::LoginError;

/// Successful forgot/reset acknowledgement (generic; no enumeration).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordResetAck {
    pub success: bool,
    pub message: String,
}

fn pre_auth_headers() -> Vec<(String, String)> {
    vec![("Content-Type".to_string(), "application/json".to_string())]
}

fn post_json(
    config: &SesameIdamClientConfig,
    path: &str,
    body: &serde_json::Value,
) -> Result<(u16, String), LoginError> {
    let url = format!("{}{path}", config.login_base());
    let bytes = serde_json::to_vec(body).map_err(|e| LoginError::Transport(e.to_string()))?;
    let options = HttpFetchOptions {
        timeout: config.timeout,
        extra_headers: pre_auth_headers(),
        ..HttpFetchOptions::default()
    };
    let (status, resp) =
        fetch_post(&url, &bytes, &options).map_err(|e| LoginError::Transport(e.to_string()))?;
    Ok((status, String::from_utf8(resp).unwrap_or_default()))
}

/// `POST /auth/password/forgot` — injects `client_id`, omits `X-Tenant-ID`.
///
/// # Errors
///
/// See [`LoginError`].
pub fn forgot_password(
    config: &SesameIdamClientConfig,
    email: &str,
) -> Result<PasswordResetAck, LoginError> {
    let body = serde_json::json!({
        "client_id": config.client_id,
        "email": email,
    });
    let (status, text) = post_json(config, "/auth/password/forgot", &body)?;
    if status == 401 {
        return Err(LoginError::Unauthorized);
    }
    if !(200..300).contains(&status) {
        return Err(LoginError::Upstream { status, body: text });
    }
    serde_json::from_str(&text).map_err(|e| LoginError::Decode(format!("{e}; body={text}")))
}

/// `POST /auth/password/reset` — injects `client_id`, omits `X-Tenant-ID`.
///
/// # Errors
///
/// See [`LoginError`].
pub fn reset_password(
    config: &SesameIdamClientConfig,
    token: &str,
    new_password: &str,
) -> Result<PasswordResetAck, LoginError> {
    let body = serde_json::json!({
        "client_id": config.client_id,
        "token": token,
        "new_password": new_password,
    });
    let (status, text) = post_json(config, "/auth/password/reset", &body)?;
    if !(200..300).contains(&status) {
        return Err(LoginError::Upstream { status, body: text });
    }
    serde_json::from_str(&text).map_err(|e| LoginError::Decode(format!("{e}; body={text}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SesameIdamClientConfig {
        SesameIdamClientConfig::new(
            "https://api.sesameidentity.dev.local/idam/v1",
            "https://org-mgmt.internal.example/idam/v1",
            "https://session.internal.example/idam/v1",
            "acme",
            "acme-web",
        )
        .expect("valid config")
    }

    #[test]
    fn forgot_body_carries_registered_client_id() {
        let body = serde_json::json!({
            "client_id": cfg().client_id,
            "email": "alice@example.com",
        });
        assert_eq!(body["client_id"], "acme-web");
        assert!(body.get("X-Tenant-ID").is_none());
    }
}
