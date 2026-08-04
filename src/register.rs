use brrtrouter::http::{fetch_get, fetch_post, HttpFetchOptions};

use crate::config::SesameIdamClientConfig;
use crate::types::{RegisterRequest, SignupValidationResponse, TokenResponse};

pub use crate::login::LoginError;

fn auth_url(config: &SesameIdamClientConfig, path: &str) -> String {
    format!("{}{path}", config.login_base())
}

/// Pre-auth headers for public north–south: content-type only.
/// Tenant is bound by `client_id` in the body/query; do not send `X-Tenant-ID`
/// (public edges strip it and OpenAPI must not require it).
fn pre_auth_headers() -> Vec<(String, String)> {
    vec![("Content-Type".to_string(), "application/json".to_string())]
}

fn post_json(
    config: &SesameIdamClientConfig,
    url: &str,
    body: &[u8],
) -> Result<(u16, String), LoginError> {
    let options = HttpFetchOptions {
        timeout: config.timeout,
        extra_headers: pre_auth_headers(),
        ..HttpFetchOptions::default()
    };
    let (status, bytes) =
        fetch_post(url, body, &options).map_err(|e| LoginError::Transport(e.to_string()))?;
    Ok((status, String::from_utf8(bytes).unwrap_or_default()))
}

/// Register against sesame `POST /idam/v1/auth/register`.
///
/// Injects `client_id` from config so tenant resolution matches login.
pub fn auth_register(
    config: &SesameIdamClientConfig,
    request: &RegisterRequest,
) -> Result<TokenResponse, LoginError> {
    let url = auth_url(config, "/auth/register");
    let mut body = serde_json::to_value(request).map_err(|e| LoginError::Transport(e.to_string()))?;
    if let Some(obj) = body.as_object_mut() {
        obj.insert(
            "client_id".to_string(),
            serde_json::Value::String(config.client_id.clone()),
        );
    }
    let bytes = serde_json::to_vec(&body).map_err(|e| LoginError::Transport(e.to_string()))?;
    let (status, text) = post_json(config, &url, &bytes)?;

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
        extra_headers: pre_auth_headers(),
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

    #[test]
    fn auth_urls_use_the_login_base_verbatim() {
        let cfg = SesameIdamClientConfig::new(
            "https://api.sesameidentity.dev.local/idam/v1",
            "https://org-mgmt.internal.example/idam/v1",
            "https://session.internal.example/idam/v1",
            "hauliage",
            "hauliage-web",
        )
        .expect("valid config");
        assert_eq!(
            auth_url(&cfg, "/auth/register"),
            "https://api.sesameidentity.dev.local/idam/v1/auth/register"
        );
        assert_eq!(
            auth_url(&cfg, "/auth/signup/validate"),
            "https://api.sesameidentity.dev.local/idam/v1/auth/signup/validate"
        );
    }

    #[test]
    fn auth_register_injects_configured_client_id() {
        let cfg = SesameIdamClientConfig::new(
            "https://api.sesameidentity.dev.local/idam/v1",
            "https://org-mgmt.internal.example/idam/v1",
            "https://session.internal.example/idam/v1",
            "hauliage",
            "hauliage-web",
        )
        .expect("valid config");
        let request = RegisterRequest {
            client_id: String::new(),
            email: "alice@example.com".to_string(),
            password: "SecureP@ss123!".to_string(),
            first_name: Some("Alice".to_string()),
            last_name: Some("Example".to_string()),
            username: Some("alice".to_string()),
            phone: None,
        };
        let mut body =
            serde_json::to_value(&request).expect("serialize register request");
        if let Some(obj) = body.as_object_mut() {
            obj.insert(
                "client_id".to_string(),
                serde_json::Value::String(cfg.client_id.clone()),
            );
        }
        assert_eq!(body["client_id"], "hauliage-web");
        assert_eq!(body["email"], "alice@example.com");
    }
}
