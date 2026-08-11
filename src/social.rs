use brrtrouter::http::{fetch_get_full, fetch_post, HttpFetchOptions};

use crate::config::SesameIdamClientConfig;
use crate::login::LoginError;
use crate::types::TokenResponse;

/// Start OAuth — returns the provider authorize URL from Sesame's 302 `Location`.
///
/// # Errors
///
/// See [`LoginError`].
pub fn social_login_start(
    config: &SesameIdamClientConfig,
    provider: &str,
    redirect_uri: &str,
) -> Result<String, LoginError> {
    let provider = provider_segment(provider)?;
    let redirect_uri = redirect_uri.trim();
    if redirect_uri.is_empty() {
        return Err(LoginError::Upstream {
            status: 400,
            body: r#"{"error":"redirect_uri_required"}"#.to_string(),
        });
    }

    let url = format!(
        "{}/auth/social/{provider}/login?client_id={}&redirect_uri={}",
        config.login_base(),
        urlencoding::encode(&config.client_id),
        urlencoding::encode(redirect_uri),
    );
    // Public north–south: tenant comes from client_id; omit X-Tenant-ID.
    let options = HttpFetchOptions {
        timeout: config.timeout,
        ..HttpFetchOptions::default()
    };
    let response =
        fetch_get_full(&url, &options).map_err(|e| LoginError::Transport(e.to_string()))?;

    if (300..400).contains(&response.status) {
        return response.location.ok_or_else(|| LoginError::Upstream {
            status: response.status,
            body: "redirect missing Location header".to_string(),
        });
    }

    let text = String::from_utf8(response.body).unwrap_or_default();
    Err(LoginError::Upstream {
        status: response.status,
        body: text,
    })
}

/// Exchange OAuth authorization code for Sesame tokens.
///
/// # Errors
///
/// See [`LoginError`].
pub fn social_callback(
    config: &SesameIdamClientConfig,
    provider: &str,
    code: &str,
    state: &str,
    redirect_uri: &str,
) -> Result<TokenResponse, LoginError> {
    let provider = provider_segment(provider)?;
    let url = format!("{}/auth/social/{provider}/callback", config.login_base());
    let body = serde_json::json!({
        "code": code,
        "state": state,
        "redirect_uri": redirect_uri,
    });
    let bytes = serde_json::to_vec(&body).map_err(|e| LoginError::Transport(e.to_string()))?;
    let mut options = tenant_options(config);
    options
        .extra_headers
        .push(("Content-Type".to_string(), "application/json".to_string()));

    let (status, resp_bytes) =
        fetch_post(&url, &bytes, &options).map_err(|e| LoginError::Transport(e.to_string()))?;
    let text = String::from_utf8(resp_bytes).unwrap_or_default();
    if status == 401 {
        return Err(LoginError::Unauthorized);
    }
    if !(200..300).contains(&status) {
        return Err(LoginError::Upstream { status, body: text });
    }
    serde_json::from_str(&text).map_err(|e| LoginError::Decode(format!("{e}; body={text}")))
}

fn tenant_options(config: &SesameIdamClientConfig) -> HttpFetchOptions {
    HttpFetchOptions {
        timeout: config.timeout,
        extra_headers: vec![("X-Tenant-ID".to_string(), config.tenant_id.clone())],
        ..HttpFetchOptions::default()
    }
}

fn provider_segment(provider: &str) -> Result<String, LoginError> {
    let provider = provider.trim().to_ascii_lowercase();
    if provider.is_empty()
        || !provider
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(LoginError::Upstream {
            status: 400,
            body: r#"{"error":"invalid_provider"}"#.to_string(),
        });
    }
    Ok(provider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_provider() {
        let err = provider_segment(" ").unwrap_err();
        assert!(matches!(err, LoginError::Upstream { status: 400, .. }));
    }

    #[test]
    fn rejects_provider_path_injection() {
        let err = provider_segment("google/../../token").unwrap_err();
        assert!(matches!(err, LoginError::Upstream { status: 400, .. }));
    }

    #[test]
    fn accepts_provider_configured_by_sesame() {
        assert_eq!(provider_segment("GitHub").unwrap(), "github");
    }
}
