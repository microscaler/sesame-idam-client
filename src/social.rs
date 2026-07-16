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
    let provider = provider.trim().to_ascii_lowercase();
    if provider != "google" && provider != "microsoft" {
        return Err(LoginError::Upstream {
            status: 400,
            body: r#"{"error":"unsupported_provider"}"#.to_string(),
        });
    }
    let redirect_uri = redirect_uri.trim();
    if redirect_uri.is_empty() {
        return Err(LoginError::Upstream {
            status: 400,
            body: r#"{"error":"redirect_uri_required"}"#.to_string(),
        });
    }

    let url = format!(
        "{}/auth/social/{provider}/login?redirect_uri={}",
        config.login_base(),
        urlencoding::encode(redirect_uri),
    );
    let options = tenant_options(config);
    let response = fetch_get_full(&url, &options).map_err(|e| LoginError::Transport(e.to_string()))?;

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
    let provider = provider.trim().to_ascii_lowercase();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_provider() {
        let cfg = SesameIdamClientConfig::default();
        let err = social_login_start(&cfg, "github", "http://localhost/oauth/callback").unwrap_err();
        assert!(matches!(err, LoginError::Upstream { status: 400, .. }));
    }
}
