use brrtrouter::http::{fetch_get_full, fetch_post, HttpFetchOptions};

use crate::config::SesameIdamClientConfig;
use crate::login::LoginError;
use crate::types::TokenResponse;

/// Start SAML login — returns IdP redirect URL from Sesame's 302 `Location`.
///
/// # Errors
///
/// See [`LoginError`].
pub fn saml_login_start(
    config: &SesameIdamClientConfig,
    org_id: &str,
    redirect_uri: &str,
) -> Result<String, LoginError> {
    let org_id = org_id.trim();
    let redirect_uri = redirect_uri.trim();
    if org_id.is_empty() || redirect_uri.is_empty() {
        return Err(LoginError::Upstream {
            status: 400,
            body: r#"{"error":"org_id_and_redirect_uri_required"}"#.to_string(),
        });
    }

    let url = format!(
        "{}/auth/saml/login?org_id={}&redirect_uri={}",
        config.login_base(),
        urlencoding::encode(org_id),
        urlencoding::encode(redirect_uri),
    );
    let options = tenant_options(config);
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

/// Exchange SAML access code for Sesame tokens.
///
/// # Errors
///
/// See [`LoginError`].
pub fn saml_callback(
    config: &SesameIdamClientConfig,
    saml_access_code: &str,
    redirect_uri: &str,
) -> Result<TokenResponse, LoginError> {
    let url = format!("{}/auth/saml/callback", config.login_base());
    let body = serde_json::json!({
        "saml_access_code": saml_access_code,
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
