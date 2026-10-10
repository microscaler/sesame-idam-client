//! SAML sign-in through an organisation's identity provider (Sesame `DESIGN-saml-sp.md` §3–4).
//!
//! The relying party never handles SAML: Sesame starts the IdP login, receives the IdP's response at its own
//! assertion consumer service, and hands the relying party a one-time `saml_access_code` on its registered
//! `redirect_uri`, which [`saml_callback`] exchanges for tokens. As for social login, the tenant comes from the
//! registered `client_id`, never from an `X-Tenant-ID` header.
//!
//! Pre-contract until Sesame's identity-login OpenAPI publishes `saml_login`, `saml_callback` and
//! `saml_domain_discovery` (the pending test in `tests/contract_sync.rs` then becomes gating).

use brrtrouter::http::{fetch_get_full, fetch_post, HttpFetchOptions};

use crate::config::SesameIdamClientConfig;
use crate::login::LoginError;
use crate::types::TokenResponse;

/// URL of Sesame's SAML login start for an organisation (`GET /auth/saml/login`).
fn login_start_url(config: &SesameIdamClientConfig, org_id: &str, redirect_uri: &str) -> String {
    format!(
        "{}/auth/saml/login?org_id={}&client_id={}&redirect_uri={}",
        config.login_base(),
        urlencoding::encode(org_id),
        urlencoding::encode(&config.client_id),
        urlencoding::encode(redirect_uri),
    )
}

fn required(value: &str, error: &str) -> Result<String, LoginError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(LoginError::Upstream {
            status: 400,
            body: format!(r#"{{"error":"{error}"}}"#),
        });
    }
    Ok(value.to_string())
}

fn public_options(config: &SesameIdamClientConfig, json_body: bool) -> HttpFetchOptions {
    let mut extra_headers = Vec::new();
    if json_body {
        extra_headers.push(("Content-Type".to_string(), "application/json".to_string()));
    }
    HttpFetchOptions {
        timeout: config.timeout,
        extra_headers,
        ..HttpFetchOptions::default()
    }
}

/// Start SAML sign-in for an organisation: returns the IdP URL to send the browser to (Sesame's 302 `Location`).
/// `redirect_uri` must be registered for the configured `client_id`.
///
/// # Errors
///
/// See [`LoginError`]: a missing argument, a transport failure, or Sesame refusing (organisation without an
/// enabled connection, unregistered `redirect_uri`).
pub fn saml_login_start(
    config: &SesameIdamClientConfig,
    org_id: &str,
    redirect_uri: &str,
) -> Result<String, LoginError> {
    let org_id = required(org_id, "org_id_required")?;
    let redirect_uri = required(redirect_uri, "redirect_uri_required")?;
    let url = login_start_url(config, &org_id, &redirect_uri);
    let response = fetch_get_full(&url, &public_options(config, false))
        .map_err(|e| LoginError::Transport(e.to_string()))?;

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

/// Exchange the one-time `saml_access_code` Sesame put on `redirect_uri` for tokens. The code is bound to the
/// `client_id` and `redirect_uri` that started the sign-in, and is valid once, for 60 seconds.
///
/// # Errors
///
/// See [`LoginError`]: [`LoginError::Unauthorized`] for an unknown, used, expired or mismatched code.
pub fn saml_callback(
    config: &SesameIdamClientConfig,
    saml_access_code: &str,
    redirect_uri: &str,
) -> Result<TokenResponse, LoginError> {
    let saml_access_code = required(saml_access_code, "saml_access_code_required")?;
    let redirect_uri = required(redirect_uri, "redirect_uri_required")?;
    let url = format!("{}/auth/saml/callback", config.login_base());
    let body = serde_json::json!({
        "saml_access_code": saml_access_code,
        "client_id": config.client_id,
        "redirect_uri": redirect_uri,
    });
    let bytes = serde_json::to_vec(&body).map_err(|e| LoginError::Transport(e.to_string()))?;
    let (status, resp_bytes) = fetch_post(&url, &bytes, &public_options(config, true))
        .map_err(|e| LoginError::Transport(e.to_string()))?;
    let text = String::from_utf8(resp_bytes).unwrap_or_default();
    if status == 401 {
        return Err(LoginError::Unauthorized);
    }
    if !(200..300).contains(&status) {
        return Err(LoginError::Upstream { status, body: text });
    }
    serde_json::from_str(&text).map_err(|e| LoginError::Decode(format!("{e}; body={text}")))
}

/// Find the organisation whose verified domain an email address belongs to, if it signs in with SAML
/// ("Sign in with SSO"). `None` means use another sign-in method; Sesame answers the same way for a domain it does
/// not know, so this cannot be used to enumerate organisations.
///
/// # Errors
///
/// See [`LoginError`].
pub fn saml_domain_discovery(
    config: &SesameIdamClientConfig,
    email: &str,
) -> Result<Option<String>, LoginError> {
    let email = required(email, "email_required")?;
    let url = format!("{}/auth/saml/discover", config.login_base());
    let body = serde_json::json!({ "email": email, "client_id": config.client_id });
    let bytes = serde_json::to_vec(&body).map_err(|e| LoginError::Transport(e.to_string()))?;
    let (status, resp_bytes) = fetch_post(&url, &bytes, &public_options(config, true))
        .map_err(|e| LoginError::Transport(e.to_string()))?;
    let text = String::from_utf8(resp_bytes).unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(LoginError::Upstream { status, body: text });
    }
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| LoginError::Decode(format!("{e}; body={text}")))?;
    Ok(value
        .get("org_id")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> SesameIdamClientConfig {
        SesameIdamClientConfig::new(
            "https://api.example.com/idam/v1",
            "https://api.example.com/idam/v1",
            "https://api.example.com/idam/v1",
            "acme",
            "acme-web",
        )
        .expect("valid config")
    }

    #[test]
    fn login_start_names_org_client_and_redirect_encoded() {
        let url = login_start_url(
            &config(),
            "b2000002-0002-4000-8000-000000000002",
            "https://app.example.com/sso/callback?next=/a b",
        );
        assert_eq!(
            url,
            "https://api.example.com/idam/v1/auth/saml/login?org_id=b2000002-0002-4000-8000-000000000002\
             &client_id=acme-web&redirect_uri=https%3A%2F%2Fapp.example.com%2Fsso%2Fcallback%3Fnext%3D%2Fa%20b"
        );
    }

    #[test]
    fn missing_arguments_fail_before_any_request() {
        let cfg = config();
        assert!(matches!(
            saml_login_start(&cfg, " ", "https://app.example.com/cb"),
            Err(LoginError::Upstream { status: 400, .. })
        ));
        assert!(matches!(
            saml_callback(&cfg, "", "https://app.example.com/cb"),
            Err(LoginError::Upstream { status: 400, .. })
        ));
        assert!(matches!(
            saml_domain_discovery(&cfg, "  "),
            Err(LoginError::Upstream { status: 400, .. })
        ));
    }

    #[test]
    fn requests_carry_no_tenant_header() {
        let options = public_options(&config(), true);
        assert!(options
            .extra_headers
            .iter()
            .all(|(name, _)| !name.eq_ignore_ascii_case("x-tenant-id")));
    }
}
