//! The BFF's back channel to Sesame: code exchange, refresh, revocation.
//!
//! Behind a trait so the flows in [`super`] are testable without a server.

use base64::Engine as _;
use brrtrouter::http::{fetch_post, HttpFetchOptions};
use serde::Deserialize;

use super::BffConfig;

/// Tokens from `POST /oauth/token`.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct OidcTokens {
    pub access_token: String,
    #[serde(default)]
    pub token_type: String,
    #[serde(default)]
    pub expires_in: u64,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

impl std::fmt::Debug for OidcTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcTokens")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("has_id_token", &self.id_token.is_some())
            .field("has_refresh_token", &self.refresh_token.is_some())
            .finish_non_exhaustive()
    }
}

/// A back-channel failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdpError {
    /// Sesame refused the grant (bad, expired, replayed or revoked): 400 or 401.
    Rejected { status: u16, error: Option<String> },
    /// Sesame answered something else, or could not be reached.
    Unavailable(String),
}

impl std::fmt::Display for IdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected { status, error } => {
                write!(f, "identity provider rejected the grant ({status}")?;
                if let Some(e) = error {
                    write!(f, ", {e}")?;
                }
                f.write_str(")")
            }
            Self::Unavailable(m) => write!(f, "identity provider unavailable: {m}"),
        }
    }
}

impl std::error::Error for IdpError {}

/// What a BFF needs from the identity provider.
pub trait IdentityProvider: Send + Sync {
    /// `grant_type=authorization_code` with the PKCE verifier.
    fn exchange_code(&self, code: &str, code_verifier: &str) -> Result<OidcTokens, IdpError>;
    /// `grant_type=refresh_token`. Sesame rotates: the answer carries a new
    /// refresh token and the old one is spent.
    fn refresh(&self, refresh_token: &str) -> Result<OidcTokens, IdpError>;
    /// Revoke the session's refresh family. Best effort: logout proceeds
    /// locally whatever this returns.
    fn revoke(&self, access_token: &str, refresh_token: Option<&str>) -> Result<(), IdpError>;
}

/// Sesame over HTTP: the token endpoint with `client_secret_basic`, and
/// `POST {login_base}/auth/logout` for revocation.
pub struct HttpIdentityProvider {
    token_url: String,
    revoke_url: String,
    redirect_uri: String,
    client_id: String,
    basic: String,
    tenant_id: String,
    timeout: std::time::Duration,
}

impl HttpIdentityProvider {
    #[must_use]
    pub fn new(config: &BffConfig) -> Self {
        // RFC 6749 §2.3.1: id and secret are form-urlencoded before Basic.
        let pair = format!(
            "{}:{}",
            urlencoding::encode(&config.client_id),
            urlencoding::encode(config.client_secret.expose())
        );
        Self {
            token_url: config.token_url.clone(),
            revoke_url: config.revoke_url.clone(),
            redirect_uri: config.redirect_uri.clone(),
            client_id: config.client_id.clone(),
            basic: base64::engine::general_purpose::STANDARD.encode(pair),
            tenant_id: config.tenant_id.clone(),
            timeout: config.http_timeout,
        }
    }

    fn token(&self, form: &[(&str, &str)]) -> Result<OidcTokens, IdpError> {
        let body = form
            .iter()
            .map(|(k, v)| format!("{k}={}", urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let options = HttpFetchOptions {
            timeout: self.timeout,
            extra_headers: vec![
                (
                    "Content-Type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                ),
                ("Accept".to_string(), "application/json".to_string()),
                ("Authorization".to_string(), format!("Basic {}", self.basic)),
            ],
            ..HttpFetchOptions::default()
        };
        let (status, bytes) = fetch_post(&self.token_url, body.as_bytes(), &options)
            .map_err(|e| IdpError::Unavailable(e.to_string()))?;
        token_answer(status, &bytes)
    }
}

/// Interpret the token endpoint's answer. Response bodies are never echoed
/// into errors on success paths: they carry tokens.
fn token_answer(status: u16, bytes: &[u8]) -> Result<OidcTokens, IdpError> {
    if status == 400 || status == 401 {
        let error = serde_json::from_slice::<serde_json::Value>(bytes)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string));
        return Err(IdpError::Rejected { status, error });
    }
    if !(200..300).contains(&status) {
        return Err(IdpError::Unavailable(format!(
            "token endpoint answered {status}"
        )));
    }
    let tokens: OidcTokens = serde_json::from_slice(bytes)
        .map_err(|e| IdpError::Unavailable(format!("unreadable token response: {e}")))?;
    if tokens.access_token.is_empty() {
        // Sesame has answered 200 with empty fields for a dead refresh token.
        return Err(IdpError::Rejected {
            status,
            error: None,
        });
    }
    Ok(tokens)
}

impl IdentityProvider for HttpIdentityProvider {
    fn exchange_code(&self, code: &str, code_verifier: &str) -> Result<OidcTokens, IdpError> {
        self.token(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.redirect_uri),
            ("code_verifier", code_verifier),
            ("client_id", &self.client_id),
        ])
    }

    fn refresh(&self, refresh_token: &str) -> Result<OidcTokens, IdpError> {
        self.token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &self.client_id),
        ])
    }

    fn revoke(&self, access_token: &str, refresh_token: Option<&str>) -> Result<(), IdpError> {
        let body = match refresh_token {
            Some(r) => serde_json::json!({ "refresh_token": r }),
            None => serde_json::json!({}),
        };
        let options = HttpFetchOptions {
            timeout: self.timeout,
            extra_headers: vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("X-Tenant-ID".to_string(), self.tenant_id.clone()),
                (
                    "Authorization".to_string(),
                    format!("Bearer {access_token}"),
                ),
            ],
            ..HttpFetchOptions::default()
        };
        let (status, _) = fetch_post(&self.revoke_url, body.to_string().as_bytes(), &options)
            .map_err(|e| IdpError::Unavailable(e.to_string()))?;
        match status {
            200..=299 => Ok(()),
            // An expired access token or an already-revoked family: nothing left to end.
            400 | 401 => Err(IdpError::Rejected {
                status,
                error: None,
            }),
            _ => Err(IdpError::Unavailable(format!("logout answered {status}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_grants_carry_the_oauth_error_only() {
        let err =
            token_answer(400, br#"{"error":"invalid_grant","error_description":"x"}"#).unwrap_err();
        assert_eq!(
            err,
            IdpError::Rejected {
                status: 400,
                error: Some("invalid_grant".into())
            }
        );
    }

    #[test]
    fn empty_access_token_is_a_rejection() {
        let err = token_answer(200, br#"{"access_token":"","token_type":"Bearer"}"#).unwrap_err();
        assert!(matches!(err, IdpError::Rejected { .. }));
    }

    #[test]
    fn server_errors_are_unavailable_and_do_not_echo_the_body() {
        let err = token_answer(502, b"secret-ish body").unwrap_err();
        assert_eq!(
            err,
            IdpError::Unavailable("token endpoint answered 502".into())
        );
    }

    #[test]
    fn token_debug_hides_tokens() {
        let t = token_answer(
            200,
            br#"{"access_token":"AT-SECRET","token_type":"Bearer","expires_in":300,"refresh_token":"RT-SECRET"}"#,
        )
        .unwrap();
        let shown = format!("{t:?}");
        assert!(!shown.contains("SECRET"), "{shown}");
    }
}
