use brrtrouter::http::{fetch_post, HttpFetchOptions};

use crate::config::SesameIdamClientConfig;
use crate::login::LoginError;
use crate::types::TokenResponse;

/// Re-issue JWT with `org_id` after org create or invite accept.
pub fn set_active_organization(
    config: &SesameIdamClientConfig,
    access_token: &str,
    organization_id: &str,
) -> Result<TokenResponse, LoginError> {
    let url = active_org_url(config);
    let body = serde_json::json!({ "organization_id": organization_id });
    let bytes = serde_json::to_vec(&body).map_err(|e| LoginError::Transport(e.to_string()))?;
    let options = HttpFetchOptions {
        timeout: config.timeout,
        extra_headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Tenant-ID".to_string(), config.tenant_id.clone()),
            (
                "Authorization".to_string(),
                format!("Bearer {access_token}"),
            ),
        ],
        ..HttpFetchOptions::default()
    };

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

/// `set_active_organization` is published by identity-login-service, so it uses
/// the login base — verbatim, never trimmed out of a full endpoint URL.
fn active_org_url(config: &SesameIdamClientConfig) -> String {
    format!("{}/sessions/active-organization", config.login_base())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_org_url_uses_the_login_base_verbatim() {
        let cfg = SesameIdamClientConfig::new(
            "https://api.sesameidentity.dev.local/idam/v1",
            "https://org-mgmt.internal.example/idam/v1",
            "https://session.internal.example/idam/v1",
            "hauliage",
        )
        .expect("valid config");
        assert_eq!(
            active_org_url(&cfg),
            "https://api.sesameidentity.dev.local/idam/v1/sessions/active-organization"
        );
    }
}
