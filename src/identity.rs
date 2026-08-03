use brrtrouter::http::{fetch_get, fetch_patch, HttpFetchOptions};

use crate::config::SesameIdamClientConfig;
use crate::org::OrgClientError;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SesameUserProfile {
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub phone_verified: Option<bool>,
    #[serde(default)]
    pub role: Option<String>,
}

/// GET /idam/v1/identity/me on identity-session-service.
pub fn fetch_current_user(
    config: &SesameIdamClientConfig,
    access_token: &str,
) -> Result<SesameUserProfile, OrgClientError> {
    let url = identity_url(config, "/identity/me");
    get_json(config, &url, access_token)
}

/// PATCH /idam/v1/identity/me on identity-session-service.
pub fn patch_current_user(
    config: &SesameIdamClientConfig,
    access_token: &str,
    first_name: Option<&str>,
    last_name: Option<&str>,
    avatar_url: Option<&str>,
) -> Result<SesameUserProfile, OrgClientError> {
    let url = identity_url(config, "/identity/me");
    let mut body = serde_json::Map::new();
    if let Some(v) = first_name {
        body.insert(
            "first_name".into(),
            serde_json::Value::String(v.to_string()),
        );
    }
    if let Some(v) = last_name {
        body.insert("last_name".into(), serde_json::Value::String(v.to_string()));
    }
    if let Some(v) = avatar_url {
        body.insert(
            "avatar_url".into(),
            serde_json::Value::String(v.to_string()),
        );
    }
    let bytes = serde_json::to_vec(&serde_json::Value::Object(body))
        .map_err(|e| OrgClientError::Transport(e.to_string()))?;
    let options = auth_options(config, access_token);
    let (status, resp_bytes) = fetch_patch(&url, &bytes, &options)
        .map_err(|e| OrgClientError::Transport(e.to_string()))?;
    let text = String::from_utf8(resp_bytes).unwrap_or_default();
    if status == 401 {
        return Err(OrgClientError::Unauthorized);
    }
    if !(200..300).contains(&status) {
        return Err(OrgClientError::Upstream { status, body: text });
    }
    serde_json::from_str(&text).map_err(|e| OrgClientError::Decode(format!("{e}; body={text}")))
}

/// identity-session-service endpoint from the configured session base, verbatim.
///
/// WHY no derivation: this used to synthesise the session host out of the login
/// base (`identity-login-service`→`identity-session-service`, dev `:8101`→
/// `:8102`). The replacement silently became a no-op once the login host was a
/// real hostname rather than the cluster service name, and `/identity/me` was
/// then requested from the login host instead of failing. The base is now a
/// required, independent config key — see [`crate::SESSION_BASE_URL_KEY`].
fn identity_url(config: &SesameIdamClientConfig, path: &str) -> String {
    format!("{}{path}", config.session_base())
}

fn get_json<T: serde::de::DeserializeOwned>(
    config: &SesameIdamClientConfig,
    url: &str,
    access_token: &str,
) -> Result<T, OrgClientError> {
    let options = auth_options(config, access_token);
    let (status, resp_bytes) =
        fetch_get(url, &options).map_err(|e| OrgClientError::Transport(e.to_string()))?;
    let text = String::from_utf8(resp_bytes).unwrap_or_default();
    if status == 401 {
        return Err(OrgClientError::Unauthorized);
    }
    if !(200..300).contains(&status) {
        return Err(OrgClientError::Upstream { status, body: text });
    }
    serde_json::from_str(&text).map_err(|e| OrgClientError::Decode(format!("{e}; body={text}")))
}

/// Bearer identity calls bind tenant from the JWT. Do not send `X-Tenant-ID`.
fn auth_options(config: &SesameIdamClientConfig, access_token: &str) -> HttpFetchOptions {
    HttpFetchOptions {
        timeout: config.timeout,
        extra_headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            (
                "Authorization".to_string(),
                format!("Bearer {access_token}"),
            ),
        ],
        ..HttpFetchOptions::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOGIN: &str = "https://api.sesameidentity.dev.local/idam/v1";
    const ORG: &str = "https://org-mgmt.internal.example/idam/v1";
    const SESSION: &str = "https://session.internal.example/idam/v1";

    fn cfg() -> SesameIdamClientConfig {
        SesameIdamClientConfig::new(LOGIN, ORG, SESSION, "hauliage", "hauliage-web")
            .expect("valid config")
    }

    #[test]
    fn identity_urls_use_the_session_base_verbatim() {
        assert_eq!(
            identity_url(&cfg(), "/identity/me"),
            "https://session.internal.example/idam/v1/identity/me"
        );
    }

    /// Regression for the removed hostname derivation: a login URL on a host
    /// that does not contain `identity-login-service` must not drag session
    /// calls onto the login host.
    #[test]
    fn unrelated_login_host_never_routes_session_calls_to_login() {
        let url = identity_url(&cfg(), "/identity/me");
        assert!(
            url.starts_with(SESSION),
            "session call left the base: {url}"
        );
        assert!(
            !url.contains("api.sesameidentity.dev.local"),
            "session call was routed to the login host: {url}"
        );
    }
}
