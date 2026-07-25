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
    let url = format!("{}/identity/me", session_base(config));
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
    let url = format!("{}/identity/me", session_base(config));
    let mut body = serde_json::Map::new();
    if let Some(v) = first_name {
        body.insert("first_name".into(), serde_json::Value::String(v.to_string()));
    }
    if let Some(v) = last_name {
        body.insert("last_name".into(), serde_json::Value::String(v.to_string()));
    }
    if let Some(v) = avatar_url {
        body.insert("avatar_url".into(), serde_json::Value::String(v.to_string()));
    }
    let bytes = serde_json::to_vec(&serde_json::Value::Object(body))
        .map_err(|e| OrgClientError::Transport(e.to_string()))?;
    let options = auth_options(config, access_token);
    let (status, resp_bytes) =
        fetch_patch(&url, &bytes, &options).map_err(|e| OrgClientError::Transport(e.to_string()))?;
    let text = String::from_utf8(resp_bytes).unwrap_or_default();
    if status == 401 {
        return Err(OrgClientError::Unauthorized);
    }
    if !(200..300).contains(&status) {
        return Err(OrgClientError::Upstream { status, body: text });
    }
    serde_json::from_str(&text).map_err(|e| OrgClientError::Decode(format!("{e}; body={text}")))
}

fn session_base(config: &SesameIdamClientConfig) -> String {
    if let Some(ref url) = config.session_url {
        return url.trim_end_matches('/').to_string();
    }
    let login_base = config.login_base();
    if login_base.contains(":8101") {
        // Local PF convention: login 8101, session 8102 (when forwarded).
        return login_base.replace(":8101", ":8102");
    }
    if login_base.contains("identity-login-service") {
        return login_base.replace("identity-login-service", "identity-session-service");
    }
    login_base
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

fn auth_options(config: &SesameIdamClientConfig, access_token: &str) -> HttpFetchOptions {
    HttpFetchOptions {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn session_base_maps_login_service_name() {
        let cfg = SesameIdamClientConfig {
            login_url: "http://identity-login-service.sesame-idam.svc.cluster.local:8080/idam/v1/auth/login".into(),
            session_url: None,
            org_mgmt_url: None,
            tenant_id: "hauliage".into(),
            timeout: Duration::from_secs(5),
        };
        assert_eq!(
            session_base(&cfg),
            "http://identity-session-service.sesame-idam.svc.cluster.local:8080/idam/v1"
        );
    }
}
