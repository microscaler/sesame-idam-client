use std::time::Duration;

use brrtrouter::http::{fetch_get, fetch_post, HttpFetchOptions};

use crate::config::SesameIdamClientConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgClientError {
    Unauthorized,
    Upstream { status: u16, body: String },
    Transport(String),
    Decode(String),
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct OrganizationSummary {
    pub id: String,
    pub name: String,
    pub tenant_id: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct UsersInOrgPage {
    pub items: Vec<OrgMemberSummary>,
    pub total: u64,
    pub page: u32,
    pub page_size: u32,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct OrgMemberSummary {
    pub user_id: String,
    pub email: String,
    pub role: String,
    #[serde(default)]
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct InviteCreated {
    pub invite_id: String,
    pub invite_token: String,
}

/// Create organization in Sesame (caller must be authenticated).
pub fn create_organization(
    config: &SesameIdamClientConfig,
    access_token: &str,
    name: &str,
) -> Result<OrganizationSummary, OrgClientError> {
    let url = format!("{}/organizations", org_mgmt_base(config));
    let body = serde_json::json!({ "name": name });
    post_json(config, &url, access_token, &body)
}

/// Accept invite token in Sesame (caller must be authenticated).
pub fn accept_invitation(
    config: &SesameIdamClientConfig,
    access_token: &str,
    token: &str,
) -> Result<OrganizationSummary, OrgClientError> {
    let url = format!("{}/invitations/accept", org_mgmt_base(config));
    let body = serde_json::json!({ "token": token });
    post_json(config, &url, access_token, &body)
}

/// Invite a user by email to an organization (Sesame sends magic-link in prod).
pub fn invite_user_to_org(
    config: &SesameIdamClientConfig,
    access_token: &str,
    org_id: &str,
    email: &str,
    role: &str,
) -> Result<InviteCreated, OrgClientError> {
    let url = format!("{}/organizations/{org_id}/invitations", org_mgmt_base(config));
    let body = serde_json::json!({ "email": email, "role": role });
    post_invite(config, &url, access_token, &body)
}

/// List active members in an organization.
pub fn fetch_users_in_org(
    config: &SesameIdamClientConfig,
    access_token: &str,
    org_id: &str,
) -> Result<UsersInOrgPage, OrgClientError> {
    let url = format!(
        "{}/organizations/{org_id}/users?page_size=100&page_number=0",
        org_mgmt_base(config)
    );
    get_json(config, &url, access_token)
}

fn org_mgmt_base(config: &SesameIdamClientConfig) -> String {
    if let Some(ref url) = config.org_mgmt_url {
        return url.trim_end_matches('/').to_string();
    }
    let login_base = config
        .login_url
        .replace("/auth/login", "")
        .trim_end_matches('/')
        .to_string();
    // Tilt dev host PF: identity-login 8101:8080; org-mgmt via manual PF
    // `kubectl port-forward -n sesame-idam svc/org-mgmt 8104:8080`.
    if login_base.contains(":8101") {
        return login_base.replace(":8101", ":8104");
    }
    // In-cluster: org endpoints live on the org-mgmt Service (ClusterIP :8080),
    // same /idam/v1 base path as login.
    if login_base.contains("identity-login-service") {
        return login_base.replace("identity-login-service", "org-mgmt");
    }
    login_base
}

fn post_json(
    config: &SesameIdamClientConfig,
    url: &str,
    access_token: &str,
    body: &serde_json::Value,
) -> Result<OrganizationSummary, OrgClientError> {
    let bytes = serde_json::to_vec(body).map_err(|e| OrgClientError::Transport(e.to_string()))?;
    let options = auth_options(config, access_token);

    let (status, resp_bytes) =
        fetch_post(url, &bytes, &options).map_err(|e| OrgClientError::Transport(e.to_string()))?;

    let text = String::from_utf8(resp_bytes).unwrap_or_default();
    if status == 401 {
        return Err(OrgClientError::Unauthorized);
    }
    if !(200..300).contains(&status) {
        return Err(OrgClientError::Upstream { status, body: text });
    }

    serde_json::from_str(&text).map_err(|e| OrgClientError::Decode(format!("{e}; body={text}")))
}

fn post_invite(
    config: &SesameIdamClientConfig,
    url: &str,
    access_token: &str,
    body: &serde_json::Value,
) -> Result<InviteCreated, OrgClientError> {
    let bytes = serde_json::to_vec(body).map_err(|e| OrgClientError::Transport(e.to_string()))?;
    let options = auth_options(config, access_token);
    let (status, resp_bytes) =
        fetch_post(url, &bytes, &options).map_err(|e| OrgClientError::Transport(e.to_string()))?;
    let text = String::from_utf8(resp_bytes).unwrap_or_default();
    if status == 401 {
        return Err(OrgClientError::Unauthorized);
    }
    if !(200..300).contains(&status) {
        return Err(OrgClientError::Upstream { status, body: text });
    }
    let parsed: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| OrgClientError::Decode(format!("{e}; body={text}")))?;
    let invite_id = parsed
        .get("invite_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let invite_token = parsed
        .get("invite_token")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    if invite_token.is_empty() {
        return Err(OrgClientError::Decode(format!(
            "invite_token missing in response; body={text}"
        )));
    }
    Ok(InviteCreated {
        invite_id,
        invite_token,
    })
}

fn post_empty(
    config: &SesameIdamClientConfig,
    url: &str,
    access_token: &str,
    body: &serde_json::Value,
) -> Result<(), OrgClientError> {
    let bytes = serde_json::to_vec(body).map_err(|e| OrgClientError::Transport(e.to_string()))?;
    let options = auth_options(config, access_token);
    let (status, resp_bytes) =
        fetch_post(url, &bytes, &options).map_err(|e| OrgClientError::Transport(e.to_string()))?;
    let text = String::from_utf8(resp_bytes).unwrap_or_default();
    if status == 401 {
        return Err(OrgClientError::Unauthorized);
    }
    if !(200..300).contains(&status) {
        return Err(OrgClientError::Upstream { status, body: text });
    }
    Ok(())
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

    fn cfg_with_login(login_url: &str) -> SesameIdamClientConfig {
        SesameIdamClientConfig {
            login_url: login_url.to_string(),
            org_mgmt_url: None,
            tenant_id: "hauliage".to_string(),
            timeout: Duration::from_secs(30),
        }
    }

    #[test]
    fn org_mgmt_base_strips_login_suffix() {
        let cfg = cfg_with_login("http://localhost:8101/idam/v1/auth/login");
        assert_eq!(org_mgmt_base(&cfg), "http://localhost:8104/idam/v1");
    }

    #[test]
    fn org_mgmt_base_maps_in_cluster_service_name() {
        let cfg = cfg_with_login(
            "http://identity-login-service.sesame-idam.svc.cluster.local:8080/idam/v1/auth/login",
        );
        assert_eq!(
            org_mgmt_base(&cfg),
            "http://org-mgmt.sesame-idam.svc.cluster.local:8080/idam/v1"
        );
    }

    #[test]
    fn org_mgmt_base_prefers_explicit_url() {
        let mut cfg = cfg_with_login(
            "http://identity-login-service.sesame-idam.svc.cluster.local:8080/idam/v1/auth/login",
        );
        cfg.org_mgmt_url = Some("http://org-mgmt.other:8080/idam/v1/".to_string());
        assert_eq!(org_mgmt_base(&cfg), "http://org-mgmt.other:8080/idam/v1");
    }
}
