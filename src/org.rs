use brrtrouter::http::{fetch_delete, fetch_get, fetch_post, HttpFetchOptions};

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
    let url = org_mgmt_url(config, "/organizations");
    let body = serde_json::json!({ "name": name });
    post_json(config, &url, access_token, &body)
}

/// Accept invite token in Sesame (caller must be authenticated).
pub fn accept_invitation(
    config: &SesameIdamClientConfig,
    access_token: &str,
    token: &str,
) -> Result<OrganizationSummary, OrgClientError> {
    let url = org_mgmt_url(config, "/invitations/accept");
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
    let url = org_mgmt_url(config, &format!("/organizations/{org_id}/invitations"));
    let body = serde_json::json!({ "email": email, "role": role });
    post_invite(config, &url, access_token, &body)
}

/// List active members in an organization.
pub fn fetch_users_in_org(
    config: &SesameIdamClientConfig,
    access_token: &str,
    org_id: &str,
) -> Result<UsersInOrgPage, OrgClientError> {
    let url = org_mgmt_url(
        config,
        &format!("/organizations/{org_id}/users?page_size=100&page_number=0"),
    );
    get_json(config, &url, access_token)
}

/// Remove a member from an organization (Sesame org-mgmt).
pub fn remove_user_from_org(
    config: &SesameIdamClientConfig,
    access_token: &str,
    org_id: &str,
    user_id: &str,
) -> Result<(), OrgClientError> {
    let url = org_mgmt_url(config, &format!("/organizations/{org_id}/users/{user_id}"));
    let body = b"{}";
    delete_status(config, &url, access_token, Some(body.as_slice()))
}

/// Revoke a pending invitation by invite_id.
pub fn revoke_pending_invite(
    config: &SesameIdamClientConfig,
    access_token: &str,
    org_id: &str,
    invite_id: &str,
) -> Result<(), OrgClientError> {
    let url = org_mgmt_url(
        config,
        &format!("/organizations/{org_id}/pending-invitations"),
    );
    let body = serde_json::json!({ "invite_id": invite_id });
    let bytes = serde_json::to_vec(&body).map_err(|e| OrgClientError::Transport(e.to_string()))?;
    delete_status(config, &url, access_token, Some(bytes.as_slice()))
}

fn delete_status(
    config: &SesameIdamClientConfig,
    url: &str,
    access_token: &str,
    body: Option<&[u8]>,
) -> Result<(), OrgClientError> {
    let options = auth_options(config, access_token);
    let (status, resp_bytes) =
        fetch_delete(url, body, &options).map_err(|e| OrgClientError::Transport(e.to_string()))?;
    let text = String::from_utf8(resp_bytes).unwrap_or_default();
    if status == 401 {
        return Err(OrgClientError::Unauthorized);
    }
    if !(200..300).contains(&status) {
        return Err(OrgClientError::Upstream { status, body: text });
    }
    Ok(())
}

/// Org-mgmt endpoint from the configured org-mgmt base, verbatim.
///
/// WHY no derivation: this used to synthesise the org-mgmt host out of
/// `login_url` (`identity-login-service`→`org-mgmt`, dev `:8101`→`:8104`).
/// When the deployment moved to a real hostname the login URL no longer
/// contained `identity-login-service`, the replacement became a no-op, and
/// every org call was silently sent to the login host instead of failing.
/// The base is now a required, independent config key — see
/// [`crate::ORG_MGMT_BASE_URL_KEY`].
fn org_mgmt_url(config: &SesameIdamClientConfig, path: &str) -> String {
    format!("{}{path}", config.org_mgmt_base())
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
    let parsed: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| OrgClientError::Decode(format!("{e}; body={text}")))?;
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

    const LOGIN: &str = "https://api.sesameidentity.dev.local/idam/v1";
    const ORG: &str = "https://org-mgmt.internal.example/idam/v1";
    const SESSION: &str = "https://session.internal.example/idam/v1";

    fn cfg() -> SesameIdamClientConfig {
        SesameIdamClientConfig::new(LOGIN, ORG, SESSION, "hauliage", "hauliage-web")
            .expect("valid config")
    }

    #[test]
    fn org_urls_use_the_org_mgmt_base_verbatim() {
        let cfg = cfg();
        assert_eq!(
            org_mgmt_url(&cfg, "/organizations"),
            "https://org-mgmt.internal.example/idam/v1/organizations"
        );
        assert_eq!(
            org_mgmt_url(&cfg, "/organizations/org-1/users/user-2"),
            "https://org-mgmt.internal.example/idam/v1/organizations/org-1/users/user-2"
        );
    }

    /// Regression for the removed hostname derivation: a login URL on a host
    /// that does not contain `identity-login-service` must not drag org calls
    /// onto the login host.
    #[test]
    fn unrelated_login_host_never_routes_org_calls_to_login() {
        let cfg = cfg();
        let url = org_mgmt_url(&cfg, "/organizations");
        assert!(
            url.starts_with(ORG),
            "org call left the org-mgmt base: {url}"
        );
        assert!(
            !url.contains("api.sesameidentity.dev.local"),
            "org call was routed to the login host: {url}"
        );
    }
}
