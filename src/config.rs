use std::time::Duration;

/// Client configuration for sesame identity-login-service.
#[derive(Debug, Clone)]
pub struct SesameIdamClientConfig {
    pub login_url: String,
    pub org_mgmt_url: Option<String>,
    /// Optional identity-session-service base (`…/idam/v1`). When unset, derived from `login_url`.
    pub session_url: Option<String>,
    pub tenant_id: String,
    pub timeout: Duration,
}

impl Default for SesameIdamClientConfig {
    fn default() -> Self {
        Self {
            login_url: "http://127.0.0.1:8101/idam/v1/auth/login".to_string(),
            org_mgmt_url: None,
            session_url: None,
            tenant_id: "default".to_string(),
            // Sesame bcrypt login is ~10s on ms02; keep headroom.
            timeout: Duration::from_secs(30),
        }
    }
}

impl SesameIdamClientConfig {
    #[must_use]
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(url) = std::env::var("SESAME_LOGIN_URL") {
            cfg.login_url = url;
        }
        if let Ok(url) = std::env::var("SESAME_ORG_MGMT_URL") {
            cfg.org_mgmt_url = Some(url);
        }
        if let Ok(url) = std::env::var("SESAME_SESSION_URL") {
            cfg.session_url = Some(url);
        }
        if let Ok(tenant) = std::env::var("SESAME_TENANT_ID") {
            cfg.tenant_id = tenant;
        }
        cfg
    }

    /// Base URL for identity-login-service (`/idam/v1`), derived from `login_url`.
    #[must_use]
    pub fn login_base(&self) -> String {
        self.login_url
            .trim_end_matches('/')
            .strip_suffix("/auth/login")
            .unwrap_or(self.login_url.trim_end_matches('/'))
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_base_strips_auth_login_suffix() {
        let cfg = SesameIdamClientConfig {
            login_url: "http://identity-login-service:8080/idam/v1/auth/login".to_string(),
            ..SesameIdamClientConfig::default()
        };
        assert_eq!(
            cfg.login_base(),
            "http://identity-login-service:8080/idam/v1"
        );
    }
}
