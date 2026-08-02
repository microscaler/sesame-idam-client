use std::fmt;
use std::time::Duration;

/// Configuration key for the identity-login-service base (`…/idam/v1`).
pub const LOGIN_BASE_URL_KEY: &str = "SESAME_LOGIN_BASE_URL";
/// Configuration key for the org-mgmt base (`…/idam/v1`).
pub const ORG_MGMT_BASE_URL_KEY: &str = "SESAME_ORG_MGMT_BASE_URL";
/// Configuration key for the identity-session-service base (`…/idam/v1`).
pub const SESSION_BASE_URL_KEY: &str = "SESAME_SESSION_BASE_URL";
/// Configuration key for the tenant sent as `X-Tenant-ID`.
pub const TENANT_ID_KEY: &str = "SESAME_TENANT_ID";
/// Configuration key for the registered relying-party client.
pub const CLIENT_ID_KEY: &str = "SESAME_CLIENT_ID";

/// Sesame bcrypt login is ~10s on ms02; keep headroom.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Rejected configuration. Every variant names the key that must be fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Required key was absent or empty. There is no fallback for it.
    Missing { key: &'static str },
    /// Key was supplied but is not usable as a service base URL.
    Invalid {
        key: &'static str,
        value: String,
        reason: &'static str,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { key } => {
                write!(
                    f,
                    "Sesame-IDAM configuration {key} is required and has no default"
                )
            }
            Self::Invalid { key, value, reason } => {
                write!(
                    f,
                    "invalid Sesame-IDAM configuration {key}={value}: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Client configuration for Sesame-IDAM.
///
/// Every service the client talks to carries its **own** base URL. Nothing is
/// derived from anything else.
///
/// WHY: the previous version synthesised the org-mgmt and identity-session
/// bases by string-replacing `identity-login-service` (and the `:8101`→`:8104`
/// / `:8102` dev-port variants) inside the configured login URL. That trick is
/// silent when it stops matching: once the deployment moved off cluster DNS
/// (`http://identity-login-service.sesame-idam.svc.cluster.local:8080/idam/v1`)
/// onto a real hostname (`https://api.sesameidentity.dev.local/idam/v1`) the
/// replacement became a no-op, and org-mgmt and session calls were sent to the
/// login host instead of failing. Explicit keys, or a hard error at
/// construction — never a guess.
///
/// The URL fields are private on purpose: they can only be set through
/// [`SesameIdamClientConfig::new`] / [`SesameIdamClientConfig::from_env`],
/// which validate them.
#[derive(Debug, Clone)]
pub struct SesameIdamClientConfig {
    login_base_url: String,
    org_mgmt_base_url: String,
    session_base_url: String,
    pub tenant_id: String,
    pub client_id: String,
    pub timeout: Duration,
}

impl SesameIdamClientConfig {
    /// Build a configuration from explicit, per-service base URLs.
    ///
    /// Each base is the `…/idam/v1` prefix of that service, e.g.
    /// `https://api.sesameidentity.dev.local/idam/v1`. Trailing slashes are
    /// trimmed; the value is otherwise used verbatim.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Missing`] when a value is empty, [`ConfigError::Invalid`]
    /// when it is not an `http(s)` base (for example the full `/auth/login`
    /// endpoint URL used by the old configuration shape).
    pub fn new(
        login_base: impl Into<String>,
        org_mgmt_base: impl Into<String>,
        session_base: impl Into<String>,
        tenant_id: impl Into<String>,
        client_id: impl Into<String>,
    ) -> Result<Self, ConfigError> {
        let login_base_url = validate_base_url(LOGIN_BASE_URL_KEY, login_base.into())?;
        let org_mgmt_base_url = validate_base_url(ORG_MGMT_BASE_URL_KEY, org_mgmt_base.into())?;
        let session_base_url = validate_base_url(SESSION_BASE_URL_KEY, session_base.into())?;
        let tenant_id = tenant_id.into().trim().to_string();
        if tenant_id.is_empty() {
            return Err(ConfigError::Missing { key: TENANT_ID_KEY });
        }
        let client_id = client_id.into().trim().to_string();
        if client_id.is_empty() {
            return Err(ConfigError::Missing { key: CLIENT_ID_KEY });
        }
        Ok(Self {
            login_base_url,
            org_mgmt_base_url,
            session_base_url,
            tenant_id,
            client_id,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Override the per-request timeout (30s otherwise, see `DEFAULT_TIMEOUT`).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Build from the process environment.
    ///
    /// # Errors
    ///
    /// See [`SesameIdamClientConfig::new`]. A key that is not set is
    /// [`ConfigError::Missing`]; there are no localhost or in-cluster defaults.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Build from an arbitrary key lookup, so a consumer can layer helm values
    /// over the environment and still get the same validation:
    ///
    /// ```no_run
    /// # use sesame_idam_client::SesameIdamClientConfig;
    /// let _cfg = SesameIdamClientConfig::from_lookup(|key| {
    ///     helm_value(key).or_else(|| std::env::var(key).ok())
    /// })?;
    /// # fn helm_value(_: &str) -> Option<String> { None }
    /// # Ok::<(), sesame_idam_client::ConfigError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// See [`SesameIdamClientConfig::new`].
    pub fn from_lookup(
        lookup: impl Fn(&'static str) -> Option<String>,
    ) -> Result<Self, ConfigError> {
        Self::new(
            lookup(LOGIN_BASE_URL_KEY).unwrap_or_default(),
            lookup(ORG_MGMT_BASE_URL_KEY).unwrap_or_default(),
            lookup(SESSION_BASE_URL_KEY).unwrap_or_default(),
            lookup(TENANT_ID_KEY).unwrap_or_default(),
            lookup(CLIENT_ID_KEY).unwrap_or_default(),
        )
    }

    /// Base URL for identity-login-service (`…/idam/v1`).
    #[must_use]
    pub fn login_base(&self) -> &str {
        &self.login_base_url
    }

    /// Base URL for org-mgmt (`…/idam/v1`).
    #[must_use]
    pub fn org_mgmt_base(&self) -> &str {
        &self.org_mgmt_base_url
    }

    /// Base URL for identity-session-service (`…/idam/v1`).
    #[must_use]
    pub fn session_base(&self) -> &str {
        &self.session_base_url
    }

    /// Full password-login endpoint on identity-login-service.
    #[must_use]
    pub fn login_url(&self) -> String {
        format!("{}/auth/login", self.login_base_url)
    }
}

fn validate_base_url(key: &'static str, value: String) -> Result<String, ConfigError> {
    let trimmed = value.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(ConfigError::Missing { key });
    }
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return Err(ConfigError::Invalid {
            key,
            value: trimmed.to_string(),
            reason: "service base URL must start with http:// or https://",
        });
    }
    // Catches the old `SESAME_LOGIN_URL` value being pasted into a base slot.
    if trimmed.ends_with("/auth/login") {
        return Err(ConfigError::Invalid {
            key,
            value: trimmed.to_string(),
            reason: "expected a service base URL such as https://host/idam/v1, not an endpoint",
        });
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOGIN: &str = "https://api.sesameidentity.dev.local/idam/v1";
    const ORG: &str = "https://org-mgmt.internal.example/idam/v1";
    const SESSION: &str = "https://session.internal.example/idam/v1";
    const CLIENT: &str = "hauliage-web";

    fn cfg() -> SesameIdamClientConfig {
        SesameIdamClientConfig::new(LOGIN, ORG, SESSION, "hauliage", CLIENT)
            .expect("valid config")
    }

    #[test]
    fn registered_client_id_is_required() {
        let error =
            SesameIdamClientConfig::new(LOGIN, ORG, SESSION, "hauliage", "   ").unwrap_err();
        assert_eq!(
            error,
            ConfigError::Missing {
                key: CLIENT_ID_KEY
            }
        );
    }

    #[test]
    fn each_base_url_is_used_verbatim() {
        let cfg = cfg();
        assert_eq!(cfg.login_base(), LOGIN);
        assert_eq!(cfg.org_mgmt_base(), ORG);
        assert_eq!(cfg.session_base(), SESSION);
        assert_eq!(
            cfg.login_url(),
            "https://api.sesameidentity.dev.local/idam/v1/auth/login"
        );
    }

    #[test]
    fn trailing_slash_is_the_only_normalisation() {
        let cfg = SesameIdamClientConfig::new(
            "  https://api.sesameidentity.dev.local/idam/v1/  ",
            ORG,
            SESSION,
            "hauliage",
            CLIENT,
        )
        .expect("valid config");
        assert_eq!(cfg.login_base(), LOGIN);
    }

    #[test]
    fn missing_login_base_names_the_key() {
        let error =
            SesameIdamClientConfig::new("", ORG, SESSION, "hauliage", CLIENT).unwrap_err();
        assert_eq!(
            error,
            ConfigError::Missing {
                key: LOGIN_BASE_URL_KEY
            }
        );
        assert!(error.to_string().contains("SESAME_LOGIN_BASE_URL"));
    }

    #[test]
    fn missing_org_mgmt_base_names_the_key() {
        let error =
            SesameIdamClientConfig::new(LOGIN, "", SESSION, "hauliage", CLIENT).unwrap_err();
        assert_eq!(
            error,
            ConfigError::Missing {
                key: ORG_MGMT_BASE_URL_KEY
            }
        );
        assert!(error.to_string().contains("SESAME_ORG_MGMT_BASE_URL"));
    }

    #[test]
    fn missing_session_base_names_the_key() {
        let error =
            SesameIdamClientConfig::new(LOGIN, ORG, "", "hauliage", CLIENT).unwrap_err();
        assert_eq!(
            error,
            ConfigError::Missing {
                key: SESSION_BASE_URL_KEY
            }
        );
        assert!(error.to_string().contains("SESAME_SESSION_BASE_URL"));
    }

    #[test]
    fn missing_tenant_names_the_key() {
        let error = SesameIdamClientConfig::new(LOGIN, ORG, SESSION, "   ", CLIENT).unwrap_err();
        assert_eq!(error, ConfigError::Missing { key: TENANT_ID_KEY });
        assert!(error.to_string().contains("SESAME_TENANT_ID"));
    }

    #[test]
    fn lookup_that_supplies_nothing_fails_closed() {
        let error = SesameIdamClientConfig::from_lookup(|_| None).unwrap_err();
        assert_eq!(
            error,
            ConfigError::Missing {
                key: LOGIN_BASE_URL_KEY
            }
        );
    }

    #[test]
    fn lookup_reads_every_service_key() {
        let cfg = SesameIdamClientConfig::from_lookup(|key| match key {
            LOGIN_BASE_URL_KEY => Some(LOGIN.to_string()),
            ORG_MGMT_BASE_URL_KEY => Some(ORG.to_string()),
            SESSION_BASE_URL_KEY => Some(SESSION.to_string()),
            TENANT_ID_KEY => Some("hauliage".to_string()),
            CLIENT_ID_KEY => Some(CLIENT.to_string()),
            _ => None,
        })
        .expect("valid config");
        assert_eq!(cfg.login_base(), LOGIN);
        assert_eq!(cfg.org_mgmt_base(), ORG);
        assert_eq!(cfg.session_base(), SESSION);
        assert_eq!(cfg.tenant_id, "hauliage");
        assert_eq!(cfg.client_id, CLIENT);
    }

    #[test]
    fn rejects_an_endpoint_url_in_a_base_slot() {
        let error = SesameIdamClientConfig::new(
            "https://api.sesameidentity.dev.local/idam/v1/auth/login",
            ORG,
            SESSION,
            "hauliage",
            CLIENT,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ConfigError::Invalid {
                key: LOGIN_BASE_URL_KEY,
                ..
            }
        ));
    }

    #[test]
    fn rejects_a_base_without_a_scheme() {
        let error =
            SesameIdamClientConfig::new(
                LOGIN,
                "org-mgmt:8080/idam/v1",
                SESSION,
                "hauliage",
                CLIENT,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ConfigError::Invalid {
                key: ORG_MGMT_BASE_URL_KEY,
                ..
            }
        ));
    }

    #[test]
    fn default_timeout_allows_slow_bcrypt() {
        assert!(cfg().timeout >= Duration::from_secs(30));
    }

    #[test]
    fn with_timeout_overrides_the_default() {
        let cfg = cfg().with_timeout(Duration::from_secs(5));
        assert_eq!(cfg.timeout, Duration::from_secs(5));
    }
}
