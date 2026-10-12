//! BFF configuration (ADR-014 §3, `BffConfig`).

use std::time::Duration;

use super::BffError;

/// A client secret. Never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// One relying-party BFF: its confidential client, its cookie and its limits.
#[derive(Clone, Debug)]
pub struct BffConfig {
    /// Registered confidential client.
    pub client_id: String,
    pub client_secret: Secret,
    /// Tenant the client belongs to (sent as `X-Tenant-ID` on revocation).
    pub tenant_id: String,
    /// Expected `iss` of ID tokens.
    pub issuer: String,
    /// Browser-facing `/oauth/authorize` on the hosted surface.
    pub authorize_url: String,
    /// Back-channel `/oauth/token`.
    pub token_url: String,
    /// Back-channel `/auth/logout` (refresh-family revocation).
    pub revoke_url: String,
    /// Browser-facing end-session endpoint, when Sesame offers one.
    pub end_session_url: Option<String>,
    /// Exact-match registered callback, `https://<bff host>/auth/callback`.
    pub redirect_uri: String,
    pub scope: String,
    /// `__Host-` prefixed cookie name.
    pub cookie_name: String,
    /// Exact `Origin` values accepted on non-safe requests.
    pub allowed_origins: Vec<String>,
    /// Header a cross-site form cannot set, required on non-safe requests.
    pub csrf_header: (String, String),
    /// `return_to` must start with one of these (all relative, starting `/`).
    pub return_to_prefixes: Vec<String>,
    pub default_return_to: String,
    /// Where the browser lands after logout (relative or absolute on the BFF host).
    pub post_logout_redirect: String,
    pub idle_timeout: Duration,
    pub absolute_timeout: Duration,
    pub http_timeout: Duration,
}

/// A missing or unacceptable setting, by environment key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BffConfigError {
    Missing(&'static str),
    Invalid {
        key: &'static str,
        reason: &'static str,
    },
}

impl std::fmt::Display for BffConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(k) => write!(f, "BFF setting {k} is required"),
            Self::Invalid { key, reason } => write!(f, "BFF setting {key}: {reason}"),
        }
    }
}

impl std::error::Error for BffConfigError {}

/// Environment keys read by [`BffConfig::from_lookup`], after the prefix.
pub const ENV_KEYS: &[&str] = &[
    "CLIENT_ID",
    "CLIENT_SECRET",
    "CLIENT_SECRET_FILE",
    "TENANT_ID",
    "ISSUER",
    "AUTHORIZE_URL",
    "TOKEN_URL",
    "REVOKE_URL",
    "END_SESSION_URL",
    "REDIRECT_URI",
    "SCOPE",
    "COOKIE_NAME",
    "ALLOWED_ORIGINS",
    "CSRF_HEADER",
    "RETURN_TO_PREFIXES",
    "DEFAULT_RETURN_TO",
    "POST_LOGOUT_REDIRECT",
    "IDLE_TIMEOUT_SECS",
    "ABSOLUTE_TIMEOUT_SECS",
    "HTTP_TIMEOUT_MS",
];

fn is_local_http(url: &str) -> bool {
    ["http://localhost", "http://127.0.0.1", "http://[::1]"]
        .iter()
        .any(|p| {
            url.strip_prefix(p)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/']))
        })
}

fn browser_url_ok(url: &str) -> bool {
    url.starts_with("https://") || is_local_http(url)
}

fn back_channel_url_ok(url: &str) -> bool {
    url.starts_with("https://") || url.starts_with("http://")
}

/// A same-site relative path: `/` then not `/` or `\`, no control characters.
pub(crate) fn is_relative_path(p: &str) -> bool {
    p.starts_with('/')
        && !p.starts_with("//")
        && !p.starts_with("/\\")
        && p.len() <= 2048
        && !p.chars().any(|c| c.is_control() || c == '\\')
}

impl BffConfig {
    /// Read settings with `lookup(prefix + key)`, typically `std::env::var`.
    ///
    /// Required: `CLIENT_ID`, `CLIENT_SECRET` (or `CLIENT_SECRET_FILE`),
    /// `TENANT_ID`, `ISSUER`, `AUTHORIZE_URL`, `TOKEN_URL`, `REVOKE_URL`,
    /// `REDIRECT_URI`, `COOKIE_NAME`, `ALLOWED_ORIGINS` (comma-separated).
    /// Defaults: scope `openid profile email`, `CSRF_HEADER`
    /// `X-Requested-With: sesame-bff`, prefixes `/`, return to `/`, idle 30
    /// minutes, absolute 12 hours, HTTP timeout 5 s.
    ///
    /// # Errors
    /// [`BffConfigError`] naming the key.
    pub fn from_lookup(
        prefix: &str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, BffConfigError> {
        let get = |k: &str| {
            lookup(&format!("{prefix}{k}"))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let req = |k: &'static str| get(k).ok_or(BffConfigError::Missing(k));
        let secs = |k: &'static str, d: u64| -> Result<Duration, BffConfigError> {
            get(k).map_or(Ok(Duration::from_secs(d)), |v| {
                v.parse()
                    .map(Duration::from_secs)
                    .map_err(|_| BffConfigError::Invalid {
                        key: k,
                        reason: "not a whole number of seconds",
                    })
            })
        };
        let list = |v: String| -> Vec<String> {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };
        let secret = match get("CLIENT_SECRET") {
            Some(s) => s,
            None => {
                let path =
                    get("CLIENT_SECRET_FILE").ok_or(BffConfigError::Missing("CLIENT_SECRET"))?;
                std::fs::read_to_string(path)
                    .map(|s| s.trim().to_string())
                    .map_err(|_| BffConfigError::Invalid {
                        key: "CLIENT_SECRET_FILE",
                        reason: "unreadable",
                    })?
            }
        };
        let csrf_header = match get("CSRF_HEADER") {
            None => ("X-Requested-With".to_string(), "sesame-bff".to_string()),
            Some(v) => {
                let (n, val) = v.split_once(':').ok_or(BffConfigError::Invalid {
                    key: "CSRF_HEADER",
                    reason: "expected `Name: value`",
                })?;
                (n.trim().to_string(), val.trim().to_string())
            }
        };
        let http_timeout = match get("HTTP_TIMEOUT_MS") {
            None => Duration::from_secs(5),
            Some(v) => {
                v.parse()
                    .map(Duration::from_millis)
                    .map_err(|_| BffConfigError::Invalid {
                        key: "HTTP_TIMEOUT_MS",
                        reason: "not a whole number of milliseconds",
                    })?
            }
        };
        Self {
            client_id: req("CLIENT_ID")?,
            client_secret: Secret::new(secret),
            tenant_id: req("TENANT_ID")?,
            issuer: req("ISSUER")?,
            authorize_url: req("AUTHORIZE_URL")?,
            token_url: req("TOKEN_URL")?,
            revoke_url: req("REVOKE_URL")?,
            end_session_url: get("END_SESSION_URL"),
            redirect_uri: req("REDIRECT_URI")?,
            scope: get("SCOPE").unwrap_or_else(|| "openid profile email".to_string()),
            cookie_name: req("COOKIE_NAME")?,
            allowed_origins: list(req("ALLOWED_ORIGINS")?),
            csrf_header,
            return_to_prefixes: get("RETURN_TO_PREFIXES")
                .map_or_else(|| vec!["/".to_string()], list),
            default_return_to: get("DEFAULT_RETURN_TO").unwrap_or_else(|| "/".to_string()),
            post_logout_redirect: get("POST_LOGOUT_REDIRECT").unwrap_or_else(|| "/".to_string()),
            idle_timeout: secs("IDLE_TIMEOUT_SECS", 30 * 60)?,
            absolute_timeout: secs("ABSOLUTE_TIMEOUT_SECS", 12 * 3600)?,
            http_timeout,
        }
        .validated()
    }

    /// Check the settings ADR-014 makes non-negotiable.
    ///
    /// # Errors
    /// [`BffConfigError::Invalid`].
    pub fn validated(self) -> Result<Self, BffConfigError> {
        let bad = |key, reason| Err(BffConfigError::Invalid { key, reason });
        if self.client_secret.expose().is_empty() {
            return Err(BffConfigError::Missing("CLIENT_SECRET"));
        }
        let name = &self.cookie_name;
        if !name.starts_with("__Host-")
            || name.len() <= 7
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return bad("COOKIE_NAME", "must be a __Host- prefixed token");
        }
        if !browser_url_ok(&self.redirect_uri) {
            return bad("REDIRECT_URI", "must be https (http only on localhost)");
        }
        if !browser_url_ok(&self.authorize_url) {
            return bad("AUTHORIZE_URL", "must be https (http only on localhost)");
        }
        if let Some(u) = &self.end_session_url {
            if !browser_url_ok(u) {
                return bad("END_SESSION_URL", "must be https (http only on localhost)");
            }
        }
        if !back_channel_url_ok(&self.token_url) {
            return bad("TOKEN_URL", "must be an http(s) URL");
        }
        if !back_channel_url_ok(&self.revoke_url) {
            return bad("REVOKE_URL", "must be an http(s) URL");
        }
        if self.allowed_origins.is_empty()
            || self
                .allowed_origins
                .iter()
                .any(|o| !browser_url_ok(o) || o.ends_with('/'))
        {
            return bad(
                "ALLOWED_ORIGINS",
                "one or more scheme://host[:port] origins",
            );
        }
        let (h, v) = &self.csrf_header;
        if h.is_empty()
            || v.is_empty()
            || !h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return bad("CSRF_HEADER", "expected `Name: value`");
        }
        if self.return_to_prefixes.is_empty()
            || !self.return_to_prefixes.iter().all(|p| is_relative_path(p))
        {
            return bad("RETURN_TO_PREFIXES", "relative paths starting with /");
        }
        if !is_relative_path(&self.default_return_to) {
            return bad("DEFAULT_RETURN_TO", "a relative path starting with /");
        }
        if self.idle_timeout.is_zero() || self.idle_timeout > self.absolute_timeout {
            return bad(
                "IDLE_TIMEOUT_SECS",
                "must be positive and at most the absolute timeout",
            );
        }
        if !self.scope.split(' ').any(|s| s == "openid") {
            return bad("SCOPE", "must include openid");
        }
        Ok(self)
    }

    /// `return_to` must be a relative path under an allowed prefix (no open redirect).
    pub(crate) fn check_return_to<'a>(&self, r: &'a str) -> Result<&'a str, BffError> {
        if is_relative_path(r)
            && self
                .return_to_prefixes
                .iter()
                .any(|p| r.starts_with(p.as_str()))
        {
            Ok(r)
        } else {
            Err(BffError::InvalidReturnTo)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;

    pub(crate) fn env() -> HashMap<String, String> {
        [
            ("CLIENT_ID", "app-web"),
            ("CLIENT_SECRET", "s3cret"),
            ("TENANT_ID", "acme"),
            ("ISSUER", "https://auth.example.com"),
            (
                "AUTHORIZE_URL",
                "https://auth.example.com/idam/v1/oauth/authorize",
            ),
            (
                "TOKEN_URL",
                "http://identity-login-service:8080/idam/v1/oauth/token",
            ),
            (
                "REVOKE_URL",
                "http://identity-login-service:8080/idam/v1/auth/logout",
            ),
            ("REDIRECT_URI", "https://app.example.com/auth/callback"),
            ("COOKIE_NAME", "__Host-app"),
            ("ALLOWED_ORIGINS", "https://app.example.com"),
            ("CSRF_HEADER", "X-App-Request: 1"),
        ]
        .into_iter()
        .map(|(k, v)| (format!("BFF_{k}"), v.to_string()))
        .collect()
    }

    pub(crate) fn config() -> BffConfig {
        let e = env();
        BffConfig::from_lookup("BFF_", |k| e.get(k).cloned()).expect("valid")
    }

    fn with(k: &str, v: &str) -> Result<BffConfig, BffConfigError> {
        let mut e = env();
        e.insert(format!("BFF_{k}"), v.to_string());
        BffConfig::from_lookup("BFF_", |key| e.get(key).cloned())
    }

    #[test]
    fn defaults_apply() {
        let c = config();
        assert_eq!(c.idle_timeout, Duration::from_secs(1800));
        assert_eq!(c.absolute_timeout, Duration::from_secs(43200));
        assert_eq!(c.scope, "openid profile email");
        assert_eq!(c.csrf_header, ("X-App-Request".into(), "1".into()));
        assert!(!format!("{c:?}").contains("s3cret"));
    }

    #[test]
    fn missing_keys_are_named() {
        let mut e = env();
        e.remove("BFF_TOKEN_URL");
        let err = BffConfig::from_lookup("BFF_", |k| e.get(k).cloned()).unwrap_err();
        assert_eq!(err, BffConfigError::Missing("TOKEN_URL"));
    }

    #[test]
    fn unsafe_settings_are_refused() {
        assert!(with("COOKIE_NAME", "session").is_err());
        assert!(with("COOKIE_NAME", "__Secure-app").is_err());
        assert!(with("REDIRECT_URI", "http://app.example.com/auth/callback").is_err());
        assert!(with("ALLOWED_ORIGINS", "*").is_err());
        assert!(with("ALLOWED_ORIGINS", "https://app.example.com/").is_err());
        assert!(with("SCOPE", "profile").is_err());
        assert!(with("IDLE_TIMEOUT_SECS", "999999").is_err());
        assert!(with("RETURN_TO_PREFIXES", "https://evil.example").is_err());
        assert!(with("REDIRECT_URI", "http://localhost:3000/auth/callback").is_ok());
        assert!(with("REDIRECT_URI", "http://localhost.evil.example/cb").is_err());
    }

    #[test]
    fn return_to_must_be_relative_and_allowed() {
        let mut c = config();
        assert!(c.check_return_to("/dashboard?x=1").is_ok());
        for bad in [
            "//evil.example",
            "/\\evil.example",
            "https://evil.example",
            "dashboard",
            "/a\nb",
        ] {
            assert_eq!(
                c.check_return_to(bad),
                Err(BffError::InvalidReturnTo),
                "{bad:?}"
            );
        }
        c.return_to_prefixes = vec!["/app/".into()];
        assert!(c.check_return_to("/admin").is_err());
        assert!(c.check_return_to("/app/x").is_ok());
    }
}
