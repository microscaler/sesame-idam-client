//! Relying-party BFF sessions (ADR-014).
//!
//! A relying party's browser app never holds a Sesame token. Its BFF is a
//! confidential OIDC client: it sends the browser to Sesame's hosted login,
//! redeems the code with PKCE and its client secret, keeps the tokens in a
//! server-side store, and gives the browser an opaque `__Host-` cookie.
//!
//! ```text
//! GET  /auth/start?return_to=/x   -> Bff::start_login      -> 302 to /oauth/authorize
//! GET  /auth/callback?code&state  -> Bff::complete_login   -> 302 to /x + Set-Cookie
//! any  /api/...                   -> Bff::check_csrf, Bff::resolve -> bearer for downstream
//! POST /auth/logout               -> Bff::logout           -> 302 + cleared cookie
//! ```
//!
//! Every sign-in method (password, passkey, OTP, social, SAML) happens on the
//! hosted surface and ends in the same callback; nothing here is per-method.
//! The crate's password, registration and social helpers are for Sesame's own
//! hosted surface and machine flows, not for relying-party BFFs.

mod config;
mod crypto;
mod idp;
mod store;

use std::sync::Arc;
use std::time::Duration;

pub use config::{BffConfig, BffConfigError, Secret, ENV_KEYS};
pub use idp::{HttpIdentityProvider, IdentityProvider, IdpError, OidcTokens};
#[cfg(feature = "redis-store")]
pub use store::RedisStore;
pub use store::{MemoryStore, PreAuth, SessionRecord, SessionStore, StoreError};

/// Default for [`BffConfig::preauth_ttl`] (`PREAUTH_TTL_SECS`): how long a sign-in may take between `/auth/start`
/// and `/auth/callback`. 30 minutes, the life of Sesame's authorization request (a hosted login page left open that
/// long still completes, and must find its state here).
pub const PREAUTH_TTL: Duration = Duration::from_secs(1800);
/// Refresh the access token when it expires within this window.
pub const REFRESH_LEEWAY_SECS: u64 = 60;
/// Allowed clock skew when checking ID token times.
const CLOCK_SKEW_SECS: u64 = 60;
/// Write `last_seen` back at most this often (sliding idle timeout).
const TOUCH_INTERVAL_SECS: u64 = 60;
/// Single-flight refresh lock lifetime, and how long a waiter polls.
const REFRESH_LOCK: Duration = Duration::from_secs(10);
const REFRESH_WAIT_STEPS: u32 = 30;
const REFRESH_WAIT_STEP: Duration = Duration::from_millis(100);

/// Why a BFF request failed. Map to HTTP as [`BffError::status`] suggests.
#[derive(Debug, PartialEq, Eq)]
pub enum BffError {
    /// No cookie, an unknown or expired session, or a refresh Sesame refused.
    /// The browser should go to `/auth/start`.
    NoSession,
    /// The callback's `state` is unknown, expired or already used.
    InvalidState,
    /// The user or Sesame ended the sign-in (`error` on the callback).
    Denied(String),
    /// The ID token failed a check; the sign-in is refused.
    InvalidIdToken(&'static str),
    /// `return_to` is not a same-site relative path on the allow-list.
    InvalidReturnTo,
    /// A non-safe request without an allowed `Origin` and the custom header.
    Csrf,
    /// The store or Sesame could not be reached.
    Unavailable(String),
}

impl BffError {
    /// The HTTP status a BFF should answer with.
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Self::NoSession => 401,
            Self::InvalidState
            | Self::Denied(_)
            | Self::InvalidIdToken(_)
            | Self::InvalidReturnTo => 400,
            Self::Csrf => 403,
            Self::Unavailable(_) => 503,
        }
    }
}

impl std::fmt::Display for BffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSession => f.write_str("no session"),
            Self::InvalidState => f.write_str("unknown or expired sign-in state"),
            Self::Denied(e) => write!(f, "sign-in ended: {e}"),
            Self::InvalidIdToken(why) => write!(f, "ID token rejected: {why}"),
            Self::InvalidReturnTo => f.write_str("return_to is not an allowed relative path"),
            Self::Csrf => f.write_str("cross-site request refused"),
            Self::Unavailable(m) => write!(f, "unavailable: {m}"),
        }
    }
}

impl std::error::Error for BffError {}

impl From<StoreError> for BffError {
    fn from(e: StoreError) -> Self {
        Self::Unavailable(e.to_string())
    }
}

/// A browser redirect, optionally setting or clearing the session cookie.
#[derive(Debug, PartialEq, Eq)]
pub struct Redirect {
    pub location: String,
    pub set_cookie: Option<String>,
}

/// A resolved session: what a BFF route needs to call its backends.
pub struct ActiveSession {
    /// `Authorization: Bearer` value for downstream calls. Never send it to the browser.
    pub access_token: String,
    pub subject: String,
    pub tenant_id: Option<String>,
    pub organization_id: Option<String>,
    key: String,
}

impl std::fmt::Debug for ActiveSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActiveSession")
            .field("subject", &self.subject)
            .field("tenant_id", &self.tenant_id)
            .field("organization_id", &self.organization_id)
            .finish_non_exhaustive()
    }
}

/// Verifies an ID token's signature (for example against Sesame's JWKS).
/// Without one, [`Bff::complete_login`] relies on the token arriving directly
/// from the token endpoint over the back channel (OIDC Core 3.1.3.7 item 6)
/// and still checks issuer, audience, nonce and expiry.
pub type IdTokenSignatureCheck = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// The BFF session engine. Cheap to clone and share across coroutines.
#[derive(Clone)]
pub struct Bff {
    config: Arc<BffConfig>,
    store: Arc<dyn SessionStore>,
    idp: Arc<dyn IdentityProvider>,
    signature: Option<IdTokenSignatureCheck>,
    clock: fn() -> u64,
}

fn system_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Bff {
    #[must_use]
    pub fn new(
        config: BffConfig,
        store: Arc<dyn SessionStore>,
        idp: Arc<dyn IdentityProvider>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            store,
            idp,
            signature: None,
            clock: system_now,
        }
    }

    /// The production wiring: Sesame over HTTP.
    #[must_use]
    pub fn with_http(config: BffConfig, store: Arc<dyn SessionStore>) -> Self {
        let idp = Arc::new(HttpIdentityProvider::new(&config));
        Self::new(config, store, idp)
    }

    #[must_use]
    pub fn with_id_token_signature_check(mut self, check: IdTokenSignatureCheck) -> Self {
        self.signature = Some(check);
        self
    }

    #[cfg(test)]
    fn with_clock(mut self, clock: fn() -> u64) -> Self {
        self.clock = clock;
        self
    }

    #[must_use]
    pub fn config(&self) -> &BffConfig {
        &self.config
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    // -- sign-in -------------------------------------------------------------

    /// `GET /auth/start`: record a pre-auth and send the browser to Sesame.
    ///
    /// # Errors
    /// [`BffError::InvalidReturnTo`], or [`BffError::Unavailable`] when the store fails.
    pub fn start_login(&self, return_to: Option<&str>) -> Result<Redirect, BffError> {
        let return_to = match return_to {
            None | Some("") => self.config.default_return_to.clone(),
            Some(r) => self.config.check_return_to(r)?.to_string(),
        };
        let state = crypto::random_token();
        let nonce = crypto::random_token();
        let code_verifier = crypto::random_token();
        let challenge = crypto::pkce_s256(&code_verifier);
        self.store.put_preauth(
            &state,
            &PreAuth {
                code_verifier,
                nonce: nonce.clone(),
                return_to,
                created_at: self.now(),
            },
            self.config.preauth_ttl,
        )?;
        let location = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
            self.config.authorize_url,
            urlencoding::encode(&self.config.client_id),
            urlencoding::encode(&self.config.redirect_uri),
            urlencoding::encode(&self.config.scope),
            state,
            nonce,
            challenge,
        );
        Ok(Redirect {
            location,
            set_cookie: None,
        })
    }

    /// `GET /auth/callback`: redeem the code, check the ID token, create the
    /// session and redirect to the recorded `return_to` with the cookie.
    ///
    /// Pass the callback's `code`, `state` and `error` query parameters.
    ///
    /// # Errors
    /// See [`BffError`]; every error leaves no session behind.
    pub fn complete_login(
        &self,
        code: Option<&str>,
        state: Option<&str>,
        error: Option<&str>,
    ) -> Result<Redirect, BffError> {
        let state = state
            .filter(|s| !s.is_empty())
            .ok_or(BffError::InvalidState)?;
        // Spend the pre-auth first: a state is good for one callback only.
        let pre = self
            .store
            .take_preauth(state)?
            .ok_or(BffError::InvalidState)?;
        if let Some(e) = error.filter(|e| !e.is_empty()) {
            return Err(BffError::Denied(e.chars().take(64).collect()));
        }
        let code = code
            .filter(|c| !c.is_empty())
            .ok_or(BffError::InvalidState)?;
        let tokens = self
            .idp
            .exchange_code(code, &pre.code_verifier)
            .map_err(|e| match e {
                IdpError::Rejected { .. } => BffError::InvalidState,
                IdpError::Unavailable(m) => BffError::Unavailable(m),
            })?;
        let id_token = tokens
            .id_token
            .as_deref()
            .ok_or(BffError::InvalidIdToken("missing"))?;
        let id_claims = self.check_id_token(id_token, &pre.nonce)?;
        let record = self.build_record(&tokens, &id_claims);
        let cookie = self.store_new(&record)?;
        Ok(Redirect {
            location: pre.return_to,
            set_cookie: Some(cookie),
        })
    }

    fn check_id_token(&self, id_token: &str, nonce: &str) -> Result<serde_json::Value, BffError> {
        let claims = crypto::jwt_payload(id_token).ok_or(BffError::InvalidIdToken("malformed"))?;
        if let Some(check) = &self.signature {
            if !check(id_token) {
                return Err(BffError::InvalidIdToken("signature"));
            }
        }
        if claims.get("iss").and_then(|v| v.as_str()) != Some(self.config.issuer.as_str()) {
            return Err(BffError::InvalidIdToken("issuer"));
        }
        let aud_ok = match claims.get("aud") {
            Some(serde_json::Value::String(a)) => *a == self.config.client_id,
            Some(serde_json::Value::Array(a)) => {
                a.iter()
                    .any(|v| v.as_str() == Some(self.config.client_id.as_str()))
                    && claims.get("azp").map_or(a.len() == 1, |azp| {
                        azp.as_str() == Some(self.config.client_id.as_str())
                    })
            }
            _ => false,
        };
        if !aud_ok {
            return Err(BffError::InvalidIdToken("audience"));
        }
        let given = claims.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
        if !crypto::constant_time_eq(given.as_bytes(), nonce.as_bytes()) {
            return Err(BffError::InvalidIdToken("nonce"));
        }
        let now = self.now();
        let exp = claims
            .get("exp")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        if exp + CLOCK_SKEW_SECS <= now {
            return Err(BffError::InvalidIdToken("expired"));
        }
        if let Some(iat) = claims.get("iat").and_then(serde_json::Value::as_u64) {
            if iat > now + CLOCK_SKEW_SECS {
                return Err(BffError::InvalidIdToken("issued in the future"));
            }
        }
        if claims
            .get("sub")
            .and_then(|v| v.as_str())
            .is_none_or(str::is_empty)
        {
            return Err(BffError::InvalidIdToken("subject"));
        }
        Ok(claims)
    }

    /// A session record from fresh tokens. The ID token has been checked; the
    /// access token is only read for routing facts (tenant, organisation) -
    /// backends verify it.
    fn build_record(&self, tokens: &OidcTokens, id_claims: &serde_json::Value) -> SessionRecord {
        let now = self.now();
        let access = crypto::jwt_payload(&tokens.access_token).unwrap_or(serde_json::Value::Null);
        let text = |v: &serde_json::Value, k: &str| {
            v.get(k)
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        SessionRecord {
            access_token: tokens.access_token.clone(),
            refresh_token: tokens.refresh_token.clone(),
            id_token: tokens.id_token.clone(),
            access_expires_at: now + tokens.expires_in,
            subject: text(id_claims, "sub").unwrap_or_default(),
            tenant_id: text(&access, "tenant_id").or_else(|| text(id_claims, "tenant_id")),
            organization_id: text(&access, "org_id").or_else(|| text(id_claims, "org_id")),
            created_at: now,
            last_seen: now,
            absolute_expires_at: now + self.config.absolute_timeout.as_secs(),
        }
    }

    /// Store a record under a new random id; returns the `Set-Cookie` value.
    fn store_new(&self, record: &SessionRecord) -> Result<String, BffError> {
        let cookie_value = crypto::random_token();
        let key = crypto::session_key(&cookie_value);
        self.store.put_session(&key, record, self.ttl(record))?;
        self.store.index_session(
            &self.subject_key(record),
            &key,
            self.config.absolute_timeout,
        )?;
        Ok(self.cookie(&cookie_value, record))
    }

    fn subject_key(&self, record: &SessionRecord) -> String {
        format!(
            "{}:{}",
            record.tenant_id.as_deref().unwrap_or("-"),
            record.subject
        )
    }

    /// Store TTL: the sliding idle window, capped by the absolute expiry.
    fn ttl(&self, record: &SessionRecord) -> Duration {
        let remaining = record.absolute_expires_at.saturating_sub(self.now());
        Duration::from_secs(remaining.min(self.config.idle_timeout.as_secs()).max(1))
    }

    fn cookie(&self, value: &str, record: &SessionRecord) -> String {
        let max_age = record.absolute_expires_at.saturating_sub(self.now());
        format!(
            "{}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}",
            self.config.cookie_name
        )
    }

    /// A `Set-Cookie` value that removes the session cookie.
    #[must_use]
    pub fn clear_cookie(&self) -> String {
        format!(
            "{}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
            self.config.cookie_name
        )
    }

    // -- requests ------------------------------------------------------------

    /// CSRF for non-safe methods (ADR-014 §2.5): `Origin` must be on the
    /// allow-list and the custom header must be present with its value.
    /// `header` looks a request header up case-insensitively.
    ///
    /// # Errors
    /// [`BffError::Csrf`].
    pub fn check_csrf<'a>(
        &self,
        method: &str,
        header: impl Fn(&str) -> Option<&'a str>,
    ) -> Result<(), BffError> {
        if matches!(
            method.to_ascii_uppercase().as_str(),
            "GET" | "HEAD" | "OPTIONS"
        ) {
            return Ok(());
        }
        let origin_ok = header("origin")
            .is_some_and(|o| self.config.allowed_origins.iter().any(|a| a == o.trim()));
        let (name, value) = &self.config.csrf_header;
        let marker_ok = header(name).is_some_and(|v| v.trim() == value);
        if origin_ok && marker_ok {
            Ok(())
        } else {
            Err(BffError::Csrf)
        }
    }

    /// Resolve the session cookie from a `Cookie` header: touch the idle
    /// timer, refresh the access token when it is about to expire (one
    /// refresh per session at a time), and return the bearer for downstream.
    ///
    /// # Errors
    /// [`BffError::NoSession`] when the browser must sign in again;
    /// [`BffError::Unavailable`] when the store or Sesame cannot be reached.
    pub fn resolve(&self, cookie_header: Option<&str>) -> Result<ActiveSession, BffError> {
        let value = cookie_header
            .and_then(|h| crypto::cookie_value(h, &self.config.cookie_name))
            .filter(|v| crypto::looks_like_token(v))
            .ok_or(BffError::NoSession)?;
        let key = crypto::session_key(value);
        let mut record = self.store.get_session(&key)?.ok_or(BffError::NoSession)?;
        let now = self.now();
        if now >= record.absolute_expires_at {
            self.end(&key, &record);
            return Err(BffError::NoSession);
        }
        let mut dirty = false;
        if record.access_expires_at <= now + REFRESH_LEEWAY_SECS {
            record = self.refresh(&key, record)?;
        } else if now >= record.last_seen + TOUCH_INTERVAL_SECS {
            record.last_seen = now;
            dirty = true;
        }
        if dirty {
            self.store.put_session(&key, &record, self.ttl(&record))?;
        }
        Ok(ActiveSession {
            access_token: record.access_token,
            subject: record.subject,
            tenant_id: record.tenant_id,
            organization_id: record.organization_id,
            key,
        })
    }

    fn refresh(&self, key: &str, record: SessionRecord) -> Result<SessionRecord, BffError> {
        let lock = format!("refresh:{key}");
        if self.store.try_lock(&lock, REFRESH_LOCK)? {
            let result = self.refresh_locked(key);
            let _ = self.store.unlock(&lock);
            return result;
        }
        // Another request is refreshing this session: wait for its result.
        let before = record.access_expires_at;
        for _ in 0..REFRESH_WAIT_STEPS {
            may::coroutine::sleep(REFRESH_WAIT_STEP);
            match self.store.get_session(key)? {
                None => return Err(BffError::NoSession),
                Some(r) if r.access_expires_at != before => return Ok(r),
                Some(_) => {}
            }
        }
        // Still being refreshed: the current token is usable until it expires.
        if record.access_expires_at > self.now() {
            Ok(record)
        } else {
            Err(BffError::Unavailable("session refresh in progress".into()))
        }
    }

    fn refresh_locked(&self, key: &str) -> Result<SessionRecord, BffError> {
        // Re-read under the lock: a refresh may have just finished.
        let mut record = self.store.get_session(key)?.ok_or(BffError::NoSession)?;
        if record.access_expires_at > self.now() + REFRESH_LEEWAY_SECS {
            return Ok(record);
        }
        let Some(refresh_token) = record.refresh_token.clone() else {
            self.end(key, &record);
            return Err(BffError::NoSession);
        };
        match self.idp.refresh(&refresh_token) {
            Ok(tokens) => {
                let now = self.now();
                record.access_token = tokens.access_token;
                record.access_expires_at = now + tokens.expires_in;
                if tokens.refresh_token.is_some() {
                    record.refresh_token = tokens.refresh_token;
                }
                if tokens.id_token.is_some() {
                    record.id_token = tokens.id_token;
                }
                if let Some(access) = crypto::jwt_payload(&record.access_token) {
                    if let Some(org) = access.get("org_id").and_then(|v| v.as_str()) {
                        record.organization_id = Some(org.to_string()).filter(|s| !s.is_empty());
                    }
                }
                record.last_seen = now;
                self.store.put_session(key, &record, self.ttl(&record))?;
                Ok(record)
            }
            Err(IdpError::Rejected { .. }) => {
                // Revoked, expired or reused: the session is over.
                self.end(key, &record);
                Err(BffError::NoSession)
            }
            Err(IdpError::Unavailable(m)) => {
                if record.access_expires_at > self.now() {
                    Ok(record)
                } else {
                    Err(BffError::Unavailable(m))
                }
            }
        }
    }

    /// Replace the session's tokens after a privilege change (organisation
    /// switch, step-up) and rotate its id (ADR-014 §2.3, fixation). Returns
    /// the new `Set-Cookie`; the old cookie stops working.
    ///
    /// # Errors
    /// [`BffError::InvalidIdToken`] when `tokens` carries no subject;
    /// [`BffError::Unavailable`] when the store fails.
    pub fn rotate(&self, session: &ActiveSession, tokens: &OidcTokens) -> Result<String, BffError> {
        let old = self
            .store
            .get_session(&session.key)?
            .ok_or(BffError::NoSession)?;
        let id_claims = tokens
            .id_token
            .as_deref()
            .and_then(crypto::jwt_payload)
            .unwrap_or_else(|| serde_json::json!({ "sub": old.subject }));
        if id_claims.get("sub").and_then(|v| v.as_str()) != Some(old.subject.as_str()) {
            return Err(BffError::InvalidIdToken("subject"));
        }
        let mut record = self.build_record(tokens, &id_claims);
        if record.refresh_token.is_none() {
            record.refresh_token = old.refresh_token.clone();
        }
        // Keep the original sign-in's absolute expiry: rotation is not a new sign-in.
        record.created_at = old.created_at;
        record.absolute_expires_at = old.absolute_expires_at;
        let cookie = self.store_new(&record)?;
        self.store.delete_session(&session.key)?;
        let _ = self
            .store
            .unindex_session(&self.subject_key(&old), &session.key);
        Ok(cookie)
    }

    // -- sign-out ------------------------------------------------------------

    /// `POST /auth/logout`: revoke at Sesame, delete the session, clear the
    /// cookie and send the browser to Sesame's end-session endpoint when one
    /// is configured (otherwise to `post_logout_redirect`).
    ///
    /// Logout always succeeds for the browser: an unknown cookie still gets a
    /// cleared cookie and the redirect.
    #[must_use]
    pub fn logout(&self, cookie_header: Option<&str>) -> Redirect {
        let mut id_token_hint = None;
        if let Some(value) = cookie_header
            .and_then(|h| crypto::cookie_value(h, &self.config.cookie_name))
            .filter(|v| crypto::looks_like_token(v))
        {
            let key = crypto::session_key(value);
            if let Ok(Some(record)) = self.store.get_session(&key) {
                id_token_hint = record.id_token.clone();
                self.end(&key, &record);
            }
        }
        Redirect {
            location: self.logout_location(id_token_hint.as_deref()),
            set_cookie: Some(self.clear_cookie()),
        }
    }

    /// "Sign out everywhere": end every session of this subject at this BFF.
    /// Returns how many were ended.
    ///
    /// # Errors
    /// [`BffError::Unavailable`] when the store fails.
    pub fn logout_everywhere(&self, session: &ActiveSession) -> Result<usize, BffError> {
        let subject_key = format!(
            "{}:{}",
            session.tenant_id.as_deref().unwrap_or("-"),
            session.subject
        );
        let keys = self.store.indexed_sessions(&subject_key)?;
        let mut ended = 0;
        for key in keys {
            match self.store.get_session(&key)? {
                Some(record) => {
                    self.end(&key, &record);
                    ended += 1;
                }
                None => {
                    let _ = self.store.unindex_session(&subject_key, &key);
                }
            }
        }
        Ok(ended)
    }

    fn logout_location(&self, id_token_hint: Option<&str>) -> String {
        match &self.config.end_session_url {
            Some(url) => {
                let mut l = format!(
                    "{url}?client_id={}&post_logout_redirect_uri={}",
                    urlencoding::encode(&self.config.client_id),
                    urlencoding::encode(&self.config.post_logout_redirect),
                );
                if let Some(hint) = id_token_hint {
                    l.push_str("&id_token_hint=");
                    l.push_str(&urlencoding::encode(hint));
                }
                l
            }
            None => self.config.post_logout_redirect.clone(),
        }
    }

    /// Revoke (best effort) and delete a session.
    fn end(&self, key: &str, record: &SessionRecord) {
        let _ = self
            .idp
            .revoke(&record.access_token, record.refresh_token.as_deref());
        let _ = self.store.delete_session(key);
        let _ = self.store.unindex_session(&self.subject_key(record), key);
    }
}

#[cfg(test)]
mod tests;
