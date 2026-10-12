//! Session storage for relying-party BFFs (ADR-014 §2.3).
//!
//! Two kinds of record, both with a TTL:
//!
//! - **pre-auth**, keyed by the OAuth `state`: the PKCE verifier, nonce and
//!   `return_to` of a sign-in in progress. Read once ([`SessionStore::take_preauth`]).
//! - **session**, keyed by the SHA-256 of the cookie value: tokens and subject.
//!   The store never sees a usable cookie, so a dump of it cannot be replayed
//!   as a browser session.
//!
//! [`MemoryStore`] serves tests and single-replica development;
//! `RedisStore` (feature `redis-store`) is the production store.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// A sign-in in progress, between `/auth/start` and `/auth/callback`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreAuth {
    pub code_verifier: String,
    pub nonce: String,
    pub return_to: String,
    pub created_at: u64,
}

/// A signed-in browser session. Stored server-side only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    /// Unix seconds at which the access token expires.
    pub access_expires_at: u64,
    pub subject: String,
    pub tenant_id: Option<String>,
    pub organization_id: Option<String>,
    pub created_at: u64,
    pub last_seen: u64,
    /// Unix seconds after which the session ends regardless of activity.
    pub absolute_expires_at: u64,
}

impl std::fmt::Debug for SessionRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionRecord")
            .field("subject", &self.subject)
            .field("tenant_id", &self.tenant_id)
            .field("organization_id", &self.organization_id)
            .field("access_expires_at", &self.access_expires_at)
            .field("absolute_expires_at", &self.absolute_expires_at)
            .finish_non_exhaustive()
    }
}

/// The store could not be reached or returned something unreadable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "session store: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

/// Storage behind a BFF. Implementations must be safe to share across
/// coroutines and replicas: `take_preauth` is atomic (one callback wins) and
/// `try_lock` is a cross-replica mutex with expiry.
pub trait SessionStore: Send + Sync {
    fn put_preauth(&self, state: &str, record: &PreAuth, ttl: Duration) -> Result<(), StoreError>;
    /// Read and delete in one step.
    fn take_preauth(&self, state: &str) -> Result<Option<PreAuth>, StoreError>;

    fn put_session(
        &self,
        key: &str,
        record: &SessionRecord,
        ttl: Duration,
    ) -> Result<(), StoreError>;
    fn get_session(&self, key: &str) -> Result<Option<SessionRecord>, StoreError>;
    fn delete_session(&self, key: &str) -> Result<(), StoreError>;

    /// Index a session under its subject, for "sign out everywhere".
    fn index_session(&self, subject_key: &str, key: &str, ttl: Duration) -> Result<(), StoreError>;
    fn unindex_session(&self, subject_key: &str, key: &str) -> Result<(), StoreError>;
    fn indexed_sessions(&self, subject_key: &str) -> Result<Vec<String>, StoreError>;

    /// Acquire `name` for `ttl` if nobody holds it. Returns whether acquired.
    fn try_lock(&self, name: &str, ttl: Duration) -> Result<bool, StoreError>;
    fn unlock(&self, name: &str) -> Result<(), StoreError>;
}

// ---------------------------------------------------------------------------
// In-memory store
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MemoryInner {
    preauth: HashMap<String, (PreAuth, std::time::Instant)>,
    sessions: HashMap<String, (SessionRecord, std::time::Instant)>,
    index: HashMap<String, HashSet<String>>,
    locks: HashMap<String, std::time::Instant>,
}

/// Process-local store. Not shared across replicas; for tests and development.
#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<MemoryInner>,
}

impl MemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemoryInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn deadline(ttl: Duration) -> std::time::Instant {
    std::time::Instant::now() + ttl
}

fn live(at: std::time::Instant) -> bool {
    std::time::Instant::now() < at
}

impl SessionStore for MemoryStore {
    fn put_preauth(&self, state: &str, record: &PreAuth, ttl: Duration) -> Result<(), StoreError> {
        self.lock()
            .preauth
            .insert(state.to_string(), (record.clone(), deadline(ttl)));
        Ok(())
    }

    fn take_preauth(&self, state: &str) -> Result<Option<PreAuth>, StoreError> {
        Ok(self
            .lock()
            .preauth
            .remove(state)
            .filter(|(_, at)| live(*at))
            .map(|(r, _)| r))
    }

    fn put_session(
        &self,
        key: &str,
        record: &SessionRecord,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        self.lock()
            .sessions
            .insert(key.to_string(), (record.clone(), deadline(ttl)));
        Ok(())
    }

    fn get_session(&self, key: &str) -> Result<Option<SessionRecord>, StoreError> {
        let mut inner = self.lock();
        match inner.sessions.get(key) {
            Some((r, at)) if live(*at) => Ok(Some(r.clone())),
            Some(_) => {
                inner.sessions.remove(key);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    fn delete_session(&self, key: &str) -> Result<(), StoreError> {
        self.lock().sessions.remove(key);
        Ok(())
    }

    fn index_session(
        &self,
        subject_key: &str,
        key: &str,
        _ttl: Duration,
    ) -> Result<(), StoreError> {
        self.lock()
            .index
            .entry(subject_key.to_string())
            .or_default()
            .insert(key.to_string());
        Ok(())
    }

    fn unindex_session(&self, subject_key: &str, key: &str) -> Result<(), StoreError> {
        let mut inner = self.lock();
        if let Some(set) = inner.index.get_mut(subject_key) {
            set.remove(key);
            if set.is_empty() {
                inner.index.remove(subject_key);
            }
        }
        Ok(())
    }

    fn indexed_sessions(&self, subject_key: &str) -> Result<Vec<String>, StoreError> {
        Ok(self
            .lock()
            .index
            .get(subject_key)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default())
    }

    fn try_lock(&self, name: &str, ttl: Duration) -> Result<bool, StoreError> {
        let mut inner = self.lock();
        match inner.locks.get(name) {
            Some(at) if live(*at) => Ok(false),
            _ => {
                inner.locks.insert(name.to_string(), deadline(ttl));
                Ok(true)
            }
        }
    }

    fn unlock(&self, name: &str) -> Result<(), StoreError> {
        self.lock().locks.remove(name);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Redis store
// ---------------------------------------------------------------------------

#[cfg(feature = "redis-store")]
pub use redis_store::RedisStore;

#[cfg(feature = "redis-store")]
mod redis_store {
    use super::{PreAuth, SessionRecord, SessionStore, StoreError};
    use std::sync::Mutex;
    use std::time::Duration;

    /// Redis-backed store. Synchronous connections with timeouts, sharded
    /// behind mutexes (the same pattern as Sesame's token-status lookup), so a
    /// slow Redis bounds request latency rather than piling up coroutines.
    ///
    /// Keys are `{prefix}pre:{state}`, `{prefix}s:{hash}`, `{prefix}u:{subject}`
    /// and `{prefix}lock:{name}`. Give each BFF its own prefix or database.
    pub struct RedisStore {
        client: redis::Client,
        prefix: String,
        timeout: Duration,
        shards: Vec<Mutex<Option<redis::Connection>>>,
    }

    impl RedisStore {
        /// # Errors
        /// When `url` is not a valid Redis URL.
        pub fn new(url: &str, prefix: &str, timeout: Duration) -> Result<Self, StoreError> {
            let client = redis::Client::open(url).map_err(|e| StoreError(e.to_string()))?;
            Ok(Self {
                client,
                prefix: prefix.to_string(),
                timeout,
                shards: (0..8).map(|_| Mutex::new(None)).collect(),
            })
        }

        fn with<T>(
            &self,
            route: &str,
            f: impl Fn(&mut redis::Connection) -> redis::RedisResult<T>,
        ) -> Result<T, StoreError> {
            let idx = route
                .bytes()
                .fold(0usize, |a, b| a.wrapping_mul(31).wrapping_add(b as usize))
                % self.shards.len();
            let mut slot = self.shards[idx]
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if slot.is_none() {
                let conn = self
                    .client
                    .get_connection_with_timeout(self.timeout)
                    .map_err(|e| StoreError(e.to_string()))?;
                conn.set_read_timeout(Some(self.timeout))
                    .and_then(|()| conn.set_write_timeout(Some(self.timeout)))
                    .map_err(|e| StoreError(e.to_string()))?;
                *slot = Some(conn);
            }
            let conn = slot.as_mut().expect("connection just set");
            match f(conn) {
                Ok(v) => Ok(v),
                Err(e) => {
                    // Drop the connection on I/O trouble; the next call reconnects.
                    if e.is_io_error() || e.is_timeout() || e.is_connection_dropped() {
                        *slot = None;
                    }
                    Err(StoreError(e.to_string()))
                }
            }
        }

        fn key(&self, kind: &str, id: &str) -> String {
            format!("{}{kind}:{id}", self.prefix)
        }
    }

    fn ms(d: Duration) -> u64 {
        u64::try_from(d.as_millis()).unwrap_or(u64::MAX).max(1)
    }

    fn decode<T: serde::de::DeserializeOwned>(
        raw: Option<String>,
    ) -> Result<Option<T>, StoreError> {
        raw.map(|s| serde_json::from_str(&s).map_err(|e| StoreError(e.to_string())))
            .transpose()
    }

    impl SessionStore for RedisStore {
        fn put_preauth(
            &self,
            state: &str,
            record: &PreAuth,
            ttl: Duration,
        ) -> Result<(), StoreError> {
            let k = self.key("pre", state);
            let v = serde_json::to_string(record).map_err(|e| StoreError(e.to_string()))?;
            self.with(&k, |c| {
                redis::cmd("SET")
                    .arg(&k)
                    .arg(&v)
                    .arg("PX")
                    .arg(ms(ttl))
                    .query(c)
            })
        }

        fn take_preauth(&self, state: &str) -> Result<Option<PreAuth>, StoreError> {
            let k = self.key("pre", state);
            decode(self.with(&k, |c| redis::cmd("GETDEL").arg(&k).query(c))?)
        }

        fn put_session(
            &self,
            key: &str,
            record: &SessionRecord,
            ttl: Duration,
        ) -> Result<(), StoreError> {
            let k = self.key("s", key);
            let v = serde_json::to_string(record).map_err(|e| StoreError(e.to_string()))?;
            self.with(&k, |c| {
                redis::cmd("SET")
                    .arg(&k)
                    .arg(&v)
                    .arg("PX")
                    .arg(ms(ttl))
                    .query(c)
            })
        }

        fn get_session(&self, key: &str) -> Result<Option<SessionRecord>, StoreError> {
            let k = self.key("s", key);
            decode(self.with(&k, |c| redis::cmd("GET").arg(&k).query(c))?)
        }

        fn delete_session(&self, key: &str) -> Result<(), StoreError> {
            let k = self.key("s", key);
            self.with(&k, |c| redis::cmd("DEL").arg(&k).query(c))
        }

        fn index_session(
            &self,
            subject_key: &str,
            key: &str,
            ttl: Duration,
        ) -> Result<(), StoreError> {
            let k = self.key("u", subject_key);
            self.with(&k, |c| {
                redis::pipe()
                    .cmd("SADD")
                    .arg(&k)
                    .arg(key)
                    .ignore()
                    // The newest session lives longest, so its TTL covers the set.
                    .cmd("PEXPIRE")
                    .arg(&k)
                    .arg(ms(ttl))
                    .ignore()
                    .query(c)
            })
        }

        fn unindex_session(&self, subject_key: &str, key: &str) -> Result<(), StoreError> {
            let k = self.key("u", subject_key);
            self.with(&k, |c| redis::cmd("SREM").arg(&k).arg(key).query(c))
        }

        fn indexed_sessions(&self, subject_key: &str) -> Result<Vec<String>, StoreError> {
            let k = self.key("u", subject_key);
            self.with(&k, |c| redis::cmd("SMEMBERS").arg(&k).query(c))
        }

        fn try_lock(&self, name: &str, ttl: Duration) -> Result<bool, StoreError> {
            let k = self.key("lock", name);
            let set: Option<String> = self.with(&k, |c| {
                redis::cmd("SET")
                    .arg(&k)
                    .arg("1")
                    .arg("NX")
                    .arg("PX")
                    .arg(ms(ttl))
                    .query(c)
            })?;
            Ok(set.is_some())
        }

        fn unlock(&self, name: &str) -> Result<(), StoreError> {
            let k = self.key("lock", name);
            self.with(&k, |c| redis::cmd("DEL").arg(&k).query(c))
        }
    }
}
