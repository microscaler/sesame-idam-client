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
    use may_redis::{CommandBuilder, FromRedisValue, RedisClient};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// Redis-backed store on `may_redis`, a may-native client: commands go over a `may::net` socket
    /// with a coroutine-aware wait, so a request coroutine parks while its command runs and the may
    /// worker keeps running the other requests. One multiplexed connection serves every coroutine;
    /// the lock around it is a may lock held only to fetch or replace the client, never across a
    /// command or a call to Sesame. The Redis host is resolved by `brrtrouter::net` (off the worker
    /// threads) and the connection is made to the address.
    ///
    /// A dead connection (Redis restarted, an idle cut) is replaced on the next call, and a call
    /// that fails on a connection that died under it is retried once on the new one.
    ///
    /// Each call is timed in `sesame_bff_store_seconds{op}` ([`crate::bff::render_prometheus`]).
    ///
    /// Keys are `{prefix}pre:{state}`, `{prefix}s:{hash}`, `{prefix}u:{subject}`
    /// and `{prefix}lock:{name}`. Give each BFF its own prefix or database.
    pub struct RedisStore {
        inner: Arc<Inner>,
        prefix: String,
    }

    /// Where and how to connect: from the `redis://` URL.
    struct Target {
        host: String,
        port: u16,
        user: Option<String>,
        password: Option<String>,
        db: u32,
    }

    struct Inner {
        target: Target,
        timeout: Duration,
        client: may::sync::Mutex<Option<RedisClient>>,
    }

    fn percent_decode(s: &str) -> String {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
            out.push(b[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// `redis://[[user]:password@]host[:port][/db]`. TLS (`rediss://`) is not supported here.
    fn parse_url(url: &str) -> Result<Target, StoreError> {
        let rest = url.trim().strip_prefix("redis://").ok_or_else(|| {
            StoreError(format!(
                "session store URL must be redis://..., got a {} URL",
                url.split(':').next().unwrap_or("")
            ))
        })?;
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let (creds, hostport) = match authority.rfind('@') {
            Some(i) => (Some(&authority[..i]), &authority[i + 1..]),
            None => (None, authority),
        };
        let (user, password) = match creds {
            Some(c) => match c.split_once(':') {
                Some((u, p)) => (
                    (!u.is_empty()).then(|| percent_decode(u)),
                    Some(percent_decode(p)),
                ),
                None => (None, Some(percent_decode(c))),
            },
            None => (None, None),
        };
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) if !p.contains(']') => (
                h.trim_matches(|c| c == '[' || c == ']').to_string(),
                p.parse::<u16>()
                    .map_err(|_| StoreError("bad port in the session store URL".into()))?,
            ),
            _ => (
                hostport.trim_matches(|c| c == '[' || c == ']').to_string(),
                6379,
            ),
        };
        if host.is_empty() {
            return Err(StoreError("no host in the session store URL".into()));
        }
        let db = path
            .split('?')
            .next()
            .filter(|d| !d.is_empty())
            .map(|d| d.parse::<u32>())
            .transpose()
            .map_err(|_| StoreError("bad database number in the session store URL".into()))?
            .unwrap_or(0);
        Ok(Target {
            host,
            port,
            user,
            password,
            db,
        })
    }

    impl RedisStore {
        /// Nothing connects here: the first call does.
        ///
        /// # Errors
        /// When `url` is not a `redis://` URL.
        pub fn new(url: &str, prefix: &str, timeout: Duration) -> Result<Self, StoreError> {
            Ok(Self {
                inner: Arc::new(Inner {
                    target: parse_url(url)?,
                    timeout,
                    client: may::sync::Mutex::new(None),
                }),
                prefix: prefix.to_string(),
            })
        }

        /// Run `f` against the shared client and time it as `op`. A failure on a connection that
        /// has died is retried once on a fresh one.
        fn with<T>(
            &self,
            op: &'static str,
            f: impl Fn(&RedisClient) -> Result<T, may_redis::RedisError>,
        ) -> Result<T, StoreError> {
            let started = Instant::now();
            // Only a kept connection is retried: one the server closed while it sat idle fails its
            // next command (pp, Oct 2026). A connection opened for this call that fails is a real
            // failure and is returned as is.
            let result = self.inner.client().and_then(|(c, reused)| match f(&c) {
                Ok(v) => Ok(v),
                Err(e) if reused && !c.is_alive() => {
                    let (fresh, _) = self.inner.client()?;
                    f(&fresh).map_err(|e2| StoreError(format!("{e2} (after {e})")))
                }
                Err(e) => Err(StoreError(e.to_string())),
            });
            crate::bff::metrics::observe(op, started.elapsed(), result.is_ok());
            result
        }

        fn key(&self, kind: &str, id: &str) -> String {
            format!("{}{kind}:{id}", self.prefix)
        }
    }

    impl Inner {
        /// The live client and whether it was kept from an earlier call, connecting (or
        /// replacing a dead one) first if needed.
        fn client(&self) -> Result<(RedisClient, bool), StoreError> {
            let mut slot = self
                .client
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(c) = slot.as_ref().filter(|c| c.is_alive()) {
                return Ok((c.clone(), true));
            }
            *slot = None;
            let c = self.connect()?;
            *slot = Some(c.clone());
            Ok((c, false))
        }

        fn connect(&self) -> Result<RedisClient, StoreError> {
            let t = &self.target;
            let addrs = brrtrouter::net::resolve(&t.host, t.port, self.timeout)
                .map_err(|e| StoreError(format!("session store: {e}")))?;
            let mut last = String::from("no address");
            for addr in addrs {
                match RedisClient::connect_with_timeout(
                    &addr.ip().to_string(),
                    addr.port(),
                    self.timeout,
                ) {
                    Ok(client) => {
                        if let Some(pass) = &t.password {
                            let mut auth = CommandBuilder::new("AUTH");
                            if let Some(user) = &t.user {
                                auth = auth.arg(user.as_str());
                            }
                            client
                                .execute::<String>(auth.arg(pass.as_str()))
                                .map_err(|e| StoreError(format!("session store AUTH: {e}")))?;
                        }
                        if t.db != 0 {
                            client
                                .execute::<String>(
                                    CommandBuilder::new("SELECT").arg(t.db.to_string()),
                                )
                                .map_err(|e| StoreError(format!("session store SELECT: {e}")))?;
                        }
                        return Ok(client);
                    }
                    Err(e) => last = e.to_string(),
                }
            }
            Err(StoreError(format!(
                "session store {}:{}: {last}",
                t.host, t.port
            )))
        }
    }

    fn ms(d: Duration) -> String {
        u64::try_from(d.as_millis())
            .unwrap_or(u64::MAX)
            .max(1)
            .to_string()
    }

    fn decode<T: serde::de::DeserializeOwned>(
        raw: Option<String>,
    ) -> Result<Option<T>, StoreError> {
        raw.map(|s| serde_json::from_str(&s).map_err(|e| StoreError(e.to_string())))
            .transpose()
    }

    fn exec<T: FromRedisValue>(
        c: &RedisClient,
        cmd: CommandBuilder,
    ) -> Result<T, may_redis::RedisError> {
        c.execute::<T>(cmd)
    }

    impl SessionStore for RedisStore {
        fn put_preauth(
            &self,
            state: &str,
            record: &PreAuth,
            ttl: Duration,
        ) -> Result<(), StoreError> {
            let v = serde_json::to_string(record).map_err(|e| StoreError(e.to_string()))?;
            let (k, px) = (self.key("pre", state), ms(ttl));
            self.with("put_preauth", |c| {
                exec::<String>(
                    c,
                    CommandBuilder::new("SET")
                        .arg(k.as_str())
                        .arg(v.as_str())
                        .arg("PX")
                        .arg(px.as_str()),
                )
                .map(|_| ())
            })
        }

        fn take_preauth(&self, state: &str) -> Result<Option<PreAuth>, StoreError> {
            let k = self.key("pre", state);
            decode(self.with("take_preauth", |c| {
                exec::<Option<String>>(c, CommandBuilder::new("GETDEL").arg(k.as_str()))
            })?)
        }

        fn put_session(
            &self,
            key: &str,
            record: &SessionRecord,
            ttl: Duration,
        ) -> Result<(), StoreError> {
            let v = serde_json::to_string(record).map_err(|e| StoreError(e.to_string()))?;
            let (k, px) = (self.key("s", key), ms(ttl));
            self.with("put_session", |c| {
                exec::<String>(
                    c,
                    CommandBuilder::new("SET")
                        .arg(k.as_str())
                        .arg(v.as_str())
                        .arg("PX")
                        .arg(px.as_str()),
                )
                .map(|_| ())
            })
        }

        fn get_session(&self, key: &str) -> Result<Option<SessionRecord>, StoreError> {
            let k = self.key("s", key);
            decode(self.with("get_session", |c| {
                exec::<Option<String>>(c, CommandBuilder::new("GET").arg(k.as_str()))
            })?)
        }

        fn delete_session(&self, key: &str) -> Result<(), StoreError> {
            let k = self.key("s", key);
            self.with("delete_session", |c| {
                exec::<i64>(c, CommandBuilder::new("DEL").arg(k.as_str())).map(|_| ())
            })
        }

        fn index_session(
            &self,
            subject_key: &str,
            key: &str,
            ttl: Duration,
        ) -> Result<(), StoreError> {
            let (k, px) = (self.key("u", subject_key), ms(ttl));
            self.with("index_session", |c| {
                let mut p = c.pipeline();
                p.add(CommandBuilder::new("SADD").arg(k.as_str()).arg(key));
                // The newest session lives longest, so its TTL covers the set.
                p.add(
                    CommandBuilder::new("PEXPIRE")
                        .arg(k.as_str())
                        .arg(px.as_str()),
                );
                p.execute_raw().map(|_| ())
            })
        }

        fn unindex_session(&self, subject_key: &str, key: &str) -> Result<(), StoreError> {
            let k = self.key("u", subject_key);
            self.with("unindex_session", |c| {
                exec::<i64>(c, CommandBuilder::new("SREM").arg(k.as_str()).arg(key)).map(|_| ())
            })
        }

        fn indexed_sessions(&self, subject_key: &str) -> Result<Vec<String>, StoreError> {
            let k = self.key("u", subject_key);
            self.with("indexed_sessions", |c| {
                exec::<Vec<String>>(c, CommandBuilder::new("SMEMBERS").arg(k.as_str()))
            })
        }

        fn try_lock(&self, name: &str, ttl: Duration) -> Result<bool, StoreError> {
            let (k, px) = (self.key("lock", name), ms(ttl));
            let set: Option<String> = self.with("try_lock", |c| {
                exec::<Option<String>>(
                    c,
                    CommandBuilder::new("SET")
                        .arg(k.as_str())
                        .arg("1")
                        .arg("NX")
                        .arg("PX")
                        .arg(px.as_str()),
                )
            })?;
            Ok(set.is_some())
        }

        fn unlock(&self, name: &str) -> Result<(), StoreError> {
            let k = self.key("lock", name);
            self.with("unlock", |c| {
                exec::<i64>(c, CommandBuilder::new("DEL").arg(k.as_str())).map(|_| ())
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::parse_url;
        use super::RedisStore;
        use crate::bff::SessionStore;
        use std::sync::Arc;
        use std::time::Duration;

        /// Many coroutines at once against a real Redis (`SESAME_TEST_REDIS_URL=redis://...`):
        /// locks, the index pipeline and deletes on one multiplexed connection.
        #[test]
        #[ignore = "needs a Redis: SESAME_TEST_REDIS_URL=redis://host:port"]
        fn concurrent_calls_against_a_real_redis() {
            let url = std::env::var("SESAME_TEST_REDIS_URL").expect("SESAME_TEST_REDIS_URL");
            let store =
                Arc::new(RedisStore::new(&url, "sic-test:", Duration::from_secs(2)).unwrap());
            let handles: Vec<_> = (0..200)
                .map(|i| {
                    let s = Arc::clone(&store);
                    may::go!(move || {
                        let lock = format!("l{i}");
                        assert!(s.try_lock(&lock, Duration::from_secs(5)).unwrap());
                        assert!(!s.try_lock(&lock, Duration::from_secs(5)).unwrap());
                        s.unlock(&lock).unwrap();
                        let subject = format!("u{}", i % 10);
                        s.index_session(&subject, &format!("k{i}"), Duration::from_secs(60))
                            .unwrap();
                        assert!(s
                            .indexed_sessions(&subject)
                            .unwrap()
                            .contains(&format!("k{i}")));
                        s.unindex_session(&subject, &format!("k{i}")).unwrap();
                        s.delete_session(&format!("k{i}")).unwrap();
                        assert!(s.get_session(&format!("k{i}")).unwrap().is_none());
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }
        }

        #[test]
        fn redis_urls_parse() {
            let t = parse_url("redis://:p%40ss@redis-hot.pw.svc.cluster.local:6380/2").unwrap();
            assert_eq!(t.host, "redis-hot.pw.svc.cluster.local");
            assert_eq!(t.port, 6380);
            assert_eq!(t.user, None);
            assert_eq!(t.password.as_deref(), Some("p@ss"));
            assert_eq!(t.db, 2);
            let t = parse_url("redis://bff:secret@10.0.0.5").unwrap();
            assert_eq!((t.host.as_str(), t.port, t.db), ("10.0.0.5", 6379, 0));
            assert_eq!(t.user.as_deref(), Some("bff"));
            let t = parse_url("redis://[::1]:7000").unwrap();
            assert_eq!((t.host.as_str(), t.port), ("::1", 7000));
            assert!(parse_url("rediss://h:1").is_err());
            assert!(parse_url("redis://:pw@:1").is_err());
        }
    }
}
