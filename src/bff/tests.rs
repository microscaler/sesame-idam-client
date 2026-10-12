//! Flow tests against an in-memory store and a fake Sesame, following the
//! conformance list of ADR-014 §5.

use std::cell::Cell;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use super::config::tests::config;
use super::*;

thread_local! {
    static NOW: Cell<u64> = const { Cell::new(1_800_000_000) };
}

fn now() -> u64 {
    NOW.with(Cell::get)
}

fn advance(secs: u64) {
    NOW.with(|n| n.set(n.get() + secs));
}

fn jwt(claims: &serde_json::Value) -> String {
    format!(
        "eyJhbGciOiJSUzI1NiJ9.{}.c2ln",
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

/// Fake Sesame: remembers the last verifier, issues numbered tokens, rotates
/// refresh tokens and refuses spent ones.
#[derive(Default)]
struct FakeIdp {
    nonce: Mutex<String>,
    id_overrides: Mutex<serde_json::Value>,
    issued: Mutex<u32>,
    live_refresh: Mutex<Vec<String>>,
    revoked: Mutex<Vec<String>>,
    verifiers: Mutex<Vec<String>>,
    refresh_calls: Mutex<u32>,
    down: Mutex<bool>,
}

impl FakeIdp {
    fn tokens(&self, org: &str) -> OidcTokens {
        let mut n = self.issued.lock().unwrap();
        *n += 1;
        let refresh = format!("RT-{n}");
        self.live_refresh.lock().unwrap().push(refresh.clone());
        let mut id = serde_json::json!({
            "iss": "https://auth.example.com",
            "aud": "app-web",
            "sub": "user-1",
            "nonce": *self.nonce.lock().unwrap(),
            "exp": now() + 300,
            "iat": now(),
        });
        if let serde_json::Value::Object(o) = &*self.id_overrides.lock().unwrap() {
            for (k, v) in o {
                id[k] = v.clone();
            }
        }
        OidcTokens {
            access_token: jwt(
                &serde_json::json!({ "sub": "user-1", "tenant_id": "acme", "org_id": org, "n": *n }),
            ),
            token_type: "Bearer".into(),
            expires_in: 300,
            id_token: Some(jwt(&id)),
            refresh_token: Some(refresh),
            scope: Some("openid".into()),
        }
    }
}

impl IdentityProvider for FakeIdp {
    fn exchange_code(&self, code: &str, verifier: &str) -> Result<OidcTokens, IdpError> {
        if *self.down.lock().unwrap() {
            return Err(IdpError::Unavailable("down".into()));
        }
        if code != "good-code" {
            return Err(IdpError::Rejected {
                status: 400,
                error: Some("invalid_grant".into()),
            });
        }
        self.verifiers.lock().unwrap().push(verifier.to_string());
        Ok(self.tokens("org-1"))
    }

    fn refresh(&self, refresh_token: &str) -> Result<OidcTokens, IdpError> {
        *self.refresh_calls.lock().unwrap() += 1;
        if *self.down.lock().unwrap() {
            return Err(IdpError::Unavailable("down".into()));
        }
        let mut live = self.live_refresh.lock().unwrap();
        let Some(i) = live.iter().position(|r| r == refresh_token) else {
            return Err(IdpError::Rejected {
                status: 400,
                error: Some("invalid_grant".into()),
            });
        };
        live.remove(i);
        drop(live);
        Ok(self.tokens("org-1"))
    }

    fn revoke(&self, _access: &str, refresh: Option<&str>) -> Result<(), IdpError> {
        if let Some(r) = refresh {
            self.live_refresh.lock().unwrap().retain(|x| x != r);
            self.revoked.lock().unwrap().push(r.to_string());
        }
        Ok(())
    }
}

fn setup() -> (Bff, Arc<FakeIdp>) {
    let idp = Arc::new(FakeIdp::default());
    let bff = Bff::new(config(), Arc::new(MemoryStore::new()), idp.clone()).with_clock(now);
    (bff, idp)
}

fn query(location: &str, key: &str) -> Option<String> {
    let q = location.split_once('?')?.1;
    q.split('&').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        (k == key).then(|| urlencoding::decode(v).unwrap().into_owned())
    })
}

/// Sign in; returns the `Cookie` header the browser would send.
fn sign_in(bff: &Bff, idp: &FakeIdp, return_to: Option<&str>) -> (String, Redirect) {
    let start = bff.start_login(return_to).unwrap();
    *idp.nonce.lock().unwrap() = query(&start.location, "nonce").unwrap();
    let state = query(&start.location, "state").unwrap();
    let done = bff
        .complete_login(Some("good-code"), Some(&state), None)
        .unwrap();
    let set = done.set_cookie.clone().unwrap();
    (set.split(';').next().unwrap().to_string(), done)
}

#[test]
fn authorize_request_carries_state_nonce_and_s256() {
    let (bff, _) = setup();
    let r = bff.start_login(Some("/dash")).unwrap();
    assert!(r
        .location
        .starts_with("https://auth.example.com/idam/v1/oauth/authorize?"));
    assert_eq!(query(&r.location, "client_id").as_deref(), Some("app-web"));
    assert_eq!(
        query(&r.location, "redirect_uri").as_deref(),
        Some("https://app.example.com/auth/callback")
    );
    assert_eq!(
        query(&r.location, "code_challenge_method").as_deref(),
        Some("S256")
    );
    assert_eq!(query(&r.location, "response_type").as_deref(), Some("code"));
    assert_eq!(query(&r.location, "code_challenge").unwrap().len(), 43);
    assert_eq!(query(&r.location, "state").unwrap().len(), 43);
    assert_eq!(query(&r.location, "nonce").unwrap().len(), 43);
    assert!(r.set_cookie.is_none());
}

#[test]
fn callback_redeems_with_the_verifier_and_sets_a_host_cookie() {
    let (bff, idp) = setup();
    let start = bff.start_login(Some("/dash?tab=1")).unwrap();
    let challenge = query(&start.location, "code_challenge").unwrap();
    *idp.nonce.lock().unwrap() = query(&start.location, "nonce").unwrap();
    let state = query(&start.location, "state").unwrap();
    let done = bff
        .complete_login(Some("good-code"), Some(&state), None)
        .unwrap();

    let verifier = idp.verifiers.lock().unwrap()[0].clone();
    assert_eq!(crypto::pkce_s256(&verifier), challenge);
    assert_eq!(done.location, "/dash?tab=1");
    let cookie = done.set_cookie.unwrap();
    assert!(cookie.starts_with("__Host-app="), "{cookie}");
    for attr in [
        "Path=/",
        "Secure",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=43200",
    ] {
        assert!(cookie.contains(attr), "{attr} missing: {cookie}");
    }
    assert!(!cookie.contains("Domain"), "{cookie}");
    // Conformance 1: no token in the redirect or the cookie.
    assert!(!done.location.contains("RT-") && !cookie.contains("RT-"));
    assert!(!cookie.contains("eyJ"));
}

#[test]
fn a_state_is_good_for_one_callback() {
    let (bff, idp) = setup();
    let start = bff.start_login(None).unwrap();
    *idp.nonce.lock().unwrap() = query(&start.location, "nonce").unwrap();
    let state = query(&start.location, "state").unwrap();
    assert!(bff
        .complete_login(Some("good-code"), Some(&state), None)
        .is_ok());
    assert_eq!(
        bff.complete_login(Some("good-code"), Some(&state), None),
        Err(BffError::InvalidState)
    );
    assert_eq!(
        bff.complete_login(Some("good-code"), Some("made-up"), None),
        Err(BffError::InvalidState)
    );
    assert_eq!(
        bff.complete_login(Some("good-code"), None, None),
        Err(BffError::InvalidState)
    );
}

#[test]
fn expired_pre_auth_is_refused() {
    let idp = Arc::new(FakeIdp::default());
    let store = Arc::new(MemoryStore::new());
    let bff = Bff::new(config(), store.clone(), idp.clone()).with_clock(now);
    store
        .put_preauth(
            "st",
            &PreAuth {
                code_verifier: "v".into(),
                nonce: "n".into(),
                return_to: "/".into(),
                created_at: now(),
            },
            Duration::from_millis(1),
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(5));
    assert_eq!(
        bff.complete_login(Some("good-code"), Some("st"), None),
        Err(BffError::InvalidState)
    );
}

#[test]
fn a_denied_sign_in_spends_the_state() {
    let (bff, _) = setup();
    let state = query(&bff.start_login(None).unwrap().location, "state").unwrap();
    assert_eq!(
        bff.complete_login(None, Some(&state), Some("access_denied")),
        Err(BffError::Denied("access_denied".into()))
    );
    assert_eq!(
        bff.complete_login(Some("good-code"), Some(&state), None),
        Err(BffError::InvalidState)
    );
}

#[test]
fn a_bad_code_is_refused() {
    let (bff, _) = setup();
    let state = query(&bff.start_login(None).unwrap().location, "state").unwrap();
    assert_eq!(
        bff.complete_login(Some("stolen"), Some(&state), None),
        Err(BffError::InvalidState)
    );
}

#[test]
fn id_token_checks() {
    for (overrides, why) in [
        (
            serde_json::json!({ "nonce": "someone-elses-nonce-value" }),
            "nonce",
        ),
        (
            serde_json::json!({ "iss": "https://evil.example" }),
            "issuer",
        ),
        (serde_json::json!({ "aud": "other-app" }), "audience"),
        (
            serde_json::json!({ "aud": ["app-web", "other-app"] }),
            "audience",
        ),
        (serde_json::json!({ "exp": 1 }), "expired"),
        (
            serde_json::json!({ "iat": 4_000_000_000_u64 }),
            "issued in the future",
        ),
        (serde_json::json!({ "sub": "" }), "subject"),
    ] {
        let (bff, idp) = setup();
        *idp.id_overrides.lock().unwrap() = overrides.clone();
        let start = bff.start_login(None).unwrap();
        if overrides.get("nonce").is_none() {
            *idp.nonce.lock().unwrap() = query(&start.location, "nonce").unwrap();
        }
        let state = query(&start.location, "state").unwrap();
        assert_eq!(
            bff.complete_login(Some("good-code"), Some(&state), None),
            Err(BffError::InvalidIdToken(why)),
            "{overrides}"
        );
    }
    // Multiple audiences are fine when azp names this client.
    let (bff, idp) = setup();
    *idp.id_overrides.lock().unwrap() =
        serde_json::json!({ "aud": ["app-web", "api"], "azp": "app-web" });
    assert!(sign_in(&bff, &idp, None).1.set_cookie.is_some());
}

#[test]
fn signature_check_is_applied_when_configured() {
    let (bff, idp) = setup();
    let bff = bff.with_id_token_signature_check(Arc::new(|_| false));
    let start = bff.start_login(None).unwrap();
    *idp.nonce.lock().unwrap() = query(&start.location, "nonce").unwrap();
    let state = query(&start.location, "state").unwrap();
    assert_eq!(
        bff.complete_login(Some("good-code"), Some(&state), None),
        Err(BffError::InvalidIdToken("signature"))
    );
}

#[test]
fn open_redirects_are_refused() {
    let (bff, _) = setup();
    assert_eq!(
        bff.start_login(Some("https://evil.example")),
        Err(BffError::InvalidReturnTo)
    );
    assert_eq!(
        bff.start_login(Some("//evil.example")),
        Err(BffError::InvalidReturnTo)
    );
    assert!(bff.start_login(Some("")).is_ok());
}

#[test]
fn resolve_yields_the_bearer_and_routing_facts() {
    let (bff, idp) = setup();
    let (cookie, _) = sign_in(&bff, &idp, None);
    let s = bff.resolve(Some(&format!("other=1; {cookie}"))).unwrap();
    assert_eq!(s.subject, "user-1");
    assert_eq!(s.tenant_id.as_deref(), Some("acme"));
    assert_eq!(s.organization_id.as_deref(), Some("org-1"));
    assert!(s.access_token.starts_with("eyJ"));
    assert!(!format!("{s:?}").contains("eyJ"));
}

#[test]
fn unknown_or_malformed_cookies_have_no_session() {
    let (bff, _) = setup();
    assert_eq!(bff.resolve(None).unwrap_err(), BffError::NoSession);
    assert_eq!(
        bff.resolve(Some("__Host-app=nope")).unwrap_err(),
        BffError::NoSession
    );
    let forged = format!("__Host-app={}", crypto::random_token());
    assert_eq!(bff.resolve(Some(&forged)).unwrap_err(), BffError::NoSession);
}

#[test]
fn access_token_is_refreshed_near_expiry_and_refresh_rotates() {
    let (bff, idp) = setup();
    let (cookie, _) = sign_in(&bff, &idp, None);
    let first = bff.resolve(Some(&cookie)).unwrap().access_token;
    advance(200);
    assert_eq!(
        bff.resolve(Some(&cookie)).unwrap().access_token,
        first,
        "outside the leeway"
    );
    advance(50); // 50 s left: inside the 60 s leeway
    let second = bff.resolve(Some(&cookie)).unwrap().access_token;
    assert_ne!(second, first);
    assert_eq!(*idp.refresh_calls.lock().unwrap(), 1);
    // RT-1 was spent by rotation.
    assert_eq!(
        idp.refresh("RT-1"),
        Err(IdpError::Rejected {
            status: 400,
            error: Some("invalid_grant".into())
        })
    );
}

#[test]
fn a_refused_refresh_ends_the_session() {
    let (bff, idp) = setup();
    let (cookie, _) = sign_in(&bff, &idp, None);
    idp.live_refresh.lock().unwrap().clear(); // revoked at Sesame
    advance(290);
    assert_eq!(bff.resolve(Some(&cookie)).unwrap_err(), BffError::NoSession);
    assert_eq!(bff.resolve(Some(&cookie)).unwrap_err(), BffError::NoSession);
}

#[test]
fn sesame_down_keeps_a_still_valid_token_and_fails_soft_after() {
    let (bff, idp) = setup();
    let (cookie, _) = sign_in(&bff, &idp, None);
    *idp.down.lock().unwrap() = true;
    advance(250); // inside the leeway, token still valid
    assert!(bff.resolve(Some(&cookie)).is_ok());
    advance(100); // expired
    assert!(matches!(
        bff.resolve(Some(&cookie)),
        Err(BffError::Unavailable(_))
    ));
    *idp.down.lock().unwrap() = false;
    assert!(
        bff.resolve(Some(&cookie)).is_ok(),
        "the session survives an outage"
    );
}

#[test]
fn idle_timeout_slides_and_absolute_timeout_ends() {
    let (bff, idp) = setup();
    let (cookie, _) = sign_in(&bff, &idp, None);
    // Sliding: activity every 20 minutes keeps it alive past 30 minutes.
    for _ in 0..3 {
        advance(1200);
        assert!(bff.resolve(Some(&cookie)).is_ok());
    }
    advance(12 * 3600);
    assert_eq!(bff.resolve(Some(&cookie)).unwrap_err(), BffError::NoSession);
}

#[test]
fn csrf_requires_origin_and_marker_on_unsafe_methods() {
    let (bff, _) = setup();
    let h = |origin: Option<&'static str>, marker: Option<&'static str>| {
        move |name: &str| match name.to_ascii_lowercase().as_str() {
            "origin" => origin,
            "x-app-request" => marker,
            _ => None,
        }
    };
    assert!(bff.check_csrf("GET", h(None, None)).is_ok());
    assert!(bff
        .check_csrf("POST", h(Some("https://app.example.com"), Some("1")))
        .is_ok());
    assert_eq!(
        bff.check_csrf("POST", h(Some("https://evil.example"), Some("1"))),
        Err(BffError::Csrf)
    );
    assert_eq!(
        bff.check_csrf("PUT", h(Some("https://app.example.com"), None)),
        Err(BffError::Csrf)
    );
    assert_eq!(
        bff.check_csrf("DELETE", h(None, Some("1"))),
        Err(BffError::Csrf)
    );
}

#[test]
fn logout_revokes_deletes_and_clears() {
    let (bff, idp) = setup();
    let (cookie, _) = sign_in(&bff, &idp, None);
    let out = bff.logout(Some(&cookie));
    assert_eq!(out.location, "/");
    assert!(out.set_cookie.as_deref().unwrap().contains("Max-Age=0"));
    assert_eq!(bff.resolve(Some(&cookie)).unwrap_err(), BffError::NoSession);
    assert_eq!(idp.revoked.lock().unwrap().as_slice(), ["RT-1"]);
    // Conformance 7: the old refresh token is dead too.
    assert!(idp.refresh("RT-1").is_err());
    // Unknown cookie: still a clean logout.
    assert!(bff.logout(None).set_cookie.unwrap().contains("Max-Age=0"));
}

#[test]
fn logout_goes_to_end_session_when_configured() {
    let mut c = config();
    c.end_session_url = Some("https://auth.example.com/idam/v1/oauth/end-session".into());
    c.post_logout_redirect = "https://app.example.com/".into();
    let idp = Arc::new(FakeIdp::default());
    let bff = Bff::new(c, Arc::new(MemoryStore::new()), idp.clone()).with_clock(now);
    let (cookie, _) = sign_in(&bff, &idp, None);
    let out = bff.logout(Some(&cookie));
    assert!(out
        .location
        .starts_with("https://auth.example.com/idam/v1/oauth/end-session?client_id=app-web"));
    assert_eq!(
        query(&out.location, "post_logout_redirect_uri").as_deref(),
        Some("https://app.example.com/")
    );
    assert!(query(&out.location, "id_token_hint").is_some());
}

#[test]
fn logout_everywhere_ends_every_session_of_the_subject() {
    let (bff, idp) = setup();
    let (a, _) = sign_in(&bff, &idp, None);
    let (b, _) = sign_in(&bff, &idp, None);
    let session = bff.resolve(Some(&a)).unwrap();
    assert_eq!(bff.logout_everywhere(&session).unwrap(), 2);
    assert_eq!(bff.resolve(Some(&a)).unwrap_err(), BffError::NoSession);
    assert_eq!(bff.resolve(Some(&b)).unwrap_err(), BffError::NoSession);
}

#[test]
fn rotate_issues_a_new_id_and_kills_the_old_one() {
    let (bff, idp) = setup();
    let (cookie, _) = sign_in(&bff, &idp, None);
    let session = bff.resolve(Some(&cookie)).unwrap();
    let new_set = bff.rotate(&session, &idp.tokens("org-2")).unwrap();
    let new_cookie = new_set.split(';').next().unwrap();
    assert_ne!(new_cookie, cookie);
    assert_eq!(bff.resolve(Some(&cookie)).unwrap_err(), BffError::NoSession);
    let s = bff.resolve(Some(new_cookie)).unwrap();
    assert_eq!(s.organization_id.as_deref(), Some("org-2"));
    // Rotation keeps the original absolute expiry.
    assert!(new_set.contains("Max-Age=43200"));

    let mut other = idp.tokens("org-3");
    other.id_token = Some(jwt(&serde_json::json!({ "sub": "someone-else" })));
    assert_eq!(
        bff.rotate(&s, &other),
        Err(BffError::InvalidIdToken("subject"))
    );
}

#[test]
fn concurrent_refresh_is_single_flight() {
    let idp = Arc::new(FakeIdp::default());
    let bff = Bff::new(config(), Arc::new(MemoryStore::new()), idp.clone());
    // Real clock here: threads do not share the thread-local test clock.
    NOW.with(|n| n.set(system_now()));
    let start = bff.start_login(None).unwrap();
    *idp.nonce.lock().unwrap() = query(&start.location, "nonce").unwrap();
    let state = query(&start.location, "state").unwrap();
    let set = bff
        .complete_login(Some("good-code"), Some(&state), None)
        .unwrap()
        .set_cookie
        .unwrap();
    let cookie = set.split(';').next().unwrap().to_string();
    // Force the session to need a refresh.
    let key = crypto::session_key(crypto::cookie_value(&cookie, "__Host-app").unwrap());
    let mut r = bff.store.get_session(&key).unwrap().unwrap();
    r.access_expires_at = system_now() + 5;
    bff.store
        .put_session(&key, &r, Duration::from_secs(60))
        .unwrap();

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let (bff, cookie) = (bff.clone(), cookie.clone());
            std::thread::spawn(move || bff.resolve(Some(&cookie)).map(|s| s.access_token))
        })
        .collect();
    let tokens: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().unwrap().unwrap())
        .collect();
    assert_eq!(
        *idp.refresh_calls.lock().unwrap(),
        1,
        "one refresh for eight requests"
    );
    assert!(
        tokens.windows(2).all(|w| w[0] == w[1]),
        "every request got the refreshed token"
    );
}
