//! Random ids, PKCE, cookie parsing and unverified JWT payload reads.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

/// 256 bits from the OS CSPRNG, base64url without padding (43 characters).
/// Used for session ids, `state`, `nonce` and PKCE verifiers.
pub(crate) fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("the OS random source is available");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Shape check before a cookie value reaches the store.
pub(crate) fn looks_like_token(v: &str) -> bool {
    v.len() == 43
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// RFC 7636 S256 challenge.
pub(crate) fn pkce_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Store key for a cookie value: its SHA-256, hex. The store never holds a
/// value a browser could present.
pub(crate) fn session_key(cookie_value: &str) -> String {
    Sha256::digest(cookie_value.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The value of `name` in a `Cookie` header (or the first pair of a
/// `Set-Cookie` value). The first occurrence wins.
pub(crate) fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k.trim() == name).then(|| v.trim())
    })
}

/// Decode a JWT's payload **without verifying it**. Callers only use this for
/// tokens that came straight from the token endpoint, and check what matters.
pub(crate) fn jwt_payload(jwt: &str) -> Option<serde_json::Value> {
    let mut parts = jwt.split('.');
    let (_, payload, _) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.is_object().then_some(value)
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_43_url_safe_characters_and_distinct() {
        let a = random_token();
        let b = random_token();
        assert!(looks_like_token(&a), "{a}");
        assert_ne!(a, b);
    }

    #[test]
    fn pkce_matches_rfc_7636_appendix_b() {
        assert_eq!(
            pkce_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn cookie_value_finds_the_named_pair() {
        let h = "a=1; __Host-app=XYZ; b=2";
        assert_eq!(cookie_value(h, "__Host-app"), Some("XYZ"));
        assert_eq!(cookie_value(h, "__Host-other"), None);
        assert_eq!(
            cookie_value("__Host-app=v; Path=/; Secure", "__Host-app"),
            Some("v")
        );
    }

    #[test]
    fn session_key_is_not_the_cookie() {
        let v = random_token();
        let k = session_key(&v);
        assert_eq!(k.len(), 64);
        assert!(!k.contains(&v));
    }

    #[test]
    fn jwt_payload_reads_three_part_tokens_only() {
        let p = URL_SAFE_NO_PAD.encode(br#"{"sub":"u1"}"#);
        assert_eq!(jwt_payload(&format!("h.{p}.s")).unwrap()["sub"], "u1");
        assert!(jwt_payload(&format!("h.{p}")).is_none());
        assert!(jwt_payload(&format!("h.{p}.s.x")).is_none());
        assert!(jwt_payload("h.!!!.s").is_none());
    }
}
