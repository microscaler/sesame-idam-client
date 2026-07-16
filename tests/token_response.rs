use hauliage_sesame_idam_client::TokenResponse;

#[test]
fn token_response_deserializes_sesame_shape() {
    let json = r#"{
        "access_token": "at",
        "token_type": "Bearer",
        "expires_in": 300,
        "refresh_token": "rt",
        "user_id": "a1000001-0001-4000-8000-000000000001",
        "scope": "openid profile email"
    }"#;
    let t: TokenResponse = serde_json::from_str(json).expect("parse");
    assert_eq!(t.access_token, "at");
    assert_eq!(t.token_type, "Bearer");
    assert_eq!(t.expires_in, 300);
    assert_eq!(t.refresh_token, "rt");
}
