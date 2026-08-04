//! Request/response types aligned with sesame `TokenResponse` / `LoginRequest`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterRequest {
    pub client_id: String,
    pub email: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignupValidationResponse {
    #[serde(default)]
    pub allowed: bool,
    #[serde(default)]
    pub reasons: Vec<String>,
    #[serde(default)]
    pub requires_mfa: bool,
}

/// Sesame login `TokenResponse` (required fields + optional enrichments).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default = "default_bearer")]
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: String,
    pub user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token_expires_in: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
}

fn default_bearer() -> String {
    "Bearer".to_string()
}
