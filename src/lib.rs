//! Typed, may-native integration client for Sesame-IDAM.
//!
//! HTTP calls use [`brrtrouter::http`], which is backed by the microscaler
//! `may_minihttp` client. The crate does not introduce a second transport
//! abstraction or an async runtime.
//!
//! Every Sesame service the client talks to has its own required base URL
//! ([`LOGIN_BASE_URL_KEY`], [`ORG_MGMT_BASE_URL_KEY`], [`SESSION_BASE_URL_KEY`]).
//! [`SesameIdamClientConfig`] cannot be built without them: a missing value is a
//! [`ConfigError::Missing`] naming the key, not a default. Base URLs are never
//! derived from one another.

mod claims;
mod config;
mod identity;
mod login;
mod org;
mod register;
mod saml;
mod session;
mod social;
mod types;

pub use claims::{
    parse_validated_claims, ClaimsError, ValidatedClaims, AUTHORIZATION_CLAIMS_NAMESPACE,
};
pub use config::{
    ConfigError, SesameIdamClientConfig, LOGIN_BASE_URL_KEY, ORG_MGMT_BASE_URL_KEY,
    SESSION_BASE_URL_KEY, TENANT_ID_KEY,
};
pub use identity::{fetch_current_user, patch_current_user, SesameUserProfile};
pub use login::{auth_login, LoginError};
pub use org::{
    accept_invitation, create_organization, fetch_users_in_org, invite_user_to_org,
    remove_user_from_org, revoke_pending_invite, InviteCreated, OrgClientError, OrgMemberSummary,
    OrganizationSummary, UsersInOrgPage,
};
pub use register::{auth_register, signup_validate};
pub use saml::{saml_callback, saml_login_start};
pub use session::set_active_organization;
pub use social::{social_callback, social_login_start};
pub use types::{LoginRequest, RegisterRequest, SignupValidationResponse, TokenResponse};
