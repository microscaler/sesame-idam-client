//! Typed client for sesame identity-login-service (HI-4+).
//!
//! OpenAPI subset: `openapi/sesame-idam/identity-login-client.yaml`.

mod config;
mod login;
mod org;
mod register;
mod saml;
mod session;
mod social;
mod types;

pub use config::SesameIdamClientConfig;
pub use login::{auth_login, LoginError};
pub use org::{
    accept_invitation, create_organization, fetch_users_in_org, invite_user_to_org,
    InviteCreated, OrgClientError, OrgMemberSummary, OrganizationSummary, UsersInOrgPage,
};
pub use register::{auth_register, signup_validate};
pub use saml::{saml_callback, saml_login_start};
pub use session::set_active_organization;
pub use social::{social_callback, social_login_start};
pub use types::{LoginRequest, RegisterRequest, SignupValidationResponse, TokenResponse};
