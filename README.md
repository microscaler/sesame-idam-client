# Sesame-IDAM Rust client

`sesame-idam-client` is the typed, may-native integration boundary for Rust
services consuming [Sesame-IDAM](https://github.com/microscaler/sesame-idam).
It uses `brrtrouter::http` and therefore the microscaler `may_minihttp` client;
it does not introduce Reqwest, Tokio, or another HTTP abstraction.

The crate currently covers:

- password login and registration;
- signup eligibility validation;
- social-login start and callback;
- active-organization selection;
- organization creation, invitations, and member listing; and
- strict conversion of BRRTRouter-validated claims into a reusable identity
  context.

## Development layout

During rapid development the repositories are expected to be siblings:

```text
microscaler/
├── BRRTRouter/
├── microscaler-observability/
├── sesame-idam/
├── sesame-idam-client/
├── hauliage/
└── rerp/
```

The client depends on `../BRRTRouter`, whose observability adapter is the sibling
`../microscaler-observability`. Contract tests read the provider specs
from `../sesame-idam`, or from `SESAME_IDAM_REPO` when the provider checkout is
elsewhere. Hauliage and RERP likewise use a sibling path dependency so changes
can be developed together. Release branches should replace that development
path with an exact Git revision; the crate is intentionally not published to
crates.io.

Cargo Dependabot is deferred while the development manifest uses sibling path
dependencies, because its isolated checkout cannot resolve that topology.
GitHub Actions dependencies are still maintained automatically.

## Validation

Run the complete acceptance cycle with:

```shell
just check
```

or run `cargo fmt`, `cargo clippy`, `cargo test`, and `cargo doc` directly.

The contract test checks operations and response fields against the current
Sesame OpenAPI documents. It is a drift alarm, not a replacement for provider
integration tests.

## Trust boundary

`parse_validated_claims` does not decode or verify a token. It accepts only the
claim value that BRRTRouter exposes after successful JWT/JWS/JWE verification.
Passing claims parsed directly from an unverified token is a security defect.

## SAML status

The moved Hauliage integration already contains SAML login/callback methods.
They are retained to avoid breaking its consumer during extraction, but the
current Sesame login-service OpenAPI does not publish those operations. Treat
them as pre-contract and do not enable them in a production flow until Sesame
owns and implements the endpoints and the contract test is extended.
