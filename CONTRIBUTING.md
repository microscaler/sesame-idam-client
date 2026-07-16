# Contributing

This client is a shared contract boundary. Changes must start from the Sesame
provider OpenAPI, remain compatible with the may coroutine architecture, and
avoid product-specific policy.

Before submitting a change:

1. update the relevant Sesame OpenAPI contract;
2. update the typed request or response and contract test here;
3. run `just check`; and
4. exercise affected Hauliage and RERP consumers.

Use conventional, focused commits. Do not add Reqwest or Tokio. HTTP behavior
that belongs to the ecosystem client should be implemented in `may_minihttp`
and exposed through BRRTRouter rather than reimplemented in this crate.
