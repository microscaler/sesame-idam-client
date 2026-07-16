# Security policy

Please report vulnerabilities privately through GitHub Security Advisories for
`microscaler/sesame-idam-client`. Do not open a public issue containing exploit
details, credentials, tokens, or personally identifiable information.

The principal trust rule is that token verification belongs at the BRRTRouter
request boundary. This crate's claims adapter must never be used to imply that
arbitrary JSON or a merely decoded token has been authenticated.
