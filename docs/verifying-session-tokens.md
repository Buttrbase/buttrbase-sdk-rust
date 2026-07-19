# Verifying Session Tokens (multi-org onboarding flow)

How a Rust backend validates the **org-scoped session token** produced by ButtrBase's
email-verify → (create org | sign in) login. Pairs with the Solid frontend tutorial in
`buttrbase-frontend-solid/docs/multi-org-onboarding-auth-tutorial.md`.

---

## The one rule: this SDK verifies **RS256 only**

`Verifier::verify` pins `Algorithm::RS256` (`src/verify/verifier.rs:120`) and checks the
signature against ButtrBase's JWKS. That is deliberate and load-bearing:

- The login flow issues a **fast HS256 token** immediately (and an HS256 "signup_token" that
  proves email ownership). These are **symmetric, shared-secret** tokens — this SDK will
  **reject them** (`InvalidToken`), because it only accepts asymmetric RS256.
- The frontend runs a background **service-job** that refreshes the HS256 token into an
  **RS256** one (`POST /api/app/auth/refresh`). That RS256 token is the only thing your
  backend should — and can — accept.

So you get security for free: a backend using this SDK **cannot** be tricked into trusting
the HS256 email-proof token as a session. It only ever honors the RS256 org-scoped token.
(Requires the app's `auth.token_rs256` feature flag ON so refresh actually mints RS256.)

---

## Setup

```rust
use buttrbase_sdk::verify::{Verifier, VerifierConfig};

let verifier = Verifier::new(VerifierConfig {
    jwks_url: "https://api.buttrbase.com/.well-known/jwks.json".into(),
    issuer:   "https://api.buttrbase.com".into(),   // must match the token's `iss`
    audience: None,   // Some("your-app") to pin `aud`; None = don't validate `aud`
});
```

`Verifier` owns a JWKS cache (kid-keyed, auto-refresh with one rate-limited force-refresh on
a kid miss). It's cheap to clone (Arc inside) — build one at startup, share it across handlers.

## Verify a request

```rust
use axum::http::HeaderMap;

// Pulls `Authorization: Bearer <token>`, verifies RS256 + issuer + nbf (60s leeway),
// and returns just the principal + grants.
let ctx = verifier.verify_bearer(&headers).await?;   // -> AuthContext

// AuthContext {
//   user_id: Uuid,        // token `sub`
//   org_id:  Uuid,        // token `org`  — the tenant this session is scoped to
//   scopes:  Vec<String>,
//   roles:   Vec<String>, // from data.roles ("owner", "org_admin,leadership", …)
//   email:   Option<String>,
// }
```

`org_id` is always present — the session token is org-scoped, so every verified request
already carries its tenant. Scope your queries by `ctx.org_id`; never trust an org id from
the request body.

Lower-level: `verifier.verify(token).await? -> Claims` if you need the raw
`{ sub, org, exp, iat, scope, data }`.

---

## Errors worth handling

| `VerifyError` | Cause | Usual response |
|---|---|---|
| `MissingBearer` | no `Authorization: Bearer …` | 401 |
| `InvalidToken` | bad signature, expired, **or an HS256 token** (frontend hasn't upgraded yet) | 401 |
| `KidNotFound` | token signed by a key not in JWKS (rotation lag / wrong issuer) | 401, alert if persistent |
| `MissingKid` / `BadHeader` | malformed token | 401 |

An `InvalidToken` right after login usually means the client called you **before** the RS256
service-job finished — the frontend should gate JWKS-verified calls on the RS256 tier.

---

## Crypto-provider gotcha (startup)

`jsonwebtoken 10` needs a rustls crypto provider installed once at process start, or TLS/JWKS
verification aborts. Install it before building the `Verifier`:

```rust
rustls::crypto::aws_lc_rs::default_provider().install_default().ok();
```

See this repo's `README.md` §"Compatibility & gotchas" for the feature-flag details.

---

## Related

- `buttrbase-frontend-solid/docs/multi-org-onboarding-auth-tutorial.md` — the client flow that
  produces the token this verifies.
- `matter-framework/AUTH_PIN_ONBOARDING_SPEC.md` — the full design (two token systems, the
  account→org handoff, the `auth.token_rs256` flag SQL).
- `src/verify/verifier.rs` — the implementation (`VerifierConfig`, `Verifier`, `Claims`,
  `AuthContext`).
