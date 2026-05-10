# buttrbase-sdk-rust

Official Rust SDK for [buttrbase](https://buttrbase.com).

Two surfaces, one crate:

- **`client`** — call the buttrbase API from your Rust service
  (auth, organizations, billing, webhooks, search, jobs, etc.).
- **`verify`** — verify buttrbase-issued JWTs in your own Rust service.
  Drop-in for any service that federates auth through buttrbase.

## Install

```toml
[dependencies]
buttrbase-sdk = "0.1"
```

## Client quickstart

```rust
use buttrbase_sdk::client::ButtrBaseClient;

let mut bb = ButtrBaseClient::new("https://api.buttrbase.com".into());
bb.set_token("...".into());
let status = bb.get_status().await?;
```

## Verify quickstart

```rust
use buttrbase_sdk::verify::{Verifier, VerifierConfig};

let v = Verifier::new(VerifierConfig {
    jwks_url: "https://api.buttrbase.com/.well-known/jwks.json".into(),
    issuer: "https://api.buttrbase.com".into(),
    audience: "your-service".into(),
});

// In a handler:
let auth = v.verify_bearer(&headers).await?;
// auth.user_id, auth.org_id, auth.scopes
```

The `Verifier` lives happily in your `AppState` — clone-cheap, internal
`Arc<RwLock<...>>` for the JWKS cache. JWKS is cached for 5 min and
auto-refetched (rate-limited 1×/min) on `kid`-not-found, so buttrbase
key rotations propagate without a config push.

## Sister SDKs

- [buttrbase-sdk-go](https://github.com/S7-Works/buttrbase-sdk-go)
- [buttrbase-sdk-node](https://github.com/S7-Works/buttrbase-sdk-node)
- [buttrbase-sdk-python](https://github.com/S7-Works/buttrbase-sdk-python)

For the **CMS** product (`metaphone.app`) and **UGC + media CDN**
product (`customerstories.app`), see their own SDK families:

- `metaphone-sdks/` (Rust port forthcoming)
- `customerstories-sdks/` (Rust port forthcoming)

## License

Apache-2.0
