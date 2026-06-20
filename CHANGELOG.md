# Changelog

## 0.5.0 — 2026-06-20 — magic-link contract fix

### Changed (breaking)

- **`send_magic_link(email, app_uuid, redirect_to)`** now sends the fields the
  backend actually accepts (`email`, `app_uuid`, `redirect_to`) and returns
  `MagicLinkSent { sent, dev_token, expires_in_seconds }`. The previous
  signature sent `org_name`/`application` (ignored by the server) and omitted
  `app_uuid`/`redirect_to`, so cross-app federation could never work.
  - Pass an allowlisted `redirect_to` (origin registered on your app's
    `rp_origins` / redirect URL) so the email link returns to your callback and
    your app verifies the RS256 token. `None` ⇒ Buttrbase-hosted flow.
- **`magic_link_send`** is now a `#[deprecated]` alias delegating to
  `send_magic_link` with the corrected argument order.

### Added

- **`MagicLinkSent`** response model.

## 0.4.0 — 2026-06-20 — optional audience + pure-Rust crypto

### Changed (breaking)

- **`VerifierConfig.audience` is now `Option<String>`** (was `String`). buttrbase
  access tokens carry **no stable, per-application `aud` claim** — magic-link
  tokens set `aud` to the org *name* (or omit it) and client-credential tokens
  omit it entirely. Pinning a fixed audience therefore rejected legitimate
  tokens. When `audience` is `None` the verifier sets
  `validation.validate_aud = false`; identity then rests on the issuer + RS256
  signature + the `org`/`sub` claims. **Most consumers should pass `None`.**
  - Migration: `audience: "my-app".into()` → `audience: None` (or
    `audience: Some("my-app".into())` to keep enforcing a known audience).
- **`Verifier::audience()` now returns `Option<&str>`** (was `&str`).
- The bundled `ButtrBaseClient` verifier no longer hardcodes
  `audience: "buttrbase"` (which never matched a real token) — it uses `None`.

### Changed (build)

- JWT verification now uses `jsonwebtoken`'s **`rust_crypto`** (RustCrypto)
  backend instead of `aws_lc_rs`. This removes the `aws-lc-rs` C library and its
  `cmake`/C-toolchain build requirement; `reqwest`'s `rustls-tls` already pins
  the `ring` provider. RS256 verification behavior is unchanged.

## 0.3.0 — 2026-06-03 — org-aware registration + invitations

### Added

- **`finalize_registration(&FinalizeRegistrationRequest)`** — the new registration entry point. Replaces the legacy `register()` auto-create-by-domain behavior with an explicit `OrgChoice` (either `Create { name }` or `AcceptInvite { invitation_token }`). The full flow is now: `send_otp` → `verify_otp` → `finalize_registration`. See README "Compatibility & gotchas" for the migration recipe.
- **`OrgChoice<'a>`** — tagged enum surfacing the two registration paths.
- **`FinalizeRegistrationRequest<'a>`** — strongly-typed request body.
- **`check_org_name(name)`** → `CheckOrgNameResponse`. Replaces the prior `/api/auth/orgs/check` shim (which targeted a route the live Rust backend doesn't serve). Now hits `/api/auth/check-org-name`. Returns `{ available, reason, normalized }` where `reason ∈ { empty, too_short, too_long, invalid_chars, taken }`.
- **`create_invitation(org_uuid, &CreateInvitationRequest)`** → `CreateInvitationResponse` (includes the one-time-shown plaintext token + a ready-to-share `signup_url`).
- **`preview_invitation(token)`** → `InvitationPreview` (public, no auth — for "you're invited to Acme Inc" UI before signup).
- **`accept_invitation(token)`** → `AcceptInvitationResponse` (for already-logged-in users joining an additional org; brand-new users consume the invite via `finalize_registration` with `OrgChoice::AcceptInvite`).
- **`list_invitations(org_uuid)`** + **`revoke_invitation(org_uuid, invitation_id)`** for the admin management UI.

### Deprecated

- **`register(&RegisterRequest)`** — kept working against the live API (server-side `/api/auth/register` is unchanged for backward compat) but emits `#[deprecated]`. Migrate to `finalize_registration`. The legacy method always auto-created an org named after the email's domain — that broke the second sign-up from any domain and made invitations impossible.

### Migration recipe (0.2.x → 0.3.0)

```rust
// Before (0.2):
let token = client.send_otp(email, app_uuid).await?;
// (user enters code) — verify, then in one call:
client.register(&RegisterRequest {
    email,
    password: random_password.as_str(),
    org_name: "acme.com",           // auto-creates org with this name
    app_uuid,
    first_name: Some("Alice"),
    last_name: Some("Smith"),
}).await?;
```

```rust
// After (0.3): split into verify → finalize, with explicit org_choice.
client.send_otp(email, app_uuid).await?;
let v = client.verify_otp(email, code, app_uuid).await?;
client.finalize_registration(&FinalizeRegistrationRequest {
    email,
    password: random_password.as_str(),
    app_uuid,
    signup_token: &v.token,
    org_choice: OrgChoice::Create { name: "Acme Inc" },
    first_name: Some("Alice"),
    last_name: Some("Smith"),
}).await?;
```

Or, to accept an existing org's invitation:

```rust
org_choice: OrgChoice::AcceptInvite { invitation_token: "Bd9..." },
```

### Notes — progenitor experiment (investigated, deferred)

We evaluated [progenitor](https://docs.rs/progenitor) (Oxide's OpenAPI client generator) as a path to auto-generate the SDK from the [`buttrbase-openapi`](https://github.com/S7-Works/buttrbase-openapi) spec. Build pipeline + spec preprocessing were proved out, but progenitor 0.10 hit three hard friction points against the existing spec:

1. Required `operationId` on every operation (most legacy endpoints don't have one). **Workaround**: synthesized deterministic IDs from `method + path` in build.rs.
2. Refused unknown content types (`application/ocsp-request` was the trigger). **Workaround**: pre-filter the spec to skip endpoints by path pattern.
3. **Stopper**: internal assertion `response_types.len() <= 1` panicked on endpoints with multiple distinct success/error response schemas. No configuration knob.

Decision: defer the generator migration. Re-evaluate when either (a) progenitor catches up on multi-response support, or (b) we have time to normalize the spec to a stricter subset, or (c) we evaluate alternatives (oxide-progenitor-fork, openapi-generator-cli with rust-server template, or hand-rolling via openapi-typescript-codegen-style logic). Hand-written client remains the canonical surface for 0.3.x.

### Dependency changes

- No new runtime deps in 0.3.0. (The progenitor experiment used build-deps that have been removed.)

---

## 0.2.0 — 2026-06-02 — jsonwebtoken 9 → 10 + app_uuid migration

### Breaking (dependency)

- Bumped `jsonwebtoken` from `9.3` to `10.4.0` with `features = ["aws_lc_rs"]`. SDK public API is unchanged; this is a transitive dependency change. **If your app also depends on `jsonwebtoken` 10 directly (or via another transitive dep), you must enable exactly one of the `aws_lc_rs` / `rust_crypto` features on that dep — otherwise your app will SIGABRT on first JWT operation.** See README "Compatibility & gotchas" for the full explanation.
- This is NOT the same as `rustls`'s `CryptoProvider::install_default()` — jsonwebtoken 10 has its own internal crypto-provider abstraction selected by Cargo features at compile time.

### Why

`jsonwebtoken 10` introduced an internal `CryptoProvider` selected by feature flags at compile time. Without `aws_lc_rs` or `rust_crypto` enabled, every JWT operation panics. The SDK now pins `aws_lc_rs` so this Just Works for SDK consumers. ButtrBase backend hit this in production 2026-06-02 (~20-hour login outage); see `buttrbase-backend-rust/docs/CANONICAL_DEPS.md` for the canonical explanation.

---

## Unreleased — app_uuid migration

### Breaking
- `send_otp`, `verify_otp`, `magic_link_send`, `register` now take `app_uuid: Uuid` instead of `app: &str`. Slug-based app identifiers are no longer accepted by the backend.
  - `magic_link_send` previously did not carry an app identifier at all; it now requires `app_uuid` as its third argument.
  - `RegisterRequest` gains a required `app_uuid: Uuid` field.

### Added
- `exchange_api_key`, `exchange_refresh_token` — POST `/api/v1/auth/api-key/exchange`
- `oauth_start_url(provider, app_uuid, return_to)` helper
- App-level API key admin: `list_app_api_keys`, `create_app_api_key`, `revoke_app_api_key`, `rotate_app_api_key`
- OAuth config admin: `list_oauth_configs`, `create_oauth_config`, `update_oauth_config`, `delete_oauth_config`
- `read_audit_log` — per-app security audit log
- Model types: `ExchangeResponse`, `ApiKeySummary`, `CreatedKeyResponse`, `CreateApiKeyRequest`, `KeyType`, `ExpiryInput`, `OAuthConfigSummary`, `CreateOAuthConfigRequest`, `UpdateOAuthConfigRequest`, `AuditRow`, `AuditLogQuery`, `OAuthProvider`
- Crate dependency: `chrono` (default-features off; `serde` + `clock` features), used for typed timestamps on the new admin response types.

### Passkey support
- `passkey_register_begin`, `passkey_register_complete`,
  `passkey_authenticate_begin`, `passkey_authenticate_complete` — thin
  wrappers over `POST /api/passkeys/{register,authenticate}/{begin,complete}`.
  WebAuthn challenge / credential blobs are `serde_json::Value`
  (pass-through). `webauthn-rs` is deliberately *not* a dep on the SDK.
- `list_my_passkeys` — `GET /api/v1/me/passkeys`. Returns
  `Vec<PasskeyListItem>` in descending `created_at` order.
- `delete_my_passkey(credential_uuid)` — `DELETE /api/v1/me/passkeys/{uuid}`.
  Owner check enforced on the backend; other users' UUIDs return 404.
- Model types: `PasskeyRegistrationChallenge`,
  `PasskeyRegistrationComplete`, `PasskeyRegistrationResult`,
  `PasskeyAuthChallenge`, `PasskeyAuthComplete`, `PasskeyListItem`.
  Internal `DataEnvelope<T>` helper to unwrap the backend's
  `{data: ...}` shape for ergonomics.
