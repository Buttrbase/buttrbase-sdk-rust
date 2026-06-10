# Changelog

## Unreleased — session revocation, KMS status, payment methods, org members, OAuth configs, SAML cert rollover

### Added

- **`revoke_session_token(token)`** → `()` — POST `/api/admin/sessions/revoke`. Immediately invalidates a bearer or refresh token.
- **`list_revoked_tokens()`** → `Vec<RevokedTokenEntry>` — GET `/api/admin/sessions/revoked`. Returns all explicitly-revoked tokens with hash, timestamp, and optional reason.
- **`kms_status()`** → `KmsStatusResponse` — GET `/api/admin/kms/status`. Returns KMS provider name, operational status, key count, and last rotation timestamp.
- **`list_payment_methods(bearer)`** → `Vec<PaymentMethod>` — GET `/api/v1/customers/me/payment-methods`.
- **`create_payment_method(req, bearer)`** → `PaymentMethod` — POST `/api/v1/customers/me/payment-methods`. Attaches a provider token (e.g. Stripe `pm_…`) as a new saved method.
- **`set_default_payment_method(id, bearer)`** → `()` — POST `/api/v1/customers/me/payment-methods/{id}/default`.
- **`delete_payment_method(id, bearer)`** → `()` — DELETE `/api/v1/customers/me/payment-methods/{id}`.
- **`list_org_members(org_uuid)`** → `Vec<OrgMember>` — GET `/api/v2/organizations/{org_uuid}/members`.
- **`list_oauth_configs(app_uuid)`** → `Vec<OAuthConfigSummary>` — GET `/api/v1/apps/{app_uuid}/oauth-configs`.
- **`rollover_saml_certificates(org_uuid, connection_uuid)`** → `serde_json::Value` — PUT `/api/organizations/{org_uuid}/sso-connections/{connection_uuid}/saml-certificates`. Generates a new SAML signing certificate and returns updated SP metadata.
- New model types: `RevokeSessionRequest`, `RevokedTokenEntry`, `KmsStatusResponse`, `PaymentMethod`, `CreatePaymentMethodRequest`, `OrgMember`.

### Fixed

- Removed a duplicate `pub struct EntitlementCheckResponse` (with `allowed`/`reason` fields) that shadowed the internal `pub(crate)` deserialization envelope of the same name. The duplicate was dead code and caused a compile error when combined with other features.

---

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
