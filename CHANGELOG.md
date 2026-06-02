# Changelog

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
