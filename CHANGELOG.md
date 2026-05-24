# Changelog

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
