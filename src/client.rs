//! `ButtrBaseClient` — the main entrypoint for SaaS builders embedding
//! ButtrBase into their Rust backend.
//!
//! # Initialisation
//!
//! ```rust,ignore
//! use buttrbase_sdk::ButtrBaseClient;
//!
//! // Live (bb_live_cid_… prefix → api.buttrbase.com)
//! let bb = ButtrBaseClient::new("bb_live_cid_...", "bb_live_sk_...");
//!
//! // Sandbox (bb_test_cid_… prefix → stagingapi.buttrbase.com)
//! let bb = ButtrBaseClient::new("bb_test_cid_...", "bb_test_sk_...");
//!
//! // Self-hosted / custom base URL
//! let bb = ButtrBaseClient::with_base_url("bb_live_cid_...", "bb_live_sk_...",
//!                                         "https://api.example.com");
//! ```
//!
//! # Two authentication models
//!
//! - **App-level** (uses HTTP Basic with client_id:client_secret) — for sending
//!   OTPs, verifying magic links, reporting usage, and other operations that
//!   represent your application rather than a specific end-user.
//!
//! - **User-level** (pass the user's bearer token) — for entitlement checks,
//!   wallet, subscriptions, and anything scoped to an individual user.

use std::time::Duration;

use async_trait::async_trait;

#[async_trait]
pub trait ButtrbaseTransport: Send + Sync {
    async fn execute(&self, req: reqwest::Request) -> Result<http::Response<bytes::Bytes>, Box<dyn std::error::Error + Send + Sync>>;
}

#[derive(Clone)]
pub struct DefaultTransport {
    client: reqwest::Client,
}

#[async_trait]
impl ButtrbaseTransport for DefaultTransport {
    async fn execute(&self, req: reqwest::Request) -> Result<http::Response<bytes::Bytes>, Box<dyn std::error::Error + Send + Sync>> {
        let resp = self.client.execute(req).await?;
        let status = resp.status();
        let mut builder = http::Response::builder()
            .status(status)
            .version(resp.version());
        for (k, v) in resp.headers() {
            builder = builder.header(k, v);
        }
        let bytes = resp.bytes().await?;
        Ok(builder.body(bytes)?)
    }
}


use http::HeaderMap;
use reqwest::{Client, Method, RequestBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use uuid::Uuid;

use crate::error::Error;
use crate::models::*;
use crate::verify::{AuthContext, Claims, Verifier, VerifierConfig};

const LIVE_BASE_URL: &str = "https://api.buttrbase.com";
const SANDBOX_BASE_URL: &str = "https://stagingapi.buttrbase.com";

/// The ButtrBase API client. Cheap to clone — the underlying HTTP
/// connection pool is `Arc`-wrapped by `reqwest`.
#[derive(Clone)]
pub struct ButtrBaseClient {
    pub(crate) environment: Environment,
    pub(crate) client_id: String,
    client_secret: Option<String>,
    pub(crate) base_url: String,
    http: Client,
    transport: std::sync::Arc<dyn ButtrbaseTransport>,
    verifier: Verifier,
    /// Which application's feature catalog entitlement checks resolve against.
    ///
    /// `/api/entitlements/check` REQUIRES `app_uuid` — the backend uses it to
    /// select the catalog (`fetch_features_by_app_uuid`); the bearer supplies
    /// the user/org, but not which app's features to evaluate. Omitting it is
    /// a hard `400 missing field 'app_uuid'`, not a soft default.
    ///
    /// `None` preserves the historical (broken) body for callers that have not
    /// set it, so adding this field breaks no existing consumer's build.
    /// Set it via [`ButtrBaseClient::with_app_uuid`].
    app_uuid: Option<Uuid>,
}

impl ButtrBaseClient {
    /// Create a client from your app credentials. The environment
    /// (`live` vs `sandbox`) is inferred automatically from the
    /// `client_id` prefix (`bb_live_` → live, `bb_test_` → sandbox).
    /// Create a public client for use in frontend/native apps without a client secret.
    pub fn new_public(client_id: impl Into<String>) -> Self {
        let client_id = client_id.into();
        let env = Environment::from_client_id(&client_id);
        let base_url = match env {
            Environment::Live => LIVE_BASE_URL,
            Environment::Sandbox => SANDBOX_BASE_URL,
        };
        Self::build(client_id, None, env, base_url.to_string())
    }

    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        let client_id = client_id.into();
        let env = Environment::from_client_id(&client_id);
        let base_url = match env {
            Environment::Live => LIVE_BASE_URL,
            Environment::Sandbox => SANDBOX_BASE_URL,
        };
        Self::build(client_id, Some(client_secret.into()), env, base_url.to_string())
    }

    /// Like [`new`] but overrides the base URL — useful for self-hosted
    /// deployments and integration tests.
    pub fn with_base_url(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Self {
        let client_id = client_id.into();
        let env = Environment::from_client_id(&client_id);
        Self::build(client_id, Some(client_secret.into()), env, base_url.into())
    }

    fn build(
        client_id: String,
        client_secret: Option<String>,
        environment: Environment,
        base_url: String,
    ) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client");

        let jwks_url = format!("{}/.well-known/jwks.json", base_url);
        let verifier = Verifier::new(VerifierConfig {
            jwks_url,
            issuer: base_url.clone(),
            // buttrbase tokens carry no stable per-app `aud` — don't pin it.
            audience: None,
        });

        let transport = std::sync::Arc::new(DefaultTransport { client: http.clone() });
        Self {
            environment,
            client_id,
            client_secret,
            base_url,
            http,
            transport,
            verifier,
            app_uuid: None,
        }
    }

    // ── Accessors ─────────────────────────────────────────────────────────

    pub fn environment(&self) -> Environment {
        self.environment
    }

    pub fn is_sandbox(&self) -> bool {
        self.environment.is_sandbox()
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }
    
    pub fn with_transport(mut self, transport: std::sync::Arc<dyn ButtrbaseTransport>) -> Self {
        self.transport = transport;
        self
    }

    /// Set the application whose feature catalog entitlement checks resolve
    /// against. REQUIRED for [`check_entitlement`](Self::check_entitlement) and
    /// [`check_entitlements`](Self::check_entitlements) — without it the
    /// backend rejects the request with `400 missing field 'app_uuid'`.
    pub fn with_app_uuid(mut self, app_uuid: Uuid) -> Self {
        self.app_uuid = Some(app_uuid);
        self
    }

    /// The configured application, if any. `None` means entitlement checks will
    /// be rejected by the backend — see [`with_app_uuid`](Self::with_app_uuid).
    pub fn app_uuid(&self) -> Option<Uuid> {
        self.app_uuid
    }

    // ── Internal request helpers ──────────────────────────────────────────

    /// Build a request using HTTP Basic auth (client_id:client_secret).
    /// Used for app-level operations that don't require a user token.
    fn app_request(&self, method: Method, path: &str) -> RequestBuilder {
        let req = self.http.request(method, format!("{}{}", self.base_url, path));
        if let Some(secret) = &self.client_secret {
            req.basic_auth(&self.client_id, Some(secret))
        } else {
            req.basic_auth(&self.client_id, None::<&str>)
        }
    }

    /// Build a request using the given user bearer token.
    fn user_request(&self, method: Method, path: &str, bearer: &str) -> RequestBuilder {
        self.http
            .request(method, format!("{}{}", self.base_url, path))
            .bearer_auth(bearer)
    }

    async fn send<T: DeserializeOwned>(&self, req: RequestBuilder) -> Result<T, Error> {
        let req = req.build().map_err(|e| Error::Unexpected { status: 0, body: e.to_string() })?;
        let resp = self.transport.execute(req).await.map_err(|e| Error::Unexpected { status: 0, body: e.to_string() })?;
        parse_response(resp).await
    }

    async fn send_empty(&self, req: RequestBuilder) -> Result<(), Error> {
        let req = req.build().map_err(|e| Error::Unexpected { status: 0, body: e.to_string() })?;
        let resp = self.transport.execute(req).await.map_err(|e| Error::Unexpected { status: 0, body: e.to_string() })?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let body_bytes = resp.into_body();
        let body = String::from_utf8(body_bytes.to_vec()).unwrap_or_default();
        Err(parse_error_body(status, &body))
    }

    // ── Token verification (local — no HTTP call) ─────────────────────────

    /// Verify a bare ButtrBase JWT string. Uses JWKS with a 5-minute
    /// cache and automatic key-rotation detection (one forced refetch on
    /// `kid` miss). No round-trip on the hot path.
    pub async fn verify_token(&self, token: &str) -> Result<Claims, Error> {
        if let Ok(header) = jsonwebtoken::decode_header(token) {
            if header.alg == jsonwebtoken::Algorithm::HS256 {
                let req = self.app_request(Method::POST, "/api/auth/introspect")
                    .header("X-Introspection-Key", std::env::var("INTROSPECTION_API_KEY").unwrap_or_default())
                    .json(&serde_json::json!({ "token": token }));
                
                let resp: serde_json::Value = self.send(req).await?;
                if resp.get("active").and_then(|v| v.as_bool()) != Some(true) {
                    return Err(Error::Unexpected { status: 401, body: "token inactive".to_string() });
                }
                
                let data = resp.get("data");
                let user_uuid_str = data.and_then(|d| d.get("user_uuid")).and_then(|v| v.as_str()).unwrap_or_default();
                let org_uuid_str = data.and_then(|d| d.get("org_uuid")).and_then(|v| v.as_str()).unwrap_or_default();
                let user_uuid = Uuid::parse_str(user_uuid_str).unwrap_or_default();
                let org_uuid = Uuid::parse_str(org_uuid_str).unwrap_or_default();
                let exp = resp.get("exp").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                let roles = data.and_then(|d| d.get("roles")).and_then(|v| v.as_str()).map(|s| s.to_string());
                
                return Ok(Claims {
                    sub: user_uuid,
                    org: org_uuid,
                    exp,
                    iat: 0,
                    scope: vec![],
                    data: Some(crate::verify::ClaimsData {
                        roles,
                        email: None,
                        org_uuid: Some(org_uuid),
                        user_uuid: Some(user_uuid),
                    }),
                });
            }
        }
        Ok(self.verifier.verify(token).await?)
    }

    /// Extract and verify a `Bearer <token>` from HTTP request headers.
    pub async fn verify_bearer(&self, headers: &HeaderMap) -> Result<AuthContext, Error> {
        let auth = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        if !auth.starts_with("Bearer ") {
            return Err(Error::Unexpected { status: 401, body: "missing bearer".into() });
        }
        let token = &auth[7..];
        let claims = self.verify_token(token).await?;
        Ok(AuthContext::from(claims))
    }

    // ── OTP / magic-link auth ─────────────────────────────────────────────

    /// Send a one-time-password email to `email`.
    ///
    /// The returned `TokenPair::token` is the `signup_token` to pass to
    /// `finalize_registration` after the user enters the code.
    pub async fn send_otp(&self, email: &str, app_uuid: Uuid) -> Result<(), Error> {
        let body = serde_json::json!({ "email": email, "app_uuid": app_uuid });
        self.send_empty(
            self.app_request(Method::POST, "/api/v1/auth/otp/send")
                .json(&body),
        )
        .await
    }

    /// Verify the OTP the user received. Returns a `TokenPair` carrying a
    /// real signed access token (`buttrbase-backend-rust`
    /// `routes/auth_core.rs::verify_otp` calls `sign_access_token` /
    /// `issue_tokens_with_email` in both its org and no-org branches — this
    /// is not a special short-lived "signup" token type). Callers on the
    /// signup path pass `TokenPair::token` straight through as the
    /// `signup_token` argument to `finalize_registration`; callers on the
    /// login path store it directly as the session's access token. Both
    /// uses work because the two are the same JWT shape.
    pub async fn verify_otp(
        &self,
        email: &str,
        otp: &str,
        app_uuid: Uuid,
    ) -> Result<TokenPair, Error> {
        let body = serde_json::json!({ "email": email, "otp": otp, "app_uuid": app_uuid });
        self.send(
            self.app_request(Method::POST, "/api/v1/auth/otp/verify")
                .json(&body),
        )
        .await
    }

    /// Send an OTP through the ORG-SCOPED app route
    /// (`POST /api/app/auth/otp/send`, `buttrbase-backend-rust`
    /// `routes/app_auth.rs::otp_send`).
    ///
    /// # Correction (2026-08-09): the previous deprecation note here was FALSE
    /// This method was previously marked `#[deprecated]` with a note claiming
    /// "slug-based identifiers are no longer accepted". Read against the live
    /// backend source, that is wrong: `otp_send` still matches `app_name`
    /// as a slug FIRST (`find_app_by_name_or_uuid`, name-match before the
    /// `app_uuid` fallback) and still requires non-empty `org_uuid`/
    /// `org_name`. The route is live and org-scoped, not obsolete. Removed
    /// the attribute rather than leave a false claim standing next to a
    /// method callers may reasonably need — see `verify_otp_with_org` for
    /// the analogous, corrected story on the verify side.
    ///
    /// Prefer plain `send_otp(email, app_uuid)` when you don't need org
    /// scoping at send time (the paired `verify_otp_with_org` still enforces
    /// org membership at verify time). Use this method directly only if you
    /// already have real `app_id`/`app_name`/`org_name` values; if you only
    /// have `app_uuid` + `org_uuid`, there is currently no send-side
    /// equivalent of `verify_otp_with_org` — see that method's doc comment
    /// for why the verify path needed one and the send path was out of
    /// scope for that change.
    pub async fn send_otp_legacy(
        &self,
        app_id: i32,
        app_name: &str,
        email: &str,
        org_uuid: &str,
        org_name: &str,
    ) -> Result<(), Error> {
        let body = serde_json::json!({
            "app_id":   app_id,
            "app_name": app_name,
            "email":    email,
            "org_uuid": org_uuid,
            "org_name": org_name,
        });
        self.send_empty(
            self.app_request(Method::POST, "/api/app/auth/otp/send")
                .json(&body),
        )
        .await
    }

    /// App-id sentinel sent by [`verify_otp_with_org`] on the org-scoped
    /// verify path when the caller has no numeric `app_id` — only a UUID.
    ///
    /// Traced against `buttrbase-backend-rust` source (2026-08-09, not
    /// executed — there is no live backend/test tenancy available from this
    /// environment): `app_id` is used ONLY for token-*policy* resolution
    /// (`decide_access_alg`, `resolve_token_policy`, the per-scope
    /// step-up-gate check inside `resolve_token_scopes`) — never for the
    /// user/org identity lookup (`resolve_otp_user` takes `_app_id: i32`
    /// and never reads it; the org lookup is keyed entirely on `org_uuid`).
    /// `resolve_token_policy` resolves an unmatched `(app_id, org_uuid)` /
    /// `(app_id, NIL_ORG)` composite key to `ResolvedTokenPolicy::default()`,
    /// whose `scope_strategy_windowed` is `false` — the same "no app-level
    /// step-up policy configured" default any ordinary app without this
    /// feature gets. With `windowed == false` the per-scope gate loop in
    /// `resolve_token_scopes` never runs, so this sentinel cannot widen
    /// scopes, strip gating that would otherwise apply, or misdirect the
    /// org boundary — it degrades only to the platform's existing default
    /// policy (HS256, unwindowed scopes). `i32::MAX` is additionally chosen
    /// to make an accidental collision with a real sequential `app_id`
    /// primary key effectively impossible.
    ///
    /// *** CORRECTION 2026-08-09 — THE PARAGRAPH ABOVE IS WRONG WHERE IT
    /// MATTERS. Read this before relying on it. ***
    ///
    /// "cannot widen scopes / strip gating that would otherwise apply" does
    /// not hold. Verified in the backend, not inferred:
    /// `resolve_token_scopes` (buttrbase-backend-rust
    /// `src/routes/app_auth.rs:282-310`) runs the per-scope gate loop
    /// **only inside `if windowed`**. Within that branch, any scope whose
    /// `gates::resolve_gate(db, app_id, org_uuid, &scope)` reports
    /// `required_factor != RequiredFactor::None` is EXCLUDED from the token.
    ///
    /// So `windowed == false` does not mean "gating is preserved" — it means
    /// **the gate is never consulted**, and step-up-gated scopes (e.g. ones
    /// requiring MFA) are handed out WITHOUT the step-up. That is strictly
    /// wider than what a windowed policy would have issued.
    ///
    /// The "degrades only to the platform default" claim is therefore true
    /// ONLY IF this app has no `token_policies` row. If it has one specifying
    /// `scope_strategy = "windowed"`, this sentinel silently bypasses it.
    /// Whether zlack's app has such a row was NOT determined — it needs a
    /// query against the real database.
    ///
    /// THE FIX is server-side and already half-written in the backend:
    /// `app_auth.rs:1009-1012` resolves `policy_app_id` from the app UUID via
    /// `applications::Entity::find()`, with a comment saying that is what the
    /// policy resolver wants. `:856` should do the same instead of trusting
    /// `body.app_id`. Until that lands, DO NOT SHIP a client build that
    /// reaches this path — see task #69/#80.
    const APP_ID_UNKNOWN: i32 = i32::MAX;

    /// Verify the OTP the user received, ENFORCING organization scope when
    /// `org_uuid` is `Some`.
    ///
    /// # Why this method exists — do not "simplify" it back to `verify_otp`
    /// `verify_otp` posts to `/api/v1/auth/otp/verify`
    /// (`buttrbase-backend-rust` `routes/auth_core.rs::verify_otp`), which
    /// has NO org parameter: any account matching email+otp succeeds
    /// regardless of which organization the caller is trying to enter.
    /// Dropping the org argument to make a call site compile silently
    /// removes org scoping from authentication — do not do that.
    ///
    /// This method instead targets the ORG-ENFORCING route
    /// (`POST /api/app/auth/otp/verify`, `routes/app_auth.rs::otp_verify`)
    /// when `org_uuid` is `Some`. Traced against that handler's source (not
    /// executed): it 400s if `org_uuid` is empty, `Uuid::parse_str`s it
    /// (400 on garbage), and resolves the user WITHIN that org via
    /// `resolve_otp_user`, which 404s if the account has no `orgusers` row
    /// in the target org. `app_uuid` there is `Option<Uuid>`, so this route
    /// is not purely slug-based despite what `verify_otp_legacy`'s old
    /// (removed) deprecation note claimed.
    ///
    /// When `org_uuid` is `None` (the signup path never runs the
    /// pre-OTP org lookup, and a lookup that failed open also leaves this
    /// `None` — see call-site comments), this delegates to plain
    /// [`Self::verify_otp`] — byte-identical to the pre-org-scoping
    /// request, so signup and lookup-outage flows are unaffected.
    ///
    /// # Fields this route requires that a UUID-only caller cannot supply
    /// The backend's `OtpVerifyRequest` also requires `app_name: String`
    /// and `app_id: i32`, which a caller holding only `app_uuid` (no
    /// numeric id or human-readable name) cannot supply real values for.
    /// Traced against source (not executed):
    /// - `app_name`: `find_app_by_name_or_uuid` tries a name-match FIRST
    ///   and falls back to the `app_uuid` hint only on a miss. This sends
    ///   `app_uuid`'s own string form, making a collision with a real
    ///   registered app name vanishingly unlikely and forcing the
    ///   (correct) uuid-fallback branch.
    /// - `app_id`: see [`Self::APP_ID_UNKNOWN`] — policy-only, traced safe.
    /// - `org_name`: `resolve_otp_user` never receives `org_name` — the org
    ///   lookup is 100% `org_uuid`-keyed. `org_name` is only ever embedded
    ///   as a display claim in the minted JWT via `sign_access_token`/
    ///   `sign_refresh_token`. This sends a value derived from `org_uuid`
    ///   (never empty, since the route 400s on an empty string) rather
    ///   than a fabricated name, and tags it so a decoded token visibly
    ///   shows it was populated by a uuid-only caller.
    ///
    /// None of the three substitutions above affect the org-membership
    /// boundary this method exists to close — that boundary is enforced
    /// entirely by `org_uuid`, checked server-side against real
    /// `organizations`/`orgusers` rows.
    ///
    /// # What is NOT verified by this crate
    /// There is no live backend or test tenancy reachable from this
    /// environment. Nothing above was empirically exercised — it is traced
    /// from `buttrbase-backend-rust` source only. Neither "a same-org user
    /// authenticates" nor "a cross-org user is refused" has been run. See
    /// the `#[ignore]`d integration test in this crate for exactly what
    /// must be run, and where, before this is trusted in production.
    pub async fn verify_otp_with_org(
        &self,
        email: &str,
        otp: &str,
        app_uuid: Uuid,
        org_uuid: Option<&str>,
    ) -> Result<TokenPair, Error> {
        let Some(org_uuid) = org_uuid.filter(|s| !s.trim().is_empty()) else {
            // No org context — identical to the pre-org-scoping request.
            return self.verify_otp(email, otp, app_uuid).await;
        };
        let body = serde_json::json!({
            "otp": otp,
            "email": email,
            "app_uuid": app_uuid,
            "app_name": format!("uuid-only:{app_uuid}"),
            "app_id": Self::APP_ID_UNKNOWN,
            "org_uuid": org_uuid,
            "org_name": format!("uuid-only:{org_uuid}"),
        });
        self.send(
            self.app_request(Method::POST, "/api/app/auth/otp/verify")
                .json(&body),
        )
        .await
    }

    /// Verify an OTP through the ORG-SCOPED app route directly, when the
    /// caller already has real `app_id`/`app_name`/`org_name` values (not
    /// just `app_uuid`/`org_uuid`).
    ///
    /// # Correction (2026-08-09): the previous deprecation note here was FALSE
    /// This method was previously marked `#[deprecated]` with a note
    /// claiming "slug-based identifiers are no longer accepted". Read
    /// against the live backend source, that is wrong: this method posts to
    /// `POST /api/app/auth/otp/verify` (`routes/app_auth.rs::otp_verify`),
    /// which is live, matches `app_name` as a slug FIRST
    /// (`find_app_by_name_or_uuid`), and genuinely enforces org membership
    /// (`resolve_otp_user` 404s outside the target org). It is the same
    /// route [`Self::verify_otp_with_org`] now targets for uuid-only
    /// callers. Removed the attribute rather than leave a false claim
    /// standing on a route this crate now depends on.
    pub async fn verify_otp_legacy(
        &self,
        app_id: i32,
        app_name: &str,
        email: &str,
        otp: &str,
        org_uuid: &str,
        org_name: &str,
    ) -> Result<TokenPair, Error> {
        let body = serde_json::json!({
            "app_id":   app_id,
            "app_name": app_name,
            "email":    email,
            "otp":      otp,
            "org_uuid": org_uuid,
            "org_name": org_name,
        });
        self.send(
            self.app_request(Method::POST, "/api/app/auth/otp/verify")
                .json(&body),
        )
        .await
    }

    // ── Registration (0.3.0+) ─────────────────────────────────────────────

    /// Check whether an org name is available before calling
    /// `finalize_registration`. Returns the normalized form and the
    /// reason if unavailable (`taken`, `too_short`, `invalid_chars`, …).
    pub async fn check_org_name(&self, name: &str) -> Result<CheckOrgNameResponse, Error> {
        let body = serde_json::json!({ "name": name });
        self.send(
            self.app_request(Method::POST, "/api/v1/auth/check-org-name")
                .json(&body),
        )
        .await
    }

    /// Complete user registration after OTP verification.
    ///
    /// `req.signup_token` must be the `token` field from `verify_otp`.
    /// `req.org_choice` is either `OrgChoice::Create { name }` (new org)
    /// or `OrgChoice::AcceptInvite { invitation_token }` (join via invite).
    ///
    /// Full flow: `send_otp` → `verify_otp` → `finalize_registration`.
    pub async fn finalize_registration(
        &self,
        req: &FinalizeRegistrationRequest<'_>,
    ) -> Result<RegistrationResult, Error> {
        self.send(
            self.app_request(Method::POST, "/api/v1/auth/finalize-registration")
                .json(req),
        )
        .await
    }

    /// Legacy one-shot registration (deprecated). The backend still serves
    /// this route for backward compatibility but the auto-create-by-domain
    /// behavior collides on the second sign-up from any domain and makes
    /// invitations impossible.
    ///
    /// Migrate to: `send_otp` → `verify_otp` → `finalize_registration`.
    #[deprecated(
        since = "0.3.0",
        note = "use send_otp + verify_otp + finalize_registration instead"
    )]
    pub async fn register(&self, req: &RegisterRequest<'_>) -> Result<RegistrationResult, Error> {
        self.send(
            self.app_request(Method::POST, "/api/v1/auth/register")
                .json(req),
        )
        .await
    }

    // ── Org invitations (0.3.0+) ─────────────────────────────────────────

    /// Create an org invitation. The plaintext `token` in the response is
    /// shown once — the backend stores only its SHA-256 hash and cannot
    /// re-surface it. Capture it immediately or share via `signup_url`.
    pub async fn create_invitation(
        &self,
        org_uuid: Uuid,
        req: &CreateInvitationRequest<'_>,
    ) -> Result<CreateInvitationResponse, Error> {
        self.send(
            self.app_request(
                Method::POST,
                &format!("/api/organizations/{}/invitations", org_uuid),
            )
            .json(req),
        )
        .await
    }

    /// Preview an invitation by its token (public — no auth required).
    /// Used to show "you've been invited to join Acme Inc" before signup.
    pub async fn preview_invitation(&self, token: &str) -> Result<InvitationPreview, Error> {
        self.send(
            self.http
                .request(
                    Method::GET,
                    format!("{}/api/auth/invitations/{}", self.base_url, token),
                ),
        )
        .await
    }

    /// Accept an invitation for an already-authenticated user joining an
    /// additional org. Brand-new users should use
    /// `finalize_registration` with `OrgChoice::AcceptInvite` instead.
    pub async fn accept_invitation(
        &self,
        bearer: &str,
        token: &str,
    ) -> Result<AcceptInvitationResponse, Error> {
        self.send(
            self.user_request(
                Method::POST,
                &format!("/api/auth/invitations/{}/accept", token),
                bearer,
            ),
        )
        .await
    }

    /// List all invitations for an org (pending, accepted, and revoked).
    pub async fn list_invitations(
        &self,
        bearer: &str,
        org_uuid: Uuid,
    ) -> Result<Vec<InvitationListItem>, Error> {
        self.send(self.user_request(
            Method::GET,
            &format!("/api/organizations/{}/invitations", org_uuid),
            bearer,
        ))
        .await
    }

    /// Revoke a pending invitation by its integer ID.
    pub async fn revoke_invitation(
        &self,
        bearer: &str,
        org_uuid: Uuid,
        invitation_id: i32,
    ) -> Result<(), Error> {
        self.send_empty(self.user_request(
            Method::DELETE,
            &format!(
                "/api/organizations/{}/invitations/{}",
                org_uuid, invitation_id
            ),
            bearer,
        ))
        .await
    }

    /// Refresh an access token using the refresh token from a previous
    /// `verify_otp` or `refresh_token` call.
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<AccessToken, Error> {
        let body = serde_json::json!({ "refresh": refresh_token });
        self.send(
            self.app_request(Method::POST, "/api/app/auth/refresh")
                .json(&body),
        )
        .await
    }

    /// Send a passwordless magic-link sign-in email.
    ///
    /// The user receives an email with a one-time link and clicks it; your app's
    /// callback page then exchanges the link's `token` via [`verify_magic_link`].
    ///
    /// Cross-app federation: pass your `app_uuid` and a `redirect_to` URL whose
    /// origin is registered on your Buttrbase application (its WebAuthn
    /// `rp_origins` / configured redirect URL). When `redirect_to` is on that
    /// allowlist, the email link points straight at *your* callback
    /// (`{redirect_to}?token=...`) so your app verifies the token itself.
    /// Otherwise the link falls back to the Buttrbase-hosted sign-in page.
    /// Pass `redirect_to = None` for the first-party (Buttrbase-hosted) flow.
    ///
    /// [`verify_magic_link`]: Self::verify_magic_link
    pub async fn send_magic_link(
        &self,
        email: &str,
        app_uuid: Uuid,
        redirect_to: Option<&str>,
    ) -> Result<MagicLinkSent, Error> {
        let body = serde_json::json!({
            "email": email,
            "app_uuid": app_uuid,
            "redirect_to": redirect_to,
        });
        self.send(
            self.app_request(Method::POST, "/api/auth/magic-link/send")
                .json(&body),
        )
        .await
    }

    /// Exchange the magic-link code from the email callback for a token pair.
    pub async fn verify_magic_link(&self, token: &str) -> Result<TokenPair, Error> {
        let body = serde_json::json!({ "token": token });
        self.send(
            self.app_request(Method::POST, "/api/auth/magic-link/verify")
                .json(&body),
        )
        .await
    }

    // ── Entitlements ──────────────────────────────────────────────────────

    /// Check whether the user holding `bearer` has access to `feature_key`.
    ///
    /// ```rust,ignore
    /// let result = bb.check_entitlement(&user_token, "advanced_analytics").await?;
    /// if result.granted { /* allow */ }
    /// ```
    pub async fn check_entitlement(
        &self,
        bearer: &str,
        feature_key: &str,
    ) -> Result<EntitlementResult, Error> {
        let mut body = serde_json::json!({ "feature_key": feature_key });
        self.attach_app_uuid(&mut body);
        let resp: EntitlementCheckResponse = self
            .send(
                self.user_request(Method::POST, "/api/entitlements/check", bearer)
                    .json(&body),
            )
            .await?;
        Ok(resp.data)
    }

    /// Add the configured `app_uuid` to an entitlement request body.
    ///
    /// Both entitlement endpoints require it; the bearer identifies the user
    /// and org, but the backend still needs to know WHICH app's feature
    /// catalog to evaluate against. When unset the field is omitted, which
    /// reproduces the pre-existing behaviour (a `400` from the backend) rather
    /// than inventing a default app — guessing here would silently evaluate a
    /// caller against another application's entitlements.
    fn attach_app_uuid(&self, body: &mut serde_json::Value) {
        if let (Some(app_uuid), Some(obj)) = (self.app_uuid, body.as_object_mut()) {
            obj.insert("app_uuid".to_string(), serde_json::json!(app_uuid));
        }
    }

    /// Check multiple feature keys in one call. Returns a map of
    /// `feature_key → EntitlementResult`.
    pub async fn check_entitlements(
        &self,
        bearer: &str,
        feature_keys: &[&str],
    ) -> Result<std::collections::HashMap<String, EntitlementResult>, Error> {
        let mut body = serde_json::json!({ "feature_keys": feature_keys });
        self.attach_app_uuid(&mut body);
        let resp: EntitlementBatchResponseData = self
            .send(
                self.user_request(
                    Method::POST,
                    "/api/entitlements/check/batch",
                    bearer,
                )
                .json(&body),
            )
            .await?;
        Ok(resp.data)
    }

    /// Return all effective entitlements for the user.
    pub async fn effective_entitlements(
        &self,
        bearer: &str,
    ) -> Result<Vec<EffectiveEntitlement>, Error> {
        let resp: DataWrapper<Vec<EffectiveEntitlement>> = self
            .send(self.user_request(
                Method::GET,
                "/api/entitlements/effective",
                bearer,
            ))
            .await?;
        Ok(resp.data)
    }

    // ── Pricing ───────────────────────────────────────────────────────────

    /// Preview the price (with tax, discount, region) for a given price_id.
    pub async fn pricing_preview(
        &self,
        bearer: &str,
        req: &PricingPreviewRequest,
    ) -> Result<PricingPreview, Error> {
        let resp: DataWrapper<PricingPreview> = self
            .send(
                self.user_request(Method::POST, "/api/pricing/preview", bearer)
                    .json(req),
            )
            .await?;
        Ok(resp.data)
    }

    /// Lock a signed price quote (10-minute TTL). Pass `quote_id` to
    /// `checkout_session` to guarantee the price the user saw.
    pub async fn pricing_quote(
        &self,
        bearer: &str,
        req: &PricingPreviewRequest,
    ) -> Result<serde_json::Value, Error> {
        let resp: DataWrapper<serde_json::Value> = self
            .send(
                self.user_request(Method::POST, "/api/pricing/quote", bearer)
                    .json(req),
            )
            .await?;
        Ok(resp.data)
    }

    /// Create a checkout session. **Blocked for sandbox credentials** —
    /// the backend returns 400 if the bearer token carries `sandbox:true`.
    pub async fn checkout_session(
        &self,
        bearer: &str,
        req: &CheckoutSessionRequest,
    ) -> Result<CheckoutSession, Error> {
        let resp: DataWrapper<CheckoutSession> = self
            .send(
                self.user_request(
                    Method::POST,
                    "/api/pricing/checkout-session",
                    bearer,
                )
                .json(req),
            )
            .await?;
        Ok(resp.data)
    }

    // ── Wallet ────────────────────────────────────────────────────────────

    /// Get the user's wallet balance and budget.
    pub async fn wallet(&self, bearer: &str) -> Result<WalletSummary, Error> {
        let resp: DataWrapper<WalletSummary> =
            self.send(self.user_request(Method::GET, "/api/wallet", bearer))
                .await?;
        Ok(resp.data)
    }

    /// List wallet transactions (deposits + withdrawals).
    pub async fn wallet_transactions(
        &self,
        bearer: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<WalletTransaction>, Error> {
        let path = format!(
            "/api/wallet/transactions?limit={}&offset={}",
            limit, offset
        );
        let resp: DataWrapper<Vec<WalletTransaction>> =
            self.send(self.user_request(Method::GET, &path, bearer))
                .await?;
        Ok(resp.data)
    }

    // ── Subscriptions ─────────────────────────────────────────────────────

    /// List the user's subscriptions.
    pub async fn subscriptions(&self, bearer: &str) -> Result<Vec<SubscriptionItem>, Error> {
        let resp: DataWrapper<Vec<SubscriptionItem>> = self
            .send(self.user_request(Method::GET, "/api/subscriptions", bearer))
            .await?;
        Ok(resp.data)
    }

    /// Create a subscription for a price.
    pub async fn create_subscription<S: Serialize>(
        &self,
        bearer: &str,
        body: &S,
    ) -> Result<SubscriptionItem, Error> {
        let resp: DataWrapper<SubscriptionItem> = self
            .send(
                self.user_request(Method::POST, "/api/subscriptions", bearer)
                    .json(body),
            )
            .await?;
        Ok(resp.data)
    }

    /// Cancel a subscription by ID.
    pub async fn cancel_subscription(
        &self,
        bearer: &str,
        subscription_id: i32,
    ) -> Result<(), Error> {
        self.send_empty(self.user_request(
            Method::DELETE,
            &format!("/api/subscriptions/{}", subscription_id),
            bearer,
        ))
        .await
    }

    // ── Billing history ───────────────────────────────────────────────────

    pub async fn billing_history(&self, bearer: &str) -> Result<Vec<Invoice>, Error> {
        let resp: DataWrapper<Vec<Invoice>> = self
            .send(self.user_request(Method::GET, "/api/billing/history", bearer))
            .await?;
        Ok(resp.data)
    }

    // ── Usage reporting ───────────────────────────────────────────────────

    /// Report a metered usage event for billing reconciliation. Uses app
    /// credentials (HTTP Basic), not a user token.
    ///
    /// ```rust,ignore
    /// bb.report_usage(UsageEvent {
    ///     metric: "api_calls".into(),
    ///     quantity: 1.0,
    ///     org_uuid: Some(org_uuid),
    ///     app_uuid: None,
    ///     timestamp: None,
    /// }).await?;
    /// ```
    pub async fn report_usage(&self, event: &UsageEvent) -> Result<(), Error> {
        self.send_empty(
            self.app_request(Method::POST, "/api/usage/report")
                .json(event),
        )
        .await
    }

    // ── Analytics ─────────────────────────────────────────────────────────

    /// Ingest an analytics event on behalf of a user.
    pub async fn ingest_event(
        &self,
        bearer: &str,
        event: &AnalyticsEvent,
    ) -> Result<(), Error> {
        self.send_empty(
            self.user_request(Method::POST, "/api/analytics/events", bearer)
                .json(event),
        )
        .await
    }

    /// Get analytics overview for an app. Uses app credentials.
    pub async fn app_analytics_overview(
        &self,
        app_uuid: &str,
        period: &str,
    ) -> Result<serde_json::Value, Error> {
        let path = format!(
            "/api/analytics/apps/{}/overview?period={}",
            app_uuid, period
        );
        let resp: DataWrapper<serde_json::Value> =
            self.send(self.app_request(Method::GET, &path)).await?;
        Ok(resp.data)
    }

    /// Get analytics overview for an org (pass user bearer).
    pub async fn org_analytics_overview(
        &self,
        bearer: &str,
        org_uuid: &str,
        period: &str,
    ) -> Result<serde_json::Value, Error> {
        let path = format!(
            "/api/analytics/organizations/{}/overview?period={}",
            org_uuid, period
        );
        let resp: DataWrapper<serde_json::Value> =
            self.send(self.user_request(Method::GET, &path, bearer))
                .await?;
        Ok(resp.data)
    }

    // ── Teams ─────────────────────────────────────────────────────────────

    /// List active teams in an org.
    pub async fn org_teams(
        &self,
        bearer: &str,
        org_uuid: &str,
    ) -> Result<Vec<TeamItem>, Error> {
        let resp: DataWrapper<Vec<TeamItem>> = self
            .send(self.user_request(
                Method::GET,
                &format!("/api/organizations/{}/teams", org_uuid),
                bearer,
            ))
            .await?;
        Ok(resp.data)
    }

    /// List teams a user is a member of.
    pub async fn user_teams(
        &self,
        bearer: &str,
        user_uuid: &str,
    ) -> Result<Vec<TeamItem>, Error> {
        let resp: DataWrapper<Vec<TeamItem>> = self
            .send(self.user_request(
                Method::GET,
                &format!("/api/users/{}/teams", user_uuid),
                bearer,
            ))
            .await?;
        Ok(resp.data)
    }

    // ── Apps ──────────────────────────────────────────────────────────────

    /// List apps the authenticated user belongs to.
    pub async fn my_apps(&self, bearer: &str) -> Result<Vec<AppEntry>, Error> {
        let resp: DataWrapper<Vec<AppEntry>> = self
            .send(self.user_request(Method::GET, "/api/me/apps", bearer))
            .await?;
        Ok(resp.data)
    }

    /// List orgs within an app that the user belongs to.
    pub async fn app_orgs(
        &self,
        bearer: &str,
        app_uuid: &str,
    ) -> Result<Vec<OrgEntry>, Error> {
        let resp: DataWrapper<Vec<OrgEntry>> = self
            .send(self.user_request(
                Method::GET,
                &format!("/api/apps/{}/organizations", app_uuid),
                bearer,
            ))
            .await?;
        Ok(resp.data)
    }

    /// Get live/sandbox credential info for an app (admin only).
    pub async fn app_credentials(
        &self,
        bearer: &str,
        app_uuid: &str,
    ) -> Result<AppCredentialsResponse, Error> {
        let resp: DataWrapper<AppCredentialsResponse> = self
            .send(self.user_request(
                Method::GET,
                &format!("/api/apps/{}/credentials", app_uuid),
                bearer,
            ))
            .await?;
        Ok(resp.data)
    }

    /// Enable sandbox mode for an app.
    pub async fn enable_sandbox(&self, bearer: &str, app_uuid: &str) -> Result<(), Error> {
        let body = serde_json::json!({ "sandbox_enabled": true });
        self.send_empty(
            self.user_request(Method::PATCH, &format!("/api/apps/{}", app_uuid), bearer)
                .json(&body),
        )
        .await
    }

    /// Rotate credentials for an environment (`"live"` or `"sandbox"`).
    pub async fn rotate_credentials(
        &self,
        bearer: &str,
        app_uuid: &str,
        environment: &str,
    ) -> Result<serde_json::Value, Error> {
        let resp: DataWrapper<serde_json::Value> = self
            .send(self.user_request(
                Method::POST,
                &format!(
                    "/api/apps/{}/credentials/{}/rotate",
                    app_uuid, environment
                ),
                bearer,
            ))
            .await?;
        Ok(resp.data)
    }

    // ── Password reset (no auth) ──────────────────────────────────────────

    /// Request a password-reset email for `email`. No app credentials are
    /// sent — this endpoint is publicly accessible.
    pub async fn request_password_reset(&self, email: &str) -> Result<serde_json::Value, Error> {
        let body = serde_json::json!({ "email": email });
        self.send(
            self.http
                .request(
                    Method::POST,
                    format!("{}/api/auth/request-password-reset", self.base_url),
                )
                .json(&body),
        )
        .await
    }

    /// Complete a password reset using the `token` from the reset email and
    /// the new `password`. No app credentials are sent.
    pub async fn reset_password(
        &self,
        token: &str,
        password: &str,
    ) -> Result<serde_json::Value, Error> {
        let body = serde_json::json!({ "token": token, "password": password });
        self.send(
            self.http
                .request(
                    Method::POST,
                    format!("{}/api/auth/reset-password", self.base_url),
                )
                .json(&body),
        )
        .await
    }

    // ── Webhooks (app auth) ───────────────────────────────────────────────

    /// List all webhooks registered for this app.
    pub async fn list_webhooks(&self) -> Result<serde_json::Value, Error> {
        self.send(self.app_request(Method::GET, "/api/v1/webhooks"))
            .await
    }

    /// Register a new webhook endpoint.
    ///
    /// * `url`            — HTTPS URL that will receive webhook payloads.
    /// * `event_types`    — List of event type strings to subscribe to.
    /// * `signing_secret` — Optional HMAC signing secret for payload verification.
    /// * `description`    — Optional human-readable label.
    pub async fn create_webhook(
        &self,
        url: &str,
        event_types: Vec<String>,
        signing_secret: Option<&str>,
        description: Option<&str>,
    ) -> Result<serde_json::Value, Error> {
        let mut body = serde_json::json!({
            "url": url,
            "event_types": event_types,
        });
        if let Some(s) = signing_secret {
            body["signing_secret"] = serde_json::Value::String(s.to_string());
        }
        if let Some(d) = description {
            body["description"] = serde_json::Value::String(d.to_string());
        }
        self.send(
            self.app_request(Method::POST, "/api/v1/webhooks")
                .json(&body),
        )
        .await
    }

    /// Delete a webhook by its integer ID. Returns `()` on success (HTTP 204).
    pub async fn delete_webhook(&self, webhook_id: i32) -> Result<(), Error> {
        self.send_empty(self.app_request(
            Method::DELETE,
            &format!("/api/v1/webhooks/{}", webhook_id),
        ))
        .await
    }

    /// List delivery attempts for a webhook.
    pub async fn list_webhook_deliveries(
        &self,
        webhook_id: i32,
    ) -> Result<serde_json::Value, Error> {
        self.send(self.app_request(
            Method::GET,
            &format!("/api/v1/webhooks/{}/deliveries", webhook_id),
        ))
        .await
    }

    /// Retry a specific webhook delivery attempt.
    pub async fn retry_webhook_delivery(
        &self,
        webhook_id: i32,
        delivery_id: i32,
    ) -> Result<serde_json::Value, Error> {
        self.send(self.app_request(
            Method::POST,
            &format!(
                "/api/v1/webhooks/{}/deliveries/{}/retry",
                webhook_id, delivery_id
            ),
        ))
        .await
    }

    // ── OAuth connections (app auth) ──────────────────────────────────────

    /// Force a token refresh for the given OAuth `provider` connection
    /// (e.g. `"github"`, `"google"`).
    pub async fn refresh_oauth_connection(
        &self,
        provider: &str,
    ) -> Result<serde_json::Value, Error> {
        self.send(self.app_request(
            Method::POST,
            &format!("/v1/oauth/connections/{}/refresh", provider),
        ))
        .await
    }

    // ── Email (app auth) ──────────────────────────────────────────────────

    /// Send a transactional email via the ButtrBase email service.
    ///
    /// At least one of `html_body` or `text_body` should be provided.
    pub async fn send_email(
        &self,
        to: &str,
        subject: &str,
        html_body: Option<&str>,
        text_body: Option<&str>,
        from_address: Option<&str>,
    ) -> Result<serde_json::Value, Error> {
        let mut body = serde_json::json!({
            "to": to,
            "subject": subject,
        });
        if let Some(h) = html_body {
            body["html_body"] = serde_json::Value::String(h.to_string());
        }
        if let Some(t) = text_body {
            body["text_body"] = serde_json::Value::String(t.to_string());
        }
        if let Some(f) = from_address {
            body["from_address"] = serde_json::Value::String(f.to_string());
        }
        self.send(
            self.app_request(Method::POST, "/api/email/send")
                .json(&body),
        )
        .await
    }

    /// Send an transactional email with custom `from_address` and `reply_to` headers.
    pub async fn send_email_with_reply_to(
        &self,
        to: &str,
        subject: &str,
        html_body: Option<&str>,
        text_body: Option<&str>,
        from_address: Option<&str>,
        reply_to: Option<&str>,
    ) -> Result<serde_json::Value, Error> {
        let mut body = serde_json::json!({
            "to": to,
            "subject": subject,
        });
        if let Some(h) = html_body {
            body["html_body"] = serde_json::Value::String(h.to_string());
        }
        if let Some(t) = text_body {
            body["text_body"] = serde_json::Value::String(t.to_string());
        }
        if let Some(f) = from_address {
            body["from_address"] = serde_json::Value::String(f.to_string());
        }
        if let Some(r) = reply_to {
            body["reply_to"] = serde_json::Value::String(r.to_string());
        }
        self.send(
            self.app_request(Method::POST, "/api/email/send")
                .json(&body),
        )
        .await
    }

    // ── Backwards compatibility & missing integration methods ────────────────

    /// Deprecated alias for [`send_magic_link`](Self::send_magic_link); kept for
    /// source compatibility. Prefer `send_magic_link(email, app_uuid, redirect_to)`.
    #[deprecated(note = "use send_magic_link(email, app_uuid, redirect_to)")]
    pub async fn magic_link_send(
        &self,
        email: &str,
        redirect_to: Option<&str>,
        app_uuid: Uuid,
    ) -> Result<MagicLinkSent, Error> {
        self.send_magic_link(email, app_uuid, redirect_to).await
    }

    /// Exchange a magic-link token for a token pair (backward compatibility).
    pub async fn magic_link_verify(&self, token: &str) -> Result<LoginResponse, Error> {
        let body = serde_json::json!({ "token": token });
        let raw_resp: serde_json::Value = self
            .send(
                self.app_request(Method::POST, "/api/auth/magic-link/verify")
                    .json(&body),
            )
            .await?;

        // 1. Try to extract from the raw response body (old API style)
        if let Some(user_obj) = raw_resp.get("user") {
            if let Ok(user) = serde_json::from_value::<User>(user_obj.clone()) {
                let access_token = raw_resp
                    .get("access_token")
                    .or_else(|| raw_resp.get("token"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                return Ok(LoginResponse {
                    access_token,
                    user,
                });
            }
        }

        // 2. Fall back to parsing the JWT token from TokenPair (new API style)
        if let Ok(pair) = serde_json::from_value::<TokenPair>(raw_resp.clone()) {
            if let Ok(claims) = self.verify_token(&pair.token).await {
                return Ok(LoginResponse {
                    access_token: Some(pair.token),
                    user: User {
                        id: 0,
                        user_uuid: claims.sub.to_string(),
                        email: "".to_string(),
                        org_uuid: claims.org.to_string(),
                    },
                });
            }
        }

        Err(Error::Unexpected {
            status: 400,
            body: "failed to verify magic link and parse response".to_string(),
        })
    }

    /// Begin OIDC authorize flow (backward compatibility).
    pub async fn oidc_authorize_url(
        &self,
        connection_uuid: &str,
    ) -> Result<serde_json::Value, Error> {
        self.send(self.app_request(
            Method::GET,
            &format!("/api/auth/oidc/{}/authorize", connection_uuid),
        ))
        .await
    }

    /// OIDC Callback (backward compatibility).
    pub async fn oidc_callback(
        &self,
        params: &std::collections::HashMap<String, String>,
    ) -> Result<serde_json::Value, Error> {
        let qs: String = params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        self.send(self.app_request(
            Method::GET,
            &format!("/api/auth/oidc/callback?{}", qs),
        ))
        .await
    }

    /// Begin SAML authorize flow (backward compatibility).
    pub async fn saml_authorize_url(
        &self,
        connection_uuid: &str,
    ) -> Result<serde_json::Value, Error> {
        self.send(self.app_request(
            Method::GET,
            &format!("/api/auth/saml/{}/authorize", connection_uuid),
        ))
        .await
    }

    /// SAML Callback (backward compatibility).
    pub async fn saml_callback(
        &self,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, Error> {
        self.send(self.app_request(
            Method::POST,
            "/api/auth/saml/callback"
        ).json(payload))
        .await
    }

    /// List all invoices (backward compatibility).
    pub async fn list_invoices(&self) -> Result<Vec<Invoice>, Error> {
        let resp: DataWrapper<Vec<Invoice>> = self
            .send(self.app_request(Method::GET, "/api/billing/invoices"))
            .await?;
        Ok(resp.data)
    }

    /// Get teams in an organization (admin / backward compatibility).
    pub async fn get_org_teams(
        &self,
        org_uuid: &str,
    ) -> Result<Vec<TeamItem>, Error> {
        let resp: DataWrapper<Vec<TeamItem>> = self
            .send(self.app_request(
                Method::GET,
                &format!("/api/v2/organizations/{}/teams", org_uuid),
            ))
            .await?;
        Ok(resp.data)
    }

    /// List members of a team (admin / backward compatibility).
    pub async fn list_team_members(
        &self,
        team_uuid: &str,
    ) -> Result<Vec<serde_json::Value>, Error> {
        let resp: DataWrapper<Vec<serde_json::Value>> = self
            .send(self.app_request(
                Method::GET,
                &format!("/api/teams/{}/members", team_uuid),
            ))
            .await?;
        Ok(resp.data)
    }

    /// Check entitlements for an organization (admin / backward compatibility).
    pub async fn entitlements_check(
        &self,
        data: &EntitlementCheckRequest<'_>,
    ) -> Result<EntitlementCheckResponseLegacy, Error> {
        let resp: DataWrapper<EntitlementCheckResponseLegacy> = self
            .send(self.app_request(Method::POST, "/api/entitlements/check").json(data))
            .await?;
        Ok(resp.data)
    }
}

// ── Response parsing helpers ──────────────────────────────────────────────

async fn parse_response<T: DeserializeOwned>(resp: http::Response<bytes::Bytes>) -> Result<T, Error> {
    let status = resp.status();
    if status.is_success() {
        let bytes = resp.into_body();
        serde_json::from_slice(&bytes).map_err(|e| {
            // Preserve the raw body in the error message for debugging.
            let preview: String = String::from_utf8_lossy(&bytes[..bytes.len().min(200)])
                .into_owned();
            Error::Unexpected {
                status: status.as_u16(),
                body: format!("deserialise error: {e} — body: {preview}"),
            }
        })
    } else {
        let body_bytes = resp.into_body();
        let body = String::from_utf8(body_bytes.to_vec()).unwrap_or_default();
        Err(parse_error_body(status, &body))
    }
}

fn parse_error_body(status: StatusCode, body: &str) -> Error {
    // Try to parse `{ "error": { "message": ..., "code": ... } }` or
    // `{ "message": ... }` (ButtrBase uses both shapes).
    if let Ok(api_err) = serde_json::from_str::<ApiErrorBody>(body) {
        let (message, code) = if let Some(detail) = api_err.error {
            (detail.message, detail.code)
        } else if let Some(msg) = api_err.message {
            (msg, None)
        } else {
            (body.to_string(), None)
        };
        return Error::Api {
            status: status.as_u16(),
            message,
            code,
        };
    }
    Error::Unexpected {
        status: status.as_u16(),
        body: body.to_string(),
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use httpmock::Method::{DELETE, PATCH};
    use serde_json::json;

    fn make_client(server: &MockServer) -> ButtrBaseClient {
        ButtrBaseClient::with_base_url("bb_test_cid_test", "bb_test_sk_test", server.base_url())
    }

    fn make_live_client(server: &MockServer) -> ButtrBaseClient {
        ButtrBaseClient::with_base_url("bb_live_cid_test", "bb_live_sk_test", server.base_url())
    }

    fn wrap_data(val: serde_json::Value) -> serde_json::Value {
        json!({ "data": val })
    }

    // ── Constructor / accessors ─────────────────────────────────────────────

    #[test]
    fn test_new_sandbox_detected() {
        let c = ButtrBaseClient::new("bb_test_cid_foo", "bb_test_sk_foo");
        assert_eq!(c.environment(), Environment::Sandbox);
        assert!(c.is_sandbox());
    }

    #[test]
    fn test_new_live_detected() {
        let c = ButtrBaseClient::new("bb_live_cid_foo", "bb_live_sk_foo");
        assert_eq!(c.environment(), Environment::Live);
        assert!(!c.is_sandbox());
    }

    #[test]
    fn test_with_base_url_overrides_url() {
        let c = ButtrBaseClient::with_base_url("bb_test_cid_foo", "secret", "https://custom.host");
        assert_eq!(c.base_url(), "https://custom.host");
        assert_eq!(c.environment(), Environment::Sandbox);
    }

    #[test]
    fn test_client_clone() {
        let c = ButtrBaseClient::new("bb_test_cid_foo", "secret");
        let c2 = c.clone();
        assert_eq!(c2.environment(), c.environment());
    }

    // ── Environment model ──────────────────────────────────────────────────

    #[test]
    fn test_environment_as_str() {
        assert_eq!(Environment::Live.as_str(), "live");
        assert_eq!(Environment::Sandbox.as_str(), "sandbox");
    }

    #[test]
    fn test_environment_display() {
        assert_eq!(format!("{}", Environment::Live), "live");
        assert_eq!(format!("{}", Environment::Sandbox), "sandbox");
    }

    #[test]
    fn test_environment_is_sandbox() {
        assert!(Environment::Sandbox.is_sandbox());
        assert!(!Environment::Live.is_sandbox());
    }

    #[test]
    fn test_environment_from_client_id_sandbox() {
        assert_eq!(Environment::from_client_id("bb_test_foo"), Environment::Sandbox);
    }

    #[test]
    fn test_environment_from_client_id_live() {
        assert_eq!(Environment::from_client_id("bb_live_foo"), Environment::Live);
        assert_eq!(Environment::from_client_id("other"), Environment::Live);
    }

    #[test]
    fn test_environment_copy() {
        let e = Environment::Live;
        let e2 = e; // Copy
        assert_eq!(e, e2);
    }

    // ── Error type ─────────────────────────────────────────────────────────

    #[test]
    fn test_error_api_display() {
        let e = Error::Api {
            status: 401,
            message: "Unauthorized".to_string(),
            code: Some("AUTH_REQUIRED".to_string()),
        };
        let s = format!("{}", e);
        assert!(s.contains("401"));
        assert!(s.contains("Unauthorized"));
    }

    #[test]
    fn test_error_unexpected_display() {
        let e = Error::Unexpected {
            status: 500,
            body: "Internal Server Error".to_string(),
        };
        let s = format!("{}", e);
        assert!(s.contains("500"));
    }

    #[test]
    fn test_error_json_display() {
        let inner = serde_json::from_str::<serde_json::Value>("not valid json").unwrap_err();
        let e = Error::Json(inner);
        let s = format!("{}", e);
        assert!(s.contains("serialisation error"));
    }

    // ── send_otp (0.3.0) ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_send_otp_success() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/v1/auth/otp/send");
            then.status(200).body("{}");
        });
        let client = make_client(&server);
        client.send_otp("u@e.com", uuid::Uuid::nil()).await.unwrap();
    }

    #[tokio::test]
    async fn test_send_otp_api_error() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/v1/auth/otp/send");
            then.status(400)
                .json_body(json!({"error": {"message": "Invalid email", "code": "BAD_EMAIL"}}));
        });
        let client = make_client(&server);
        let result = client.send_otp("bad", uuid::Uuid::nil()).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Api { status, message, code } => {
                assert_eq!(status, 400);
                assert_eq!(message, "Invalid email");
                assert_eq!(code, Some("BAD_EMAIL".to_string()));
            }
            e => panic!("unexpected: {:?}", e),
        }
    }

    // ── verify_otp (0.3.0) ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_verify_otp_success() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/v1/auth/otp/verify");
            then.status(200).json_body(json!({
                "token": "signup_token_jwt",
                "refresh_token": null,
                "user_uuid": null
            }));
        });
        let client = make_client(&server);
        let pair = client.verify_otp("u@e.com", "123456", uuid::Uuid::nil()).await.unwrap();
        assert_eq!(pair.token, "signup_token_jwt");
    }

    // ── send_otp_legacy / verify_otp_legacy ────────────────────────────────

    #[tokio::test]
    #[allow(deprecated)]
    async fn test_send_otp_legacy_success() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/app/auth/otp/send");
            then.status(200).body("{}");
        });
        let client = make_client(&server);
        client.send_otp_legacy(1, "myapp", "u@e.com", "org-uuid", "myorg").await.unwrap();
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn test_verify_otp_legacy_success() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/app/auth/otp/verify");
            then.status(200).json_body(json!({
                "token": "access_jwt",
                "refresh_token": "refresh_jwt",
                "user_uuid": "00000000-0000-0000-0000-000000000001"
            }));
        });
        let client = make_client(&server);
        let pair = client.verify_otp_legacy(1, "myapp", "u@e.com", "123456", "o-uuid", "myorg").await.unwrap();
        assert_eq!(pair.token, "access_jwt");
        assert_eq!(pair.refresh_token, Some("refresh_jwt".to_string()));
    }

    // ── verify_otp_with_org (task #69: org-scoping fix) ─────────────────────
    //
    // These two `#[tokio::test]`s below are routing/contract tests only —
    // same style and same confidence level as the other httpmock tests in
    // this file (method + path against a local mock server, NOT a real
    // backend). They confirm which URL each branch calls; they say nothing
    // about org enforcement, because a mock server has no `organizations`/
    // `orgusers` tables to enforce membership against. That is exactly what
    // the two `#[ignore]`d tests further below exist to check, against a
    // real deployment — do not mistake the routing tests below for coverage
    // of the security property.
    //
    // NOTE: none of the tests in this section (routing or `#[ignore]`d) were
    // compiled in this session — disk on the dev box hit ~130MiB free mid-task
    // (see task-69-report.md), below the point it is safe to run `cargo
    // check`/`cargo test` again. Written to match the existing httpmock
    // patterns in this file (`test_verify_otp_success` /
    // `test_verify_otp_legacy_success` above) as closely as possible to
    // minimize the chance of a syntax/API mistake, but that is a source-level
    // argument, not a build result — treat as unverified until `cargo test`
    // is actually run.

    #[tokio::test]
    async fn test_verify_otp_with_org_none_delegates_to_v1_route() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/v1/auth/otp/verify");
            then.status(200).json_body(json!({
                "token": "v1_access_or_signup_jwt",
                "refresh_token": null,
                "user_uuid": null
            }));
        });
        let client = make_client(&server);
        let pair = client
            .verify_otp_with_org("u@e.com", "123456", uuid::Uuid::nil(), None)
            .await
            .unwrap();
        assert_eq!(pair.token, "v1_access_or_signup_jwt");
    }

    #[tokio::test]
    async fn test_verify_otp_with_org_some_hits_org_enforcing_route() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/app/auth/otp/verify");
            then.status(200).json_body(json!({
                "token": "org_scoped_access_jwt",
                "refresh_token": "refresh_jwt",
                "user_uuid": "00000000-0000-0000-0000-000000000002"
            }));
        });
        let client = make_client(&server);
        let pair = client
            .verify_otp_with_org("u@e.com", "123456", uuid::Uuid::nil(), Some("org-uuid-a"))
            .await
            .unwrap();
        assert_eq!(pair.token, "org_scoped_access_jwt");
    }

    #[tokio::test]
    async fn test_verify_otp_with_org_empty_string_treated_as_none() {
        // An empty (not None) org_uuid must still take the no-org path — a
        // caller passing `Some("")` (e.g. from an `Option<String>` that was
        // initialized to `Some(String::new())` rather than `None`) must not
        // be sent to a route that 400s on an empty org_uuid.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/v1/auth/otp/verify");
            then.status(200).json_body(json!({
                "token": "v1_jwt",
                "refresh_token": null,
                "user_uuid": null
            }));
        });
        let client = make_client(&server);
        let pair = client
            .verify_otp_with_org("u@e.com", "123456", uuid::Uuid::nil(), Some(""))
            .await
            .unwrap();
        assert_eq!(pair.token, "v1_jwt");
    }

    // ── verify_otp_with_org — org-scoping EXECUTABLE SPEC (NOT RUN) ─────────
    //
    // Two-direction spec for the actual security property this method
    // exists for: a same-org user authenticates; a cross-org user is
    // REFUSED. Neither has been executed — there is no live
    // buttrbase-backend-rust deployment or seeded test tenancy reachable
    // from the environment this change was written in. `#[ignore]` keeps
    // both out of the default `cargo test` run so they can never silently
    // report green on nothing.
    //
    // Do NOT replace either test below with an httpmock server that scripts
    // the response this same change would produce for either direction —
    // that would prove only "the code does what it does", not that the
    // real backend's `orgusers` membership check
    // (`buttrbase-backend-rust` `src/routes/app_auth.rs::resolve_otp_user`)
    // actually refuses a real cross-org identity. A mock that asserts your
    // own implementation back at you is worse than no test.
    //
    // ## Required test tenancy (set up once, out of band, before running)
    // - A real, reachable buttrbase-backend-rust deployment — staging, not
    //   prod — with `SECRET_KEY`/DB configured.
    // - Real app credentials for that deployment:
    //   `BUTTRBASE_TEST_CLIENT_ID`, `BUTTRBASE_TEST_CLIENT_SECRET`.
    // - `BUTTRBASE_TEST_URL` — that deployment's base URL.
    // - `BUTTRBASE_TEST_APP_UUID` — the app's real `app_uuid`.
    // - Two real, distinct `organizations` rows under that app:
    //   `BUTTRBASE_TEST_ORG_A_UUID` and `BUTTRBASE_TEST_ORG_B_UUID`.
    // - A real user account with a real `orgusers` row in ORG A and
    //   deliberately NO `orgusers` row in ORG B:
    //   `BUTTRBASE_TEST_USER_EMAIL`.
    //
    // ## Getting a real OTP into each test
    // OTPs are single-use (cleared on the first successful verify) and
    // time-boxed (10 minutes — `OTP_TTL_MINUTES` in
    // `buttrbase-backend-rust` `routes/auth_core.rs`), so this spec does not
    // try to auto-mint one — the SDK's own `send_otp` deliberately discards
    // the response body (`Result<(), Error>`), so it cannot hand back a
    // dev-echoed code even when the backend has `BUTTRBASE_OTP_DEV_ECHO`
    // set (a real gap worth a follow-up: teach `send_otp` to optionally
    // surface `dev_code` when present, for exactly this kind of test).
    // Instead, immediately before running each test:
    //   1. Trigger `POST /api/v1/auth/otp/send` for `BUTTRBASE_TEST_USER_EMAIL`
    //      against `BUTTRBASE_TEST_APP_UUID` (e.g. `bb.send_otp(...)` from a
    //      scratch binary, or `curl`).
    //   2. Read the plaintext OTP from the backend's own log line — when no
    //      SES credentials are configured it logs
    //      `tracing::info!(target: "otp", email = %email, otp = %otp_plain,
    //      "OTP generated (no SES credentials)")` (`auth_core.rs::send_otp`)
    //      — or from the real inbox if SES is configured.
    //   3. Export it as `BUTTRBASE_TEST_OTP` within the 10-minute TTL.
    //   4. `cargo test --ignored verify_otp_with_org_ -- --test-threads=1`
    //      (each test needs its OWN fresh OTP — repeat steps 1-3 per test).

    #[tokio::test]
    #[ignore = "requires a live buttrbase-backend-rust deployment + seeded \
                two-org test tenancy + a freshly-minted real OTP; see the \
                doc comment directly above this test section for exact setup"]
    async fn verify_otp_with_org_same_org_user_authenticates() {
        let client_id = std::env::var("BUTTRBASE_TEST_CLIENT_ID").expect("BUTTRBASE_TEST_CLIENT_ID");
        let client_secret =
            std::env::var("BUTTRBASE_TEST_CLIENT_SECRET").expect("BUTTRBASE_TEST_CLIENT_SECRET");
        let base_url = std::env::var("BUTTRBASE_TEST_URL").expect("BUTTRBASE_TEST_URL");
        let bb = ButtrBaseClient::with_base_url(client_id, client_secret, base_url);

        let app_uuid: Uuid = std::env::var("BUTTRBASE_TEST_APP_UUID")
            .expect("BUTTRBASE_TEST_APP_UUID")
            .parse()
            .expect("BUTTRBASE_TEST_APP_UUID must be a valid UUID");
        let email = std::env::var("BUTTRBASE_TEST_USER_EMAIL").expect("BUTTRBASE_TEST_USER_EMAIL");
        let org_a = std::env::var("BUTTRBASE_TEST_ORG_A_UUID").expect("BUTTRBASE_TEST_ORG_A_UUID");
        let otp = std::env::var("BUTTRBASE_TEST_OTP")
            .expect("BUTTRBASE_TEST_OTP — mint one per the doc comment above, this is single-use");

        // Legitimate, authorized access: the real user IS a member of org A.
        // Proving this succeeds matters as much as proving org B is refused —
        // a fix that blocks everything trivially "passes" an attack-only test.
        let result = bb.verify_otp_with_org(&email, &otp, app_uuid, Some(&org_a)).await;
        assert!(
            result.is_ok(),
            "same-org user must authenticate, got: {result:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires a live buttrbase-backend-rust deployment + seeded \
                two-org test tenancy + a freshly-minted real OTP; see the \
                doc comment above verify_otp_with_org_same_org_user_authenticates \
                for exact setup"]
    async fn verify_otp_with_org_cross_org_user_is_refused() {
        let client_id = std::env::var("BUTTRBASE_TEST_CLIENT_ID").expect("BUTTRBASE_TEST_CLIENT_ID");
        let client_secret =
            std::env::var("BUTTRBASE_TEST_CLIENT_SECRET").expect("BUTTRBASE_TEST_CLIENT_SECRET");
        let base_url = std::env::var("BUTTRBASE_TEST_URL").expect("BUTTRBASE_TEST_URL");
        let bb = ButtrBaseClient::with_base_url(client_id, client_secret, base_url);

        let app_uuid: Uuid = std::env::var("BUTTRBASE_TEST_APP_UUID")
            .expect("BUTTRBASE_TEST_APP_UUID")
            .parse()
            .expect("BUTTRBASE_TEST_APP_UUID must be a valid UUID");
        let email = std::env::var("BUTTRBASE_TEST_USER_EMAIL").expect("BUTTRBASE_TEST_USER_EMAIL");
        let org_b = std::env::var("BUTTRBASE_TEST_ORG_B_UUID").expect("BUTTRBASE_TEST_ORG_B_UUID");
        let otp = std::env::var("BUTTRBASE_TEST_OTP")
            .expect("BUTTRBASE_TEST_OTP — mint one per the doc comment above, this is single-use");

        // The adversarial case: same real user, same real (valid) OTP —
        // only the org differs, and this user has NO `orgusers` row in
        // org B. Must be refused, not silently authenticated into the
        // wrong organization's data.
        let result = bb.verify_otp_with_org(&email, &otp, app_uuid, Some(&org_b)).await;
        assert!(
            result.is_err(),
            "cross-org user must be REFUSED, not authenticated; got: {result:?}"
        );
    }

    // ── check_org_name ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_check_org_name_available() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/v1/auth/check-org-name");
            then.status(200).json_body(json!({
                "available": true,
                "reason": null,
                "normalized": "acme-inc"
            }));
        });
        let client = make_client(&server);
        let resp = client.check_org_name("Acme Inc").await.unwrap();
        assert!(resp.available);
        assert_eq!(resp.normalized, "acme-inc");
        assert!(resp.reason.is_none());
    }

    #[tokio::test]
    async fn test_check_org_name_taken() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/v1/auth/check-org-name");
            then.status(200).json_body(json!({
                "available": false,
                "reason": "taken",
                "normalized": "acme"
            }));
        });
        let client = make_client(&server);
        let resp = client.check_org_name("acme").await.unwrap();
        assert!(!resp.available);
        assert_eq!(resp.reason, Some("taken".to_string()));
    }

    // ── finalize_registration ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_finalize_registration_create_org() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/v1/auth/finalize-registration");
            then.status(200).json_body(json!({
                "access_token":  "access_jwt",
                "refresh_token": "refresh_jwt",
                "token_type":    "Bearer",
                "expires_in":    3600,
                "user_uuid":     "00000000-0000-0000-0000-000000000001",
                "org_uuid":      "00000000-0000-0000-0000-000000000002",
                "role":          "admin",
                "message":       "Registration complete"
            }));
        });
        let client = make_client(&server);
        let req = crate::models::FinalizeRegistrationRequest {
            email: "alice@example.com",
            password: "s3cur3!",
            app_uuid: uuid::Uuid::nil(),
            signup_token: "signup_tok",
            org_choice: crate::models::OrgChoice::Create { name: "Acme Inc" },
            first_name: Some("Alice"),
            last_name: None,
        };
        let result = client.finalize_registration(&req).await.unwrap();
        assert_eq!(result.access_token, "access_jwt");
        assert_eq!(result.org_uuid, "00000000-0000-0000-0000-000000000002");
        assert_eq!(result.role, "admin");
    }

    #[tokio::test]
    async fn test_finalize_registration_accept_invite() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/v1/auth/finalize-registration");
            then.status(200).json_body(json!({
                "access_token":  "access_jwt",
                "refresh_token": "refresh_jwt",
                "token_type":    "Bearer",
                "expires_in":    3600,
                "user_uuid":     "00000000-0000-0000-0000-000000000001",
                "org_uuid":      "00000000-0000-0000-0000-000000000003",
                "role":          "member",
                "message":       null
            }));
        });
        let client = make_client(&server);
        let req = crate::models::FinalizeRegistrationRequest {
            email: "bob@example.com",
            password: "s3cur3!",
            app_uuid: uuid::Uuid::nil(),
            signup_token: "signup_tok",
            org_choice: crate::models::OrgChoice::AcceptInvite { invitation_token: "Bd9abc" },
            first_name: None,
            last_name: None,
        };
        let result = client.finalize_registration(&req).await.unwrap();
        assert_eq!(result.access_token, "access_jwt");
        assert_eq!(result.org_uuid, "00000000-0000-0000-0000-000000000003");
        assert_eq!(result.role, "member");
    }

    // ── register (deprecated) ─────────────────────────────────────────────

    #[tokio::test]
    #[allow(deprecated)]
    async fn test_register_legacy() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/v1/auth/register");
            then.status(200).json_body(json!({
                "access_token":  "access_jwt",
                "refresh_token": "refresh_jwt",
                "token_type":    "Bearer",
                "expires_in":    3600,
                "user_uuid":     "00000000-0000-0000-0000-000000000001",
                "org_uuid":      "00000000-0000-0000-0000-000000000002",
                "role":          "admin",
                "message":       null
            }));
        });
        let client = make_client(&server);
        let req = crate::models::RegisterRequest {
            email: "alice@example.com",
            password: "s3cur3!",
            org_name: "acme.com",
            app_uuid: uuid::Uuid::nil(),
            first_name: Some("Alice"),
            last_name: None,
        };
        let result = client.register(&req).await.unwrap();
        assert_eq!(result.access_token, "access_jwt");
        assert_eq!(result.org_uuid, "00000000-0000-0000-0000-000000000002");
    }

    // ── invitations ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_create_invitation() {
        let server = MockServer::start();
        let org_uuid = uuid::Uuid::nil();
        server.mock(|when, then| {
            when.method(POST)
                .path(format!("/api/organizations/{}/invitations", org_uuid));
            then.status(200).json_body(json!({
                "id": 1,
                "org_uuid": org_uuid,
                "email": "bob@example.com",
                "role": "member",
                "expires_at": "2026-07-01T00:00:00Z",
                "token": "Bd9plaintext",
                "signup_url": "https://app.example.com/signup?invite=Bd9plaintext"
            }));
        });
        let client = make_client(&server);
        let req = crate::models::CreateInvitationRequest {
            email: Some("bob@example.com"),
            role: Some("member"),
            expires_in_hours: Some(48),
        };
        let resp = client.create_invitation(org_uuid, &req).await.unwrap();
        assert_eq!(resp.token, "Bd9plaintext");
        assert_eq!(resp.role, "member");
    }

    #[tokio::test]
    async fn test_preview_invitation() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/auth/invitations/Bd9abc");
            then.status(200).json_body(json!({
                "org_uuid": "00000000-0000-0000-0000-000000000001",
                "org_name": "Acme Inc",
                "email": "bob@example.com",
                "role": "member",
                "expires_at": "2026-07-01T00:00:00Z",
                "valid": true,
                "invalid_reason": null
            }));
        });
        let client = make_client(&server);
        let preview = client.preview_invitation("Bd9abc").await.unwrap();
        assert!(preview.valid);
        assert_eq!(preview.org_name, "Acme Inc");
    }

    #[tokio::test]
    async fn test_accept_invitation() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/auth/invitations/Bd9abc/accept");
            then.status(200).json_body(json!({
                "org_uuid": "00000000-0000-0000-0000-000000000001",
                "org_name": "Acme Inc",
                "role": "member"
            }));
        });
        let client = make_client(&server);
        let resp = client.accept_invitation("user_tok", "Bd9abc").await.unwrap();
        assert_eq!(resp.org_name, "Acme Inc");
        assert_eq!(resp.role, "member");
    }

    #[tokio::test]
    async fn test_list_invitations() {
        let server = MockServer::start();
        let org_uuid = uuid::Uuid::nil();
        server.mock(|when, then| {
            when.method(GET)
                .path(format!("/api/organizations/{}/invitations", org_uuid));
            then.status(200).json_body(json!([{
                "id": 1,
                "email": "bob@example.com",
                "role": "member",
                "expires_at": "2026-07-01T00:00:00Z",
                "accepted_at": null,
                "revoked_at": null
            }]));
        });
        let client = make_client(&server);
        let list = client.list_invitations("tok", org_uuid).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].role, "member");
    }

    #[tokio::test]
    async fn test_revoke_invitation() {
        let server = MockServer::start();
        let org_uuid = uuid::Uuid::nil();
        server.mock(|when, then| {
            when.method(DELETE)
                .path(format!("/api/organizations/{}/invitations/42", org_uuid));
            then.status(204).body("");
        });
        let client = make_client(&server);
        client.revoke_invitation("tok", org_uuid, 42).await.unwrap();
    }

    // ── refresh_token ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_refresh_token_success() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/app/auth/refresh");
            then.status(200).json_body(json!({
                "token": "new_access_jwt",
                "refresh_token": "new_refresh_jwt"
            }));
        });
        let client = make_client(&server);
        let at = client.refresh_token("old_refresh_jwt").await.unwrap();
        assert_eq!(at.token, "new_access_jwt");
    }

    // ── send_magic_link / verify_magic_link ────────────────────────────────

    #[tokio::test]
    async fn test_send_magic_link_success() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/auth/magic-link/send");
            then.status(200).json_body(json!({"sent": true, "expires_in_seconds": 900}));
        });
        let client = make_client(&server);
        let result = client.send_magic_link("u@e.com", uuid::Uuid::nil(), Some("myapp")).await.unwrap();
        assert!(result.sent);
    }

    #[tokio::test]
    async fn test_verify_magic_link_success() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/auth/magic-link/verify");
            then.status(200).json_body(json!({
                "token": "ml_jwt",
                "refresh_token": null,
                "user_uuid": null
            }));
        });
        let client = make_client(&server);
        let pair = client.verify_magic_link("magic_code").await.unwrap();
        assert_eq!(pair.token, "ml_jwt");
    }

    // ── check_entitlement ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_check_entitlement_granted() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/entitlements/check");
            then.status(200).json_body(wrap_data(json!({"granted": true, "reason": null})));
        });
        let client = make_client(&server);
        let result = client.check_entitlement("user_token", "advanced_analytics").await.unwrap();
        assert!(result.granted);
        assert!(result.reason.is_none());
    }

    #[tokio::test]
    async fn test_check_entitlement_denied() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/entitlements/check");
            then.status(200).json_body(wrap_data(json!({"granted": false, "reason": "plan_limit"})));
        });
        let client = make_client(&server);
        let result = client.check_entitlement("user_token", "feature_x").await.unwrap();
        assert!(!result.granted);
        assert_eq!(result.reason, Some("plan_limit".to_string()));
    }

    // ── check_entitlements (batch) ─────────────────────────────────────────

    #[tokio::test]
    async fn test_check_entitlements_batch() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/entitlements/check/batch");
            then.status(200).json_body(wrap_data(json!({
                "feature_a": {"granted": true, "reason": null},
                "feature_b": {"granted": false, "reason": "plan_limit"}
            })));
        });
        let client = make_client(&server);
        let map = client.check_entitlements("tok", &["feature_a", "feature_b"]).await.unwrap();
        assert!(map["feature_a"].granted);
        assert!(!map["feature_b"].granted);
    }

    // ── effective_entitlements ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_effective_entitlements() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/entitlements/effective");
            then.status(200).json_body(wrap_data(json!([
                {"feature_key": "feat_a", "granted": true}
            ])));
        });
        let client = make_client(&server);
        let ents = client.effective_entitlements("tok").await.unwrap();
        assert_eq!(ents.len(), 1);
        assert_eq!(ents[0].feature_key, "feat_a");
        assert!(ents[0].granted);
    }

    // ── pricing_preview ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_pricing_preview() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/pricing/preview");
            then.status(200).json_body(wrap_data(json!({
                "amount_cents": 999,
                "currency": "USD",
                "discount_cents": null,
                "tax_cents": null,
                "final_cents": 999,
                "region_resolved": null
            })));
        });
        let client = make_client(&server);
        let req = crate::models::PricingPreviewRequest {
            price_id: 1,
            coupon_code: None,
            seats: None,
            country: None,
        };
        let preview = client.pricing_preview("tok", &req).await.unwrap();
        assert_eq!(preview.amount_cents, 999);
        assert_eq!(preview.currency, "USD");
        assert_eq!(preview.final_cents, 999);
    }

    // ── pricing_quote ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_pricing_quote() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/pricing/quote");
            then.status(200).json_body(wrap_data(json!({"quote_id": "q-1", "expires_at": "2024-12-31"})));
        });
        let client = make_client(&server);
        let req = crate::models::PricingPreviewRequest {
            price_id: 2,
            coupon_code: Some("SAVE10".to_string()),
            seats: Some(5),
            country: Some("US".to_string()),
        };
        let result = client.pricing_quote("tok", &req).await.unwrap();
        assert_eq!(result["quote_id"], "q-1");
    }

    // ── checkout_session ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_checkout_session() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/pricing/checkout-session");
            then.status(200).json_body(wrap_data(json!({
                "payment_url": "https://pay.example.com/sess_1",
                "session_id": "sess_1",
                "provider": "stripe"
            })));
        });
        let client = make_live_client(&server);
        let req = crate::models::CheckoutSessionRequest {
            price_id: 1,
            quote_id: None,
        };
        let session = client.checkout_session("tok", &req).await.unwrap();
        assert_eq!(session.provider, "stripe");
        assert!(session.payment_url.contains("sess_1"));
    }

    // ── wallet ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_wallet() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/wallet");
            then.status(200).json_body(wrap_data(json!({
                "balance_cents": 5000,
                "budget_limit_cents": 10000,
                "budget_period": "monthly"
            })));
        });
        let client = make_client(&server);
        let summary = client.wallet("tok").await.unwrap();
        assert_eq!(summary.balance_cents, 5000);
        assert_eq!(summary.budget_limit_cents, Some(10000));
    }

    // ── wallet_transactions ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_wallet_transactions() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path_contains("/api/wallet/transactions");
            then.status(200).json_body(wrap_data(json!([{
                "id": 1, "kind": "deposit", "amount_cents": 1000,
                "description": "Top-up", "created_at": "2024-01-01"
            }])));
        });
        let client = make_client(&server);
        let txns = client.wallet_transactions("tok", 10, 0).await.unwrap();
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].kind, "deposit");
        assert_eq!(txns[0].amount_cents, 1000);
    }

    // ── subscriptions ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_subscriptions() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/subscriptions");
            then.status(200).json_body(wrap_data(json!([{
                "id": 1,
                "user_uuid": "00000000-0000-0000-0000-000000000001",
                "price_id": 5,
                "provider": "stripe",
                "provider_subscription_id": "sub_xxx",
                "status": "active",
                "created_at": "2024-01-01",
                "updated_at": "2024-01-01"
            }])));
        });
        let client = make_client(&server);
        let subs = client.subscriptions("tok").await.unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].provider, "stripe");
        assert_eq!(subs[0].status, "active");
    }

    #[tokio::test]
    async fn test_cancel_subscription() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(DELETE).path("/api/subscriptions/42");
            then.status(200).body("{}");
        });
        let client = make_client(&server);
        client.cancel_subscription("tok", 42).await.unwrap();
    }

    // ── billing_history ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_billing_history() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/billing/history");
            then.status(200).json_body(wrap_data(json!([{
                "id": 1, "user_id": 1, "subscription_id": null,
                "provider": "stripe", "provider_invoice_id": "inv_1",
                "amount": 999, "status": "paid",
                "invoice_pdf_url": "https://pdf.example.com",
                "created_at": "2024-01-01", "updated_at": "2024-01-01"
            }])));
        });
        let client = make_client(&server);
        let history = client.billing_history("tok").await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].provider, "stripe");
        assert_eq!(history[0].amount, 999);
    }

    // ── report_usage ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_report_usage_success() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/usage/report");
            then.status(200).body("{}");
        });
        let client = make_client(&server);
        let event = crate::models::UsageEvent {
            metric: "api_calls".to_string(),
            quantity: 1.0,
            org_uuid: None,
            app_uuid: None,
            timestamp: None,
        };
        client.report_usage(&event).await.unwrap();
    }

    #[tokio::test]
    async fn test_report_usage_with_all_fields() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/usage/report");
            then.status(200).body("{}");
        });
        let client = make_client(&server);
        let event = crate::models::UsageEvent {
            metric: "storage_gb".to_string(),
            quantity: 2.5,
            org_uuid: Some(uuid::Uuid::nil()),
            app_uuid: Some(uuid::Uuid::nil()),
            timestamp: Some("2024-01-01T00:00:00Z".to_string()),
        };
        client.report_usage(&event).await.unwrap();
    }

    // ── ingest_event ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_ingest_event() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/analytics/events");
            then.status(200).body("{}");
        });
        let client = make_client(&server);
        let event = crate::models::AnalyticsEvent {
            event_type: "page_view".to_string(),
            properties: Some(json!({"page": "/home"})),
            timestamp: None,
        };
        client.ingest_event("tok", &event).await.unwrap();
    }

    // ── app_analytics_overview / org_analytics_overview ───────────────────

    #[tokio::test]
    async fn test_app_analytics_overview() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path_contains("/api/analytics/apps/app-1/overview");
            then.status(200).json_body(wrap_data(json!({"users": 100, "events": 500})));
        });
        let client = make_client(&server);
        let result = client.app_analytics_overview("app-1", "7d").await.unwrap();
        assert_eq!(result["users"], 100);
    }

    #[tokio::test]
    async fn test_org_analytics_overview() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path_contains("/api/analytics/organizations/org-1/overview");
            then.status(200).json_body(wrap_data(json!({"active_users": 50})));
        });
        let client = make_client(&server);
        let result = client.org_analytics_overview("tok", "org-1", "30d").await.unwrap();
        assert_eq!(result["active_users"], 50);
    }

    // ── teams ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_org_teams() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/organizations/org-1/teams");
            then.status(200).json_body(wrap_data(json!([{
                "id": 1,
                "team_uuid": "00000000-0000-0000-0000-000000000001",
                "org_uuid": "org-1",
                "name": "Engineering",
                "description": null
            }])));
        });
        let client = make_client(&server);
        let teams = client.org_teams("tok", "org-1").await.unwrap();
        assert_eq!(teams.len(), 1);
        assert_eq!(teams[0].name, "Engineering");
    }

    #[tokio::test]
    async fn test_user_teams() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/users/u-1/teams");
            then.status(200).json_body(wrap_data(json!([])));
        });
        let client = make_client(&server);
        let teams = client.user_teams("tok", "u-1").await.unwrap();
        assert!(teams.is_empty());
    }

    // ── apps ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_my_apps() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/me/apps");
            then.status(200).json_body(wrap_data(json!([{
                "app_uuid": "00000000-0000-0000-0000-000000000002",
                "app_name": "My SaaS",
                "role": "admin"
            }])));
        });
        let client = make_client(&server);
        let apps = client.my_apps("tok").await.unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].app_name, "My SaaS");
    }

    #[tokio::test]
    async fn test_app_orgs() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/apps/app-uuid-1/organizations");
            then.status(200).json_body(wrap_data(json!([{
                "org_uuid": "00000000-0000-0000-0000-000000000003",
                "org_name": "ACME Corp",
                "role": "owner"
            }])));
        });
        let client = make_client(&server);
        let orgs = client.app_orgs("tok", "app-uuid-1").await.unwrap();
        assert_eq!(orgs.len(), 1);
        assert_eq!(orgs[0].org_name, "ACME Corp");
    }

    #[tokio::test]
    async fn test_app_credentials() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/apps/app-uuid-1/credentials");
            then.status(200).json_body(wrap_data(json!({
                "app_name": "MySaaS",
                "sandbox_enabled": true,
                "live": {
                    "environment": "live",
                    "client_id": "bb_live_cid_xxx",
                    "client_secret_prefix": "bb_live_sk",
                    "is_active": true,
                    "created_at": "2024-01-01",
                    "rotated_at": null
                },
                "sandbox": null
            })));
        });
        let client = make_client(&server);
        let creds = client.app_credentials("tok", "app-uuid-1").await.unwrap();
        assert_eq!(creds.app_name, "MySaaS");
        assert!(creds.sandbox_enabled);
        assert!(creds.live.is_some());
        let live = creds.live.unwrap();
        assert_eq!(live.environment, "live");
        assert!(live.is_active);
    }

    #[tokio::test]
    async fn test_enable_sandbox() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(PATCH).path("/api/apps/app-uuid-1");
            then.status(200).body("{}");
        });
        let client = make_client(&server);
        client.enable_sandbox("tok", "app-uuid-1").await.unwrap();
    }

    #[tokio::test]
    async fn test_rotate_credentials() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/apps/app-uuid-1/credentials/live/rotate");
            then.status(200).json_body(wrap_data(json!({
                "client_id": "bb_live_cid_new",
                "client_secret": "bb_live_sk_new"
            })));
        });
        let client = make_live_client(&server);
        let result = client.rotate_credentials("tok", "app-uuid-1", "live").await.unwrap();
        assert_eq!(result["client_id"], "bb_live_cid_new");
    }

    // ── create_subscription ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_create_subscription() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/subscriptions");
            then.status(200).json_body(wrap_data(json!({
                "id": 2,
                "user_uuid": "00000000-0000-0000-0000-000000000001",
                "price_id": 3,
                "provider": "stripe",
                "provider_subscription_id": "sub_yyy",
                "status": "trialing",
                "created_at": "2024-01-01",
                "updated_at": "2024-01-01"
            })));
        });
        let client = make_client(&server);
        let body = json!({"price_id": 3});
        let sub = client.create_subscription("tok", &body).await.unwrap();
        assert_eq!(sub.status, "trialing");
    }

    // ── error: unexpected status ────────────────────────────────────────────

    #[tokio::test]
    async fn test_error_unexpected_status() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/wallet");
            then.status(503).body("Service Unavailable");
        });
        let client = make_client(&server);
        let result = client.wallet("tok").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Unexpected { status, .. } => assert_eq!(status, 503),
            Error::Api { status, .. } => assert_eq!(status, 503),
            e => panic!("unexpected error: {:?}", e),
        }
    }

    // ── error: api error with message-only shape ───────────────────────────

    #[tokio::test]
    async fn test_error_message_only_shape() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/wallet");
            then.status(403)
                .json_body(json!({"message": "Forbidden"}));
        });
        let client = make_client(&server);
        let result = client.wallet("tok").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Api { message, status, .. } => {
                assert_eq!(status, 403);
                assert_eq!(message, "Forbidden");
            }
            e => panic!("unexpected: {:?}", e),
        }
    }

    // ── verify_token / verify_bearer — bad token ──────────────────────────

    #[tokio::test]
    async fn test_verify_token_bad_format() {
        let client = make_client(&MockServer::start());
        let result = client.verify_token("not.a.jwt").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_bearer_missing_header() {
        let client = make_client(&MockServer::start());
        let headers = http::HeaderMap::new();
        let result = client.verify_bearer(&headers).await;
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod entitlement_app_uuid_tests {
    use super::*;
    use httpmock::prelude::*;
    use serde_json::json;

    const APP: &str = "c4de0a30-2462-48ad-b5a0-31b63486d920";

    fn client(server: &MockServer) -> ButtrBaseClient {
        ButtrBaseClient::with_base_url("bb_test_cid_test", "bb_test_sk_test", server.base_url())
    }

    /// The whole point of `with_app_uuid`: the backend REQUIRES `app_uuid` on
    /// `/api/entitlements/check` (it selects the feature catalog). Without it
    /// the live API answers `400 missing field 'app_uuid'`, which callers see
    /// as a transport error and — in fail-closed gates — as a denial.
    #[tokio::test]
    async fn check_entitlement_sends_app_uuid_when_configured() {
        let server = MockServer::start();
        let app = Uuid::parse_str(APP).unwrap();
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/api/entitlements/check")
                .json_body(json!({ "feature_key": "hosted-index", "app_uuid": APP }));
            then.status(200)
                .json_body(json!({ "data": { "granted": true } }));
        });

        let bb = client(&server).with_app_uuid(app);
        let result = bb.check_entitlement("tok", "hosted-index").await.unwrap();

        mock.assert(); // body matched exactly, app_uuid included
        assert!(result.granted);
        assert_eq!(bb.app_uuid(), Some(app));
    }

    /// Batch endpoint takes the same field — regression guard, since it builds
    /// its body separately and was equally broken.
    #[tokio::test]
    async fn check_entitlements_batch_sends_app_uuid_too() {
        let server = MockServer::start();
        let app = Uuid::parse_str(APP).unwrap();
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/api/entitlements/check/batch")
                .json_body(json!({ "feature_keys": ["a", "b"], "app_uuid": APP }));
            then.status(200).json_body(json!({ "data": {} }));
        });

        let bb = client(&server).with_app_uuid(app);
        bb.check_entitlements("tok", &["a", "b"]).await.unwrap();

        mock.assert();
    }

    /// Adding the field must not change what existing callers send. They keep
    /// the historical (backend-rejected) body rather than silently being
    /// attributed to some default application — guessing an app here would
    /// evaluate a caller against another app's entitlements.
    #[tokio::test]
    async fn check_entitlement_omits_app_uuid_when_unset() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/api/entitlements/check")
                .json_body(json!({ "feature_key": "hosted-index" }));
            then.status(200)
                .json_body(json!({ "data": { "granted": false } }));
        });

        let bb = client(&server); // no with_app_uuid
        let result = bb.check_entitlement("tok", "hosted-index").await.unwrap();

        mock.assert();
        assert!(!result.granted);
        assert_eq!(bb.app_uuid(), None);
    }
}

#[cfg(test)]
mod magic_link_shape_tests {
    use super::*;
    use crate::models::TokenPair;

    /// The backend's `/api/auth/magic-link/verify` returns
    /// `{access_token, token_type, user:{...}, redirect_to}`. `TokenPair` names
    /// the field `token`, so without `alias = "access_token"` this payload
    /// fails to deserialize and magic-link sign-in cannot complete.
    #[test]
    fn token_pair_accepts_the_backends_access_token_spelling() {
        let body = serde_json::json!({
            "access_token": "eyJ.a.b",
            "token_type": "Bearer",
            "user": { "user_uuid": "c4de0a30-2462-48ad-b5a0-31b63486d920", "email": "a@b.c" },
            "redirect_to": "https://example.test/cb"
        });
        let tp: TokenPair = serde_json::from_value(body).expect("must deserialize");
        assert_eq!(tp.token, "eyJ.a.b");
        // Nested under `user` on this endpoint, so flat extraction yields None —
        // asserted so a future flattening change is a deliberate decision.
        assert_eq!(tp.user_uuid, None);
    }

    /// Endpoints that already spelled it `token` must keep working.
    #[test]
    fn token_pair_still_accepts_the_plain_token_spelling() {
        let body = serde_json::json!({ "token": "plain", "refresh_token": "r" });
        let tp: TokenPair = serde_json::from_value(body).expect("must deserialize");
        assert_eq!(tp.token, "plain");
        assert_eq!(tp.refresh_token.as_deref(), Some("r"));
    }
}
