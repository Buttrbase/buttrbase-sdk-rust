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
    client_secret: String,
    pub(crate) base_url: String,
    http: Client,
    verifier: Verifier,
}

impl ButtrBaseClient {
    /// Create a client from your app credentials. The environment
    /// (`live` vs `sandbox`) is inferred automatically from the
    /// `client_id` prefix (`bb_live_` → live, `bb_test_` → sandbox).
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        let client_id = client_id.into();
        let env = Environment::from_client_id(&client_id);
        let base_url = match env {
            Environment::Live => LIVE_BASE_URL,
            Environment::Sandbox => SANDBOX_BASE_URL,
        };
        Self::build(client_id, client_secret.into(), env, base_url.to_string())
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
        Self::build(client_id, client_secret.into(), env, base_url.into())
    }

    fn build(
        client_id: String,
        client_secret: String,
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
            audience: "buttrbase".to_string(),
        });

        Self {
            environment,
            client_id,
            client_secret,
            base_url,
            http,
            verifier,
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

    // ── Internal request helpers ──────────────────────────────────────────

    /// Build a request using HTTP Basic auth (client_id:client_secret).
    /// Used for app-level operations that don't require a user token.
    fn app_request(&self, method: Method, path: &str) -> RequestBuilder {
        self.http
            .request(method, format!("{}{}", self.base_url, path))
            .basic_auth(&self.client_id, Some(&self.client_secret))
    }

    /// Build a request using the given user bearer token.
    fn user_request(&self, method: Method, path: &str, bearer: &str) -> RequestBuilder {
        self.http
            .request(method, format!("{}{}", self.base_url, path))
            .bearer_auth(bearer)
    }

    async fn send<T: DeserializeOwned>(&self, req: RequestBuilder) -> Result<T, Error> {
        let resp = req.send().await?;
        parse_response(resp).await
    }

    async fn send_empty(&self, req: RequestBuilder) -> Result<(), Error> {
        let resp = req.send().await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let body = resp.text().await.unwrap_or_default();
        Err(parse_error_body(status, &body))
    }

    // ── Token verification (local — no HTTP call) ─────────────────────────

    /// Verify a bare ButtrBase JWT string. Uses JWKS with a 5-minute
    /// cache and automatic key-rotation detection (one forced refetch on
    /// `kid` miss). No round-trip on the hot path.
    pub async fn verify_token(&self, token: &str) -> Result<Claims, Error> {
        Ok(self.verifier.verify(token).await?)
    }

    /// Extract and verify a `Bearer <token>` from HTTP request headers.
    pub async fn verify_bearer(&self, headers: &HeaderMap) -> Result<AuthContext, Error> {
        Ok(self.verifier.verify_bearer(headers).await?)
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

    /// Verify the OTP the user received. Returns a `TokenPair` whose
    /// `token` field is the `signup_token` for `finalize_registration`.
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

    /// Legacy `send_otp` — uses slug-based app identifiers which the
    /// backend no longer accepts. Migrate to `send_otp(email, app_uuid)`.
    #[deprecated(
        since = "0.3.0",
        note = "slug-based identifiers are no longer accepted; use send_otp(email, app_uuid)"
    )]
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

    /// Legacy `verify_otp` — uses slug-based app identifiers which the
    /// backend no longer accepts. Migrate to `verify_otp(email, otp, app_uuid)`.
    #[deprecated(
        since = "0.3.0",
        note = "slug-based identifiers are no longer accepted; use verify_otp(email, otp, app_uuid)"
    )]
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
    ) -> Result<TokenPair, Error> {
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
    pub async fn register(&self, req: &RegisterRequest<'_>) -> Result<TokenPair, Error> {
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
                &format!("/api/v1/organizations/{}/invitations", org_uuid),
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
                    format!("{}/api/v1/invitations/{}/preview", self.base_url, token),
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
                &format!("/api/v1/invitations/{}/accept", token),
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
            &format!("/api/v1/organizations/{}/invitations", org_uuid),
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
                "/api/v1/organizations/{}/invitations/{}",
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

    /// Send a magic-link email. The user clicks the link; your callback
    /// receives a short-lived code which you exchange with `verify_magic_link`.
    pub async fn send_magic_link(
        &self,
        email: &str,
        org_name: &str,
        application: &str,
    ) -> Result<(), Error> {
        let body = serde_json::json!({
            "email":       email,
            "org_name":    org_name,
            "application": application,
        });
        self.send_empty(
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

    // ── OAuth2 client-credentials token exchange ──────────────────────────

    /// Exchange client credentials for a short-lived Bearer token.
    ///
    /// This calls `POST /api/v1/auth/token` with the OAuth2 client-credentials
    /// grant and returns the raw token response. The returned `access_token`
    /// is a JWT Bearer that can be used in the `Authorization` header.
    ///
    /// Use this when you need to authenticate against a self-hosted Buttrbase
    /// instance where the token endpoint is the primary auth method.
    pub async fn get_app_token(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<AppTokenResponse, Error> {
        let body = serde_json::json!({
            "grant_type":    "client_credentials",
            "client_id":     client_id,
            "client_secret": client_secret,
        });
        self.send(
            self.http
                .request(
                    Method::POST,
                    format!("{}/api/v1/auth/token", self.base_url),
                )
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
        let body = serde_json::json!({ "feature_key": feature_key });
        let resp: EntitlementCheckResponse = self
            .send(
                self.user_request(Method::POST, "/api/entitlements/check", bearer)
                    .json(&body),
            )
            .await?;
        Ok(resp.data)
    }

    /// Check multiple feature keys in one call. Returns a map of
    /// `feature_key → EntitlementResult`.
    pub async fn check_entitlements(
        &self,
        bearer: &str,
        feature_keys: &[&str],
    ) -> Result<std::collections::HashMap<String, EntitlementResult>, Error> {
        let body = serde_json::json!({ "feature_keys": feature_keys });
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

    // ── Session revocation (admin / app auth) ────────────────────────────

    /// Revoke a specific bearer or refresh token immediately.
    pub async fn revoke_session_token(&self, token: &str) -> Result<(), Error> {
        self.send_empty(
            self.app_request(Method::POST, "/api/admin/sessions/revoke")
                .json(&RevokeSessionRequest { token: token.to_owned() }),
        )
        .await
    }

    /// List all tokens that have been explicitly revoked.
    pub async fn list_revoked_tokens(&self) -> Result<Vec<RevokedTokenEntry>, Error> {
        self.send(self.app_request(Method::GET, "/api/admin/sessions/revoked"))
            .await
    }

    // ── KMS status (admin / app auth) ─────────────────────────────────────

    /// Return the current KMS health, provider, and key-count.
    pub async fn kms_status(&self) -> Result<KmsStatusResponse, Error> {
        self.send(self.app_request(Method::GET, "/api/admin/kms/status"))
            .await
    }

    // ── Payment methods (user auth) ───────────────────────────────────────

    /// List all saved payment methods for the authenticated user.
    pub async fn list_payment_methods(
        &self,
        bearer: &str,
    ) -> Result<Vec<PaymentMethod>, Error> {
        self.send(self.user_request(
            Method::GET,
            "/api/v1/customers/me/payment-methods",
            bearer,
        ))
        .await
    }

    /// Attach a new payment method to the authenticated user.
    pub async fn create_payment_method(
        &self,
        req: &CreatePaymentMethodRequest,
        bearer: &str,
    ) -> Result<PaymentMethod, Error> {
        self.send(
            self.user_request(
                Method::POST,
                "/api/v1/customers/me/payment-methods",
                bearer,
            )
            .json(req),
        )
        .await
    }

    /// Promote an existing payment method to the user's default.
    pub async fn set_default_payment_method(
        &self,
        payment_method_id: &str,
        bearer: &str,
    ) -> Result<(), Error> {
        self.send_empty(self.user_request(
            Method::POST,
            &format!(
                "/api/v1/customers/me/payment-methods/{}/default",
                payment_method_id
            ),
            bearer,
        ))
        .await
    }

    /// Detach and delete a payment method from the authenticated user.
    pub async fn delete_payment_method(
        &self,
        payment_method_id: &str,
        bearer: &str,
    ) -> Result<(), Error> {
        self.send_empty(self.user_request(
            Method::DELETE,
            &format!(
                "/api/v1/customers/me/payment-methods/{}",
                payment_method_id
            ),
            bearer,
        ))
        .await
    }

    // ── Organization members (app auth) ───────────────────────────────────

    /// List all members of an organization.
    pub async fn list_org_members(
        &self,
        org_uuid: &Uuid,
    ) -> Result<Vec<OrgMember>, Error> {
        self.send(self.app_request(
            Method::GET,
            &format!("/api/v2/organizations/{}/members", org_uuid),
        ))
        .await
    }

    // ── App-level OAuth configs (app auth) ────────────────────────────────

    /// List all OAuth provider configurations registered for an app.
    pub async fn list_oauth_configs(
        &self,
        app_uuid: &Uuid,
    ) -> Result<Vec<OAuthConfigSummary>, Error> {
        self.send(self.app_request(
            Method::GET,
            &format!("/api/v1/apps/{}/oauth-configs", app_uuid),
        ))
        .await
    }

    // ── SSO / SAML certificate rollover (app auth) ────────────────────────

    /// Trigger a SAML signing-certificate rollover for the given SSO
    /// connection. The backend generates a new certificate and returns the
    /// updated connection metadata (including the new SP certificate for
    /// upload to the IdP).
    pub async fn rollover_saml_certificates(
        &self,
        org_uuid: &Uuid,
        connection_uuid: &Uuid,
    ) -> Result<serde_json::Value, Error> {
        self.send(self.app_request(
            Method::PUT,
            &format!(
                "/api/organizations/{}/sso-connections/{}/saml-certificates",
                org_uuid, connection_uuid
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
}

// ── Response parsing helpers ──────────────────────────────────────────────

async fn parse_response<T: DeserializeOwned>(resp: Response) -> Result<T, Error> {
    let status = resp.status();
    if status.is_success() {
        let bytes = resp.bytes().await?;
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
        let body = resp.text().await.unwrap_or_default();
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
                "token": "access_jwt",
                "refresh_token": "refresh_jwt",
                "user_uuid": "00000000-0000-0000-0000-000000000001"
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
        let pair = client.finalize_registration(&req).await.unwrap();
        assert_eq!(pair.token, "access_jwt");
    }

    #[tokio::test]
    async fn test_finalize_registration_accept_invite() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/v1/auth/finalize-registration");
            then.status(200).json_body(json!({
                "token": "access_jwt",
                "refresh_token": null,
                "user_uuid": null
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
        let pair = client.finalize_registration(&req).await.unwrap();
        assert_eq!(pair.token, "access_jwt");
    }

    // ── register (deprecated) ─────────────────────────────────────────────

    #[tokio::test]
    #[allow(deprecated)]
    async fn test_register_legacy() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/v1/auth/register");
            then.status(200).json_body(json!({
                "token": "access_jwt",
                "refresh_token": "refresh_jwt",
                "user_uuid": "00000000-0000-0000-0000-000000000001"
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
        let pair = client.register(&req).await.unwrap();
        assert_eq!(pair.token, "access_jwt");
    }

    // ── invitations ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_create_invitation() {
        let server = MockServer::start();
        let org_uuid = uuid::Uuid::nil();
        server.mock(|when, then| {
            when.method(POST)
                .path(format!("/api/v1/organizations/{}/invitations", org_uuid));
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
            when.method(GET).path("/api/v1/invitations/Bd9abc/preview");
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
            when.method(POST).path("/api/v1/invitations/Bd9abc/accept");
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
                .path(format!("/api/v1/organizations/{}/invitations", org_uuid));
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
                .path(format!("/api/v1/organizations/{}/invitations/42", org_uuid));
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
            then.status(200).body("{}");
        });
        let client = make_client(&server);
        client.send_magic_link("u@e.com", "myorg", "myapp").await.unwrap();
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

    // ── get_app_token ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_app_token_success() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/v1/auth/token");
            then.status(200).json_body(json!({
                "access_token": "eyJhbGciOiJSUzI1NiJ9.test",
                "token_type":   "Bearer",
                "expires_in":   3600
            }));
        });
        let client = make_client(&server);
        let resp = client
            .get_app_token("bb_test_cid_test", "bb_test_sk_test")
            .await
            .unwrap();
        assert_eq!(resp.access_token, "eyJhbGciOiJSUzI1NiJ9.test");
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, 3600);
    }

    #[tokio::test]
    async fn test_get_app_token_no_basic_auth() {
        // The request must NOT carry an Authorization header — credentials go
        // in the JSON body only.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST)
                .path("/api/v1/auth/token")
                .header_exists("authorization")
                .matches(|_req| false); // never match — we assert the happy path below
            then.status(401).body("should not be reached");
        });
        server.mock(|when, then| {
            when.method(POST).path("/api/v1/auth/token");
            then.status(200).json_body(json!({
                "access_token": "tok",
                "token_type":   "Bearer",
                "expires_in":   1800
            }));
        });
        let client = make_client(&server);
        let resp = client
            .get_app_token("any_cid", "any_sk")
            .await
            .unwrap();
        assert_eq!(resp.access_token, "tok");
    }

    #[tokio::test]
    async fn test_get_app_token_error() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/v1/auth/token");
            then.status(401)
                .json_body(json!({"error": {"message": "Invalid credentials", "code": "INVALID_CREDENTIALS"}}));
        });
        let client = make_client(&server);
        let result = client.get_app_token("bad_cid", "bad_sk").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Api { status, message, code } => {
                assert_eq!(status, 401);
                assert_eq!(message, "Invalid credentials");
                assert_eq!(code, Some("INVALID_CREDENTIALS".to_string()));
            }
            e => panic!("unexpected error variant: {:?}", e),
        }
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
