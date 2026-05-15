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

    /// Send a one-time-password email to `email`. Your app is identified
    /// by `app_id` (integer PK visible in the ButtrBase dashboard) and
    /// `app_name`.
    pub async fn send_otp(
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

    /// Verify the OTP the user received and return a token pair.
    pub async fn verify_otp(
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
