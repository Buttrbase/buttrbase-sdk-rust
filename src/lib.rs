//! Official Rust SDK for **ButtrBase** — Identity, Billing & Analytics
//! infrastructure for SaaS.
//!
//! # Two surfaces
//!
//! - [`ButtrBaseClient`] — make API calls from your Rust backend.
//!   Initialise with your app credentials; the environment (`live` vs
//!   `sandbox`) is inferred automatically from the `client_id` prefix.
//!
//! - [`verify`] — verify ButtrBase-issued JWTs locally (JWKS, RS256, 5-minute
//!   cache, automatic key-rotation detection). Use this if you only need token
//!   verification without the full client.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use buttrbase_sdk::{ButtrBaseClient, models::UsageEvent};
//!
//! let bb = ButtrBaseClient::new("bb_live_cid_...", "bb_live_sk_...");
//!
//! // Verify a user token locally (no network call on the hot path)
//! let claims = bb.verify_token(&user_bearer).await?;
//!
//! // Check an entitlement
//! let result = bb.check_entitlement(&user_bearer, "advanced_analytics").await?;
//! if result.granted { /* allow the feature */ }
//!
//! // Report metered usage (app-level, uses client credentials)
//! bb.report_usage(&UsageEvent {
//!     metric: "api_calls".into(),
//!     quantity: 1.0,
//!     org_uuid: Some(claims.org),
//!     app_uuid: None,
//!     timestamp: None,
//! }).await?;
//! ```

pub mod client;
pub mod error;
pub mod models;
pub mod verify;

mod negotiator;

// Convenience re-exports at the crate root.
pub use client::ButtrBaseClient;
pub use error::Error;
pub use models::{AppTokenResponse, Environment};
pub use verify::{AuthContext, Claims, Verifier, VerifierConfig, VerifyError};
