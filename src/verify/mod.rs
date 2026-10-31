//! Verify buttrbase-issued JWTs.
//!
//! Public surface:
//!   - [`Verifier`]      — owns a JWKS cache + config, used in AppState
//!   - [`VerifierConfig`] — JWKS URL + issuer + optional audience
//!   - [`Claims`]        — what's inside the token
//!   - [`AuthContext`]   — what the handler typically wants
//!   - [`VerifyError`]   — typed failure modes; map to your AppError

mod error;
mod jwks_cache;
mod verifier;

pub use error::VerifyError;
pub use verifier::{
    assert_app_uuid, uuid_to_fp_element, verify_pts_claim_isolation, AuthContext,
    ClaimPollBatchSoa, Claims, ClaimsData, FpClaimPolynomial, PtsClaimJudgment, Verifier,
    VerifierConfig, FP_PRIME_P,
};
