use thiserror::Error;

/// Typed verification failures. Consumers usually add
/// `impl From<VerifyError> for AppError` to integrate with their own
/// error type.
///
/// The variants are split so consumers can map "user gave us a bad
/// token" (4xx) vs "we couldn't reach buttrbase to verify" (5xx)
/// distinctly without parsing strings.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// We couldn't fetch the JWKS document from buttrbase. Typically
    /// network / DNS / TLS / 5xx — map to 500/502 in callers.
    #[error("jwks fetch failed: {0}")]
    JwksFetch(String),

    /// We fetched something but it didn't parse as a JWKS document.
    /// This points at a buttrbase-side regression, not a client error.
    #[error("jwks parse failed: {0}")]
    JwksParse(String),

    /// Token's JWS header was malformed.
    #[error("token header invalid: {0}")]
    BadHeader(String),

    /// Token's JWS header had no `kid` claim. We refuse to guess.
    #[error("token missing kid")]
    MissingKid,

    /// Token's `kid` is not in the cached JWKS even after a force-refetch.
    /// Either the token was minted with a key buttrbase no longer
    /// publishes (revoked) or there's a clock/rollover bug — caller
    /// usually returns 401.
    #[error("token kid not found in jwks: {0}")]
    KidNotFound(String),

    /// Signature failed, audience didn't match, expired, etc. The
    /// inner string is the underlying jsonwebtoken error.
    #[error("token invalid: {0}")]
    InvalidToken(String),

    /// `Authorization` header missing or not `Bearer ...`.
    #[error("missing Bearer authorization")]
    MissingBearer,
}
