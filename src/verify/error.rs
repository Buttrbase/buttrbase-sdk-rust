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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwks_fetch_display() {
        let e = VerifyError::JwksFetch("connection refused".to_string());
        let s = format!("{}", e);
        assert!(s.contains("jwks fetch failed"));
        assert!(s.contains("connection refused"));
    }

    #[test]
    fn test_jwks_parse_display() {
        let e = VerifyError::JwksParse("invalid json".to_string());
        let s = format!("{}", e);
        assert!(s.contains("jwks parse failed"));
        assert!(s.contains("invalid json"));
    }

    #[test]
    fn test_bad_header_display() {
        let e = VerifyError::BadHeader("malformed header".to_string());
        let s = format!("{}", e);
        assert!(s.contains("token header invalid"));
        assert!(s.contains("malformed header"));
    }

    #[test]
    fn test_missing_kid_display() {
        let e = VerifyError::MissingKid;
        let s = format!("{}", e);
        assert!(s.contains("missing kid"));
    }

    #[test]
    fn test_kid_not_found_display() {
        let e = VerifyError::KidNotFound("my-key-id".to_string());
        let s = format!("{}", e);
        assert!(s.contains("kid not found"));
        assert!(s.contains("my-key-id"));
    }

    #[test]
    fn test_invalid_token_display() {
        let e = VerifyError::InvalidToken("expired".to_string());
        let s = format!("{}", e);
        assert!(s.contains("token invalid"));
        assert!(s.contains("expired"));
    }

    #[test]
    fn test_missing_bearer_display() {
        let e = VerifyError::MissingBearer;
        let s = format!("{}", e);
        assert!(s.contains("Bearer"));
    }

    #[test]
    fn test_debug_format() {
        let e = VerifyError::MissingKid;
        let s = format!("{:?}", e);
        assert!(s.contains("MissingKid"));
    }

    #[test]
    fn test_error_is_std_error() {
        // VerifyError implements std::error::Error (via thiserror)
        let e: Box<dyn std::error::Error> = Box::new(VerifyError::MissingBearer);
        let s = format!("{}", e);
        assert!(!s.is_empty());
    }
}
