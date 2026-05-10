//! [`Verifier`] is the public type. Construct one at startup, share it
//! via Arc/Clone to every handler, call `verify_bearer` from each
//! authenticated endpoint.

use http::HeaderMap;
use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde::Deserialize;
use uuid::Uuid;

use super::error::VerifyError;
use super::jwks_cache::JwksCache;

/// JWKS URL + issuer + audience. Public discovery URLs — nothing
/// secret. Set at boot from env.
#[derive(Debug, Clone)]
pub struct VerifierConfig {
    pub jwks_url: String,
    pub issuer: String,
    pub audience: String,
}

/// What's inside a buttrbase-issued JWT. The custom `org` claim is set
/// by `JwtIssuer::issue` on the buttrbase side.
#[derive(Clone, Debug, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub org: Uuid,
    pub exp: usize,
    pub iat: usize,
    #[serde(default)]
    pub scope: Vec<String>,
}

/// What handlers usually want. Strips the JWT-y bits and exposes just
/// the principal + grants.
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub scopes: Vec<String>,
}

impl From<Claims> for AuthContext {
    fn from(c: Claims) -> Self {
        Self {
            user_id: c.sub,
            org_id: c.org,
            scopes: c.scope,
        }
    }
}

/// Owns the JWKS cache. Cheap to clone (Arc inside).
#[derive(Clone)]
pub struct Verifier {
    config: VerifierConfig,
    jwks: JwksCache,
}

impl Verifier {
    pub fn new(config: VerifierConfig) -> Self {
        Self {
            config,
            jwks: JwksCache::new(),
        }
    }

    /// Verify a bare token string. Returns full claims.
    pub async fn verify(&self, token: &str) -> Result<Claims, VerifyError> {
        let header = decode_header(token)
            .map_err(|e| VerifyError::BadHeader(e.to_string()))?;
        let kid = header.kid.ok_or(VerifyError::MissingKid)?;

        // First try with the cached set (fetches if empty / stale).
        self.jwks.maybe_refresh(&self.config.jwks_url, false).await?;
        let key = match self.jwks.key_for(&kid).await {
            Some(k) => k,
            None => {
                // kid miss → one rate-limited force-refresh, then retry.
                self.jwks
                    .maybe_refresh(&self.config.jwks_url, true)
                    .await?;
                self.jwks
                    .key_for(&kid)
                    .await
                    .ok_or_else(|| VerifyError::KidNotFound(kid.clone()))?
            }
        };

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.config.audience]);
        validation.set_issuer(&[&self.config.issuer]);

        let data = decode::<Claims>(token, &key, &validation)
            .map_err(|e| VerifyError::InvalidToken(e.to_string()))?;
        Ok(data.claims)
    }

    /// Pull a `Bearer <token>` out of the headers, verify it, return
    /// the principal + scopes.
    pub async fn verify_bearer(
        &self,
        headers: &HeaderMap,
    ) -> Result<AuthContext, VerifyError> {
        let raw = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(VerifyError::MissingBearer)?;
        let claims = self.verify(raw).await?;
        Ok(claims.into())
    }

    /// Read-only access to the configured audience — useful for diagnostics
    /// endpoints.
    pub fn audience(&self) -> &str {
        &self.config.audience
    }

    /// Read-only access to the configured issuer.
    pub fn issuer(&self) -> &str {
        &self.config.issuer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_to_authcontext_strips_jwt_fields() {
        let c = Claims {
            sub: Uuid::nil(),
            org: Uuid::nil(),
            exp: 0,
            iat: 0,
            scope: vec!["read:pages".into()],
        };
        let auth: AuthContext = c.into();
        assert_eq!(auth.scopes, vec!["read:pages".to_string()]);
    }
}
