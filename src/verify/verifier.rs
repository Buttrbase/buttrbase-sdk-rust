//! [`Verifier`] is the public type. Construct one at startup, share it
//! via Arc/Clone to every handler, call `verify_bearer` from each
//! authenticated endpoint.

use http::HeaderMap;
use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use serde::Deserialize;
use uuid::Uuid;

use super::error::VerifyError;
use super::jwks_cache::JwksCache;

/// JWKS URL + issuer + optional audience. Public discovery URLs — nothing
/// secret. Set at boot from env.
///
/// `audience` is **optional**. buttrbase access tokens do not carry a stable,
/// per-application `aud` claim — magic-link tokens set `aud` to the org *name*
/// (or omit it), and client-credential tokens omit it entirely. So most
/// consumers should leave this `None` (no `aud` validation) and rely on the
/// `iss` + signature + `org` claim. Set `Some(_)` only if you mint tokens with
/// a known audience and want it enforced.
#[derive(Debug, Clone)]
pub struct VerifierConfig {
    pub jwks_url: String,
    pub issuer: String,
    pub audience: Option<String>,
}

/// Identity enrichment carried under the buttrbase `data` claim envelope.
/// Additive: tokens without `data` deserialize to `None`.
#[derive(Clone, Debug, Deserialize, Default)]
pub struct ClaimsData {
    #[serde(default)]
    pub roles: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub org_uuid: Option<Uuid>,
    #[serde(default)]
    pub user_uuid: Option<Uuid>,
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
    /// The buttrbase **app** this token was minted for, promoted to a
    /// top-level claim by `app_auth.rs` so a JWKS verifier can read it.
    ///
    /// Read this — or better, set [`Verifier::with_expected_app_uuid`] and let
    /// the verifier enforce it. The issuer, the JWKS endpoint and `aud`
    /// (`BUTTRBASE_TOKEN_AUDIENCE`, default `"s7-platform"`) are identical for
    /// every app on the platform, so signature + issuer + audience proves the
    /// token came from *buttrbase*, not that it came from buttrbase *for your
    /// app*. `app_auth.rs` records this happening for real:
    ///
    /// > "An access token minted for one product therefore verifies perfectly
    /// > at another product's API, which is not a hypothetical — an Affordable
    /// > Reasoning token authenticated against the Get Airtight API and got as
    /// > far as business-rule validation."
    ///
    /// `None` for tokens minted before the claim was promoted. Treating `None`
    /// as "any app" is what makes the hole exploitable, so
    /// `with_expected_app_uuid` rejects it.
    #[serde(default)]
    pub app_uuid: Option<Uuid>,
    #[serde(default)]
    pub data: Option<ClaimsData>,
}

/// What handlers usually want. Strips the JWT-y bits and exposes just
/// the principal + grants.
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub scopes: Vec<String>,
    pub roles: Vec<String>,
    pub email: Option<String>,
}

impl From<Claims> for AuthContext {
    fn from(c: Claims) -> Self {
        // buttrbase stores `data.roles` as a single comma/space-delimited
        // string (e.g. "owner" or "org_admin,leadership"); split to a Vec.
        let roles = c
            .data
            .as_ref()
            .and_then(|d| d.roles.as_deref())
            .map(|s| {
                s.split([',', ' '])
                    .filter(|p| !p.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let email = c.data.as_ref().and_then(|d| d.email.clone());
        Self {
            user_id: c.sub,
            org_id: c.org,
            scopes: c.scope,
            roles,
            email,
        }
    }
}

/// Owns the JWKS cache. Cheap to clone (Arc inside).
#[derive(Clone)]
pub struct Verifier {
    config: VerifierConfig,
    jwks: JwksCache,
    /// Opt-in. `None` preserves the historical behaviour of not checking which
    /// app a token was minted for; see [`Verifier::with_expected_app_uuid`].
    expected_app_uuid: Option<Uuid>,
}

impl Verifier {
    pub fn new(config: VerifierConfig) -> Self {
        Self {
            config,
            jwks: JwksCache::new(),
            expected_app_uuid: None,
        }
    }

    /// Require that tokens were minted for this buttrbase app.
    ///
    /// **You almost certainly want this.** Without it, a valid token minted for
    /// *any* app on the platform authenticates against your API, because the
    /// issuer, JWKS and `aud` are platform-wide rather than per-app. See the
    /// note on [`Claims::app_uuid`].
    ///
    /// A builder method rather than a `VerifierConfig` field so that adding it
    /// does not break existing `VerifierConfig { .. }` literals.
    ///
    /// Enforcement rejects both a mismatched `app_uuid` and a **missing** one —
    /// reading absence as "any app" is exactly the hole this closes. If you
    /// serve tokens minted before the claim was promoted, migrate them first.
    pub fn with_expected_app_uuid(mut self, app_uuid: Uuid) -> Self {
        self.expected_app_uuid = Some(app_uuid);
        self
    }

    /// The app uuid this verifier is pinned to, for diagnostics endpoints.
    pub fn expected_app_uuid(&self) -> Option<Uuid> {
        self.expected_app_uuid
    }

    /// Verify a bare token string. Returns full claims.
    pub async fn verify(&self, token: &str) -> Result<Claims, VerifyError> {
        let header = decode_header(token).map_err(|e| VerifyError::BadHeader(e.to_string()))?;
        let kid = header.kid.ok_or(VerifyError::MissingKid)?;

        // First try with the cached set (fetches if empty / stale).
        self.jwks
            .maybe_refresh(&self.config.jwks_url, false)
            .await?;
        let key = match self.jwks.key_for(&kid).await {
            Some(k) => k,
            None => {
                // kid miss → one rate-limited force-refresh, then retry.
                self.jwks.maybe_refresh(&self.config.jwks_url, true).await?;
                self.jwks
                    .key_for(&kid)
                    .await
                    .ok_or_else(|| VerifyError::KidNotFound(kid.clone()))?
            }
        };

        let mut validation = Validation::new(Algorithm::RS256);
        match &self.config.audience {
            Some(aud) => validation.set_audience(&[aud]),
            // No fixed audience to pin → don't reject on `aud`. Identity is
            // established by the issuer + signature + the `org`/`sub` claims.
            None => validation.validate_aud = false,
        }
        validation.set_issuer(&[&self.config.issuer]);
        // Hardening: reject not-before and allow small clock skew (60s).
        validation.validate_nbf = true;
        validation.leeway = 60; // seconds

        let data = decode::<Claims>(token, &key, &validation)
            .map_err(|e| VerifyError::InvalidToken(e.to_string()))?;

        // Signature, issuer, expiry and nbf are all validated above. This is the
        // separate question they cannot answer: was the token minted for *this*
        // app? The issuer and JWKS are platform-wide, so a cryptographically
        // valid token for another product passes every check above.
        assert_app_uuid(&data.claims, self.expected_app_uuid)?;

        Ok(data.claims)
    }

    /// Pull a `Bearer <token>` out of the headers, verify it, return
    /// the principal + scopes.
    pub async fn verify_bearer(&self, headers: &HeaderMap) -> Result<AuthContext, VerifyError> {
        let raw = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(VerifyError::MissingBearer)?;
        let claims = self.verify(raw).await?;
        Ok(claims.into())
    }

    /// Read-only access to the configured audience, if any — useful for
    /// diagnostics endpoints. `None` means `aud` is not validated.
    pub fn audience(&self) -> Option<&str> {
        self.config.audience.as_deref()
    }

    /// Read-only access to the configured issuer.
    pub fn issuer(&self) -> &str {
        &self.config.issuer
    }
}

/// Enforce the app binding. Split out of [`Verifier::verify`] so it can be
/// unit-tested without a JWKS endpoint and a signed token.
///
/// Reports through `VerifyError::InvalidToken` rather than new variants on
/// purpose: consumers match `VerifyError` exhaustively (metaphone's
/// `From<VerifyError> for AppError` has no wildcard arm), so adding variants
/// would be a breaking change for every dependent crate. The message carries
/// the detail for logs, and 401 is the correct response for both cases anyway.
fn assert_app_uuid(claims: &Claims, expected: Option<Uuid>) -> Result<(), VerifyError> {
    let Some(expected) = expected else {
        // Not pinned: preserve the historical behaviour.
        return Ok(());
    };
    match claims.app_uuid {
        None => Err(VerifyError::InvalidToken(
            "token carries no app_uuid claim; refusing to treat its absence as any-app".to_string(),
        )),
        Some(found) if found != expected => Err(VerifyError::InvalidToken(format!(
            "token was minted for app {found}, expected {expected}"
        ))),
        Some(_) => Ok(()),
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
            data: None,
            app_uuid: None,
        };
        let auth: AuthContext = c.into();
        assert_eq!(auth.scopes, vec!["read:pages".to_string()]);
    }

    #[test]
    fn test_claims_scope_default_empty() {
        let json = r#"{"sub":"00000000-0000-0000-0000-000000000000","org":"00000000-0000-0000-0000-000000000001","exp":9999999999,"iat":0}"#;
        let claims: Claims = serde_json::from_str(json).unwrap();
        assert!(claims.scope.is_empty());
    }

    #[test]
    fn test_claims_scope_populated() {
        let json = r#"{"sub":"00000000-0000-0000-0000-000000000000","org":"00000000-0000-0000-0000-000000000001","exp":9999999999,"iat":0,"scope":["read:users","write:users"]}"#;
        let claims: Claims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.scope, vec!["read:users", "write:users"]);
    }

    #[test]
    fn test_authcontext_from_claims_copies_fields() {
        let uid = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        let oid = Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();
        let c = Claims {
            sub: uid,
            org: oid,
            exp: 1000,
            iat: 500,
            scope: vec!["admin".to_string()],
            data: None,
            app_uuid: None,
        };
        let auth: AuthContext = c.into();
        assert_eq!(auth.user_id, uid);
        assert_eq!(auth.org_id, oid);
        assert_eq!(auth.scopes, vec!["admin"]);
    }

    #[test]
    fn test_verifier_audience_accessor() {
        let cfg = VerifierConfig {
            jwks_url: "https://example.com/.well-known/jwks.json".to_string(),
            issuer: "https://example.com".to_string(),
            audience: Some("my-app".to_string()),
        };
        let v = Verifier::new(cfg);
        assert_eq!(v.audience(), Some("my-app"));
    }

    #[test]
    fn test_verifier_audience_optional_none() {
        let cfg = VerifierConfig {
            jwks_url: "https://example.com/.well-known/jwks.json".to_string(),
            issuer: "https://example.com".to_string(),
            audience: None,
        };
        let v = Verifier::new(cfg);
        assert_eq!(v.audience(), None);
    }

    #[test]
    fn test_verifier_issuer_accessor() {
        let cfg = VerifierConfig {
            jwks_url: "https://example.com/.well-known/jwks.json".to_string(),
            issuer: "https://issuer.example.com".to_string(),
            audience: Some("aud".to_string()),
        };
        let v = Verifier::new(cfg);
        assert_eq!(v.issuer(), "https://issuer.example.com");
    }

    #[tokio::test]
    async fn test_verify_bearer_missing_header() {
        let cfg = VerifierConfig {
            jwks_url: "https://example.com/.well-known/jwks.json".to_string(),
            issuer: "https://example.com".to_string(),
            audience: Some("aud".to_string()),
        };
        let v = Verifier::new(cfg);
        let headers = http::HeaderMap::new();
        let result = v.verify_bearer(&headers).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            VerifyError::MissingBearer => {}
            e => panic!("expected MissingBearer, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_verify_bearer_not_bearer_scheme() {
        let cfg = VerifierConfig {
            jwks_url: "https://example.com/.well-known/jwks.json".to_string(),
            issuer: "https://example.com".to_string(),
            audience: Some("aud".to_string()),
        };
        let v = Verifier::new(cfg);
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", "Basic dXNlcjpwYXNz".parse().unwrap());
        let result = v.verify_bearer(&headers).await;
        assert!(matches!(result.unwrap_err(), VerifyError::MissingBearer));
    }

    #[tokio::test]
    async fn test_verify_bad_token_format() {
        let cfg = VerifierConfig {
            jwks_url: "https://example.com/.well-known/jwks.json".to_string(),
            issuer: "https://example.com".to_string(),
            audience: Some("aud".to_string()),
        };
        let v = Verifier::new(cfg);
        // Not a valid JWT
        let result = v.verify("not.a.jwt.at.all").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            VerifyError::BadHeader(_) => {}
            e => panic!("expected BadHeader, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_verify_token_missing_kid() {
        // A JWT with no kid in the header.
        // Header: {"alg":"RS256"}, Payload: {...}, Sig: dummy
        // eyJhbGciOiJSUzI1NiJ9 = base64url({"alg":"RS256"})
        let token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.fakesig";
        let cfg = VerifierConfig {
            jwks_url: "https://example.com/.well-known/jwks.json".to_string(),
            issuer: "https://example.com".to_string(),
            audience: Some("aud".to_string()),
        };
        let v = Verifier::new(cfg);
        let result = v.verify(token).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            VerifyError::MissingKid => {}
            e => panic!("expected MissingKid, got {:?}", e),
        }
    }

    #[test]
    fn test_verifier_clone() {
        let cfg = VerifierConfig {
            jwks_url: "https://example.com/.well-known/jwks.json".to_string(),
            issuer: "https://example.com".to_string(),
            audience: Some("aud".to_string()),
        };
        let v = Verifier::new(cfg);
        let v2 = v.clone();
        assert_eq!(v2.audience(), Some("aud"));
    }

    #[test]
    fn test_verifier_config_debug() {
        let cfg = VerifierConfig {
            jwks_url: "url".to_string(),
            issuer: "iss".to_string(),
            audience: Some("aud".to_string()),
        };
        let s = format!("{:?}", cfg);
        assert!(s.contains("aud"));
    }

    #[test]
    fn claims_expose_roles_and_email_from_data_envelope() {
        let json = include_str!("../../tests/fixtures/access_token_claims.json");
        let claims: Claims = serde_json::from_str(json).unwrap();
        let data = claims.data.as_ref().expect("data envelope present");
        assert_eq!(data.roles.as_deref(), Some("owner"));
        assert_eq!(data.email.as_deref(), Some("test@example.com"));
        let auth: AuthContext = claims.into();
        assert!(auth.roles.contains(&"owner".to_string()));
        assert_eq!(auth.email.as_deref(), Some("test@example.com"));
    }
    // ── app_uuid binding ────────────────────────────────────────────────────
    //
    // The issuer, JWKS endpoint and `aud` are platform-wide, so signature +
    // issuer + expiry prove a token came from buttrbase, not that it came from
    // buttrbase *for this app*. These tests cover the check that closes that
    // gap. `app_auth.rs` in buttrbase-backend-rust records it happening for
    // real: an Affordable Reasoning token authenticated against the Get
    // Airtight API.

    const OUR_APP: &str = "11111111-1111-1111-1111-111111111111";
    const OTHER_APP: &str = "22222222-2222-2222-2222-222222222222";

    fn claims_with_app(app_uuid: Option<Uuid>) -> Claims {
        Claims {
            sub: Uuid::nil(),
            org: Uuid::nil(),
            exp: 0,
            iat: 0,
            scope: Vec::new(),
            app_uuid,
            data: None,
        }
    }

    #[test]
    fn app_uuid_is_not_checked_when_unconfigured() {
        // Backwards compatibility: every existing consumer builds
        // Verifier::new(config) with no expectation and must keep verifying.
        let ours = Uuid::parse_str(OUR_APP).unwrap();
        let other = Uuid::parse_str(OTHER_APP).unwrap();
        assert!(assert_app_uuid(&claims_with_app(None), None).is_ok());
        assert!(assert_app_uuid(&claims_with_app(Some(other)), None).is_ok());
        assert!(assert_app_uuid(&claims_with_app(Some(ours)), None).is_ok());
    }

    #[test]
    fn matching_app_uuid_is_accepted() {
        let ours = Uuid::parse_str(OUR_APP).unwrap();
        assert!(assert_app_uuid(&claims_with_app(Some(ours)), Some(ours)).is_ok());
    }

    #[test]
    fn token_minted_for_another_app_is_rejected() {
        let ours = Uuid::parse_str(OUR_APP).unwrap();
        let other = Uuid::parse_str(OTHER_APP).unwrap();
        let err = assert_app_uuid(&claims_with_app(Some(other)), Some(ours))
            .expect_err("cross-app token must be rejected");
        let msg = err.to_string();
        // Both uuids appear, so an operator can tell which app leaked.
        assert!(msg.contains(OTHER_APP), "{msg}");
        assert!(msg.contains(OUR_APP), "{msg}");
        assert!(matches!(err, VerifyError::InvalidToken(_)));
    }

    #[test]
    fn missing_app_uuid_is_rejected_when_pinned() {
        // The important one: absence must not be read as "any app", or a token
        // minted before the claim was promoted becomes a universal pass.
        let ours = Uuid::parse_str(OUR_APP).unwrap();
        let err = assert_app_uuid(&claims_with_app(None), Some(ours))
            .expect_err("missing app_uuid must be rejected");
        assert!(err.to_string().contains("no app_uuid"), "{err}");
    }

    #[test]
    fn app_uuid_deserializes_from_the_top_level_claim() {
        // buttrbase stamps it with json!(app_uuid), i.e. a bare UUID string at
        // the top level -- not nested under `data`.
        let json = format!(
            r#"{{"sub":"{OUR_APP}","org":"{OUR_APP}","exp":0,"iat":0,"app_uuid":"{OTHER_APP}"}}"#
        );
        let claims: Claims = serde_json::from_str(&json).unwrap();
        assert_eq!(claims.app_uuid, Some(Uuid::parse_str(OTHER_APP).unwrap()));
    }

    #[test]
    fn app_uuid_absent_deserializes_to_none() {
        // Tokens minted before the claim was promoted must still parse, so that
        // pinning produces a clear rejection rather than a deserialize error.
        let json = format!(r#"{{"sub":"{OUR_APP}","org":"{OUR_APP}","exp":0,"iat":0}}"#);
        let claims: Claims = serde_json::from_str(&json).unwrap();
        assert_eq!(claims.app_uuid, None);
    }

    #[test]
    fn with_expected_app_uuid_is_recorded() {
        let ours = Uuid::parse_str(OUR_APP).unwrap();
        let config = VerifierConfig {
            jwks_url: "https://example.invalid/jwks".to_string(),
            issuer: "https://example.invalid".to_string(),
            audience: None,
        };
        assert_eq!(Verifier::new(config.clone()).expected_app_uuid(), None);
        assert_eq!(
            Verifier::new(config)
                .with_expected_app_uuid(ours)
                .expected_app_uuid(),
            Some(ours)
        );
    }
}
