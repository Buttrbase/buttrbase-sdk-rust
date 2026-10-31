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
        if header.alg != Algorithm::RS256 {
            return Err(VerifyError::InvalidToken("InvalidAlgorithm".to_string()));
        }

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
        verify_pts_claim_isolation(&data.claims, self.expected_app_uuid)?;

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
pub fn assert_app_uuid(claims: &Claims, expected: Option<Uuid>) -> Result<(), VerifyError> {
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

/// Mersenne prime $p = 2^{61} - 1$ for Proof 142 deterministic polynomial factorization over $\mathbb{F}_p$.
pub const FP_PRIME_P: u64 = (1u64 << 61) - 1;

#[inline]
fn fp_add(a: u64, b: u64) -> u64 {
    let sum = (a as u128) + (b as u128);
    let folded = ((sum & (FP_PRIME_P as u128)) + (sum >> 61)) as u64;
    if folded >= FP_PRIME_P {
        folded - FP_PRIME_P
    } else {
        folded
    }
}

#[inline]
fn fp_sub(a: u64, b: u64) -> u64 {
    let b_mod = b % FP_PRIME_P;
    fp_add(a % FP_PRIME_P, FP_PRIME_P - b_mod)
}

#[inline]
fn fp_mul(a: u64, b: u64) -> u64 {
    let prod = (a % FP_PRIME_P) as u128 * (b % FP_PRIME_P) as u128;
    let lo = (prod & (FP_PRIME_P as u128)) as u64;
    let hi = (prod >> 61) as u64;
    fp_add(lo, hi)
}

/// Folds a 128-bit `Uuid` tagged with a domain separator into an element of $\mathbb{F}_p$ ($p = 2^{61} - 1$).
#[inline]
pub fn uuid_to_fp_element(id: Uuid, domain_tag: u64) -> u64 {
    let raw = id.as_u128();
    let lo = (raw & ((1u128 << 61) - 1)) as u64;
    let mid = ((raw >> 61) & ((1u128 << 61) - 1)) as u64;
    let hi = (raw >> 122) as u64;
    let mixed = fp_add(lo, fp_mul(mid, 0x9E37_79B9_7F4A_7C15 % FP_PRIME_P));
    let mixed = fp_add(mixed, fp_mul(hi + 1, domain_tag % FP_PRIME_P));
    fp_add(mixed, domain_tag)
}

/// Monic degree-4 polynomial over $\mathbb{F}_p$ ($p = 2^{61} - 1$) binding `(sub, org, app_uuid, exp)`
/// under OpenAI Math Proof 142 (Uniform Deterministic Polynomial-Time Factorization over Prime Fields $\mathbb{F}_p$).
///
/// Represents $P(x) = \prod_{i=0}^3 (x - r_i) = x^4 + c_3 x^3 + c_2 x^2 + c_1 x + c_0 \pmod p$.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FpClaimPolynomial {
    /// Coefficients `[c_0, c_1, c_2, c_3]` of the monic degree-4 polynomial in $\mathbb{F}_p[x]$.
    pub coeffs: [u64; 4],
    /// Canonical roots `[r_sub, r_org, r_app, r_exp]` in $\mathbb{F}_p$.
    pub roots: [u64; 4],
}

const _: () = assert!(core::mem::size_of::<FpClaimPolynomial>() == 64);
const _: () = assert!(core::mem::align_of::<FpClaimPolynomial>() == 64);

/// 64-byte cache-aligned Structure-of-Arrays (SoA) batch window for 4 concurrent
/// session/poll claim commitments (`[u64; 4]` expiry timestamps + `[u64; 4]` $\mathbb{F}_p$ evaluations).
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimPollBatchSoa {
    /// Expiry timestamps (`exp` in Unix seconds) for up to 4 polled session tokens.
    pub exp_lanes: [u64; 4],
    /// Evaluated $\mathbb{F}_p$ polynomial tags $P(\text{challenge}) \pmod p$ for the 4 lanes.
    pub fp_tag_lanes: [u64; 4],
}

const _: () = assert!(core::mem::size_of::<ClaimPollBatchSoa>() == 64);
const _: () = assert!(core::mem::align_of::<ClaimPollBatchSoa>() == 64);

impl ClaimPollBatchSoa {
    /// Packs up to 4 `(Claims, app_uuid)` pairs into a single 64-byte cache-aligned SoA window
    /// evaluated at `challenge` in $\mathbb{F}_p$. Unused lanes are zero-filled.
    pub fn from_claims_slice(items: &[(&Claims, Uuid)], challenge: u64) -> Self {
        let mut exp_lanes = [0u64; 4];
        let mut fp_tag_lanes = [0u64; 4];
        for (lane, (claims, app_uuid)) in items.iter().take(4).enumerate() {
            exp_lanes[lane] = claims.exp as u64;
            let poly = FpClaimPolynomial::from_claims(claims, *app_uuid);
            fp_tag_lanes[lane] = poly.evaluate(challenge);
        }
        Self {
            exp_lanes,
            fp_tag_lanes,
        }
    }

    /// Returns a 4-bit mask where bit `i` is `1` iff lane `i` is populated and strictly un-expired (`exp > now_unix_secs`).
    #[inline]
    pub const fn active_lane_mask(&self, now_unix_secs: u64) -> u8 {
        let mut mask = 0u8;
        let mut i = 0;
        while i < 4 {
            if self.exp_lanes[i] > now_unix_secs {
                mask |= 1u8 << i;
            }
            i += 1;
        }
        mask
    }
}

impl FpClaimPolynomial {
    /// Deterministically constructs the monic claim-binding polynomial over $\mathbb{F}_p$.
    pub fn from_claims(claims: &Claims, app_uuid: Uuid) -> Self {
        let r0 = uuid_to_fp_element(claims.sub, 0x101);
        let r1 = uuid_to_fp_element(claims.org, 0x202);
        let r2 = uuid_to_fp_element(app_uuid, 0x303);
        let r3 = fp_add((claims.exp as u64) % FP_PRIME_P, 0x404);

        // Elementary symmetric polynomials e1, e2, e3, e4 over F_p
        let e1 = fp_add(fp_add(r0, r1), fp_add(r2, r3));
        let e2 = fp_add(
            fp_add(fp_mul(r0, r1), fp_mul(r0, r2)),
            fp_add(
                fp_add(fp_mul(r0, r3), fp_mul(r1, r2)),
                fp_add(fp_mul(r1, r3), fp_mul(r2, r3)),
            ),
        );
        let e3 = fp_add(
            fp_add(fp_mul(fp_mul(r0, r1), r2), fp_mul(fp_mul(r0, r1), r3)),
            fp_add(fp_mul(fp_mul(r0, r2), r3), fp_mul(fp_mul(r1, r2), r3)),
        );
        let e4 = fp_mul(fp_mul(r0, r1), fp_mul(r2, r3));

        // P(x) = x^4 - e1 x^3 + e2 x^2 - e3 x + e4 (mod p)
        let c3 = fp_sub(0, e1);
        let c2 = e2;
        let c1 = fp_sub(0, e3);
        let c0 = e4;

        Self {
            coeffs: [c0, c1, c2, c3],
            roots: [r0, r1, r2, r3],
        }
    }

    /// Evaluates $P(x) \pmod p$ via Horner's rule.
    pub fn evaluate(&self, x: u64) -> u64 {
        let x = x % FP_PRIME_P;
        let mut acc = 1u64; // leading coefficient of x^4
        acc = fp_add(fp_mul(acc, x), self.coeffs[3]);
        acc = fp_add(fp_mul(acc, x), self.coeffs[2]);
        acc = fp_add(fp_mul(acc, x), self.coeffs[1]);
        fp_add(fp_mul(acc, x), self.coeffs[0])
    }

    /// Deterministically factors $P(x)$ over $\mathbb{F}_p$ by synthetic linear division $(x - r_i)$
    /// without randomness (Proof 142), verifying that `claims` and `expected_app_uuid` split $P(x)$
    /// into exact linear factors with zero remainder.
    pub fn verify_deterministic_factorization(
        &self,
        claims: &Claims,
        expected_app_uuid: Uuid,
    ) -> Result<(), VerifyError> {
        let Some(token_app) = claims.app_uuid else {
            return Err(VerifyError::InvalidToken(
                "token carries no app_uuid claim for F_p factorization".to_string(),
            ));
        };
        if token_app != expected_app_uuid {
            return Err(VerifyError::InvalidToken(format!(
                "F_p polynomial root mismatch: token app {token_app} != expected {expected_app_uuid}"
            )));
        }

        let candidate_roots = [
            uuid_to_fp_element(claims.sub, 0x101),
            uuid_to_fp_element(claims.org, 0x202),
            uuid_to_fp_element(expected_app_uuid, 0x303),
            fp_add((claims.exp as u64) % FP_PRIME_P, 0x404),
        ];

        // Current polynomial coefficients from highest degree to lowest: [1, c3, c2, c1, c0]
        let mut poly = [
            1u64,
            self.coeffs[3],
            self.coeffs[2],
            self.coeffs[1],
            self.coeffs[0],
        ];
        let mut deg = 4usize;

        for &root in &candidate_roots {
            // Synthetic division by (x - root) in F_p[x]
            let mut rem = 0u64;
            for slot in poly.iter_mut().take(deg + 1) {
                let coeff = *slot;
                *slot = rem;
                rem = fp_add(fp_mul(rem, root), coeff);
            }
            if rem != 0 {
                return Err(VerifyError::InvalidToken(
                    "Proof 142 F_p polynomial factorization failed: non-zero linear remainder"
                        .to_string(),
                ));
            }
            // Shift quotient down
            for i in 0..deg {
                poly[i] = poly[i + 1];
            }
            deg -= 1;
        }

        if deg != 0 || poly[0] != 1 {
            return Err(VerifyError::InvalidToken(
                "Proof 142 F_p polynomial factorization failed: non-monic quotient".to_string(),
            ));
        }

        Ok(())
    }
}

/// Strongly-normalized Pure Type System (PTS) claim judgment under OpenAI Math Proof 245
/// (Weak Normalization Implies Strong Normalization in Pure Type Systems).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PtsClaimJudgment {
    pub sub: Uuid,
    pub org: Uuid,
    pub app_uuid: Option<Uuid>,
    pub normalized_scopes: Vec<String>,
    pub normalized_roles: Vec<String>,
    pub beta_reduction_steps: usize,
    pub fp_commitment: Option<FpClaimPolynomial>,
}

/// Enforces OpenAI Math Proof 245 (PTS Strong Normalization & Church–Rosser Envelope Confluence)
/// and Proof 142 (Deterministic $\mathbb{F}_p$ Polynomial Factorization Non-Forgery) on decoded JWT claims.
pub fn verify_pts_claim_isolation(
    claims: &Claims,
    expected_app_uuid: Option<Uuid>,
) -> Result<PtsClaimJudgment, VerifyError> {
    // 1. Enforce cross-app app_uuid type isolation
    assert_app_uuid(claims, expected_app_uuid)?;

    let mut beta_steps = 1usize;

    // 2. Proof 245 Church-Rosser confluence between top-level claims and nested `data` envelope
    if let Some(ref data) = claims.data {
        if let Some(data_user) = data.user_uuid {
            beta_steps += 1;
            if claims.sub != Uuid::nil() && data_user != Uuid::nil() && claims.sub != data_user {
                return Err(VerifyError::InvalidToken(format!(
                    "PTS claim non-confluence: top-level sub {} conflicts with data.user_uuid {}",
                    claims.sub, data_user
                )));
            }
        }
        if let Some(data_org) = data.org_uuid {
            beta_steps += 1;
            if claims.org != Uuid::nil() && data_org != Uuid::nil() && claims.org != data_org {
                return Err(VerifyError::InvalidToken(format!(
                    "PTS claim non-confluence: top-level org {} conflicts with data.org_uuid {}",
                    claims.org, data_org
                )));
            }
        }
    }

    // 3. Strongly normalizing beta-reduction of scopes and roles into canonical normal form
    let mut normalized_scopes: Vec<String> = claims
        .scope
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    beta_steps += normalized_scopes.len();
    normalized_scopes.sort();
    normalized_scopes.dedup();

    let mut normalized_roles: Vec<String> = claims
        .data
        .as_ref()
        .and_then(|d| d.roles.as_deref())
        .map(|s| {
            s.split([',', ' '])
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    beta_steps += normalized_roles.len();
    normalized_roles.sort();
    normalized_roles.dedup();

    // 4. Proof 142 deterministic F_p polynomial factorization commitment when app_uuid is present
    let fp_commitment = if let Some(expected_app) = expected_app_uuid {
        let poly = FpClaimPolynomial::from_claims(claims, expected_app);
        poly.verify_deterministic_factorization(claims, expected_app)?;
        Some(poly)
    } else {
        claims
            .app_uuid
            .map(|app| FpClaimPolynomial::from_claims(claims, app))
    };

    Ok(PtsClaimJudgment {
        sub: claims.sub,
        org: claims.org,
        app_uuid: claims.app_uuid,
        normalized_scopes,
        normalized_roles,
        beta_reduction_steps: beta_steps,
        fp_commitment,
    })
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

    #[test]
    fn proof_245_pts_claim_isolation_and_confluence() {
        let ours = Uuid::parse_str(OUR_APP).unwrap();
        let other = Uuid::parse_str(OTHER_APP).unwrap();
        let sub_id = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        let org_id = Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();

        let valid_claims = Claims {
            sub: sub_id,
            org: org_id,
            exp: 2_000_000_000,
            iat: 1_900_000_000,
            scope: vec![
                "write:users".into(),
                "read:users".into(),
                "read:users".into(),
            ],
            app_uuid: Some(ours),
            data: Some(ClaimsData {
                roles: Some("admin, member, admin".into()),
                email: Some("user@example.com".into()),
                org_uuid: Some(org_id),
                user_uuid: Some(sub_id),
            }),
        };

        let judgment = verify_pts_claim_isolation(&valid_claims, Some(ours))
            .expect("confluent same-app claims must type-check");
        assert_eq!(judgment.app_uuid, Some(ours));
        assert_eq!(judgment.normalized_scopes, vec!["read:users", "write:users"]);
        assert_eq!(judgment.normalized_roles, vec!["admin", "member"]);
        assert!(judgment.beta_reduction_steps >= 4);
        assert!(judgment.fp_commitment.is_some());

        // Cross-app token must be rejected
        assert!(verify_pts_claim_isolation(&valid_claims, Some(other)).is_err());

        // Conflicting nested data.org_uuid vs top-level org must be rejected (non-confluent)
        let mut forged_envelope = valid_claims.clone();
        forged_envelope.data.as_mut().unwrap().org_uuid = Some(other);
        let err = verify_pts_claim_isolation(&forged_envelope, Some(ours))
            .expect_err("non-confluent org_uuid envelope must be rejected");
        assert!(err.to_string().contains("non-confluence"));
    }

    #[test]
    fn proof_142_fp_polynomial_factorization_non_forgery() {
        let ours = Uuid::parse_str(OUR_APP).unwrap();
        let other = Uuid::parse_str(OTHER_APP).unwrap();
        let sub_id = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        let org_id = Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();

        let claims = Claims {
            sub: sub_id,
            org: org_id,
            exp: 1_800_000_000,
            iat: 1_700_000_000,
            scope: vec!["read:all".into()],
            app_uuid: Some(ours),
            data: None,
        };

        let poly = FpClaimPolynomial::from_claims(&claims, ours);
        // Every root r_i must satisfy P(r_i) == 0 (mod p)
        for &r in &poly.roots {
            assert_eq!(poly.evaluate(r), 0);
        }
        // Deterministic factorization succeeds for the authentic claims + app_uuid
        assert!(poly.verify_deterministic_factorization(&claims, ours).is_ok());

        // Attempting to factor with another app_uuid fails deterministically
        assert!(poly
            .verify_deterministic_factorization(&claims, other)
            .is_err());

        // Tampering with claims.sub while keeping polynomial commitment fails synthetic division
        let mut tampered_claims = claims.clone();
        tampered_claims.sub = other;
        assert!(poly
            .verify_deterministic_factorization(&tampered_claims, ours)
            .is_err());
    }

    #[tokio::test]
    async fn proof_142_rejects_algorithm_confusion_header() {
        // Header: {"alg":"HS256","kid":"k1"} -> base64url = eyJhbGciOiJIUzI1NiIsImtpZCI6ImsxIn0
        let token = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImsxIn0.eyJzdWIiOiJ0ZXN0In0.fakesig";
        let cfg = VerifierConfig {
            jwks_url: "https://example.com/.well-known/jwks.json".to_string(),
            issuer: "https://example.com".to_string(),
            audience: None,
        };
        let v = Verifier::new(cfg);
        let err = v
            .verify(token)
            .await
            .expect_err("HS256 header on RS256 JWKS verifier must be rejected");
        assert!(err.to_string().contains("InvalidAlgorithm"), "{err}");
    }

    #[test]
    fn soa_64_byte_cache_aligned_claim_poll_batch() {
        assert_eq!(core::mem::size_of::<FpClaimPolynomial>(), 64);
        assert_eq!(core::mem::align_of::<FpClaimPolynomial>(), 64);
        assert_eq!(core::mem::size_of::<ClaimPollBatchSoa>(), 64);
        assert_eq!(core::mem::align_of::<ClaimPollBatchSoa>(), 64);

        let ours = Uuid::parse_str(OUR_APP).unwrap();
        let c1 = Claims {
            sub: Uuid::from_u128(1),
            org: Uuid::from_u128(2),
            exp: 2_000,
            iat: 1_000,
            scope: vec!["chat:sync".into()],
            app_uuid: Some(ours),
            data: None,
        };
        let c2 = Claims {
            exp: 1_500,
            ..c1.clone()
        };
        let batch = ClaimPollBatchSoa::from_claims_slice(&[(&c1, ours), (&c2, ours)], 42);
        assert_eq!(batch.exp_lanes, [2_000, 1_500, 0, 0]);
        assert_eq!(batch.active_lane_mask(1_200), 0b0011);
        assert_eq!(batch.active_lane_mask(1_500), 0b0001);
        assert_eq!(batch.active_lane_mask(2_000), 0b0000);
        assert_ne!(batch.fp_tag_lanes[0], batch.fp_tag_lanes[1]);
    }
}
