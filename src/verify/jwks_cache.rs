//! JWKS cache with TTL + rate-limited force-refetch on kid miss.
//!
//! Fetched lazily. Stale keys (>5min) trigger a refresh on the next
//! verify; a `kid` not present in the cached set triggers a force
//! refresh (rate-limited to 1×/min) before erroring — so key rotation
//! at buttrbase propagates within a minute without touching consumer
//! configs.

use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::{DecodingKey, jwk::JwkSet};
use tokio::sync::RwLock;

use super::error::VerifyError;

const JWKS_TTL: Duration = Duration::from_secs(300);
const JWKS_REFETCH_FLOOR: Duration = Duration::from_secs(60);

#[derive(Clone, Default)]
pub(crate) struct JwksCache {
    inner: Arc<RwLock<JwksCacheInner>>,
}

#[derive(Default)]
struct JwksCacheInner {
    set: Option<JwkSet>,
    fetched_at: Option<Instant>,
    last_refetch: Option<Instant>,
}

impl JwksCache {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    async fn fetch(&self, url: &str) -> Result<(), VerifyError> {
        let resp = reqwest::Client::new()
            .get(url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| VerifyError::JwksFetch(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(VerifyError::JwksFetch(format!(
                "status {}",
                resp.status()
            )));
        }
        let set: JwkSet = resp
            .json()
            .await
            .map_err(|e| VerifyError::JwksParse(e.to_string()))?;
        let mut inner = self.inner.write().await;
        inner.set = Some(set);
        inner.fetched_at = Some(Instant::now());
        Ok(())
    }

    pub(crate) async fn maybe_refresh(
        &self,
        url: &str,
        force: bool,
    ) -> Result<(), VerifyError> {
        let need = {
            let inner = self.inner.read().await;
            match inner.fetched_at {
                None => true,
                Some(t) if t.elapsed() > JWKS_TTL => true,
                _ => {
                    force
                        && inner
                            .last_refetch
                            .map_or(true, |r| r.elapsed() > JWKS_REFETCH_FLOOR)
                }
            }
        };
        if need {
            self.fetch(url).await?;
            if force {
                let mut inner = self.inner.write().await;
                inner.last_refetch = Some(Instant::now());
            }
        }
        Ok(())
    }

    pub(crate) async fn key_for(&self, kid: &str) -> Option<DecodingKey> {
        let inner = self.inner.read().await;
        let set = inner.set.as_ref()?;
        let jwk = set.find(kid)?;
        DecodingKey::from_jwk(jwk).ok()
    }
}
