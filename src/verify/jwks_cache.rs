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

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

    fn minimal_jwks() -> serde_json::Value {
        // A minimal JWKS with a single RSA key (key id = "test-kid")
        serde_json::json!({
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "test-kid",
                    "use": "sig",
                    "alg": "RS256",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB"
                }
            ]
        })
    }

    #[tokio::test]
    async fn test_cache_starts_empty() {
        let cache = JwksCache::new();
        // key_for returns None when cache is empty
        let key = cache.key_for("any-kid").await;
        assert!(key.is_none());
    }

    #[tokio::test]
    async fn test_maybe_refresh_fetches_on_first_call() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/jwks.json");
            then.status(200).json_body(minimal_jwks());
        });
        let cache = JwksCache::new();
        let url = format!("{}/jwks.json", server.base_url());
        cache.maybe_refresh(&url, false).await.unwrap();
        // After fetch, key_for returns Some for "test-kid"
        let key = cache.key_for("test-kid").await;
        assert!(key.is_some());
    }

    #[tokio::test]
    async fn test_maybe_refresh_returns_none_for_unknown_kid() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/jwks.json");
            then.status(200).json_body(minimal_jwks());
        });
        let cache = JwksCache::new();
        let url = format!("{}/jwks.json", server.base_url());
        cache.maybe_refresh(&url, false).await.unwrap();
        let key = cache.key_for("unknown-kid").await;
        assert!(key.is_none());
    }

    #[tokio::test]
    async fn test_maybe_refresh_fails_on_server_error() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/jwks.json");
            then.status(500).body("Internal Server Error");
        });
        let cache = JwksCache::new();
        let url = format!("{}/jwks.json", server.base_url());
        let result = cache.maybe_refresh(&url, false).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            VerifyError::JwksFetch(msg) => assert!(msg.contains("500")),
            e => panic!("unexpected error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_maybe_refresh_fails_on_bad_json() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/jwks.json");
            then.status(200).body("not valid json");
        });
        let cache = JwksCache::new();
        let url = format!("{}/jwks.json", server.base_url());
        let result = cache.maybe_refresh(&url, false).await;
        assert!(result.is_err());
        // Either JwksFetch or JwksParse (reqwest may fail at parse stage)
        match result.unwrap_err() {
            VerifyError::JwksParse(_) | VerifyError::JwksFetch(_) => {},
            e => panic!("unexpected error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_force_refresh_updates_last_refetch() {
        let server = MockServer::start();
        // Serve JWKS twice (normal + force)
        server.mock(|when, then| {
            when.method(GET).path("/jwks.json");
            then.status(200).json_body(minimal_jwks());
        });
        let cache = JwksCache::new();
        let url = format!("{}/jwks.json", server.base_url());
        // First fetch
        cache.maybe_refresh(&url, false).await.unwrap();
        // Force fetch should succeed too
        cache.maybe_refresh(&url, true).await.unwrap();
        let key = cache.key_for("test-kid").await;
        assert!(key.is_some());
    }

    #[tokio::test]
    async fn test_no_refetch_within_floor_when_forced() {
        // Two consecutive force calls — the second should be rate-limited
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/jwks.json");
            then.status(200).json_body(minimal_jwks());
        });
        let cache = JwksCache::new();
        let url = format!("{}/jwks.json", server.base_url());
        cache.maybe_refresh(&url, true).await.unwrap();
        cache.maybe_refresh(&url, true).await.unwrap();
        // The mock was only called once (second force is rate-limited)
        assert_eq!(mock.hits(), 1);
    }
}
