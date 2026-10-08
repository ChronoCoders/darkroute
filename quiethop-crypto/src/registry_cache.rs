//! Fetch, cache and refresh policy for the signed registry.
//!
//! The policy lives here rather than in either binary because the client and the
//! relay follow the same one, and two copies would drift.
//!
//! Three rules shape it.
//!
//! A fetch happens at most once per fresh window, never inside a circuit build.
//! `GET /api/v1/registry` is public and unauthenticated, so a fetch per circuit
//! would tell the authority, by client IP, exactly when that address builds
//! circuits. Removing the route endpoint while leaking the same timing through
//! fetches would trade one channel for a weaker version of itself.
//!
//! The whole envelope is persisted, so a restart inside the fresh window
//! re-verifies from disk instead of fetching. The stored copy is re-verified
//! rather than trusted, which puts a tampered state file through the same checks
//! as a tampered response.
//!
//! A failed refresh is not fatal while the last verified document is still
//! inside its own validity. Past `valid_until` there is no grace period and
//! [`RegistryCache::usable`] fails, so the caller refuses new circuits rather
//! than falling back to an unverified or expired relay set.

use std::path::{Path, PathBuf};

use base64::Engine as _;

use crate::registry::{self, PinnedKey, RegistryError, Verified};
use crate::state;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

pub struct RegistryCache {
    url: String,
    dir: PathBuf,
    pinned: Vec<PinnedKey>,
    threshold: usize,
    current: Option<Verified>,
}

impl RegistryCache {
    /// `threshold` signatures from `pinned` keys must verify.
    ///
    /// A threshold above the number of pinned keys could never be met, so it is
    /// rejected here rather than failing every fetch at runtime.
    pub fn new(
        url: String,
        dir: PathBuf,
        pinned: Vec<PinnedKey>,
        threshold: usize,
    ) -> Result<Self, RegistryError> {
        if pinned.is_empty() {
            return Err(RegistryError::Registry(
                "no pinned registry signing key is configured".into(),
            ));
        }
        if threshold == 0 {
            return Err(RegistryError::Registry(
                "the signature threshold must be at least 1".into(),
            ));
        }
        if threshold > pinned.len() {
            return Err(RegistryError::Registry(format!(
                "threshold {threshold} exceeds the {} pinned keys, so it could never be met",
                pinned.len()
            )));
        }
        Ok(Self {
            url,
            dir,
            pinned,
            threshold,
            current: None,
        })
    }

    /// Verify a response body, persist it, and hold it as current.
    ///
    /// Public so a test can drive the cache without standing up an HTTP server.
    pub fn accept_body(&mut self, body: &[u8], now_unix: i64) -> Result<(), RegistryError> {
        let previous = state::load(&self.dir)?;
        let verified = registry::verify(
            body,
            &self.pinned,
            self.threshold,
            now_unix,
            previous.as_ref(),
        )?;
        registry::remember(&self.dir, &verified, body)?;
        self.current = Some(verified);
        Ok(())
    }

    /// Startup: reuse the stored envelope while it is still fresh, else fetch.
    pub async fn prime(&mut self, now_unix: i64) -> Result<(), RegistryError> {
        if let Some(reused) = self.reuse_stored(now_unix) {
            self.current = Some(reused);
            return Ok(());
        }
        let body = self.fetch().await?;
        self.accept_body(&body, now_unix)
    }

    /// Fetch when the current document is past its fresh window.
    ///
    /// `Ok(false)` means the document was still fresh and nothing was fetched.
    /// An error means the fetch or its verification failed, and the caller keeps
    /// serving from [`Self::usable`] until that document expires.
    pub async fn refresh_if_stale(&mut self, now_unix: i64) -> Result<bool, RegistryError> {
        if let Some(current) = &self.current {
            if current.document.fresh_until_unix()? > now_unix {
                return Ok(false);
            }
        }
        let body = self.fetch().await?;
        self.accept_body(&body, now_unix)?;
        Ok(true)
    }

    /// The document to use now, or an error when none may be used.
    ///
    /// This is the fail-closed point. There is no grace period past
    /// `valid_until`, so an authority outage long enough to outlast the last
    /// document stops new circuits rather than widening the window.
    pub fn usable(&self, now_unix: i64) -> Result<&Verified, RegistryError> {
        let current = self.current.as_ref().ok_or_else(|| {
            RegistryError::Registry("no verified registry has been accepted".into())
        })?;
        if !current.document.is_usable_at(now_unix)? {
            return Err(RegistryError::Registry(
                "the last verified registry is outside its validity window".into(),
            ));
        }
        Ok(current)
    }

    /// Whether a refresh is due, for a caller driving its own timer.
    pub fn is_stale(&self, now_unix: i64) -> Result<bool, RegistryError> {
        match &self.current {
            Some(current) => Ok(current.document.fresh_until_unix()? <= now_unix),
            None => Ok(true),
        }
    }

    pub fn state_dir(&self) -> &Path {
        &self.dir
    }

    fn reuse_stored(&self, now_unix: i64) -> Option<Verified> {
        let stored = state::load(&self.dir).ok()??;
        let bytes = B64.decode(stored.envelope_b64.as_deref()?).ok()?;
        let verified = registry::verify(
            &bytes,
            &self.pinned,
            self.threshold,
            now_unix,
            Some(&stored),
        )
        .ok()?;
        if verified.document.fresh_until_unix().ok()? > now_unix {
            Some(verified)
        } else {
            None
        }
    }

    async fn fetch(&self) -> Result<Vec<u8>, RegistryError> {
        let resp = reqwest::get(&self.url)
            .await
            .map_err(|e| RegistryError::Registry(format!("registry fetch failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(RegistryError::Registry(format!(
                "registry fetch returned status {}",
                status.as_u16()
            )));
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| RegistryError::Registry(format!("registry body unreadable: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::DOMAIN;
    use ed25519_dalek::{Signer, SigningKey};

    // 2026-10-08T14:00:00Z, fresh for an hour, valid for six.
    const AFTER: i64 = 1_791_468_000;
    const FRESH: i64 = AFTER + 3600;
    const UNTIL: i64 = AFTER + 6 * 3600;

    /// Nothing listens here, so a fetch fails at once. A cache that returns Ok
    /// with this url demonstrably served from disk rather than the network.
    const UNROUTABLE: &str = "http://127.0.0.1:1/api/v1/registry";

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[0x33; 32])
    }

    fn pinned(k: &SigningKey) -> PinnedKey {
        PinnedKey::from_bytes(&k.verifying_key().to_bytes()).unwrap()
    }

    fn document() -> Vec<u8> {
        format!(
            r#"{{"version":{},"valid_after":"2026-10-08T14:00:00Z","fresh_until":"2026-10-08T15:00:00Z","valid_until":"2026-10-08T20:00:00Z","relays":[]}}"#,
            AFTER / 3600
        )
        .into_bytes()
    }

    fn envelope(k: &SigningKey, doc: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(DOMAIN);
        msg.push(0x00);
        msg.extend_from_slice(doc);
        let sig = k.sign(&msg);
        format!(
            r#"{{"document":"{}","signatures":[{{"key_id":"{}","sig":"{}"}}]}}"#,
            B64.encode(doc),
            pinned(k).key_id,
            B64.encode(sig.to_bytes())
        )
        .into_bytes()
    }

    fn cache(dir: &Path) -> RegistryCache {
        RegistryCache::new(
            UNROUTABLE.to_string(),
            dir.to_path_buf(),
            vec![pinned(&key())],
            1,
        )
        .expect("a single pinned key with threshold 1 is valid")
    }

    /// A refresh that fails must not stop service while the document it already
    /// holds is inside its own validity, and must stop it at valid_until with no
    /// grace period.
    #[test]
    fn a_failed_refresh_serves_until_valid_until_and_refuses_after() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cache(dir.path());
        c.accept_body(&envelope(&key(), &document()), AFTER + 60)
            .unwrap();

        // No further accept_body call, so every later instant models a window in
        // which refreshes kept failing.
        assert!(c.usable(AFTER + 60).is_ok(), "fresh document is usable");
        assert!(
            c.usable(FRESH + 1).is_ok(),
            "past fresh_until it is still usable"
        );
        assert!(
            c.usable(UNTIL - 1).is_ok(),
            "one second before valid_until it is still usable"
        );
        let err = c.usable(UNTIL).expect_err("at valid_until it must refuse");
        match err {
            RegistryError::Registry(m) => {
                assert!(m.contains("validity window"), "message was {m}")
            }
            other => panic!("wrong error: {other:?}"),
        }
        assert!(c.usable(UNTIL + 3600).is_err(), "still refused later");
    }

    #[test]
    fn staleness_begins_exactly_at_fresh_until() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cache(dir.path());
        assert!(
            c.is_stale(AFTER).unwrap(),
            "with no document a refresh is due"
        );
        c.accept_body(&envelope(&key(), &document()), AFTER + 60)
            .unwrap();
        assert!(!c.is_stale(FRESH - 1).unwrap(), "fresh one second before");
        assert!(c.is_stale(FRESH).unwrap(), "stale at fresh_until");
    }

    /// A restart inside the fresh window must re-verify from disk rather than
    /// fetch, so the authority sees one fetch per window and not one per start.
    #[tokio::test]
    async fn a_restart_inside_the_fresh_window_reuses_the_stored_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let mut first = cache(dir.path());
        first
            .accept_body(&envelope(&key(), &document()), AFTER + 60)
            .unwrap();

        let mut second = cache(dir.path());
        second
            .prime(AFTER + 120)
            .await
            .expect("prime must reuse the stored envelope, since no fetch could succeed");
        assert!(second.usable(AFTER + 120).is_ok());
    }

    /// Reuse is bounded by the fresh window. Past it the cache must go to the
    /// network, which here means failing rather than serving a stale document.
    #[tokio::test]
    async fn a_restart_past_the_fresh_window_does_not_reuse() {
        let dir = tempfile::tempdir().unwrap();
        let mut first = cache(dir.path());
        first
            .accept_body(&envelope(&key(), &document()), AFTER + 60)
            .unwrap();

        let mut second = cache(dir.path());
        let err = second
            .prime(FRESH + 1)
            .await
            .expect_err("past fresh_until prime must attempt a fetch");
        match err {
            RegistryError::Registry(m) => assert!(m.contains("fetch"), "message was {m}"),
            other => panic!("wrong error: {other:?}"),
        }
    }

    /// The stored copy is re-verified, not trusted. A tampered state file must
    /// send the cache to the network rather than be served.
    #[tokio::test]
    async fn a_tampered_stored_envelope_is_not_reused() {
        let dir = tempfile::tempdir().unwrap();
        let mut first = cache(dir.path());
        let good = envelope(&key(), &document());
        first.accept_body(&good, AFTER + 60).unwrap();

        // A local attacker rewriting the state file would rewrite all of it, so
        // both stored copies are replaced with a well formed document signed by
        // a key this cache does not pin. Tampering only the envelope would leave
        // an intact document_b64 that a trusting implementation could still read.
        let forged_doc = document();
        let forged = envelope(&SigningKey::from_bytes(&[0x44; 32]), &forged_doc);
        let mut stored = state::load(dir.path()).unwrap().unwrap();
        stored.envelope_b64 = Some(B64.encode(&forged));
        stored.document_b64 = B64.encode(&forged_doc);
        state::store(dir.path(), &stored).unwrap();

        let mut second = cache(dir.path());
        assert!(
            second.prime(AFTER + 120).await.is_err(),
            "a stored envelope signed by an unpinned key must not be reused"
        );
    }

    #[test]
    fn an_unmeetable_threshold_is_rejected_at_construction() {
        let dir = tempfile::tempdir().unwrap();
        let k = key();
        assert!(
            RegistryCache::new(UNROUTABLE.into(), dir.path().into(), vec![pinned(&k)], 2).is_err()
        );
        assert!(
            RegistryCache::new(UNROUTABLE.into(), dir.path().into(), vec![pinned(&k)], 0).is_err()
        );
        assert!(RegistryCache::new(UNROUTABLE.into(), dir.path().into(), vec![], 1).is_err());
        assert!(
            RegistryCache::new(UNROUTABLE.into(), dir.path().into(), vec![pinned(&k)], 1).is_ok()
        );
    }
}
