//! Signed relay registry: fetch, verify, then parse.
//!
//! Order matters and is the point of this module. The response carries the
//! document base64-encoded, and nothing inside it is read until a threshold of
//! signatures from pinned keys has verified over the exact bytes. A document
//! that fails verification is never parsed, so a malformed or hostile document
//! cannot reach the JSON decoder.
//!
//! The signed message is `"quiethop/v1/registry" || 0x00 || document_bytes`.
//! The label is bound so a signature cannot be replayed from any other context
//! that signs raw bytes with the same key, and the `0x00` makes the prefix
//! unambiguous against a longer label starting with it.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey, SIGNATURE_LENGTH};
use serde::Deserialize;

use crate::noise::STATIC_KEY_LEN;

use crate::state::{self, RegistryState};

/// Errors from registry verification and the state file behind it.
///
/// This lives beside the verifier rather than in either binary, because the
/// client and the relay both verify with the same rules and must not drift
/// into two implementations of them (ARCHITECTURE 5.2, SECURITY_MODEL 5.3).
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("registry: {0}")]
    Registry(String),
    #[error("registry equivocation: two different documents carry version {0}")]
    Equivocation(i64),
    #[error("malformed registry signing key: {0}")]
    InvalidKey(String),
    #[error("registry state: {0}")]
    State(String),
}

/// Signature domain. Must match the authority's `registry.Domain`.
pub const DOMAIN: &[u8] = b"quiethop/v1/registry";

/// Clock-skew allowance on `valid_after` only.
///
/// 60 seconds against a 6 hour validity window is 1.7%, enough to absorb an
/// unsynchronised client clock without meaningfully widening the window. It is
/// deliberately not applied to `valid_until`: leniency at the start costs
/// nothing, while leniency at the end would extend the time an attacker has to
/// replay a document whose relay set has been retired.
pub const SKEW_ALLOWANCE_SECS: i64 = 60;

/// How many pinned keys must sign. One for now; the format already carries a
/// list so operator co-signing needs no wire change.
pub const DEFAULT_THRESHOLD: usize = 1;

#[derive(Debug, Clone, Deserialize)]
pub struct RelayEntry {
    pub id: String,
    pub operator_id: String,
    pub host_id: String,
    pub role: String,
    pub ip: String,
    pub port: u16,
    pub tls_name: String,
    pub static_pubkey: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Document {
    pub version: i64,
    pub valid_after: String,
    pub fresh_until: String,
    pub valid_until: String,
    pub relays: Vec<RelayEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct SignatureEntry {
    key_id: String,
    sig: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Envelope {
    document: String,
    signatures: Vec<SignatureEntry>,
}

/// A pinned registry signing key.
#[derive(Debug, Clone)]
pub struct PinnedKey {
    pub key_id: String,
    pub key: VerifyingKey,
}

impl PinnedKey {
    /// Build from a 32-byte public key, deriving the key id the same way the
    /// authority does: the first 8 bytes of SHA-256 over the raw key.
    pub fn from_bytes(raw: &[u8; 32]) -> Result<Self, RegistryError> {
        let key = VerifyingKey::from_bytes(raw)
            .map_err(|_| RegistryError::InvalidKey("registry signing key".into()))?;
        Ok(Self {
            key_id: key_id_for(raw),
            key,
        })
    }

    pub fn from_hex(hex: &str) -> Result<Self, RegistryError> {
        let raw = decode_hex32(hex)
            .ok_or_else(|| RegistryError::InvalidKey("registry signing key hex".into()))?;
        Self::from_bytes(&raw)
    }
}

pub fn key_id_for(raw: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(raw);
    let mut out = String::with_capacity(16);
    for b in &digest[..8] {
        out.push(nibble(b >> 4));
        out.push(nibble(b & 0x0f));
    }
    out
}

/// The exact bytes a registry signature covers.
fn signed_message(document: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(DOMAIN.len() + 1 + document.len());
    msg.extend_from_slice(DOMAIN);
    msg.push(0x00);
    msg.extend_from_slice(document);
    msg
}

/// Reduce an address to one spelling before it is compared.
///
/// An IPv4-mapped IPv6 address such as `::ffff:10.1.0.1` names the same host as
/// `10.1.0.1`. Compared as written, the two read as different families, which
/// skips the IPv4 prefix rule in SECURITY_MODEL §5.3 and lets through a path
/// that rule exists to forbid. It also makes a relay refuse a peer the registry
/// does list, under the other spelling.
///
/// Every comparison on both sides goes through here, so the client and the relay
/// cannot drift into two notions of when two addresses are the same.
/// `to_canonical` leaves a genuine IPv6 address untouched.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// [`canonical_ip`] for a socket address, keeping the port.
pub fn canonical_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(canonical_ip(addr.ip()), addr.port())
}

impl RelayEntry {
    /// The entry's address, canonical.
    ///
    /// This and [`RelayEntry::addr`] are the only ways an entry's address enters
    /// a comparison, which is what keeps the reduction in one place.
    pub fn ip_addr(&self) -> Result<IpAddr, RegistryError> {
        let ip: IpAddr = self
            .ip
            .parse()
            .map_err(|_| RegistryError::Registry("registry entry holds no IP literal".into()))?;
        Ok(canonical_ip(ip))
    }

    /// The socket address to dial, canonical.
    ///
    /// Parsed as a literal and never resolved: SECURITY_MODEL §5.3 forbids
    /// resolving a name anywhere in path construction, because a resolver that
    /// saw those lookups would learn the path.
    pub fn addr(&self) -> Result<SocketAddr, RegistryError> {
        let ip = self.ip_addr()?;
        if self.port == 0 {
            return Err(RegistryError::Registry("registry entry has port 0".into()));
        }
        Ok(SocketAddr::new(ip, self.port))
    }

    /// The X25519 static public key the NK handshake is pinned to.
    pub fn static_key(&self) -> Result<[u8; STATIC_KEY_LEN], RegistryError> {
        let raw = decode_hex(&self.static_pubkey)
            .ok_or_else(|| RegistryError::Registry("static_pubkey is not hex".into()))?;
        raw.try_into()
            .map_err(|_| RegistryError::Registry("static_pubkey is not 32 bytes".into()))
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

impl Document {
    /// `valid_after` as Unix seconds.
    pub fn valid_after_unix(&self) -> Result<i64, RegistryError> {
        parse_rfc3339(&self.valid_after)
    }

    /// `fresh_until` as Unix seconds. Past it the document is still usable and a
    /// newer one is expected to exist, which is when a refetch is due.
    pub fn fresh_until_unix(&self) -> Result<i64, RegistryError> {
        parse_rfc3339(&self.fresh_until)
    }

    /// `valid_until` as Unix seconds. There is no grace period past it.
    pub fn valid_until_unix(&self) -> Result<i64, RegistryError> {
        parse_rfc3339(&self.valid_until)
    }

    /// Whether the document may be used at `now_unix`.
    ///
    /// Verification already checked this, but time moves on afterwards: a
    /// document verified inside its window expires while it is cached, so every
    /// use re-checks rather than trusting the check made at fetch time.
    pub fn is_usable_at(&self, now_unix: i64) -> Result<bool, RegistryError> {
        let after = self.valid_after_unix()?;
        let until = self.valid_until_unix()?;
        Ok(now_unix + SKEW_ALLOWANCE_SECS >= after && now_unix < until)
    }
}

/// A document that passed every check, with the bytes it was verified over.
#[derive(Debug, Clone)]
pub struct Verified {
    pub document: Document,
    pub bytes: Vec<u8>,
    pub key_ids: Vec<String>,
}

/// Verify an envelope and return the parsed document.
///
/// `now_unix` is the current time in seconds. `previous` is the stored state,
/// or `None` on first use.
pub fn verify(
    body: &[u8],
    pinned: &[PinnedKey],
    threshold: usize,
    now_unix: i64,
    previous: Option<&RegistryState>,
) -> Result<Verified, RegistryError> {
    if threshold == 0 {
        return Err(RegistryError::Registry(
            "threshold must be at least 1".into(),
        ));
    }
    let envelope: Envelope = serde_json::from_slice(body).map_err(|e| {
        RegistryError::Registry(format!("response is not a registry envelope: {e}"))
    })?;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(envelope.document.as_bytes())
        .map_err(|e| RegistryError::Registry(format!("document is not base64: {e}")))?;

    // Signatures first. Nothing inside the document is read until a threshold
    // of pinned keys has verified over these exact bytes.
    let msg = signed_message(&bytes);
    let mut accepted: BTreeSet<String> = BTreeSet::new();
    for entry in &envelope.signatures {
        let Some(pin) = pinned.iter().find(|p| p.key_id == entry.key_id) else {
            // Not a pinned key id. Silently skipped rather than fatal, so a
            // future co-signer unknown to this verifier cannot break it.
            continue;
        };
        let raw = match base64::engine::general_purpose::STANDARD.decode(entry.sig.as_bytes()) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let Ok(fixed) = <[u8; SIGNATURE_LENGTH]>::try_from(raw.as_slice()) else {
            continue;
        };
        // verify_strict, not verify: it rejects non-canonical and small-order
        // keys that plain verify accepts.
        if pin
            .key
            .verify_strict(&msg, &Signature::from_bytes(&fixed))
            .is_ok()
        {
            accepted.insert(pin.key_id.clone());
        }
    }
    if accepted.len() < threshold {
        return Err(RegistryError::Registry(format!(
            "{} of {threshold} required signatures from pinned keys verified",
            accepted.len()
        )));
    }

    let document: Document = serde_json::from_slice(&bytes)
        .map_err(|e| RegistryError::Registry(format!("verified document does not parse: {e}")))?;

    check_validity(&document, now_unix)?;
    check_rollback(&document, &bytes, previous)?;

    Ok(Verified {
        document,
        bytes,
        key_ids: accepted.into_iter().collect(),
    })
}

fn check_validity(doc: &Document, now_unix: i64) -> Result<(), RegistryError> {
    let after = parse_rfc3339(&doc.valid_after)?;
    let until = parse_rfc3339(&doc.valid_until)?;
    if until <= after {
        return Err(RegistryError::Registry(
            "valid_until is not after valid_after".into(),
        ));
    }
    // version is hours since the epoch, derived from valid_after rather than
    // counted. Checking it here makes version order and hour order the same
    // thing on both sides, so a document cannot claim to be newer than its own
    // hour (docs/DECISIONS.md entry 16).
    if after % 3600 != 0 {
        return Err(RegistryError::Registry(format!(
            "valid_after {} is not on an exact hour",
            doc.valid_after
        )));
    }
    let expected = after / 3600;
    if doc.version != expected {
        return Err(RegistryError::Registry(format!(
            "version {} does not match valid_after {}, which is hour {expected}",
            doc.version, doc.valid_after
        )));
    }
    if now_unix + SKEW_ALLOWANCE_SECS < after {
        return Err(RegistryError::Registry(format!(
            "document is not yet valid: valid_after {} is more than {SKEW_ALLOWANCE_SECS}s ahead",
            doc.valid_after
        )));
    }
    // No grace period past valid_until.
    if now_unix >= until {
        return Err(RegistryError::Registry(format!(
            "document expired at {}",
            doc.valid_until
        )));
    }
    Ok(())
}

fn check_rollback(
    doc: &Document,
    bytes: &[u8],
    previous: Option<&RegistryState>,
) -> Result<(), RegistryError> {
    let Some(prev) = previous else {
        // Trust on first use: no baseline exists, so this document becomes it.
        return Ok(());
    };
    if doc.version < prev.highest_version {
        return Err(RegistryError::Registry(format!(
            "rollback: version {} is below the highest seen {}",
            doc.version, prev.highest_version
        )));
    }
    if doc.version == prev.highest_version {
        let stored = base64::engine::general_purpose::STANDARD
            .decode(prev.document_b64.as_bytes())
            .map_err(|e| RegistryError::State(format!("stored document is not base64: {e}")))?;
        if stored != bytes {
            // Two different documents under one version. Only the authority
            // can produce both, so this is local evidence of equivocation.
            return Err(RegistryError::Equivocation(doc.version));
        }
    }
    Ok(())
}

/// Record a verified document as the new baseline, if it advances the version.
pub fn remember(dir: &Path, verified: &Verified, envelope: &[u8]) -> Result<(), RegistryError> {
    let state = RegistryState {
        highest_version: verified.document.version,
        document_b64: base64::engine::general_purpose::STANDARD.encode(&verified.bytes),
        key_ids: verified.key_ids.clone(),
        envelope_b64: Some(base64::engine::general_purpose::STANDARD.encode(envelope)),
    };
    match state::load(dir)? {
        Some(prev) if prev.highest_version >= state.highest_version => Ok(()),
        _ => state::store(dir, &state),
    }
}

/// Parse RFC 3339 UTC with a Z suffix into a unix timestamp.
///
/// Deliberately narrow: the authority emits exactly this shape, so accepting
/// numeric offsets or fractional seconds would widen what a client treats as a
/// valid timestamp without any publisher producing it.
fn parse_rfc3339(s: &str) -> Result<i64, RegistryError> {
    let bad = || RegistryError::Registry(format!("timestamp {s:?} is not RFC 3339 UTC with Z"));
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return Err(bad());
    }
    let num = |from: usize, to: usize| -> Result<i64, RegistryError> {
        s.get(from..to)
            .ok_or_else(bad)?
            .parse::<i64>()
            .map_err(|_| bad())
    };
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&mo) || h > 23 || mi > 59 || sec > 60 {
        return Err(bad());
    }
    // The day must exist in that month of that year. Bounding it at 31 would
    // accept 2026-02-29 and 2026-04-31, and days_from_civil would silently
    // roll them into the following month rather than report anything.
    if d < 1 || d > days_in_month(y, mo) {
        return Err(bad());
    }
    Ok(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + sec)
}

/// Whether a year is a leap year in the proleptic Gregorian calendar: every
/// fourth year, except centuries, except every fourth century.
fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Days in a month. `m` must already be in 1..=12.
fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(y) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 from a civil date, after Howard Hinnant's algorithm.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn nibble(v: u8) -> char {
    char::from_digit(u32::from(v), 16).unwrap_or('0')
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let b = s.as_bytes();
    for (i, pair) in b.chunks(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::STANDARD;

    /// 2026-10-07T14:30:00Z, inside the sample document's validity.
    const NOW: i64 = 1_791_383_400;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn pinned_of(k: &SigningKey) -> PinnedKey {
        PinnedKey::from_bytes(&k.verifying_key().to_bytes()).unwrap()
    }

    /// Build a document whose version is derived from its hour, as the
    /// authority does.
    fn doc_bytes(valid_after: &str, valid_until: &str) -> Vec<u8> {
        let version = parse_rfc3339(valid_after).expect("valid_after parses") / 3600;
        doc_bytes_versioned(version, valid_after, valid_until)
    }

    /// Build a document with an explicit version, so a mismatch can be tested.
    fn doc_bytes_versioned(version: i64, valid_after: &str, valid_until: &str) -> Vec<u8> {
        format!(
            r#"{{"version":{version},"valid_after":"{valid_after}","fresh_until":"{valid_after}","valid_until":"{valid_until}","relays":[]}}"#
        )
        .into_bytes()
    }

    fn sample_doc() -> Vec<u8> {
        doc_bytes("2026-10-07T14:00:00Z", "2026-10-07T20:00:00Z")
    }

    /// The hour number for the sample document's valid_after.
    fn sample_version() -> i64 {
        parse_rfc3339("2026-10-07T14:00:00Z").unwrap() / 3600
    }

    fn envelope(k: &SigningKey, document: &[u8]) -> Vec<u8> {
        let sig = k.sign(&signed_message(document));
        let pin = pinned_of(k);
        format!(
            r#"{{"document":"{}","signatures":[{{"key_id":"{}","sig":"{}"}}]}}"#,
            B64.encode(document),
            pin.key_id,
            B64.encode(sig.to_bytes())
        )
        .into_bytes()
    }

    #[test]
    fn a_valid_document_verifies() {
        let k = signing_key(1);
        let doc = sample_doc();
        let v = verify(&envelope(&k, &doc), &[pinned_of(&k)], 1, NOW, None).unwrap();
        assert_eq!(v.document.version, sample_version());
        assert_eq!(v.bytes, doc, "the verified bytes must be the signed bytes");
        assert_eq!(v.key_ids, vec![pinned_of(&k).key_id]);
    }

    #[test]
    fn one_flipped_byte_fails() {
        let k = signing_key(2);
        let doc = sample_doc();
        let good = envelope(&k, &doc);
        // Control: unmodified verifies.
        assert!(verify(&good, &[pinned_of(&k)], 1, NOW, None).is_ok());

        let mut flipped = doc.clone();
        flipped[10] ^= 0x01;
        // Re-wrap the flipped document with the original signature.
        let sig = k.sign(&signed_message(&doc));
        let body = format!(
            r#"{{"document":"{}","signatures":[{{"key_id":"{}","sig":"{}"}}]}}"#,
            B64.encode(&flipped),
            pinned_of(&k).key_id,
            B64.encode(sig.to_bytes())
        )
        .into_bytes();
        assert!(matches!(
            verify(&body, &[pinned_of(&k)], 1, NOW, None),
            Err(RegistryError::Registry(_))
        ));
    }

    #[test]
    fn a_signature_from_a_non_pinned_key_fails() {
        let real = signing_key(3);
        let other = signing_key(4);
        let doc = sample_doc();
        // Control: the pinned key verifies its own signature.
        assert!(verify(&envelope(&real, &doc), &[pinned_of(&real)], 1, NOW, None).is_ok());
        // Signed by `other`, but only `real` is pinned.
        assert!(matches!(
            verify(&envelope(&other, &doc), &[pinned_of(&real)], 1, NOW, None),
            Err(RegistryError::Registry(_))
        ));
    }

    #[test]
    fn an_expired_document_fails_with_no_grace_period() {
        let k = signing_key(5);
        let doc = sample_doc();
        // One second past valid_until, 2026-10-07T20:00:00Z.
        let expired_at = parse_rfc3339("2026-10-07T20:00:00Z").unwrap();
        assert!(matches!(
            verify(&envelope(&k, &doc), &[pinned_of(&k)], 1, expired_at, None),
            Err(RegistryError::Registry(_))
        ));
        // Control: one second before it is still accepted.
        assert!(verify(
            &envelope(&k, &doc),
            &[pinned_of(&k)],
            1,
            expired_at - 1,
            None
        )
        .is_ok());
    }

    #[test]
    fn a_not_yet_valid_document_fails_outside_the_skew_allowance() {
        let k = signing_key(6);
        let doc = sample_doc();
        let after = parse_rfc3339("2026-10-07T14:00:00Z").unwrap();
        // Inside the allowance: accepted.
        assert!(verify(
            &envelope(&k, &doc),
            &[pinned_of(&k)],
            1,
            after - SKEW_ALLOWANCE_SECS,
            None
        )
        .is_ok());
        // One second beyond it: rejected.
        assert!(matches!(
            verify(
                &envelope(&k, &doc),
                &[pinned_of(&k)],
                1,
                after - SKEW_ALLOWANCE_SECS - 1,
                None
            ),
            Err(RegistryError::Registry(_))
        ));
    }

    #[test]
    fn a_lower_version_after_a_higher_one_is_a_rollback() {
        let k = signing_key(7);
        // Version follows the hour, so an older document is an earlier hour.
        // The 13:00 document is still inside its six hour validity at 14:30.
        let high = doc_bytes("2026-10-07T14:00:00Z", "2026-10-07T20:00:00Z");
        let prev = RegistryState {
            highest_version: sample_version(),
            document_b64: B64.encode(&high),
            key_ids: vec![pinned_of(&k).key_id],
            envelope_b64: None,
        };
        // Control: the same version with the same bytes is accepted.
        assert!(verify(&envelope(&k, &high), &[pinned_of(&k)], 1, NOW, Some(&prev)).is_ok());

        let low = doc_bytes("2026-10-07T13:00:00Z", "2026-10-07T19:00:00Z");
        match verify(&envelope(&k, &low), &[pinned_of(&k)], 1, NOW, Some(&prev)) {
            Err(RegistryError::Registry(m)) => assert!(m.contains("rollback"), "message was {m}"),
            other => panic!("a rollback was accepted: {other:?}"),
        }
    }

    #[test]
    fn the_same_version_with_different_bytes_is_equivocation() {
        let k = signing_key(8);
        let first = doc_bytes("2026-10-07T14:00:00Z", "2026-10-07T20:00:00Z");
        // Same hour and therefore the same version, different relay list.
        let second = format!(
            r#"{{"version":{},"valid_after":"2026-10-07T14:00:00Z","fresh_until":"2026-10-07T15:00:00Z","valid_until":"2026-10-07T20:00:00Z","relays":[{{"id":"x","operator_id":"o","host_id":"h","role":"guard","ip":"203.0.113.1","port":443,"tls_name":"n","static_pubkey":"00"}}]}}"#,
            sample_version()
        )
        .into_bytes();
        let prev = RegistryState {
            highest_version: sample_version(),
            document_b64: B64.encode(&first),
            key_ids: vec![pinned_of(&k).key_id],
            envelope_b64: None,
        };
        match verify(
            &envelope(&k, &second),
            &[pinned_of(&k)],
            1,
            NOW,
            Some(&prev),
        ) {
            Err(RegistryError::Equivocation(v)) if v == sample_version() => {}
            other => panic!("equivocation was not reported: {other:?}"),
        }
    }

    /// A correctly signed document whose version does not match its hour must
    /// be refused. Version and hour order are the same thing by construction,
    /// so a document claiming otherwise is either a publisher bug or an attempt
    /// to look newer than it is.
    #[test]
    fn a_version_that_does_not_match_valid_after_is_rejected() {
        let k = signing_key(20);
        // Control: the derived version is accepted.
        let right = doc_bytes("2026-10-07T14:00:00Z", "2026-10-07T20:00:00Z");
        assert!(verify(&envelope(&k, &right), &[pinned_of(&k)], 1, NOW, None).is_ok());

        for wrong in [sample_version() + 1, sample_version() - 1, 1, 0] {
            let doc = doc_bytes_versioned(wrong, "2026-10-07T14:00:00Z", "2026-10-07T20:00:00Z");
            match verify(&envelope(&k, &doc), &[pinned_of(&k)], 1, NOW, None) {
                Err(RegistryError::Registry(m)) => assert!(
                    m.contains("does not match valid_after"),
                    "version {wrong}: message was {m}"
                ),
                other => panic!("version {wrong} was accepted: {other:?}"),
            }
        }
    }

    #[test]
    fn an_off_hour_valid_after_is_rejected() {
        let k = signing_key(21);
        // 14:30 is not a publication boundary, so no version can match it.
        let doc = doc_bytes_versioned(
            sample_version(),
            "2026-10-07T14:30:00Z",
            "2026-10-07T20:30:00Z",
        );
        match verify(&envelope(&k, &doc), &[pinned_of(&k)], 1, NOW, None) {
            Err(RegistryError::Registry(m)) => {
                assert!(m.contains("not on an exact hour"), "message was {m}")
            }
            other => panic!("an off-hour valid_after was accepted: {other:?}"),
        }
    }

    /// The threshold must be read, not assumed. Raising it to 2 with one
    /// signature must fail even though that signature is valid.
    #[test]
    fn the_threshold_is_enforced() {
        let k = signing_key(9);
        let doc = sample_doc();
        let body = envelope(&k, &doc);
        // Control: threshold 1 passes with one signature.
        assert!(verify(&body, &[pinned_of(&k)], 1, NOW, None).is_ok());
        match verify(&body, &[pinned_of(&k)], 2, NOW, None) {
            Err(RegistryError::Registry(m)) => {
                assert!(m.contains("of 2 required"), "message was {m}")
            }
            other => panic!("threshold 2 was satisfied by one signature: {other:?}"),
        }
    }

    /// Domain separation: a signature over the bare document bytes must not
    /// verify as a registry signature.
    #[test]
    fn a_signature_over_the_bare_document_does_not_verify() {
        let k = signing_key(10);
        let doc = sample_doc();
        // Control: the domain-separated envelope verifies.
        assert!(verify(&envelope(&k, &doc), &[pinned_of(&k)], 1, NOW, None).is_ok());

        let bare = k.sign(&doc);
        let body = format!(
            r#"{{"document":"{}","signatures":[{{"key_id":"{}","sig":"{}"}}]}}"#,
            B64.encode(&doc),
            pinned_of(&k).key_id,
            B64.encode(bare.to_bytes())
        )
        .into_bytes();
        assert!(matches!(
            verify(&body, &[pinned_of(&k)], 1, NOW, None),
            Err(RegistryError::Registry(_))
        ));
    }

    #[test]
    fn a_document_is_not_parsed_before_it_verifies() {
        // The document is not valid JSON at all. A verifier that parsed first
        // would report a parse error; one that verifies first reports a
        // signature failure.
        let k = signing_key(11);
        let junk = b"not json at all".to_vec();
        let other = signing_key(12);
        let body = format!(
            r#"{{"document":"{}","signatures":[{{"key_id":"{}","sig":"{}"}}]}}"#,
            B64.encode(&junk),
            pinned_of(&other).key_id,
            B64.encode(other.sign(&signed_message(&junk)).to_bytes())
        )
        .into_bytes();
        match verify(&body, &[pinned_of(&k)], 1, NOW, None) {
            Err(RegistryError::Registry(m)) => assert!(
                m.contains("required signatures"),
                "expected a signature failure before any parse, got {m}"
            ),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn key_id_matches_the_authority_derivation() {
        // sha256 over the raw 32 byte key, first 8 bytes, hex.
        let k = signing_key(13);
        let raw = k.verifying_key().to_bytes();
        use sha2::{Digest, Sha256};
        let want: String = Sha256::digest(raw)[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(key_id_for(&raw), want);
    }

    #[test]
    fn timestamps_must_be_rfc3339_utc_with_z() {
        assert!(parse_rfc3339("2026-10-07T14:00:00Z").is_ok());
        for bad in [
            "2026-10-07T14:00:00+01:00",
            "2026-10-07 14:00:00Z",
            "2026-10-07T14:00:00.5Z",
            "2026-13-07T14:00:00Z",
            "2026-10-07T24:00:00Z",
            "",
        ] {
            assert!(parse_rfc3339(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn civil_date_conversion_matches_known_epochs() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(parse_rfc3339("2000-01-01T00:00:00Z").unwrap(), 946_684_800);
        assert_eq!(
            parse_rfc3339("2026-10-07T14:00:00Z").unwrap(),
            1_791_381_600
        );
    }

    /// The Rust half of the cross-language check: a document signed by the Go
    fn sample_entry(ip: &str, port: u16, key: &str) -> RelayEntry {
        RelayEntry {
            id: "r1".into(),
            operator_id: "op".into(),
            host_id: "h".into(),
            role: "guard".into(),
            ip: ip.into(),
            port,
            tls_name: "r1.example".into(),
            static_pubkey: key.into(),
        }
    }

    #[test]
    fn addr_parses_v4_and_v6_literals() {
        assert_eq!(
            sample_entry("10.0.0.1", 443, "").addr().unwrap(),
            "10.0.0.1:443".parse::<std::net::SocketAddr>().unwrap()
        );
        assert_eq!(
            sample_entry("2001:db8::1", 443, "").addr().unwrap(),
            "[2001:db8::1]:443".parse::<std::net::SocketAddr>().unwrap()
        );
    }

    /// The guarantee is that a name is never resolved. An entry whose ip field
    /// holds one must fail rather than fall back to DNS (SECURITY_MODEL 5.3).
    #[test]
    fn addr_refuses_a_hostname() {
        for name in ["node01.example", "localhost", ""] {
            assert!(
                sample_entry(name, 443, "").addr().is_err(),
                "{name:?} was accepted as an address"
            );
        }
    }

    #[test]
    fn canonical_form_reduces_a_mapped_address_and_leaves_others_alone() {
        let mapped: std::net::IpAddr = "::ffff:10.1.0.1".parse().unwrap();
        let plain: std::net::IpAddr = "10.1.0.1".parse().unwrap();
        let real_v6: std::net::IpAddr = "2001:db8::1".parse().unwrap();

        assert_eq!(
            canonical_ip(mapped),
            plain,
            "a mapped address reduces to IPv4"
        );
        assert_eq!(canonical_ip(plain), plain, "plain IPv4 is unchanged");
        assert_eq!(
            canonical_ip(real_v6),
            real_v6,
            "a genuine IPv6 is unchanged"
        );
        assert_ne!(mapped, plain, "the two spellings differ before reduction");
    }

    #[test]
    fn an_entry_address_is_canonical_in_both_spellings() {
        let want: std::net::IpAddr = "10.1.0.1".parse().unwrap();
        for spelling in ["10.1.0.1", "::ffff:10.1.0.1"] {
            let e = sample_entry(spelling, 443, &"ab".repeat(STATIC_KEY_LEN));
            assert_eq!(e.ip_addr().unwrap(), want, "{spelling} did not reduce");
            assert_eq!(
                e.addr().unwrap(),
                "10.1.0.1:443".parse::<std::net::SocketAddr>().unwrap(),
                "{spelling} did not reduce in addr()"
            );
        }
    }

    #[test]
    fn canonical_addr_keeps_the_port() {
        let a: std::net::SocketAddr = "[::ffff:10.1.0.1]:8443".parse().unwrap();
        assert_eq!(
            canonical_addr(a),
            "10.1.0.1:8443".parse::<std::net::SocketAddr>().unwrap()
        );
    }

    #[test]
    fn addr_refuses_port_zero() {
        assert!(sample_entry("10.0.0.1", 0, "").addr().is_err());
    }

    #[test]
    fn static_key_decodes_exactly_32_bytes() {
        let key = "ab".repeat(STATIC_KEY_LEN);
        assert_eq!(
            sample_entry("10.0.0.1", 443, &key).static_key().unwrap(),
            [0xABu8; STATIC_KEY_LEN]
        );
    }

    #[test]
    fn static_key_rejects_wrong_length_and_bad_hex() {
        for bad in [
            "ab".repeat(STATIC_KEY_LEN - 1),
            "zz".repeat(STATIC_KEY_LEN),
            "abc".to_string(),
        ] {
            assert!(
                sample_entry("10.0.0.1", 443, &bad).static_key().is_err(),
                "{bad} was accepted"
            );
        }
    }

    /// authority must verify here. The vector is read from the shared testdata
    /// file that the Go suite also verifies.
    #[test]
    fn the_committed_go_vector_verifies() {
        let raw = std::fs::read("../testdata/registry_vector.json").expect("read vector");
        let v: serde_json::Value = serde_json::from_slice(&raw).expect("parse vector");
        assert_eq!(v["domain"].as_str().unwrap().as_bytes(), DOMAIN);

        let pub_hex = v["public_key"].as_str().unwrap();
        let pin = PinnedKey::from_hex(pub_hex).expect("pinned key");
        assert_eq!(pin.key_id, v["key_id"].as_str().unwrap());

        let document = B64
            .decode(v["document_b64"].as_str().unwrap())
            .expect("document base64");
        let sig = B64
            .decode(v["signature_b64"].as_str().unwrap())
            .expect("signature base64");
        let fixed = <[u8; SIGNATURE_LENGTH]>::try_from(sig.as_slice()).expect("64 byte signature");
        pin.key
            .verify_strict(&signed_message(&document), &Signature::from_bytes(&fixed))
            .expect("the Go-signed vector must verify in Rust");

        // Control: the same signature must fail over altered bytes.
        let mut altered = document.clone();
        altered[0] ^= 0x01;
        assert!(pin
            .key
            .verify_strict(&signed_message(&altered), &Signature::from_bytes(&fixed))
            .is_err());
    }

    /// RFC 8032 section 7.1 vectors, public key, message and signature only.
    /// These exercise the primitive, so they use verify_strict directly rather
    /// than the registry wrapper, which adds domain separation.
    #[test]
    fn rfc8032_vectors_verify() {
        let raw = std::fs::read("../testdata/ed25519_rfc8032.json").expect("read vectors");
        let v: serde_json::Value = serde_json::from_slice(&raw).expect("parse vectors");
        let vectors = v["vectors"].as_array().expect("vectors array");
        assert!(
            !vectors.is_empty(),
            "no vectors loaded, so this test would pass vacuously"
        );
        for vec in vectors {
            let name = vec["name"].as_str().unwrap();
            let key = PinnedKey::from_hex(vec["public_key"].as_str().unwrap())
                .unwrap_or_else(|e| panic!("{name}: public key: {e}"));
            let msg = hex_to_bytes(vec["message"].as_str().unwrap()).expect("message hex");
            let sig = hex_to_bytes(vec["signature"].as_str().unwrap()).expect("signature hex");
            let fixed = <[u8; SIGNATURE_LENGTH]>::try_from(sig.as_slice()).expect("64 bytes");
            key.key
                .verify_strict(&msg, &Signature::from_bytes(&fixed))
                .unwrap_or_else(|e| panic!("{name} did not verify: {e}"));

            // Control: a corrupted signature must fail, so a verifier that
            // accepted everything could not pass this test.
            let mut bad = fixed;
            bad[0] ^= 0x01;
            assert!(
                key.key
                    .verify_strict(&msg, &Signature::from_bytes(&bad))
                    .is_err(),
                "{name} verified with a corrupted signature"
            );
        }
    }

    fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
        if !s.len().is_multiple_of(2) {
            return None;
        }
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(s.len() / 2);
        for pair in b.chunks(2) {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
        }
        Some(out)
    }
}

/// Exhaustive check of the hand-written date conversion.
///
/// `parse_rfc3339` and `days_from_civil` are arithmetic written by hand, so
/// spot checks prove little. These tests walk every day in range against a
/// reference built the other way round: a counter that starts at the epoch and
/// adds one day at a time, tracking month lengths and leap years explicitly.
/// It shares no code with production, so the two have to agree by being right
/// rather than by being the same function.
#[cfg(test)]
mod date_tests {
    use super::{parse_rfc3339, RegistryError};

    const FIRST_YEAR: i64 = 1970;
    const LAST_YEAR: i64 = 2100;

    /// Reference leap rule, written independently of `is_leap_year`.
    fn ref_is_leap(y: i64) -> bool {
        if y % 400 == 0 {
            return true;
        }
        if y % 100 == 0 {
            return false;
        }
        y % 4 == 0
    }

    /// Reference month lengths, written independently of `days_in_month`.
    fn ref_month_len(y: i64, m: i64) -> i64 {
        const LENGTHS: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let base = LENGTHS[(m - 1) as usize];
        if m == 2 && ref_is_leap(y) {
            base + 1
        } else {
            base
        }
    }

    /// Every (year, month, day, unix-midnight) in range, counted forward from
    /// the epoch one day at a time.
    fn reference_days() -> Vec<(i64, i64, i64, i64)> {
        let mut out = Vec::with_capacity(48_000);
        let mut secs: i64 = 0;
        for y in FIRST_YEAR..=LAST_YEAR {
            for m in 1..=12 {
                for d in 1..=ref_month_len(y, m) {
                    out.push((y, m, d, secs));
                    secs += 86_400;
                }
            }
        }
        out
    }

    #[test]
    fn reference_counter_is_internally_consistent() {
        // Guard the reference itself before trusting it as an oracle.
        let days = reference_days();
        assert_eq!(
            days.first().unwrap(),
            &(1970, 1, 1, 0),
            "epoch must be day zero"
        );
        assert_eq!(
            days.last().unwrap().0,
            LAST_YEAR,
            "the walk must reach the last year"
        );
        assert_eq!(days.last().unwrap().1, 12);
        assert_eq!(days.last().unwrap().2, 31);
        // Consecutive entries are exactly one day apart, with no gap or repeat.
        for pair in days.windows(2) {
            assert_eq!(
                pair[1].3 - pair[0].3,
                86_400,
                "gap between {:?} and {:?}",
                pair[0],
                pair[1]
            );
        }
        // 1970 to 2100 inclusive holds 32 leap years in the Gregorian calendar,
        // counted here rather than asserted from memory.
        let leaps = (FIRST_YEAR..=LAST_YEAR).filter(|y| ref_is_leap(*y)).count();
        assert_eq!(days.len() as i64, 365 * 131 + leaps as i64);
        assert!(
            !ref_is_leap(2100),
            "2100 is a century that is not a leap year"
        );
        assert!(ref_is_leap(2000), "2000 is divisible by 400");
    }

    #[test]
    fn every_day_round_trips_at_midnight_and_last_second() {
        let days = reference_days();
        assert!(days.len() > 47_000, "only {} days generated", days.len());

        for (y, m, d, midnight) in days {
            let at_midnight = format!("{y:04}-{m:02}-{d:02}T00:00:00Z");
            match parse_rfc3339(&at_midnight) {
                Ok(got) => assert_eq!(got, midnight, "{at_midnight} parsed to the wrong instant"),
                Err(e) => panic!("{at_midnight} was rejected: {e}"),
            }

            let at_end = format!("{y:04}-{m:02}-{d:02}T23:59:59Z");
            let want = midnight + 23 * 3600 + 59 * 60 + 59;
            match parse_rfc3339(&at_end) {
                Ok(got) => assert_eq!(got, want, "{at_end} parsed to the wrong instant"),
                Err(e) => panic!("{at_end} was rejected: {e}"),
            }
        }
    }

    #[test]
    fn impossible_dates_are_rejected() {
        for s in [
            "2026-02-29T00:00:00Z", // 2026 is not a leap year
            "2100-02-29T00:00:00Z", // century, not a leap year
            "2026-04-31T00:00:00Z", // April has 30 days
            "2026-13-01T00:00:00Z", // no thirteenth month
            "2026-00-10T00:00:00Z", // no zeroth month
        ] {
            assert!(
                matches!(parse_rfc3339(s), Err(RegistryError::Registry(_))),
                "{s} was accepted"
            );
        }
    }

    #[test]
    fn real_leap_days_are_accepted() {
        for s in ["2000-02-29T00:00:00Z", "2024-02-29T00:00:00Z"] {
            assert!(parse_rfc3339(s).is_ok(), "{s} was rejected");
        }
    }

    #[test]
    fn day_zero_and_month_zero_are_rejected_in_every_month() {
        for m in 1..=12 {
            let s = format!("2026-{m:02}-00T00:00:00Z");
            assert!(parse_rfc3339(&s).is_err(), "{s} was accepted");
        }
    }

    #[test]
    fn one_past_the_end_of_every_month_is_rejected() {
        // The complement of the round-trip test: the first day that does not
        // exist in each month. The years cover a leap year, a common year, a
        // century that is not a leap year and a century that is, so the whole
        // leap rule is exercised rather than only its common case.
        for y in [2024, 2026, 2100, 2000] {
            for m in 1..=12 {
                let past = ref_month_len(y, m) + 1;
                if past > 31 {
                    continue; // cannot be expressed in two digits as a real day
                }
                let s = format!("{y:04}-{m:02}-{past:02}T00:00:00Z");
                assert!(
                    parse_rfc3339(&s).is_err(),
                    "{s} was accepted but {m:02} has {} days",
                    ref_month_len(y, m)
                );
            }
        }
    }
}
