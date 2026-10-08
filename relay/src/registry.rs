//! The verified registry as the relay consumes it.
//!
//! Both ends of a relay link are decided here rather than by configuration
//! (ARCHITECTURE §5.5). An inbound relay link is accepted only from an address
//! the registry lists with the role directly upstream, and an EXTEND is refused
//! unless the registry carries the next hop with the role directly downstream at
//! exactly that address and port. The facts used to live in
//! RELAY_PEER_ALLOWLIST and PEER_HOSTNAMES, which no signature covered.
//!
//! Readers take a snapshot: they clone an `Arc` under a short synchronous lock
//! and release it immediately, so no lock is ever held across an await
//! (ARCHITECTURE §5.4, §5.5).

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};

use quiethop_crypto::registry::{canonical_addr, canonical_ip, RelayEntry, Verified};

use crate::config::Role;

/// Shared holder for the current verified document.
///
/// Empty until the first document is published, which production does before
/// binding the listener, so a relay never serves without a verified registry.
#[derive(Clone, Default)]
pub struct RegistryHandle {
    current: Arc<RwLock<Option<Arc<Verified>>>>,
}

impl RegistryHandle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn publish(&self, verified: Arc<Verified>) {
        // A poisoned lock means a reader panicked while holding it. Replacing
        // the value is still correct, and refusing to publish would strand the
        // relay on an old document, so the poison is cleared rather than
        // propagated.
        match self.current.write() {
            Ok(mut slot) => *slot = Some(verified),
            Err(poisoned) => *poisoned.into_inner() = Some(verified),
        }
    }

    /// The current document when it may be used at `now_unix`, else `None`.
    ///
    /// This is the fail-closed point for the relay. A refresh that keeps failing
    /// leaves the last verified document in the handle, and it stays in service
    /// until its own valid_until with no grace period, after which this returns
    /// `None` and every consumer refuses (ARCHITECTURE 5.5).
    ///
    /// Three conditions all read as `None`, so none of them can be mistaken for
    /// permission: nothing published yet, a poisoned lock, and a document whose
    /// timestamps do not parse or have passed.
    pub fn usable(&self, now_unix: i64) -> Option<Arc<Verified>> {
        let current = self.current.read().ok()?.clone()?;
        match current.document.is_usable_at(now_unix) {
            Ok(true) => Some(current),
            _ => None,
        }
    }
}

/// The role directly upstream, the only one that may open an inbound relay link.
///
/// A guard has none: it accepts client connections, never relay-protocol
/// inbound, so no address is admitted for it at all.
pub fn upstream_role(role: Role) -> Option<&'static str> {
    match role {
        Role::Guard => None,
        Role::Middle => Some("guard"),
        Role::Exit => Some("middle"),
    }
}

/// The role directly downstream, the only one this relay may extend to.
pub fn downstream_role(role: Role) -> Option<&'static str> {
    match role {
        Role::Guard => Some("middle"),
        Role::Middle => Some("exit"),
        Role::Exit => None,
    }
}

/// Whether `peer` may open an inbound relay link to a relay in `role`.
///
/// Matches on address only, not port, because the peer's source port is
/// ephemeral and is not the port the registry publishes for it.
pub fn admits_inbound(doc: &Verified, role: Role, peer: IpAddr) -> bool {
    let Some(want) = upstream_role(role) else {
        return false;
    };
    // Both sides canonical. A dual-stack listener reports an IPv4 peer as
    // ::ffff:a.b.c.d, and a registry entry may carry either spelling, so
    // comparing as written refuses a peer the registry does list.
    let peer = canonical_ip(peer);
    doc.document
        .relays
        .iter()
        .any(|e| e.role == want && e.ip_addr().is_ok_and(|ip| ip == peer))
}

/// The registry entry for an EXTEND target, or `None` when it is not a
/// permitted next hop.
///
/// Address and port must both match the published entry, so a peer cannot be
/// reached on a port the authority did not publish for it.
pub fn extend_target(doc: &Verified, role: Role, next: SocketAddr) -> Option<&RelayEntry> {
    let want = downstream_role(role)?;
    // RelayEntry::addr is canonical and the EXTEND cell already decodes a mapped
    // address to IPv4, but the caller's value is reduced here too so the match
    // does not depend on where it came from.
    let next = canonical_addr(next);
    doc.document
        .relays
        .iter()
        .find(|e| e.role == want && e.addr().is_ok_and(|a| a == next))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quiethop_crypto::registry::Document;

    fn entry(id: &str, role: &str, ip: &str, port: u16) -> RelayEntry {
        RelayEntry {
            id: id.into(),
            operator_id: "op".into(),
            host_id: id.into(),
            role: role.into(),
            ip: ip.into(),
            port,
            tls_name: format!("{id}.example"),
            static_pubkey: "ab".repeat(32),
        }
    }

    fn verified() -> Verified {
        Verified {
            document: Document {
                version: 1,
                valid_after: "2026-10-08T14:00:00Z".into(),
                fresh_until: "2026-10-08T15:00:00Z".into(),
                valid_until: "2026-10-08T20:00:00Z".into(),
                relays: vec![
                    entry("g", "guard", "10.1.0.1", 443),
                    entry("m", "middle", "10.2.0.1", 443),
                    entry("e", "exit", "10.3.0.1", 443),
                ],
            },
            bytes: Vec::new(),
            key_ids: Vec::new(),
        }
    }

    #[test]
    fn roles_are_adjacent_in_one_direction_only() {
        assert_eq!(upstream_role(Role::Guard), None);
        assert_eq!(upstream_role(Role::Middle), Some("guard"));
        assert_eq!(upstream_role(Role::Exit), Some("middle"));
        assert_eq!(downstream_role(Role::Guard), Some("middle"));
        assert_eq!(downstream_role(Role::Middle), Some("exit"));
        assert_eq!(downstream_role(Role::Exit), None);
    }

    #[test]
    fn inbound_is_admitted_only_from_the_upstream_role() {
        let d = verified();
        let guard_ip: IpAddr = "10.1.0.1".parse().unwrap();
        let middle_ip: IpAddr = "10.2.0.1".parse().unwrap();
        let exit_ip: IpAddr = "10.3.0.1".parse().unwrap();

        assert!(
            admits_inbound(&d, Role::Middle, guard_ip),
            "guard reaches middle"
        );
        assert!(
            admits_inbound(&d, Role::Exit, middle_ip),
            "middle reaches exit"
        );

        // The wrong direction, the wrong role and an unlisted address are all refused.
        assert!(!admits_inbound(&d, Role::Middle, exit_ip));
        assert!(!admits_inbound(&d, Role::Exit, guard_ip));
        assert!(!admits_inbound(
            &d,
            Role::Middle,
            "198.51.100.9".parse().unwrap()
        ));
        // A guard accepts no relay-protocol inbound at all.
        assert!(!admits_inbound(&d, Role::Guard, middle_ip));
    }

    #[test]
    fn an_extend_target_must_match_role_address_and_port() {
        let d = verified();
        let middle: SocketAddr = "10.2.0.1:443".parse().unwrap();
        assert_eq!(
            extend_target(&d, Role::Guard, middle).map(|e| e.id.as_str()),
            Some("m")
        );
        assert_eq!(
            extend_target(&d, Role::Middle, "10.3.0.1:443".parse().unwrap()).map(|e| e.id.as_str()),
            Some("e")
        );
        // Right relay, wrong port.
        assert!(extend_target(&d, Role::Guard, "10.2.0.1:8443".parse().unwrap()).is_none());
        // Listed relay, wrong role for this hop.
        assert!(extend_target(&d, Role::Guard, "10.3.0.1:443".parse().unwrap()).is_none());
        // Not in the registry at all.
        assert!(extend_target(&d, Role::Guard, "198.51.100.9:443".parse().unwrap()).is_none());
        // An exit extends to nothing.
        assert!(extend_target(&d, Role::Exit, middle).is_none());
    }

    /// A dual-stack listener reports an IPv4 peer as ::ffff:a.b.c.d. That peer
    /// must be admitted when the registry lists a.b.c.d for the upstream role,
    /// and the reverse spelling must work too, because either side may carry
    /// either form.
    #[test]
    fn a_mapped_peer_matches_a_plain_registry_entry() {
        let d = verified();
        let mapped: IpAddr = "::ffff:10.1.0.1".parse().unwrap();
        assert!(
            admits_inbound(&d, Role::Middle, mapped),
            "a mapped form of the listed guard address must be admitted"
        );

        // Control: a mapped address that is not listed is still refused, so the
        // reduction has not turned the check into an accept-everything.
        let unlisted: IpAddr = "::ffff:198.51.100.7".parse().unwrap();
        assert!(!admits_inbound(&d, Role::Middle, unlisted));
    }

    #[test]
    fn a_plain_peer_matches_a_mapped_registry_entry() {
        let mut d = verified();
        for e in d.document.relays.iter_mut() {
            if e.role == "guard" {
                e.ip = "::ffff:10.1.0.1".to_string();
            }
        }
        let plain: IpAddr = "10.1.0.1".parse().unwrap();
        assert!(
            admits_inbound(&d, Role::Middle, plain),
            "a plain peer must match a mapped entry"
        );
        // Control: the role still has to be the upstream one.
        assert!(!admits_inbound(&d, Role::Exit, plain));
    }

    /// An EXTEND naming [::ffff:a.b.c.d]:port must match the registry entry
    /// a.b.c.d:port, with the port still compared exactly.
    #[test]
    fn a_mapped_extend_target_matches_a_plain_entry() {
        let d = verified();
        let mapped: SocketAddr = "[::ffff:10.2.0.1]:443".parse().unwrap();
        assert_eq!(
            extend_target(&d, Role::Guard, mapped).map(|e| e.id.as_str()),
            Some("m"),
            "the mapped spelling of the listed middle must match"
        );

        // Control: the port is still exact, so the reduction has not loosened
        // the address match into a host-only match.
        let wrong_port: SocketAddr = "[::ffff:10.2.0.1]:8443".parse().unwrap();
        assert!(extend_target(&d, Role::Guard, wrong_port).is_none());

        // Control: the role is still checked.
        let exit_mapped: SocketAddr = "[::ffff:10.3.0.1]:443".parse().unwrap();
        assert!(extend_target(&d, Role::Guard, exit_mapped).is_none());
    }

    #[test]
    fn a_plain_extend_target_matches_a_mapped_entry() {
        let mut d = verified();
        for e in d.document.relays.iter_mut() {
            if e.role == "middle" {
                e.ip = "::ffff:10.2.0.1".to_string();
            }
        }
        let plain: SocketAddr = "10.2.0.1:443".parse().unwrap();
        assert_eq!(
            extend_target(&d, Role::Guard, plain).map(|e| e.id.as_str()),
            Some("m")
        );
        assert!(extend_target(&d, Role::Guard, "10.2.0.1:8443".parse().unwrap()).is_none());
    }

    /// 2026-10-08T14:00:00Z, inside the window the fixture declares.
    const INSIDE: i64 = 1_791_468_060;
    /// 2026-10-08T20:00:00Z, exactly valid_until, where there is no grace.
    const AT_EXPIRY: i64 = 1_791_489_600;

    #[test]
    fn a_handle_with_nothing_published_reads_as_absent() {
        let h = RegistryHandle::new();
        assert!(
            h.usable(INSIDE).is_none(),
            "an empty handle must fail closed"
        );
        h.publish(Arc::new(verified()));
        assert!(h.usable(INSIDE).is_some());
    }

    /// The document stays in the handle after it expires, and must stop being
    /// served at valid_until rather than being served because it is present.
    #[test]
    fn a_published_document_stops_being_usable_at_valid_until() {
        let h = RegistryHandle::new();
        h.publish(Arc::new(verified()));
        assert!(
            h.usable(AT_EXPIRY - 1).is_some(),
            "one second before expiry"
        );
        assert!(
            h.usable(AT_EXPIRY).is_none(),
            "no grace period at valid_until"
        );
        assert!(h.usable(AT_EXPIRY + 86_400).is_none());
    }

    /// A document whose timestamps cannot be parsed must fail closed rather than
    /// be treated as always valid.
    #[test]
    fn an_unparseable_window_fails_closed() {
        let mut v = verified();
        v.document.valid_until = "not a timestamp".to_string();
        let h = RegistryHandle::new();
        h.publish(Arc::new(v));
        assert!(h.usable(INSIDE).is_none());
    }
}
