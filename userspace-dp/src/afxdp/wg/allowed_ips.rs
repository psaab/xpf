//! AllowedIPs LPM table.
//!
//! WireGuard's AllowedIPs is a longest-prefix-match table from
//! `IpAddr → peer`. It is used by the WG reference implementation
//! for **both** directions, and xpf uses it for both too:
//!
//! - Outbound (encap): pick which peer to encrypt to from the inner
//!   dst IP — `WgEngine::peer_for_dest` (transit encap in
//!   `frame/wg.rs`, the TUN-read fallback in `wg_control`, and the
//!   per-peer underlay selection for PTB / TCP-segmentation /
//!   dispatch-egress sizing that must agree with the encap peer).
//! - Inbound (decap): verify the decrypted inner src IP globally
//!   resolves to the peer whose key decrypted the packet
//!   (`AllowedIps::matches_for_peer`, WG spec §5.4.6).
//!
//! Because the global LPM decides both directions, overlapping
//! AllowedIPs across peers can never authorise plaintext for the
//! wrong session: the most specific covering prefix wins, and only
//! its owner may send from (decap) or receive to (encap) an address
//! inside it. `try_encap` still takes an explicit peer pubkey from
//! the caller; the LPM is the peer-SELECTION step in front of it.
//!
//! Implementation (#15250, A69-03): per-family, prefix-length-
//! bucketed hash maps. Each family keeps one hash map per possible
//! prefix length (33 for IPv4, 129 for IPv6), keyed by the masked
//! network address at that length. A lookup masks the query address
//! at each length from longest to shortest and probes the map —
//! at most 33 (v4) / 129 (v6) hash probes, each independent of the
//! number of configured peers or prefixes. The previous flat list
//! sorted by prefix length scanned every entry of BOTH families
//! per packet (up to one comparison per configured prefix), so
//! lookup cost grew linearly with the peer/prefix count on every
//! decap source gate and every encap peer selection.
//!
//! The table is rebuilt at config-commit time (`reconcile_peers`)
//! and published inside the engine's atomic `PeerTable` snapshot,
//! so lookups never allocate and never lock. Hash iteration order
//! is never observed: probing is by exact masked key, longest
//! length first, so the result is deterministic. Duplicate
//! `(prefix, peer)` inserts are idempotent; for an identical
//! `(prefix)` claimed by two peers the FIRST inserter wins
//! (stable, matching the old stable-sort tie-break) and the loser
//! authoritatively owns nothing inside it.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Prefix lengths 0..=32 (IPv4).
const V4_BUCKETS: usize = 33;
/// Prefix lengths 0..=128 (IPv6).
const V6_BUCKETS: usize = 129;

/// One family's length-bucketed LPM index.
///
/// `buckets[len]` maps the masked network address (as an integer
/// with host bits zeroed) at prefix length `len` to the owning
/// peer index. Lookup probes lengths from longest to shortest, so
/// the first hit is the longest-prefix match.
#[derive(Debug, Clone)]
struct FamilyLpm<const N: usize, K> {
    buckets: Vec<HashMap<K, u32>>,
}

impl<const N: usize, K: Eq + std::hash::Hash> Default for FamilyLpm<N, K> {
    fn default() -> Self {
        Self {
            buckets: (0..N).map(|_| HashMap::new()).collect(),
        }
    }
}

impl<const N: usize, K: Eq + std::hash::Hash> FamilyLpm<N, K> {
    fn insert(&mut self, masked_key: K, prefix_len: u8, peer_index: u32) {
        // First inserter wins an exact (prefix) tie: reconciliation
        // inserts peers in table order, so the earliest configured
        // peer keeps a duplicated prefix (the old flat list's
        // stable-sort tie-break). A re-insert for the SAME peer is
        // the same value, hence idempotent.
        self.buckets[prefix_len as usize]
            .entry(masked_key)
            .or_insert(peer_index);
    }

    fn remove_peer(&mut self, peer_index: u32) {
        for bucket in &mut self.buckets {
            bucket.retain(|_, owner| *owner != peer_index);
        }
    }
}

impl FamilyLpm<V4_BUCKETS, u32> {
    fn lookup(&self, ip: Ipv4Addr) -> Option<u32> {
        let addr = u32::from(ip);
        for len in (0..V4_BUCKETS).rev() {
            let bucket = &self.buckets[len];
            if bucket.is_empty() {
                continue;
            }
            let masked = if len == 0 {
                0
            } else {
                addr & (u32::MAX << (32 - len))
            };
            if let Some(&peer) = bucket.get(&masked) {
                return Some(peer);
            }
        }
        None
    }
}

impl FamilyLpm<V6_BUCKETS, u128> {
    fn lookup(&self, ip: Ipv6Addr) -> Option<u32> {
        let addr = u128::from(ip);
        for len in (0..V6_BUCKETS).rev() {
            let bucket = &self.buckets[len];
            if bucket.is_empty() {
                continue;
            }
            let masked = if len == 0 {
                0
            } else {
                addr & (u128::MAX << (128 - len))
            };
            if let Some(&peer) = bucket.get(&masked) {
                return Some(peer);
            }
        }
        None
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct AllowedIps {
    /// Per-family LPM indexes. A v4 query never touches v6 state
    /// and vice versa (the old flat list interleaved both families
    /// in one scan).
    ///
    /// `matches_for_peer` is a global LPM lookup followed by a
    /// peer-identity compare, because WG cryptokey routing
    /// requires the global LPM semantic (see the `matches_for_peer`
    /// doc for details). A per-peer "is the address covered by any
    /// of this peer's prefixes" check is incorrect by construction
    /// against overlapping cross-peer prefixes and must not be
    /// reintroduced.
    v4: FamilyLpm<V4_BUCKETS, u32>,
    v6: FamilyLpm<V6_BUCKETS, u128>,
}

impl AllowedIps {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Insert a CIDR for a peer. Slow path only (config commit).
    pub(crate) fn insert(&mut self, cidr: ipnet::IpNet, peer_index: u32) {
        match cidr {
            ipnet::IpNet::V4(net) => {
                let masked = u32::from(net.network());
                self.v4.insert(masked, net.prefix_len(), peer_index);
            }
            ipnet::IpNet::V6(net) => {
                let masked = u128::from(net.network());
                self.v6.insert(masked, net.prefix_len(), peer_index);
            }
        }
    }

    /// Remove every entry for a peer. Used when the peer is dropped
    /// from the config snapshot.
    pub(crate) fn remove_peer(&mut self, peer_index: u32) {
        self.v4.remove_peer(peer_index);
        self.v6.remove_peer(peer_index);
    }

    /// Longest-prefix-match lookup. Returns the peer_index of the
    /// most specific covering prefix, or `None` if no entry covers
    /// `addr`. Cost is bounded by the family's prefix-length count
    /// (33 / 129 hash probes), independent of table size.
    pub(crate) fn lookup(&self, addr: IpAddr) -> Option<u32> {
        match addr {
            IpAddr::V4(ip) => self.v4.lookup(ip),
            IpAddr::V6(ip) => self.v6.lookup(ip),
        }
    }

    /// Cryptokey-routing gate used on decap: after we know which
    /// peer decrypted the packet, verify that a global LPM lookup of
    /// the inner src IP across the entire AllowedIPs table resolves
    /// to that same peer.
    ///
    /// WG spec §5.4.6 requires the global LPM semantic, NOT a
    /// per-peer "is the address covered by any of this peer's
    /// prefixes" check. The distinction matters when AllowedIPs
    /// overlap across peers: e.g. peer A owns `10.0.0.0/8` and peer
    /// B owns `10.1.1.0/24`. A packet authenticated by A with inner
    /// src `10.1.1.5` must be dropped, because the global LPM
    /// resolves `10.1.1.5` to B's more-specific /24 — even though
    /// A's /8 also covers it. The per-peer-only check (which an
    /// earlier r4 revision implemented) silently violated this and
    /// allowed A to spoof source addresses inside B's prefix.
    ///
    /// Returns true iff `lookup(addr) == Some(peer_index)`.
    pub(crate) fn matches_for_peer(&self, addr: IpAddr, peer_index: u32) -> bool {
        self.lookup(addr) == Some(peer_index)
    }

    /// Test-only: number of stored prefixes (exact-match keys)
    /// across both families.
    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        self.v4.buckets.iter().map(HashMap::len).sum::<usize>()
            + self.v6.buckets.iter().map(HashMap::len).sum::<usize>()
    }
}

#[cfg(test)]
mod allowed_ips_tests {
    use super::*;
    use std::str::FromStr;

    fn net(s: &str) -> ipnet::IpNet {
        ipnet::IpNet::from_str(s).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    #[test]
    fn longest_prefix_wins() {
        let mut t = AllowedIps::new();
        t.insert(net("10.0.0.0/8"), 1);
        t.insert(net("10.1.0.0/16"), 2);
        t.insert(net("10.1.2.0/24"), 3);
        assert_eq!(t.lookup(ip("10.1.2.5")), Some(3));
        assert_eq!(t.lookup(ip("10.1.3.5")), Some(2));
        assert_eq!(t.lookup(ip("10.2.0.5")), Some(1));
        assert_eq!(t.lookup(ip("11.0.0.0")), None);
    }

    #[test]
    fn ipv6_lookup() {
        let mut t = AllowedIps::new();
        t.insert(net("2001:db8::/32"), 1);
        t.insert(net("2001:db8:1::/48"), 2);
        assert_eq!(t.lookup(ip("2001:db8:1::1")), Some(2));
        assert_eq!(t.lookup(ip("2001:db8:2::1")), Some(1));
        assert_eq!(t.lookup(ip("2001:db9::1")), None);
    }

    #[test]
    fn matches_for_peer_rejects_wrong_peer() {
        // The core safety property: a peer's AllowedIPs gate must
        // reject inner src IPs that belong to a *different* peer.
        // This is what the inbound side relies on.
        let mut t = AllowedIps::new();
        t.insert(net("10.0.0.0/24"), 1);
        t.insert(net("10.0.1.0/24"), 2);
        assert!(t.matches_for_peer(ip("10.0.0.5"), 1));
        assert!(!t.matches_for_peer(ip("10.0.0.5"), 2));
        assert!(t.matches_for_peer(ip("10.0.1.5"), 2));
        assert!(!t.matches_for_peer(ip("10.0.1.5"), 1));
        // No matching prefix → reject for any peer.
        assert!(!t.matches_for_peer(ip("10.1.0.5"), 1));
    }

    /// Cryptokey routing: when peer A owns a less-specific prefix
    /// and peer B owns a more-specific one within it, an inner-src
    /// inside B's prefix that arrives over A's session MUST be
    /// rejected — the global LPM resolves to B, so A is not the
    /// authoritative owner. This is the WG §5.4.6 semantic.
    #[test]
    fn matches_for_peer_overlapping_lpm_picks_most_specific() {
        let mut t = AllowedIps::new();
        t.insert(net("10.0.0.0/8"), 1); // peer A owns 10/8
        t.insert(net("10.1.1.0/24"), 2); // peer B owns 10.1.1/24
        // 10.1.1.5 globally resolves to peer B; only B may
        // authoritatively use that source.
        assert!(!t.matches_for_peer(ip("10.1.1.5"), 1));
        assert!(t.matches_for_peer(ip("10.1.1.5"), 2));
        // 10.2.0.5 globally resolves to peer A; only A may use it.
        assert!(t.matches_for_peer(ip("10.2.0.5"), 1));
        assert!(!t.matches_for_peer(ip("10.2.0.5"), 2));
    }

    #[test]
    fn duplicate_insert_same_peer_is_idempotent() {
        let mut t = AllowedIps::new();
        t.insert(net("10.0.0.0/8"), 1);
        t.insert(net("10.0.0.0/8"), 1);
        assert_eq!(t.lookup(ip("10.1.1.1")), Some(1));
        assert_eq!(t.entry_count(), 1);
    }

    /// Cross-peer identical prefixes are a misconfiguration in WG
    /// cryptokey routing: only one peer can own a given address.
    /// The first inserter wins, and `matches_for_peer` reflects
    /// that — the loser cannot authoritatively use any address
    /// inside the prefix. This test pins the behavior so a future
    /// change can't accidentally return true for both peers.
    #[test]
    fn duplicate_cross_peer_prefix_only_one_peer_wins() {
        let mut t = AllowedIps::new();
        t.insert(net("10.0.0.0/8"), 1);
        t.insert(net("10.0.0.0/8"), 2);
        let winner = t.lookup(ip("10.1.1.1")).unwrap();
        assert_eq!(winner, 1, "first inserter wins the exact tie");
        assert!(t.matches_for_peer(ip("10.1.1.1"), winner));
        let loser = if winner == 1 { 2 } else { 1 };
        assert!(!t.matches_for_peer(ip("10.1.1.1"), loser));
    }

    #[test]
    fn remove_peer_clears_entries() {
        let mut t = AllowedIps::new();
        t.insert(net("10.0.0.0/8"), 1);
        t.insert(net("192.168.0.0/16"), 1);
        t.insert(net("172.16.0.0/12"), 2);
        t.remove_peer(1);
        assert_eq!(t.lookup(ip("10.1.1.1")), None);
        assert_eq!(t.lookup(ip("192.168.1.1")), None);
        assert_eq!(t.lookup(ip("172.16.1.1")), Some(2));
    }

    #[test]
    fn slash_zero_matches_everything() {
        let mut t = AllowedIps::new();
        t.insert(net("0.0.0.0/0"), 9);
        t.insert(net("10.0.0.0/8"), 1);
        // /8 wins for 10/8
        assert_eq!(t.lookup(ip("10.0.0.1")), Some(1));
        // /0 catches everything else
        assert_eq!(t.lookup(ip("8.8.8.8")), Some(9));
    }

    #[test]
    fn v6_slash_zero_and_host_route() {
        let mut t = AllowedIps::new();
        t.insert(net("::/0"), 9);
        t.insert(net("2001:db8::dead:beef/128"), 4);
        assert_eq!(t.lookup(ip("2001:db8::dead:beef")), Some(4));
        assert_eq!(t.lookup(ip("2001:db8::dead:beee")), Some(9));
        assert_eq!(t.lookup(ip("2001:db9::1")), Some(9));
        // Family isolation: the v6 /0 must not answer a v4 query.
        assert_eq!(t.lookup(ip("10.0.0.1")), None);
    }

    #[test]
    fn non_octet_boundary_prefixes() {
        let mut t = AllowedIps::new();
        t.insert(net("10.0.0.0/9"), 1);
        t.insert(net("10.128.0.0/9"), 2);
        t.insert(net("2001:db8:8000::/33"), 3);
        assert_eq!(t.lookup(ip("10.0.0.1")), Some(1));
        assert_eq!(t.lookup(ip("10.127.255.1")), Some(1));
        assert_eq!(t.lookup(ip("10.128.0.1")), Some(2));
        assert_eq!(t.lookup(ip("2001:db8:8000::1")), Some(3));
        assert_eq!(t.lookup(ip("2001:db8::1")), None);
    }

    /// #15250 (A69-03) regression: LPM correctness at hub scale.
    /// 1024 peers each own a distinct /24 under one peer's /8; every
    /// query — hit on the LAST-inserted prefix, hit on the /8
    /// remainder, v6 hit, and a miss — must resolve to the global
    /// longest-prefix owner. On the old flat list these answers were
    /// also correct but cost a scan of all 1025+ entries per query;
    /// the flat-cost side of the acceptance is the lookup-cost test
    /// in `engine_tests` (peer_for_dest at P=1024) and the bench in
    /// `benches/allowed_ips_lookup.rs`.
    #[test]
    fn lpm_at_1024_peer_scale() {
        let mut t = AllowedIps::new();
        t.insert(net("10.0.0.0/8"), 0);
        for i in 0..1024u32 {
            let cidr = format!("10.{}.{}.0/24", (i >> 8) & 0xff, i & 0xff);
            t.insert(net(&cidr), i + 1);
        }
        t.insert(net("2001:db8::/32"), 2000);
        for i in 0..256u32 {
            let cidr = format!("2001:db8:{i:x}::/48");
            t.insert(net(&cidr), 2001 + i);
        }
        // Last-inserted v4 /24 wins over the /8.
        assert_eq!(t.lookup(ip("10.3.255.7")), Some(1024));
        assert_eq!(t.lookup(ip("10.0.0.7")), Some(1));
        // Inside the /8 but outside every /24 → the /8 owner.
        assert_eq!(t.lookup(ip("10.9.9.9")), Some(0));
        // v6 most-specific wins; the v6 /32 owner keeps the rest.
        assert_eq!(t.lookup(ip("2001:db8:ff::1")), Some(2001 + 255));
        assert_eq!(t.lookup(ip("2001:db8:100::1")), Some(2000));
        assert_eq!(t.lookup(ip("2001:db9::1")), None);
        assert_eq!(t.lookup(ip("11.0.0.1")), None);
        // The decap gate at scale: only the /24 owner may source
        // from inside its /24; the /8 owner may not.
        assert!(t.matches_for_peer(ip("10.3.255.7"), 1024));
        assert!(!t.matches_for_peer(ip("10.3.255.7"), 0));
    }
}
