// Static 1:1 NAT table — bidirectional internal↔external mapping.

use super::NatDecision;
use crate::StaticNATRuleSnapshot;
use rustc_hash::FxHashMap;
use std::net::IpAddr;

/// Static 1:1 NAT entry (bidirectional).
#[derive(Clone, Debug)]
pub(crate) struct StaticNatEntry {
    pub(crate) external_ip: IpAddr,
    pub(crate) internal_ip: IpAddr,
    pub(crate) from_zone: String,
}

/// Lookup table for static NAT -- indexed by IP for O(1) matching.
#[derive(Clone, Debug, Default)]
pub(crate) struct StaticNatTable {
    /// external_ip -> entry (for inbound DNAT)
    dnat: FxHashMap<IpAddr, StaticNatEntry>,
    /// internal_ip -> entry (for outbound SNAT)
    snat: FxHashMap<IpAddr, StaticNatEntry>,
}

/// Parse a static-NAT address that may carry a canonical host mask
/// (`x.x.x.x/32`, `addr/128`). Junos emits static-NAT match/then in
/// canonical prefix form, and the Go compiler copies that mask verbatim
/// into the snapshot; `IpAddr::from_str` REJECTS CIDR notation, so the mask
/// must be stripped before the parse or the rule is silently dropped (#2122).
///
/// Static NAT is an exact `IpAddr -> IpAddr` 1:1 mapping, so the ONLY
/// meaningful mask is the host mask. We accept a bare address or a host mask
/// (`/32` for v4, `/128` for v6) and reject any other suffix — a non-host
/// prefix (`/24`), a non-numeric mask, a trailing/empty/double slash etc.
/// would silently translate the wrong scope, so it is a misconfiguration to
/// surface (skip), not to coerce to a host route. A genuinely-malformed
/// address likewise returns `None`, preserving the caller's skip-on-invalid
/// behavior.
fn parse_nat_addr(s: &str) -> Option<IpAddr> {
    let mut parts = s.splitn(2, '/');
    let addr: IpAddr = parts.next()?.parse().ok()?;
    match parts.next() {
        // Bare address — no mask.
        None => Some(addr),
        // Host mask only: /32 for v4, /128 for v6. Anything else is rejected.
        Some(mask) => {
            let host_len = match addr {
                IpAddr::V4(_) => "32",
                IpAddr::V6(_) => "128",
            };
            if mask == host_len { Some(addr) } else { None }
        }
    }
}

impl StaticNatTable {
    pub(crate) fn from_snapshots(snaps: &[StaticNATRuleSnapshot]) -> Self {
        let mut table = StaticNatTable::default();
        for snap in snaps {
            let external_ip: IpAddr = match parse_nat_addr(&snap.external_ip) {
                Some(ip) => ip,
                None => continue,
            };
            let internal_ip: IpAddr = match parse_nat_addr(&snap.internal_ip) {
                Some(ip) => ip,
                None => continue,
            };
            let entry = StaticNatEntry {
                external_ip,
                internal_ip,
                from_zone: snap.from_zone.clone(),
            };
            table.dnat.insert(external_ip, entry.clone());
            table.snat.insert(internal_ip, entry);
        }
        table
    }

    /// Match inbound: if dst_ip is an external IP, return DNAT decision.
    pub(crate) fn match_dnat(&self, dst_ip: IpAddr, ingress_zone: &str) -> Option<NatDecision> {
        let entry = self.dnat.get(&dst_ip)?;
        if !entry.from_zone.is_empty() && entry.from_zone != ingress_zone {
            return None;
        }
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some(entry.internal_ip),
            ..NatDecision::default()
        })
    }

    /// Match outbound: if src_ip is an internal IP, return SNAT decision.
    ///
    /// Note: from_zone is NOT checked for SNAT. The zone constraint on the
    /// static NAT rule set (`from zone X`) controls which ingress zone
    /// triggers DNAT only. For SNAT (outbound), the internal IP match is
    /// sufficient -- the traffic originates from the internal host regardless
    /// of which zone it enters through.
    pub(crate) fn match_snat(&self, src_ip: IpAddr, _ingress_zone: &str) -> Option<NatDecision> {
        let entry = self.snat.get(&src_ip)?;
        Some(NatDecision {
            rewrite_src: Some(entry.external_ip),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    }

    /// Returns true if the table has any entries.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.dnat.is_empty()
    }

    /// Returns all external IPs (for local delivery recognition).
    pub(crate) fn external_ips(&self) -> impl Iterator<Item = &IpAddr> {
        self.dnat.keys()
    }
}
