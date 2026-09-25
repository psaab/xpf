// Static 1:1 NAT table — bidirectional internal↔external mapping.

use super::{NatCounterStore, NatDecision, NatRuleCounter};
use super::destination::DnatTable;
use crate::StaticNATRuleSnapshot;
use crate::prefix::{PrefixV4, PrefixV6};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rustc_hash::FxHashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

/// #3435: parsed `match source-address` constraint for a static-NAT rule.
/// Mirrors the DNAT #2394 model. `constrained` records whether the rule HAD a
/// source-address list at all (snapshot non-empty), independent of how many
/// entries PARSED, so a scoped rule whose entries ALL failed to parse fails
/// CLOSED (matches no peer) instead of silently reverting to match-any (the
/// #3435 H01 fail-open). The inbound (DNAT) direction matches the packet
/// SOURCE against this constraint; the reverse (SNAT) direction matches the
/// packet DESTINATION (the original client).
#[derive(Clone, Debug, Default)]
struct SourceConstraint {
    constrained: bool,
    v4: Vec<PrefixV4>,
    v6: Vec<PrefixV6>,
}

impl SourceConstraint {
    /// Parse the snapshot's `source_addresses` list. Each entry is a CIDR
    /// prefix or a bare host IP (-> /32 / /128). `IpNet::from_str` rejects a
    /// bare IP, so fall back to `IpAddr` for that. An unparseable entry is
    /// skipped but still leaves `constrained = true` (fail-closed semantics).
    ///
    /// #5190: the skip is no longer SILENT. Fail-closed is correct — a
    /// scoped rule whose only entry is malformed must match nothing — but
    /// with no telemetry an operator sees a static-NAT rule that simply
    /// stopped matching and has nothing to look at. `nat_counters` +
    /// `rule_name` exist solely to name the offending rule in that
    /// diagnostic; they do not affect the parsed result.
    fn from_list(list: &[String], nat_counters: &NatCounterStore, rule_name: &str) -> Self {
        let constrained = !list.is_empty();
        let mut v4: Vec<PrefixV4> = Vec::new();
        let mut v6: Vec<PrefixV6> = Vec::new();
        for prefix in list {
            match prefix.parse::<IpNet>() {
                Ok(IpNet::V4(net)) => v4.push(PrefixV4::from_net(net)),
                Ok(IpNet::V6(net)) => v6.push(PrefixV6::from_net(net)),
                Err(_) => match prefix.parse::<IpAddr>() {
                    Ok(IpAddr::V4(a)) => {
                        if let Ok(net) = Ipv4Net::new(a, 32) {
                            v4.push(PrefixV4::from_net(net));
                        }
                    }
                    Ok(IpAddr::V6(a)) => {
                        if let Ok(net) = Ipv6Net::new(a, 128) {
                            v6.push(PrefixV6::from_net(net));
                        }
                    }
                    Err(_) => nat_counters.record_parse_error(&format!(
                        "static-NAT rule {rule_name:?}: unparseable match source-address \
                         {prefix:?} (entry dropped; rule stays source-scoped and fails closed)"
                    )),
                },
            }
        }
        Self { constrained, v4, v6 }
    }

    /// Does `peer` satisfy the constraint?
    /// - Unconstrained (no list): match any.
    /// - Constrained but no entry parsed: match NOTHING (fail closed).
    /// - Otherwise: `peer` must fall in one parsed prefix of its own family.
    fn matches(&self, peer: IpAddr) -> bool {
        if !self.constrained {
            return true;
        }
        if self.v4.is_empty() && self.v6.is_empty() {
            // Scoped but no entry parsed -> fail closed (the #3435 / #2394
            // fail-open guard).
            return false;
        }
        match peer {
            IpAddr::V4(v4) => self.v4.iter().any(|n| n.contains(v4)),
            IpAddr::V6(v6) => self.v6.iter().any(|n| n.contains(v6)),
        }
    }
}

/// #3435: evaluate a static-NAT entry's source-address constraint against the
/// candidate peer. `peer` is `None` only on the test / zone-only non-scoped
/// wrappers (which carry no peer IP); those paths skip the source gate. The
/// production transit path always supplies `Some(..)` via the `*_scoped`
/// variants — the inbound peer is the packet SOURCE, the reverse peer is the
/// packet DESTINATION.
#[inline]
fn source_ok(constraint: &SourceConstraint, peer: Option<IpAddr>) -> bool {
    match peer {
        Some(ip) => constraint.matches(ip),
        None => true,
    }
}

/// #3096: does a static-NAT rule's `from` scope (zone + interface +
/// routing-instance, each empty = wildcard) match the packet's context on the
/// relevant direction? All present constraints are AND-ed.
#[inline]
fn static_scope_ok(
    from_zone: &str,
    from_interface: &str,
    from_routing_instance: &str,
    zone: &str,
    ifname: &str,
    routing_instance: &str,
) -> bool {
    (from_zone.is_empty() || from_zone == zone)
        && (from_interface.is_empty() || from_interface == ifname)
        && (from_routing_instance.is_empty() || from_routing_instance == routing_instance)
}

/// #3605: pick the best-matching entry from a per-key `Vec` of scope-differing
/// static-NAT rules. Two tiers, mirroring the sibling [`super::DnatTable`]:
///   1. a zone-SCOPED entry (`from_zone` non-empty) that the caller's `admit`
///      predicate accepts — a split-horizon rule for this ingress/egress
///      context;
///   2. otherwise a zone-WILDCARD entry (`from_zone` empty) that `admit`
///      accepts — the catch-all default.
/// The specific tier wins over the wildcard tier regardless of config order,
/// so a coexisting wildcard rule cannot shadow a matching scoped rule. Within
/// a tier the first accepted entry (config/snapshot order) wins. `admit` folds
/// in ALL the gates (`static_scope_ok`, i.e. zone/interface/routing-instance,
/// plus `source_ok`); the tiering here only orders zone-scoped vs wildcard.
fn pick_scoped<'a>(
    entries: Option<&'a Vec<StaticNatEntry>>,
    admit: impl Fn(&&StaticNatEntry) -> bool,
) -> Option<&'a StaticNatEntry> {
    let entries = entries?;
    entries
        .iter()
        .find(|e| !e.from_zone.is_empty() && admit(e))
        .or_else(|| entries.iter().find(|e| e.from_zone.is_empty() && admit(e)))
}

/// Static 1:1 NAT entry (bidirectional).
#[derive(Clone, Debug)]
pub(crate) struct StaticNatEntry {
    pub(crate) external_ip: IpAddr,
    pub(crate) internal_ip: IpAddr,
    pub(crate) from_zone: String,
    /// #3096: interface-/routing-instance scope. The static-NAT `from` clause
    /// is gated against the INGRESS interface/VRF on the inbound (DNAT)
    /// direction and against the EGRESS interface/VRF on the reverse (SNAT)
    /// direction — symmetric with `from_zone`. Empty = unscoped on that axis.
    pub(crate) from_interface: String,
    pub(crate) from_routing_instance: String,
    /// #2491: external (pre-translation) destination port the inbound packet
    /// must carry for a port-mapped rule. `None` = whole-address 1:1 (match
    /// any port, the legacy behaviour).
    pub(crate) match_dst_port: Option<u16>,
    /// #2491: internal (post-translation) destination port to rewrite to.
    /// `None` = no port translation (whole-address 1:1).
    pub(crate) mapped_port: Option<u16>,
    /// #3435: `match source-address` constraint. Gated against the packet
    /// SOURCE on the inbound (DNAT) direction and against the packet
    /// DESTINATION (the original client) on the reverse (SNAT) direction.
    /// Unconstrained = match any peer (unchanged behavior).
    source: SourceConstraint,
    /// #2218: per-rule translation hit counter (None for counter_id 0).
    pub(crate) hit_counter: Option<Arc<NatRuleCounter>>,
}

/// Lookup table for static NAT -- indexed by (IP, Option<port>) for O(1)
/// matching. #2491: a single external IP can host several per-port mappings
/// (`mapped-port`) AND a port-less whole-address 1:1 mapping, so the key
/// carries the matched port. The port-less entry uses `None` and is the
/// fallback when no port-specific entry matches.
///
/// #3605: each key holds a `Vec` of entries, NOT a single entry. Junos
/// supports zone-/interface-/routing-instance-/source-scoped static NAT
/// (split-horizon: the same public `(external_ip, match-port)` translated
/// differently per ingress context). Two such rules share the same map key
/// but differ only by scope; storing one entry per key silently overwrote
/// the first rule (last-write-wins), so a packet hitting the lost rule's
/// scope was forwarded UNtranslated (identity leak) or mis-translated. The
/// `Vec` lets scope-differing rules coexist and be matched per-candidate by
/// the same `static_scope_ok` / `source_ok` gates used everywhere else,
/// mirroring the `blocks` Vec and the sibling [`super::DnatTable`] which
/// already group entries in a `Vec` per key.
#[derive(Clone, Debug, Default)]
pub(crate) struct StaticNatTable {
    /// (external_ip, match-port) -> entries (for inbound DNAT). The match-port
    /// is the external destination port (`Some` for a port-mapped rule,
    /// `None` for a whole-address rule). #3605: a `Vec` so scope-differing
    /// rules on the same key coexist; matched per-candidate by scope.
    dnat: FxHashMap<(IpAddr, Option<u16>), Vec<StaticNatEntry>>,
    /// (internal_ip, mapped-port) -> entries (for outbound SNAT). The mapped-port
    /// is the internal source port of the return packet (`Some` for a
    /// port-mapped rule, `None` for a whole-address rule). #3605: a `Vec`, as
    /// `dnat`.
    snat: FxHashMap<(IpAddr, Option<u16>), Vec<StaticNatEntry>>,
    /// #3031: block-to-block (subnet) static-NAT rules. A source prefix maps
    /// 1:1 by offset to an equal-length destination prefix. These cannot be
    /// keyed by exact IP, so they are scanned linearly on the session-miss
    /// cold path (block rules are rare). Exact host entries above take
    /// precedence over an overlapping block.
    blocks: Vec<StaticNatBlock>,
}

/// #3031: a block-to-block static-NAT rule. `external` (the public side) and
/// `internal` (the private side) are equal-length prefixes; a host H in one
/// block maps to the same offset in the other (network bits replaced, host
/// bits preserved). Bidirectional, exactly like the host [`StaticNatEntry`].
#[derive(Clone, Debug)]
pub(crate) struct StaticNatBlock {
    /// External (public) prefix — matched on inbound DNAT (`dst_ip`).
    external: NatPrefix,
    /// Internal (private) prefix — matched on outbound SNAT (`src_ip`).
    internal: NatPrefix,
    /// Rule's `from zone` external-zone constraint (empty = any zone),
    /// gated exactly like the host entry's `from_zone`.
    from_zone: String,
    /// #3096: interface-/routing-instance scope, gated like the host entry.
    from_interface: String,
    from_routing_instance: String,
    /// #3435: `match source-address` constraint, gated like the host entry
    /// (packet SOURCE on inbound DNAT, packet DESTINATION on reverse SNAT).
    source: SourceConstraint,
    /// Per-rule translation hit counter (#2218); None for counter_id 0.
    hit_counter: Option<Arc<NatRuleCounter>>,
}

/// Host mask (the low `32-len` bits set) for an IPv4 prefix of `len`
/// network bits. Guards the `len >= 32` shift: `u32::MAX >> 32` is UB
/// (release-mode masks the shift amount to 0, a no-op) so a host route
/// (`len == 32`, no host bits) returns `0` explicitly.
fn host_mask_v4(len: u8) -> u32 {
    if len >= 32 {
        0
    } else {
        u32::MAX >> len
    }
}

/// Host mask for an IPv6 prefix of `len` network bits. Same `len >= 128`
/// shift guard as [`host_mask_v4`].
fn host_mask_v6(len: u8) -> u128 {
    if len >= 128 {
        0
    } else {
        u128::MAX >> len
    }
}

/// A parsed static-NAT prefix: a canonical network base plus the prefix
/// length. A host route (bare address, `/32`, `/128`) has `len == max` for
/// its family.
#[derive(Clone, Copy, Debug)]
struct NatPrefix {
    base: IpAddr,
    len: u8,
}

impl NatPrefix {
    /// Maximum prefix length for the address family (32 v4 / 128 v6).
    fn max_len(&self) -> u8 {
        match self.base {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }

    /// True when this is a host route (`/32` v4, `/128` v6) — the legacy
    /// exact 1:1 static-NAT case.
    fn is_host(&self) -> bool {
        self.len == self.max_len()
    }

    /// True when `addr` falls within this prefix (same family, network bits
    /// equal). A cross-family compare is never in-prefix.
    fn contains(&self, addr: IpAddr) -> bool {
        match (self.base, addr) {
            (IpAddr::V4(b), IpAddr::V4(a)) => {
                let hm = host_mask_v4(self.len);
                (u32::from(a) & !hm) == u32::from(b)
            }
            (IpAddr::V6(b), IpAddr::V6(a)) => {
                let hm = host_mask_v6(self.len);
                (u128::from(a) & !hm) == u128::from(b)
            }
            _ => false,
        }
    }
}

/// Remap `addr` (which lives in the `src` prefix) into the `dst` prefix,
/// preserving the host bits (offset within the block) and replacing the
/// network bits: `dst_base | (addr & host_mask(src.len))`. `src.len` and
/// `dst.len` are equal by construction (enforced in `from_snapshots`), so
/// the host mask is shared. Returns `None` only on a family mismatch
/// (never happens for a validated block rule).
fn remap_addr(addr: IpAddr, src: &NatPrefix, dst: &NatPrefix) -> Option<IpAddr> {
    match (addr, dst.base) {
        (IpAddr::V4(a), IpAddr::V4(d)) => {
            let hm = host_mask_v4(src.len);
            Some(IpAddr::V4(Ipv4Addr::from(
                (u32::from(d) & !hm) | (u32::from(a) & hm),
            )))
        }
        (IpAddr::V6(a), IpAddr::V6(d)) => {
            let hm = host_mask_v6(src.len);
            Some(IpAddr::V6(Ipv6Addr::from(
                (u128::from(d) & !hm) | (u128::from(a) & hm),
            )))
        }
        _ => None,
    }
}

/// Parse a static-NAT address that may carry a canonical host mask
/// (`x.x.x.x/32`, `addr/128`) OR a block prefix (`198.51.100.0/24`). Junos
/// emits static-NAT match/then in canonical prefix form and the Go compiler
/// copies that mask verbatim into the snapshot; `IpAddr::from_str` REJECTS
/// CIDR notation, so the mask must be stripped before the parse or the rule
/// is silently dropped (#2122).
///
/// #3031: a non-host prefix is no longer rejected. A bare address / `/32` /
/// `/128` parses to a host route (`len == max`, the legacy exact 1:1 case);
/// a shorter prefix parses to a block (`len < max`) whose base is
/// canonicalized to the network address (host bits beyond the prefix length
/// are masked off so the offset remap and `contains` use a clean base even
/// if the operator authored host bits). A non-numeric mask, an out-of-range
/// length (`/33`, `/129`), or a malformed address still returns `None`,
/// preserving the caller's skip-on-invalid behavior. Whether a parsed
/// block is INSTALLED is decided in `from_snapshots` (equal-length 1:1
/// pairs only).
fn parse_nat_prefix(s: &str) -> Option<NatPrefix> {
    // #7481: parse through `IpNet` / `IpAddr`, the SAME path
    // `source/mod.rs::parse_match_prefix` uses, rather than a hand-rolled
    // `splitn` + `u8::from_str`.
    //
    // The hand-rolled version's integer parser accepted a leading `+`, so
    // `10.0.0.0/+24` installed here as `(10.0.0.0, /24)` while the Go strict
    // gate and `ipnet` both rejected it. Measured across all three
    // implementations: two already agreed and this one did not, so aligning it
    // needed no grammar decision — it was one parser against a consensus.
    //
    // `IpNet::from_str` rejects a bare host address, which this grammar must
    // accept as an implicit /32 or /128, so the `IpAddr` fallback is kept —
    // again matching parse_match_prefix rather than inventing a third shape.
    // #7481: normalize the prefix-length spelling before any parser sees it.
    let s = &super::normalize_nat_prefix_len(s);
    let (addr, len) = match s.parse::<IpNet>() {
        Ok(net) => (net.addr(), net.prefix_len()),
        Err(_) => {
            let addr: IpAddr = s.parse().ok()?;
            let max = match addr {
                IpAddr::V4(_) => 32u8,
                IpAddr::V6(_) => 128u8,
            };
            (addr, max)
        }
    };
    let max = match addr {
        IpAddr::V4(_) => 32u8,
        IpAddr::V6(_) => 128u8,
    };
    if len > max {
        return None;
    }
    let base = match addr {
        IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a) & !host_mask_v4(len))),
        IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a) & !host_mask_v6(len))),
    };
    Some(NatPrefix { base, len })
}

/// #7481: expose `parse_nat_prefix` to the corpus differential.
///
/// A `for_test` accessor rather than widening the function's visibility: the
/// differential needs to CALL it, not to have it become part of the module's
/// surface. Same trade as `Nat64Prefix::for_test` — loosening production
/// visibility to make a test possible is how an invariant stops being one.
#[cfg(test)]
/// Returns whether the parser ACCEPTS the literal, not the parsed value: the
/// differential compares verdicts, and `NatPrefix` is private to this module.
/// Widening it to make a test compile is the trade this accessor exists to
/// avoid.
pub(super) fn parse_nat_prefix_accepts_for_test(s: &str) -> bool {
    parse_nat_prefix(s).is_some()
}

impl StaticNatTable {
    /// Whether a flowless packet could match a port-specific static-NAT
    /// translation. Protocol 255 is the non-first-fragment unknown sentinel;
    /// it is treated as possible rather than classified from packet bytes.
    pub(crate) fn flowless_l4_translation_possible(
        &self,
        protocol: u8,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        ingress_zone: &str,
        ingress_ifname: &str,
        ingress_routing_instance: &str,
        egress_zone: &str,
        egress_ifname: &str,
        egress_routing_instance: &str,
    ) -> bool {
        if protocol != u8::MAX && !crate::ip_proto::has_l4_ports(protocol) {
            return false;
        }
        self.dnat.iter().any(|((external_ip, port), entries)| {
            *external_ip == dst_ip
                && port.is_some()
                && entries.iter().any(|entry| {
                    static_scope_ok(
                        &entry.from_zone,
                        &entry.from_interface,
                        &entry.from_routing_instance,
                        ingress_zone,
                        ingress_ifname,
                        ingress_routing_instance,
                    ) && source_ok(&entry.source, Some(src_ip))
                })
        }) || self.snat.iter().any(|((internal_ip, port), entries)| {
            *internal_ip == src_ip
                && port.is_some()
                && entries.iter().any(|entry| {
                    static_scope_ok(
                        &entry.from_zone,
                        &entry.from_interface,
                        &entry.from_routing_instance,
                        egress_zone,
                        egress_ifname,
                        egress_routing_instance,
                    ) && source_ok(&entry.source, Some(dst_ip))
                })
        })
    }

    pub(crate) fn from_snapshots(
        snaps: &[StaticNATRuleSnapshot],
        nat_counters: &NatCounterStore,
    ) -> Self {
        let mut table = StaticNatTable::default();
        for snap in snaps {
            // #4718: surface an unparseable external/internal IP loudly instead
            // of a silent skip, so a leniently-loaded / peer-synced bad rule is
            // observable rather than a mysteriously-absent translation.
            let ext_prefix = match parse_nat_prefix(&snap.external_ip) {
                Some(p) => p,
                None => {
                    nat_counters.record_parse_error(&format!(
                        "static-NAT rule {:?}: unparseable external-ip {:?}",
                        snap.name, snap.external_ip
                    ));
                    continue;
                }
            };
            let int_prefix = match parse_nat_prefix(&snap.internal_ip) {
                Some(p) => p,
                None => {
                    nat_counters.record_parse_error(&format!(
                        "static-NAT rule {:?}: unparseable internal-ip {:?}",
                        snap.name, snap.internal_ip
                    ));
                    continue;
                }
            };
            // #3031: a non-host prefix on EITHER side is a block-to-block
            // (subnet) static-NAT rule. A valid block map needs equal-length
            // prefixes of the SAME family (1:1 by offset). A host-vs-block or
            // mismatched-length or mixed-family pair is a genuine misconfig —
            // skip it with the #2122 rationale (the Go strict commit-check
            // rejects it; this is the lenient-load / peer-sync backstop). The
            // legacy host (both `/32`/`/128`/bare) case falls through to the
            // exact-IP map path below, byte-identical to pre-#3031.
            if !ext_prefix.is_host() || !int_prefix.is_host() {
                if ext_prefix.base.is_ipv4() != int_prefix.base.is_ipv4()
                    || ext_prefix.len != int_prefix.len
                {
                    continue;
                }
                // #5658: a zero-length (`/0`) block prefix maps the ENTIRE
                // address family 1:1. `host_mask_v4(0)` / `host_mask_v6(0)` is
                // all-ones, so `!hm == 0` and `contains()` matches EVERY address
                // in the family — and the equal-length offset remap preserves all
                // host bits, making it an identity translation regardless of the
                // operator-written bases. Installed in the ordered block scan it
                // would shadow every narrower static/DNAT rule while claiming to
                // translate (traffic hijack / blackhole / policy bypass on the
                // translated address). Reject it fail-closed BEFORE block
                // insertion / local-target extraction / counter allocation,
                // mirroring the family/length/port drops above. The lengths are
                // equal here, so testing either side suffices; test both for
                // robustness. The Go strict commit-check rejects this too
                // (validateNATHostMaskStrict); this is the lenient-load /
                // peer-sync backstop. No non-zero floor is imposed — a legitimate
                // large-but-intentional block (e.g. `/8`, `/64`) still installs.
                if ext_prefix.len == 0 || int_prefix.len == 0 {
                    nat_counters.record_parse_error(&format!(
                        "static-NAT rule {:?}: block prefix {}/{} <-> {}/{} has a \
                         zero-length (/0) prefix that remaps the entire address \
                         family 1:1 (identity NAT shadowing all destinations) — \
                         rejected",
                        snap.name,
                        ext_prefix.base,
                        ext_prefix.len,
                        int_prefix.base,
                        int_prefix.len
                    ));
                    continue;
                }
                // #3202: a block (subnet) pair that ALSO carries a port match or
                // a mapped-port is not representable here. `StaticNatBlock` does
                // an address-only, ALL-PORT offset remap with no port fields, so
                // installing it would SILENTLY widen "port 80 of this /24 -> 8080"
                // into "every port of the /24". Drop the rule instead of
                // mis-installing it (fail CLOSED). The Go strict commit-check
                // already rejects this; this is the lenient-load / peer-sync
                // backstop, mirroring the host-side #2491 fail-closed behavior.
                if snap.match_destination_port != 0 || snap.mapped_port != 0 {
                    continue;
                }
                table.blocks.push(StaticNatBlock {
                    external: ext_prefix,
                    internal: int_prefix,
                    from_zone: snap.from_zone.clone(),
                    from_interface: snap.from_interface.clone(),
                    from_routing_instance: snap.from_routing_instance.clone(),
                    source: SourceConstraint::from_list(
                        &snap.source_addresses,
                        nat_counters,
                        &snap.name,
                    ),
                    hit_counter: nat_counters.rule_counter(snap.counter_id),
                });
                continue;
            }
            let external_ip: IpAddr = ext_prefix.base;
            let internal_ip: IpAddr = int_prefix.base;
            // #2491: a `mapped_port` without a `match_destination_port` has no
            // inbound trigger (no external port to match) and the reverse SNAT
            // cannot recover the original port. Drop the port rewrite, but keep
            // the entry as a whole-address 1:1: this is fail-closed for the
            // translation, NOT for the match (the zero match port remains the
            // intentional unconstrained wildcard). The Go compiler's
            // static-NAT exclusion must reject malformed destination-port tokens
            // before they can reach this wire-level ambiguity.
            let (match_dst_port, mapped_port) = match (snap.match_destination_port, snap.mapped_port)
            {
                (0, _) => (None, None),
                (m, 0) => (Some(m), None),
                (m, p) => (Some(m), Some(p)),
            };
            let entry = StaticNatEntry {
                external_ip,
                internal_ip,
                from_zone: snap.from_zone.clone(),
                from_interface: snap.from_interface.clone(),
                from_routing_instance: snap.from_routing_instance.clone(),
                match_dst_port,
                mapped_port,
                source: SourceConstraint::from_list(
                    &snap.source_addresses,
                    nat_counters,
                    &snap.name,
                ),
                hit_counter: nat_counters.rule_counter(snap.counter_id),
            };
            // DNAT keyed by the external (pre-translation) destination port.
            // #3605: push onto the per-key Vec instead of insert() so a
            // second rule that shares this `(external_ip, match_dst_port)` but
            // differs by scope (zone/interface/routing-instance/source) no
            // longer overwrites the first. Preserves config/snapshot order
            // within the key, which the specificity tiering in the match path
            // relies on for the wildcard fallback.
            table
                .dnat
                .entry((external_ip, match_dst_port))
                .or_default()
                .push(entry.clone());
            // #2769: SNAT key scoping. The reverse key is the internal-host
            // source port of the return packet.
            //   * mapped-port rule:   return packets leave on the `mapped_port`
            //     (the inbound DNAT rewrote the destination port to it), so the
            //     SNAT key is `Some(mapped_port)`.
            //   * port-scoped 1:1 rule (`match destination-port` WITHOUT a
            //     `mapped-port`): NO port translation happens, so the internal
            //     service runs on — and its return packets leave from — the
            //     matched external port. The SNAT key MUST be
            //     `Some(match_dst_port)`, NOT `None`. Keying on `None` (the
            //     pre-#2769 bug) made the reverse SNAT match ANY source port on
            //     the internal host, source-translating every service on the
            //     box, not just the one port that was port-scoped inbound.
            //   * whole-address 1:1 rule: no port match at all, keys on `None`.
            let snat_port = mapped_port.or(match_dst_port);
            // #3605: as with `dnat`, push onto the per-key Vec so scope-
            // differing rules on the same `(internal_ip, snat_port)` coexist.
            table
                .snat
                .entry((internal_ip, snat_port))
                .or_default()
                .push(entry);
        }
        table
    }

    /// Match inbound: if dst_ip is an external IP, return DNAT decision.
    ///
    /// Returns just the decision; existing callers/tests keep their
    /// `Option<NatDecision>` shape. The cold path uses
    /// [`match_dnat_with_counter`] (#2218) for the per-rule hit counter.
    ///
    /// #2491: the test-only port-less wrapper looks up the whole-address
    /// entry (port `0` exercises only the `None` fallback). The production
    /// path uses [`match_dnat_with_counter`] with the packet's destination
    /// port so a port-mapped rule can be matched.
    #[cfg(test)]
    pub(crate) fn match_dnat(&self, dst_ip: IpAddr, ingress_zone: &str) -> Option<NatDecision> {
        self.match_dnat_with_counter(dst_ip, 0, ingress_zone)
            .map(|(decision, _)| decision)
    }

    /// #2218: as [`match_dnat`] but also returns the matched entry's
    /// per-rule hit counter (if any).
    ///
    /// #2491: `dst_port` is the inbound packet's destination port. A
    /// port-mapped entry keyed on `Some(match_dst_port)` is tried first; on a
    /// miss the whole-address entry keyed on `None` is the fallback. When the
    /// matched entry carries a `mapped_port`, the decision rewrites the
    /// destination port too.
    ///
    /// #2864: the zone constraint is evaluated PER CANDIDATE, not once after
    /// the `(port, None)` precedence is resolved. Otherwise a port-specific
    /// entry whose `from_zone` does not match the packet's ingress zone would
    /// short-circuit to `None` and never try the whole-address `(dst_ip, None)`
    /// fallback, silently bypassing a legitimate whole-address DNAT rule. The
    /// port-specific entry still wins when its zone DOES match; only on a
    /// zone-fail (or a port miss) do we fall back to the whole-address entry
    /// and validate ITS zone.
    pub(crate) fn match_dnat_with_counter(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        ingress_zone: &str,
    ) -> Option<(NatDecision, Option<Arc<NatRuleCounter>>)> {
        // Unscoped wrapper: empty interface/RI scope = wildcard (pre-#3096
        // behavior); `None` source = skip the #3435 source gate (this is the
        // test / zone-only path that carries no peer IP). The production
        // transit path uses the *_scoped variant with the real packet source.
        self.match_dnat_with_counter_scoped(dst_ip, dst_port, None, ingress_zone, "", "")
    }

    /// #3096: as [`match_dnat_with_counter`] but additionally gates each
    /// candidate on the static-NAT rule's `from interface` /
    /// `from routing-instance` scope against the packet's INGRESS interface
    /// config-name and routing-instance. Empty scope fields are wildcards, so
    /// a zone-only or global static-NAT rule is unaffected.
    ///
    /// #3435: `src_ip` is the inbound packet's SOURCE address, matched against
    /// each candidate's `match source-address` constraint. `None` skips the
    /// source gate (the non-scoped / test wrappers); the production path
    /// passes `Some(packet source)`. A source-scoped rule whose source list is
    /// non-empty but parses to nothing matches NO source (fail closed).
    pub(crate) fn match_dnat_with_counter_scoped(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        src_ip: Option<IpAddr>,
        ingress_zone: &str,
        ingress_ifname: &str,
        ingress_routing_instance: &str,
    ) -> Option<(NatDecision, Option<Arc<NatRuleCounter>>)> {
        // Per-candidate gate: an entry matches only when its zone AND
        // interface AND routing-instance constraints all hold (empty = any)
        // AND its #3435 source-address constraint admits the packet source.
        let zone_ok = |entry: &&StaticNatEntry| {
            static_scope_ok(
                &entry.from_zone,
                &entry.from_interface,
                &entry.from_routing_instance,
                ingress_zone,
                ingress_ifname,
                ingress_routing_instance,
            ) && source_ok(&entry.source, src_ip)
        };
        // #3605: a key now holds a `Vec` of scope-differing rules. Within the
        // key, prefer a zone-SCOPED entry that admits the packet over a
        // zone-WILDCARD one (`pick_scoped`, mirroring the sibling `DnatTable`
        // two-tier match), so a specific split-horizon rule is not shadowed by
        // a coexisting wildcard rule regardless of config order. All the finer
        // gates (interface/routing-instance/source) are AND-ed in via
        // `zone_ok`.
        //
        // Port-specific entry takes precedence over the whole-address entry,
        // but only if one of its candidates passes the scope check. On a port
        // miss OR a port-specific scope mismatch across ALL its candidates,
        // fall back to the whole-address entries (each scope-checked on its
        // own).
        if let Some(entry) = pick_scoped(self.dnat.get(&(dst_ip, Some(dst_port))), &zone_ok)
            .or_else(|| pick_scoped(self.dnat.get(&(dst_ip, None)), &zone_ok))
        {
            // #4074: this cannot attach a spurious L4 port to an ICMP flow (the
            // regression the DNAT-pool path had). A port-mapped entry always
            // carries `mapped_port = Some(_)` together with `match_dst_port =
            // Some(nonzero)` (the build maps `match_destination_port == 0` to
            // `(None, None)`), so it is keyed under `(ip, Some(nonzero))` and an
            // ICMP packet (dst_port 0) can never match it; the whole-address
            // `(ip, None)` bucket only ever holds `mapped_port = None`. So
            // `rewrite_dst_port` is structurally `None` for ICMP here — no
            // protocol gate needed.
            return Some((
                NatDecision {
                    rewrite_src: None,
                    rewrite_dst: Some(entry.internal_ip),
                    rewrite_dst_port: entry.mapped_port,
                    ..NatDecision::default()
                },
                entry.hit_counter.clone(),
            ));
        }
        // #3031: block-to-block DNAT. Exact host entries above take
        // precedence; on a miss, scan the (rare) block rules. `dst_ip` in the
        // external prefix translates to the same offset in the internal
        // prefix (network bits replaced, host bits preserved). The decision
        // carries only `rewrite_dst` (an `IpAddr`), so the existing host
        // static-NAT checksum fixup path applies unchanged.
        for blk in &self.blocks {
            if static_scope_ok(
                &blk.from_zone,
                &blk.from_interface,
                &blk.from_routing_instance,
                ingress_zone,
                ingress_ifname,
                ingress_routing_instance,
            ) && source_ok(&blk.source, src_ip)
                && blk.external.contains(dst_ip)
            {
                if let Some(translated) = remap_addr(dst_ip, &blk.external, &blk.internal) {
                    return Some((
                        NatDecision {
                            rewrite_src: None,
                            rewrite_dst: Some(translated),
                            ..NatDecision::default()
                        },
                        blk.hit_counter.clone(),
                    ));
                }
            }
        }
        None
    }

    /// Match outbound: if src_ip is an internal IP, return SNAT decision.
    ///
    /// #2871: the egress (destination) zone IS checked for SNAT, mirroring the
    /// #2864 DNAT-direction zone gate. Static NAT is bidirectional but, per
    /// Junos/vSRX parity, the reverse (source) translation applies only when
    /// the packet egresses TOWARD the rule-set's external zone — the rule's
    /// `from zone` (`entry.from_zone`). The DNAT direction matches the external
    /// zone on INGRESS (`from_zone == ingress_zone`); the SNAT direction
    /// symmetrically matches it on EGRESS (`from_zone == egress_zone`).
    ///
    /// Without this gate, an outbound packet sourced from a static-NAT internal
    /// IP but destined for ANOTHER internal zone (trust↔dmz east-west,
    /// peer-to-peer on internal segments) was source-translated to the public
    /// `external_ip`, breaking internal routing, internal security-policy match
    /// (which then saw the translated source), and intra-site connectivity —
    /// a cross-zone leak.
    ///
    /// An empty `from_zone` ("any zone") matches every egress zone, preserving
    /// the wildcard rule behaviour.
    ///
    /// Returns just the decision; the cold path uses
    /// [`match_snat_with_counter`] (#2218) for the per-rule hit counter.
    ///
    /// #2491: the test-only port-less wrapper looks up the whole-address
    /// entry (port `0` exercises only the `None` fallback).
    #[cfg(test)]
    pub(crate) fn match_snat(&self, src_ip: IpAddr, egress_zone: &str) -> Option<NatDecision> {
        self.match_snat_with_counter(src_ip, 0, egress_zone)
            .map(|(decision, _)| decision)
    }

    /// #2218: as [`match_snat`] but also returns the matched entry's
    /// per-rule hit counter (if any).
    ///
    /// #2491: `src_port` is the return packet's source port — for a
    /// port-mapped flow this is the internal `mapped_port`. A port-specific
    /// entry keyed on `Some(src_port)` is tried first; on a miss the
    /// whole-address entry keyed on `None` is the fallback. When the matched
    /// entry carries a `mapped_port`, the decision un-translates the source
    /// port back to the external `match_dst_port`.
    pub(crate) fn match_snat_with_counter(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        egress_zone: &str,
    ) -> Option<(NatDecision, Option<Arc<NatRuleCounter>>)> {
        // Unscoped wrapper: empty interface/RI scope = wildcard (pre-#3096);
        // `None` peer = skip the #3435 source gate (test / zone-only path).
        self.match_snat_with_counter_scoped(src_ip, src_port, None, egress_zone, "", "")
    }

    /// #3096: as [`match_snat_with_counter`] but additionally gates each
    /// candidate on the static-NAT rule's `from interface` /
    /// `from routing-instance` scope against the packet's EGRESS interface
    /// config-name and routing-instance — the SNAT-direction analog of the
    /// DNAT ingress gate (the rule's `from` external context is matched on
    /// egress for the reverse translation, symmetric with #2871's egress-zone
    /// gate). Empty scope fields are wildcards.
    ///
    /// #3435: `dst_ip` is the outbound packet's DESTINATION — the original
    /// client — matched against each candidate's `match source-address`
    /// constraint (the reverse-direction analog of the inbound source gate, so
    /// the static mapping's source scoping holds symmetrically on the return
    /// path). `None` skips the gate (test / non-scoped wrappers); production
    /// passes `Some(packet destination)`.
    pub(crate) fn match_snat_with_counter_scoped(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: Option<IpAddr>,
        egress_zone: &str,
        egress_ifname: &str,
        egress_routing_instance: &str,
    ) -> Option<(NatDecision, Option<Arc<NatRuleCounter>>)> {
        // #2871 / #3096: per-candidate egress gate — zone AND interface AND
        // routing-instance must all hold (empty = any). Evaluate PER CANDIDATE
        // so a port-specific entry whose scope does not match falls back to the
        // whole-address entry rather than short-circuiting to None. #3435: the
        // source-address constraint is matched against the DESTINATION (the
        // original client) on this reverse direction.
        let zone_ok = |entry: &&StaticNatEntry| {
            static_scope_ok(
                &entry.from_zone,
                &entry.from_interface,
                &entry.from_routing_instance,
                egress_zone,
                egress_ifname,
                egress_routing_instance,
            ) && source_ok(&entry.source, dst_ip)
        };
        // #3605: per-key `Vec` with the same two-tier specificity pick as the
        // DNAT direction — a zone-scoped reverse mapping wins over a coexisting
        // wildcard one, and port-specific beats whole-address.
        if let Some(entry) = pick_scoped(self.snat.get(&(src_ip, Some(src_port))), &zone_ok)
            .or_else(|| pick_scoped(self.snat.get(&(src_ip, None)), &zone_ok))
        {
            // For a port-mapped rule, un-translate the source port back to the
            // external (pre-translation) port; for a whole-address rule this is
            // `None` (no port rewrite).
            let rewrite_src_port = entry.mapped_port.and(entry.match_dst_port);
            return Some((
                NatDecision {
                    rewrite_src: Some(entry.external_ip),
                    rewrite_dst: None,
                    rewrite_src_port,
                    ..NatDecision::default()
                },
                entry.hit_counter.clone(),
            ));
        }
        // #3031: block-to-block reverse SNAT — the inverse of the DNAT
        // offset map. `src_ip` in the internal prefix translates back to the
        // same offset in the external prefix, so the return path's source is
        // un-NAT'd to the public block and the reverse session key matches.
        for blk in &self.blocks {
            if static_scope_ok(
                &blk.from_zone,
                &blk.from_interface,
                &blk.from_routing_instance,
                egress_zone,
                egress_ifname,
                egress_routing_instance,
            ) && source_ok(&blk.source, dst_ip)
                && blk.internal.contains(src_ip)
            {
                if let Some(translated) = remap_addr(src_ip, &blk.internal, &blk.external) {
                    return Some((
                        NatDecision {
                            rewrite_src: Some(translated),
                            rewrite_dst: None,
                            ..NatDecision::default()
                        },
                        blk.hit_counter.clone(),
                    ));
                }
            }
        }
        None
    }

    /// Returns true if the table has any entries.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.dnat.is_empty() && self.blocks.is_empty()
    }

    /// Returns all external IPs (for local delivery recognition). #2491: the
    /// DNAT map is now keyed by `(IpAddr, Option<u16>)`; project the IP out.
    /// A given external IP appears once per distinct port mapping, which is
    /// fine for the consumers (they dedup or only test membership).
    ///
    /// #3031: also yields each block rule's external network base. A block's
    /// inbound DNAT match is NOT gated on `local_v4`/`local_v6` membership
    /// (the cold-path `match_dnat_with_counter` runs on transit regardless),
    /// so emitting only the base — rather than expanding a whole (possibly
    /// /16 or v6-huge) prefix into the local set — is sufficient parity for
    /// Returns the external (firewall-owned) IPs this table's rules match on.
    ///
    /// #7219: a BLOCK rule contributes its usable hosts when the block is small
    /// enough (`DnatTable::MAX_LOCAL_PREFIX_HOSTS`), not just its network base.
    ///
    /// The base-only version was defensible about the DNAT MATCH — that lookup
    /// is prefix-keyed and independent of `local_v*` — but `local_v*` has a
    /// SECOND role as the proxy-ARP/ND and local-delivery address set. On a
    /// directly-connected external segment the firewall answered ARP/ND only for
    /// `203.0.113.0`, so every other address the block translates was
    /// unreachable: peers got no reply for `.1`-`.254`, inbound traffic never
    /// arrived, and the translation that would have handled it correctly was
    /// never reached. Silent, and indistinguishable from a routing problem.
    ///
    /// The bound is `DnatTable`'s constant rather than a second copy: the two
    /// tables register into the SAME `local_v*` set, so a divergent bound would
    /// mean one NAT family proxy-ARPs a block size the other refuses, for no
    /// reason a reader could reconstruct.
    ///
    /// Static-NAT has NO exemption concept — the issue asks whether an analogue
    /// of DNAT's #6025 `exact_off` shadowing is needed, and there is none to
    /// port: `off` does not appear in this file's grammar at all. An exact-host
    /// entry here is always a TRANSLATE, so it can only duplicate an address the
    /// block expansion also yields, which the dedup below absorbs.
    ///
    /// Implemented ON TOP of `external_ips_scoped` so the deduped view and the
    /// scoped view cannot drift on the expansion bound — the same reason
    /// `DnatTable::destination_ips` is. They were independent before this, which
    /// is precisely how one of them could have been fixed and the other not.
    pub(crate) fn external_ips(&self) -> impl Iterator<Item = IpAddr> {
        let mut seen: FxHashMap<IpAddr, ()> = FxHashMap::default();
        for (ip, _instance) in self.external_ips_scoped() {
            seen.entry(ip).or_insert(());
        }
        seen.into_keys()
    }

    /// #3769: like [`external_ips`], but pairs each external IP with the
    /// `from routing-instance` scope of the owning rule ("" = the default
    /// instance / global). The forwarding-state builder converts the routing
    /// instance to a canonical route table and records the table attribution
    /// in `local_tables_v*`, so the local-delivery shortcut is gated on the
    /// resolving VRF instead of the global `local_v*` membership. A single
    /// external IP may appear more than once (per port mapping AND per
    /// split-horizon scope, #3605); every (IP, instance) pair is yielded and
    /// the builder inserts into a per-IP set of tables.
    ///
    /// #7219: block rules contribute their usable hosts under the shared
    /// `MAX_LOCAL_PREFIX_HOSTS` bound. A larger block still contributes only its
    /// network base and relies on being ROUTED to the firewall rather than
    /// proxy-ARP'd — the same trade `DnatTable` makes, and the reason the bound
    /// exists at all is that an unbounded expansion of a /8 would be 16M entries
    /// in a hot lookup set.
    pub(crate) fn external_ips_scoped(&self) -> Vec<(IpAddr, &str)> {
        let mut out = Vec::new();
        for ((ip, _port), entries) in &self.dnat {
            for entry in entries {
                out.push((*ip, entry.from_routing_instance.as_str()));
            }
        }
        for block in &self.blocks {
            let instance = block.from_routing_instance.as_str();
            let base = block.external.base;
            // Never register the UNSPECIFIED address as a proxy-ARP/ND target:
            // it is not an owned unicast VIP, and registering it perturbs
            // local-delivery classification (#5658, same guard as DNAT's).
            if !base.is_unspecified() {
                out.push((base, instance));
            }
            match base {
                IpAddr::V4(addr) => {
                    if static_block_host_count_v4(block.external.len)
                        <= DnatTable::MAX_LOCAL_PREFIX_HOSTS
                        && let Ok(net) = Ipv4Net::new(addr, block.external.len)
                    {
                        for host in net.hosts() {
                            out.push((IpAddr::V4(host), instance));
                        }
                    }
                }
                IpAddr::V6(addr) => {
                    // Only expand a v6 block that is itself host-scale; anything
                    // shorter is astronomically large.
                    //
                    // The `is_some_and` (rather than `is_none_or`) polarity is
                    // DEFENSE IN DEPTH, not the primary guard, and a mutation
                    // flipping it is INERT: `host_count_v6` returns None only
                    // for a prefix shorter than /1, and #5658 already rejects a
                    // zero-length block prefix fail-closed before insertion (an
                    // equal-length /0 pair is an identity translation that would
                    // shadow every narrower rule). So no /0 block reaches here.
                    // Kept anyway — the cost is one comparison, and the failure
                    // it would prevent is a hang enumerating 2^128 addresses,
                    // not a wrong answer. `static_nat_zero_length_block_is_
                    // rejected_before_expansion_7219` pins the invariant this
                    // relies on.
                    if static_block_host_count_v6(block.external.len)
                        .is_some_and(|h| h <= u128::from(DnatTable::MAX_LOCAL_PREFIX_HOSTS))
                        && let Ok(net) = Ipv6Net::new(addr, block.external.len)
                    {
                        for host in net.hosts() {
                            out.push((IpAddr::V6(host), instance));
                        }
                    }
                }
            }
        }
        out
    }
}

/// #7219: usable host count of an IPv4 prefix (saturating; /0 -> u32::MAX).
/// Mirrors `destination.rs`'s `host_count_v4`, which is private to that module.
fn static_block_host_count_v4(prefix_len: u8) -> u32 {
    match 32u32.checked_sub(u32::from(prefix_len)) {
        Some(host_bits) if host_bits < 32 => 1u32 << host_bits,
        _ => u32::MAX,
    }
}

/// #7219: usable host count of an IPv6 prefix; `None` if it overflows u128.
fn static_block_host_count_v6(prefix_len: u8) -> Option<u128> {
    match 128u32.checked_sub(u32::from(prefix_len)) {
        Some(host_bits) if host_bits < 128 => Some(1u128 << host_bits),
        _ => None,
    }
}
