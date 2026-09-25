// Destination NAT (DNAT) table — O(1) lookup by (protocol, dst_ip, dst_port).

use super::{NatCounterStore, NatDecision, NatRuleCounter};
use crate::DestinationNATRuleSnapshot;
use crate::prefix::{PrefixV4, PrefixV6};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rustc_hash::FxHashMap;
use std::net::IpAddr;
use std::sync::Arc;

pub(super) use crate::ip_proto::{PROTO_TCP, PROTO_UDP};

/// #2396: protocol-wildcard sentinel for an IP-only / any-protocol DNAT rule
/// (Junos `match destination-address <ip>` with no application and no port).
/// Such a rule translates traffic to the destination REGARDLESS of L4
/// protocol, including ICMP/ICMPv6/GRE. The IP-only case keys under this
/// sentinel and `lookup_with_counter` falls back to it after the
/// concrete-protocol and wildcard-port lookups miss.
///
/// #2396 (Copilot fold): the sentinel is `256`, OUTSIDE the 0-255 IANA
/// protocol range, so it is DISTINCT from every real protocol — including
/// protocol 0 (HOPOPT), which is a legitimate value in the SSOT
/// (`appid.ProtocolNumber`/`proto_number`). The earlier `PROTO_ANY = 0`
/// collided with HOPOPT: a DNAT rule with `protocol 0` would have keyed under
/// the wildcard and broadened to match ALL protocols. `DnatKey.protocol` is
/// therefore a `u16`: real protocol bytes widen losslessly to 0..=255 and the
/// wildcard is the unreachable 256th value.
pub(crate) const PROTO_ANY: u16 = 256;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct DnatKey {
    /// IANA protocol number widened to u16 (0..=255), or `PROTO_ANY` (256) for
    /// the IP-only / any-protocol wildcard entry. u16 so the wildcard is
    /// distinct from protocol 0 (HOPOPT) — see `PROTO_ANY`.
    pub protocol: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DnatValue {
    pub new_dst_ip: IpAddr,
    pub new_dst_port: u16,
}

/// #3844: outcome of matching a DNAT entry within one proto/port tier.
///
/// The lookup probes tiers with `.or_else` (exact `(proto, dst, port)` →
/// wildcard port → `PROTO_ANY` → prefix LPM). A `None` from a tier means "no
/// rule matched" and `.or_else` continues to the next tier. `Some(Exempt)` and
/// `Some(Translate)` are BOTH matches, so either one halts the `.or_else`
/// chain — this is what gives a matched `then destination-nat off` rule the
/// Junos "stop evaluation" semantic: it short-circuits the broader tiers and
/// the caller then maps `Exempt` to no-DNAT.
enum DnatOutcome {
    /// A translate rule matched — apply the pool translation (and its counter).
    Translate(DnatValue, Option<Arc<NatRuleCounter>>),
    /// A `then destination-nat off` exemption matched — no translation, and the
    /// remaining tiers are short-circuited (they are never probed because this
    /// is a non-`None` `.or_else` result).
    Exempt,
}

#[derive(Clone, Debug)]
struct DnatEntry {
    from_zone: Box<str>,
    /// #3096: interface-/routing-instance scope. DNAT translates on inbound,
    /// so these gate the entry against the packet's INGRESS interface
    /// config-name / routing-instance. Empty = unscoped on that axis (a
    /// zone-only or global DNAT rule is unaffected).
    from_interface: Box<str>,
    from_routing_instance: Box<str>,
    /// #2394: whether the DNAT rule was scoped to a `match source-address` at
    /// all (snapshot list non-empty). This is independent of how many entries
    /// PARSED: it stays true even when every source entry was unparseable, so
    /// `source_matches` can fail closed (match nothing) for a scoped rule whose
    /// entries all failed rather than silently reverting to match-any (the
    /// #2394 fail-open). `false` = unscoped rule -> match any source (unchanged
    /// behavior).
    source_constrained: bool,
    /// #2394: parsed source-address prefixes (CIDR or bare-host /32 /128). A
    /// packet source must fall in one of these for the entry to fire.
    source_v4: Vec<PrefixV4>,
    source_v6: Vec<PrefixV6>,
    /// #3437 (H10): the source-port constraint of the DNAT rule's `match
    /// application` term as inclusive (low, high) ranges. Empty =
    /// source-port-unconstrained (match any source port, the pre-#3437
    /// behavior). Non-empty = the flow's source port MUST fall in one range or
    /// the entry does not fire — so an application-scoped DNAT no longer
    /// translates every source port. A low>high range never matches (the
    /// fail-CLOSED never-match sentinel) and is preserved verbatim.
    match_src_ports: Vec<(u16, u16)>,
    /// #3449: a MULTI-port `match destination-port` range as inclusive
    /// (low, high) ranges. Empty = no range constraint — the entry's exact
    /// `DnatKey.dst_port` (or the wildcard-port=0 catch-all) governs, unchanged.
    /// Non-empty: the entry is keyed under the wildcard port (dst_port=0) and
    /// the flow's destination port MUST fall in one of these ranges, otherwise
    /// the entry does not fire. This lets `destination-port 20000 to 30000`
    /// install ONE wildcard-port entry with a [20000,30000] range instead of
    /// 10 001 exact-port entries (the control-plane amplification #3449 closes).
    /// A low>high range never matches (preserved verbatim), like the source-port
    /// never-match sentinel. AND-ed with `match_src_ports` and the ICMP
    /// type/code constraint in `l4_extra_matches`.
    match_dst_ports: Vec<(u16, u16)>,
    /// #3437 (H11): the ICMP/ICMPv6 type[,code] constraint of the DNAT rule's
    /// `match application` term. `None` = unconstrained (match every type/code
    /// of the protocol). `Some(type)` requires the packet's ICMP type to equal
    /// it; when `match_icmp_code` is also `Some` the code must equal it too. A
    /// non-ICMP packet (no `(type, code)` supplied) never satisfies an
    /// ICMP-type-constrained entry (fail closed).
    match_icmp_type: Option<u8>,
    match_icmp_code: Option<u8>,
    /// #3844: a `then destination-nat off` no-translate EXEMPTION. When true a
    /// match on this entry means "do NOT translate" — the lookup returns no
    /// DNAT decision AND short-circuits the remaining proto/port/prefix tiers
    /// (the Junos ordered "matched rule wins, stop" semantic), so a later DNAT
    /// rule cannot re-translate the exempted flow. `value` is a placeholder for
    /// an off entry (never read; the exemption returns before any translation).
    /// An off entry is also excluded from `destination_ips` local-address
    /// registration — the exempted destination is a real routed host, not a
    /// VIP the firewall should proxy-ARP/ND for.
    off: bool,
    value: DnatValue,
    /// #2218: per-rule translation hit counter (None for counter_id 0).
    hit_counter: Option<Arc<NatRuleCounter>>,
}

impl DnatEntry {
    /// #3096: does the packet's ingress interface / routing-instance satisfy
    /// this entry's `from interface` / `from routing-instance` scope? Empty
    /// fields are wildcards; present fields are AND-ed.
    fn scope_ok(&self, ingress_ifname: &str, ingress_routing_instance: &str) -> bool {
        (self.from_interface.is_empty() || self.from_interface.as_ref() == ingress_ifname)
            && (self.from_routing_instance.is_empty()
                || self.from_routing_instance.as_ref() == ingress_routing_instance)
    }

    /// #2394: does the packet source IP satisfy this entry's source-address
    /// constraint?
    ///
    /// - Unscoped rule (`source_constrained == false`): match any source.
    /// - Scoped rule whose entries ALL failed to parse (constrained but both
    ///   prefix vecs empty): match NOTHING — fail closed, never fall back to
    ///   match-any (the #2394 fail-open). This is the DNAT sibling of #2398.
    /// - Otherwise: the packet source must fall in one of the parsed prefixes
    ///   of its own address family.
    fn source_matches(&self, src_ip: IpAddr) -> bool {
        if !self.source_constrained {
            return true;
        }
        if self.source_v4.is_empty() && self.source_v6.is_empty() {
            // Scoped but no entry parsed -> fail closed.
            return false;
        }
        match src_ip {
            IpAddr::V4(v4) => self.source_v4.iter().any(|net| net.contains(v4)),
            IpAddr::V6(v6) => self.source_v6.iter().any(|net| net.contains(v6)),
        }
    }

    /// #3437: does the flow satisfy this entry's application-derived L4 match
    /// constraints — `source-port` (H10) and ICMP `type[,code]` (H11)?
    ///
    /// - An empty `match_src_ports` is a source-port wildcard (unchanged
    ///   behavior); a non-empty set requires `src_port` to fall in one range.
    /// - `match_icmp_type == None` is an ICMP-type wildcard; `Some(t)` requires
    ///   the packet's ICMP type to equal `t` (and, if `match_icmp_code` is also
    ///   `Some`, its code to equal that). `packet_icmp == None` (a non-ICMP
    ///   packet) can never satisfy an ICMP-type-constrained entry — fail closed.
    ///
    /// #3449: a non-empty `match_dst_ports` requires `dst_port` to fall in one
    /// range (the wide-range DNAT representation); empty is a wildcard.
    ///
    /// All axes are AND-ed (mirroring Junos and the source-NAT path #3429).
    fn l4_extra_matches(&self, src_port: u16, dst_port: u16, packet_icmp: Option<(u8, u8)>) -> bool {
        if !self.match_dst_ports.is_empty() && !port_in_ranges(dst_port, &self.match_dst_ports) {
            return false;
        }
        if !self.match_src_ports.is_empty() && !port_in_ranges(src_port, &self.match_src_ports) {
            return false;
        }
        if let Some(want_type) = self.match_icmp_type {
            match packet_icmp {
                Some((typ, code)) => {
                    if typ != want_type {
                        return false;
                    }
                    if let Some(want_code) = self.match_icmp_code {
                        if code != want_code {
                            return false;
                        }
                    }
                }
                None => return false,
            }
        }
        true
    }

    /// #3844: map a matched entry to its lookup outcome. An `off` entry is a
    /// no-translate exemption; any other entry translates to its pool value.
    fn to_outcome(&self) -> DnatOutcome {
        if self.off {
            DnatOutcome::Exempt
        } else {
            DnatOutcome::Translate(self.value, self.hit_counter.clone())
        }
    }
}

/// #3164: protocol+port key for the prefix (longest-prefix-match) DNAT entries.
/// Mirrors `DnatKey` minus the destination IP — the IP is matched by prefix
/// containment, not hashed.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct DnatProtoPortKey {
    pub protocol: u16,
    pub dst_port: u16,
}

/// #3164: one non-host DNAT destination prefix and its translation entry. The
/// prefix is stored in its address family (exactly one of `v4`/`v6` is set);
/// `contains`/`prefix_len` dispatch on the family.
#[derive(Clone, Debug)]
struct DnatPrefixSlot {
    v4: Option<PrefixV4>,
    v6: Option<PrefixV6>,
    entry: DnatEntry,
}

impl DnatPrefixSlot {
    fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.v4.is_some_and(|p| p.contains(v4)),
            IpAddr::V6(v6) => self.v6.is_some_and(|p| p.contains(v6)),
        }
    }

    fn prefix_len(&self) -> u8 {
        self.v4
            .map(|p| p.prefix_len())
            .or_else(|| self.v6.map(|p| p.prefix_len()))
            .unwrap_or(0)
    }

    /// The prefix network address, for local-address registration.
    fn network(&self) -> Option<IpAddr> {
        self.v4
            .map(|p| IpAddr::V4(p.addr()))
            .or_else(|| self.v6.map(|p| IpAddr::V6(p.addr())))
    }
}

/// Destination NAT lookup table.
///
/// Host destinations (a bare IP, /32, or /128) are keyed by
/// `(protocol, dst_ip, dst_port)` in the exact `entries` map — the O(1) fast
/// path. A wildcard port entry (`dst_port = 0`) matches any destination port
/// when no exact-port entry exists.
///
/// #3164: non-host destination PREFIXES (`198.51.100.0/24`) live in
/// `prefix_entries`, keyed by `(protocol, dst_port)` only, and are matched by
/// longest-prefix containment. A host (/32, /128) is the longest possible
/// prefix, so the exact map is always probed first and wins; the prefix scan is
/// the fallback when no host entry matches.
#[derive(Clone, Debug, Default)]
pub(crate) struct DnatTable {
    entries: FxHashMap<DnatKey, Vec<DnatEntry>>,
    /// #3164: non-host prefix entries, keyed by protocol+port; the destination
    /// IP is matched by prefix containment (longest-prefix-match) within each
    /// slot vec.
    prefix_entries: FxHashMap<DnatProtoPortKey, Vec<DnatPrefixSlot>>,
}

/// #3164: a classified DNAT destination — a host (exact-map key) or a non-host
/// prefix (longest-prefix-match). Exactly one of `v4`/`v6` is set in `Prefix`.
enum DnatDest {
    Host(IpAddr),
    Prefix {
        v4: Option<PrefixV4>,
        v6: Option<PrefixV6>,
    },
}

impl DnatTable {
    /// #6899 test-only: total installed entries across BOTH the exact-host map
    /// and the prefix map.
    ///
    /// It exists because "the rule was dropped" is NOT observable through
    /// `lookup`: a dropped rule and a rule installed under a DIFFERENT key both
    /// answer `None` for any address the test happens to probe. A cell asserting
    /// the #4718 both-unparseable DROP therefore passes for the wrong reason
    /// unless it can see that nothing was installed AT ALL — which is what this
    /// reports, without the cell needing to guess which key a broken
    /// implementation would have chosen.
    #[cfg(test)]
    pub(crate) fn installed_entry_count(&self) -> usize {
        self.entries.values().map(|v| v.len()).sum::<usize>()
            + self.prefix_entries.values().map(|v| v.len()).sum::<usize>()
    }
    /// Does an L4-scoped DNAT translation remain possible for a flowless
    /// packet? Protocol 255 is the non-first-fragment unknown sentinel; it is
    /// treated as possible without recovering protocol or ports from bytes.
    pub(crate) fn flowless_l4_translation_possible(
        &self,
        protocol: u8,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        zone: &str,
        ingress_ifname: &str,
        ingress_routing_instance: &str,
    ) -> bool {
        let protocol_unknown = protocol == u8::MAX;
        let carries_ports = protocol_unknown || crate::ip_proto::has_l4_ports(protocol);
        let entry_possible = |entry: &DnatEntry, entry_protocol: u16, entry_port: u16| {
            if entry.off
                || (!entry.from_zone.is_empty() && entry.from_zone.as_ref() != zone)
                || !entry.scope_ok(ingress_ifname, ingress_routing_instance)
                || !entry.source_matches(src_ip)
                || (entry_protocol != PROTO_ANY
                    && !protocol_unknown
                    && entry_protocol != u16::from(protocol))
            {
                return false;
            }
            let has_l4_selector = entry_protocol != PROTO_ANY
                || entry_port != 0
                || !entry.match_src_ports.is_empty()
                || !entry.match_dst_ports.is_empty()
                || entry.match_icmp_type.is_some()
                || entry.match_icmp_code.is_some();
            if !has_l4_selector {
                return false;
            }
            if (!entry.match_src_ports.is_empty()
                || !entry.match_dst_ports.is_empty()
                || entry_port != 0)
                && !carries_ports
            {
                return false;
            }
            if (entry.match_icmp_type.is_some() || entry.match_icmp_code.is_some())
                && !protocol_unknown
                && !matches!(
                    protocol,
                    crate::ip_proto::PROTO_ICMP | crate::ip_proto::PROTO_ICMPV6
                )
            {
                return false;
            }
            if (!entry.match_src_ports.is_empty()
                && !entry.match_src_ports.iter().any(|(low, high)| low <= high))
                || (!entry.match_dst_ports.is_empty()
                    && !entry.match_dst_ports.iter().any(|(low, high)| low <= high))
            {
                return false;
            }
            entry.match_dst_ports.is_empty()
                || entry_port == 0
                || entry.match_dst_ports.iter().any(|(low, high)| {
                    low <= high && *low <= entry_port && entry_port <= *high
                })
        };

        self.entries.iter().any(|(key, entries)| {
            key.dst_ip == dst_ip
                && entries
                    .iter()
                    .any(|entry| entry_possible(entry, key.protocol, key.dst_port))
        }) || self.prefix_entries.iter().any(|(key, slots)| {
            slots.iter().any(|slot| {
                slot.contains(dst_ip) && entry_possible(&slot.entry, key.protocol, key.dst_port)
            })
        })
    }

    pub(crate) fn from_snapshots(
        snaps: &[DestinationNATRuleSnapshot],
        nat_counters: &NatCounterStore,
    ) -> Self {
        let mut table = DnatTable::default();
        for snap in snaps {
            // #3164: classify the destination as a HOST (exact-map fast path) or
            // a non-host PREFIX (longest-prefix-match). `destination_prefix` is
            // the additive wire signal: non-empty => a non-host CIDR. A host
            // destination, or an older helper that never sets the field, leaves
            // it empty and we key the exact `destination_address`. A /32 or /128
            // prefix is itself a host and collapses back to the exact map.
            let dest: DnatDest = if !snap.destination_prefix.is_empty() {
                match snap.destination_prefix.parse::<IpNet>() {
                    Ok(IpNet::V4(net)) => {
                        if net.prefix_len() == 32 {
                            DnatDest::Host(IpAddr::V4(net.addr()))
                        } else {
                            DnatDest::Prefix {
                                v4: Some(PrefixV4::from_net(net)),
                                v6: None,
                            }
                        }
                    }
                    Ok(IpNet::V6(net)) => {
                        if net.prefix_len() == 128 {
                            DnatDest::Host(IpAddr::V6(net.addr()))
                        } else {
                            DnatDest::Prefix {
                                v4: None,
                                v6: Some(PrefixV6::from_net(net)),
                            }
                        }
                    }
                    // Unparseable prefix: fall back to the host
                    // `destination_address` if it parses, else drop the entry
                    // (fail-closed, like an unparseable host destination).
                    // #4718: surface the drop loudly instead of a silent skip.
                    Err(_) => match snap.destination_address.parse::<IpAddr>() {
                        Ok(ip) => {
                            // #6899 (C180-023): the FALLBACK was silent. #4718
                            // surfaced the both-unparseable DROP three lines
                            // below, and that neighbouring `record_parse_error`
                            // is a decoy: it fires only when the prefix AND the
                            // address both fail. With a VALID base address the
                            // rule installed against it and the malformed prefix
                            // vanished — DNAT quietly targeting one host where
                            // the operator wrote a block, with nothing in the
                            // counters to look at.
                            //
                            // The fallback itself is DELIBERATE and is kept: the
                            // comment above states it, and #4718 chose to
                            // surface the drop, not to remove the fallback. The
                            // defect is the silence, so this records and
                            // continues rather than dropping a rule that is
                            // currently forwarding.
                            //
                            // Reachability, stated honestly: the Go snapshot
                            // builder already SKIPS a token that parses as
                            // neither IP nor CIDR (nat_destination.go), so a
                            // normal commit cannot get here. This is the
                            // last-line arm for config drift across a
                            // mixed-version pair or a direct control-socket
                            // write — the same class of caller #4718's own arms
                            // exist for.
                            nat_counters.record_parse_error(&format!(
                                "DNAT rule {:?}: unparseable destination prefix {:?}; \
                                 falling back to the host destination address {:?} — \
                                 the configured block is NOT being translated",
                                snap.name, snap.destination_prefix, snap.destination_address
                            ));
                            DnatDest::Host(ip)
                        }
                        Err(_) => {
                            nat_counters.record_parse_error(&format!(
                                "DNAT rule {:?}: unparseable destination prefix {:?} and address {:?}",
                                snap.name, snap.destination_prefix, snap.destination_address
                            ));
                            continue;
                        }
                    },
                }
            } else {
                match snap.destination_address.parse::<IpAddr>() {
                    Ok(ip) => DnatDest::Host(ip),
                    // #4718: surface the drop loudly instead of a silent skip.
                    Err(_) => {
                        nat_counters.record_parse_error(&format!(
                            "DNAT rule {:?}: unparseable destination address {:?}",
                            snap.name, snap.destination_address
                        ));
                        continue;
                    }
                }
            };
            // #3844: an off (exemption) entry carries no pool. Parse the pool
            // address only for a translate entry; for an off entry the value is
            // a placeholder that is never read (the exemption short-circuits
            // before any translation), so a missing/empty pool_address must NOT
            // drop the entry the way it does for a translate rule.
            //
            // #6823: an ACTIONLESS entry (`off` clear AND no pool at all) is
            // the third shape, and it lands here too — the empty string does
            // not parse, so the entry is dropped and the traffic falls
            // through, which IS the decided contract (see the ZERO-actions
            // bullet in pkg/config/compiler_validate_strict_nat.go). Only the
            // DIAGNOSTIC was wrong: "unparseable pool address" sends an
            // operator hunting a serialization bug, when the cause is a
            // malformed CONFIG rule that named no translation action —
            // precisely the shape `xpf_nat_rules_lenient_terminal_action`
            // (#7640) reports on the control-plane side. The Go builder never
            // emits this entry (`nat_destination.go` skips it), so reaching it
            // means a hand-built snapshot or a mixed-version xpfd/helper pair;
            // the drop, the counter and the loud log are all unchanged, and
            // the message now names the actual cause so the two surfaces can
            // be connected.
            //
            // NOTE this branch is load-bearing beyond its wording: widening the
            // `snap.off` placeholder above to cover any pool-less entry would
            // install this rule with a 0.0.0.0 pool, and `to_outcome` — which
            // branches on `off` alone — would then TRANSLATE every matching
            // flow into a blackhole. actionless_dnat_entry_falls_through_6823
            // pins that.
            let pool_ip: IpAddr = if snap.off {
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            } else if snap.pool_address.is_empty() {
                nat_counters.record_parse_error(&format!(
                    "DNAT rule {:?}: no translation action (neither a pool nor \
                     `off`) — a malformed rule admitted by a tolerant load; the \
                     rule is dropped and matching traffic falls through",
                    snap.name
                ));
                continue;
            } else {
                match snap.pool_address.parse() {
                    Ok(ip) => ip,
                    // #4718: surface the drop loudly instead of a silent skip.
                    Err(_) => {
                        nat_counters.record_parse_error(&format!(
                            "DNAT rule {:?}: unparseable pool address {:?}",
                            snap.name, snap.pool_address
                        ));
                        continue;
                    }
                }
            };
            // Determine the protocol key to insert this entry under.
            //
            // #2396: previously only `"tcp"`/`"udp"`/`""` were recognized and
            // everything else hit `_ => continue` — a GRE/ICMP/ICMPv6 DNAT
            // rule compiled and committed but was SILENTLY DROPPED here, never
            // reaching the dataplane (fail-open: configured translation
            // absent). And an IP-only rule (`""` + no port) expanded to
            // TCP+UDP only, so an IP-only DNAT did NOT cover ICMP/GRE despite
            // the closeout doc claiming "IP-only DNAT works for ICMP via
            // wildcard lookup".
            //
            // Now:
            //  - a concrete protocol token resolves through the shared SSOT
            //    (`proto_number`, mirrors Go's `appid.ProtocolNumber`) to its
            //    IANA number (widened to u16) — a single keyed entry covering
            //    exactly that protocol. This INCLUDES `"0"` (HOPOPT), which is
            //    a real, exact protocol — NOT the wildcard.
            //  - `""` + a destination port is still a port-based rule and
            //    defaults to TCP (the Go builder already rewrites `""`->`"tcp"`
            //    for a non-zero port; we keep the fallback for robustness).
            //  - `""` + NO port is a true IP-only / any-protocol DNAT: it is
            //    keyed under the protocol WILDCARD (`PROTO_ANY = 256`, distinct
            //    from every real protocol incl. HOPOPT), and the lookup falls
            //    back to that wildcard so it covers ALL protocols INCLUDING
            //    ICMP/ICMPv6/GRE — honoring the doc.
            //
            // An unresolvable token still drops the entry, but the Go commit
            // gate (validateDestinationNATProtocolStrict) rejects an
            // unresolvable DNAT protocol before it can reach the wire on the
            // commit path (#2396); a tolerant load downgrades to a warning, so
            // this `continue` is the dataplane backstop for a leniently-loaded
            // bad config, not the operator-facing failure mode.
            let proto: u16 = match snap.protocol.as_str() {
                "" => {
                    if snap.destination_port != 0 {
                        u16::from(PROTO_TCP)
                    } else {
                        PROTO_ANY
                    }
                }
                token => match crate::ip_proto::proto_number(token) {
                    Some(p) => u16::from(p),
                    None => continue,
                },
            };
            let hit_counter = nat_counters.rule_counter(snap.counter_id);
            // #2394 (Copilot fold): parse the source-address constraint once per
            // rule. Each entry may be a CIDR prefix (`198.51.100.0/24`) OR a bare
            // host IP (`198.51.100.42`) — Junos carries source-address verbatim
            // and the Go compiler does NOT normalize it, so a bare host reaches
            // the wire with no `/prefix`. `IpNet::from_str` REQUIRES `addr/prefix`
            // form and rejects a bare IP, so we fall back to parsing a bare
            // `IpAddr` -> /32 (v4) or /128 (v6). Without this fallback a bare-host
            // source-scoped DNAT would skip its only entry, leave the source
            // lists empty, and silently match ANY source — the exact #2394
            // fail-open reintroduced for bare-IP sources.
            //
            // `source_constrained` records whether the rule HAD a source
            // constraint at all (snapshot list non-empty), independent of how
            // many entries parsed. It drives the fail-closed distinction in
            // `source_matches`: a rule that WAS scoped but whose entries ALL
            // failed to parse must match NOTHING, not everything.
            let source_constrained = !snap.source_addresses.is_empty();
            let mut source_v4: Vec<PrefixV4> = Vec::new();
            let mut source_v6: Vec<PrefixV6> = Vec::new();
            for prefix in &snap.source_addresses {
                match prefix.parse::<IpNet>() {
                    Ok(IpNet::V4(net)) => source_v4.push(PrefixV4::from_net(net)),
                    Ok(IpNet::V6(net)) => source_v6.push(PrefixV6::from_net(net)),
                    // Bare host IP fallback -> /32 or /128.
                    Err(_) => match prefix.parse::<IpAddr>() {
                        Ok(IpAddr::V4(v4)) => {
                            if let Ok(net) = Ipv4Net::new(v4, 32) {
                                source_v4.push(PrefixV4::from_net(net));
                            }
                        }
                        Ok(IpAddr::V6(v6)) => {
                            if let Ok(net) = Ipv6Net::new(v6, 128) {
                                source_v6.push(PrefixV6::from_net(net));
                            }
                        }
                        // #5190: an entry that is neither a CIDR prefix nor a
                        // bare host IP is DROPPED from the parsed list. The
                        // rule keeps `source_constrained`, so `source_matches`
                        // still fails CLOSED (#2394) — but before #5190 the
                        // drop was also SILENT, so an operator whose DNAT rule
                        // stopped matching had no signal that its only source
                        // entry never reached the dataplane. Fail-closed is
                        // the right behaviour; being quiet about it is not.
                        Err(_) => nat_counters.record_parse_error(&format!(
                            "DNAT rule {:?}: unparseable match source-address {:?} \
                             (entry dropped; rule stays source-scoped and fails closed)",
                            snap.name, prefix
                        )),
                    },
                }
            }
            // #3437: parse the application-derived L4 match constraints. A
            // source-port range with low > high is the never-match sentinel and
            // is preserved verbatim (it can never satisfy `port_in_ranges`).
            let mut match_src_ports: Vec<(u16, u16)> = Vec::with_capacity(snap.match_source_ports.len());
            for r in &snap.match_source_ports {
                match_src_ports.push((r.low, r.high));
            }
            // #3449: the multi-port destination-port range constraint. A low>high
            // range is the impossible never-match form and is preserved verbatim
            // (it can never satisfy `port_in_ranges`). Empty = no range
            // constraint — the entry's exact/wildcard `destination_port` governs.
            let mut match_dst_ports: Vec<(u16, u16)> =
                Vec::with_capacity(snap.match_destination_ports.len());
            for r in &snap.match_destination_ports {
                match_dst_ports.push((r.low, r.high));
            }
            let entry = DnatEntry {
                from_zone: snap.from_zone.clone().into_boxed_str(),
                from_interface: snap.from_interface.clone().into_boxed_str(),
                from_routing_instance: snap.from_routing_instance.clone().into_boxed_str(),
                source_constrained,
                source_v4,
                source_v6,
                match_src_ports,
                match_dst_ports,
                match_icmp_type: snap.match_icmp_type,
                match_icmp_code: snap.match_icmp_code,
                off: snap.off,
                value: DnatValue {
                    new_dst_ip: pool_ip,
                    new_dst_port: if snap.pool_port != 0 {
                        snap.pool_port
                    } else {
                        snap.destination_port
                    },
                },
                hit_counter,
            };
            // #3164: route a host to the O(1) exact map and a non-host prefix to
            // the longest-prefix-match table. Both translate to the same pool
            // (many:1 for a prefix) — block-mapping (1:1 offset) is out of scope.
            match dest {
                DnatDest::Host(dst_ip) => {
                    Self::insert_entry(
                        table.entries.entry(DnatKey {
                            protocol: proto,
                            dst_ip,
                            dst_port: snap.destination_port,
                        }),
                        entry,
                    );
                }
                DnatDest::Prefix { v4, v6 } => {
                    Self::insert_prefix_slot(
                        table.prefix_entries.entry(DnatProtoPortKey {
                            protocol: proto,
                            dst_port: snap.destination_port,
                        }),
                        DnatPrefixSlot { v4, v6, entry },
                    );
                }
            }
        }
        table
    }

    /// Look up a DNAT entry for the given packet fields.
    ///
    /// 1. Exact match: `(protocol, dst_ip, dst_port)`
    /// 2. Wildcard port fallback: `(protocol, dst_ip, 0)`
    /// 3. #2396 protocol-wildcard fallback: `(PROTO_ANY, dst_ip, 0)` — an
    ///    IP-only / any-protocol DNAT rule that covers ALL L4 protocols
    ///    (incl. ICMP/ICMPv6/GRE). Tried last so a concrete-protocol or
    ///    concrete-port rule always wins over the catch-all.
    ///
    /// Returns just the decision; existing callers/tests keep their
    /// `Option<NatDecision>` shape. The cold path uses
    /// [`lookup_with_counter`] (#2218) to also obtain the matched rule's
    /// per-rule hit counter — `NatDecision` (wire-frozen over HA) does NOT
    /// grow a field.
    /// Test/back-compat convenience wrapper: the original
    /// `(protocol, src_ip, dst_ip, dst_port, ingress_zone)` shape with no
    /// source-port and no ICMP type/code awareness (#3437). It supplies
    /// `src_port = 0` and `packet_icmp = None`, so a rule carrying an
    /// application source-port (H10) or ICMP type/code (H11) constraint fails
    /// closed here — exercise those via [`lookup_with_counter`]. Production
    /// uses [`lookup_with_counter_scoped`] with the real flow fields.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn lookup(
        &self,
        protocol: u8,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        ingress_zone: &str,
    ) -> Option<NatDecision> {
        self.lookup_with_counter(protocol, src_ip, dst_ip, 0, dst_port, ingress_zone, None)
            .map(|(decision, _)| decision)
    }

    /// #2218: as [`lookup`] but also returns the matched entry's per-rule
    /// hit counter (if any), for the cold-path commit site.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn lookup_with_counter(
        &self,
        protocol: u8,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        ingress_zone: &str,
        packet_icmp: Option<(u8, u8)>,
    ) -> Option<(NatDecision, Option<Arc<NatRuleCounter>>)> {
        // Unscoped wrapper: empty interface/RI scope = wildcard (pre-#3096).
        self.lookup_with_counter_scoped(
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            ingress_zone,
            "",
            "",
            packet_icmp,
        )
    }

    /// #3096: as [`lookup_with_counter`] but additionally gates each candidate
    /// on the DNAT rule's `from interface` / `from routing-instance` scope
    /// against the packet's INGRESS interface config-name and routing-instance.
    /// Empty scope fields are wildcards. The zone-tier precedence (zone-
    /// specific wins over zone-wildcard) and #3164 LPM ordering are unchanged;
    /// the scope is an additional AND filter on eligibility.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn lookup_with_counter_scoped(
        &self,
        protocol: u8,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        ingress_zone: &str,
        ingress_ifname: &str,
        ingress_routing_instance: &str,
        packet_icmp: Option<(u8, u8)>,
    ) -> Option<(NatDecision, Option<Arc<NatRuleCounter>>)> {
        // #4074: whether the inbound protocol carries a rewritable 16-bit L4
        // port (TCP/UDP). A port-less protocol (ICMP/ICMPv6/GRE/...) has no L4
        // port, so a DNAT rule must NEVER attach a translated destination port
        // to it — captured here before `protocol` is widened to the u16 key
        // space below. Without this, an UNSCOPED pool DNAT rule (no `match
        // destination-port`) whose pool carries a `port` would set
        // `rewrite_dst_port = Some(pool_port)` for an ICMP echo, and the SNAT
        // ICMP-identifier rewriter (`apply_nat_icmp_identifier_rewrite`) would
        // then corrupt the ICMP Query Identifier to the pool port. ICMP DNAT
        // must stay address-only (the pre-#4074 behaviour).
        let protocol_has_l4_ports = crate::ip_proto::has_l4_ports(protocol);
        // The inbound packet protocol is a real IANA byte; widen it to the
        // u16 key space. The wildcard sentinel (PROTO_ANY = 256) is OUTSIDE
        // this range, so a real packet — even one carrying protocol 0 (HOPOPT)
        // — can never alias the wildcard entry on the exact/port-wildcard
        // probes; the wildcard is only reached via the explicit final fallback.
        let protocol = u16::from(protocol);
        let outcome = self
            .match_entries(
                self.entries.get(&DnatKey {
                    protocol,
                    dst_ip,
                    dst_port,
                }),
                src_ip,
                src_port,
                dst_port,
                ingress_zone,
                ingress_ifname,
                ingress_routing_instance,
                packet_icmp,
            )
            .or_else(|| {
                self.match_entries(
                    self.entries.get(&DnatKey {
                        protocol,
                        dst_ip,
                        dst_port: 0,
                    }),
                    src_ip,
                    src_port,
                    dst_port,
                    ingress_zone,
                    ingress_ifname,
                    ingress_routing_instance,
                    packet_icmp,
                )
            })
            .or_else(|| {
                // #2396: protocol-wildcard, IP-only DNAT — matches any L4
                // protocol (ICMP/ICMPv6/GRE/...) to this destination. Only
                // reached when no concrete (protocol, port) entry matched, so
                // a specific rule always wins. PROTO_ANY (256) is distinct
                // from every real protocol, so this probe targets exactly the
                // IP-only entries and a `protocol 0`/HOPOPT exact rule is never
                // conflated with the catch-all.
                self.match_entries(
                    self.entries.get(&DnatKey {
                        protocol: PROTO_ANY,
                        dst_ip,
                        dst_port: 0,
                    }),
                    src_ip,
                    src_port,
                    dst_port,
                    ingress_zone,
                    ingress_ifname,
                    ingress_routing_instance,
                    packet_icmp,
                )
            })
            .or_else(|| {
                // #3164: longest-prefix-match fallback. Reached only when no
                // exact-host entry matched — a host (/32, /128) is the longest
                // possible prefix, so the exact map always wins. Within the
                // prefix table the same three proto/port tiers apply (exact
                // proto+port, then wildcard port, then PROTO_ANY), and within a
                // tier the LONGEST matching prefix wins.
                self.match_prefix_lpm(
                    protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    ingress_zone,
                    ingress_ifname,
                    ingress_routing_instance,
                    packet_icmp,
                )
            });
        // #3844: map the winning tier's outcome to a decision. A `then
        // destination-nat off` exemption (Exempt) — or no matching rule (None)
        // — produces NO DNAT decision. The `.or_else` chain already
        // short-circuited at the tier where an Exempt matched (Exempt is a
        // non-None value, so a broader tier was never probed), giving the Junos
        // "matched rule wins, stop evaluation" semantic: a later/broader DNAT
        // rule cannot re-translate the exempted flow.
        let (value, hit_counter) = match outcome {
            Some(DnatOutcome::Translate(v, c)) => (v, c),
            Some(DnatOutcome::Exempt) | None => return None,
        };
        // #4074: gate the destination-port translation on the protocol actually
        // carrying an L4 port. A port-less protocol (ICMP/ICMPv6/GRE/...) keeps
        // `rewrite_dst_port = None` — address-only DNAT — so a pooled-port DNAT
        // rule can never smuggle a spurious L4 port onto an ICMP flow (which
        // would otherwise drive the ICMP-identifier rewriter to corrupt the
        // Query Identifier).
        let rewrite_dst_port =
            if protocol_has_l4_ports && value.new_dst_port != 0 && value.new_dst_port != dst_port {
                Some(value.new_dst_port)
            } else {
                None
            };
        Some((
            NatDecision {
                rewrite_src: None,
                rewrite_dst: Some(value.new_dst_ip),
                rewrite_src_port: None,
                rewrite_dst_port,
                nat64: false,
                nptv6: false,
            },
            hit_counter,
        ))
    }
    /// Whether a fragment whose shim metadata carries the protocol-unknown
    /// sentinel would match any same-family DNAT translation. Probe concrete
    /// protocols represented by host/prefix buckets and at most one
    /// unrepresented protocol for protocol-agnostic rules. This preserves exact
    /// rule matching without recovering the fragment's real protocol or
    /// performing 255 table lookups.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn has_unknown_protocol_translation_match_scoped(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        ingress_zone: &str,
        ingress_ifname: &str,
        ingress_routing_instance: &str,
        packet_icmp: Option<(u8, u8)>,
    ) -> bool {
        let fragment_sentinel = u16::from(crate::session::SHIM_PROTO_FRAGMENT_NO_L4);
        let mut configured_protocols = [0u64; 4];
        for key in self.entries.keys() {
            if key.protocol < fragment_sentinel
                && key.dst_ip == dst_ip
                && key.dst_port == dst_port
            {
                let protocol = key.protocol as usize;
                configured_protocols[protocol / 64] |= 1u64 << (protocol % 64);
            }
        }
        for (key, slots) in &self.prefix_entries {
            if key.protocol < fragment_sentinel
                && key.dst_port == dst_port
                && slots.iter().any(|slot| slot.contains(dst_ip))
            {
                let protocol = key.protocol as usize;
                configured_protocols[protocol / 64] |= 1u64 << (protocol % 64);
            }
        }
        let matches_protocol = |protocol| {
            self.lookup_with_counter_scoped(
                protocol,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                ingress_zone,
                ingress_ifname,
                ingress_routing_instance,
                packet_icmp,
            )
            .is_some()
        };
        let mut wildcard_probe_done = false;
        for protocol in 0..usize::from(fragment_sentinel) {
            let configured = configured_protocols[protocol / 64] & (1u64 << (protocol % 64)) != 0;
            if configured || !wildcard_probe_done {
                if matches_protocol(protocol as u8) {
                    return true;
                }
                wildcard_probe_done |= !configured;
            }
        }
        false
    }


    #[allow(clippy::too_many_arguments)]
    fn match_entries(
        &self,
        entries: Option<&Vec<DnatEntry>>,
        src_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        ingress_zone: &str,
        ingress_ifname: &str,
        ingress_routing_instance: &str,
        packet_icmp: Option<(u8, u8)>,
    ) -> Option<DnatOutcome> {
        let entries = entries?;
        // #2394: an entry only fires when its zone, source-address, AND #3096
        // interface/routing-instance scope all match. #3437: the application's
        // source-port (H10) and ICMP type/code (H11) constraints are AND-ed in
        // too. Zone-specific entries still win over zone-wildcard entries, but
        // within each tier every constraint must hold — an entry whose source,
        // interface/RI scope, source-port, or ICMP type/code does not match the
        // packet is skipped (no fail-open).
        //
        // #3844: WITHIN a tier the first matching entry (zone-specific, then
        // zone-wildcard) determines the outcome via `to_outcome` — a `then
        // destination-nat off` entry yields `Exempt` (no translation), any
        // other entry yields `Translate`. An `Exempt` (a `Some(..)`) halts the
        // cross-tier `.or_else` chain, so it short-circuits the LOWER tiers.
        // NOTE ON PRECEDENCE: across tiers this is MOST-SPECIFIC-WINS (exact
        // (proto,dst,port) > wildcard-port > proto-any > prefix-LPM), NOT strict
        // Junos config order. A more-specific *later* translate rule beats a
        // broader *earlier* off rule (same tier-precedence the DnatTable applies
        // to translate-vs-translate, #3164). To exempt traffic that a translate
        // rule would otherwise catch, the `off` rule must be at least as
        // specific as that translate rule (typically the same match tier).
        entries
            .iter()
            .find(|entry| {
                !entry.from_zone.is_empty()
                    && entry.from_zone.as_ref() == ingress_zone
                    && entry.scope_ok(ingress_ifname, ingress_routing_instance)
                    && entry.source_matches(src_ip)
                    && entry.l4_extra_matches(src_port, dst_port, packet_icmp)
            })
            .or_else(|| {
                entries.iter().find(|entry| {
                    entry.from_zone.is_empty()
                        && entry.scope_ok(ingress_ifname, ingress_routing_instance)
                        && entry.source_matches(src_ip)
                        && entry.l4_extra_matches(src_port, dst_port, packet_icmp)
                })
            })
            .map(|entry| entry.to_outcome())
    }

    /// #3164: longest-prefix-match over the non-host prefix table. Mirrors the
    /// exact-host probe order — exact `(protocol, dst_port)`, then wildcard port
    /// `(protocol, 0)`, then `(PROTO_ANY, 0)` — so proto/port specificity is
    /// honored the same way for prefixes; within each tier the LONGEST matching
    /// prefix wins. Returns the first tier that yields a match.
    #[allow(clippy::too_many_arguments)]
    fn match_prefix_lpm(
        &self,
        protocol: u16,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        ingress_zone: &str,
        ingress_ifname: &str,
        ingress_routing_instance: &str,
        packet_icmp: Option<(u8, u8)>,
    ) -> Option<DnatOutcome> {
        self.match_prefix_slots(
            self.prefix_entries.get(&DnatProtoPortKey {
                protocol,
                dst_port,
            }),
            dst_ip,
            src_ip,
            src_port,
            dst_port,
            ingress_zone,
            ingress_ifname,
            ingress_routing_instance,
            packet_icmp,
        )
        .or_else(|| {
            self.match_prefix_slots(
                self.prefix_entries.get(&DnatProtoPortKey {
                    protocol,
                    dst_port: 0,
                }),
                dst_ip,
                src_ip,
                src_port,
                dst_port,
                ingress_zone,
                ingress_ifname,
                ingress_routing_instance,
                packet_icmp,
            )
        })
        .or_else(|| {
            self.match_prefix_slots(
                self.prefix_entries.get(&DnatProtoPortKey {
                    protocol: PROTO_ANY,
                    dst_port: 0,
                }),
                dst_ip,
                src_ip,
                src_port,
                dst_port,
                ingress_zone,
                ingress_ifname,
                ingress_routing_instance,
                packet_icmp,
            )
        })
    }

    /// #3164: pick the best prefix slot for a destination IP within one
    /// proto/port bucket. Zone-specific entries win over zone-wildcard entries
    /// (mirroring `match_entries`); within each zone tier the LONGEST matching
    /// prefix whose source-address constraint holds wins, and the FIRST such
    /// slot in insertion order breaks a same-length tie (deterministic).
    #[allow(clippy::too_many_arguments)]
    fn match_prefix_slots(
        &self,
        slots: Option<&Vec<DnatPrefixSlot>>,
        dst_ip: IpAddr,
        src_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        ingress_zone: &str,
        ingress_ifname: &str,
        ingress_routing_instance: &str,
        packet_icmp: Option<(u8, u8)>,
    ) -> Option<DnatOutcome> {
        let slots = slots?;
        let best_in_tier = |zone_specific: bool| -> Option<&DnatPrefixSlot> {
            let mut best: Option<&DnatPrefixSlot> = None;
            for slot in slots {
                let zone_ok = if zone_specific {
                    !slot.entry.from_zone.is_empty()
                        && slot.entry.from_zone.as_ref() == ingress_zone
                } else {
                    slot.entry.from_zone.is_empty()
                };
                if !zone_ok
                    || !slot.entry.scope_ok(ingress_ifname, ingress_routing_instance)
                    || !slot.contains(dst_ip)
                    || !slot.entry.source_matches(src_ip)
                    || !slot.entry.l4_extra_matches(src_port, dst_port, packet_icmp)
                {
                    continue;
                }
                // STRICTLY-greater replacement keeps the first slot among equal
                // prefix lengths (deterministic on overlap ambiguity).
                if best.is_none_or(|b| slot.prefix_len() > b.prefix_len()) {
                    best = Some(slot);
                }
            }
            best
        };
        best_in_tier(true)
            .or_else(|| best_in_tier(false))
            .map(|slot| slot.entry.to_outcome())
    }

    /// #3164: dedup-insert a prefix slot. Like `insert_entry`, two slots with the
    /// same (from_zone, source constraint) AND the same prefix are the same rule
    /// and the later one replaces the earlier; distinct prefixes or distinct
    /// source scopes are retained.
    fn insert_prefix_slot(
        slot: std::collections::hash_map::Entry<'_, DnatProtoPortKey, Vec<DnatPrefixSlot>>,
        new_slot: DnatPrefixSlot,
    ) {
        let slots = slot.or_default();
        if let Some(existing) = slots.iter_mut().find(|existing| {
            existing.v4 == new_slot.v4
                && existing.v6 == new_slot.v6
                && existing.entry.from_zone == new_slot.entry.from_zone
                // #3096: scope-distinct rules (same zone/prefix/source but a
                // different interface/RI scope) are distinct entries.
                && existing.entry.from_interface == new_slot.entry.from_interface
                && existing.entry.from_routing_instance == new_slot.entry.from_routing_instance
                && existing.entry.source_constrained == new_slot.entry.source_constrained
                && existing.entry.source_v4 == new_slot.entry.source_v4
                && existing.entry.source_v6 == new_slot.entry.source_v6
                // #3437: the application-derived L4 match (source-port, ICMP
                // type/code) is part of the rule identity. Two terms of one
                // application-set can share (zone, prefix, source, proto, port)
                // yet differ only in ICMP type (e.g. echo-request vs reply) —
                // both must be retained, not deduped onto each other.
                && existing.entry.match_src_ports == new_slot.entry.match_src_ports
                // #3449: destination-port range is part of the rule identity.
                && existing.entry.match_dst_ports == new_slot.entry.match_dst_ports
                && existing.entry.match_icmp_type == new_slot.entry.match_icmp_type
                && existing.entry.match_icmp_code == new_slot.entry.match_icmp_code
                // #3844: an off (exemption) rule and a translate rule that share
                // an otherwise-identical match are DISTINCT — both must be
                // retained so the exemption can win by insertion (config) order.
                // Deduping them would collapse one onto the other and either
                // drop the exemption (fail-open) or drop the translation.
                && existing.entry.off == new_slot.entry.off
        }) {
            *existing = new_slot;
            return;
        }
        slots.push(new_slot);
    }

    fn insert_entry(
        slot: std::collections::hash_map::Entry<'_, DnatKey, Vec<DnatEntry>>,
        entry: DnatEntry,
    ) {
        let entries = slot.or_default();
        // #2394: dedup on (from_zone, source constraint). Two distinct
        // source-scoped DNAT rules in the same from-zone with the same
        // (proto, dst, port) are NOT the same entry — both must be retained so
        // each fires only for its configured source. Keying dedup on zone alone
        // would drop one and silently broaden/narrow the other. `source_constrained`
        // is part of the key so an UNSCOPED rule (match-any) and a fully-malformed
        // SCOPED rule (fail-closed) — both with empty prefix vecs — never collapse
        // onto each other.
        if let Some(existing) = entries.iter_mut().find(|existing| {
            existing.from_zone == entry.from_zone
                // #3096: interface/RI scope is part of the rule identity.
                && existing.from_interface == entry.from_interface
                && existing.from_routing_instance == entry.from_routing_instance
                && existing.source_constrained == entry.source_constrained
                && existing.source_v4 == entry.source_v4
                && existing.source_v6 == entry.source_v6
                // #3437: application-derived L4 match (source-port, ICMP
                // type/code) is part of the rule identity — see
                // insert_prefix_slot.
                && existing.match_src_ports == entry.match_src_ports
                // #3449: the destination-port range is part of the rule
                // identity — two range rules sharing (zone, dst, proto) but a
                // different range are distinct entries, both retained.
                && existing.match_dst_ports == entry.match_dst_ports
                && existing.match_icmp_type == entry.match_icmp_type
                && existing.match_icmp_code == entry.match_icmp_code
                // #3844: an off (exemption) rule and a translate rule sharing an
                // otherwise-identical match are DISTINCT entries — see
                // insert_prefix_slot. Both are retained; the earlier-inserted
                // (config-order-first) entry wins in match_entries' `.find()`.
                && existing.off == entry.off
        }) {
            *existing = entry;
            return;
        }
        entries.push(entry);
    }

    /// Returns true if the table has any entries (exact-host or prefix).
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.prefix_entries.is_empty()
    }

    /// #3164: cold-path cap on whole-block proxy-ARP/ND expansion. A DNAT
    /// destination prefix whose usable-host count is at or below this bound is
    /// expanded host-by-host into the local-address set so the firewall answers
    /// for the entire block on a directly-connected segment; a larger block
    /// registers only its network base and relies on the block being ROUTED to
    /// the firewall (no proxy-ARP), which is the usual deployment. The bound
    /// keeps a fat /16-or-shorter from exploding `local_v4`/`local_v6` (a /20 is
    /// the smallest v4 prefix that still expands).
    pub(crate) const MAX_LOCAL_PREFIX_HOSTS: u32 = 4096;

    /// Returns all destination IPs (the external/public IPs that DNAT rules match on).
    /// These must be registered as local addresses so traffic to them is recognized.
    ///
    /// #3164: exact-host destinations contribute their IP. A non-host prefix
    /// contributes its usable hosts when the block is small enough
    /// (`MAX_LOCAL_PREFIX_HOSTS`) so proxy-ARP/ND works for a directly-connected
    /// DNAT block; a larger block contributes only its network base (it must be
    /// routed to the firewall). The DNAT MATCH itself is independent of this set
    /// (the pre-routing lookup keys on the packet destination directly), so a
    /// large block is still fully translated — only on-segment proxy-ARP is
    /// bounded.
    pub(crate) fn destination_ips(&self) -> impl Iterator<Item = IpAddr> {
        // Deduplicate by collecting unique dst_ip values. #3769: implemented
        // on top of `destination_ips_scoped` so the set of registered local
        // IPs (and the block-expansion bound) can never drift between the two
        // views.
        let mut seen: FxHashMap<IpAddr, ()> = FxHashMap::default();
        for (ip, _instance) in self.destination_ips_scoped() {
            seen.entry(ip).or_insert(());
        }
        seen.into_keys()
    }

    /// #3769: like [`destination_ips`], but pairs each destination IP with the
    /// `from routing-instance` scope of the owning DNAT rule ("" = the default
    /// instance / global). The forwarding-state builder converts the routing
    /// instance to a canonical route table and records the attribution in
    /// `local_tables_v*`, so the local-delivery shortcut is gated on the
    /// resolving VRF rather than the global `local_v*` membership (the #3769
    /// cross-VRF local-delivery leak). Not deduplicated — a destination IP can
    /// legitimately be owned by DNAT rules in more than one routing-instance;
    /// the builder inserts into a per-IP set of tables. The same
    /// `MAX_LOCAL_PREFIX_HOSTS`-bounded prefix expansion as `destination_ips`
    /// is applied so on-segment proxy-ARP/ND parity is preserved.
    pub(crate) fn destination_ips_scoped(&self) -> Vec<(IpAddr, &str)> {
        let mut out: Vec<(IpAddr, &str)> = Vec::new();
        for (key, entries) in &self.entries {
            for entry in entries {
                // #3844: a `then destination-nat off` exemption must NOT
                // register its destination as a firewall-local address — the
                // exempted destination is a real host reachable via routing,
                // not a VIP the firewall owns, so proxy-ARP/ND for it would
                // hijack that host's traffic on a directly-connected segment.
                if entry.off {
                    continue;
                }
                out.push((key.dst_ip, entry.from_routing_instance.as_ref()));
            }
        }
        // #6025: exact-host `off` exemptions that can shadow a translate prefix.
        // An exact-host entry is probed before ANY prefix in the DNAT lookup
        // (see `lookup_with_counter_scoped`), so a specific `/32 destination-nat
        // off` whose match scope is a SUPERSET of a broader translate prefix
        // ALWAYS wins the match for that host — it is never translated. The
        // bounded prefix expansion below would otherwise still register the
        // exempt host as a firewall-local proxy-ARP/ND target and LocalDeliver
        // its inbound traffic instead of routing it to the real host (the #6025
        // silent blackhole). Collected once; empty (the common case, no
        // exemptions) makes the per-host `shadowed` check a cheap no-op.
        let exact_off: Vec<(&DnatKey, &DnatEntry)> = self
            .entries
            .iter()
            .flat_map(|(key, entries)| entries.iter().filter(|e| e.off).map(move |e| (key, e)))
            .collect();
        // #9159: PREFIX-scoped `off` exemptions that can shadow a BROADER
        // translate prefix. The loop below already declines to register an `off`
        // slot's OWN addresses (`continue`), but that withdraws nothing from an
        // enclosing translate prefix whose expansion covers the same hosts - so a
        // `/26 destination-nat off` inside a `/24` translate rule left all 62
        // exempt hosts registered firewall-local while the DNAT match correctly
        // selected `off` for them. The two views disagreed and the exception
        // became a blackhole. #6025 fixed this for exact hosts; all four of its
        // tests use `/32`, which is why the prefix arm was never exercised.
        let prefix_off: Vec<(&DnatProtoPortKey, &DnatPrefixSlot)> = self
            .prefix_entries
            .iter()
            .flat_map(|(key, slots)| slots.iter().filter(|s| s.entry.off).map(move |s| (key, s)))
            .collect();
        for (proto_port, slots) in &self.prefix_entries {
            for slot in slots {
                if slot.entry.off {
                    continue;
                }
                let instance = slot.entry.from_routing_instance.as_ref();
                // #6025: a prefix-registered address is withdrawn when a
                // superset exact-host `off` exemption (see `exact_off`) shadows
                // it for THIS translate slot — the off wins the DNAT match for
                // that host, so registering it firewall-local would blackhole
                // the exempt host via LocalDelivery. A non-superset (partially
                // scoped) off never suppresses, so a genuinely-translated
                // address is preserved.
                let shadowed = |addr: IpAddr| -> bool {
                    exact_off.iter().any(|(off_key, off)| {
                        off_key.dst_ip == addr
                            && off_scope_superset(off_key, off, proto_port, &slot.entry)
                    })
                        // #9159: or a PREFIX-scoped `off` that CONTAINS this
                        // address and wins the match against this slot. Winning
                        // is the load-bearing half: an `off` that loses leaves
                        // the address genuinely translated, and withdrawing it
                        // would break the DNAT it was configured for. See
                        // `off_prefix_scope_superset` for the two match rules
                        // (same zone tier, strictly longer prefix).
                        || prefix_off.iter().any(|(off_key, off_slot)| {
                            off_slot.contains(addr)
                                && off_prefix_scope_superset(
                                    off_key, off_slot, proto_port, slot,
                                )
                        })
                };
                if let Some(net) = slot.network() {
                    // #5658: never register the UNSPECIFIED address (0.0.0.0 / ::)
                    // as a firewall-local / proxy-ARP / ND-owned target. A `/0`
                    // DNAT match prefix is a legitimate "all routed destinations"
                    // rule and is preserved — the pre-routing packet-path lookup
                    // keys on the destination directly and is INDEPENDENT of this
                    // local set, so translation for routed traffic still works.
                    // But its network base is the unspecified address, which is
                    // not an owned unicast VIP; registering it perturbs
                    // local-delivery classification and would proxy-ARP for
                    // 0.0.0.0. (Any prefix whose canonical base is unspecified —
                    // e.g. a `/0`, or the reserved 0.0.0.0/8 — is skipped; such a
                    // base is never a valid on-segment VIP.) Host expansion for a
                    // `/0` is already skipped by the MAX_LOCAL_PREFIX_HOSTS bound
                    // below (host_count is u32::MAX / None), so only the base push
                    // needed this guard.
                    if !net.is_unspecified() && !shadowed(net) {
                        out.push((net, instance));
                    }
                }
                match (slot.v4, slot.v6) {
                    (Some(p), _) => {
                        let hosts = host_count_v4(p.prefix_len());
                        if hosts <= Self::MAX_LOCAL_PREFIX_HOSTS {
                            if let Ok(net) =
                                Ipv4Net::new(p.addr(), p.prefix_len())
                            {
                                for host in net.hosts() {
                                    let ip = IpAddr::V4(host);
                                    if !shadowed(ip) {
                                        out.push((ip, instance));
                                    }
                                }
                            }
                        }
                    }
                    (_, Some(p)) => {
                        // Only expand a v6 block that is itself host-scale;
                        // anything shorter is astronomically large.
                        let hosts = host_count_v6(p.prefix_len());
                        if hosts.is_some_and(|h| h <= u128::from(Self::MAX_LOCAL_PREFIX_HOSTS)) {
                            if let Ok(net) =
                                Ipv6Net::new(p.addr(), p.prefix_len())
                            {
                                for host in net.hosts() {
                                    let ip = IpAddr::V6(host);
                                    if !shadowed(ip) {
                                        out.push((ip, instance));
                                    }
                                }
                            }
                        }
                    }
                    (None, None) => {}
                }
            }
        }
        out
    }
}

/// #3437: is `port` within any inclusive (low, high) range in `ranges`? A range
/// with low > high (the never-match sentinel) is never satisfied. Mirrors the
/// source-NAT `port_in_ranges` in `nat/source.rs`.
fn port_in_ranges(port: u16, ranges: &[(u16, u16)]) -> bool {
    ranges.iter().any(|&(lo, hi)| port >= lo && port <= hi)
}

/// #3164: usable host count of an IPv4 prefix (saturating; /0 -> u32::MAX).
fn host_count_v4(prefix_len: u8) -> u32 {
    match 32u32.checked_sub(u32::from(prefix_len)) {
        Some(host_bits) if host_bits < 32 => 1u32 << host_bits,
        _ => u32::MAX,
    }
}

/// #3164: usable host count of an IPv6 prefix; `None` if it overflows u128
/// (anything shorter than /1), which is always far above any local bound.
fn host_count_v6(prefix_len: u8) -> Option<u128> {
    match 128u32.checked_sub(u32::from(prefix_len)) {
        Some(host_bits) if host_bits < 128 => Some(1u128 << host_bits),
        _ => None,
    }
}

/// #6025: is the exact-host `off` exemption `off` (keyed `off_key`) a match-scope
/// SUPERSET of the translate prefix slot (`slot`, keyed `slot_key`)? That is,
/// does the exemption catch every packet the translate slot would? An exact-host
/// entry is probed before ANY prefix in the DNAT lookup, so when the exemption's
/// scope is a superset it is GUARANTEED to win the match for the shared
/// destination — the address is never translated by that slot and can be safely
/// withdrawn from the firewall-local set (it must be routed to the real host,
/// not LocalDelivered).
///
/// The test is deliberately conservative — each axis is a wildcard-or-equal
/// check, and the source and L4-application axes require the exemption to be
/// UNCONSTRAINED. A partially-scoped exemption (a specific source, port range,
/// ICMP type, protocol, or port that the translate does not fully share) leaves
/// some traffic to the address translated, so the address stays firewall-local.
/// This never over-suppresses, so a genuine DNAT-to-firewall VIP is never
/// blackholed.
fn off_scope_superset(
    off_key: &DnatKey,
    off: &DnatEntry,
    slot_key: &DnatProtoPortKey,
    slot: &DnatEntry,
) -> bool {
    // Zone: the exemption is zone-wildcard or shares the slot's from-zone.
    //
    // #9159: this clause is sound for an EXACT-HOST exemption and is NOT sound
    // for a prefix-scoped one, which is why the prefix arm uses
    // `off_prefix_scope_superset` rather than this function. An exact-host entry
    // is probed before ANY prefix (`lookup_with_counter_scoped`), so it wins the
    // match whatever tier the translate slot is in. Prefix-vs-prefix is decided
    // by `match_prefix_slots`, which runs the zone-SPECIFIC tier to exhaustion
    // before the zone-wildcard tier -- so a zone-wildcard `off` LOSES to a
    // zone-specific translate prefix and must not withdraw from it.
    (off.from_zone.is_empty() || off.from_zone == slot.from_zone)
        && off_scope_superset_common(off_key.protocol, off_key.dst_port, off, slot_key, slot)
}

/// #9159: the protocol / port / interface / routing-instance / source / L4
/// clauses shared by the exact-host and prefix-scoped `off` predicates.
///
/// Factored rather than duplicated on purpose. A hand-copied second list is a
/// third artifact that can drift from both, and this predicate is the one that
/// decides whether an address is withdrawn from firewall-local registration --
/// a clause missing on one side is either a blackhole (#9159) or a broken DNAT
/// (over-withdrawal), depending on which side lost it.
fn off_scope_superset_common(
    off_protocol: u16,
    off_dst_port: u16,
    off: &DnatEntry,
    slot_key: &DnatProtoPortKey,
    slot: &DnatEntry,
) -> bool {
    // Protocol: the exemption is keyed on the protocol wildcard (PROTO_ANY) or
    // exactly the slot's protocol.
    (off_protocol == PROTO_ANY || off_protocol == slot_key.protocol)
        // Port: the exemption is keyed on the wildcard port (0) or exactly the
        // slot's port.
        && (off_dst_port == 0 || off_dst_port == slot_key.dst_port)
        // Interface: interface-wildcard or the same from-interface (#3096).
        && (off.from_interface.is_empty() || off.from_interface == slot.from_interface)
        // Routing-instance: RI-wildcard or the same from-routing-instance.
        && (off.from_routing_instance.is_empty()
            || off.from_routing_instance == slot.from_routing_instance)
        // Source: the exemption must match ANY source — a source-scoped off
        // leaves other sources translated.
        && !off.source_constrained
        // L4 application constraints (#3437/#3449): the exemption must carry
        // none — a src-port / dst-port range or ICMP type/code constraint leaves
        // the complementary L4 traffic translated.
        && off.match_src_ports.is_empty()
        && off.match_dst_ports.is_empty()
        && off.match_icmp_type.is_none()
}

/// #9159: does a PREFIX-scoped `destination-nat off` slot win the DNAT match for
/// the addresses it covers, against this translate slot?
///
/// Only an `off` that WINS may withdraw an address from firewall-local
/// registration. Withdrawing one it loses is the opposite defect: the address is
/// genuinely translated, and dropping its proxy-ARP/ND registration breaks the
/// DNAT it was configured for. So the two match rules `match_prefix_slots`
/// implements are reproduced here, and both are necessary:
///
///   * SAME TIER. `best_in_tier(true)` (zone-specific) is run to exhaustion
///     before `best_in_tier(false)` (zone-wildcard), so a zone-wildcard `off`
///     never beats a zone-specific translate prefix. Equality of the zone
///     strings is the condition -- both empty, or both the same zone -- and it
///     is STRICTER than `off_scope_superset`'s zone clause, which is correct for
///     exact hosts (probed ahead of every prefix) and not for prefixes.
///   * STRICTLY LONGER. Within a tier the longest prefix wins, and
///     `match_prefix_slots` keeps the FIRST slot among equal lengths. An `off`
///     of equal length therefore may or may not win, depending on insertion
///     order, so it is not withdrawn. That under-withdrawal leaves the #9159
///     blackhole standing only for an ambiguous overlap, which is the safe
///     direction: over-withdrawal breaks working DNAT for every host in the
///     range.
fn off_prefix_scope_superset(
    off_key: &DnatProtoPortKey,
    off_slot: &DnatPrefixSlot,
    slot_key: &DnatProtoPortKey,
    slot: &DnatPrefixSlot,
) -> bool {
    off_slot.entry.from_zone == slot.entry.from_zone
        && off_slot.prefix_len() > slot.prefix_len()
        && off_scope_superset_common(
            off_key.protocol,
            off_key.dst_port,
            &off_slot.entry,
            slot_key,
            &slot.entry,
        )
}
