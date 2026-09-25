//! HA synced-session reservation.
//!
//! Reservation of a peer-synced session's source-NAT translation on this node.
//! Reaches back into `source` for exactly one item — `SourceNatRule::matches_ignoring_scope`,
//! which stays with the rest of the match predicates in `mod.rs`.
//!
//! #6988 PURE CODE MOTION: every line below was moved verbatim from
//! `nat/source.rs` lines 1838-2352. The only edits are the visibility
//! widenings enumerated in `source/mod.rs`; no logic, no ordering and no
//! signature changed.

use super::*;

/// #6211: the ACTIVE node's `(from_zone, to_zone)` NAME pair for a synced
/// session, when the standby could resolve BOTH from the wire-carried zone
/// IDs. `None` means "the active's zone pair is unknown here" — an old peer
/// that carried neither a zone id nor a resolvable zone name, or a zone that
/// is not in this node's snapshot (config drift) — and selects the pre-#6211
/// first-pool-match fallback rather than narrowing on a zone the standby is
/// guessing at.
pub(crate) type SyncedNatZones<'a> = Option<(&'a str, &'a str)>;

/// #4388: reserve a peer-synced session's translated pool port in THIS node's
/// local source-NAT allocator so a post-failover local allocation cannot hand
/// the same `(pool_addr, port)` to a new flow (NAT source collision / session
/// hijack surface).
///
/// The standby imports the active node's pre-computed NAT decision but never
/// calls `allocate_translation`, so its allocator has no record that
/// `(pool_addr, port)` is in use. Mirror `release_source_nat_allocation`'s
/// flow-key / translated-tuple construction EXACTLY so the same-key
/// `release_flow` / `rollback_flow` on the standard teardown path
/// (`release_source_nat_allocation`, already called for every reaped or
/// delete-synced session) frees the reservation — no new delete site.
///
/// A synced session with NO source NAT at all (`rewrite_src` unset — plain
/// forwarding) reserves nothing. If the synced pool address is not a member of
/// ANY local pool (config drift between nodes), the reserve is skipped
/// gracefully — it never panics and never fabricates a reservation on the wrong
/// pool.
///
/// #5338: an ADDRESS-ONLY source-NAT decision (`port no-translation` on a
/// port-bearing protocol, or a port-less protocol such as GRE/ESP) carries a
/// pool `rewrite_src` but NO `rewrite_src_port` — the wire keeps the packet's
/// own source port. The ACTIVE node (#5336 round-robin/persistent, #5341
/// deterministic-CGNAT) still MINTS a reverse-identity occupancy token for such
/// a flow via [`PortAllocator::reserve_address_only`], keyed on the translated
/// reverse identity (protocol, pool address, PRESERVED source port, remote), so
/// the reverse (1:N) index can disambiguate which internal flow owns a given
/// public tuple. The standby must mint the SAME token for a synced address-only
/// session; otherwise, after failover to it, its reverse index cannot
/// disambiguate the promoted session (and a fresh local address-only flow could
/// claim the same public identity the reverse index cannot tell apart). This
/// mirrors the active-node mint here; NO pool PORT bit is consumed. The token is
/// freed by the SAME teardown path as a PAT port
/// (`release_source_nat_allocation` -> `PortAllocator::release_flow`, already
/// called for every reaped or delete-synced session) — no new delete site. The
/// #6207 `deterministic` threading applies ONLY to the port-bearing
/// [`PortAllocator::reserve_flow`] arm; an address-only token carries no port
/// bit, so — exactly like the active node's #5341 path — it mints via the plain
/// `reserve_address_only` regardless of the pool's allocation mode.
///
/// #6211: WHICH rule the reservation lands on now mirrors the active node's
/// choice.
///
/// SCOPE — the motivating config is NOT reachable through a supported commit.
/// #5144 hard-rejects duplicate source-NAT pool addresses at strict commit
/// (`TestNAT5144ExactDuplicateSourcePools` asserts `CompileConfig` refuses
/// exactly this shape), so the live surface is the two paths that BYPASS the
/// strict compiler: a pre-#5144 persisted config, and the tolerant
/// load / peer-sync path (#1960 no-brick). That bounds the original defect's
/// severity — it is not an ordinary operator configuration.
///
/// Two source-NAT rules may carry the SAME pool ADDRESS in SEPARATE
/// allocators (distinct `pool_name` / port range => distinct `allocator_key`),
/// and the pre-#6211 selection — "the first rule whose pool CONTAINS
/// `rewrite_src`" — narrowed on NO other axis, while the active picked its rule
/// by zone/policy match. Under such a config the standby's reservation could
/// land in a DIFFERENT allocator than the active used for the same session, so
/// after a failover a new local flow matching the OTHER rule missed the
/// collision guard — the reverse-identity token sat in the wrong allocator,
/// reintroducing the reverse-path ambiguity the token exists to prevent.
///
/// The fix is LOCAL, not a wire change: every input the active's rule match
/// consumes is already synced. The zone pair rides the session-sync wire as
/// `ingress_zone_id`/`egress_zone_id` (`SessionSyncRequest`, resolved into
/// `SessionMetadata::ingress_zone`/`egress_zone`) and the 5-tuple IS the
/// session key, so the standby re-runs the active's own match predicate
/// ([`SourceNatRule::matches_ignoring_scope`]) instead of inventing a second
/// identity scheme. Only the #3096 interface / routing-instance scope is
/// node-local and unconfirmable; see that method for why it is treated as
/// unconstrained rather than as a mismatch. An unresolvable zone pair
/// (`synced_zones == None` — an old peer, or config drift) falls back to the
/// pre-#6211 first-pool-match, which is no worse than what shipped
/// (rolling-upgrade safe).
/// Reserve a synced translation WITHOUT recording a worker holder — the
/// pre-#6211-F2 contract. Production must use
/// [`reserve_synced_source_nat_allocation_for_worker`]; this entry point remains
/// for tests that exercise the single-holder semantics directly.
/// Compile-time completeness guard for #6211 F2: this untracked entry point is
/// TEST-ONLY, so a production caller that forgot to thread its `worker_id` is a
/// BUILD FAILURE in the non-test profile rather than a silent single-holder
/// release of a reservation every worker holds. Production uses the
/// `_for_worker` twin.
#[cfg(test)]
pub(crate) fn reserve_synced_source_nat_allocation(
    // #6751: see `reserve_synced_source_nat_allocation_with_holder`.
    iface_allocs: &InterfaceNatAllocators,
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    // #6211: see `SyncedNatZones`.
    synced_zones: SyncedNatZones<'_>,
    now_ns: u64,
) {
    reserve_synced_source_nat_allocation_with_holder(
        iface_allocs,
        rules,
        key,
        nat,
        is_reverse,
        synced_zones,
        now_ns,
        NatHolder::Untracked,
    );
}

/// #6211 F2: reserve a synced translation and record `worker_id` as a HOLDER.
///
/// `handle_upsert_synced` runs on EVERY worker (the entry is fanned out to each
/// worker's command queue) while the source-NAT allocator is a single shared
/// `Arc`, so the same `(flow, translated)` is reserved N times. Recording each
/// worker's bit is what lets the release path free the port only after the LAST
/// worker lets go — without it the first worker to reap or delete-sync the
/// session frees a port the other N-1 are still forwarding through.
pub(crate) fn reserve_synced_source_nat_allocation_for_worker(
    // #6751: see `reserve_synced_source_nat_allocation_with_holder`.
    iface_allocs: &InterfaceNatAllocators,
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    synced_zones: SyncedNatZones<'_>,
    // #6528: the stale-tuple eviction inside `reserve_flow` retires the
    // incumbent with release semantics, which re-arms a persistent lease's idle
    // expiry off a real clock.
    now_ns: u64,
    worker_id: u32,
) -> bool {
    reserve_synced_source_nat_allocation_with_holder(
        iface_allocs,
        rules,
        key,
        nat,
        is_reverse,
        synced_zones,
        now_ns,
        NatHolder::Worker(worker_id),
    )
}

/// #6600: the COORDINATOR-side reservation, taken BEFORE the shared session
/// entry is published.
///
/// It holds `NatHolder::Untracked`, which contributes no holder bit, so the
/// per-worker reservations that follow are absorbed rather than doubled:
/// `reserve_flow` finds the identical `(flow, translated)` already live and
/// takes its idempotent early-return, OR-ing the worker's bit in. The last
/// worker's release then empties the mask and frees the port exactly as before.
pub(crate) fn reserve_synced_source_nat_allocation_untracked(
    // #6751: see `reserve_synced_source_nat_allocation_with_holder`.
    iface_allocs: &InterfaceNatAllocators,
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    synced_zones: SyncedNatZones<'_>,
    now_ns: u64,
) -> bool {
    reserve_synced_source_nat_allocation_with_holder(
        iface_allocs,
        rules,
        key,
        nat,
        is_reverse,
        synced_zones,
        now_ns,
        NatHolder::Untracked,
    )
}

/// Returns whether this node can own a peer-synced source-NAT translation.
/// `true` means a source-NAT reservation was taken or is unnecessary (a reverse
/// entry, a NAT64 decision, or no `rewrite_src`); `false` means a candidate
/// source-NAT rule refused the tuple (#6600). NAT64 tuples belong exclusively
/// to `reserve_synced_nat64_allocation`: booking one here first makes that
/// allocator's peer check mistake the same import for a conflicting SNAT owner
/// (#10706).
///
/// Before #6600 the bool `reserve_synced_on_first_pool_owner` already computed
/// was discarded here, and the whole chain up to `handle_upsert_synced` returned
/// `()` — so a refusal was not returned, not counted and not logged. The
/// coordinator uses this return to refuse the import outright rather than
/// publishing a session whose translation names a port this node does not own.
fn reserve_synced_source_nat_allocation_with_holder(
    // #6751: the interface-mode identity registry. A peer-synced session
    // whose translated address is an EGRESS address (interface-mode SNAT)
    // owns no pool allocation at all, so the pool scan below answers
    // `NothingToReserve` for it. The standby must nevertheless hold that
    // identity BEFORE it ever mints locally: otherwise its first
    // post-failover admission would preserve a source port an imported live
    // session is already using, and the promoted node would carry the exact
    // ambiguity #6751 removes.
    iface_allocs: &InterfaceNatAllocators,
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    // #6211: see `SyncedNatZones`.
    synced_zones: SyncedNatZones<'_>,
    now_ns: u64,
    holder: NatHolder,
) -> bool {
    // NAT64's translated source belongs exclusively to its NAT64 allocator.
    // Reserving it in a peer source-NAT pool first makes the NAT64 leg's
    // peer-ownership check refuse this same import (#10706).
    if is_reverse || nat.nat64 {
        return true;
    }
    let Some(rewrite_src) = nat.rewrite_src else {
        return true;
    };
    let flow = SourceNatFlowKey {
        protocol: key.protocol,
        src_ip: key.src_ip,
        dst_ip: nat.rewrite_dst.unwrap_or(key.dst_ip),
        src_port: key.src_port,
        // #9388: the POST-DNAT destination port. See the twin line in
        // `release.rs` for the full reasoning — this is the RESERVE half of the
        // same record, and the two must be keyed identically or the standby
        // books a reservation the active's teardown can never free. It also
        // feeds PASS 1's `matches_ignoring_scope` filter below, so with the
        // pre-translation port the standby could select a rule the active never
        // matched whenever two rule-sets discriminate on `match
        // destination-port`.
        //
        // MUST move together with `release.rs`.
        dst_port: nat.rewrite_dst_port.unwrap_or(key.dst_port),
        // #9062: the same domain the session layer stamped, so this key matches
        // the one the match path built.
        routing_scope: key.routing_domain,
    };
    // #6211 PASS 1 — reserve on a rule the ACTIVE node could actually have
    // matched. `flow` is byte-identical to the active's SNAT-match tuple
    // (`nat_match_flow.forward_key` in `poll_descriptor`: original source,
    // POST-DNAT destination ADDRESS **and PORT**, original source port).
    // #9388: the port half of that claim was FALSE between #9034 and #9388 —
    // #9034 moved the active's match/allocate tuple onto `policy_dst_port`
    // while this key stayed on the pre-translation `key.dst_port`. It is true
    // again because the `dst_port` line above now reads `rewrite_dst_port`.
    // Feeding it back through the
    // SAME `matches_*` predicate reproduces the active's rule choice on every
    // axis the standby can see — and, like the active's
    // `match_source_nat_result_for_tuple`, takes the FIRST matching rule in
    // snapshot order (that order IS the Junos specificity precedence, #4161).
    // A synced session always carries a real L4 protocol, so `tuple_unknown`
    // is false — the address-only `match_source_nat` wrapper's sentinel
    // (#5687) does not apply here.
    if let Some((from_zone, to_zone)) = synced_zones {
        match reserve_synced_on_first_pool_owner(
            rules.iter().filter(|rule| {
                rule.matches_ignoring_scope(
                    from_zone,
                    to_zone,
                    flow.src_ip,
                    flow.dst_ip,
                    false,
                    flow.protocol,
                    flow.src_port,
                    flow.dst_port,
                )
            }),
            // #6979 F1: PASS 1 reproduces the active's choice, so it stops at
            // the first pool-owning candidate rather than searching for one
            // that accepts.
            true,
            flow,
            rewrite_src,
            nat.rewrite_src_port,
            now_ns,
            holder,
        ) {
            SyncedReserveOutcome::Reserved => return true,
            // #6979 F1: a PASS 1 REFUSAL is final. It does NOT fall through.
            //
            // A refusal here means the standby CAN see which rule the active
            // matched, that rule's pool owns the translated address, and its
            // allocator declined because a different live allocation already
            // holds the identity. Falling through asked PASS 2 the same
            // question with the narrowing removed, and PASS 2 answers by
            // taking the first rule whose pool merely CONTAINS the address —
            // so an overlapping sibling accepts and the session is published
            // with its reservation booked in an allocator the active never
            // used.
            //
            // That is not a smaller loss than refusing; it is a LATENT one.
            // Measured at the parent of this change, with two rules whose
            // pools both own 203.0.113.10 and a local squatter on
            // 203.0.113.10:20000 in rule A's allocator:
            //
            //   step1  accepted=true   A.used=1 (squatter)  B.used=1 (F)
            //   step2  squatter retires  A.used=0           B.used=1
            //   step3  new A-flow granted the SAME tuple F holds in B: true
            //
            // The import was ACCEPTED, F was recorded in B, and once the
            // squatter retired nothing in A knew about F — so A re-issued the
            // identity F is still live on. A refused import publishes nothing;
            // a wrong-allocator reservation is silent until failover.
            //
            // This deliberately weakens #6211's "no configuration can come out
            // of #6211 with FEWER reservations than it had" for the REFUSAL
            // case only. The trade is acceptable because the refusal is
            // OBSERVABLE: the coordinator's caller turns this `false` into
            // `SyncedImportOutcome::RejectedReserve` and bumps
            // `import_reserve_refused`, surfaced as
            // `xpf_userspace_synced_import_reserve_refused_total` (#8101),
            // whose help text already says those flows will not survive a
            // failover. Fail-loud is only the better half of this trade
            // because that counter exists, so the increment is bound by a test
            // rather than assumed.
            SyncedReserveOutcome::Refused => return false,
            // #7581 / #6751: NOT a refusal. No rule the standby can confirm as
            // a match owns the translated address — the shape interface-mode
            // SNAT always produces, and also what genuine config drift looks
            // like. This MUST still fall through, or interface-mode synced
            // sessions stop reserving anything and drift stops degrading
            // gracefully. The whole fix is that these two outcomes are
            // different answers and only one of them stops the search.
            SyncedReserveOutcome::NothingToReserve => {}
        }
    }
    // #6211 PASS 2 — the pre-#6211 behaviour, unchanged: the first rule whose
    // pool CONTAINS the translated address, with no zone/tuple narrowing.
    //
    // Reached when the zone pair is unknown (`synced_zones == None`), when NO
    // rule the standby can confirm as a match owns the address (the active
    // matched an interface-scoped rule under a config the standby cannot
    // reproduce, or the nodes' NAT config has drifted), or when every matching
    // candidate REFUSED the reservation (a local flow already owns the
    // identity). Keeping the fallback unconditional is deliberate: it is
    // exactly what shipped before this fix, so no configuration can come out
    // of #6211 with FEWER reservations than it had. Pass 1 can only move a
    // reservation to a better-justified allocator, never remove one.
    // #7581: PASS 2's answer decides. `NothingToReserve` — no rule's pool owns
    // the translated address, the shape interface-mode source NAT always
    // produces — is NOT a refusal, and is answered exactly like the
    // `rewrite_src == None` early return above.
    match reserve_synced_on_first_pool_owner(
        rules.iter(),
        // PASS 2 keeps the pre-#6211 first-acceptor scan, byte-identical.
        // Bound by `pass2_still_falls_through_a_refusing_owner_6979_f1` — this
        // claim was unbound until then, and mutating it to `true` escaped the
        // entire suite (5125 collected, zero red).
        false,
        flow,
        rewrite_src,
        nat.rewrite_src_port,
        now_ns,
        holder,
    ) {
        // #6751: no rule's pool owns the translated address. #7581 established
        // that this is NOT a refusal; it is the shape interface-mode SNAT
        // ALWAYS produces, and this is where it acquires a domain of its own.
        SyncedReserveOutcome::NothingToReserve => {
            reserve_synced_interface_identity(iface_allocs, flow, rewrite_src, nat, now_ns, holder)
        }
        // `Reserved` publishes; `Refused` (a pool-owning candidate DECLINED —
        // a different live allocation owns the identity, #6600) does NOT, and
        // must NOT fall through to the interface domain, or two domains would
        // each hand out one translated identity (§5.3: the scan STOPS at
        // `Owned` and ABORTS at `IdentityConflict`). `may_publish` stays the
        // single place that encodes which outcomes block.
        other => other.may_publish(),
    }
}

/// #6751: the INTERFACE-registry arm of the synced-reserve domain scan.
///
/// Reached only when no pool owns the translated address (`NothingToReserve`),
/// which is exactly the interface-mode shape. Returns whether the caller may
/// publish the synced session.
///
/// IMPORT-DRIVEN CREATION is deliberate: this uses the same fallible
/// `allocator_for` the local mint uses, not the lookup-only accessor. A fresh
/// passive standby has an EMPTY registry, so a lookup-only reserve would record
/// nothing for every imported row, and the node's FIRST local mint after a
/// failover would then create an empty allocator and happily preserve a port an
/// imported live session already owns. Creating on import makes the standby's
/// registry mirror the active's occupied identities before any local mint runs.
///
/// A NAT64 decision is excluded: its reservation belongs to
/// `reserve_synced_nat64_allocation`, and taking a second token here would put
/// one flow in two domains.
fn reserve_synced_interface_identity(
    iface_allocs: &InterfaceNatAllocators,
    flow: SourceNatFlowKey,
    rewrite_src: IpAddr,
    nat: NatDecision,
    now_ns: u64,
    holder: NatHolder,
) -> bool {
    if nat.nat64 {
        return true;
    }
    let Some(alloc) = iface_allocs.allocator_for(rewrite_src) else {
        // The registry is at its cap with nothing reclaimable. Refuse the
        // import rather than publish a session whose identity this node does
        // not hold — the standby must never carry a session it cannot own.
        crate::nat::INTERFACE_SNAT_REGISTRY_CAP_EXHAUSTION.fetch_add(1, Ordering::Relaxed);
        return false;
    };
    // The active's decision names the translated port: `rewrite_src_port` when
    // it PAT'd the flow, the flow's own source port when it preserved it —
    // the same reconstruction `release_source_nat_allocation_with_mode` uses,
    // so the reservation and its eventual release name one tuple.
    let translated_port = nat.rewrite_src_port.unwrap_or(flow.src_port);
    match alloc.reserve_interface_identity(flow, rewrite_src, translated_port, now_ns, holder) {
        InterfaceDomainReserve::Owned => true,
        // An HA-fidelity loss, not a data-path drop: this synced session will
        // not survive a failover onto this node. Its OWN series, so it cannot
        // be mistaken for local admissions being dropped.
        InterfaceDomainReserve::IdentityConflict => {
            crate::nat::INTERFACE_SNAT_SYNC_IDENTITY_CONFLICT_DROPS.fetch_add(1, Ordering::Relaxed);
            false
        }
        // Out of bookkeeping capacity — the same event class the local
        // admission counts, reached from the import side.
        InterfaceDomainReserve::RegistryCap => {
            crate::nat::INTERFACE_SNAT_REGISTRY_CAP_EXHAUSTION.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}

/// #6211: reserve the synced translation on the first rule in `rules` whose
/// pool owns `rewrite_src` and which ACCEPTS the reservation. Returns whether
/// a reservation was taken. Both #6211 passes share this body, so the two
/// differ ONLY in which rules they are offered — the reservation semantics
/// (pool-mode gate, address-index math, address-only vs port-bearing arm,
/// per-rule fall-through) cannot drift between them.
/// The outcome of a synced-translation reservation attempt (#7581).
///
/// `reserve_synced_on_first_pool_owner` used to return a bare `bool`, which
/// collapsed two opposite situations into one `false`:
///
///   * a candidate rule's pool OWNS the translated address and its allocator
///     DECLINED — a genuine collision, and the case #6600 exists to refuse; and
///   * NO candidate owns the translated address at all, so there is nothing to
///     reserve.
///
/// The second is not a refusal. It is the same situation as a decision with no
/// `rewrite_src`, which the caller has always answered `true` to. Interface-mode
/// source NAT is exactly this case — the translated address is the egress
/// interface's own address, no rule is `pool_mode`, and no allocator has
/// anything to hand out — so every peer-synced import under interface-mode SNAT
/// read as a collision. `upsert_synced_session` refuses before
/// `publish_shared_session`, so since #6600 those sessions reached neither the
/// standby's shared `synced` map nor its worker tables, and the promoted node
/// had no state for them after a failover. It was invisible because the Go side
/// kept its BPF mirror row, which is what `show security flow session` reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncedReserveOutcome {
    /// A pool-owning candidate accepted the reservation.
    Reserved,
    /// A pool-owning candidate DECLINED — a different live allocation owns the
    /// translated identity (#6600). The import must be refused.
    Refused,
    /// No candidate rule's pool owns the translated address, so no allocator
    /// has anything to reserve. Not a refusal.
    NothingToReserve,
}

impl SyncedReserveOutcome {
    /// Whether the caller may publish the synced session. Only `Refused`
    /// blocks it.
    pub(crate) fn may_publish(self) -> bool {
        !matches!(self, SyncedReserveOutcome::Refused)
    }
}

/// #6979 F1: `stop_at_first_owner` makes the scan reproduce the ACTIVE node's
/// rule choice instead of searching for one that will say yes.
///
/// PASS 1 passes `true`. Its candidate set is already "rules the active could
/// have matched", in snapshot order — which IS the Junos specificity precedence
/// (#4161) the active itself resolves with. So the FIRST candidate whose pool
/// owns the translated address is the active's rule, and if that rule's
/// allocator declines, the honest answer is `Refused`. Walking on to the next
/// candidate answers a DIFFERENT question ("who will accept?") and books the
/// reservation in an allocator the active never used.
///
/// PASS 2 passes `false` and is byte-identical to before: it is the
/// un-narrowed pre-#6211 fallback for a zone pair the standby cannot resolve or
/// a config that has drifted, where "first rule whose pool contains the
/// address" is the only question that can be asked.
///
/// A QUARANTINED first owner (#7076) returns `Refused` under
/// `stop_at_first_owner` for the same reason it produced `Refused` before —
/// candidacy is kept, only the allocator is skipped — so blocking the import
/// still mirrors the active's `Unavailable`.
fn reserve_synced_on_first_pool_owner<'a>(
    rules: impl Iterator<Item = &'a SourceNatRule>,
    stop_at_first_owner: bool,
    flow: SourceNatFlowKey,
    rewrite_src: IpAddr,
    rewrite_src_port: Option<u16>,
    // #6528: threaded to `reserve_flow` for its stale-tuple eviction.
    now_ns: u64,
    // #6211 F2: the worker taking this reservation, so a fan-out to N workers
    // records N holders on ONE allocator record.
    holder: NatHolder,
) -> SyncedReserveOutcome {
    // #7581: `saw_candidate` records whether ANY rule's pool actually owned the
    // translated address. Without it, "no owner" and "every owner declined"
    // both fell out of the loop as the same value.
    let mut saw_candidate = false;
    for rule in rules {
        if !rule.pool_mode {
            continue;
        }
        // #5338: address-only synced decision (pool address chosen, source port
        // PRESERVED on the wire). Mint the reverse-identity occupancy token on
        // the rule whose pool owns `rewrite_src`, mirroring the active node's
        // #5336/#5341 mint so the reverse 1:N index disambiguates identically. A
        // collision on the standby (`Err` — a local flow already owns the
        // identity) or a foreign pool address (no pool member) leaves the rule
        // untouched and tries the next, matching the port-bearing arm's per-rule
        // fall-through and the config-drift skip.
        let Some(rewrite_src_port) = rewrite_src_port else {
            // #8132: `position`, not `any` — the absolute pool index (v6
            // folded after v4, matching `address_index`) is what the lease's
            // idle-expiry index is keyed on. `is_some()` is the same candidacy
            // predicate `any` gave, so the pool-membership decision below is
            // unchanged.
            let addr_index = match rewrite_src {
                IpAddr::V4(v4) => rule.pool_addresses_v4.iter().position(|a| *a == v4),
                IpAddr::V6(v6) => rule
                    .pool_addresses_v6
                    .iter()
                    .position(|a| *a == v6)
                    .map(|i| rule.pool_addresses_v4.len() + i),
            };
            let Some(addr_index) = addr_index else {
                continue;
            };
            saw_candidate = true;
            // #7076: a rule carrying a `pool_failure` OWNS the translated
            // address on paper but has no allocator a packet path will ever
            // consult — since #6812, `resolve_pool_allocators` marks a
            // budget-refused rule `OverBudget` while deliberately leaving
            // `pool_mode` true, the pool fully expanded, and the DEFAULT
            // `PortAllocator` in place. Mirror the ACTIVE node, which returns
            // `SourceNatLookup::Unavailable` for exactly this rule and fails the
            // flow CLOSED.
            //
            // SKIP THE ALLOCATOR, NOT THE CANDIDACY. `saw_candidate` is already
            // set above, and that is load-bearing: `continue`-ing BEFORE it —
            // the one-line fix the issue proposes — turns this outcome from
            // `Refused` into `NothingToReserve`, which pass 2 answers by falling
            // through to `reserve_synced_interface_identity`. Measured on
            // master: `may_publish` flips false -> true on BOTH arms, so a
            // pool-domain address is handed to the INTERFACE domain — the
            // two-domains-one-identity leak the pass-2 comment forbids. Blocking
            // the import is also what master already does, so this preserves
            // today's behaviour while removing its dependence on the shape of
            // `impl Default for PortAllocator`.
            if rule.pool_failure.is_some() {
                if stop_at_first_owner {
                    return SyncedReserveOutcome::Refused;
                }
                continue;
            }
            // #8132: hand the allocator this rule's persistence identity when
            // the rule runs `persistent-nat`, so the reservation JOINS the
            // source's lease (creating it on the first session) instead of
            // minting a bare reverse-identity token and no lease. Without this
            // the standby holds zero leases for every `port no-translation`
            // persistent client, and a failover moves the client's public
            // ADDRESS — which under an address-only rule is the entire property
            // the lease pins, since the client keeps its own source port on the
            // wire and there is no translated port to preserve.
            //
            // Derived through the SAME `persistent_source_key` helper the local
            // path and #7360's port-bearing arm call, from the same `flow` the
            // rule match used, so the standby's lease is keyed identically to
            // the active's — including the `permit` shape, which decides
            // whether the remote endpoint is folded in (#2823).
            let persistent = rule.persistent_nat.then(|| {
                (
                    flow.persistent_source_key(rule.persistent_nat_permit),
                    rule.persistent_nat_timeout_ns,
                )
            });
            if let Ok(translated) = rule.pool_allocator.reserve_address_only_maybe_persistent(
                flow,
                rewrite_src,
                addr_index,
                now_ns,
                holder,
                persistent,
            ) {
                // #8115 R2: the identity the ACTIVE node chose may be one a
                // LOCAL flow already owns in a PEER pool. `reserve_address_only`
                // checks only THIS allocator's `address_only_owners`, so the
                // import succeeded against a map that cannot see the peer, and
                // the coordinator would then publish it and let the reverse-map
                // insert displace the local owner.
                //
                // Refusing is not a new policy invented here — it is the policy
                // this function ALREADY applies to the same conflict inside one
                // allocator (a taken bit / an owned token returns `Refused` two
                // lines below). It is also observable by construction: `Refused`
                // is `may_publish() == false`, which the caller turns into
                // `SyncedImportOutcome::RejectedReserve` and counts on
                // `xpf_userspace_synced_import_reserve_refused_total`, whose
                // help text already says those flows will not survive a
                // failover. That counter is what makes fail-loud the better half
                // of the trade (#8101), and it is why "surface the conflict
                // rather than silently reserve" needs no new disposition.
                //
                // PASS 1 ONLY, and that gate is the whole design constraint.
                // `stop_at_first_owner` is what distinguishes the two passes,
                // and PASS 2 — reached when the zone pair CANNOT be resolved —
                // must stay byte-identical. That is an HA node's entire first
                // sync, before any snapshot is applied: there is no way to
                // reproduce the active's rule choice, so the only available
                // question is which rule's pool contains the address. Refusing
                // there rejects EVERY import on such a node.
                //
                // Measured, not reasoned: without this gate the change reds
                // `pass2_still_falls_through_a_refusing_owner_6979_f1`,
                // `coordinator_pre_publish_reserve_uses_the_workers_zone_pair_6600`
                // and two #6211 "frees both allocators" cells. #6979 F1 already
                // knew PASS 2 accepts into the wrong allocator — its own comment
                // measures the three-step latent loss — and left it deliberately
                // for exactly this reason.
                //
                // Within PASS 1 the address is fixed by the WIRE, so no sibling
                // rule can reach a different one and there is nothing to fall
                // through to.
                if stop_at_first_owner && peer_owns_wire_identity(rule, flow, translated) {
                    rule.pool_allocator
                        .rollback_flow(flow, translated, now_ns, holder);
                    return SyncedReserveOutcome::Refused;
                }
                return SyncedReserveOutcome::Reserved;
            }
            // #6979 F1: the active's rule declined. Under `stop_at_first_owner`
            // that is the answer, not a reason to ask a sibling.
            if stop_at_first_owner {
                return SyncedReserveOutcome::Refused;
            }
            continue;
        };
        // The absolute allocator address index mirrors the allocation path:
        // v4 addresses occupy `[0, len_v4)`, v6 addresses follow at
        // `[len_v4, len_v4 + len_v6)` (see `address_index` / the v6_offset in
        // `match_source_nat_result_for_tuple`).
        let addr_index = match rewrite_src {
            IpAddr::V4(v4) => rule.pool_addresses_v4.iter().position(|a| *a == v4),
            IpAddr::V6(v6) => rule
                .pool_addresses_v6
                .iter()
                .position(|a| *a == v6)
                .map(|i| rule.pool_addresses_v4.len() + i),
        };
        let Some(addr_index) = addr_index else {
            continue;
        };
        saw_candidate = true;
        // #7076: see the address-only arm above — skip the ALLOCATOR, keep the
        // CANDIDACY, so a quarantined owner yields `Refused` (import blocked,
        // mirroring the active node's `Unavailable`) and never
        // `NothingToReserve` (which would fall through to the interface domain).
        if rule.pool_failure.is_some() {
            if stop_at_first_owner {
                return SyncedReserveOutcome::Refused;
            }
            continue;
        }
        // #5178: tag the reservation deterministic iff this rule runs a
        // deterministic CGNAT (mode 1) pool, so its release uses
        // `free_no_recycle` and the standby's recycle queue does not grow under
        // synced-session churn — matching the active node's
        // `allocate_deterministic_v4` release path.
        // #7360: hand the allocator this rule's persistence identity when the
        // rule runs `persistent-nat`, so the reservation JOINS the source's
        // lease (creating it on the first session) instead of competing with it
        // for the occupancy bit. Without this a persistent client's 2nd..Nth
        // sessions were refused on the bit their own lease already held, and
        // `handle_upsert_synced` dropped them before publishing.
        //
        // The key is derived from the same `flow` the rule match used, through
        // the SAME `persistent_source_key` helper the local path calls, so the
        // standby's lease is keyed identically to the active's — including the
        // `permit` shape, which decides whether the remote endpoint is folded
        // in (#2823).
        //
        // PORT-BEARING ARM. The address-only arm above (`port no-translation`
        // / a port-less protocol) takes the #6041 lease path and needed its own
        // variant — mint the token AND join the lease at the address the WIRE
        // named, rather than choosing one the way
        // `reserve_address_only_persistent` does. That landed as #8132; the two
        // arms now build `persistent` identically and differ only in which
        // reserve they hand it to.
        let persistent = rule
            .persistent_nat
            .then(|| (flow.persistent_source_key(rule.persistent_nat_permit), rule.persistent_nat_timeout_ns));
        let translated = TranslatedTuple {
            ip: rewrite_src,
            port: rewrite_src_port,
        };
        if rule.pool_allocator.reserve_flow_maybe_persistent(
            flow,
            translated,
            addr_index,
            rule.deterministic_v4.is_some(),
            now_ns,
            holder,
            persistent,
        ) {
            // #8115 R2: see the address-only arm above. `reserve_flow` checks
            // and sets only THIS allocator's bitmap, so an imported flow
            // narrowed to pool B succeeds while a LOCAL flow already owns the
            // same tuple in pool A.
            if stop_at_first_owner && peer_owns_wire_identity(rule, flow, translated) {
                rule.pool_allocator
                    .rollback_flow(flow, translated, now_ns, holder);
                return SyncedReserveOutcome::Refused;
            }
            return SyncedReserveOutcome::Reserved;
        }
        // #6979 F1: see the address-only arm. The first pool-owning candidate
        // is the ACTIVE's rule; its refusal is the answer.
        if stop_at_first_owner {
            return SyncedReserveOutcome::Refused;
        }
    }
    if saw_candidate {
        SyncedReserveOutcome::Refused
    } else {
        SyncedReserveOutcome::NothingToReserve
    }
}
