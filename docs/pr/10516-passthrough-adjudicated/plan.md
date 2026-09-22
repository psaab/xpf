# DRAFT v1 — Issue 10516: Stage-11 IPsec passthrough mints the armed-fence Adjudicated token for unadjudicated traffic (no SA check)

Status: DRAFT v1 (STEP-0 design path, no production code)
Date: 2026-09-22
Base: 5dcaa104fb36637f7b76bdd0b3ba26ea880f1046 (origin/master at lane start)
Branch: fix/10516-passthrough-adjudicated
Worktree: /home/ps/git/pi-xpf/.claude/worktrees/10516-passthrough
Issue: #10516 (OPEN, Medium; High iff U-5 shows inward route)
Lane: Eng10516 (wave-4, STEP-0 size gate)

## 0. Verdict

DESIGN path. The assignment requires the fix to REQUIRE the SA check (fail closed);
an outlet-only change (Adjudicated to Delegated) stops minting the token but adds no
SA gate and therefore does not satisfy the brief (confirmed by lane advisory:
outlet-only must not be treated as satisfying this assignment). No authoritative
live-SA lookup exists anywhere in-tree (zero SADB / XfrmState / XfrmPolicy symbols
in userspace-dp/src plus pkg; pkg/routing/xfrm.go manages xfrmi lifecycle only, no
SA state), so adding the required gate entails unresolved lookup-source, key,
fragment, NAT-T, family, perf, and HA choices, any one of which risks a bypass.
Per the brief FREEZE rule, this lane lands the plan only and makes no production
code change.

## 1. Problem (fail-open)

The armed FORWARD fence admits (iifname xpf-usp1, mark 0x58465001) as
proven-adjudicated transit. That mark is minted structurally by queue identity:
Stage-11 IPsec passthrough reinjects via SlowPathOutlet::Adjudicated, which writes
xpf-usp1 queue 0, and the TC ingress classifier stamps 0x58465001 for
queue_mapping == 1 only. But the class placed on that queue is documented as
unadjudicated: is_ipsec_traffic matches proto 50/51 plus UDP 500/4500 with NO
SA-existence check, and classify_ipsec_admission returns Exempt for ESP/AH,
ESP-in-UDP, and NAT-T keepalives via NotIsakmp ("unconditional passthrough — the
SA is the authorization"). The Exempt half never meets any host-inbound,
zone-policy, session, NAT, or screen gate. "The SA is the authorization" holds only
for frames that reach XFRM on the kernel INPUT path; a kernel-FORWARDED frame
(dst = NAT external owned via proxy-ARP/ND, VRRP BACKUP VIP) rides the pinhole
through the fence ACCEPT and the xpf_transit_q0_delivered witness counter.

Narrowed scope (from the issue, verified against source): #5620 pins genuinely
kernel-local dsts to INPUT/XFRM (intended passthrough); the pinhole fires only for
owned-but-not-kernel-local dsts (DNAT-to-another-host externals per the code's own
poll_stages.rs:1324-1330 caveat; VRRP BACKUP VIPs). The attacker cannot aim at
arbitrary internal hosts; the ordinary case hairpins out the WAN
(reflection/TTL loop). The IKE half IS adjudicated (#4323 Option B plus #6471
live-exchange seed). Perf rationale justifies the zone-policy exemption, NOT
minting the fence's adjudication-proof token. Forwarded-frame consequence beyond
XFRM/DoS exposure (unmetered path into SA-lookup/anti-replay/crypto; TUN queue
plus shared rate-budget) is undemonstrated — gated on U-5/U-5a. Medium stands;
High iff inward route is shown.

## 2. Live evidence (STEP-0, current base)

All file:line refs below were read from the worktree at the base commit above.

### 2.1 End-to-end chain (match, Exempt, Adjudicated, usp1q0, mark, fence ACCEPT)

1. Match — userspace-dp/src/afxdp/forwarding/ipsec.rs:32-36
   is_ipsec_traffic(protocol, dst_port) = proto ESP(50) or AH(51) or
   (UDP and dst_port 500/4500). No SA input. Family note ipsec.rs:15-30:
   IPv6 AH never sets protocol 51 (shim walks NEXTHDR_AUTH), so the AH arm is
   v4-only; v6 AH-to-self rides the shim local-dest shunt.
2. Local-dst gate — userspace-dp/src/afxdp/poll_stages.rs:1294-1333
   stage_ipsec_passthrough_check returns NotClaimed unless
   forwarding.owns_configured_ip(flow.dst_ip). #5620 comment :1311-1330 states
   the gate and its caveat: DNAT externals mapping to ANOTHER host are ALSO in
   local_v star (proxy-ARP/ND ownership) so the raw-dst check still claims them
   as local passthrough; that exotic case is UNCHANGED by #5620.
3. Admission — userspace-dp/src/afxdp/forwarding/ipsec.rs:131-150
   classify_ipsec_admission returns Exempt for NotIsakmp (ESP/AH raw, ESP-in-UDP
   on 4500 with non-zero first word, 1-byte NAT-T keepalive) and for set
   Responder SPI; NewInboundIke only for all-zero Responder SPI or truncated
   (fail closed). Call-site discriminator poll_stages.rs:1367-1395 (#6471):
   set-SPI IKE is exempt ONLY with a matching IkeExchangeTable seed, else it
   faces the same host-inbound gate as NEW. ESP/AH/ESP-in-UDP/keepalive (None
   from established_ike_initiator_spi) stay unconditionally exempt.
4. Reinject mint site — userspace-dp/src/afxdp/poll_stages.rs:1405-1425
   reinject_ipsec_passthrough builds ipsec_passthrough_decision() (LocalDelivery,
   local_ifindex 0, :1148-1160) and calls
   maybe_reinject_slow_path_from_frame_with_outlet(..., SlowPathOutlet::Adjudicated,
   ...) at :1420. Sole call site:
   userspace-dp/src/afxdp/poll_descriptor/mod.rs:598 (after the #9950
   fragment-overlap check_and_record at :575-596; import at :88).
5. Outlet to queue — userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:150-161
   (enum docs: Trusted = xpf-usp0; Adjudicated = xpf-usp1 queue 0 + TC mark;
   Delegated = xpf-usp1 queue 1 unmarked) and :431-434
   (Adjudicated to enqueue_adjudicated, Delegated to enqueue_delegated).
   Filtered-chokepoint contrast poll_descriptor/mod.rs:7254-7268: only
   missing_neighbor_adjudicated selects Adjudicated; host-authorized
   LocalDelivery selects Trusted; everything else selects Delegated.
6. Queue to mark — userspace-dp/src/slowpath.rs:40-46
   (ADJUDICATED_QUEUE_INDEX 0, MAPPING 1, MARK 0x58465001),
   enqueue_adjudicated :1138-1144 (PacketQueue::Adjudicated) vs
   enqueue_delegated :1151-1157 (PacketQueue::Delegated),
   load_queue_mark_program :188-243 (clear mark for every queue, set only for
   mapping 1; unknown queues stay unmarked and hit fence DROP).
7. Fence ACCEPT — pkg/nftables/transit_barrier.go:33/35
   (AdjudicatedTransitMark 0x58465001, mask 0xffffffff), :20 counter
   xpf_transit_q0_delivered (downstream-of-TUN witness, not a verdict),
   :41-44 ForwardFenceSpec (AllowedMarks exact conjunction);
   pkg/daemon/daemon_transit_gate.go:105 (xpf-usp1), :107-117 (residual docs:
   adjudicated xfrm reinjects and delegated traffic share iifname; queue
   classifier marks only the adjudicated queue; fence requires interface AND
   exact mark), :164-168 (marked pinhole construction).
8. Bug-moving commit — 3329415f7 (fence: admit adjudicated usp1 transit by skb
   mark, Refs #10391): poll_stages.rs hunk moves the IPsec reinject from the
   Delegated/false path to SlowPathOutlet::Adjudicated deliberately, with the
   multi-queue TUN plus TC classifier plus fence conjunction in the same commit.
9. Pinned behavior — userspace-dp/src/afxdp/tests_slow_path_disposition.rs:1291-1306
   (reinject_outlet_declared_per_production_site_9637): asserts the IPsec
   passthrough site contains SlowPathOutlet::Adjudicated with the comment
   "exempt classes never gate-passed, but their xfrm/reinject packets must carry
   the structural fence mark". This test pins the bug as intended and must be
   re-pointed by the fix (see section 7).

### 2.2 Not already fixed

- gh issue view 10516: state OPEN, full body present, no linked merged fix.
- git log --oneline --all --grep 10516: empty.
- gh pr list --state merged --search 10516: empty.
- HEAD still contains SlowPathOutlet::Adjudicated at poll_stages.rs:1420 and the
  pinning assertion at tests_slow_path_disposition.rs:1300.

### 2.3 Blast-radius numbers (git grep on base)

- reinject_ipsec_passthrough: 1 def (poll_stages.rs:1405), 1 call site
  (poll_descriptor/mod.rs:598), 1 import (mod.rs:88).
- SlowPathOutlet::Adjudicated: 4 files, 1 hit each — poll_stages.rs (mint site),
  poll_descriptor/mod.rs (missing-neighbor chokepoint), tx/dispatch/slow_path.rs
  (outlet to enqueue mapping), tests_slow_path_disposition.rs (pinning test).
- enqueue_adjudicated: 3 files (tx/dispatch/slow_path.rs, slowpath.rs,
  slowpath_reinject_9506_tests.rs).
- AdjudicatedTransitMark: 6 files (prod: pkg/daemon/daemon_transit_gate.go,
  pkg/nftables/transit_barrier.go, pkg/nftables/transit_barrier_idempotency.go;
  tests: transit_fence_10302_test.go, transit_barrier_9852_test.go,
  transit_barrier_idempotency_test.go).
- is_ipsec_traffic / classify_ipsec_admission: 5 files (forwarding/README.md,
  forwarding/ipsec.rs, forwarding/tests.rs, poll_stages.rs, poll_stages_tests.rs).
- XfrmState / XfrmPolicy / SADB / sadb (case variants): ZERO hits in
  userspace-dp/src plus pkg. Authoritative live-SA lookup does not exist in-tree.
- ESP/AH SPI extractors: ZERO. Only IKE extractors exist
  (ike_initiation_spi, established_ike_initiator_spi, ipsec.rs:159-199 plus
  tests :580-624); ESP-in-UDP explicitly returns None from both.
- IKE exchange table: IkeExchangeTable / SharedIkeExchangeTable
  (forwarding/ipsec.rs:206-299, cap 4096, 24h idle, Mutex, Arc-shared across
  workers plus GRE local-origin threads, NOT HA-synced, poison-recovered).
  Covers IKE control plane only; ipsec.rs:291 states "the ESP data plane is
  exempt throughout".

### 2.4 Cross-links (same run / same area, different fixes)

- #10525 OPEN (stage-11 DNAT-to-self IKE gate bypass): same stage-11 area,
  different fix — gate vs outlet selection. Must sequence with this fix; shared
  stage_ipsec_passthrough_check plus host-inbound helper plus tests.
- #10518 OPEN (GRE TunOrigin provenance): joint section 5.4 experiment settles
  both; native-GRE-inner IPsec reaches Stage 11 after decap
  (poll_descriptor/mod.rs:495-502 per prior review) and is part of the
  unadjudicated population.
- #5620 (dst pin): fixes transit-to-REMOTE bypass; leaves transit-DNAT-to-another
  host plus VRRP BACKUP VIP pinhole (poll_stages.rs:1324-1330 caveat).
- #4323 / #6471 (IKE gating): NEW IKE plus unseeded set-SPI IKE face
  host-inbound; ESP/AH/data plane unconditionally exempt.
- #10391 / 3329415f7 (mark infrastructure): multi-queue plus TC plus fence.
- #9506 (xfrmi plaintext half), #10302 / #7191 (fence install discipline).

## 3. Why outlet-only is insufficient

Changing poll_stages.rs:1420 from SlowPathOutlet::Adjudicated to Delegated would
stop minting the fence mark for the unadjudicated class (queue 1 stays unmarked
per slowpath.rs:188-243 and hits fence DROP on FORWARD). That matches the issue's
"fix direction: stop minting the Adjudicated token (outlet selection)" sentence
read in isolation. It does NOT satisfy this lane's explicit requirement: the fix
MUST require the SA check (fail closed). The lane advisory confirms outlet-only
must not be treated as satisfying the assignment. Reasons:

- Delegated still reinjects to the kernel via xpf-usp1 queue 1; INPUT-path frames
  still reach XFRM (intended), but the dataplane has proven nothing about SA
  existence either way. The vulnerability narrative ("the SA is the authorization"
  without ever checking an SA) is unaddressed as a positive gate.
- Without an SA lookup, there is no way to distinguish "ESP with a live SA that
  XFRM will accept" from "ESP with no SA that XFRM will drop but that meanwhile
  consumes the pinhole, the TUN queue, the shared rate budget, and XFRM
  SA-lookup/anti-replay/crypto cycles". Fail-closed demands deny-on-miss at the
  dataplane, not drop-later-at-XFRM.
- The pinning test at tests_slow_path_disposition.rs:1300 would need re-pointing
  either way; outlet-only spends that churn without buying the SA proof the
  assignment demands.
- Any SA-gated design still needs the outlet decision (which queue/mark a
  proven-SA packet earns vs an unproven one), so outlet selection is a sub-choice
  inside the SA-gated design, not a substitute for it.

Hence section 6 designs an SA-gated, fail-closed fix; section 5 records
outlet-only as a rejected alternative with its bypass residual.

## 4. Options considered

### Option A — Outlet-only (Adjudicated to Delegated). REJECTED as the fix.

Change: poll_stages.rs:1420 to SlowPathOutlet::Delegated; re-point the pinning
test :1291-1306; no SA lookup.
Effect: unadjudicated IPsec reinjects via queue 1, unmarked, fence-DROP on
FORWARD; INPUT-path XFRM delivery preserved (mark is FORWARD-scoped).
Pros: one-line prod change, minimal perf/compat risk, matches the issue's
outlet-selection sentence.
Cons / bypass residual: no SA proof; spoofed ESP/AH to owned-but-not-local dsts
still enters the TUN queue and XFRM input path unmetered at the dataplane;
rate-budget and crypto-cycle DoS residual remains; does not meet the MUST-require-
SA-check requirement. Verdict: rejected as the complete fix; retained as a
sub-step inside Option C (unproven class goes Delegated).

### Option B — SA-gated Adjudicated (keep queue 0 for proven SA, drop unproven). CANDIDATE.

Change: insert a live-SA existence check between stage_ipsec_passthrough_check
(Passthrough verdict) and reinject_ipsec_passthrough (or inside the reinject
before outlet selection). Proven-SA packets keep SlowPathOutlet::Adjudicated;
missing/expired/invalid-SA packets are dropped (silent, with counter plus
exception event), never reinjected on either queue.
Pros: smallest outlet delta; fence semantics unchanged ("Adjudicated means
dataplane-proven"); no new queue; U-5/U-5a witness (xpf_transit_q0_delivered)
directly measures proven-SA transit.
Cons: drops unproven INPUT-path frames that XFRM would have dropped anyway
(acceptable) but also drops any legitimate SA whose dataplane cache is stale
(availability risk during rekey/failover/restart — needs grace design, section 6);
requires the SA cache/sync subsystem (the hard part).
Bypass analysis: fail-closed if every error/nil/unknown path denies (section 6.8);
TOCTOU window (SA expires between check and XFRM input) is bounded by cache TTL
plus XFRM's own final drop.

### Option C — SA-gated outlet split (proven to Adjudicated, unproven to Delegated). CANDIDATE.

Change: same SA check as B, but unproven packets are reinjected via
SlowPathOutlet::Delegated (queue 1, unmarked) instead of dropped.
Pros: preserves INPUT-path delivery for edge SAs the cache misses (softer
availability); FORWARD fence still drops unproven (no mark), closing the pinhole.
Cons: keeps the TUN-queue/rate-budget/XFRM-cycle DoS residual for spoofed
unproven floods (the exact undemonstrated consequence the issue gates on U-5);
two outlets for one stage complicates the pinning test and the operator model
("Delegated now carries unproven IPsec" vs "Delegated means no-policy transit").
Bypass analysis: closes the fence-bypass (FORWARD) but not the XFRM-input
metering bypass; acceptable only if U-5 shows WAN-hairpin-only AND a separate
rate-metering control covers queue 1. Verdict: candidate only as a compat
soft-landing; B is the preferred end state.

### Option D — Drop plus divert to host-inbound/zone-policy (treat unproven as ordinary). REJECTED.

Change: return NotClaimed for unproven-SA IPsec so it continues to transit
forwarding plus zone-policy.
Pros: reuses existing policy machinery.
Cons: breaks intended INPUT/XFRM passthrough for proven SAs whose cache missed;
transit policy was deliberately exempted for perf; reintroduces the pre-#5620
terminal-claim confusion in reverse. Verdict: rejected.

Recommended: Option B (SA-gated Adjudicated, drop unproven), with Option C as a
documented compat fallback if availability testing forces a soft-landing. The rest
of this plan details B.

## 5. Chosen design — Option B (SA-gated, fail-closed)

### 5.1 Insertion point and control flow

Primary insertion: userspace-dp/src/afxdp/poll_descriptor/mod.rs at the
IpsecPassthroughOutcome::Passthrough arm (:570-609), between the #9950
fragment-overlap check_and_record (:575-596) and the reinject_ipsec_passthrough
call (:597-598). Rationale: the SA check must run only for packets that passed
match plus local-dst plus admission plus fragment-overlap (rare path, no
common-datapath cost), and must run before any queue write (no mint-then-revoke).
Alternative (equivalent, to be settled at implement time): inside
reinject_ipsec_passthrough (poll_stages.rs:1405-1425) before outlet selection,
returning false on SA miss. Either way the rule is: no SA proof, no enqueue on
any queue, no mark.

Pseudocode at the arm (names illustrative; implementer reuses in-tree styles):

  Passthrough => {
    // existing frag-overlap block unchanged (:575-596)
    // NEW: live-SA existence gate (fail closed)
    //   key = sa_key_from_packet(packet_frame, meta, flow) // section 5.3-5.4
    //   hit = sa_cache.lookup(key, now_ns)                 // section 5.5
    //   if key unparseable OR !hit => {
    //     counters.sa_miss_drop += 1; exception(sa_miss, tuple, spi?, reason);
    //     fail any frag admission; recycle frame; continue; // NEVER reinject
    //   }
    // existing reinject (proven-SA only) keeps Adjudicated outlet
    let accepted = reinject_ipsec_passthrough(...);
    ...
  }

Denied arm (:610-630) unchanged. NotClaimed path unchanged.

### 5.2 What "SA proof" means (conservative v1)

v1 proves EXISTENCE of a live inbound SA matching the packet's
(dst, SPI, proto) triple, with family plus NAT-T normalization per section 5.4.
It does NOT prove anti-replay window, lifetime bytes/packets, mode
(transport/tunnel), or policy (XfrmPolicy) match — XFRM remains the final
enforcer for those; the dataplane gate proves "an SA exists that could accept
this SPI to this dst", which is sufficient to deny the no-SA spoof population
(the issue's acceptance sends ESP proto 50 with NO SA). Any packet whose SA key
cannot be parsed (fragments without SPI, truncated headers) is treated as
unproven and dropped (fail closed), with explicit carve-outs only where section
5.4 requires them.

IKE (UDP 500/4500 ISAKMP) is OUT of scope for the SA gate: it is already gated by
#4323/#6471 (host-inbound plus live-exchange seed). The SA gate applies to the
data plane only: ESP (proto 50), AH (proto 51, v4 only per ipsec.rs:15-30),
ESP-in-UDP (4500, non-zero first word), and NAT-T keepalive handling per 5.4.

### 5.3 SA key (v1)

Key triple: (dst_ip, spi_u32, proto_u8) where proto distinguishes ESP vs AH
(50/51) and ESP-in-UDP normalizes to ESP (proto 50) with the outer dst_ip.
Rationale: kernel XFRM state is keyed by (dst, SPI, proto); src is NOT part of
the state key (it appears in policy/selectors, not state lookup), so v1 omits
src to match XFRM semantics. if_id (xfrmi binding): v1 IGNORES if_id (wildcard)
because Stage-11 passthrough serves both policy-based (no xfrmi) and route-based
(xfrmi) SAs and the packet at this point carries no if_id; a same-SPI-different-
tunnel collision resolves as "proven" (safe direction for availability; XFRM
still enforces the binding on input). Mark/VRF/table: v1 ignores; dst_ip is the
raw on-wire dst (flow.dst_ip) as in the #5620 check. This must be recorded as a
known over-approximation (fails toward admit for the proven set, never toward
mint for the unproven set).

Open key questions for plan review (must close before implement): include src as
a hardening discriminator (deviates from XFRM but narrows spoof)? Include if_id
once the resolver can attribute the dst to an xfrmi (needs the xfrmi if_id map
wired into ForwardingState)? Key AH by (dst, SPI, 51) with ICV length checks?

### 5.4 Parsers (new code, fail-closed)

1. ESP (proto 50, unfragmented or first-fragment with full SPI word): SPI =
   big-endian u32 at L4 offset + 0. Bounds-check via packet_frame.get, mirroring
   isakmp_demux (ipsec.rs:84-112). Truncated => unproven/drop.
2. AH (proto 51, IPv4 only): SPI at L4 offset + 4 (AH fixed header: NextHdr,
   PayloadLen, RESERVED, SPI, Seq). Bounds-check; truncated => unproven/drop.
   IPv6 AH: unreachable here (shim walks it; ipsec.rs:15-30 documents the shunt)
   — no parser needed; document.
3. ESP-in-UDP (UDP 4500, non-marker, non-keepalive): SPI at UDP payload + 0
   (after 8-byte UDP header, no 4-byte marker — marker presence means IKE, per
   ipsec.rs:99-107). Reuse the 4500 demux: marker [0,0,0,0] => IKE (out of
   scope); length 1 keepalive (0xFF) => section 5.4.4; else ESP SPI word.
   Truncated => unproven/drop.
4. NAT-T keepalive (UDP 4500, 1-byte 0xFF): no SPI, no SA. v1 drops keepalives
   that reach Stage 11 as unproven (they are NAT-mapping refresh, not XFRM
   input; XFRM never consumes them). Confirm with strongSwan behavior at review;
   alternative is to exempt keepalives to Delegated (Option C soft-landing).
5. Fragments: non-first fragments carry no SPI (ESP/AH header not present).
   v1 drops non-first-fragment ESP/AH-claimed packets as unparseable/unproven.
   First fragments with a complete SPI word are keyed normally. Interaction with
   the #9950 frag_overlap tracker (mod.rs:575-606): the SA gate runs AFTER
   check_and_record, so a dropped unproven fragment still fails its admission
   (fail path at :603-605 pattern). Reassembly is explicitly out of scope.
   Compatibility risk: legitimate fragmented ESP (rare; IKE negotiates MTU,
   NAT-T avoids it) would drop — needs a compat note plus counter.
6. IPv4 vs IPv6: ESP parser is family-agnostic (L4 offset from meta); dst_ip
   carries the family; cache keys IpAddr (v4/v6) like IkeExchangeKey
   (ipsec.rs:232-247). AH v6 out of scope per above.

All parsers must be branch-light, bounds-checked with .get, no allocs, no
panics, and unit-tested for truncation (mirroring spi_extractors_fail_safe_on_
truncation, ipsec.rs:613-624).

### 5.5 SA cache (new subsystem — the hard part)

Per-packet netlink XFRM dump is impossible on the dataplane (syscall per packet,
Stage 11 runs before cache/session/policy). v1 therefore needs a shared,
read-optimized SA-existence cache, populated out-of-band:

- Snapshot source (to be settled at review; ordered preference):
  (a) Periodic netlink XfrmStateList poll (e.g. 1-5s) from a slow control thread,
      parsing (dst, SPI, proto, state, lifetimes) and publishing an immutable
      snapshot (ArcSwap, mirroring local_tunnel_deliveries / ForwardingState
      patterns). Filter to inbound/usable states only.
  (b) Netlink XFRM monitor (ACQUIRE/EXPIRE/DELETE events) plus periodic
      full-sync fallback. Lower staleness, higher complexity.
  (c) strongSwan VICI/whack query. Rejected for v1 (daemon coupling, creds,
      schema drift); revisit only if netlink proves insufficient.
- Read path: Stage-11 workers hold Arc<Snapshot>; lookup is a HashMap get on
  (dst, SPI, proto) with no lock (immutable snapshot) or a sharded lock-free
  read. No Mutex on the ESP data plane (contrast IkeExchangeTable's Mutex,
  which is safe only because IKE is pps-bounded, ipsec.rs:273-283; ESP is
  line-rate and must not take a contended lock).
- Staleness/TOCTOU: snapshot interval T plus XFRM input delay bounds the window
  in which an expired SA still mints (over-admit) or a fresh SA still drops
  (over-drop). Over-admit is bounded by T and closed by XFRM's own drop;
  over-drop is the availability risk. Mitigations: short T (1s), grace window
  for recently-seen SPIs (negative-cache TTL much shorter than positive, or no
  negative cache — miss means drop but recheck on next snapshot, so a fresh SA
  heals within T), rekey overlap (IKE installs the new SA before deleting the
  old; both present during overlap, so no gap), startup/restart posture (empty
  cache drops data-plane IPsec until the first snapshot lands — fail closed;
  bound the blackout by blocking dataplane-ready on first snapshot or by a
  short fail-open-degraded window ONLY if review explicitly blesses it with a
  counter; default is fail-closed blackout measured in one poll interval).
- HA/failover: like IkeExchangeTable (ipsec.rs:285-291), v1 is NOT HA-synced;
  the new node builds its cache from its own kernel's XFRM states (which are
  themselves not synced for host-terminated IKE — same gap as the primary path).
  Document; revisit with XFRM state sync if that ever lands.
- Memory/perf: key (u128 dst + u32 SPI + u8 proto) packed; expected table size
  hundreds (site-to-site scale), cap with oldest-eviction plus eviction counter
  mirroring IKE_EXCHANGE_TABLE_CAP/evictions (ipsec.rs:206/294-298). Snapshot
  swap must not alloc on the read path.

This subsystem is the reason the lane is DESIGN: source, interval, grace,
negative-cache, cap/eviction, HA, and restart-posture choices each risk a bypass
or an outage and need adversarial review before code.

### 5.6 Fence / outlet / counter disposition (Option B)

- Proven-SA packets: unchanged path (Adjudicated outlet, queue 0, mark,
  fence ACCEPT, xpf_transit_q0_delivered witness). Fence spec
  (daemon_transit_gate.go:133-184, nftables/transit_barrier.go:37-44) unchanged.
- Unproven packets: dropped at Stage 11 (silent, Junos host-inbound posture
  like the Denied arm, poll_stages.rs:1170-1176), with a new counter (e.g.
  sa_miss_dropped_packets) plus a tuple-rich exception event (spi, dst, proto,
  reason: no_sa / unparseable / truncated / non_first_fragment). No enqueue on
  either queue; no mark; no fence interaction. The xpf_transit_q0_delivered
  delta then measures proven-SA transit only, which is exactly what U-5/U-5a
  needs.
- Pinning test (tests_slow_path_disposition.rs:1291-1306) must be re-pointed:
  the IPsec site keeps Adjudicated outlet selection for the proven path, with an
  added assertion that the SA gate precedes it (source-text cell mirroring the
  existing after_call pattern, plus behavioral cells in section 7). The old
  "exempt classes never gate-passed but must carry the mark" comment is the bug
  statement and goes away.

### 5.7 Ownership / VRRP / DNAT interaction

The SA gate does NOT replace the #5620 owns_configured_ip check; it layers on
top (match, local-dst, admission, frag-overlap, THEN sa-proof). The
transit-DNAT-to-another-host caveat (poll_stages.rs:1324-1330) and VRRP BACKUP
VIP population remain claimed as local passthrough, but unproven-SA packets to
them now drop instead of minting. Proven-SA packets to a BACKUP VIP (legitimate
only during failover windows) still mint — acceptable: an SA match is stronger
proof than VIP mastership, and XFRM plus the RG/VRRP layer still scope delivery.
#10525 (DNAT-to-self IKE gate) sequences before/after this fix without conflict:
  #10525 narrows WHICH IKE reaches the reinject; this fix narrows WHICH data-plane
packets earn the mark. Shared test files (poll_stages_tests.rs,
tests_slow_path_disposition.rs) need joint ownership during implementation.

### 5.8 Fail-closed rules (normative)

- Every error/nil/unknown SA path denies (no fallback mint, no else-Adjudicated).
- Unparseable (truncated, non-first fragment, unknown demux) denies.
- Empty/unready cache denies (startup blackout, poller error, snapshot poison).
- Cache poller error latches the last-good snapshot with a staleness counter AND
  a staleness ceiling: beyond the ceiling (e.g. 3 missed polls), deny-all
  (fail closed) rather than ride a stale snapshot indefinitely.
- No config knob for permissive/tolerant mode in v1. If a compat escape hatch is
  ever added, it defaults off, logs, and carries a fail-closed commit guard.
- No alloc/copy/compute on the common path: the gate runs only for
  is_ipsec_traffic packets that passed all prior gates (rare), and the lookup is
  a single map get on an immutable snapshot.

### 5.9 Perf budget

Stage 11 runs before flow-cache/session/NAT/policy; the SA gate must not regress
common-datapath throughput. Budget: zero extra work for non-IPsec packets (early
NotClaimed unchanged); for IPsec-claimed packets, one parser (bounds-checked
slice reads) plus one snapshot map get. No syscalls, no locks, no allocs on the
worker. Snapshot publication (control thread) may alloc freely. Smoke: iperf3
line-rate plus targeted ESP flood with/without SA, measuring worker cycles and
drop counters; the existing stage-10 flood screen bounds IKE pps, and the new
sa_miss counter bounds unproven-ESP visibility.

## 6. Tests

### 6.1 Unit (deterministic, no netlink, no cluster)

- Parser cells (new, beside ipsec.rs tests): ESP SPI extraction (aligned,
  truncated, non-first-fragment marker), AH SPI (v4, truncated), ESP-in-UDP SPI
  (marker vs non-marker vs keepalive vs truncated), v6 AH unreachable
  documentation cell. Each FAIL-ON-REVERT (remove the bounds check, test goes RED).
- Classifier cells (extend forwarding/tests.rs is_ipsec block :3222-3292 and
  ipsec.rs classify cells :626-676): prove Exempt scope unchanged (gate is
  downstream, not in classify).
- Gate cells (new, poll_stages_tests.rs): synthetic Passthrough packets with a
  fake SA cache — hit mints (reinject called, Adjudicated outlet), miss drops
  (no reinject, counter plus exception), unparseable drops, truncated drops,
  non-first-fragment drops, keepalive drops (or Delegated if review picks the
  soft-landing). Table-driven, no sleeps/ports. FAIL-ON-REVERT: gate removal
  makes miss cases mint (RED).
- Outlet cells (re-point tests_slow_path_disposition.rs:1291-1306): proven path
  keeps Adjudicated; add source-text cell asserting the SA gate precedes the
  outlet selection; add REAL-primitive per-path cells (section 6.3 pattern)
  driving proven/unproven through maybe_reinject_slow_path_from_frame_with_outlet.
- Cache cells (new): snapshot publish/swap, positive/negative TTL, cap/eviction
  oldest-first plus eviction counter (mirror exchange_full_evicts_oldest_not_
  newest, ipsec.rs:720-724, and the #6747 recency cells), poison/error latching,
  staleness-ceiling deny-all.

### 6.2 Integration (in-tree suites, isolated env)

- Affected suites: userspace-dp forwarding/poll_stages/slowpath suites,
  pkg/nftables transit_barrier suites, pkg/daemon transit_fence suites. Run with
  isolated GOCACHE/GOTMPDIR under /dev/shm (Rust: isolated CARGO_TARGET_DIR).
  No project-wide validation (parent owns it); no cluster/incus commands.
- RED-on-revert firsthand (implement lane): stash the gate (keep tests), run the
  new miss-drop cells — EXPECT FAIL (mint instead of drop); restore — EXPECT
  PASS. Record both outputs in the PR.

### 6.3 Armed-box acceptance (U-5/U-5a, from the issue; REQUIRED to settle severity)

On an armed box with live DNAT: ip route get <external>, confirm the mark ACCEPT
in the fence (nft list plus AdjudicatedTransitMark 0x58465001), send ESP
(proto 50, NO SA) to the external, read xpf_transit_q0_delivered delta plus
kernel egress iface. Inward route/egress implies High; WAN hairpin only implies
Medium stands. Post-fix expectation: q0 delta ZERO for no-SA ESP (dropped at
Stage 11, never enqueued); proven-SA ESP (establish a real tunnel/SA first)
shows q0 delta plus correct INPUT/XFRM delivery. Joint section 5.4 experiment
with #10518 (GRE TunOrigin): run the same probe over native-GRE-inner IPsec to
settle both populations in one armed session. This experiment cannot be a unit
test; it is the severity gate and the end-to-end proof.

## 7. Rollout / compat

- Fence/wire format: unchanged (same mark, mask, iifname, counter). No
  nftables/daemon prod change expected; fence tests unchanged.
- Dataplane upgrade: restart-blackout bounded by first-snapshot latency (one poll
  interval, fail closed); document in release notes. Rollback is single-commit
  revert (gate removal restores always-passthrough; pinning test reverts with it).
- Config: no new knob in v1 (section 5.8). If review demands a compat hatch
  (Option C soft-landing or keepalive exemption), it ships default-off with
  fail-closed commit validation and a dedicated counter.
- Interop: strongSwan/libreswan rekey overlap covers the staleness window (both
  SAs present during overlap); DPD/rekey re-prove liveness. Fragmented-ESP
  senders (rare) break loudly (dropped with counter) — release-note plus counter
  alert; revisit only with evidence.
- Sequencing: land #10525 (IKE gate) and this fix in either order; both touch
  stage_ipsec_passthrough_check plus shared tests — second implementer rebases
  and re-runs the joint cells. Coordinate via hub before editing shared files.

## 8. Open questions (must close at plan review; several gate implementability)

- OQ1 (severity): U-5/U-5a result — inward route (High) or WAN hairpin only
  (Medium stands)? Schedules the joint #10518 experiment.
- OQ2 (lookup source): netlink poll (interval? states filter?) vs monitor events
  vs other? Who owns the poller thread, and what is the dataplane-ready gate?
- OQ3 (key): (dst, SPI, proto) wildcard src/if_id (v1 proposal) vs hardened
  (src? if_id? mark? table?)? AH key details?
- OQ4 (fragments): drop non-first (v1) vs reassemble vs allow-with-counter?
  First-fragment SPI completeness rule? Overlap with #9950 tracker?
- OQ5 (NAT-T): keepalive drop (v1) vs Delegated exemption? ESP-in-UDP SPI offset
  edge cases (short UDP, jumbo, GRO)?
- OQ6 (family): v6 AH permanently out of scope (shunt covers)? v6 ESP key
  normalization (ext-hdr walk parity with shim)?
- OQ7 (staleness): poll interval T, negative-cache policy, staleness ceiling,
  startup blackout bound, poison/error latching?
- OQ8 (perf): snapshot structure (HashMap vs table-indexed), cap/eviction,
  worker read cost measured where? iperf3 plus ESP-flood smoke thresholds?
- OQ9 (HA): document-not-sync (v1) vs future XFRM sync dependency?
- OQ10 (compat): Option C soft-landing needed, or straight to B? Keepalive plus
  fragmented-ESP breakage acceptable with counters?
- OQ11 (ownership): BACKUP-VIP proven-SA mint acceptable? DNAT-external
  attribution to xfrmi if_id in a later key hardening?
- OQ12 (IKE interplay): any change to IkeExchangeTable (cap 4096, 24h idle,
  Mutex) or keep IKE fully separate?

## 9. Acceptance

- SA-gated fail-closed fix landed per section 5 (proven mints Adjudicated,
  unproven drops with counter plus exception, no error path mints).
- Pinning test re-pointed plus new gate/parser/cache cells green; RED-on-revert
  demonstrated firsthand by the implement lane.
- Affected suites green (userspace-dp forwarding/poll_stages/slowpath,
  pkg/nftables, pkg/daemon fence); no project-wide validation in-lane.
- U-5/U-5a armed-box experiment run: no-SA ESP shows zero q0 delta (fixed);
  proven-SA ESP shows q0 delta plus correct delivery; severity settled
  (Medium stands vs High) and recorded.
- No outlet-only residual: unproven class earns no mark on any queue (Option B)
  or earns Delegated-unmarked with explicit DoS-acceptance plus metering
  (Option C fallback, only if review blesses it).

## Appendix A. File:line index (base 5dcaa10)

- Issue: gh issue view 10516 (OPEN, body sections What/Evidence/Narrowed/
  Acceptance/Review origin; cross-links #10525, #10518).
- userspace-dp/src/afxdp/forwarding/ipsec.rs:32-36 (is_ipsec_traffic),
  :38-61 (IpsecAdmissionClass docs), :63-112 (isakmp_demux), :114-150
  (classify_ipsec_admission), :159-199 (IKE SPI extractors), :201-299
  (IKE_EXCHANGE_TABLE_CAP/IDLE/Key/Table docs), :273-291 (sharing/locking/
  HA/ESP-exempt), :580-676 (SPI/classify tests).
- userspace-dp/src/afxdp/poll_stages.rs:1148-1160 (ipsec_passthrough_decision),
  :1162-1177 (IpsecPassthroughOutcome), :1294-1398
  (stage_ipsec_passthrough_check: match :1308, #5620 :1311-1333 with caveat
  :1324-1330, #4323/#6471 :1334-1395, Passthrough :1397), :1400-1425
  (reinject_ipsec_passthrough, outlet :1420).
- userspace-dp/src/afxdp/poll_descriptor/mod.rs:88 (import), :575-609
  (frag-overlap plus reinject call :598 plus admission commit/fail),
  :610-630 (Denied arm), :7254-7268 (filtered chokepoint outlet mapping).
- userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:150-172 (outlet enum plus
  docs plus reinject_host_authorized), :313-435 (with_outlet reinject, mapping
  :431-434).
- userspace-dp/src/slowpath.rs:40-46 (queue/mark consts), :188-243 (TC loader),
  :1130-1158 (enqueue Trusted/Adjudicated/Delegated), :1134-1137 (adjudicated
  docs).
- pkg/nftables/transit_barrier.go:20 (counter), :30-35 (mark/mask), :37-44 (spec).
- pkg/daemon/daemon_transit_gate.go:105 (xpf-usp1), :107-124 (residual docs),
  :125-184 (spec funcs, pinhole :164-168).
- userspace-dp/src/afxdp/tests_slow_path_disposition.rs:1291-1306 (pinning test).
- userspace-dp/src/afxdp/forwarding/tests.rs:3222-3292 (is_ipsec cells).
- pkg/routing/xfrm.go (xfrmi lifecycle only; no SA state — absence evidence).
- 3329415f7 (mark infrastructure plus Adjudicated move, Refs #10391).

## Appendix B. Verification commands run (STEP-0)

- pwd plus HEAD plus branch: worktree 10516-passthrough, 5dcaa10,
  fix/10516-passthrough-adjudicated.
- gh issue view 10516 --json body (OPEN, full What/Evidence/Narrowed/
  Acceptance/origin); --comments tail (cross-links #10525, #10518).
- git log --oneline --all --grep 10516 (empty); gh pr list --state merged
  --search 10516 (empty); git log --grep passthrough/Adjudicat (hits #6691,
  #6471, 3329415f7, mark fixes).
- git grep counts/counts above (section 2.3); XFRM/SADB zero-hit proof;
  git show 3329415f7 --stat plus poll_stages.rs hunk (Delegated/false to
  Adjudicated).
- gh issue view 10525/10518 titles (both OPEN, distinct fixes).
- Reads: all Appendix A ranges (poll_stages, poll_descriptor, slow_path,
  slowpath, transit_barrier, daemon_transit_gate, ipsec, pinning test).

## Appendix C. Blast-radius recap

1 mint site, 1 call site, 4 outlet files, 3 enqueue files, 6 mark files,
5 classifier files, 0 in-tree SA/SADB symbols, 0 ESP/AH SPI extractors.
The SA cache subsystem (section 5.5) is new code with no in-tree precedent for
data-plane-rate XFRM state reads; IkeExchangeTable is the closest analog and is
explicitly IKE-only plus Mutex-gated (safe at IKE pps, unsafe at ESP line rate).
