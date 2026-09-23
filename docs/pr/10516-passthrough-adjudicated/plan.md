# DRAFT v4 — Issue 10516: Stage-11 IPsec passthrough mints the armed-fence Adjudicated token for unadjudicated traffic (no SA check)

Status: IMPLEMENTATION FOLD (v4 design; deferred armed-box procedures in §7.1)
Date: 2026-09-22
Base: 5dcaa104fb36637f7b76bdd0b3ba26ea880f1046 (v1 base; v2 commit dae7b5ad8)
Branch: fix/10516-passthrough-adjudicated
Worktree: /home/ps/git/pi-xpf/.claude/worktrees/10516-passthrough
Issue: #10516 (OPEN, Medium; High iff U-5 shows inward route)
Lane: Eng10516 (wave-4; v4 fold per Main brief)
Reviewers: Rev10516PlanA + Rev10516PlanB round 1 (BOTH PLAN-NEEDS-MAJOR); Rev10516Delta1 + Rev10516Delta2 (BOTH STILL-NEEDS-WORK, split-convergent)
## 0. Verdict and v1-to-v4 delta

DESIGN path, unchanged. Round-1 review verified the v1 evidence chain and blast
counts as accurate but returned PLAN-NEEDS-MAJOR on both lanes with convergent
must-fix findings: the SA-existence gate as specified does not close the
FORWARD-path bypass (stale-window and observed-SPI populations still mint), the
"XFRM closes over-admit" closure claim is false on exactly the vulnerable path,
the fragment rule is unreachable as written, and the test plan does not pin the
gate-to-outlet wiring. Additionally the live population is narrower than v1
claimed: raw ESP/AH never reach the mint (flowless to NotClaimed), so the
parsers, fragment rule, and U-5 probe must be rescoped to UDP-500/4500, and the
VRRP half of the issue is ungrounded (VIPs never satisfy the Stage-11 claim).

v4 is a REDESIGN fold addressing every must-fix (finding-to-fix map in App. D):


1. RESCOPE to UDP-500/4500: raw ESP/AH are flowless to NotClaimed and never
   reach the mint or any gate (§2.2). The v1 raw ESP/AH parsers, the outer
   non-first-drop rule, and the GRE-inner-ESP claims are DELETED (not deferred).
   U-5 is fixed to ESP-in-UDP-with-SPI plus GRE-inner UDP (the v1 proto-50
   probe is vacuous). No #6837 reversal is pursued (KILL-grade, §2.2 last two
   bullets).
2. NEVER-MINT-ADJUDICATED: Stage-11 IPsec never selects Adjudicated/q0.
   A proven SA always selects unmarked Delegated/q1; an SA miss, stale/error/
   unparseable/keepalive always drops (§5.6). This is stricter than a locality
   split and avoids trusting a race-prone kernel-local/mastership oracle.
   Delegated preserves the legitimate INPUT/XFRM path, while every packet the
   kernel routes through FORWARD reaches the armed fence DROP. The q0 mark is
   therefore never minted from mere SA existence. The v1 "XFRM closes
   over-admit" claim is deleted for FORWARD (FORWARD never consumes XFRM).
3. LOCALITY PROOF (subsumed, not an authorization oracle): reachable GRE-inner
   UDP to an interface-local destination exercises the real local INPUT/XFRM
   consumer via Delegated; DNAT/static-NAT externals mapped to another host
   exercise unmarked FORWARD fencing. DNAT-to-self is explicitly dispositioned:
   the raw pre-NAT key may miss if XFRM identifies the translated local dst,
   and that mismatch drops until a separately reviewed candidate-key design.
   Interface-IP and VIP destinations are otherwise shunted or NotClaimed before
   Stage 11 (§5.6, §2.3), so they are not substituted for the local cell. Any
   future VIP ownership change MUST remain unmarked unless a separate
   authorization contract is proven. No Stage-11 locality result can mint q0.
4. STALENESS: event-driven invalidation (raw NETLINK_XFRM monitor, NEWSA/
   DELSA/EXPIRE with immediate removal) plus 30s GETSA drift-sync fallback
   (not poll-only), deny-on-stale (first missed sync or poller error denies all
   immediately plus a counter), NO T-window over-admit, NO last-good latch
   (§5.5).
5. SPECIFY: exact lookup API, UAPI-visible SA fields and direction handling,
   interval, owner thread, ready-gate (§5.5); hardened key including src with
   AH deferred (§5.3); exact frag admission-fail path with raw/UDP separation
   (§5.1, §5.4); rate-limited lock-free miss path (§5.8); snapshot structure
   (Arc FxHashMap, cap 4096, control-only eviction, counter) plus perf numbers
   (§5.9); HA/blackout/rekey plus strongSwan compat plus release notes plus
   no-q0 hatch prohibition (§5.10, §5.11, §8).
6. BLAST: q0-writer inventory, source ownership, and rollback boundaries remain
   explicit (§2.4, §5.6, §8, App. C).

7. TESTS: real wire-frame cells (no-SA UDP spoof denied with q0-zero,
   valid-SA GRE-inner-local-via-Delegated with q0-zero plus INPUT delivery,
   raw/non-first to NotClaimed) plus arm-level gate-to-outlet wiring pins,
   no-Adjudicated-from-Stage-11 pin, explicit DNAT-to-self key-mismatch drop,
   and stale/observed-SPI bypass pins (§6). OQ1-12 adopted per PlanB except
   where PlanA is stricter (§9).

The deterministic implementation and unit-path cells are now landed on this
branch; armed-box, privileged-socket, flood, and perf procedures remain
deferred as enumerated in §7.1.


## 1. Problem (fail-open), rescoped

The armed FORWARD fence admits (iifname xpf-usp1, mark 0x58465001) as
proven-adjudicated transit. That mark is minted structurally by queue identity:
Stage-11 IPsec passthrough reinjects via SlowPathOutlet::Adjudicated, which
writes xpf-usp1 queue 0, and the TC ingress classifier stamps 0x58465001 for
queue_mapping == 1 only. The class placed on that queue includes packets that
never met any host-inbound, zone-policy, session, NAT, or screen gate and for
which NO SA-existence check runs: ESP-in-UDP and NAT-T keepalives on UDP 4500
(classify_ipsec_admission returns Exempt via NotIsakmp — "unconditional
passthrough"). "The SA is the authorization" holds only for frames that reach
XFRM on the kernel INPUT path; a kernel-FORWARDED frame (dst = NAT external
owned via proxy-ARP/ND and claimed through the local_v append) rides the
pinhole through the fence ACCEPT and the xpf_transit_q0_delivered witness
counter. The safe closure is to remove this Stage-11 q0 mint entirely:
unmarked Delegated still reaches the kernel TUN/XFRM INPUT path, while any
FORWARD route is rejected by the armed fence.

Scope corrections from v1 (each proven in §2):

- The issue text says is_ipsec_traffic "matches proto 50/51 + UDP 500/4500".
  The predicate does match all three, but only the UDP-500/4500 population can
  REACH it: raw ESP/AH are flowless (no SessionFlow) and Stage 11 returns
  NotClaimed before the predicate (§2.2). The live unadjudicated population is
  UDP-500/4500 ESP-in-UDP (plus keepalives), NOT raw ESP/AH.
- The issue's "VRRP BACKUP VIP" half is ungrounded: VIPs are absent from the
  userspace ownership sets (§2.3) and VIP dsts are shunted to the kernel by
  the shim before userspace ever sees them. Stage 11 cannot claim a VIP dst on
  any node (master or backup). The DNAT/static-NAT-external half is live and
  is the entire pinhole population.
- The IKE half IS adjudicated (#4323 Option B plus #6471 live-exchange seed)
  and is out of scope for the SA gate. Perf rationale justifies the
  zone-policy exemption, NOT minting the fence's adjudication-proof token.
- Forwarded-frame consequence beyond XFRM/DoS exposure (unmetered path into
  SA-lookup/anti-replay/crypto; TUN queue plus shared rate-budget) is
  undemonstrated — gated on U-5/U-5a (§7). Medium stands; High iff inward
  route is shown.

## 2. Live evidence (re-verified at v4 fold)

All file:line refs below were read from the worktree. Source base 5dcaa10;
the source refs were re-verified unchanged through the v4 plan fold.


### 2.1 UDP-only poll path: wire to mark (the live chain)

For a UDP-500/4500 packet to a DNAT-to-another-host external:

1. Shim steers to XSK: the dst is a DNAT external, which is absent from the
   shim local maps (buildLocalAddressEntries covers interface addrs only,
   pkg/dataplane/userspace/maps_sync.go:1378-1415, plus kernel AddrList VIPs at
   :1094-1125 — no NAT externals), so is_local_destination is false and the
   packet is not shunted (userspace-xdp/src/lib.rs:794-806). The interface-NAT
   arm keeps ESP/GRE to the kernel but lets UDP fall through to the XSK
   redirect (:807-825, ESP/GRE early-return at :820-822).
2. Flow parses (UDP has ports): stage_parse_flow_and_learn calls
   parse_session_flow_from_bytes (userspace-dp/src/afxdp/poll_stages.rs:398-424,
   call at :407; GRE-only fallback at :418-424, no ESP/AH fallback).
   parse_flow_ports has TCP/UDP plus ICMP arms
   (userspace-dp/src/afxdp/frame/inspect.rs:1312-1367) and metadata_tuple_complete
   accepts UDP (:1075-1090 region, UDP arm true), so flow is Some.
3. Screen runs (stage_screen_check), then the #9950 fragment-overlap CHECK
   (check-only pre-hook at
   userspace-dp/src/afxdp/poll_descriptor/mod.rs:481-549; recording deferred to
   the TX site).
4. Stage 11 claims: stage_ipsec_passthrough_check
   (userspace-dp/src/afxdp/poll_stages.rs:1294-1398) — flow is Some (:1304-1306
   pass), is_ipsec_traffic matches UDP-4500
   (userspace-dp/src/afxdp/forwarding/ipsec.rs:32-36),
   owns_configured_ip(flow.dst_ip) is true via the DNAT-destination append to
   local_v (poll_stages.rs:1331-1333; append at
   userspace-dp/src/afxdp/forwarding_build/mod.rs:880-922, inserts at :906 and
   :914; caveat at poll_stages.rs:1324-1330 stating transit-DNAT-to-another-host
   is still claimed), classify_ipsec_admission returns Exempt for ESP-in-UDP
   via NotIsakmp (ipsec.rs:99-107 demux, :131-150 classify, :138 arm), and the
   #6471 discriminator finds no IKE SPI (established_ike_initiator_spi returns
   None for ESP-in-UDP) so the packet stays unconditionally exempt
   (poll_stages.rs:1367-1395). Verdict: Passthrough (:1397).
5. Reinject mints: the Passthrough arm
   (userspace-dp/src/afxdp/poll_descriptor/mod.rs:570-609) runs the
   check_and_record fragment detail (:575-596) then calls
   reinject_ipsec_passthrough (:598), which builds ipsec_passthrough_decision()
   (LocalDelivery, local_ifindex 0, poll_stages.rs:1148-1160) and calls
   maybe_reinject_slow_path_from_frame_with_outlet with
   SlowPathOutlet::Adjudicated (poll_stages.rs:1405-1425, outlet at :1420).
6. Outlet to queue: SlowPathOutlet docs
   (userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:150-161) and mapping at
   :431-434 (Adjudicated to enqueue_adjudicated).
7. Queue to mark: enqueue_adjudicated writes PacketQueue::Adjudicated, queue 0
   (userspace-dp/src/slowpath.rs:1138-1144); TC consts at :40-46 (index 0,
   mapping 1, mark 0x58465001); load_queue_mark_program at :188-243 clears
   every queue's mark then sets the value only for mapping 1.
8. Fence ACCEPT: AdjudicatedTransitMark 0x58465001 plus mask
   (pkg/nftables/transit_barrier.go:33-35), counter xpf_transit_q0_delivered
   (:20), ForwardFenceSpec exact conjunction (:37-44); daemon pinhole
   xpf-usp1 plus mark (pkg/daemon/daemon_transit_gate.go:105, :107-124 docs,
   :164-168 construction).
9. Bug-moving commit 3329415f7 (Refs #10391) deliberately moved the IPsec
   reinject from Delegated/false to SlowPathOutlet::Adjudicated in the same
   commit that added multi-queue TUN plus TC plus fence conjunction (verified
   hunk). Pinning test
   userspace-dp/src/afxdp/tests_slow_path_disposition.rs:1291-1306 asserts the
   Adjudicated outlet with the "exempt classes never gate-passed, but ...
   must carry the structural fence mark" comment — pins the bug as intended.

### 2.2 Raw ESP/AH never reach the mint or any gate (flowless to NotClaimed)

- The shim resolves L4 for exactly TCP, UDP, ICMP, ICMPv6; everything else
  gets a placeholder (0,0,0,0) tuple
  (userspace-dp/src/afxdp/frame/inspect.rs:1091-1125, esp. :1096-1100).
- metadata_tuple_complete refuses every other protocol (:1125 `_ => false`),
  so ESP (50), AH (51), GRE (47), OSPF (89) "stay flowless and take the
  route-based, session-less forward path" (:1111-1115), which still forwards
  and still applies zone policy, input filters, and PBR on the flowless arm
  (:1113-1115).
- parse_flow_ports has no arm for ESP/AH (:1366 `_ => None`), and every
  SessionFlow builder propagates the None, so parse_session_flow_from_bytes
  returns None for ESP/AH. Pinned by
  userspace-dp/src/afxdp/frame/tests_shim_ext_parity.rs:2727-2730 ("#6837: ESP
  has no shim-resolved L4 identity, so its placeholder tuple is refused").
- Stage 11 returns NotClaimed for flow None BEFORE the predicate
  (poll_stages.rs:1304-1306 precede :1308), so raw ESP/AH never reach
  is_ipsec_traffic, owns_configured_ip, classify, or the reinject. They take
  ordinary transit forwarding — no mint, no fence mark, no SA gate to design.
- Non-first outer fragments: v4 substitutes PROTO_FRAGMENT_NO_L4 (255) at
  userspace-xdp/src/lib.rs:1590-1591 (with the first-fragment 8-byte minimum
  at :1597-1599 and the tuple-tolerant fallback at :1608-1615); v6 substitutes
  the same sentinel at :1724-1725 (fail-closed map discipline at :1705-1723).
  is_ipsec_traffic(255, ·) is false, so outer non-first fragments are
  NotClaimed at :1307-1310. Independently, userspace refuses non-first
  fragments a SessionFlow at the single chokepoint
  (userspace-dp/src/afxdp/frame/inspect.rs:1574-1585, esp. :1583-1584) because
  meta.flow ports may hold payload bytes (:1576-1578); documented in
  userspace-dp/src/afxdp/frame/README.md:137-153 (flowless stateless forward,
  no policy-on-fake-ports; GRE decap inherits None and stamps (0,0) at :154).
- GRE-inner ESP/AH: stage_native_gre_decap (poll_stages.rs:331-342, called at
  poll_descriptor/mod.rs:308-314) swaps to the inner meta/frame, which then
  goes through the SAME flowless parser — inner ESP/AH are NotClaimed. Only
  GRE-inner UDP reaches Stage 11. The v1 §2.4 "GRE-inner IPsec ... part of the
  unadjudicated population" holds for GRE-inner UDP only.
- Consequence: v1 §5.4.1-2 (ESP/AH SPI parsers), §5.4.5 (outer non-first drop),
  §6.1 ESP/AH parser cells, and §6.3/§7 proto-50 U-5 probe are DELETED as dead
  code/tests/probes (flowless proof inspect.rs:1113-1115). The forwarding README
  secondary-path sentence listing "transit/NAT IPv4 AH"
  (forwarding/README.md:1084-1093, esp. :1087) is stale post-#6837 for the AH
  half (raw outer ESP was already noted as shunted at :1105-1108). The same
  README's "configured interface IPs, including SNAT/WAN IP and VIPs" wording
  at :1099-1100 is stale for VIP ownership; the source insert sites and this
  plan's NotClaimed cell are authoritative.

- #6837 MUST NOT be reversed: reintroducing SessionKey { protocol, 0, 0 }
  aliasing reinstalls "two entries per transit flow, aliasing every distinct
  flow between one endpoint pair onto one key" (inspect.rs:1106-1109) and
  re-opens the closed defect (issue #6837 is CLOSED: "non-TCP/UDP/ICMP
  protocols bypass the flowless path via the metadata fallback and get
  degenerate zero-port session keys"). A discriminator-based session for ESP
  is #7188 future work on the PARSE side (inspect.rs:1117-1124) and is out of
  scope. Any v3 that requires raw-ESP gating via #6837 reversal is KILL-grade.

### 2.3 VRRP half dropped with proof (VIPs cannot satisfy the claim)

- Userspace ownership sets are built from exactly two sources: interface
  addrs from the config snapshot (configured_iface_v* always;
  local_v* unless NAT-excluded —
  userspace-dp/src/afxdp/forwarding_build/interfaces.rs:605-640, inserts at
  :609/:613 and :636/:640) plus static-NAT externals and DNAT destinations
  (forwarding_build/mod.rs:880-922, inserts at :906/:914). NOTHING in
  forwarding_build inserts VRRP VIPs (VIPs are kernel-added by the VRRP
  subsystem, not config interface addrs).
- owns_configured_ip(ip) = configured_iface_v* OR local_v* membership
  (userspace-dp/src/afxdp/types/forwarding.rs:886-891; NAT-decoupled rationale
  at :874-884). A VIP is in neither set, so owns_configured_ip(VIP) is false
  and Stage 11 returns NotClaimed at poll_stages.rs:1331-1333. No mint path
  exists for VIP dst on ANY node.
- Independently, the SHIM shunts VIP dsts to the kernel before userspace sees
  them: buildDesiredLocalAddressSets adds kernel AddrList addrs (VIPs) to
  userspace_local_v4/v6 (pkg/dataplane/userspace/maps_sync.go:1094-1125,
  esp. :1094-1097 "Without this, the XDP shim doesn't recognize VIP
  destinations as local"), and is_local_destination shunts to cpumap_or_pass
  (userspace-xdp/src/lib.rs:794-806).
- BACKUP node: the VIP is absent from the kernel too, so the packet goes to
  XSK — but owns_configured_ip is still false there, so NotClaimed to
  transit. No mint on backup either.
- Therefore the issue's "VRRP BACKUP VIP" population does not exist as a
  Stage-11 claim. V2 drops the VRRP half (DNAT/static-NAT external is the
  entire pinhole population) and specifies a future-proof invariant instead
  (§5.6): if VIPs ever enter the userspace ownership sets, ownership changes
  MUST preserve the unmarked-only invariant and require owner RG forwarding-
  active (`owner_rg_for_local_address` plus
  `gate_fabric_zone_override_on_local_owner_rg` at
  userspace-dp/src/afxdp/forwarding/fabric.rs:371-415, as used by the IKE
  gate at poll_stages.rs:1200-1213), with a VIP-dst to NotClaimed pin test
  guarding the current posture.

### 2.4 Complete q0-writer inventory (fence-level blast)

Three logical writers select PacketQueue::Adjudicated (queue 0, marked):

1. IPsec passthrough (THIS ISSUE — ungated): poll_stages.rs:1420 outlet
   selection via the :598 call site; enqueue_adjudicated with lease None
   (slowpath.rs:1138-1144). No SA check, no policy check for the Exempt class.
2. Missing-neighbor adjudication (policy-proof gated): filtered chokepoint
   selects Adjudicated only when missing_neighbor_adjudicated is true, with
   the "explicit userspace adjudication proof" comment
   (poll_descriptor/mod.rs:7249-7268, outlet at :7261; mapping at
   userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:433 routes through the same
   enqueue_adjudicated API).

3. #9506 Go-submit xfrmi-plaintext (lease plus admission gated):
   submit_adjudicated_frame builds PacketQueue::Adjudicated with lease Some
   (slowpath.rs:1392-1394, fn at :1324-1440) after admit_with_class plus
   pre-checks; the delegated worker routes Adjudicated requests to the
   adjudicated_tun fd (:1583-1589) and enforces the q0 lease check as the
   authorization linearization point immediately before the TUN write
   (:1598-1613, PreWrite::Proceed required).

For the IPsec class the reinject site is the SOLE mint among
SlowPathOutlet::Adjudicated references (4 files times 1 hit: poll_stages.rs
mint, poll_descriptor/mod.rs chokepoint, slow_path.rs mapping,
tests_slow_path_disposition.rs pin). Structural refs: TC consts
(slowpath.rs:40-46), TC loader (:188-243), fence spec plus mark plus counter
(transit_barrier.go:20, :33-35, :37-44), daemon gate (daemon_transit_gate.go:
105, :107-124, :133-184, pinhole :164-168).

Blast counts (re-verified): reinject_ipsec_passthrough 1 def / 1 call site /
1 import; enqueue_adjudicated 3 files; AdjudicatedTransitMark 6 files (3 prod
plus 3 tests); is_ipsec/classify 5 files; XfrmState/XfrmPolicy/SADB/sadb ZERO
hits in userspace-dp/src plus pkg (pkg/routing/xfrm.go manages xfrmi
lifecycle only — LinkAdd/Del, if_id derivation — no SA state); IKE-only
extractors (ike_initiation_spi, established_ike_initiator_spi, ipsec.rs:159-199)
with ESP-in-UDP explicitly returning None; IkeExchangeTable IKE-only
(ipsec.rs:206-299: cap 4096, 24h idle, Mutex, Arc-shared, NOT HA-synced,
"the ESP data plane is exempt throughout" at :291).

Not-already-fixed at tip: issue #10516 OPEN (title/body/state/comments/url
re-read; body 3266 chars; 1 comment, the #10525/#10518 cross-link); merged-PR
searches for 10516 empty and for passthrough/adjudicated show only #10410
(mark admission), #8236 (NoRoute adjudication), #6691 (secure-tunnel netdev —
#5619 PR1), none of which is this fix; SlowPathOutlet/xpf-usp1 merged search
empty; git log grep shows only the v1 plan commit plus #10391 infrastructure
plus the CLOSED #6837 portless-tuple work. SlowPathOutlet::Adjudicated still
at poll_stages.rs:1420, pin still at tests_slow_path_disposition.rs:1300.

Cross-links: #10525 OPEN (DNAT-to-self IKE gate — same stage, gate-vs-outlet
split, shared check plus tests); #10518 OPEN (GRE TunOrigin — joint armed
experiment with GRE-inner UDP, §7); #5620 (dst pin with DNAT caveat);
#4323/#6471 (IKE gating, untouched); #10391/3329415f7 (mark infrastructure);
#9506 (q0 writer 3); #6837 CLOSED (must not reverse).

## 3. Why outlet-only is insufficient (kept from v1)

Changing poll_stages.rs:1420 to SlowPathOutlet::Delegated would stop minting
the fence mark for the unadjudicated class (queue 1 stays unmarked per
slowpath.rs:188-243 and hits fence DROP on FORWARD). By itself it does NOT
satisfy this lane's explicit requirement that the fix REQUIRE the SA check:
without the positive gate, no-SA spoofed UDP still consumes the delegated TUN
queue and XFRM input work. The chosen design therefore makes Delegated the
only SA-HIT outlet, not a replacement for the SA gate. SA misses, stale/error,
and unparseable packets drop before any queue write.

## 4. Options (revised for UDP scope and no-q0 closure)

### Option A — Outlet-only (Adjudicated to Delegated). REJECTED as the fix.

Same change and effect as v1 §4-A, now scoped to the UDP population. Rejected
because it has no positive SA gate; it remains the safe emergency rollback
shape, not the issue fix.

### Option B — SA-gated, never-mint-Adjudicated (chosen).

Insert a live-SA existence gate between the Passthrough verdict and reinject.
Every proven-SA packet uses unmarked Delegated; every miss/error/truncation/
keepalive drops. This preserves legitimate INPUT/XFRM delivery and makes all
FORWARD routes hit the armed fence DROP. No kernel-local or VRRP/mastership
oracle authorizes q0. Full design in §5.

### Option C — SA-gated plus any Adjudicated mint. REJECTED.

Any SA-hit Adjudicated outlet, whether restricted to kernel-local or extended
to owned-but-not-local, turns mere cache existence into the armed q0 token.
The kernel-local/configuration sets are not a race-free authorization oracle,
and FORWARD never consumes XFRM. No Option-C hatch is permitted in this plan;
future availability work would need a separate authorization contract and
review.

### Option D — Return NotClaimed for unproven (ordinary transit). REJECTED.

Breaks intended INPUT/XFRM passthrough on any cache miss and re-litigates the
deliberate perf exemption. Unchanged from v1.

## 5. Chosen design — Option B (SA-gated, never-mint-Adjudicated, fail-closed)

### 5.1 Insertion point and control flow

Primary (and only) insertion: the IpsecPassthroughOutcome::Passthrough arm in
userspace-dp/src/afxdp/poll_descriptor/mod.rs:570-609, between the #9950
fragment check_and_record (:575-596) and the reinject_ipsec_passthrough call
(:598). The gate runs only for packets that passed match plus local-dst plus
admission plus fragment-overlap (rare path, no common-datapath cost) and
before any queue write (no mint-then-revoke). Gate cells therefore belong in
poll_descriptor tests, NOT poll_stages_tests (which cover the verdict
function only) — see §6.

The arm HAS the parsed flow (flow.as_ref() is Some — the check matched on it
at :559-568), so the SA key uses flow.dst_ip and flow.src_ip directly
(authoritative, parsed). The alternative of gating inside
reinject_ipsec_passthrough is REJECTED unless its signature is changed to
thread the flow addrs: it takes (packet_frame, meta, …) with NO flow
(poll_stages.rs:1405-1410). meta.flow_dst_addr exists
(userspace-dp/src/afxdp/types/mod.rs:186-187) but is shim-stamped, and the
shim-stamped L4 tuple is known-unreliable for fragments
(inspect.rs:1576-1578) — flow is authoritative, meta is not. No
implement-time latitude on this point: gate at the arm with flow-derived key.

The arm MUST classify the already-admitted IKE branch before the ESP SPI
parser. Reuse the exact `isakmp_demux` semantics from
`userspace-dp/src/afxdp/forwarding/ipsec.rs:84-112`, and distinguish transport
demux from the outlet predicate: for UDP-500, a present payload slice of any
length, including empty or 1-15 bytes, is `Isakmp`; only an absent payload
slice (a truncated UDP header) is `Truncated` (ipsec.rs:96-98, :108-111). For
UDP-4500, only a payload whose first four bytes are all zero is `Isakmp` (the
four-byte marker). The outlet-level `is_admitted_positive_ike` branch narrows
that positive demux to a complete 16-byte ISAKMP header (the responder-SPI
span checked by classification at ipsec.rs:143-148); shorter or `Truncated` packets
are malformed IKE and drop under §5.7. Established-IKE spoof without the
#6471 live-exchange seed is Denied in stage_ipsec_passthrough_check
(:1367-1395) and never reaches this arm.

Pseudocode at the arm (names illustrative; implementer reuses in-tree styles;
exact fail path mirrors :599-606):

  Passthrough => {
    // existing frag-overlap check_and_record block unchanged (:575-596),
    // yielding admission_to_commit: Option<OverlapAdmissionToken>
    // NEW: branch on the existing demux before the data-plane SA gate
    //   let outlet = if is_admitted_positive_ike(packet_frame, meta) {
    //     // IKE passed #4323/#6471 and has a complete 16-byte header.
    //     // No SA lookup is permitted; always unmarked/q1.
    //     SlowPathOutlet::Delegated
    //   } else if is_malformed_ike(packet_frame, meta) {
    //     // UDP-500/4500 IKE demux-positive but short/truncated header.
    //     sa_miss_dropped_packets.fetch_add(1, Relaxed);
    //     sampled_sa_miss_exception_reason("malformed_ike"); // §5.8
    //     if let Some(tok) = admission_to_commit.take() {
    //       worker_ctx.forwarding.nat64.frag_overlap.fail_admission(tok);
    //     }
    //     binding.scratch.scratch_recycle.push(desc.addr);
    //     continue; // NEVER run the 4500 ESP parser or reinject
    //   } else {
    //     // UDP-4500 ESP-in-UDP data plane only; malformed/unknown -> miss
    //     let (dst, src) = (flow.dst_ip, flow.src_ip);   // flow is Some here
    //     let spi = esp_in_udp_spi(packet_frame, meta); // §5.4; None => miss
    //     let proven = spi.is_some_and(|s| sa_cache.lookup(dst, s, src));
    //     if proven {
    //       SlowPathOutlet::Delegated                      // ALWAYS unmarked/q1
    //     } else {
    //       sa_miss_dropped_packets.fetch_add(1, Relaxed);
    //       sampled_sa_miss_exception(...);                 // §5.8, may skip
    //       if let Some(tok) = admission_to_commit.take() {
    //         worker_ctx.forwarding.nat64.frag_overlap.fail_admission(tok);
    //       }                                               // mirror :603-605
    //       binding.scratch.scratch_recycle.push(desc.addr);
    //       continue;                                       // NEVER reinject
    //     }
    //   };
    //   // existing reinject now takes the computed outlet (signature gains
    //   // one param; the ::Adjudicated literal at :1420 is deleted):
    //   let accepted = reinject_ipsec_passthrough_with_outlet(..., outlet);
    //   // existing commit/fail of frag admission on accepted (:599-606)
    //   ...
  }

Denied (:610-630) and NotClaimed paths unchanged. No error/nil/unknown path
reaches an outlet selection — every one takes the drop arm. Admitted positive
IKE is the sole non-SA branch and always selects Delegated; malformed
IKE/UDP-500 never reaches the ESP parser; a true SA lookup never selects
SlowPathOutlet::Adjudicated: Stage 11 has no q0 mint.


### 5.2 What "SA proof" means (UDP data plane only)

The gate applies to the UDP-500/4500 data plane ONLY:

- ESP-in-UDP (UDP 4500, non-marker, non-keepalive per the demux at
  ipsec.rs:99-107): gated on the SA cache (§5.3-§5.5).
- NAT-T keepalive (UDP 4500, 1-byte 0xFF): no SPI, no SA — dropped as
  unproven with its own counter. Safe: keepalives refresh NAT bindings by
  TRAVERSING the peer's NAT outbound, not by being delivered to our IKE
  daemon; our daemon originates its own keepalives (never inbound Stage-11
  packets) and ignores inbound 0xFF (no reply is defined). Dropping inbound
  keepalives at Stage 11 therefore affects no NAT state and no IKE state
  machine. Counter plus release note required; strongSwan non-reply behavior
  to be confirmed by the implement lane against a live daemon (one armed-box
  observation, §7).
- Tiny/truncated UDP-4500 data (payload shorter than the SPI word, UDP header
  itself truncated): unproven, dropped. For UDP-500 or UDP-4500 marker IKE,
  the §5.1 malformed-IKE branch handles a missing/shorter 16-byte ISAKMP
  header before the ESP parser and drops it with the same fail/recycle path.
- IKE ISAKMP (UDP 500 direct, UDP 4500 with the four-byte zero marker):
  admitted IKE means the demux is positive and the ISAKMP header is complete
  (at least 16 bytes); it is OUT OF THE SA gate but NOT out of the outlet
  decision. It has passed #4323/#6471 host-inbound/live-exchange admission and
  selects unmarked Delegated/q1 without any SA-cache lookup. This preserves
  local IKE INPUT delivery; an IKE packet to a transit-DNAT destination is
  intentionally unmarked and is dropped by the FORWARD fence. An empty/short
  UDP-500 payload may be host-inbound-gated as NewInboundIke, but if permitted
  it takes the explicit malformed-IKE drop arm under §5.7 rather than the
  Delegated branch. An unseeded established-spoof is Denied by :1367-1395
  before this arm.
- Raw ESP/AH (proto 50/51): unreachable (flowless to NotClaimed, §2.2) — no
  parser, no gate, no test cells beyond the NotClaimed pins (§6). AH (v4 and
  v6) is DEFERRED permanently with the flowless proof (no AH work exists to
  schedule).

The gate proves EXISTENCE of a current inbound SA matching (dst, SPI, src)
using only fields the XFRM UAPI exposes (§5.5). It does NOT prove anti-replay
window, lifetime bytes/packets, mode, policy, or packet authentication —
XFRM remains the final enforcer after Delegated reinjection on INPUT. For a
FORWARD route, XFRM still does not run, but the unmarked q1 packet reaches the
armed fence DROP. SA existence therefore never mints the q0 token.

### 5.3 SA key (hardened)

Key: (dst_ip: IpAddr, spi_u32: u32, src_ip: IpAddr), proto implied
ESP-in-UDP (single-protocol gate; no proto byte needed). Rationale:

- dst plus SPI mirrors the kernel XFRM state key (dst, SPI, proto); the gate
  normalizes ESP-in-UDP to ESP semantics.
- src is INCLUDED (PlanB plus fold brief; deliberate deviation from the XFRM
  state key). Cost: free (flow.src_ip is parsed). Benefit: off-path spoof of
  an observed (dst, SPI) fails the positive gate unless the attacker also
  spoofs the correct src. Even a correct observed tuple receives unmarked
  Delegated, so it cannot mint q0; INPUT still reaches XFRM and FORWARD hits
  the armed fence DROP.
- if_id (xfrmi binding): v1 IGNORES (wildcard). The packet carries no if_id
  at Stage 11 and the dst-to-tunnel map is not wired into ForwardingState.
  This remains conservative because the only positive outcome is Delegated:
  kernel INPUT XFRM enforces the binding (pkg/routing/xfrm.go:80-83), while
  FORWARD never receives the armed mark. Counter for multi-tunnel same-(dst,
  SPI) observations remains required for operator visibility.
- Mark/VRF/table: v1 ignores (dst is the raw on-wire dst as in the #5620
  check). No q0 authorization depends on this wildcard; any future narrower
  scope needs its own review.
- AH: no key (flowless, §2.2).

Open key hardening beyond v1 (explicitly deferred, NOT implement-time
latitude): dst-to-xfrmi if_id attribution (needs the xfrm.go if_id map plus
dst-to-tunnel wiring in ForwardingState); src-port or VRF scoping. Each
needs its own plan review.

### 5.4 Parsers (ESP-in-UDP SPI only; fail-closed)

Single parser: esp_in_udp_spi(packet_frame, l4_offset, dst_port) -> Option<u32>.
dst_port is 4500 for this parser; except admitted IKE handled by the §5.1
IKE-first branch, UDP-500 is not sent here. A complete UDP-500 IKE header
reaches the Delegated branch; a short or truncated UDP-500 packet is
unparseable and drops under §5.7. Steps, all bounds-checked with .get
(mirroring isakmp_demux, ipsec.rs:84-112), no allocs, no panics:

1. UDP header present: packet_frame.get(l4_offset..l4_offset+8) else None.
2. Payload = frame[l4_offset+8..]. Check the exact one-byte
   `payload == [0xFF]` NAT-T keepalive BEFORE any `payload.get(0..4)` call:
   return None with the keepalive reason and never treat 0xFF as an SPI.
   Otherwise match payload.get(0..4):
   - None (shorter than one SPI word — includes tiny first-fragments whose
     L4 span covers the UDP header but not the SPI word): None (truncated to
     unproven). NOTE: the shim's first-fragment 8-byte minimum
     (userspace-xdp/src/lib.rs:1597-1599) guarantees the UDP tuple, NOT the
     SPI word — the parser must bounds-check the word independently.
   - Some([0,0,0,0]): IKE marker — out of scope (caller already demuxed;
     defensive None).
   - Some(spi_bytes): Some(u32 BE word 0) — the ESP SPI. A 2-3 byte payload
     is None via the get(0..4) failure, matching the existing demux shape at
     ipsec.rs:104.

3. No GRO/coalescing assumption is silently relied upon: the parser reads the
   frame as presented; state explicitly that GRO is assumed not to coalesce
   ESP-in-UDP across datagrams (no GRO hooks exist for it) AND that a
   coalesced super-frame would still parse word 0 of the first datagram
   (fail direction: wrong-SPI miss to drop, never mint-by-confusion — the
   key includes the full triple and the cache holds real SPIs).

Fragment handling (raw vs UDP separated — v1 §5.4.5 rewritten):

- Outer non-first fragments (any proto): proto-255 substituted by the shim
  (v4 lib.rs:1590-1591, v6 :1724-1725) to NotClaimed at poll_stages.rs:1307-1310,
  and independently refused a SessionFlow at inspect.rs:1583-1584. They NEVER
  reach the gate, NEVER mint, and are governed by transit policy on the
  flowless arm (frame README:137-153; flowless still applies zone policy per
  inspect.rs:1113-1115). No gate code and no "drop non-first" rule exist for
  them — there is no signal to key on at the gate (meta.protocol==255 implies
  NotClaimed upstream). The "non-first" test cell is therefore a NotClaimed
  pin (§6), not a gate cell.
- Outer first-fragment UDP-4500: flow parses (UDP tuple present), Stage 11
  may claim; the SA gate keys the SPI word if fully within the declared end,
  else truncated to drop (§5.4 step 2). Frag admission commit/fail follows
  the existing :599-606 shape, with the miss path calling fail_admission
  exactly as §5.1 specifies (fragment_overlap/mod.rs:761).
- GRE-inner fragments: re-parsed post-decap (poll_descriptor/mod.rs:308-314)
  under the same flowless rule — inner non-first is None (frame README:154
  stamps (0,0)), inner first-fragment UDP follows the outer first-fragment
  rule. No reassembly anywhere (explicitly out of scope, both reviewers
  concur).
- No shim or meta changes: preserving original next-header or adding fragment
  metadata upstream is NOT proposed (its own blast radius; unnecessary since
  outer non-first never mints).

### 5.5 SA snapshot subsystem (event-driven, deny-on-stale)

Per-packet netlink is impossible on the dataplane (syscall per packet before
cache/session/policy). v1 therefore specifies a shared, read-optimized
SA-existence snapshot with event-driven invalidation. Every choice below is
pinned — no "to be settled at implement time" remains on bypass-risking axes.

- API (exact): raw NETLINK_XFRM socket via libc (already a direct dep,
  userspace-dp/Cargo.toml:17) — NO new crate. Mirror the neighbor monitor
  exactly: socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_XFRM) per
  neighbor.rs:986-992 (which uses NETLINK_ROUTE), bind to multicast groups
  XFRMGRP_SA plus XFRMGRP_EXPIRE (cf. RTNLGRP_NEIGH bind at neighbor.rs:998-1002),
  full dump via XFRM_MSG_GETSA with NLM_F_DUMP (cf. the resolver's unicast
  GET pattern at neighbor_resolver.rs:289-307), message constants from
  UAPI linux/xfrm.h (XFRM_MSG_NEWSA/DELSA/UPDSA/FLUSHSA/EXPIRE; the implement
  lane cites numeric values from the vendored headers — symbolic names are
  normative here). Go-side vishvananda/netlink (go.mod:14, v1.3.1) is
  available but REJECTED for this path: the consumer is a Rust ArcSwap read
  by packet workers, and a Go publisher would need new cross-language IPC;
  the Rust raw-socket path has the closer precedent (neighbor monitor) and
  zero new deps.
- State filter (exact and implementable from UAPI): accept only a parsed
  xfrm_usersa_info whose family is AF_INET/AF_INET6 and id.proto is ESP
  (IPPROTO_ESP), plus a present, well-formed XFRMA_SA_DIR attribute equal to
  XFRM_SA_DIR_IN. The UAPI struct has no lifecycle state field (only flags;
  /usr/include/linux/xfrm.h:388-409), so the implementation MUST NOT name or
  test a fictional XFRM_STATE_VALID value. A missing direction attribute,
  malformed message, unsupported family/proto, or parse uncertainty is
  ineligible and is not inserted. The admissible/absent/expired/invalid
  state list is derived from message type plus these fields, not a kernel
  internal enum.
- Lifetime handling: GETSA dump records are current kernel candidates; before
  insert, reject a record whose xfrm_lifetime_cur counters already meet a
  finite hard byte/packet limit or whose hard add-time limit is already
  elapsed (compare the kernel add_time seconds in the same realtime domain;
  overflow, clock conversion failure, or uncertainty rejects).
  NEWSA/UPDSA use the same eligibility parser. XFRM_MSG_EXPIRE carries
  xfrm_user_expire {state, hard}; remove on either soft or hard expiry
  conservatively and count it, because a soft event is no longer a proof of
  continued authorization. DELSA removes immediately; FLUSHSA triggers an
  immediate full redump. ACQUIRE has no insert path. This explicitly handles
  expiry without inventing a lifecycle field.
- Direction is therefore read from XFRMA_SA_DIR, not inferred by key match.
  Require XFRM_SA_DIR_IN; outbound states and self-dst ambiguity are excluded
  before publication. No policy/selector evaluation (out of scope — this is
  an existence gate before XFRM's final INPUT enforcement).
- Events (exact): NEWSA with an eligible UAPI record inserts or refreshes;
  DELSA removes immediately; EXPIRE (soft or hard) removes immediately;
  UPDSA upserts only when eligible, else removes; FLUSHSA triggers an
  immediate full redump; ACQUIRE is ignored. ENOBUFS on the monitor socket
  triggers an immediate full redump (mirror the neighbor ENOBUFS/redump
  telemetry at coordinator/status.rs:837-842 — same three counters required:
  netlink_enobufs, netlink_redumps, netlink_redump_upserts, plus xfrm-specific
  sa_inserts/sa_removes/sa_expiry_removes).
- Drift sync: 30s periodic full GETSA dump reconciles any missed event
  (NOT the primary freshness mechanism — the monitor is). Any drift-sync
  failure, any monitor socket error, or any redump failure sets the STALE
  flag immediately (first failure, no grace count) — see deny-on-stale.
- Deny-on-stale (normative, replaces v1's 3-miss ceiling and last-good
  latch — both DELETED as fail-open): while STALE is set, EVERY data-plane
  SA lookup returns miss (deny-all for the gated class) and a
  sa_snapshot_stale_deny counter increments; STALE clears only on the next
  successful FULL dump. There is NO last-good window, NO T-second over-admit,
  NO negative-cache interplay (there is no negative cache — miss means drop
  and heal on the next insert). A deletion therefore stops the positive
  Delegated reinjection within one monitor-event latency (milliseconds),
  never within one poll interval; no deletion can create a q0 mint.
- Owner thread (exact): `xfrm-sa-monitor`, a supervised aux thread mirroring
  the neighbor monitor lifecycle: spawn via spawn_supervised_aux (mirror
  `userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:1107-1136`, incl.
  catch_unwind no-respawn semantics
  plus spawn-failure retry with BOTH handles None), stop plus JOIN via
  retained monitor_stop/monitor_join handles (mirror
  coordinator/neighbor_manager.rs:51-61 and stop_and_join_monitor at :168-176
  — joining, bounded by a 500ms SO_RCVTIMEO, is the no-mutation-after-stop
  guard), 500ms recv timeout (same bound), process-wide thread-count leak
  gates mirroring the #6637/#7413 neigh-monitor gates. It owns the ONLY
  writer to the snapshot ArcSwap.

- Ready-gate (exact): block dataplane-ready on the FIRST successful full
  dump (blackout == one dump latency, millisecond-scale, one-time, measured
  and asserted in §6). Defense in depth regardless of hook wiring: workers
  deny while the snapshot payload's generation == 0 (no successful dump
  ever published), so any hook omission fails closed by construction. The
  implement lane names the exact ready hook plus its test pin; the
  generation-0 deny makes the hook choice non-bypass-risking.
- Snapshot structure (exact): Arc<FxHashMap<SAKey, SAEpoch>> behind ArcSwap
  (rustc-hash is a direct dep, Cargo.toml:20; FastMap==FxHashMap precedent at
  afxdp/types/mod.rs:43; ArcSwap publisher precedent: local_tunnel_deliveries
  at coordinator/mod.rs:262 and :549, plus CoS maps and ha_state). SAKey =
  (dst: u128 network-order, spi: u32, src: u128). SAEpoch = insert
  generation (u64, for telemetry/overlap measurement only — NOT a TTL).
  Worker read path: ONE ArcSwap load per batch/tick into a worker-local Arc
  clone, then HashMap::get per IPsec-claimed packet. No locks, no allocs, no
  syscalls on any worker. Cap 4096 entries plus control-thread-ONLY eviction
  (oldest insert-epoch) plus eviction counter (mirrors
  IKE_EXCHANGE_TABLE_CAP plus evictions at ipsec.rs:206 and :294-298, but
  with lock-free reads — the IKE Mutex is safe ONLY at IKE pps, ipsec.rs:273-283,
  and MUST NOT be reused at ESP-in-UDP data rates).

- DELETED v1 claims: "Over-admit is bounded by T and closed by XFRM's own
  drop" (§5.5), "same-SPI collision resolves as proven, XFRM enforces on
  input" as a FORWARD argument (§5.3), "3 missed polls to deny-all" and
  "latch last-good" (§5.8), "snapshot poison" terminology (restated as
  poller-error latching onto STALE). The corrected closure is stronger:
  Stage 11 never selects SlowPathOutlet::Adjudicated, even for a local
  destination. A positive SA lookup selects Delegated/q1; a miss/stale/error
  drops. Thus no snapshot race or observed SPI can mint q0. The q1 INPUT
  path still lets XFRM enforce packet authentication, while q1 FORWARD
  traffic reaches the armed fence DROP.

### 5.6 No-q0 disposition and actual local-consumer proof

No `is_kernel_local_ip` helper is introduced and no configured/local set is
treated as a mint authorization oracle. `owns_configured_ip` remains the
Stage-11 CLAIM gate (interface addrs plus NAT externals), but its result never
selects Adjudicated. Ordinary direct interface addresses and current VIPs are
shunted by the XDP shim before AF_XDP (`userspace-xdp/src/lib.rs:794-806`);
interface-NAT-excluded direct addresses are the explicit XSK exception and
follow table rows 8/9 (Delegated on a hit, drop on a miss), never q0.


The q0/q1 consumer split is concrete, not a naming convention:

- `slowpath.rs:1506-1555` opens the Delegated outlet's primary TUN plus a
  separate `adjudicated_tun`; `slowpath.rs:1583-1586` maps
  `(Delegated, PacketQueue::Delegated)` to the primary `tun.as_raw_fd()`.
- `slowpath.rs:1586-1589` maps `PacketQueue::Adjudicated` only to the
  separate adjudicated TUN, whose ingress classifier is the q0 mark path
  (`slowpath.rs:188-243`). Stage 11 will no longer submit that queue.

- The remaining q0 writers are the missing-neighbor policy-proof path and the
  #9506 lease/admission path (complete inventory §2.4/App. C). Those are
  unrelated authorization consumers; neither is needed for a packet delivered
  to kernel INPUT. Removing the Stage-11 q0 writer therefore removes no
  legitimate local-input requirement.

Actual local-consuming Stage-11 proof uses the reachable GRE-inner population,
not a direct interface-IP frame. For native GRE, the XDP inner classifier
returns USERSPACE_SESSION_ACTION_REDIRECT when the inner destination is in
USERSPACE_INTERFACE_NAT_V4 or USERSPACE_LOCAL_V4
(`userspace-xdp/src/lib.rs:1147-1155`), so the outer GRE stays on XSK
(`:831-835`); Stage 6 decapsulates it (`poll_descriptor/mod.rs:308-314`),
then the normal parser and Stage 11 see the inner UDP-4500 frame and its
interface-local destination. A proven inner (dst,SPI,src) SA therefore writes
the primary xpf-usp1 TUN through `PacketQueue::Delegated`, without q0. The
kernel receives that inner packet on xpf-usp1 and routes it through INPUT,
where XFRM applies inbound state/policy and if_id binding
(`pkg/routing/xfrm.go:80-83`). INPUT is outside the transit-barrier FORWARD
conjunction (`pkg/daemon/daemon_transit_gate.go:133-184`,
`pkg/nftables/transit_barrier.go:37-44`), so it never required q0. The
valid-SA-local cell MUST use this GRE-inner path and observe Delegated queue 1,
q0 delta zero, and INPUT/XFRM delivery.

DNAT/static-NAT externals remain the live transit population: they are absent
from shim local maps and are steered to XSK (`userspace-xdp/src/lib.rs:
794-825`); forwarding build owns the raw pre-NAT external
(`forwarding_build/mod.rs:880-922`). The gate key is the raw parsed
`flow.dst_ip` (§5.1/§5.3). If an external mapped to this firewall is
translated before the kernel's XFRM lookup, its XFRM `id.daddr` may be the
post-DNAT local address rather than the raw external. In that mismatch case
the exact SA lookup misses and drops; the fix MUST NOT claim DNAT-to-self
function preservation or add an unreviewed external-to-translated-local
candidate lookup. If the raw external is the kernel SA key, a hit still uses
unmarked Delegated and INPUT/XFRM remains functional. A DNAT external mapped
to another host is unmarked q1 and reaches FORWARD, where the armed fence
drops it. This explicit mismatch disposition is fail-closed and is a
release-noted availability consideration for any future candidate-key plan.

Disposition table (Stage-11 populations, post-admission):

| #  | dst class                                  | SA   | disposition       | rationale                                  |
|----|--------------------------------------------|------|-------------------|--------------------------------------------|
| 1  | GRE-inner -> interface-local target        | hit  | Delegated         | primary TUN; INPUT/XFRM; q0 zero           |
| 2  | GRE-inner -> interface-local target        | miss | drop+sa_miss      | no proven SA                               |
| 3  | NAT external -> DNAT-to-self, key hit      | hit  | Delegated         | INPUT/XFRM; q0 zero                        |
| 4  | NAT external -> DNAT-to-self, key miss     | miss | drop+sa_miss      | explicit raw/post-NAT mismatch             |
| 5  | NAT external -> transit target             | hit  | Delegated         | unmarked q1; FORWARD fence                 |
| 6  | NAT external -> transit target             | miss | drop+sa_miss      | no SA, no function to preserve             |
| 7  | outer direct interface IP or VIP           | —    | NotClaimed        | shim shunt/ownership; no Stage 11          |
| 8  | outer interface-NAT-excluded direct IP     | hit  | Delegated         | XSK claim; INPUT/XFRM; q0 zero             |
| 9  | outer interface-NAT-excluded direct IP     | miss | drop+sa_miss      | no proven SA                              |
| 10 | admitted positive IKE                      | —    | Delegated         | positive demux + complete >=16B SPI prefix; no SA lookup; q0 zero |
| 11 | malformed IKE                              | —    | drop+malformed_ike | short/truncated UDP-500 or UDP-4500 marker; no SA/outlet/q0 |
| 12 | unowned                                    | —    | NotClaimed        | existing :1331-1333 gate                   |

IKE-row legend: row 10 requires positive `isakmp_demux` plus a complete
>=16-byte ISAKMP Initiator/Responder SPI prefix (the classifier's
`isakmp.get(8..16)` span), then selects unmarked Delegated/q1 without an SA
lookup. Row 11 is demux-positive but short/truncated UDP-500 or short
UDP-4500-marker IKE; it increments `malformed_ike`, fails any fragment
admission token, recycles, and never selects an outlet or q0. Neither row
reaches the ESP parser.

Rows 1, 3, 5, and 8 are positive SA hits and intentionally use the same
unmarked outlet. Rows 2, 4, 6, 9, and 11 drop regardless of destination;
row 10 is the admitted-IKE exception and deliberately skips the SA lookup.
Locality is observed for proof and tests, never used to mint q0. An unseeded
established IKE spoof is Denied before this table. A BACKUP-VIP cannot reach
this table under the current shim/ownership proof. If a future change puts
VIPs into userspace ownership, it MUST preserve the unmarked-only invariant
and separately require active-RG authorization; no VIP change may reintroduce
Stage-11 Adjudicated.

Fence, mark, counter, TC: unchanged. `xpf_transit_q0_delivered` no longer
counts Stage-11 IPsec traffic after this fix; it remains the witness for the
other q0 writers and must stay zero for every Stage-11 cell.

### 5.7 Fail-closed rules (normative)

- Every error/nil/unknown SA path denies (no fallback mint, no
  else-Adjudicated, no outlet default).
- Unparseable (truncated, keepalive-shape ambiguity resolved as keepalive to
  drop, non-UDP reaching the arm) denies.
- Empty/unready snapshot (generation 0, no successful dump yet) denies.
- STALE set (any monitor error, redump failure, or drift-sync failure)
  denies ALL gated lookups immediately plus the staleness counter; clears
  only on a successful full dump. No grace count, no last-good latch.
- No config knob or hatch permits a positive hit to select Adjudicated.
  Any future availability exception needs a separate authorization contract
  and review; it cannot be an implement-time option in this fix.
- No alloc/copy/compute on the common path: the gate runs only for
  is_ipsec_traffic packets that passed all prior gates (rare), and costs one
  parser (bounded slice reads) plus one map get on a worker-local Arc
  snapshot. There is no locality oracle or second mint decision.

### 5.8 Miss path (lock-free, flood-safe)

Per-miss work on the worker:

1. Atomic counter ALWAYS: sa_miss_dropped_packets.fetch_add(1, Relaxed)
   (plus reason-split counters: no_sa, truncated, malformed_ike, keepalive,
   stale_deny). No lock, no alloc, wait-free.
2. Exception event CONDITIONALLY: thread-local 1-in-N pre-gate (mirror
   `REDIRECT_SAMPLE_SEQ: Cell<u64>` sequence, no shared RMW —
   `userspace-dp/src/afxdp/binding_state/latency.rs:54-61`; non-sampled cost
   ~one fetch_add plus mask, `userspace-dp/src/afxdp/binding_state/tx_inbox.rs:
   157-164`) with N=256, THEN the existing per-worker ring
   `admit(key, now)` sampler (afxdp/disposition.rs:473-474) via
   record_exception with a &'static reason (alloc-free per :454-461) or
   record_exception_suffixed for miss sub-reasons (alloc-free per :521-529,
   the #6101 slow-path precedent at
   `userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:441-453`). The ring Mutex is
   per-worker (disposition.rs:227-228 "no cross-worker contention"), and the
   pre-gate means 255/256 misses never touch it. No per-event String, no
   Utc::now, no tuple-rich owned payload on the flood path (tuple detail
   lives in the sampled 1/256 only).

3. Frag admission fail plus recycle per §5.1 (fail_admission takes a shard
   lock at fragment_overlap/mod.rs:761-764 — acceptable: only for packets
   that already hold an admission token, i.e. fragments, never for the
   unfragmented flood).

Flood bar (§6, §10): 1Mpps spoofed ESP-in-UDP flood to a DNAT external —
workers sustain line processing, sa_miss counter linear with offered load,
sampled exceptions bounded (~3900/s at N=256), no worker stall, no
cross-worker cacheline traffic beyond the shared IpsecSaStore atomics.

### 5.9 Perf budget (numeric)

- Non-IPsec packets: ZERO extra work (early NotClaimed at :1304-1310
  unchanged). Bar: iperf3 line-rate forwarding regression <1% vs base
  (same binary with gate compiled out is NOT an acceptable control — measure
  gate-present vs pre-change on identical hardware; the gate is downstream
  of the claim, so the expected delta is noise).
- IPsec-claimed UDP packets: one parser (bounded .get reads, branch-light)
  plus one FxHashMap get on a worker-local Arc. Bar: <2% single-flow
  UDP-4500 throughput delta on the proven-SA path; ESP-in-UDP no-SA flood
  drop cost linear with zero allocs (allocator counters flat).
- Snapshot publish (control thread): full rebuild plus ArcSwap store per
  event-batch/30s; may alloc freely. Bar: <10ms p99 publish latency at 4096
  entries; worker tick never blocks on publish (ArcSwap acquire/release).
- Cap/eviction: 4096 entries (mirrors IKE cap scale for this box class),
  control-thread-only oldest-epoch eviction, eviction counter with alarm
  threshold (nonzero means cap binding — same operator meaning as
  IkeExchangeTable::evictions, ipsec.rs:294-298).

### 5.10 HA, restart, rekey, strongSwan compat

- Restart: empty snapshot (generation 0) drops all gated data-plane IPsec
  until the first dump lands (fail closed); ready-gate (§5.5) bounds the
  blackout to one dump latency (ms-scale) by blocking dataplane-ready.
  Measure and assert the blackout in §6 (upper bound 5s including
  worst-case dump at 4096 entries).
- HA/failover: NOT synced (same gap as the IkeExchangeTable, ipsec.rs:285-291,
  plus kernel conntrack plus kernel XFRM states themselves — none sync for
  host-terminated IPsec). The new node builds from its own kernel (empty to
  drops until IKE re-establishes via DPD/rekey/re-auth). BACKUP mints
  nothing (§2.3, §5.6). No new XFRM-sync dependency for v1.
- Rekey overlap: strongSwan make-before-break emits an eligible NEWSA/UPDSA
  record before the old SA's DELSA/EXPIRE removal; both records are present
  during overlap when the monitor delivers them. The implement lane PROVES
  this with a live rekey while flooding proven-SA traffic: zero sa_miss spike
  across the overlap window (counter assertion, §6/§7). No kernel-internal
  DYING/VALID state test is claimed; eligibility is the UAPI parser plus
  event ordering in §5.5.
- Reauth/manual-down/DPD-timeout: genuine over-drop window (old SA deleted,
  new not yet installed). Bounded by IKE re-establishment time; instrumented
  (sa_miss spike plus stale/absent telemetry); release-noted. This is the
  availability cost of fail-closed and has no hatch in this plan.
- strongSwan compat proofs required of the implement lane (each a §6/§7
  cell or armed observation): (a) rekey overlap zero-spike (above);
  (b) inbound keepalive drop causes no IKE state change and no log storm
  (daemon log assertion over 60s of keepalive flood); (c) DPD/rekey traffic
  (IKE, out of gate scope) unaffected by snapshot churn; (d) tunnel
  establishment from cold (empty snapshot to first dump to first proven
  Delegated reinject) within the ready-gate bound.

### 5.11 No availability hatch in this fix

There is deliberately no Option-C exception. A miss, stale snapshot, monitor
error, or UAPI-uncertain record drops; a hit uses unmarked Delegated. Allowing
an existence hit to select Adjudicated would recreate the issue because q0 is
the armed authorization token, regardless of whether the destination appears
kernel-local. Any future availability proposal must first provide a separate
race-free authorization contract, prove all local consumers, and receive a
new plan review. It MUST NOT be a config knob or an implement-time fallback.

## 6. Tests (real wire frames; pins that fail on the bypass)

Conventions: FAIL-ON-REVERT every security cell (state the defect that reds
it); table-driven, no sleeps/ports for unit cells; full module/file runs per
the verification rule (never only the flipped test). Gate cells live in
poll_descriptor tests (the arm), NOT poll_stages_tests (verdict-only) —
see §5.1.

### 6.1 Real-path gate cells (poll_descriptor; fake SA snapshot + real frames)

Each cell builds a REAL wire frame plus meta, runs parse_session_flow_from_bytes
through stage_ipsec_passthrough_check into the arm with a seeded/fake
snapshot, and asserts disposition plus queue plus counters:

1. no-SA ESP-in-UDP spoof to DNAT-external (v4 and v6): UDP-4500,
   non-zero SPI word, no marker, dst = DNAT-to-another-host external, empty
   snapshot — EXPECT drop at Stage 11, NO enqueue on either queue,
   sa_miss_dropped_packets +1 (no_sa), q0 delta zero. REDS ON: gate removal,
   else-Adjudicated fallback, zero-SPI-hit, outlet literal remaining.
2. valid-SA GRE-inner UDP-4500 to an interface-local destination: construct a
   native GRE outer whose classifier redirects the inner local destination
   (`userspace-xdp/src/lib.rs:1147-1155`), decap at Stage 6, and seed an
   inbound SA for the inner (dst,SPI,src). EXPECT Stage 11 Delegated outlet,
   queue 1, NO mark, q0 delta zero, and INPUT/XFRM delivery. REDS ON:
   over-drop, key mismatch (e.g. src omitted), snapshot wiring break, or any
   Adjudicated/q0 result. An ordinary direct interface-IP frame is shunted
   before Stage 11 and is not a valid substitute; an interface-NAT-excluded
   direct IP is the separate table-row-8/9 XSK population.

3. NAT-appended SA-hit to a transit target: raw UDP-4500 frame with dst a
   DNAT external mapped to another host, snapshot seeded — EXPECT Delegated
   outlet, queue 1, NO mark, and armed-fence FORWARD drop. REDS ON: any
   Adjudicated selection or egress.
4. NAT-appended SA-miss to a transit target: frame as (3) with no matching
   raw external SA — EXPECT drop (table row 6), sa_miss counter, q0 zero.
5. keepalive to drop: UDP-4500 1-byte 0xFF to DNAT external — EXPECT drop,
   keepalive counter +1. REDS ON: keepalive exemption re-added.
6. tiny first-fragment to drop: UDP-4500 first fragment with <4 payload bytes
   past the UDP header — EXPECT drop, truncated counter +1. REDS ON: short
   read panic or mint.
7. raw ESP/AH to NotClaimed (v4 ESP unfrag, v4 AH, v6 ESP, non-first frags of
   each): EXPECT NotClaimed verdict, gate never consulted (assert via verdict
   plus no SA counter movement plus transit disposition). REDS ON: #6837
   reversal (flow Some for ESP) — this cell is the reversal tripwire.
8. GRE-inner UDP-4500 no-SA to an interface-local destination: native GRE
   classifier redirect plus decap (mod.rs:308-314), then Stage-11 drop per
   cell 1. EXPECT q0 zero. REDS ON: inner path bypassing the gate.
   (GRE-inner ESP: NotClaimed pin per §2.2.)
9. VIP dst to NotClaimed: UDP-4500 to a VIP-shaped addr absent from the
   snapshot sets — EXPECT NotClaimed (owns false). REDS ON: VIPs entering
   userspace sets and then selecting any Stage-11 Adjudicated outlet; future
   ownership must retain the unmarked-only invariant.
10. stale-SPI to drop: seed snapshot, apply monitor DELSA for the key (drive
    the removal path, §6.3), probe same frame — EXPECT drop. REDS ON: T-window
    over-admit, last-good latch, removal-path break.
11. observed-SPI wrong-src to drop: seed (dst,SPI,srcA), probe same dst+SPI
    from srcB — EXPECT drop (src hardening pin). REDS ON: src dropped from
    key/lookup.
12. truncated-UDP to drop: frame ending inside the UDP header — EXPECT drop
    (unproven). REDS ON: .get removal (panic) or default-SPI invention.
13. DNAT-to-self raw/post-NAT key mismatch: seed only the translated local
    XFRM daddr, send ESP-in-UDP to the raw external dst — EXPECT drop with
    sa_miss and q0 zero; assert no unreviewed candidate-key lookup. REDS ON:
    treating NAT translation as implicit SA-key equivalence.
14a. permitted NEW-IKE: with an empty / fail-on-access SA snapshot (any SA
    lookup hard-fails), construct a complete (at least 16-byte) ISAKMP header
    with a zero responder SPI in a permitted host-inbound zone. Exercise both
    UDP-500 direct and the UDP-4500 four-byte zero-marker form where applicable.
    EXPECT #4323 host-inbound admission followed by #6471 seeding, then
    Delegated/q1, INPUT/IKE delivery, q0 zero, and no SA lookup. REDS ON:
    SA-cache access, drop, Adjudicated/q0, or transit bypass.
14b. seeded-established-IKE: with an empty / fail-on-access SA snapshot (any SA
    lookup hard-fails), construct a complete ISAKMP header with a non-zero
    responder SPI and a preexisting live #6471 seed. Exercise both UDP-500
    direct and the UDP-4500 four-byte zero-marker form where applicable.
    EXPECT host-inbound bypassed, Delegated/q1, INPUT/IKE delivery, q0 zero,
    and no SA lookup. REDS ON: SA-cache access, host-inbound re-gating,
    Adjudicated/q0, or transit bypass.
15. unseeded established-IKE spoof: establish no #6471 live-exchange entry,
    send an established-looking UDP-4500 IKE frame with a non-zero responder
    SPI — EXPECT Denied before the arm, no outlet and no SA lookup, q0 zero.
    REDS ON: spoof reaching Passthrough or minting any queue/mark.
16-frag. permitted-zone truncated UDP-500 first fragment: send a full UDP
    header whose ISAKMP payload is empty or 1-15 bytes, obtain an overlap
    admission token, and exercise the §5.1 malformed-IKE drop branch.
    EXPECT malformed_ike counter, fail_admission(token), scratch recycle, no
    SA lookup, no outlet/queue, and q0 zero. REDS ON: missing fail/recycle,
    Delegated, ESP-SPI parsing, or any q0.
16-unfrag. permitted-zone truncated UDP-500 unfragmented frame: send the same
    empty or 1-15-byte ISAKMP payload without an overlap token and exercise the
    same malformed-IKE drop branch. EXPECT malformed_ike counter, scratch
    recycle only (assert fail_admission is not called), no SA lookup, no
    outlet/queue, and q0 zero. REDS ON: fail_admission on an unfragmented
    packet, Delegated, ESP-SPI parsing, or any q0.

### 6.2 Wiring pins (arm level — NOT source text)

- Gate-to-outlet behavioral cell: drive proven/unproven through the REAL arm
  (not maybe_reinject..._with_outlet directly — that fn takes outlet as a
  PARAMETER at userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:313-435 and
  cannot prove verdict-to-outlet wiring) and assert the outlet argument
  observed at the reinject call: proven plus a current inbound SA is
  Delegated/q1, every unproven path is dropped before reinject, full-header
  admitted IKE is Delegated/q1 with INPUT delivery and no SA lookup,
  malformed-IKE/short UDP-500 takes the explicit drop arm, unseeded
  established-IKE spoof is Denied before the arm, and Adjudicated is
  impossible. REDS ON: wiring swapped, literal Adjudicated outlet restored,
  malformed-IKE path reaching the ESP parser, or queue 0 observed.
- Re-pointed pinning test (tests_slow_path_disposition.rs:1291-1306): delete
  the Stage-11 Adjudicated assertion and add behavioral rows for
  valid-SA-local-via-Delegated (queue 1, q0 zero, INPUT delivery),
  Delegated-on-NAT-appended-hit, admitted-IKE-to-Delegated, malformed-IKE
  drop, and drop-on-miss. DELETE the "exempt classes never gate-passed, but
  ... must carry the structural fence mark" comment (it states the bug). DO
  NOT add a source-text "gate precedes outlet" cell (repeats the bug-pinning
  anti-pattern — the behavioral cell above replaces it).
- No-Adjudicated-from-Stage-11 regression: enumerate every Stage-11 UDP
  disposition in the real arm and assert no call can submit
  PacketQueue::Adjudicated; leave the other q0 writers' policy-proof tests
  intact. RED-on-revert (implement lane, firsthand) is split by reversion:
  restoring only the literal Adjudicated outlet while retaining the gate makes
  hit cells 2, 3, 14a, and 14b RED, while Stage-11 miss/drop cells 1, 4, 5,
  6, 8, 10, 11, 12, 13, and 16-frag/16-unfrag remain GREEN; independent
  cells 7, 9, and 15 remain GREEN. Removing the gate/miss drop makes
  1, 4, 5, 6, 8, 10, 11, 12, 13, and 16-frag/16-unfrag RED while
  hit cells 2, 3, 14a, and 14b remain GREEN and independent cells 7, 9, and
  15 remain NotClaimed/Denied. Record both outputs in the PR.

### 6.3 Snapshot/monitor cells (deterministic, socketpair-driven)

Mirror the neighbor AF_UNIX SOCK_DGRAM socketpair seam (neighbor.rs:1101-1105;
no privileged socket, no real kernel churn). Build messages with the actual
UAPI payload: xfrm_usersa_info plus XFRMA_SA_DIR=XFRM_SA_DIR_IN. Assert NEWSA
insert and UPDSA refresh only for AF_INET/AF_INET6 ESP records with a
well-formed inbound direction; missing direction, non-ESP, malformed attrs,
and already-exhausted hard lifetime are rejected. There is no
XFRM_STATE_VALID lifecycle field to test. Assert DELSA and either soft or hard
EXPIRE immediate removal (lookup-miss on the very next get — no window),
UPDSA ineligible removal, FLUSHSA full redump, ENOBUFS redump plus telemetry
triple (mirror status.rs:837-842), 30s drift-sync reconciliation of a
planted-missed event, STALE on monitor error/redump failure/drift failure
with deny-all plus counter plus clear-on-full-dump, generation-0 deny,
ready-gate block (dataplane not ready before first dump; blackout bound 5s),
cap-4096 oldest-eviction plus eviction counter (mirror
exchange_full_evicts_oldest_not_newest at ipsec.rs:720-724 and the #6747
recency shape, adapted to control-thread-only eviction with lock-free reads),
self-dst hairpin counter cell, and no-Adjudicated/q0 output for every
positive lookup.

### 6.4 Parser plus classifier regression cells

- ESP-in-UDP SPI extractor: aligned, marker-present (None/IKE), keepalive
  (None), 2-3 byte payload (None), UDP-header-truncated (None), frame-end
  inside header (None). Each REDS ON bounds-check removal (panic or
  wrong-SPI). Mirror spi_extractors_fail_safe_on_truncation
  (ipsec.rs:613-624).
- Classifier scope unchanged (forwarding/tests.rs:3222-3292,
  ipsec.rs:626-676): keep as regression scaffolding ONLY (passes trivially —
  the gate is downstream; pins no security property).
- v6 ESP-in-UDP with ext-hdr chains: keyed by IpAddr with shim l4_offset
  parity (tests_shim_ext_parity corpus) — unit cells with Fragment plus
  Destination-Options chains.

### 6.5 Suites and isolation

Affected suites: userspace-dp frame/forwarding/poll_stages/poll_descriptor/
slowpath suites, pkg/nftables transit_barrier suites, pkg/daemon transit
fence suites — run as FULL modules/files, never single tests (sibling
regressions fail the lane). Isolated env: unique GOCACHE/GOTMPDIR per lane
under /dev/shm plus isolated CARGO_TARGET_DIR. No cluster/incus commands.
No project-wide validation in-lane (parent owns it).

## 7. Armed-box acceptance (U-5/U-5a REDONE — vacuous probe replaced)

The v1 probe ("send ESP proto 50, no SA") is VACUOUS: raw ESP is flowless to
NotClaimed (§2.2) and shows zero q0 delta even unfixed. Redone probes use
ESP-in-UDP with SPI. All runs on an armed box with live DNAT, sharing one
armed session with the #10518 GRE-inner-UDP experiment (§7 joint run):


- P0 (repro, pre-fix): ip route get <DNAT-to-another-host external>; confirm
  the (xpf-usp1, 0x58465001) ACCEPT in the fence nft listing; send ESP-in-UDP
  (UDP 4500, non-zero SPI, NO SA) to the external; read
  xpf_transit_q0_delivered delta plus kernel egress iface. EXPECT pre-fix:
  q0 delta NONZERO (reproduces the issue for the live population).
- P1 (fix, no-SA): same probe post-fix. EXPECT: q0 delta ZERO, sa_miss
  (no_sa) delta NONZERO, no egress. Any q0 delta is a fix failure.
- P2 (fix, valid-SA-local-via-Delegated): establish a real inbound tunnel/SA
  for a native GRE inner UDP-4500 flow whose inner destination is in
  USERSPACE_LOCAL_V4, send matching GRE-encapped ESP-in-UDP, and trace Stage
  6 decap into the primary Delegated TUN queue and kernel INPUT/XFRM.
  EXPECT: queue 1, no mark, q0 delta ZERO, correct INPUT/XFRM delivery
  (function preserved). Any Adjudicated/q0 result is a fix failure and
  proves the no-q0 pin is absent. This is the reachable local population;
  ordinary direct interface-IP input is shunted before Stage 11, while
  interface-NAT-excluded direct IP follows table rows 8/9.

- P3 (fix, stale-SPI): delete the SA, probe the deleted SPI within 30s.
  EXPECT: drop, sa_miss/stale telemetry, q0 delta ZERO (monitor DELSA removal
  proof — a T-window design would mint or reinject here).
- P4 (fix, observed-spoofed-src): live SA (dst,SPI,srcA); probe same dst+SPI
  from srcB to the transit external and to the GRE-inner local flow. EXPECT:
  both drop, q0 delta ZERO, no INPUT delivery for the miss; a correct srcA
  hit remains Delegated/q1 and still q0 ZERO. No XFRM-ICV proof is used to
  authorize q0.
- P5 (fix, GRE-inner UDP): GRE-encapped inner UDP-4500 ESP-in-UDP no-SA to
  the USERSPACE_LOCAL_V4 inner destination. EXPECT: drop, q0 ZERO (joint
  #10518 population).
- P6 (compat): rekey during P2 flood — EXPECT zero sa_miss spike across
  overlap (§5.10); DPD/rekey IKE traffic during snapshot churn — EXPECT no
  IKE state or log change; 60s inbound keepalive flood — EXPECT drops plus
  zero IKE state/log impact; cold establishment from an empty snapshot to the
  first proven Delegated reinject MUST complete within the ready-gate bound
  (§5.10).

Severity gate (unchanged): inward route/egress on P0-P1 pre-fix implies
High; WAN hairpin only implies Medium stands. Post-fix, P1/P2/P3/P4/P5 must
show zero q0 delta in ALL cases; P2 must additionally show Delegated queue 1
and correct local INPUT/XFRM delivery. The fix closes the pinhole regardless
of severity.

### 7.1 Approved deferred executable procedures

The following checks are intentionally deferred to an armed box or a
privileged host. They are not substitutes for the deterministic cells above:
each procedure records the exact fixture, the counters to snapshot, and the
fail-closed acceptance condition. Save command output, packet captures, and
counter snapshots under one run directory, and record the commit under test.

#### 7.1.1 Privileged live-XFRM-socket monitor variant

Run this only after the socketpair test in §6.3 is green. It proves the same
NEWSA/DELSA/EXPIRE/FLUSHSA path against the live kernel netlink socket while
using a dedicated strongSwan child and an isolated capture directory:

```bash
set -euo pipefail
run="$PWD/evidence/10516-live-xfrm-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$run"
: "${METRICS_URL:?set METRICS_URL to the daemon's Prometheus endpoint}"
: "${CHILD:?set CHILD to the dedicated strongSwan child name}"
sudo ip -s xfrm state >"$run/xfrm.before"
curl -fsS "$METRICS_URL" >"$run/metrics.before"
sudo swanctl --load-all
sudo swanctl --initiate --child "$CHILD"
sudo swanctl --list-sas --raw >"$run/sas.after-init"
sudo swanctl --terminate --child "$CHILD"
sudo ip xfrm state flush
curl -fsS "$METRICS_URL" >"$run/metrics.after-events"
sudo ip -s xfrm state >"$run/xfrm.after"
```

The run must exercise NEWSA, UPDSA, DELSA, at least one soft or hard EXPIRE,
and FLUSHSA. Acceptance is: NEWSA/UPDSA are visible on the next lookup, DELSA
and EXPIRE are misses before the next poll, FLUSHSA leaves the store stale
until a complete dump, and the monitor leaves no child or open socket after
the daemon is stopped. Attach `swanctl --list-sas --raw`, the metrics delta,
and the kernel-state snapshots. If the armed-box strongSwan profile cannot
force one of the expiry forms, mark that row `INCONCLUSIVE`; do not weaken
the deterministic socketpair cell.

#### 7.1.2 NAT, GRE, VIP, and DNAT-to-self wire variants

Use one isolated capture directory and take counter snapshots immediately
before and after each row:

```bash
set -euo pipefail
run="$PWD/evidence/10516-wire-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$run"
: "${METRICS_URL:?set METRICS_URL to the daemon's Prometheus endpoint}"
: "${INGRESS_IF:?set INGRESS_IF to the fixture ingress interface}"
curl -fsS "$METRICS_URL" >"$run/metrics.before"
sudo nft list ruleset >"$run/nft.before"
sudo tcpdump -i any -nn -s 256 -w "$run/wire.pcap" \
  '(udp port 500 or udp port 4500 or proto 47)' &
cap=$!
trap 'kill "$cap" 2>/dev/null || true' EXIT
```

Build the fixed packet manifest before the run (family, ingress interface,
source, destination, UDP ports, SPI, responder SPI, GRE inner tuple, and
expected SA key); do not hand-edit captures between rows. Replay exactly one
pcap per row and retain each generator command and exit status:

```bash
for row in nat-hit-transit nat-miss gre-inner-no-sa vip-notclaimed dnat-to-self; do
  sudo tcpreplay --intf1 "$INGRESS_IF" --pps=1 "$run/$row.pcap" \
    >"$run/$row.replay" 2>&1
done
```

* **NAT-hit-transit + fence:** send a complete UDP-4500 ESP-in-UDP frame to
  the DNAT external with a seeded inbound `(translated-dst,SPI,src)` SA.
  Require Delegated/q1, zero q0 delta, and an observed armed-fence drop on
  FORWARD; a kernel egress is a failure.
* **NAT-miss:** repeat with the same frame and no SA. Require no queue,
  `sa_miss_dropped_packets` and `sa_miss_no_sa` deltas of one, zero q0, and
  no egress.
* **GRE-inner no-SA:** decapsulate a native GRE frame whose inner destination
  is the interface-local address, then send the same UDP-4500 payload without
  an SA. Require no queue, a miss counter delta, zero q0, and no INPUT/XFRM
  delivery.
* **VIP NotClaimed:** send UDP-4500 to a VIP-shaped destination absent from
  the userspace ownership set. Require NotClaimed behavior, unchanged SA
  counters, no q0, and the normal route disposition.
* **DNAT-to-self:** send the raw-external destination while seeding only the
  translated local destination. Require a miss/drop and zero q0; any
  candidate-key lookup or Delegated result fails the row.

Stop capture after all rows, then collect:

```bash
curl -fsS "$METRICS_URL" >"$run/metrics.after"
sudo nft list ruleset >"$run/nft.after"
kill "$cap"; wait "$cap" || test "$?" = 143
```

#### 7.1.3 Fragment and parser variants

Run the two permitted-zone UDP-500 rows separately. The **16-frag** row is a
full UDP header followed by a 0--15-byte ISAKMP payload in the first fragment;
the **16-unfrag** row is the same bytes in one unfragmented frame. Record
whether an overlap admission token was issued. Both rows must take the
malformed-IKE drop arm, increment only `sa_miss_malformed_ike`, recycle the
descriptor, perform no SA lookup, and enqueue neither q0 nor q1. Only the
fragmented row may call `fail_admission`; seeing that call on the unfragmented
row fails the run.

#### 7.1.4 Armed-box P0--P6 and strongSwan compatibility

Pin the fixture before every run:

```bash
set -euo pipefail
run="$PWD/evidence/10516-armed-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$run"
: "${METRICS_URL:?set METRICS_URL to the daemon's Prometheus endpoint}"
: "${DNAT_EXTERNAL:?set DNAT_EXTERNAL to the DNAT-to-another-host address}"
sudo cli show chassis cluster status >"$run/cluster.before"
curl -fsS "$METRICS_URL" >"$run/metrics.before"
sudo nft list chain inet xpf-transit forward-fence >"$run/fence.before"
ip route get "$DNAT_EXTERNAL" >"$run/route.before"
```
Before each phase row, establish its stated SA/IKE precondition, then replay
exactly one pcap and retain the output:

```bash
: "${INGRESS_IF:?set INGRESS_IF to the fixture ingress interface}"
for phase in P0 P1 P2 P3 P4 P5 P6; do
  sudo tcpreplay --intf1 "$INGRESS_IF" --pps=1 "$run/$phase.pcap" \
    >"$run/$phase.replay" 2>&1
done
```

* **P0 (pre-fix reproduction):** on the pre-fix binary, send the manifest's
  no-SA UDP-4500 non-zero-SPI packet to the DNAT external. The q0 counter must
  increase and the packet must take the recorded fence route; this is the
  only expected non-zero-q0 row.
* **P1 (post-fix miss):** repeat on the fixed binary. Require q0 delta zero,
  `sa_miss_no_sa` positive, and no egress.
* **P2 (post-fix local hit):** establish a real inbound strongSwan SA for a
  native GRE inner UDP flow, send matching GRE-encapsulated ESP-in-UDP, and
  capture the inner path. Require Delegated/q1, zero q0, and INPUT/XFRM
  delivery.
* **P3 (stale):** delete the P2 SA, resend the exact SPI within 30 seconds,
  and require immediate miss/stale telemetry, q0 zero, and no INPUT delivery.
* **P4 (source spoof):** keep `(dst,SPI,srcA)` live and send the same
  `(dst,SPI)` from `srcB` to both transit and GRE-local destinations. Require
  both drops, zero q0, and no INPUT delivery; the srcA control packet must
  remain Delegated/q1.
* **P5 (GRE-inner no-SA):** run the P2 GRE manifest with the SA absent.
  Require miss/drop, zero q0, and no INPUT delivery.
* **P6 (compatibility):** during P2, rekey once, initiate a fresh IKE
  exchange, send DPD/keepalive traffic, and remove/reinstall the SA. Record
  `swanctl --list-sas --raw`, daemon logs, and the before/after counters.
  Require no IKE state/log errors, no q0, and the first proven Delegated
  reinject after an empty-store restart within the §5.5 ready bound.

For every row, include `swanctl --list-sas --raw` before/after and a
timestamped q0-counter delta. P0--P5 are invalid if the armed fence is not
loaded; P2/P6 are invalid if strongSwan cannot report the expected SA.

#### 7.1.5 1Mpps flood and perf-budget measurements

Use `tcpreplay` with a pinned source-port/SPI pcap so each miss is
independent and no generated packet can accidentally match a live SA:

```bash
set -euo pipefail
run="$PWD/evidence/10516-perf-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$run"
: "${METRICS_URL:?set METRICS_URL to the daemon's Prometheus endpoint}"
: "${INGRESS_IF:?set INGRESS_IF to the fixture ingress interface}"
: "${PACKET_PCAP:?set PACKET_PCAP to the fixed nonzero-SPI miss pcap}"
curl -fsS "$METRICS_URL" >"$run/metrics.before"
set +e
sudo timeout --signal=TERM --kill-after=5s 60s \
  perf stat -a -e cycles,instructions,cache-misses \
    -o "$run/perf.txt" -- \
    tcpreplay --intf1 "$INGRESS_IF" --loop=0 --pps=1000000 "$PACKET_PCAP" \
    >"$run/generator.log" 2>&1
rc=$?
set -e
test "$rc" -eq 124
curl -fsS "$METRICS_URL" >"$run/metrics.after"
```

The generator must report 60 seconds at 1,000,000 packets/s; abort and mark
the row invalid on underrun, packet loss in the generator, or a live matching
SA. Acceptance for §5.8 is linear `sa_miss_dropped_packets`, bounded sampled
exceptions (the configured sample phase, approximately 3900/s at N=256),
no worker stall, and no q0. For §5.9, run the same fixture with (a) ordinary
non-IPsec traffic, (b) proven-SA UDP-4500 traffic, and (c) the 1Mpps miss
load. Record packets/s, p50/p99 latency if available, cycles/packet,
instructions/packet, cache misses, CPU utilization, and q0/miss deltas.
Compare fixed versus the immediately preceding binary on identical hardware:
non-IPsec throughput regression <1%, proven-SA regression <2%, and all
miss/fence invariants above remain true. A missing perf counter or an
unreached offered rate is `INCONCLUSIVE`, never a pass.

## 8. Rollout and compat

- Fence/wire format: UNCHANGED (same mark, mask, iifname, counter, TC
  program). No nftables/daemon prod change; fence tests unchanged.
- Dataplane upgrade: restart blackout bounded by first-dump latency
  (ready-gate, §5.5; asserted ≤5s in §6.3). Document in release notes with
  the generation-0-deny behavior. Rollback is single-commit revert (gate
  removal restores always-passthrough-for-UDP; pinning test reverts with it;
  snapshot thread removal is part of the same commit).
- Breaking behaviors (all release-noted with counters): inbound NAT-T
  keepalive drop (§5.2 traversal argument); tiny-first-fragment UDP-4500
  drop (§5.4); DNAT-to-self raw/post-NAT SA-key mismatch drop (§5.6);
  admitted-IKE-to-Delegated for host INPUT and unmarked transit-IKE fence
  drop (§5.1/§5.6); reauth/manual-down over-drop windows (§5.10);
  fragmented-ESP senders unaffected (never reached the gate — flowless,
  §2.2 — no note needed beyond the rescope statement).
- Sequencing: land #10525 (IKE gate) and this fix in either order; both
  touch stage_ipsec_passthrough_check plus shared tests — second implementer
  rebases and re-runs the joint cells (§6). Coordinate via hub before editing
  shared files. #10518 joint armed run per §7.


## 9. Open questions (adopted resolutions)

Adopt PlanB's OQ1-12 answers except where PlanA is stricter (noted per item;
fold-brief directives win all ties):

- OQ1 severity: UNANSWERABLE from source — requires §7 P0-P6 on an armed box
  (both reviewers concur). Vacuous proto-50 probe replaced; stale plus
  observed-spoofed-src probes added (PlanA F5 + PlanB P1-7 converge).
- OQ2 lookup source: (b) monitor plus poll fallback (PlanB; fold brief) —
  raw NETLINK_XFRM monitor with immediate removal plus 30s GETSA drift-sync
  (§5.5). PlanA's poll-acceptable is SUPERSEDED (fail-open for FORWARD).
  Owner: xfrm-sa-monitor supervised aux thread; ready-gate blocks on first
  dump. NO new crate (libc raw socket, neighbor-monitor precedent).
- OQ3 key and direction: (dst, SPI, src), proto-implied, with
  XFRMA_SA_DIR_IN required from the UAPI message; if_id/mark/table remain
  wildcard only because the positive outcome is Delegated, never q0. The
  UAPI has no XFRM_STATE_VALID lifecycle field (/usr/include/linux/xfrm.h:
  388-409); eligibility uses message type, identity, direction, lifetime,
  and EXPIRE/DELSA removal (§5.5). AH deferred permanently (flowless).
- OQ4 fragments: outer non-first moot (NotClaimed, no gate — both concur);
  UDP first-frag SPI-word-or-truncated-drop (§5.4); no reassembly (both
  concur); SA-miss calls fail_admission plus recycle mirroring :603-605
  (PlanB P1-5 exact path adopted).
- OQ5 NAT-T: keepalive drop with traversal argument (§5.2; both concur on
  drop, PlanA F6 demanded the argument — supplied). SPI offset via bounded
  .get; short-UDP to truncated-drop; jumbo to gate-pass then TUN-MTU
  MtuExceeded fail-closed (slowpath.rs:1171-1180 region per v1 read —
  re-pin at implement); GRO non-coalescing stated explicitly (§5.4).
- OQ6 family: v6 AH out of scope permanently (shim walk plus shunt,
  ipsec.rs:15-30; both concur). v6 ESP-in-UDP keyed by IpAddr like
  IkeExchangeKey (ipsec.rs:232-247) with ext-hdr unit cells (§6.4).
- OQ7 staleness: monitor-immediate plus 30s drift; NO negative cache;
  FIRST missed sync or poller error to deny-all plus counter (PlanB;
  fold brief) — PlanA's 3-miss ceiling SUPERSEDED (availability cliff
  that is also a bypass window); startup blocked on first dump (§5.5).
- OQ8 perf: Arc FxHashMap cap 4096 plus control-only oldest-eviction plus
  counter (PlanB; §5.5, §5.9) with numeric bars (iperf3 <1%, proven-path
  <2%, 1Mpps flood linear). PlanA's "<1% bar" concurred and extended.
- OQ9 HA: document-not-sync (both concur; same gap as IKE table plus
  conntrack plus XFRM); new node empty-to-drops until re-establish; BACKUP
  and MASTER both have no Stage-11 q0 mint (§2.3, §5.6). No new XFRM-sync
  dependency for v1.
- OQ10 compat: straight to B (both concur), strengthened to never-mint-
  Adjudicated; there is no C hatch. Keepalive/frag/rekey gaps are
  release-noted with counters plus strongSwan proofs (§5.10, §7 P6).
- OQ11 ownership: VIP membership DISPROVEN (§2.3) — VRRP half dropped (both
  reviewers required prove-or-drop; proof came back negative). BACKUP
  proven-mint is impossible structurally (NotClaimed); any future VIP-in-sets
  change must preserve the unmarked-only invariant and active-RG review
  (§5.6). DNAT-to-xfrmi if_id attribution deferred (both concur).
- OQ12 IKE interplay: NO change to IkeExchangeTable (both concur; cap
  4096/24h/Mutex stays IKE-pps-only at ipsec.rs:206-299). ESP-in-UDP
  data rates never touch that lock (§5.5 snapshot is lock-free for
  readers). Shared-test-file coordination only.

## 10. Acceptance
- SA-gated, never-mint-Adjudicated fix landed per §5: every proven UDP
  ESP-in-UDP hit is Delegated/q1 with no mark; every miss/stale/error/
  unparseable/keepalive drops with counters; no Stage-11 path submits q0;
  no T-window; no last-good latch; no "XFRM closes FORWARD" claim.
- Admitted IKE UDP-500 and UDP-4500 zero-marker traffic selects Delegated/q1
  without an SA-cache lookup and reaches local INPUT; an unseeded
  established-IKE spoof is Denied before the arm and cannot mint any queue or
  mark.
- Valid-SA GRE-inner-local-via-Delegated preserves queue-1 delivery through
  the primary xpf-usp1 TUN into kernel INPUT/XFRM, with q0 delta zero.
  Owned-but-not-local SA hits are also Delegated or drops on miss, never
  Adjudicated; current VIPs remain NotClaimed.
- Pinning test re-pointed per §6.2 (behavioral rows; bug comment deleted;
  no source-text gate-precedence cell; no-Adjudicated-from-Stage-11 pin).
- §6 cells green as FULL modules/files; RED-on-revert demonstrated
  firsthand by the implement lane. With only the outlet literal reverted
  (gate retained), hit cells 2/3/14a/14b RED while Stage-11 miss/drop cells
  1/4/5/6/8/10/11/12/13/16-frag/16-unfrag stay GREEN; independent cells
  7/9/15 stay GREEN. With the gate removed, unproven Stage-11 cells
  1/4/5/6/8/10/11/12/13/16-frag/16-unfrag RED while hit cells 2/3/14a/14b stay GREEN;
  cells 7/9/15 remain NotClaimed/Denied.

- Numeric perf bars met (§5.9) with measured numbers in the PR.
- §7 P0-P6 armed-box run complete: P0 reproduces pre-fix (nonzero q0);
  P1/P2/P3/P4/P5 zero q0 post-fix, with P2 INPUT/XFRM delivery; P6 compat
  proven; severity settled and recorded.
- strongSwan compat proofs (a)-(d) in §5.10 delivered.
- No #6837-reversal code anywhere (cell 7 tripwire guards).
- No outlet-only residual: unproven ESP-in-UDP traffic never queues; admitted
  IKE is the explicit admission-proven non-SA exception and queues only
  unmarked Delegated/q1; no Stage-11 path can mint q0 from mere SA
  existence.

## Appendix A. File:line index (source tip 5dbdc95dc; v4 plan fold)


- Issue: gh issue view 10516 --json title,body,state,comments,url (OPEN,
  3266-char body: What/Evidence/Narrowed/Acceptance/Review-origin; 1 comment:
  #10525/#10518 cross-link). #10525 OPEN (DNAT-to-self IKE gate), #10518 OPEN
  (GRE TunOrigin), #6837 CLOSED (portless-tuple — must not reverse).
- userspace-dp/src/afxdp/frame/inspect.rs:1075-1125
  (metadata_tuple_complete, #6837 refusal :1091-1125, aliasing :1106-1109,
  flowless path :1111-1115, discriminator note :1117-1124), :1312-1367
  (parse_flow_ports TCP/UDP/ICMP-only, :1366 None arm), :1574-1585
  (non-first to None chokepoint, :1583-1584).
- userspace-dp/src/afxdp/frame/tests_shim_ext_parity.rs:2727-2730 (ESP
  flowless pin).
- userspace-dp/src/afxdp/frame/README.md:127-163 (port-less NAT :127-136,
  non-first flowless :137-153, GRE inherits :154, screen :157-163).
- userspace-xdp/src/lib.rs:794-806 (local-dest shunt), :807-825
  (interface-NAT arm, ESP/GRE to kernel :820-822), :831-850 (native-GRE
  redirect versus pass-to-kernel), :1055-1155 (inner classifier redirects
  USERSPACE_LOCAL_V4/INTERFACE_NAT destinations), :1590-1618 (v4 frag
  sentinel :1590-1591, 8B minimum :1597-1599, fallback :1608-1615),
  :1686-1735 (v6 sentinel :1724-1725, fail-closed discipline :1705-1723).
- userspace-dp/src/afxdp/poll_stages.rs:331-342 (GRE decap helper),
  :398-424 (parse flow and learn, GRE-only fallback :418-424), :1148-1160
  (ipsec decision), :1162-1177 (outcome enum), :1179-1234 (IKE deny zone,
  #6458 mastership :1200-1213), :1294-1398 (Stage-11 check: flow gate
  :1304-1306, predicate :1307-1310, #5620 :1311-1333 with caveat :1324-1330,
  classify/#6471 :1334-1395, Passthrough :1397), :1405-1425 (reinject,
  outlet :1420).
- userspace-dp/src/afxdp/poll_descriptor/mod.rs:88 (import), :308-314 (GRE
  decap site — CORRECTED from v1's :495-502), :481-549 (frag pre-hook,
  ESP/AH-outer note :491-492), :550-568 (Stage-11 call), :570-609
  (Passthrough arm: record :575-596, reinject :598, commit/fail :599-606),
  :610-630 (Denied arm), :7254-7268 (chokepoint, Adjudicated at :7261).
- userspace-dp/src/afxdp/forwarding/ipsec.rs:15-30 (v6 AH note), :32-36
  (predicate), :63-112 (demux, truncated :96-98, 4500 marker :99-107),
  :114-150 (classify, NotIsakmp :138, Truncated :139), :159-199 (IKE SPI
  extractors), :201-299 (exchange table: cap :206, idle :218, key :232-247,
  sharing :273-283, HA :285-291), :613-676 (truncation/classify tests).
- userspace-dp/src/afxdp/forwarding/fabric.rs:364-415 (owner_rg_for_local_
  address :371-384, gate on local owner RG :397-415).
- userspace-dp/src/afxdp/types/forwarding.rs:869-891 (owns_configured_ip
  :886-891, NAT-decoupled docs :874-884).
- userspace-dp/src/afxdp/types/mod.rs:43 (FastMap==FxHashMap), :133-190
  (UserspaceDpMeta: l4_offset :142, protocol :178, flow ports/addrs
  :184-187), :204-230 (ForwardPacketMeta).
- userspace-dp/src/afxdp/forwarding_build/interfaces.rs:605-640
  (interface-addr population :609/:613/:636/:640).
- userspace-dp/src/afxdp/forwarding_build/mod.rs:880-922 (NAT-external
  append :880-882, inserts :906/:914).
- userspace-dp/src/afxdp/forwarding/README.md:1075-1113 (two paths
  :1075-1093 with STALE AH half at :1087, #5620 :1095-1113).
- userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:150-172 (outlet enum
  plus docs), :313-435 (with_outlet reinject, mapping :431-434),
  :441-453 (alloc-free rate_limited precedent).
- userspace-dp/src/slowpath.rs:40-46 (queue/mark consts), :188-243 (TC
  loader), :1130-1158 (enqueue fns), :1324-1440 (9506 submit, queue+lease
  :1392-1394), :1506-1555 (primary versus adjudicated TUN setup),
  :1569-1631 (worker routing :1583-1589, pre_write_check :1598-1613).
- userspace-dp/src/afxdp/disposition.rs:227-228 (per-worker ring),
  :454-485 (record_exception plus admit sampler), :521-548 (suffixed
  alloc-free).
- userspace-dp/src/afxdp/binding_state/latency.rs:54-61 (thread-local
  1-in-N sample, `REDIRECT_SAMPLE_SEQ`);
  userspace-dp/src/afxdp/binding_state/tx_inbox.rs:157-164 (sampled cost).

- userspace-dp/src/afxdp/neighbor.rs:460-470 (raw AF_NETLINK send),
  :975-1002 (monitor thread socket plus group bind), :1101-1105
  (socketpair test seam).
- userspace-dp/src/afxdp/coordinator/neighbor_manager.rs:51-61, :168-176
  (stop plus JOIN); userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:
  1107-1136 (supervised spawn); coordinator/status.rs:837-842 (ENOBUFS
  telemetry); coordinator/mod.rs:262, :549 (local_tunnel_deliveries ArcSwap),
  :568 (control exception ring).

- userspace-dp/src/fragment_overlap/mod.rs:482 (check_overlap), :607
  (check_and_record), :734 (commit_admission), :761 (fail_admission).
- userspace-dp/Cargo.toml:11 (arc-swap), :17 (libc), :20 (rustc-hash).
- pkg/nftables/transit_barrier.go:20 (counter), :30-35 (mark/mask), :37-44
  (spec). pkg/daemon/daemon_transit_gate.go:105 (xpf-usp1), :107-124
  (residual docs), :133-184 (spec, pinhole :164-168).
- pkg/dataplane/userspace/maps_sync.go:1094-1125 (VIP AddrList union),
  :1378-1415 (interface-addr entries, no NAT externals).
- pkg/routing/xfrm.go:13-67 (xfrmi lifecycle only), :80-83 (if_id binding);
  /usr/include/linux/xfrm.h:144-147 (SA direction), :388-409
  (xfrm_usersa_info has flags, no lifecycle state), :469-472 (expire event).
- go.mod:14 (vishvananda/netlink — available, rejected for this path).
- userspace-dp/src/afxdp/tests_slow_path_disposition.rs:1291-1306
  (pinning test), :1320-1323 (REAL-primitive pattern).
- userspace-dp/src/afxdp/forwarding/tests.rs:3222-3292 (predicate cells).
- 3329415f7 (mark infrastructure plus Adjudicated move, Refs #10391).

## Appendix B. Verification commands run (v1 STEP-0 plus v2/v3/v4 folds)


- pwd plus HEAD plus branch (worktree 10516-passthrough; base 5dcaa10;
  tip 5dbdc95 v1 plan commit; branch fix/10516-passthrough-adjudicated).
- gh issue view 10516 --json title,body,state,comments,url (OPEN; 3266-char
  body; 1 comment) plus --jq title/state/url and body/comments lengths.
- gh pr list --state merged --search "10516" (empty), "passthrough
  adjudicated" (#10410/#8236/#6691 only — none this fix), "SlowPathOutlet
  xpf-usp1" (empty); git log --grep "10516|10391|5620|6471|6837" (v1 plan
  plus infra plus CLOSED #6837); gh issue views #10525/#10518 (OPEN) and
  #6837 (CLOSED).
- git show 3329415f7 --stat plus poll_stages.rs hunk (false to Adjudicated).
- git grep counts (§2.4); XFRM/SADB zero-hit proof; ESP/AH SPI extractor
  absence proof (IKE-only extractors).
- Reads: every App. A range above (flowless chain, shim shunt plus frag
  arms, native-GRE inner redirect and decap, Stage-11 plus arm plus chokepoint,
  classifier plus table, outlet/queue/TC/fence, primary versus adjudicated
  TUN routing and local INPUT/XFRM path, ownership plus NAT append plus VIP
  sync, mastership pattern, monitor plus ArcSwap plus sampler precedents, UAPI
  direction and lifetime/expire fields, frag admission fns, meta plus Cargo
  deps, pinning plus predicate tests).

## Appendix C. Blast-radius recap (complete)

- Stage-11 IPsec mint baseline: 1 def (poll_stages.rs:1405) plus 1 call
  site (mod.rs:598) plus 1 import (:88); outlet literal at :1420 is deleted
  by the fix, replaced by the §5.1 computed Delegated outlet; reinject
  signature gains one param.
- SlowPathOutlet::Adjudicated baseline: 4 files times 1 (Stage-11 mint,
  chokepoint :7261, mapping userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:
  433, pin :1300). The fix removes the Stage-11 mint and pin; the enum/mapping
  remain for the other q0 writers.
- q0 writers (fence level, baseline complete): (1) IPsec lease-None outlet
  path (this issue, removed by this fix); (2) missing-neighbor policy-proof
  outlet path; (3) #9506 lease plus admission submit path with pre-write
  linearization. Plus worker fd routing (:1586-1589), TC classifier, fence
  conjunction. Post-fix Stage-11 contributes zero q0 writes.
- Mark/classifier/enqueue counts per §2.4. SA lookup: zero in-tree (the
  §5.5 subsystem is new; nearest precedents: neighbor monitor thread plus
  ArcSwap publishers plus FxHashMap maps, all cited).
- Flowless populations (never mint, never gated): raw ESP/AH all frag
  states, outer non-first frags any proto, GRE-inner ESP/AH. Live gated
  population: UDP-500/4500 with flow Some (IKE out of gate scope; ESP-in-UDP
  plus keepalive gated).
- Shim steering: local-dest (incl. VIPs) to kernel; native-GRE inner local
  destinations in USERSPACE_LOCAL_V4/INTERFACE_NAT are redirected to XSK for
  decap; interface-NAT ESP/GRE to kernel, UDP to XSK; DNAT externals (not in
  shim maps) to XSK; session-miss UDP to XSK.

## Appendix D. Round-1 finding-to-fix map (v2 audit trail retained)

PlanA: F1 (existence-gate FORWARD bypass; XFRM-closure false) to §5.6
never-mint-Adjudicated closure plus §5.5 deletion of the closure claim;
F2 (BACKUP-VIP mint) to §2.3 drop-with-proof plus §5.6 unmarked-only
invariant; F3 (unreachable frag rule) to §2.2 plus §5.4 rewrite around
proto-255/NotClaimed with inner-frag analysis; F4 (inbound filter) to §5.5
exact UAPI-visible filter, XFRMA_SA_DIR_IN, lifetime/expire handling, and
event-driven removal; F5 (test misplacement/wiring/U-5) to §6.1 arm siting
plus §6.2 behavioral wiring plus §7 P3/P4 probes plus reinject-signature
constraint in §5.1; F6 (rekey/counter/ceiling/keepalive) to §5.10 overlap
proof plus §5.8 counter-plus-sampled design plus §5.5 deny-on-stale plus
§5.2 traversal argument; M1 (cross-refs) fixed throughout (all §/App refs
re-checked); M2 (GRE :308-314) corrected; M3 (pre-hook :481-549) cited; M4
(:7261) re-pinned; M5 (line counts, log-empty-at-tip) noted.

PlanB: P0-1 (raw/flowless premise) to §2.2 rescope plus §5.2/§5.4/§6/§7
UDP-only rewrite plus §2.2 last two bullets (#6837 non-reversal); P0-2
 (T-window fail-open)
to §5.5 monitor-immediate plus deny-on-stale with all windows/latches
deleted; P1-3 (unresolved lookup) to §5.5 exact API/filter/owner/ready-gate;

P1-4 (wildcard key) to §5.3 src-hardened key plus collision analysis;
P1-5 (frag/admission) to §5.1 exact fail path plus §5.4 raw/UDP split;
P1-6 (miss-path lock) to §5.8 counter-plus-thread-local-sampled design;
P1-7 (synthetic tests) to §6 real-wire cells plus §6.2 wiring pins;
P2-8 (blast omissions) to §2.4 plus App. C; P2-9 (HA/VIP) to §5.10 plus
§2.3 drop-with-proof and §5.6 no-q0 closure; P2-10 (perf/snapshot open) to
§5.5 structure plus §5.9 numbers; P2-11 (invariants/compat) to §5.7 plus
§5.11 no-hatch rule plus §8 notes.
