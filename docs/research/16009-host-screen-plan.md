# #16009 — shim kernel-PASS bypasses worker malformed screens: host-screen plan (design, not yet implemented)

- **Status:** DESIGN CANDIDATE for three-seat plan review (GPT-6.1 Sol /
  GLM-5.3 / Kimi K3.1 Pro). No production code in this commit. Engineering
  starts only after plan review passes. Self-assessment at §11.
- **Base:** `origin/master` at `6c27f54cf2` (branch
  `research/16009-host-screen` is parked exactly on it). Every anchor below
  was re-read at that SHA; the issue body cites `c1b86e871b`, whose lines
  have moved.
- **Input, not truth:** the uncommitted prior-lane candidate
  `docs/log/16009.md` (base `fed39c4bc1`) was treated as input and
  re-verified claim by claim. Where it drifts from `6c27f54cf2` this doc
  corrects it (notably: `land_gate` is at `lib.rs:2605-2636`, not
  `:2611-2642`; the ctrl-disabled call is at `:1721`, not `:1727`; the
  shimverify override env is `XPF_SHIM_ALLOW_LOW_HEADROOM`, see
  `cmd/shimverify/main.go:232ff`, not `XPF_SHIMVERIFY_OVERRIDE`).

---

## 1. Verified mechanism (what is actually broken)

`xdp_userspace_prog` (`userspace-xdp/src/lib.rs:612-618`) → `try_xdp_userspace`
returns `XDP_PASS` / `cpumap_or_pass` (`:2138-2146`) on terminal kernel-pass
arms. Those packets never reach the AF_XDP worker, so worker screen stage 10
never runs on them:

- worker entry (flow path): `check_packet_with_zone_id_opts`,
  `userspace-dp/src/screen/mod.rs:912`; stateless order: `check_land`
  `:961` → `check_tcp_flag_screens` `:964` → `check_fragment_and_route`
  `:972`.
- flowless twin: `check_flowless_screens_opts`, `mod.rs:1232` (stateless
  tail at `:1274`; it deliberately runs no TCP-flag screens — see §4.4).

Only LAND is replicated at the shim: the outlined `land_gate`
(`lib.rs:2605-2636`), healthy call site `:791-794`, ctrl-disabled call site
`:1721-1723`, host-compiled predicate `userspace-xdp/src/land.rs`
(`is_land` `:46-48`, `land_disposition` `:71-80`: unresolved zone → Drop).

Terminal host-bound (destination-qualified) kernel-pass arms, all verified
at `6c27f54cf2`:

| Arm | Anchor / insertion point for `host_screen_gate` |
|---|---|
| WG steer | `lib.rs:944-951`; after predicate succeeds, before branch counter / return `:950` |
| early-filter multicast / link-local | `lib.rs:952-965`; after predicate succeeds, before trace and `pass_local_control` `:964` |
| session-hit `PASS_TO_KERNEL` | `lib.rs:1002-1028`; after hop-limit veto, before local trace/counters and return `:1028` |
| session-miss NAT-external NDP | `lib.rs:1035-1044`; inside matching arm, before branch counter / return `:1043` |
| session-miss proxy-NDP | `lib.rs:1050-1059`; inside matching arm, before branch counter / return `:1058` |
| session-miss ICMP-to-interface-NAT local | `lib.rs:1060-1073`; after predicate, before trace/counter / return `:1072` |
| session-miss local destination | `lib.rs:1101-1121`; after hop-limit veto, before trace/counter / return `:1120` |
| interface-NAT tunnel kernel pass | `lib.rs:1125-1139`; inside `interface_nat_tunnel_passes_to_kernel`, before branch counter / return `:1138` |
| GRE-inner `PASS_TO_KERNEL` | `lib.rs:1155-1175`; after typed predicate succeeds, before trace/counters / return `:1174` |
| binding-not-ready degraded local/control | `binding_ready_slot` call `:854`; after `is_degraded_local_or_control` returns true, before `pass_local_control` `:891-894` |
| ctrl-disabled local/control | `degraded_ctrl_disabled_action` `lib.rs:1671`; after `PassLocalControl` disposition, before branch counter / `pass_local_control` `:1726-1728` |

The `land_gate` call sites (`lib.rs:791-794`, ctrl-disabled `:1721-1723`)
remain exactly where they are. Do NOT put `host_screen_gate` beside
them: those points precede the dispatch decision and include transit
packets that later redirect to the worker (§5.5 / K4).

Transit session-miss / redirect (`:1141-1148`, XSK redirect at `:1269`)
DOES reach the worker and is already screened there. The plan must not
screen transit at the shim (double-screening + wrong-zone risk, §9 K4).


Not the fix: SYN/UDP/ICMP flood RATE meters are already replicated for
host-bound traffic in nft — `pkg/nftables/host_inbound_screens.go`
(per-zone/per-family meters, `:22-35`, `HostInboundScreenFloodRules`
`:54-180`). Explicitly out of scope; do not duplicate.

**Verified absence on master:** no `host_screen` / `HOST_SCREEN` symbol
anywhere under `userspace-xdp/` or `pkg/dataplane/` (grep: zero hits).
`USERSPACE_FALLBACK_REASON_MAX = 21` (`lib.rs:65`); reasons 0..20 at
`:36-64` (19 `land_drop`, 20 `land_alarm`; 6 and 12 reserved-never-emitted,
#17248). Degraded stats map: `USERSPACE_FALLBACK_STATS`
PerCpuArray sized by that MAX (`lib.rs:578-579`); Go mirror
`degradedPathReasonNames [21]string` (`pkg/dataplane/userspace/maps_sync.go:1010-1034`).

## 2. The decision: narrow scope (option 1)

**Chosen: option (1) — narrow #16009 to the worker's stateless
per-packet geometry/source-route/TCP predicates plus an aggregate shim
counter, with successor issues filed for the stateful / fidelity
residue.** “Worker equivalent” here means these predicates and the
resolved **raw ingress** screen-zone policy, with explicit fail-closed
boundaries in §§4.3, 5.5: ordinary geometry on an unresolved zone follows
LAND's shim policy; tiny flags-unknown parsing is gated on screen-state
presence, not the syn-frag profile bit. The worker's optional
claimed-zone union is an open parity question in §4.3 / Q-D.

Concretely, #16009 (this plan) covers exactly the per-packet,
no-cross-packet-state verdict class:

1. ping-of-death geometry (`check_ping_of_death`),
2. teardrop GEOMETRY (`check_teardrop` — zero/under-length payload, and
   non-last-fragment payload not a multiple of 8),
3. icmp-fragment (wire protocol),
4. syn-frag (SYN on first fragment) plus the #16007 tiny-first-fragment
   flags-unknown parse error, gated on the presence of screen state as
   specified in §4.3 (not on the syn-frag bit),
5. source-route (v4 LSRR/SSRR sighting; v6 Routing type 0/1 sighting),
6. the TCP-flag family (syn-fin / no-flag / fin-no-ack / winnuke) behind
   its own mask bits — Q1 decided IN, §4.4,

…decided at the shim from a scratch-laundered packed verdict (§5), gated
per ingress screen state by a published mask byte (§6), counted by ONE
aggregate `host_screen_drop` / `host_screen_alarm` pair appended to the
degraded-path ABI (§6.3). Flood meters stay in nft untouched. Everything
else in the issue's literal text (true fragment overlap, port-scan /
ip-sweep, SYN-cookie challenge semantics, per-reason counter fidelity)
moves to successor issues (§10) — it is worker- or kernel-stateful and
cannot be made stateless at XDP without a different architecture.

**⚠ C1 honesty, stated once and binding for all parity claims below:**
the candidate's cell C1 (v4 MF=1, 4-byte payload) exercises ONLY the
teardrop *geometry* arm (`data_len % 8 != 0` on a non-last fragment,
`stateless.rs:239-241`). It MUST NOT be treated as proving overlap
handling. True teardrop is cross-fragment offset/length overlap, which
neither the worker's stateless check nor this plan detects: the worker's
own doc says so (`stateless.rs:178-183`: "This does NOT make the check an
overlap detector… the only fragment-state module in the tree
(`fragment_assoc`) states in its own doc that it ASSOCIATES rather than
RFC-reassembles"). Any test, comment, or doc produced under this plan that
calls C1 an "overlap" cell is a defect. C1 is relabelled accordingly in §8.

### 2.1 Rejected alternative (2): literal scope / cross-fragment state / redirect-to-worker

- **Cross-fragment state at XDP** (overlap detection, scan/sweep trackers,
  cookie minting) requires per-flow/per-source state machines and timers
  in BPF maps. That is a different architecture, not a screen replication;
  it also destroys the verifier budget argument (§7) before it starts —
  the stateless widening alone already rejected at 1,000,001 insns (§3).
  The worker itself does not do RFC reassembly/overlap (`fragment_assoc`
  associates only), so "literal parity" would exceed the worker, not match
  it.
- **Redirect-to-worker for host-bound traffic** (force every kernel-pass
  candidate through AF_XDP and let the worker pass it back) re-opens the
  exact terminal-arm semantics LAND was replicated to preserve: local
  delivery latency/availability now depends on worker health on the
  degraded and ctrl-disabled paths (`pass_local_control` exists precisely
  so local/control traffic survives a dead worker, `lib.rs:1812-1816`),
  and it reintroduces the #304/#10640 class of transit-vs-local
  destination-qualification bugs at a new boundary. It is the fallback if
  K1 kills the stateless shape (§9), not the plan.
- **Literal per-reason counters at the shim** would need first-reason
  precedence replication (worker order LAND → TCP-flag → POD → teardrop →
  icmp-frag → source-route with per-reason `GlobalCtrScreen*` /
  `ScreenReasonCounters[19]`, `pkg/dataplane/types.go:1619ff`) plus seven
  new ABI indices. The aggregate localises the drop to zone+shim; the
  split is an observability refinement, filed as a successor (§10 S4),
  not a correctness requirement.

### 2.2 Rejected alternative (3): split #16009 itself, or plan-kill the candidate

- **Plan-kill is not warranted at the design stage.** The bypass is real
  and verified (§1), the shim already has the basic per-packet predicate /
  zone-map / aggregate-counter mechanism for LAND, and the baseline object
  (before this change) has 22.08% measured headroom. The proposed delta is
  still unmeasured: K1 makes verifier evidence a hard landing gate.
  PLAN-KILL requires all three seats converging on reject; the honest
  self-assessment (§11) is that this bounded plan is reviewable and
  killable on measurement, not on principle.
- **Splitting #16009 into per-check issues** would fragment one mechanism
  (one gate, one map, one ABI append) into five landings that each re-pay
  the verifier measurement and the map-wiring cost, and would let partial
  parity ship silently (e.g. POD without icmp-fragment). The split that
  IS correct — stateless geometry here, stateful/fidelity residue in
  successors — is what option (1) already does.

## 3. The disproved shape: WIP `738b7b942e` (do not revive as-is)

Commit `738b7b942e` ("userspace-xdp: add host malformed screens to
kernel-PASS path (WIP, verifier-blocked) (#16009)", on `fix/16009-campaign`,
not on master) implemented this issue by WIDENING the parser return
structs:

- `ExtWalk` +4 fields (`frag_off`, `is_first_fragment`, `frag_data_off`,
  `routing_source_route`) in `userspace-xdp/src/ipv6_ext_walk.rs`;
- `ParsedPacket` +7 fields (`is_first_fragment`, `ip_frag_off`,
  `frag_data_off`, `saw_source_route`, …) in `userspace-xdp/src/lib.rs`.

Genuine `make generate-userspace-xdp` REJECT at **1,000,001 processed insns
vs the 1,000,000 cap** (baseline 779,213 — still the recorded master
figure: `pkg/dataplane/userspace_xdp_gate_verdict.json` at `6c27f54cf2`,
`processed_insns: 779213`, headroom 22.08%, floor 15%). The issue comment
(2026-10-28, Eng16009Opus) records the bisect: the dominant cost is the
parse/walk widening multiplying verifier states across downstream arms,
NOT the verdict arithmetic; neutralising the gate call sites still
rejects. This matches the tree's own warnings: `ParsedPacket` carries the
#8274 note that widening by a `u16` relocated a read and rejected the
object (`lib.rs:2150-2156`), and the #8249 scratch precedent states the
mechanism verbatim (`lib.rs:591-598`).

**Salvage from `738b7b942e` — extract, do not cherry-pick the parse
widening:**

| Salvage (reuse as-is or near-verbatim) | Why it is sound |
|---|---|
| `userspace-xdp/src/host_screen.rs` — pure verdict (`host_malformed_verdict`, `host_malformed_disposition`, mask constants `HOST_SCREEN_*` bits 0-7) | Host-compilable, never the reject cause; its inputs change (§5.3) but its arithmetic mirrors `stateless.rs` line-for-line |
| `userspace-xdp/src/ipv4_len_gate.rs::ipv4_has_source_route_option` (new in WIP, +43 lines) | Pure TLV scan of an already-held header slice; reused by §5.2 |
| Go: `pkg/dataplane/userspace/host_screen.go` (`buildUserspaceHostScreenEntries`, `hostScreenMaskFor`, `syncUserspaceHostScreenMapLocked`, `checkHostScreenCapacity` 65536) | Mirrors the landed LAND builder (`land_screen.go:69-176`); resolution rules (explicit row / conservative / inert+alarm / collision-poison) already correct |
| Loader/pin wiring: `pkg/dataplane/userspace/maps.go` (`mapNameUserspaceHostScreen`), `pkg/dataplane/loader_userspace_shim.go` (`userspaceHostScreenMapName`, pin lists), `pkg/dataplane/retirement_boundary_canary_test.go` allowlist row, `userspace-dp/src/afxdp/bpf_map/pin.rs` | Follows the `userspace_land_screen` precedent exactly; wiring was not implicated in the reject |
| Tests: `host_screen_16009_test.go` (Go builder), `host_screen_drop_16009_test.go` (BPF cells, harness `loadUserspaceXDPTestCollection` / `runUserspaceXDPTestPacket`), `userspace-dp/src/afxdp/frame/tests_shim_host_screen_16009.rs` (host twin vs `worker_malformed_mask_for_test`, the test-only oracle the WIP added to `stateless.rs` +54 lines) | Harnesses all exist on master (§8); cells re-labelled per §8, corpus fed from the packed word instead of the widened struct |
| Counter constants choice (append 21/22) | Matches §6.3; WIP already chose append-only |

| Do NOT salvage | Why |
|---|---|
| `ParsedPacket` +7 / `ExtWalk` +4 widening and every construction site | The measured reject cause (§3 above) |
| WIP's unconditional `tcp_flags_unknown → SYN_FRAG` in `host_malformed_verdict` | Fires before the zone byte is consulted; drops legal tiny first fragments for unresolved zones — corrected by §4.3 |
| WIP's gate placement as proof of budget | Its two calls after LAND precede the redirect decision and can drop transit; replace them with the 11 selected terminal arms (§5.5). The WIP object never verified, so its placement cost was not measurable |

## 4. Worker predicates being replicated (source of truth)

Worker decode: `FragView{offset_bytes, more, data_len, pod_extent}`
(`userspace-dp/src/screen/packet.rs:32-37`), decoded once in
`extract.rs` via `frag_view_v4` (`packet.rs:60-73`: offset
`(raw & 0x1FFF) << 3`, `data_len = total_len − ihl*4` saturating,
`pod_extent = total_len`) and `frag_view_v6` (`packet.rs:80-88`: offset
`raw & 0xFFF8`, `data_len = payload_len − frag_data_off` saturating,
`pod_extent = data_len`). Profile fields `packet.rs:150-193`; config
mapping `pkg/dataplane/userspace/screens.go:60-71` (PingDeath ←
`sp.ICMP.PingDeath`, Teardrop ← `sp.IP.TearDrop`, ICMPFragment ←
`sp.ICMP.Fragment`, SynFrag ← `sp.TCP.SynFrag`, SourceRoute ←
`sp.IP.SourceRouteOption`); emit gate `enforcesAnyCheck`
`screens.go:171-179` already counts all five, so no emit-gate change.

| Check | Worker predicate (verified) | Notes for the shim |
|---|---|---|
| ping-of-death | `stateless.rs:131-143`: `profile.ping_death && frag.offset_bytes + frag.pod_extent > 65535` (`>` not `>=`) | any protocol, fragments only (`frag: Option`, `None` ⇒ skip) |
| teardrop (geometry) | `stateless.rs:222-243`: `teardrop && (frag.data_len == 0 ‖ (frag.more && frag.data_len % 8 != 0))` | NOT overlap detection (§2, §10 S1). Legal 1-7 B LAST fragment (MF=0) passes (#9426) |
| icmp-fragment | `stateless.rs:247-258`: `icmp_fragment && is_fragment && protocol ∈ {1, 58}` | keys on the WIRE protocol; a non-first fragment's parsed `protocol` is the 255 sentinel (`ipv6_ext_walk.rs:179`, shim substitution at `lib.rs:2435-2462`), so the shim tests `wire_protocol` (`ParsedPacket.wire_protocol`, `lib.rs:2184`) — the worker recovers it the same way (`extract.rs:393-397`, #9114) |
| syn-frag | `stateless.rs:78-82` inside `check_tcp_flag_screens:42-85`: `syn_frag && (tcp_flags & SYN) && is_first_fragment`; plus #16007 arm `:57-59`: `tcp_flags_unknown && is_first_fragment → "syn-frag"` regardless of profile SYN bit | Normal known-flags SYN-frag obeys the syn-frag bit. Tiny flags-unknown is an earlier `extract_screen_info` error (`extract.rs:423-442`, mapped to `"syn-frag"` at `packet.rs:309-334`), and the production stage drops that error whenever the worker has screen state, regardless of the profile bit or alarm setting (`poll_stages.rs:1112-1126,1347-1376`; flowless twin `:1195-1231`). Mirror row-presence semantics in §4.3. |
| source-route | `stateless.rs:275-283`: `source_route && (saw_ipv4_source_route ‖ saw_ipv6_routing_header)` | v4: actual LSRR(131)/SSRR(137) TLV, NOT ihl>5 (`extract.rs:242-300`, incl. malformed-option fail-closed ordering #4543/#15947); v6: Routing header (next-header 43) with routing-type ∈ {0,1} (`userspace-dp/src/afxdp/frame/inspect.rs:358-377` `rh[2]`, folded at `extract.rs:367`) |
| TCP-flag family (Q1) | `stateless.rs:62-76`: syn-fin `:62-64`, no-flag `:66-68`, fin-no-ack `:70-72`, winnuke `:74-76` (URG && dst_port == 139), all under the outer guard `:46-51` (`protocol == TCP && (!is_fragment ‖ is_first_fragment)`) | see §4.4 |

Worker counters (NOT replicated; residue §10 S4): `GlobalCtrScreenPingOfDeath = 18`
(`pkg/dataplane/types.go:1065`), `GlobalCtrScreenSynFrag = 25` (`:1072`),
`GlobalCtrScreenICMPFragment = 43` (`:1091`), `ScreenIPSourceRoute = 1<<12`
(`:1551`), `ScreenReasonCounters[19]` (`:1616-1635`).

### 4.1 Atomic fragments

An IPv6 atomic Fragment header (offset 0, M=0) is NOT a fragment
(`frag_view_v6` governing rule; `packet.rs:28-30`, shim `fragment_seen`
clearing at `ipv6_ext_walk.rs:341-343`). It must trip no fragment check.
Pinned by a corpus row in §8(a) and by C16 (§8).

### 4.2 Double-fragment chains

The worker's governing-header rule (FIRST readable non-atomic sighting
governs; a later atomic must not erase it — `extract.rs:368-398`,
#14129/#10661; a second readable non-atomic is `Err` there,
`extract.rs:364-366`) is preserved at the shim by WRITE-ONCE scratch
semantics (§5.2): the walk writes fragment fields only at the first
non-atomic sighting (local `fragment_seen_before`, `ipv6_ext_walk.rs:323`).

### 4.3 Tiny-fragment fail-closed: mirror worker screen-state gate (not the profile bit)

The candidate's tiny-fragment correction must be tied to actual worker
control flow, not inferred from the later profile predicate. In
`stage_screen_check_with_ambiguous`, the worker computes
`raw_profile_zone = roles.raw_zone.filter(|(_, name)| screen.zone_has_screen_state(name))`
and returns Pass before extraction only if BOTH `raw_profile_zone` and
`claimed_zone` are absent (`userspace-dp/src/afxdp/poll_stages.rs:1112-1126`).
Once either exists, `extract_screen_info` runs. A tiny first TCP fragment
whose declared datagram ends before the flags byte returns
`TinyFirstFragmentFlagsUnknown` (`screen/extract.rs:423-442`), maps to
`"syn-frag"` (`screen/packet.rs:309-334`), and the production error arm
records a drop and returns before consulting `ScreenProfile.syn_frag` or
`alarm_without_drop` (`poll_stages.rs:1347-1376`; flowless twin
`:1195-1231`). Thus the worker behavior is:

- **Worker screen state present** (a resolved profile zone, missing
  profile reference, or inert profile reference — exact worker predicate
  `ScreenState::zone_has_screen_state`, `screen/mod.rs:811-823`): drop
  this tiny-first-fragment shape, independent of the syn-frag bit and
  audit modifier. The shim MUST mirror this as a special fail-closed
  parser verdict, not as an ordinary syn-frag mask bit (which would
  wrongly pass when syn-frag is off or alarm is on).
- **No worker screen state**: worker returns Pass before extraction;
  shim does not drop this tiny shape solely for unknown flags. A
  non-zero resolved ingress zone is NOT sufficient to imply screen
  state.

At the shim, the `userspace_host_screen` row's PRESENCE is the state
signal: `buildUserspaceHostScreenEntries` publishes rows for emitted
screen snapshots and missing/inert refs, including a zero malformed-mask
row when screen state exists only for e.g. a flood check; no row means
no screen state. The parser scratch carries `tcp_flags_unknown`; on this
branch the gate resolves the ingress `zone_id`, then:

1. unresolved `zone_id == 0` → do not synthesize the tiny error (there is
   no published screen state);
2. resolved zone + host-screen row exists → DROP as
   `host_screen_drop`, even if the row's syn-frag bit is clear or its
   alarm bit is set (worker extractor error is fail-closed before audit
   disposition);
3. resolved zone + row absent → no screen state, so do not drop solely
   for tiny flags-unknown.

This differs from the candidate's proposed “resolved zone but syn-frag
off ⇒ Pass” because that proposal misread `mod.rs:947-957` as the full
worker path: it overlooked the earlier extractor-error return. It also
differs from the WIP's unconditional pre-zone trip, which drops tiny
fragments even when the worker's no-screen-state fast path would Pass.
Cell C6 (§8) must pin all three states. The geometry-only unresolved
policy remains separately fail-closed by the LAND precedent; that is a
deliberate policy extension, not a claim of worker no-screen-zone parity.

**Raw/claimed-zone boundary:** the worker can also receive an ambiguous
`claimed_zone` from fabric routing and consult that zone for stateless
screens even when the raw ingress zone has no screen state
(`poll_stages.rs:1002-1050,1121-1126,1200-1211`). The shim's terminal
kernel-PASS context exposes only the raw `(ifindex, VLAN)` ingress
resolver; this plan's row-presence rule therefore models that raw role.
Q-D asks the seats to confirm that no shim terminal arm needs the worker's
claimed-zone union. If one does, this is a real parity gap to resolve
before the plan can be called worker-equivalent—not an implicit claim
that the shim has a claimed-zone input.

### 4.4 Q1 — TCP-flag family: INCLUDED (decided)

The issue's named five are the acceptance set; the candidate asked
whether the TCP-flag family (syn-fin, no-flag, fin-no-ack, winnuke) rides
along. **Decision: include it, behind its own mask bits** (WIP bit layout:
bit 5 syn-fin, bit 6 shared no-flag/fin-no-ack/winnuke family — the Go
builder packs `snap.SynFin` → bit 5, `snap.NoFlag ‖ snap.FinNoAck ‖
snap.WinNuke` → bit 6, §6.2). Reasons:

- Same stateless class, same outer guard (`stateless.rs:46-51`); the
  inputs (`tcp_flags`, `flow_dst_port`) are already parsed locals — the
  marginal verifier cost is register compares, budgeted in §7 and
  separately killable (K1 fallback drops this family first, §9).
- Leaving it out keeps a KNOWN terminal bypass for host-bound TCP: a
  SYN+FIN or no-flag packet to a local address with the profile enabling
  those checks would still kernel-PASS unscreened — the same defect
  class as the named five, on the same arms.
- Dropping it later, if a seat or K1 demands, is a mask-bit deletion in
  `host_screen.rs` + `host_screen.go`, not a redesign (the WIP already
  factored it that way).

Flowless-path asymmetry, stated honestly: the worker's flowless twin
(`check_flowless_screens_opts`) does NOT run TCP-flag screens or syn-frag
at all (`mod.rs:1262-1276`). The shim gate runs on parsed packets before
any flow/flowless distinction exists, so the shim is STRICTER than the
flowless worker path for first fragments. That is parity with the
flow-present path (which is the path host-bound kernel-pass traffic is
being denied), and it is the fail-closed direction; it is not a
divergence that admits anything the worker drops.

## 5. Fix shape: scratch-laundered packed verdict, ZERO struct widening

**Invariant (kill-criterion-grade): `ParsedPacket` (`lib.rs:2148-2195`)
and `ExtWalk` (`ipv6_ext_walk.rs:191-226`) gain ZERO fields.
`MAX_EXT_HDRS` (= 7, `ipv6_ext_walk.rs:49`), walk advance/break behaviour,
and `parse_l4` signatures are unchanged.** Verified at landing by an empty
diff on those definitions (§7.3).

### 5.1 Precedent

`userspace_v6frag_scratch` (`lib.rs:603-604`, comment `:588-602`):
"Reading a SECOND value out of the walk defeats the verifier's state
merging at the loop exit… A map read is opaque to the verifier… Measured:
consuming the flag directly REJECTS at 1,000,001; laundered it costs
+298,128 and verifies." `parse_ipv6` already performs the
write-then-read dance with fail-closed-on-map-error posture at
`lib.rs:2438-2462`.

### 5.2 New scratch map

```rust
#[map(name = "userspace_screen_scratch")]
static USERSPACE_SCREEN_SCRATCH: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
```

declared beside `USERSPACE_V6FRAG_SCRATCH` (after `lib.rs:604`). ONE `u64`
per CPU, written by the parsers from already-validated locals, read ONCE
by the outlined gate. A map read is opaque to the verifier, so the packed
word does not fork downstream state. Per-CPU is required (concurrent
queues/CPUs — same argument as `lib.rs:600-602`).

Wiring follows the `userspace_land_screen` precedent exactly:
shim map decl (after `lib.rs:519`), `pkg/dataplane/userspace/maps.go`
name const (after `:56`), `pkg/dataplane/loader_userspace_shim.go` pin
lists, `pkg/dataplane/retirement_boundary_canary_test.go` allowlist row,
`userspace-dp/src/afxdp/bpf_map/pin.rs` row. The WIP did this wiring
correctly — reuse its diff (§3).

### 5.3 What the parsers write (no new packet reads except as noted)

The scratch word is initialised to zero for EACH parsed packet before
any optional sighting writes, so clean packets cannot inherit stale
state. Every required scratch map operation is checked: on failure the
parser returns `None` (the existing shim parse-fail drop) and the gate
is never reached. Do not promise to write an all-ones sentinel after
`get_ptr_mut` itself failed — that failure means no writable slot was
returned. Thus the gate reads only a word written for the current packet.

- **IPv4** (`parse_ipv4`, `lib.rs:2263-2386`): every input is already a
  local there — `frag_field` (`:2316`), `non_first_fragment` /
  `first_fragment` (`:2317-2318`), `total_len` (`:2292`), `ihl`
  (`:2277`), `tcp_flags_unknown` (`:2353-2355`), wire protocol `iph[9]`
  (`:2322`, `:2375`). Pack the geometry and TCP trip locals before
  returning `Some`. ONE new packet-shape computation: the LSRR/SSRR
  sighting over the already-read header slice (`read_bytes(..., ihl)` at
  `:2281` — slice already held). Reuse the WIP's
  `ipv4_has_source_route_option` in `userspace-xdp/src/ipv4_len_gate.rs`
  as-is: pure host-compilable TLV scan with worker fail-closed
  malformed-option ordering (`extract.rs:242-300`). It adds a bounded
  ≤40-byte loop over a validated local slice, no new packet-pointer
  arithmetic. This is the budget risk line (§7 K1).
- **IPv6** (`parse_ipv6`, `lib.rs:2388-2523` + `walk_ipv6_ext_headers`,
  `ipv6_ext_walk.rs:273-368`): initialize the scratch before the walk.
  The walk already decodes the governing values as locals it currently
  discards — fragment word `word` (`:321`),
  `non_first_fragment_sighting` (`:322`), first-vs-atomic distinction
  (`:341`), Routing-header class (GENERIC arm `:286`; `protocol == 43`
  costs one compare on the already-loaded byte; type byte `rh[2]` reuses
  the span the arm already revalidates at `:290-295`). Update the
  scratch FROM INSIDE the loop arms (where `word`/`offset` are freshly
  validated locals) — do NOT return these through `ExtWalk` (§5
  invariant). `frag_data_off` = `offset + 8 − (l3_offset + 40)` at the
  governing first non-atomic Fragment sighting, exactly the worker's
  `frag_view_v6` input (`extract.rs:380-382`). Write-once at the first
  non-atomic sighting preserves the governing-header rule (§4.2).
  After the walk, `parse_ipv6` must also finalize the tiny-flags bit:
  from the packed first-fragment fact + terminal TCP protocol, set
  `tcp_flags_unknown` only when `payload_len != 0 &&
  ipv6_declared_end(l3_offset as usize, payload_len) <
  (walk.offset as usize) + 14`.
  This matches the worker's IPv6 zero-length sentinel:
  `ip_payload_len == 0` means no declared bound (`usize::MAX`) and
  must NOT manufacture a tiny-flags error (`extract.rs:421-435`).
  The existing shim `l4_truncated` check (`lib.rs:2479-2482`) is
  independent and may still reject a captured extension chain before any
  host-screen gate; do not change or describe that as a screen verdict.
  This is required because current `ParsedPacket.tcp_flags_unknown` is
  IPv4-only (IPv6 literal is false, `lib.rs:2507`). Finalize by checked
  scratch read/modify/write beside the existing `:2446-2462` dance;
  read/write failure returns `None`. The scratch writer inside the walk
  does not change its return shape or parity-visible advance/break
  behaviour.

### 5.4 Packed word layout (u64)

```
bits  0     is_fragment
      1     is_first_fragment
      2     more (MF/M)
      3     tcp_flags_unknown
      4     saw_source_route          (v4 LSRR/SSRR sighting OR v6 RH0/1 sighting)
      5     is_ipv6
      6     wire_is_icmp              (wire_protocol ∈ {1,58}, precomputed)
      7     syn_present               (tcp_flags & SYN; meaningful only when !is_fragment ‖ is_first_fragment)
      8     tcp_flag_trip_synfin      ┐ TCP-flag family trips precomputed in parse_l4's
      9     tcp_flag_trip_flagfam     ┘ TCP arm, where flags/port are validated locals —
                                        ┘ the gate never re-reads the flags byte
 16-31  frag_offset_bytes  (v4: (raw&0x1FFF)<<3; v6: raw&0xFFF8)
 32-47  frag_data_len      (v4: total_len − ihl*4 saturating; v6: payload_len − frag_data_off saturating)
 48-63  pod_extent         (v4: total_len; v6: frag_data_len)  [both saturated at 0xFFFF]
```

Precomputing the two TCP trip bits in the parser is deliberate: it keeps
the gate's arithmetic to fragment geometry only, and keeps
`flow_dst_port` (winnuke's port-139 test, `stateless.rs:74`) out of the
word — winnuke is decided where the port is already a local. Saturation
at 0xFFFF is sound for the POD compare: any true value > 65535 trips
identically (`offset + extent > 65535` is monotone in both).

Resolved-zone mask bits (published byte, §6.2 — distinct space from the
scratch word): bit0 ping-death, bit1 teardrop, bit2 icmp-fragment,
bit3 syn-frag, bit4 source-route, bit5 syn-fin, bit6 tcp-flag family,
bit7 alarm-without-drop. (WIP `HOST_SCREEN_*` constants, `host_screen.rs:39-58`;
Go mirrors in `host_screen.go:49-59`. A Go↔Rust agreement test pins them, §8c.)

### 5.5 The gate

```rust
#[inline(never)]
fn host_screen_gate(pkt: &ParsedPacket, ingress_ifindex: u32) -> bool // true ⇒ drop with HOST_SCREEN_DROP
```

in `lib.rs` beside `land_gate`, using the WIP-salvaged pure verdict from
`userspace-xdp/src/host_screen.rs` (`host_malformed_verdict` +
`host_malformed_disposition`, §3) re-fed from the packed word:

1. Read `USERSPACE_SCREEN_SCRATCH[0]` (opaque ⇒ no state fork). Read
   failure ⇒ return true (fail-closed drop); never treat a missing word
   as a clean packet or reuse stale contents. If `is_fragment == 0 &&
   saw_source_route == 0 && !tcp trips && !tcp_flags_unknown`, return
   false. Common case: one map read + one AND/compare. (LAND's gate
   early-outs on `!is_land` before any map read, `lib.rs:2607`; ours
   cannot — the trip facts live IN the scratch. Cost accepted and
   budgeted in §7.)
2. If `tcp_flags_unknown && is_first_fragment`, resolve the ingress zone
   and read the screen-state row. Row present ⇒ immediately DROP/count
   `host_screen_drop` (regardless of syn-frag bit and alarm bit, matching
   the worker's extractor-error path); row absent or zone unresolved ⇒
   continue without a tiny-only verdict. This special case is why the
   ordinary mask cannot be the only gate input (§4.3).
3. Compute the ordinary verdict mask from the word (pure scalar ops):
   POD / teardrop / icmp-frag / known-flags syn-frag / source-route /
   syn-fin / flag-family bits. If mask == 0, return false. Known-flags
   checks remain profile-mask-gated.
4. Zone resolution — reuse `land_gate`'s exact resolver:
   `UserspaceWgIngressZoneKey{ifindex, vlan_id or u16::MAX}` →
   `USERSPACE_WG_INGRESS_ZONES` → zone_id (`lib.rs:2610-2624`).
   `zone_id == 0` ⇒ unresolved. Sharing this resolver is K3 (§9).
5. Read `userspace_host_screen: HashMap<u32, u8>` (new map, §6.1;
   StableZoneID → mask byte). Absent row under a resolved zone =
   checks-off / no worker screen state. Rows are published for worker
   screen-state zones, including a zero malformed-mask row when state
   exists only for e.g. a flood check (§6.2).
6. Disposition: unresolved ⇒ Drop for any ordinary tripped mask bit
   (LAND-style fail-closed policy; this is intentionally stricter than
   the worker's no-state Pass, §4.3); resolved ⇒
   `mask & zone_byte & ALL_CHECKS == 0` → Pass; alarm bit (bit 7) set
   on a tripped ordinary check → count `host_screen_alarm`, Pass; else
   Drop. The tiny-error special case at step 2 is fail-closed before
   audit disposition. Alarm counting discipline: increment inside the
   gate (like `land_alarm`, `lib.rs:2632`) and let the packet proceed —
   never counted as drop, never double-counted with `pass_to_kernel`
   (the subsequent arm counts that itself, as today).

**Placement rule: screen ONLY after the existing dispatch has selected a
terminal kernel-pass action.** The tempting two-call-site design — one
`host_screen_gate` immediately after each `land_gate` at `lib.rs:791` /
`:1721` — is WRONG: those sites precede the session lookup / redirect
decision. A transit session-miss packet with malformed geometry would
then drop in the shim instead of reaching XSK (`:1141-1148`, redirect
`:1269`), violating K4 and making the C1 transit control impossible.
The LAND gates remain unchanged and ahead of dispatch; host screening is
added to the selected terminal arms below (§1's full table).

`host_screen_gate(&parsed, ingress_ifindex)` is the single outlined
helper, called at each of the 11 terminal pass sites listed in §1:
healthy WG steer, early-filter `pass_local_control`, session-hit
`PASS_TO_KERNEL`, NAT-external NDP, proxy-NDP, ICMP-to-interface-NAT
local, session-miss local, interface-NAT tunnel, GRE-inner pass,
binding-not-ready local/control fallback, and ctrl-disabled
`PassLocalControl`. Each insertion is after that arm's existing
destination/control predicate has selected kernel delivery, but BEFORE
its pass-specific counters and `pass_local_control` / `cpumap_or_pass`
return. If the helper drops, return
`drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_HOST_SCREEN_DROP)`
immediately. Do not place the gate in a generic pass helper that also
serves non-IP or non-adjudicated traffic.

This uses the branch's exact eligibility test rather than reimplementing
locality in a new predicate: by construction, transit session-miss /
redirect falls through and never calls the gate. The
`kernel_pass.rs::DEGRADED_TWIN` table needs NO new rows — no pass arm is
created or reclassified, only packets are subtracted immediately before
the already-selected pass.

**GRE-inner caveat (explicit):** the gate screens the OUTER packet only.
A native-GRE packet whose INNER is `PASS_TO_KERNEL` (`lib.rs:1155-1175`)
carries an inner packet the worker would screen on decap; the outer gate
cannot see it. This matches LAND's current posture (LAND is also
outer-only at the shim). Recorded as residue §10 S5 — do NOT widen
`classify_native_gre_inner` in this fix.

**Q2 — gate above binding-ready: NO (decided).** A global gate above
`binding_ready_slot` (`lib.rs:854`) is unsafe: transit packets have not
yet been classified as redirect vs kernel-PASS, so C1 would screen
transit too. Instead, the binding-not-ready arm first runs
`is_degraded_local_or_control`; only inside its true branch, immediately
before `pass_local_control` (`lib.rs:891-894`), does it call the gate.
Thus host-bound malformed traffic still drops while the worker is
unready, but transit is still dropped/redirected by the existing branch
without shim screening. The ctrl-disabled twin likewise gates only the
`PassLocalControl` match arm (`lib.rs:1726-1728`), after
`is_degraded_local_or_control` has adjudicated it. C13 pins the degraded
host-bound case; C1/C15 transit twins pin the necessary exclusion.

## 6. Control plane + counter ABI

### 6.1 New map `userspace_host_screen`

`HashMap<u32, u8>` (StableZoneID → mask byte), `with_max_entries(65536)`,
declared in `lib.rs` after `USERSPACE_LAND_SCREEN` (`:519`). Loader/pin/
allowlist wiring per §5.2.

### 6.2 Go builder (salvage WIP `host_screen.go`)

`pkg/dataplane/userspace/host_screen.go` (new): mask bits `1<<0..1<<6`
per-check + `1<<7` alarm; `buildUserspaceHostScreenEntries` packs from
`ScreenProfileSnapshot` (`screens.go:60-86`); missing-profile zones get
the conservative mask (ping-death / teardrop / syn-frag / source-route /
syn-fin / flag-family, NOT icmp-fragment — mirroring
`ScreenProfile::conservative_default()`, `packet.rs:229-242`);
inert-profile zones the same + their `AlarmWithoutDrop`; a StableZoneID
claimed by two zones with different masks is poisoned to all-checks-drop;
explicit zero-mask row for zones with worker screen state but no
malformed-check bits (e.g. flood-only); no row for a legitimate no-screen
zone. Thus row presence carries `zone_has_screen_state` (§4.3).
`syncUserspaceHostScreenMapLocked` iterates the live pinned map (LAND
pattern, `land_screen.go:123-176`), called from the same reconcile point
as `syncUserspaceLandScreenLocked` (`maps_sync.go:579`, inside
`syncUserspaceClassifierMapsLocked` `:542`). Capacity:
`checkHostScreenCapacity` (65536). No emit-gate change (§4).

### 6.3 Counter ABI — append-only, existing indices pinned

Existing space (DO NOT renumber): `USERSPACE_FALLBACK_REASON_*` = 0..20,
`MAX = 21` (`lib.rs:36-65`); Go `degradedPathReasonNames [21]string`
(`maps_sync.go:1010-1034`: 0 ctrl_disabled … 19 land_drop, 20 land_alarm;
slots 6 `icmp` and 12 `no_session` reserved-never-emitted, #17248).
The `USERSPACE_BRANCH_ARM_*` space is untouched — the gate is not a
dispatch arm; its drop reuses `drop_degraded_transit`.

New (append-only, exactly the WIP's choice):

```rust
const USERSPACE_FALLBACK_REASON_HOST_SCREEN_DROP: u32 = 21;
const USERSPACE_FALLBACK_REASON_HOST_SCREEN_ALARM: u32 = 22;
const USERSPACE_FALLBACK_REASON_MAX: u32 = 23;   // was 21
```

Go mirror: `degradedPathReasonNames` grows to `[23]string` with
`21: "host_screen_drop"`, `22: "host_screen_alarm"`; the reader loop
already bounds on `len(...)` (`maps_sync.go:1049`). The #8258 agreement
test (`pkg/dataplane/userspace/degraded_reason_agreement_8258_test.go`,
`TestDegradedPathReasonNamesAgreeWithTheShim_8258:93`) self-enrols the
new constants — it MUST go red until the Go side lands; that is the
desired forcing function. Per-reason fidelity: the shim counts ONE
`host_screen_drop` per dropped packet (not per tripped check). A packet
tripping two checks counts once at the shim vs the worker's
first-reason-wins single count — same cardinality, different attribution.
Stated, not hidden: operators see `host_screen_drop`/`host_screen_alarm`
totals on the degraded-path surface; the per-reason split remains
available only for worker-seen traffic (§10 S4).

## 7. Verifier budget — proof strategy

### 7.1 Numbers

Baseline (recorded, master): **779,213** processed insns, cap 1,000,000,
headroom 22.08%, floor 15% (`pkg/dataplane/userspace_xdp_gate_verdict.json`).

**Plan ceiling: total ≤ 850,000 processed insns (headroom ≥ 15.0%, i.e.
the existing floor passes with NO override).** The override env
(`XPF_SHIM_ALLOW_LOW_HEADROOM`, `cmd/shimverify/main.go:232ff`) MUST NOT
be consumed by this change: a run with `override_consumed: true` in the
verdict JSON is a failed landing for #16009, regardless of the number.

Estimated deltas [INFERENCE — no measurement exists; the regen run in
§7.2 is the kill gate]. The #8249 lesson is that per-site arithmetic is
cheap and return-state widening is what kills; every number below is for
state-free scalar / map-opaque work:

| Change | Est. Δ insns | Basis |
|---|---|---|
| Two parser scratch init/pack writes (IPv4 and IPv6) | +2,000–6,000 | one `get_ptr_mut` + 8-byte store + pack shifts per parser; locals already validated |
| IPv4 LSRR/SSRR scan (`ipv4_len_gate.rs`, ≤40 B bounded loop over held slice) | +3,000–10,000 | bounded loop, no packet-pointer math; the risk line (K1) |
| IPv6 walk in-loop sightings (frag word + RH compare, write-once) | +2,000–8,000 | tests on already-loaded `word`/class byte inside existing arms; no ExtWalk return change |
| IPv6 tiny-flags finalization (scratch read/modify/write against declared payload end) | +1,000–3,000 | needed because current shim's unknown-flags field is IPv4-only; honors worker `extract.rs:423-442` |
| Gate subprogram (1 outlined body: scratch read, mask arith, WG-zone + host-mask reads, disposition) | +1,500–4,000 | scalar ops + map gets; outlined ⇒ walked once, called only by terminal pass arms |
| Eleven gate call sites + drop returns | +1,100–3,300 | one BPF-to-BPF call + compare each; transit path does not call gate |
| Counter increments (drop via existing `drop_degraded_transit`; alarm via existing outlined `incr_fallback_stat`, `lib.rs:2009-2013`) | ~0 | existing outlined callee, new index only |
| **Total** | **+10,600 – 34,300** | **projected 789,813 – 813,513 ⇒ headroom 21.0–18.6%, floor passes with ≥ 36,487 slack-to-floor** |

### 7.2 Measurement protocol (existing machinery, no new tooling)

1. Capture the baseline verdict BEFORE the change (`make generate-userspace-xdp`,
   Makefile `:95-98` → `cmd/shimverify`; writes
   `pkg/dataplane/userspace_xdp_gate_verdict.json` + manifest hashes).
   Expected: 779,213 on the current toolchain/kernel.
2. Apply steps in landing order (§12): host verdict + twin first, then
   parser scratch writes, then gate + all 11 terminal call sites +
   constants — regen at THIS point; stop at K1 if red. Go wiring follows
   the verifier decision.
3. Record after-verdict: processed insns, headroom, `override_consumed`
   (must be `false`), object/source hashes moving together
   (`pkg/dataplane/userspace_xdp_manifest.json` pins this;
   `userspace_xdp_manifest_test.go`).

### 7.3 Structural proofs (diff-level, no measurement)

- `git diff` on `ParsedPacket` (`lib.rs:2148-2195`) and `ExtWalk`
  (`ipv6_ext_walk.rs:191-226`) definitions: EMPTY. Any field addition is
  an automatic plan violation — this is the exact change measured to
  reject (§3).
- `MAX_EXT_HDRS`, walk advance/break statements, `parse_l4` signature:
  unchanged.
- `USERSPACE_BRANCH_ARM_*` table: unchanged.

## 8. RED/GREEN cells (existing harnesses only — no new test infrastructure)

**(a) Host twin parity** — `userspace-dp` cargo, source-include pattern
(`tests_shim_land_13953.rs:19` / `tests_shim_gre_inner_14954.rs:48`
`#[path]` include; registered in `userspace-dp/src/afxdp/frame/mod.rs:2758ff`).
Reuse the WIP's `tests_shim_host_screen_16009.rs` + the
`worker_malformed_mask_for_test` oracle, but feed it from the PACKED WORD:
corpus = every decisive shape × {v4, v6} × {screen row present,
screen row absent, alarm row, unresolved zone}: POD max-offset fragment;
teardrop zero-payload / MF+non-multiple-of-8 / legal 1–7 B LAST fragment
(must PASS — #9426 regression shape); ICMP/ICMPv6 fragment;
SYN-on-first-fragment; tiny first fragment flags-unknown (drop with a
screen-state row even when syn-frag is off or alarm is on; do NOT drop
solely for tiny flags when the row is absent or the zone unresolved —
§4.3); IPv6 zero `ip_payload_len` sentinel with captured TCP ACK:
`extract_screen_info` must not yield `TinyFirstFragmentFlagsUnknown`,
and the packed word must not set the tiny bit (teardrop mask off);
LSRR-after-malformed-option; RH0 / RH1 / RH2 (RH2 must PASS); SYN+FIN;
no-flag; FIN-no-ACK; winnuke port 139 vs 443; IPv6 atomic fragment (must
trip nothing, §4.1); clean packets. FAIL-ON-REVERT: deleting any verdict
arm reds its row.

**(b) BPF decisive cells** — `BPF_PROG_TEST_RUN` harness, reuse the WIP's
`host_screen_drop_16009_test.go` (harness:
`pkg/dataplane/userspace/land_drop_13953_test.go` loaders/runners —
`loadUserspaceXDPTestCollection`, `runUserspaceXDPTestPacket`,
`assertUserspaceXDPDegradedPathStat[Absent]`). Cells (packet → local dst
= drop + `host_screen_drop`; same packet → transit dst = existing redirect
to worker and no shim host-screen counter):

| Cell | Shape → local | Expected (drop-enforcing zone) | Honest label / control |
|---|---|---|---|
| C1 | v4 non-last fragment, MF=1, 4-byte payload (offset 0) | XDP_DROP, `host_screen_drop`+1, `pass_to_kernel` absent | **GEOMETRY ONLY** (`data_len % 8 != 0`, `stateless.rs:239-241`). Does NOT prove overlap handling (§2). Transit twin: existing worker redirect; no shim `host_screen_drop` |
| C2 | v4 LSRR (IHL 6, kind 131) | DROP + counter | same packet, zone mask without source-route: PASS-to-kernel, no counter |
| C3 | v6 ICMPv6 non-first fragment | DROP + counter | v6 UDP non-first fragment, icmp-frag on: NOT dropped by this check |
| C4 | v4 POD (offset 0x1FFF, extent pushing sum > 65535) | DROP + counter | offset making sum == 65535 exactly: PASS (boundary, `>` not `>=`) |
| C5 | v4 SYN first-fragment | DROP + counter | SYN whole packet: PASS (not a fragment) |
| C6 | v4 tiny first fragment (declared L4 = 8 B, flags unseen) | DROP + `host_screen_drop` when a screen-state row exists, even if syn-frag is off or alarm is on | screen row absent or zone unresolved: no tiny-only drop; synfrag-on alone is not the trigger (§4.3) |
| C7 | v6 RH0 | DROP + counter | RH2: PASS |
| C8 | v4 legal last fragment 1–7 B, teardrop on | PASS to kernel (no counter) | #9426 false-positive guard |
| C9 | alarm zone, C1 packet | PASS to kernel, `host_screen_alarm`+1, `host_screen_drop` absent | — |
| C10 | unresolved zone (no WG row), C1 packet | DROP + counter (fail-closed geometry) | unresolved + C6 packet: NOT host-screen-dropped |
| C11 | LAND packet (src==dst), LAND on, all malformed off | `land_drop`, NOT `host_screen_drop` (LAND still runs at `lib.rs:791` before dispatch; host gate is only in selected pass arms) | — |
| C12 | clean TCP ACK to local | PASS, no screen counters (gate common-case cost only) | — |
| C13 | degraded (binding-not-ready seed → `is_degraded_local_or_control` true → `pass_local_control`), C1 packet | DROP + `host_screen_drop` at the selected local/control fallback site | no global pre-binding gate; transit-false branch remains unchanged (Q2, §5.5) |
| C14 | ctrl-disabled (`ctrl.enabled=0`, adjudicated ifindex), C1 packet | DROP + `host_screen_drop` in `PassLocalControl` arm (`lib.rs:1726-1728`) | non-adjudicated ifindex ctrl-disabled: unchanged ctrl_disabled drop, no screen counter |
| C15 | double-count guard: C1 packet that is ALSO session-hit `PASS_TO_KERNEL` | exactly one `host_screen_drop`, zero worker screen counters (worker never sees it) | transit twin redirected: worker stage-10 counts per-reason, shim `host_screen_drop` stays 0 |
| C16 (added) | v6 atomic fragment header (offset 0, M=0), all fragment checks on | PASS (not a fragment, §4.1) | — |
| C17 (added) | v6 [atomic Frag][non-atomic Frag offset>0] ICMPv6, icmp-frag on | DROP + counter (governing-header rule, §4.2) | single atomic only: PASS (C16) |
| C18 (added) | v6 tiny first fragment (M=1, declared TCP L4 = 8 B, flags unseen) | same as C6: drop with screen-state row even if syn-frag off/alarm on | row absent / unresolved: no tiny-only drop; pins v6 declared-length inference |
| C19 (added) | v6 first Fragment (M=1), wire Payload Length=0, captured TCP ACK bytes; screen-state row, syn-frag on, teardrop off | worker extractor/packed-word twin: no tiny error; BPF: existing L3 `PARSE_FAIL` drop, no `host_screen_drop` | pins zero-as-unbounded tiny-flags rule; does NOT claim the BPF packet passes |

Cells C1–C15 are the candidate's set, mapped onto the narrowed scope:
all remain in the in-scope per-packet stateless class; the narrowing
changes their LABELS and claims made from them (C1 above all), not their
packets. C16–C19 are added because atomic/double-fragment handling,
v6 tiny-flags inference, and the zero-payload-length sentinel are
load-bearing worker rules the candidate corpus only implied.

**(c) Go cells:** `buildUserspaceHostScreenEntries` table (WIP's
`host_screen_16009_test.go`, reused: full / audit / off / flood-only
(explicit zero malformed-mask row, still present) / missing / inert /
genuine no-screen zones, collision poisoning, nil snapshot); mask-bit
agreement test vs Rust `HOST_SCREEN_*` constants (#8258 pattern);
capacity check (`checkHostScreenCapacity`, 65536).

**(d) Verifier cell:** §7.2 regen — RED = > 850,000 or REJECT or
`override_consumed: true`; GREEN = ≤ 850,000 with floor PASS, no override.

**(e) No-regression:** existing shim suites stay green untouched —
`land_drop_13953_test.go`, `xdp_branch_stats_16241_test.go`,
`degraded_reason_agreement_8258_test.go` (after its Go mirror grows — it
MUST red mid-change, green at landing),
`userspace_xdp_manifest_test.go`, `verify_userspace_shim_headroom_test.go`;
worker screen suites (`userspace-dp/src/screen/tests*.rs`) untouched
(the worker is not modified except the test-only mask oracle).

## 9. Risks and kill criteria (K1–K5)

- **K1 (the kill criterion):** regen > 850,000 processed insns, or any
  REJECT, or any consumed override ⇒ this shape is dead. The fallback is
  NOT gate-override and NOT struct widening (both rejected by evidence);
  it is re-scoping to fewer checks — drop the TCP-flag family first (Q1,
  §4.4; it is the only family whose trips are precomputed in `parse_l4`)
  and re-measure. If the five-check shape alone exceeds the ceiling, the
  issue returns to STEP-0 with redirect-to-worker (§2.1) as the remaining
  architecture — materially larger, out of this plan. Sub-threshold:
  830,000–850,000 lands only with a written headroom-recovery follow-up
  filed; any single line in the §7.1 table measuring > 25,000 alone ⇒
  stop and re-plan that line (likely the v4 options loop; the fallback is
  scratch-carrying a 2-bit options-scan RESULT computed during the
  existing `read_bytes(ihl)` validation instead of a second loop — a
  kind-byte scan WITHOUT the TLV length walk is not equivalent for
  malformed tails, `extract.rs:230-300`, and must not be substituted
  silently).
- **K2 (scratch staleness):** every parsed packet that reaches any of the
  11 gate sites must have a current-packet word. Initialise to zero before
  optional writes (IPv4 after `read_bytes(..., ihl)` at `lib.rs:2281`;
  IPv6 before `:2410` walk), check every parser map operation, and on any
  write/finalization failure return `None` from the parser (existing
  fail-closed parse drop), not an all-ones sentinel through a missing map
  pointer. The gate's scratch READ failure separately returns Drop. If
  any `Some` path to a terminal gate site can lack the current packet's
  completed word, KILL: stale scratch is a silent bypass.
- **K3 (zone-key skew):** the gate MUST use the identical
  (ifindex, vlan-or-`u16::MAX`) key as `land_gate` (`lib.rs:2610-2624`).
  A second keying convention = zones silently unresolved = everything
  drops (availability) or, inverted, passes. The host twin pins key
  construction by reusing land's resolver shape; if the implementer
  cannot share the resolver without an extra map walk per packet that
  blows K1, KILL and re-plan around a shared outlined resolver.
- **K4 (transit double-screen / host-bound coverage):** invoke the gate
  ONLY after one of the exact terminal kernel-pass branches in §1 has
  selected that action, and before its pass counters / pass return. A
  common gate immediately after LAND is WRONG: transit session-miss
  packets there have not yet been selected for redirect vs kernel PASS,
  and some later XSK-redirect. Any such pre-decision gate can drop
  worker-admissible transit; any omitted terminal pass site leaves a
  host-bound bypass. C1/C15 must assert both halves: local malformed
  packets increment `host_screen_drop`; transit twins do not increment
  it and still take the existing redirect path. Either an early gate or
  a missing pass-site gate blocks the plan.
- **K5 (scope creep):** any appearance in the diff of R-overlap state,
  scan/sweep trackers, or SYN-cookie minting/validation at XDP kills the
  "bounded" claim and should kill the plan at review. Those are
  successors (§10), never this diff.

Other stated risks: GRE-inner outer-only screening (§5.5, §10 S5);
session-hit cached `PASS_TO_KERNEL` rows installed before a screen-profile
change — the gate reads the current per-zone screen row immediately
before the terminal pass, so profile changes take effect on existing
session-hit traffic too. No screen row under a resolved zone means
`zone_has_screen_state == false`, NOT "unresolved": the new shim object,
host-screen map wiring, and config-derived map sync must ship together,
with the row rebuild complete before activating the program (existing
loader invariant at `loader_userspace_shim.go:115-117`). A mixed-version
deployment that runs the new object without the new Go map writer is
unsupported; otherwise screen checks would be disabled for resolved zones.

## 10. Successor issues to file (exact titles)

Filed when this plan lands (or when #16009 closes under it), so the
narrowing is on the record and the residue is not silently dropped:

- **S1:** `screen: true fragment-overlap (teardrop) detection needs cross-fragment state — worker fragment_assoc is association-only`
- **S2:** `screen: port-scan / ip-sweep parity for host-bound kernel-PASS traffic (stateful trackers are worker new-flow only)`
- **S3:** `screen: SYN-cookie challenge semantics for host-bound traffic bypassed by shim kernel-PASS`
- **S4:** `shim: per-reason screen counter fidelity for host-bound drops (aggregate host_screen_drop only today)`
- **S5:** `shim: GRE-inner / decapsulated inner packets are outer-screened only on the kernel-PASS arm`

(Flood RATE meters are deliberately NOT a successor: already replicated
in `pkg/nftables/host_inbound_screens.go`, §1.)

## 11. Self-assessment and questions for the three plan seats

**Self-assessment: PLAN-READY-shaped, conditional on measurement and
plan-seat audit.** The predicates, carriage, ABI, and cells are
source-verified at `6c27f54cf2`; the verifier number is unmeasured, so K1
is a hard kill criterion with a pre-agreed fallback order. The candidate's
Q1 is decided IN (§4.4); Q2 is decided NO global pre-binding gate (§5.5).
The key correction to the candidate is architectural: the host-screen
helper belongs at each terminal kernel-pass arm, not beside the two LAND
sites, or transit traffic can be dropped before redirect selection.

Questions the seats are asked to attack, in order of lethality:

1. **Q-A (K4 audit):** are all 11 insertion points in §1 AFTER their
   exact terminal kernel-pass eligibility decision? In particular, can
   a multicast/early-filter or GRE-inner branch still carry transit
   traffic when its gate call runs? Name any site that must be narrowed
   or removed.
2. **Q-B (K2 audit):** is there ANY path from `parse_ipv4`/`parse_ipv6`
   returning `Some` to any of the 11 gate sites on which this packet's
   scratch word is not complete, or any gate read failure that can still
   return Pass (including the ctrl-disabled twin's independent parse,
   `lib.rs:1696-1711`)?
3. **Q-C (K3):** can `land_gate`'s resolver be shared with
   `host_screen_gate` without repeating WG-zone lookups at terminal
   pass sites, and if not, does the extra lookup fit the §7.1 budget?
4. **Q-D (§4.3):** does raw ingress row presence exactly model the
   worker's `zone_has_screen_state` for resolved profiles,
   missing-profile refs, inert refs, and profiles with zero malformed
   bits (e.g. flood-, LAND-, or stateful-check-only)? Can the worker's
   ambiguous `claimed_zone` union (`poll_stages.rs:1002-1050,1200-1211`)
   ever apply to traffic on one of these shim terminal arms, despite the
   shim having only raw ingress resolution? Is unresolved-zone fail-closed
   policy for ordinary trips acceptable, given it is stricter than the
   worker's no-state Pass?
5. **Q-E (Q1 cost):** is precomputing TCP-flag trip bits in `parse_l4`
   register-cheap, or does it fork verifier states in the TCP arm as
   return-widening did? This is the first K1 fallback if wrong.
6. **Q-F (§5.3 v6):** do in-walk scratch writes and post-walk tiny-flags
   finalization preserve #4555 parity without widening `ExtWalk` or
   creating stale partial words, including the worker's zero
   `ip_payload_len` / `usize::MAX` declared-bound sentinel?
7. **Q-G (§6.3):** is one aggregate `host_screen_drop` / `alarm`
   acceptable as landing observability, with S4 as fidelity follow-up,
   or is per-reason attribution a landing requirement?

## 12. Scope-size estimate and landing sequence (for the engineering lane)

Estimate: ~650–950 lines net new/changed (verdict module ~250 salvaged,
parser scratch writes/options scans/finalization ~125, gate + 11 terminal
call sites ~130, Go builder/sync/wiring ~250 salvaged, counter mirrors
~10), plus ~700 lines of tests (mostly salvaged) and regenerated
object/manifest/verdict artifacts. One engineering lane, no worker
production change (test-only oracle excepted).

Sequence: (1) host verdict `host_screen.rs` + packed-word decode and
source-include twin (§8a) green; (2) checked parser scratch writes,
IPv4 TLV scan and IPv6 in-walk sightings plus post-walk tiny-flags
finalization; `ParsedPacket`/`ExtWalk` diff EMPTY (§7.3); (3) implement
the outlined gate, all 11 terminal call sites, and append-only reason /
counter constants (21/22); (4) regenerate and measure the COMPLETE shim
object (§8d), stop at K1 (≤850,000 processed insns, floor PASS, no
verifier override); (5) Go map wiring, builder/sync, counter mirror, §8c
green, #8258 green again; (6) BPF cells §8b incl. C1–C19, docs
`docs/afxdp-packet-processing.md` screen-parity paragraph (WIP hunk
reused), and manifest/gate-verdict artifacts committed with the object.
