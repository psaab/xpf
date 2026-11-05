# #16009 — shim kernel-PASS bypasses worker malformed screens: host-screen plan

- **Status:** design revision folding the three prior PLAN-NEEDS-MAJOR seat
  reviews; ready for a fresh three-seat plan review. No production code is
  included. Implementation starts only after the plan seats converge.
- **Source base:** claims below were checked against `origin/master` at
  `6c27f54cf2`. Five earlier documentation-only commits are above that
  base on `research/16009-host-screen`: `476df53770`, `c8e39b6d26`,
  `f2fcfcff85`, `7ddbb5c743`, and `359cc7e348`. Source anchors refer to
  the base, not the candidate's older line numbers.
- **Input, not truth:** the prior-lane candidate `docs/log/16009.md` was
  checked claim by claim. Corrections include `land_gate` at
  `lib.rs:2605-2636`, ctrl-disabled LAND at `:1721-1723`, and the actual
  verifier override `XPF_SHIM_ALLOW_LOW_HEADROOM`
  (`cmd/shimverify/main.go:232ff`).
- **History:** preserve those five pushed research commits; the seat records'
  SHAs remain historical review references. This fold adds a new commit
  with the `(#16009)` subject; no prior commit is rewritten.

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

The 11 parsed-IP terminal kernel-pass arms included in the gate, all
verified at `6c27f54cf2`:

| Arm | Anchor / insertion point for `host_screen_gate` |
|---|---|
| WG steer | `lib.rs:944-951`; after predicate succeeds, before branch counter / return `:950` |
| early-filter IPv4 limited-broadcast/multicast and IPv6 multicast (not link-local unicast) | `lib.rs:952-965`; after predicate succeeds, before trace and `pass_local_control` `:964`; exact classes in `early_filter.rs:85-109` |
| session-hit `PASS_TO_KERNEL` | `lib.rs:1002-1028`; after hop-limit veto, before local trace/counters and return `:1028` |
| session-miss NAT-external NDP | `lib.rs:1035-1044`; inside matching arm, before branch counter / return `:1043` |
| session-miss proxy-NDP | `lib.rs:1050-1059`; inside matching arm, before branch counter / return `:1058` |
| session-miss ICMP-to-interface-NAT local | `lib.rs:1060-1073`; after predicate, before trace/counter / return `:1072` |
| session-miss local destination | `lib.rs:1101-1121`; after hop-limit veto, before trace/counter / return `:1120` |
| interface-NAT tunnel kernel pass | `lib.rs:1125-1139`; inside `interface_nat_tunnel_passes_to_kernel`, before branch counter / return `:1138` |
| GRE-inner `PASS_TO_KERNEL` | `lib.rs:1155-1175`; after typed predicate succeeds, before trace/counters / return `:1174` |
| binding-not-ready degraded local/control | `binding_ready_slot` call `:854`; after `is_degraded_local_or_control` returns true, before `pass_local_control` `:891-894` |
| ctrl-disabled local/control | `degraded_ctrl_disabled_action` `lib.rs:1671`; after `PassLocalControl` disposition, before branch counter / `pass_local_control` `:1726-1728` |

Two earlier CPUMAP returns are deliberately outside this gate: L2 parse
failure (`lib.rs:636-638`) and non-adjudicated ingress (`:714-717`) occur
before a `ParsedPacket` exists, so neither has the scratch word or raw-zone
context required here.

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

**Chosen: option (1) — narrow #16009 to worker stateless predicates on
raw ingress state where required fields are actually available, with the
explicit conservative capture-short divergence in C22, plus one aggregate
shim drop/alarm counter.** Also include the worker's screen-state-gated
IPv4 malformed-options and duplicate non-atomic IPv6-fragment parse errors.
This does not include cross-packet state or per-reason observability. The
early-filter multicast/limited-broadcast arm is an explicit policy
extension, not worker parity: the worker does not run malformed screens
for those early-pass packets.

The narrowed screen contract covers:

1. ping-of-death geometry (`check_ping_of_death`);
2. teardrop **geometry** only (`check_teardrop`: zero/under-length payload
   or non-last payload not divisible by eight);
3. ICMP-fragment, tested using the wire protocol;
4. SYN on a first fragment (`syn-frag`) and the worker's
   screen-state-gated tiny-first-fragment flags-unknown error for IPv4;
5. source-route: IPv4 LSRR/SSRR and IPv6 Routing type 0/1;
6. each TCP-flag check with its own independently enabled mask bit:
   SYN+FIN, no-flag, FIN-without-ACK, and WinNuke;
7. worker fail-closed extraction errors for malformed IPv4 options and a
   second readable non-atomic IPv6 Fragment header, gated by screen-state
   row presence.

The v6 tiny-first-fragment worker verdict is **not** claimed as host-screen
parity: `parse_ipv6` rejects the short declared/captured TCP shape before
the proposed gate. C18 is therefore an earlier `L3 PARSE_FAIL` control,
not a `host_screen_drop` cell. See §4.3 and §8.

The gate uses a scratch-laundered packed verdict (§5), a raw-ingress
`HashMap<u32, u16>` row (§6), and the append-only aggregate
`host_screen_drop` / `host_screen_alarm` pair (§6.3). Flood meters stay in
`pkg/nftables/host_inbound_screens.go` and MUST NOT be duplicated. True
fragment overlap, port-scan/IP-sweep, SYN-cookie challenge semantics,
zone/reason events and per-reason counter fidelity are assigned to named
successors (§10). The raw/claimed-zone boundary is decided and bounded in
§4.3; it is not left as an open Q-D.

**C1 honesty, binding for every parity claim:** the candidate's C1 (IPv4
MF=1, four-byte payload) exercises ONLY the teardrop geometry predicate
(`data_len % 8 != 0`, `stateless.rs:222-242`). It MUST NOT be described as
proving overlap handling. `stateless.rs:178-183` explicitly says
`check_teardrop` is not an overlap detector. True overlap is handled by a
different, stateful worker module, `fragment_overlap`; that tracker checks
LocalDelivery fragments but does not record those fragments
(`fragment_overlap/mod.rs:131-140`). C1 proves neither that tracker nor a
two-fragment overlap outcome. The actual host-bound overlap acceptance is
assigned to S1: two overlapping LocalDelivery fragments, with the second
rejected by the integrated overlap path (§10). No measured parity argument
for overlap is claimed.

### 2.1 Rejected alternative (2): literal scope / cross-fragment state / redirect-to-worker

- **Literal overlap parity is not a stateless screen.** The worker does
  have the stateful `fragment_overlap` tracker: it checks fragment byte
  ranges at `poll_descriptor/mod.rs:1728-1806` and rechecks at commit/TX.
  However, its module documents that non-IPsec LocalDelivery fragments
  are checked but never recorded (`fragment_overlap/mod.rs:139-140`).
  Redirecting every kernel-bound packet to the worker alone therefore does
  not close the host-bound two-fragment acceptance; S1 must make the
  LocalDelivery pair test pass. Stateful port/sweep tracking and cookie
  minting are also different mechanisms. The rejected 738b7b942e struct
  widening already hit 1,000,001 processed instructions (§3); that is not
  a reason to claim these stateful requirements do not exist.
- **Redirect-to-worker for every host-bound packet** also changes the
  existing terminal-arm contract: local/control availability would depend
  on worker health, including degraded and ctrl-disabled paths where
  `pass_local_control` is intentional (`lib.rs:1812-1816`). It creates a
  new transit-vs-local qualification boundary. This remains a possible
  re-plan if K1 kills this shape, not an in-scope fallback.
- **Per-reason shim events/counters** require worker-order attribution
  (`LAND → TCP flags → POD → teardrop → ICMP-fragment → source-route`)
  and zone/reason event behavior, including the worker screen-drop paths
  at `poll_stages.rs:1360-1374,1450-1504`. The aggregate shim counters
  identify neither reason nor zone; they do not “localise” a drop.
  S4 owns that observability residue.


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
| `userspace-xdp/src/host_screen.rs` — pure verdict (`host_malformed_verdict`, `host_malformed_disposition`) and `HOST_SCREEN_*` masks | Salvage the host-compiled verdict arithmetic only; revise to a `u16` with independent SYN+FIN/no-flag/FIN-no-ACK/WinNuke bits and a separate alarm bit (§4.4, §5.4-6). The shared WIP flag-family bit is rejected. |
| `userspace-xdp/src/ipv4_len_gate.rs::ipv4_has_source_route_option` (WIP helper) | Reuse only as a TLV-walk starting point, refactored to return both source-route sighting and malformed-options verdict. It does NOT mirror the worker's `TruncatedIpv4Header` path by itself. No shim parser already drops these malformed options; the worker error is at `extract.rs:224-241,258-299` and is screen-state-gated. Remove any “parser drops earlier” justification. |
| Go: `pkg/dataplane/userspace/host_screen.go` (`buildUserspaceHostScreenEntries`, `hostScreenMaskFor`, `syncUserspaceHostScreenMapLocked`, `checkHostScreenCapacity` 65536) | Reuse the builder shape, but do NOT claim its missing-profile handling is already correct: `ScreenMissingProfiles` must carry `AlarmWithoutDrop` for defined `BadNumericUnresolved` references as well as inert references; truly undefined profiles remain false (`screens.go:492-503`, worker `screen/mod.rs:571-585`). Add the §8 Go/BPF audit cell. |
| Loader/pin wiring: `pkg/dataplane/userspace/maps.go` (`mapNameUserspaceHostScreen`), `pkg/dataplane/loader_userspace_shim.go` (`userspaceHostScreenMapName`, pin lists), `pkg/dataplane/retirement_boundary_canary_test.go` allowlist row, `userspace-dp/src/afxdp/bpf_map/pin.rs` | Follows the `userspace_land_screen` precedent exactly; wiring was not implicated in the reject |
| Tests: `host_screen_16009_test.go` (Go builder), `host_screen_drop_16009_test.go` (BPF cells), `userspace-dp/src/afxdp/frame/tests_shim_host_screen_16009.rs` (host twin vs `worker_malformed_mask_for_test`, a test-only oracle) | The BPF helper definitions `loadUserspaceXDPTestCollection`, `runUserspaceXDPTestPacket`, and degraded-path stat assertions are in `pkg/dataplane/userspace/xdp_shim_decouple_test.go:513,661,674,707`; `land_drop_13953_test.go` consumes them. Cells are re-labelled per §8, and the corpus is fed from the packed word instead of a widened struct. |
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
| TCP-flag checks (Q1) | `stateless.rs:62-82`: syn-fin `:62-64`, no-flag `:66-68`, fin-no-ack `:70-72`, winnuke `:74-76`, syn-frag `:78-82`, under outer guard `:46-51`; tiny unknown first-fragment error is earlier at `:52-59` | Every profile check is independent; no shared no-flag/FIN-no-ACK/WinNuke mask bit. Compute each trip at the parser's common post-L4 point (§4.4/§5.3). |

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

The worker's IPv6 extractor rejects a second readable non-atomic Fragment
header as `MultipleIpv6FragmentHeaders` (`screen/extract.rs:357-365`).
Separately, the governing-header rule is that the first readable
non-atomic Fragment header governs and a later atomic header must not
erase it (`:368-398`). These are distinct properties.

The shim's `ipv6_ext_walk.rs:308-343` currently tracks fragment sightings
and the governing word, but not a second non-atomic header. Add one
scratch-only `multiple_ipv6_non_atomic` bit when a second readable,
non-atomic Fragment header is encountered, before the walk's non-first
fragment break. A row-present screen-state gate drops this worker
extractor error. Do not widen `ExtWalk` or change its advance/break
rules. C17 tests only `[atomic][non-atomic]` governing selection; it
MUST NOT be cited as a duplicate-header test. C21 is the separate
duplicate-header cell.

### 4.3 Screen-state errors and raw/claimed-zone boundary

`stage_screen_check_with_ambiguous` returns Pass before extraction only
when both `raw_profile_zone` and `claimed_zone` are absent
(`userspace-dp/src/afxdp/poll_stages.rs:1112-1126`). Once screen state is
present, extractor errors are fail-closed before profile-mask or alarm
evaluation:

- IPv4 malformed TLVs return `ScreenParseError::TruncatedIpv4Header`
  (`screen/extract.rs:224-241,258-299`), including malformed TLVs both
  before and after a valid LSRR/SSRR. In either order the worker returns
  an extraction error, not a `ScreenPacketInfo` with a normal
  source-route verdict, and drops even when `source_route` is disabled.
  The shim MUST carry a separate malformed-v4 bit and gate it on row
  presence; a source-route sighting bit alone is insufficient.
- A second readable non-atomic IPv6 Fragment header returns
  `MultipleIpv6FragmentHeaders` (`extract.rs:357-365`); mirror it with
  the independent scratch bit from §4.2 and the same row-presence rule.
- A first-fragment TCP datagram whose **declared** end is before the
  flags byte returns `TinyFirstFragmentFlagsUnknown` (`extract.rs:412-442`),
  mapped to `syn-frag` (`screen/packet.rs:309-334`). The production error
  arm drops before `ScreenProfile.syn_frag` or `alarm_without_drop`
  (`poll_stages.rs:1347-1376`; flowless twin `:1195-1231`).

For IPv4 tiny-flags-unknown and the two parse-shape errors above, the
`userspace_host_screen` row's PRESENCE is the shim's screen-state signal:
the Go builder publishes rows for active, missing-profile, inert, and
zero-malformed-mask-but-screen-state zones. Therefore:

1. resolved ingress zone plus row present → drop/count
   `host_screen_drop`, regardless of the ordinary mask or alarm bit;
2. resolved zone plus no row → no screen state, so do not drop solely for
   one of these special parse errors;
3. unresolved zone → likewise do not synthesize a special parse-error
   screen verdict.

This is different from ordinary geometry. Ordinary tripped geometry on
an unresolved zone follows the LAND-style fail-closed policy (C10), which
is explicitly stricter than the worker's no-state Pass. C6 pins all three
IPv4 tiny-error states. For IPv6 tiny first fragments, the worker has the
declared-length error above, but the shim's current `parse_ipv6` /
`parse_l4` and `ipv6_declared_end` check rejects the short shape before
the host gate (`userspace-xdp/src/lib.rs:2467-2482`). Keep that existing
`L3 PARSE_FAIL`; C18 is not a host-screen verdict and makes no v6 tiny
parity claim.

**Claimed-zone decision (Q-D resolved by scope, not left open):** the
worker can consult an ambiguous fabric `claimed_zone` even when raw
ingress has no screen state (`poll_stages.rs:1002-1050,1121-1126,1200-1211`).
`tests_fabric_zone_stamp.rs:5888-5968` proves the worker stage-10 screen
drops the ambiguous claimed-`lan` SYN+FIN before session installation;
its clean control at `:5976-6019` admits the flow. This test proves the
worker claim behavior, not that every shim terminal arm is screened.

The shim steering row is only a bare 5-tuple plus action; it carries no
zone or fabric provenance (`userspace-dp/src/afxdp/bpf_map/mod.rs:109-141`;
shim lookup at `userspace-xdp/src/lib.rs:399-409,556-563`). The existing
multi-zone demotion is a limited protection: session publication passes
`has_multiple_zones` (`poll_descriptor/mod.rs:13137-13144`), and
`uses_kernel_local_session_map_entry` demotes kernel-local rows when
multiple zones exist (`bpf_map/mod.rs:76-105`). It prevents the
session-hit `PASS_TO_KERNEL` row in the two-zone #16051 fixture
(`test_fixtures.rs:739-763`, `forwarding_build/zones.rs:68-80`).

That does NOT close the session-miss local arm (`userspace-xdp/src/lib.rs:
1101-1121`, before any session row exists) or GRE-inner PASS
(`:1155-1175`, which uses an inner-tuple lookup). Neither can recover the
worker's claimed zone. Scope all claimed-zone terminal-pass behavior out
of #16009 as S6, with a primary worker publish-boundary owner and an
arm-by-arm successor acceptance for session-hit PASS, session-miss local,
and GRE-inner PASS. #16009 claims raw-ingress parity only; it does not
claim universal fabric-claimed-zone equivalence.

### 4.4 Q1 — TCP-flag family: INCLUDED, with independent bits

**Decision: include all four candidate Q1 checks**—SYN+FIN, no-flag,
FIN-without-ACK, and WinNuke—because each is a worker stateless
predicate on the same host-bound TCP packet. The worker profile has
independent booleans (`ScreenProfile`); the WIP's shared
no-flag/FIN-no-ACK/WinNuke mask bit is incorrect and MUST NOT be reused.
Use separate `u16` bits: bit 5 SYN+FIN, bit 6 no-flag, bit 7 FIN-without-
ACK, bit 8 WinNuke; bit 9 remains alarm-without-drop (§5.4-6).

The worker check order is SYN+FIN → no-flag → FIN-without-ACK → WinNuke
→ SYN-frag (`stateless.rs:62-82`). The shim only reports an aggregate
drop, so it need not reproduce first-reason attribution in this scope;
S4 owns that gap. C23 tests every one of the 16 enable/disable masks
against four isolated tripping packets and the worker oracle. The four
packet shapes are SYN|FIN|ACK (only SYN+FIN), flags zero (only no-flag),
FIN without ACK (only FIN-without-ACK), and URG|ACK to destination port
139 (only WinNuke).

**B5 placement:** compute the TCP predicate bits at each parser's common
post-L4 convergence point, after either `first_fragment_l4` or `parse_l4`
has supplied protocol, flags, and destination port. Do not put the work
only inside `parse_l4`: IPv4 first fragments take the separate
`first_fragment_l4` branch (`lib.rs:2336-2347`, implementation at
`:2809-2835`). The common point must set SYN-frag for a known SYN first
fragment as well as the four Q1 trip bits. Unknown flags set no ordinary
trip bits; the IPv4 tiny-error state gate is separate (§4.3, §5.3).

Flowless-path asymmetry, stated honestly: `check_flowless_screens_opts`
does NOT run TCP-flag screens or syn-frag (`screen/mod.rs:1262-1276`).
The shim gate runs before flow/flowless classification, so it may be
stricter than that worker flowless path. The target is the flow-present
worker screen that host-bound kernel-PASS traffic bypasses; no claim is
made that the worker flowless twin has these checks.

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
The walk itself remains map-free and core-only. Add a public callback trait
and a no-op sink in `ipv6_ext_walk.rs`:

```rust
pub trait ExtWalkObserver {
    /// true = continue; false = observer write failed (fail closed).
    fn second_non_atomic_fragment(&mut self) -> bool;
}

pub struct NoopExtWalkObserver;
impl ExtWalkObserver for NoopExtWalkObserver {
    fn second_non_atomic_fragment(&mut self) -> bool {
        true
    }
}

#[inline(always)]
pub fn walk_ipv6_ext_headers<O: ExtWalkObserver>(
    data: usize,
    data_end: usize,
    l3_offset: u16,
    first_protocol: u8,
    start_offset: u16,
    observer: &mut O,
) -> Option<ExtWalk>;
```
Make `walk_ipv6_ext_headers` generic over `O: ExtWalkObserver` and take
`&mut O`; use static dispatch only (no closure allocation, function
pointer, `std`, `aya`, or map reference in the core file). Keep a separate
local `non_atomic_seen` from `fragment_seen` so atomic headers do not count.
On transition to the second readable non-atomic Fragment header, call the
observer exactly once **before** the non-first-fragment break. A false
return makes the walker return `None`; `parse_ipv6` propagates `None`
through the existing fail-closed parse path, so no terminal kernel-PASS
arm runs.

`parse_ipv6` owns a BPF-only `HostScreenWalkObserver` in `lib.rs`; on the
callback it performs a checked `USERSPACE_SCREEN_SCRATCH.get_ptr_mut(0)`
and ORs `multiple_ipv6_non_atomic`, returning false if the map lookup
fails. Host callers pass `NoopExtWalkObserver`; the host witness uses a
recording observer. Migrate `tests_shim_ext_parity.rs`,
`tests_10661_atomic_chain.rs`, and `tests_shim_gre_inner_14954.rs` to the
new argument. Do not add any `ExtWalk` field.

Wiring follows the `userspace_land_screen` precedent exactly:
shim map decl (after `lib.rs:519`), `pkg/dataplane/userspace/maps.go`
name const (after `:56`), `pkg/dataplane/loader_userspace_shim.go` pin
lists, `pkg/dataplane/retirement_boundary_canary_test.go` allowlist row,
`userspace-dp/src/afxdp/bpf_map/pin.rs` row. The WIP did this wiring
correctly — reuse its diff (§3).

### 5.3 What the parsers write (no struct widening)

Initialize the per-CPU scratch word to zero for EACH packet before optional
sightings. Check every map operation; any failed parser write/finalization
returns `None` through the existing parse-fail drop. The gate read failure
is separately fail-closed. Never reuse stale contents or claim an
all-ones sentinel when `get_ptr_mut` returned no writable slot.

- **IPv4** (`parse_ipv4`, `lib.rs:2263-2386`): pack geometry from the
  existing locals (`frag_field :2316`, first/non-first `:2317-2318`,
  `total_len :2292`, `ihl :2277`, wire protocol `iph[9] :2322/:2375`).
  Scan the already-read IHL slice (`read_bytes(..., ihl) :2281`) with a
  bounded TLV walker in `ipv4_len_gate.rs`. It must produce both
  `saw_source_route` (LSRR 131 / SSRR 137) and `malformed_options`:
  missing length byte, length `< 2`, overrun, or LSRR/SSRR length `< 3`.
  If any option is malformed, suppress the ordinary source-route sighting:
  worker extraction returns `Err(TruncatedIpv4Header)` even when a valid
  LSRR/SSRR preceded a malformed TLV, so no ordinary screen verdict runs.
  Preserve the distinct malformed scratch bit; screen-state row presence
  controls its disposition as specified in §5.5.
- **TCP, in BOTH parser paths:** after `first_fragment_l4` or `parse_l4`
  has supplied validated protocol, flags, and destination port, compute the
  independent SYN+FIN, no-flag, FIN-without-ACK, WinNuke, and known
  SYN-first-fragment trip bits. The IPv4 first-fragment branch is at
  `lib.rs:2336-2347` (`first_fragment_l4` implementation `:2809-2835`);
  the normal branch uses `parse_l4`. The common safe convergence point is
  after `lib.rs:2355`, before `ParsedPacket` construction at `:2362`.
  Use the actual wire TCP protocol (`iph[9]`), not placeholder tuple
  fields; non-first fragments, sentinel fallback, and capture-unknown
  flags must produce no ordinary TCP trips. Do not add packet reads for
  already available locals.
- **IPv4 tiny flags:** preserve two distinct facts. The worker's tiny
  extraction error uses the IP-declared end,
  `l3_offset + total_len < tcp_offset + 14`
  (`screen/extract.rs:419-428`); set `tiny_declared_unknown` from that
  condition, independently of capture length. `first_fragment_l4` uses
  capture-clamped `l4_end = min(declared_end, data_end)`
  (`lib.rs:2296,2353-2355`) for safe reads; set
  `tcp_flags_capture_unknown` when the flags byte was not actually read.
  Suppress all ordinary TCP trips when that capture-unknown bit is set,
  rather than treating placeholder zero flags as a real no-flag packet.
  Thus short capture with a lying-long `total_len` is not the worker tiny
  error, but remains capture-unknown. In C22 the worker returns `Ok` with
  caller-stamped flags 0 (`extract.rs:423-442`): `{no_flag}` alone drops
  `tcp-no-flag`, while `{syn_frag}` alone passes. The shim safely
  suppresses ordinary flag trips and passes both profiles; this bounded
  divergence is explicit, not a parity claim. Capture bounds still guard
  every actual byte read.
- **IPv6** (`parse_ipv6`, `lib.rs:2388-2523`; `walk_ipv6_ext_headers`,
  `ipv6_ext_walk.rs:273-368`): initialize packed scratch before the walk.
  The core walker keeps a local non-atomic-sighting flag distinct from
  `fragment_seen` (atomic headers do not count), and calls the
  `ExtWalkObserver` from §5.2 exactly once on the second readable
  non-atomic Fragment header, before the non-first break. The
  `HostScreenWalkObserver` owned by `lib.rs` performs the checked
  per-CPU-scratch write; on failure the callback returns false, the walker
  returns `None`, and `parse_ipv6` fails closed. Do not widen `ExtWalk`.
- **No IPv6 tiny-flags finalization:** current `parse_ipv6` / `parse_l4`
  rejects declared-short or captured-short TCP headers before the host
  gate (`lib.rs:2467-2482`). It returns `None` before constructing
  `ParsedPacket`; even if `parse_l4` can read Ethernet padding, the
  declared-end check rejects that parse. Keep the existing `L3 PARSE_FAIL`;
  do not synthesize a v6 `host_screen_drop` bit. The worker's
  `ip_payload_len == 0` / `usize::MAX` tiny-check sentinel remains in the
  host-extractor oracle (`extract.rs:421-435`), but C18/C19 only pin the
  shim's earlier parse failure, not v6 screen parity.

All parser changes remain scratch-only. `ParsedPacket` and `ExtWalk`
definitions stay byte-for-byte unchanged; `MAX_EXT_HDRS`, walk
advance/break behavior, and the `parse_l4` signature stay unchanged.

### 5.4 Packed word and profile-mask layouts

The parser-to-gate scratch word remains one `u64`:

```text
bits  0     is_fragment
      1     is_first_fragment
      2     more (IPv4 MF / IPv6 M)
      3     tiny_declared_unknown (IPv4; IP-declared-end rule)
      4     saw_source_route (v4 LSRR/SSRR or v6 RH0/RH1)
      5     is_ipv6
      6     wire_is_icmp (wire protocol ∈ {1, 58})
      7     tcp_trip_syn_frag
      8     tcp_trip_syn_fin
      9     tcp_trip_no_flag
     10     tcp_trip_fin_no_ack
     11     tcp_trip_winnuke
     12     malformed_ipv4_options
     13     multiple_ipv6_non_atomic
     14     tcp_flags_capture_unknown (actual capture lacks flags byte)
     15     reserved
 16-31     frag_offset_bytes (v4: (raw & 0x1FFF)<<3; v6: raw & 0xFFF8)
 32-47     frag_data_len (v4: total_len − ihl*4; v6: payload_len − frag_data_off)
 48-63     pod_extent (v4: total_len; v6: frag_data_len)
```

Every trip bit is a packet predicate computed independently of profile
mask settings; the gate intersects the trip facts with the zone's enabled
checks. `tcp_trip_winnuke` includes URG and destination port 139 at the
common post-L4 point. Saturating the 16-bit geometry fields at 0xFFFF
preserves the POD comparison: any true `offset + extent > 65535` remains
greater after saturation.

The zone row is a **`u16`**, separate from the scratch word:

```text
bit 0 ping-death       bit 5 SYN+FIN
bit 1 teardrop         bit 6 no-flag
bit 2 ICMP-fragment    bit 7 FIN-without-ACK
bit 3 SYN-frag         bit 8 WinNuke
bit 4 source-route     bit 9 alarm-without-drop
bits 10-15 reserved
```

No shared TCP-family bit is permitted. Rust `HOST_SCREEN_*` constants
and Go builder bits must match exactly (§6.2, §8c).

### 5.5 The gate

```rust
#[inline(never)]
fn host_screen_gate(pkt: &ParsedPacket, ingress_ifindex: u32) -> bool // true ⇒ drop with HOST_SCREEN_DROP
```

Add the one outlined gate in `userspace-xdp/src/lib.rs`, beside
`land_gate`, using the salvageable pure verdict in
`userspace-xdp/src/host_screen.rs` (`host_malformed_verdict` and
`host_malformed_disposition`) over the scratch-laundered word:

1. Read `USERSPACE_SCREEN_SCRATCH[0]`. Read failure is fail-closed Drop;
   never treat a missing word as clean or reuse stale data. A packet with
   no fragment/source-route/TCP trip and no parse-error bit returns Pass
   after this one opaque map read.
2. For `tiny_declared_unknown && is_first_fragment`,
   `malformed_ipv4_options`, or `multiple_ipv6_non_atomic`, resolve the
   raw ingress zone and inspect the screen row. Row present means
   immediate `host_screen_drop`, independent of ordinary mask and alarm;
   absent row or unresolved zone means no special parse-error verdict.
   `tcp_flags_capture_unknown` is not this worker parse error: it suppresses
   ordinary TCP trip creation only. The v6 tiny case never reaches this
   gate; it remains `L3 PARSE_FAIL` (§4.3/C18).
3. Build independent ordinary trip bits: POD, teardrop, ICMP-fragment,
   known-flags SYN-frag, source-route, SYN+FIN, no-flag, FIN-without-ACK,
   and WinNuke. If none tripped, return Pass.
4. Resolve zones exactly as `land_gate` does:
   `UserspaceWgIngressZoneKey{ifindex, vlan_id or u16::MAX}` →
   `USERSPACE_WG_INGRESS_ZONES` → StableZoneID (`lib.rs:2610-2624`).
   Zone 0 is unresolved; sharing this resolver is K3 (§9).
5. Read `userspace_host_screen: HashMap<u32, u16>` (StableZoneID →
   independent profile mask). A missing row under a resolved zone means
   no screen state/checks; the builder emits zero-mask rows for zones
   whose worker screen state exists only for a flood check (§6.2).
6. For ordinary trips, unresolved zone means Drop (LAND-style
   fail-closed policy, intentionally stricter than worker no-state Pass).
   For a resolved zone, `trips & zone_mask & ALL_CHECKS == 0` means Pass;
   otherwise alarm bit 9 counts `host_screen_alarm` and passes, while a
   non-alarm row drops. Special parse-error drops precede alarm handling.
   Increment the alarm counter inside this gate, like `land_alarm`
   (`lib.rs:2632`); do not double-count the later pass counter.

**Placement rule: invoke only after dispatch selects a terminal
kernel-pass action.** Putting the helper after either LAND site
(`lib.rs:791` or `:1721`) is wrong: those sites precede redirect
selection and would drop transit packets before XSK (`:1141-1148`,
redirect at `:1269`). Leave both LAND sites unchanged. The single
`host_screen_gate(&parsed, ingress_ifindex)` call is added at all 11
terminal pass arms in §1, after each existing destination/control
predicate but before its pass counter and `pass_local_control` /
`cpumap_or_pass` return: WG steer, early-filter multicast/broadcast,
session-hit `PASS_TO_KERNEL`, NAT-external NDP, proxy-NDP,
ICMP-to-interface-NAT local, session-miss local, interface-NAT tunnel,
GRE-inner pass, binding-not-ready local/control, and ctrl-disabled
`PassLocalControl`. A drop uses
`drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_HOST_SCREEN_DROP)`.
Do not put it in a generic helper used by non-IP or non-adjudicated
traffic.

The gate consumes the branch's already-selected kernel-pass eligibility;
transit session-miss/redirect falls through and never calls it.
`kernel_pass.rs::DEGRADED_TWIN` needs no new rows: no pass arm is
created/reclassified, only a malformed packet is removed immediately
before the existing pass.

**GRE-inner caveat:** the gate sees only the outer packet. A native-GRE
packet with an inner `PASS_TO_KERNEL` hit (`lib.rs:1155-1175`) can carry
an inner packet the worker would screen after decapsulation; the shim
does not inspect that inner packet here. This remains S5 (§10).

**Candidate Q2 — gate above binding-ready: NO (decided).** Do not add a
global gate above `binding_ready_slot` (`lib.rs:854`): transit has not yet
been classified and could be screened before redirect. Call only inside
the `is_degraded_local_or_control == true` branch, before
`pass_local_control` (`lib.rs:891-894`). The false/transit branch remains
unchanged. The ctrl-disabled twin likewise gates only after
`degraded_ctrl_disabled_action` selects `PassLocalControl`
(`lib.rs:1671,1726-1728`). C13 and C14 pin those selected local/control
paths; their transit/non-adjudicated controls pin the exclusion.

## 6. Control plane + counter ABI

### 6.1 New map `userspace_host_screen`

`HashMap<u32, u16>` (StableZoneID → independent screen mask),
`with_max_entries(65536)`, declared in `userspace-xdp/src/lib.rs` after
`USERSPACE_LAND_SCREEN` (`:519`). Wire it through
`pkg/dataplane/userspace/maps.go` (`mapNameUserspaceHostScreen`),
`pkg/dataplane/loader_userspace_shim.go` (`userspaceHostScreenMapName`
and pin lists), `pkg/dataplane/retirement_boundary_canary_test.go`, and
`userspace-dp/src/afxdp/bpf_map/pin.rs`, following the landed
`userspace_land_screen` precedent.

### 6.2 Go builder (salvage WIP `host_screen.go`)

`pkg/dataplane/userspace/host_screen.go` builds `u16` mask values with
bits 0-8 for the nine independent checks and bit 9 for alarm. Pack each
`ScreenProfileSnapshot` boolean independently; never OR no-flag,
FIN-without-ACK, and WinNuke into a shared bit. Missing-profile zones
receive conservative checks—POD, teardrop, SYN-frag, source-route,
SYN+FIN, no-flag, FIN-without-ACK, and WinNuke, but not ICMP-fragment—
matching `ScreenProfile::conservative_default()`
(`screen/packet.rs:229-242`; `land` remains its separate existing gate).
Copy `ScreenMissingProfileRef.AlarmWithoutDrop` to bit 9 even for a
defined `BadNumericUnresolved` reference; a truly undefined profile has
no modifier and remains false (`screens.go:492-503`). Inert-profile
zones likewise copy `AlarmWithoutDrop`. The worker consults both ref
lists (`screen/mod.rs:571-585`).

If a StableZoneID is claimed by conflicting profiles, poison it to
all-checks-drop. Publish an explicit zero-check mask row when worker
screen state exists only for a flood check; publish no row for a genuine
no-screen zone. Row presence therefore carries `zone_has_screen_state`
(§4.3).

`syncUserspaceHostScreenMapLocked` follows `land_screen.go:123-176`,
called from the same reconcile point as
`syncUserspaceLandScreenLocked` (`maps_sync.go:579`, inside
`syncUserspaceClassifierMapsLocked` `:542`). Keep the existing
`checkHostScreenCapacity` limit at 65536; no emit-gate change.

### 6.3 Counter ABI — append-only, every mirror updated

Do not renumber fallback reasons 0-20; `USERSPACE_FALLBACK_REASON_MAX`
is currently 21 (`lib.rs:36-65`, `maps_sync.go:1010-1034`). Append:

```rust
const USERSPACE_FALLBACK_REASON_HOST_SCREEN_DROP: u32 = 21;
const USERSPACE_FALLBACK_REASON_HOST_SCREEN_ALARM: u32 = 22;
const USERSPACE_FALLBACK_REASON_MAX: u32 = 23;
```

Exactly three production degraded-reason tables require updating: shim
constants, Go `degradedPathReasonNames`, and Rust
`DEGRADED_PATH_REASON_NAMES`. Update them in one change:

- `userspace-xdp/src/lib.rs`: append constants 21/22 and size the
  reason-only `USERSPACE_FALLBACK_STATS` `PerCpuArray` to 23. Regenerate
  the BPF object; an old 21-entry object cannot emit either new index.
- `pkg/dataplane/userspace/maps_sync.go`: `degradedPathReasonNames`
  becomes `[23]string`, with indices 21/22 named
  `host_screen_drop`/`host_screen_alarm`; keep the reader bounded by
  `len(...)`.
- `userspace-dp/src/afxdp/bpf_map/pin.rs`:
  `DEGRADED_PATH_REASON_NAMES` appends the same names at 21/22.
- Agreement/reachability tests: the Go shim agreement test
  (`degraded_reason_agreement_8258_test.go:93-143`) and Rust agreement
  test (`bpf_map_tests.rs:411-472`) self-enroll and must see both names.
  The Go reachability test
  `TestEveryShimFallbackReasonIsActuallyReachable_8258` (`:173ff`) must
  find both constants referenced by live gate/drop code.
- Hard-coded pins: update the Rust reason-length/indices test
  (`bpf_map_tests.rs:394-408`) to length 23 and assert both names at 21/22.
  Update `maps_sync_cap_test.go:21-58`'s required-name list and literal to
  23; its current length `if` has an empty body and is not a guard by
  itself.
- Dynamic degraded-status consumers resolve by name; do not hard-code
  21/22 (`degraded_status_13294_test.go:18`,
  `xdp_shim_decouple_test.go:692-743`). Branch-arm name tables are a
  separate ABI and remain untouched.

The shim counts one aggregate `host_screen_drop` per packet or one
`host_screen_alarm` for an audited pass. It does NOT identify check reason
or ingress zone and emits no worker-equivalent screen-drop event. Worker
drop/alarm events carry tuple, zone, and screen reason
(`userspace-dp/src/afxdp/event_emit.rs:313-407,621-643`); the event/drop
paths are in
`userspace-dp/src/afxdp/poll_stages.rs:1360-1374,1450-1504`. That gap is
S4, not something the aggregate counter “localises.”

## 7. Verifier budget — proof strategy

### 7.1 Hard ceiling

Measured master baseline: **779,213 processed instructions** (cap
1,000,000; 22.08% headroom; 15% floor), recorded in
`pkg/dataplane/userspace_xdp_gate_verdict.json` at
`6c27f54cf2`. Hard landing ceiling: **≤850,000 processed instructions**
(at least 15% headroom, floor PASS). `XPF_SHIM_ALLOW_LOW_HEADROOM`
(`cmd/shimverify/main.go:232ff`) MUST NOT be consumed; a verifier reject
or `override_consumed: true` is K1 FAIL regardless of the reported count.

The following deltas are **[INFERENCE] estimates, not evidence**; only the
complete-object regen is a proof:

| Change | Estimated Δ insns | Basis |
|---|---:|---|
| IPv4/IPv6 scratch init and pack | +2,000–6,000 | One checked per-CPU word write per parser; locals already validated |
| IPv4 LSRR/SSRR + malformed-TLV scan | +3,000–10,000 | Bounded ≤40-byte walk over held header bytes; no new packet-pointer math |
| IPv6 fragment/Routing sightings + second non-atomic bit | [INFERENCE] +2,000–8,000 | Includes the generic, statically dispatched observer and checked scratch-map lookup/store on the second non-atomic header; this range is not a measured callback cost. |
| Independent post-L4 TCP trips, including `first_fragment_l4` path | +2,000–6,000 | Scalar comparisons/bit packs at parser convergence; no profile-state fork |
| Outlined gate, zone/mask lookups, dispositions | +1,500–4,000 | One outlined body shared by 11 terminal pass arms |
| Eleven gate call sites and drop returns | +1,100–3,300 | BPF-to-BPF calls; transit path does not call the gate |
| Appended counters | ~0 | Existing outlined counter helpers; indices only |
| **Projected total** | **+11,600–37,300** | **~790,800–816,600; at least ~33,400 below the 850,000 ceiling** |

No standalone instruction count is asserted for the observer callback.
Its static dispatch and the checked per-CPU map operation on the second
non-atomic path are included in the complete-object processed-insn
measurement; no unmeasured callback estimate substitutes for K1. The
estimate excludes no in-scope parser correction and does not substitute
for measurement. There is no v6 tiny-flags finalization cost: the shim
rejects that shape before the host gate (§4.3/C18).

### 7.2 Measurement protocol

1. Baseline evidence is the recorded 779,213-insn
   `pkg/dataplane/userspace_xdp_gate_verdict.json` from the source base;
   do not overwrite it as the comparison before recording its hash.
2. Implement all in-scope BPF changes first, including B1-B5: independent
   TCP masks/trips, IPv4 malformed-options verdict, IPv6 duplicate
   non-atomic sighting via the generic observer and checked scratch sink,
   the declared-length capture distinction, the outlined gate, and all 11
   terminal sites. Then run `make generate-userspace-xdp` on the
   **complete object**. No partial pre-B1–B5 object is a K1 result.
3. Record processed-insn count, headroom, `override_consumed` (must be
   false), and matching source/object hashes in
   `pkg/dataplane/userspace_xdp_gate_verdict.json` and
   `userspace_xdp_manifest.json`.
4. K1 passes only at ≤850,000 with floor PASS and no override. Any reject,
   >850,000, or consumed override kills this shape; the Q1 TCP-residue
   reassignment rule is explicit in §9.

### 7.3 Structural proofs (diff-level, no measurement)

- The `ParsedPacket` definition (`lib.rs:2148-2195`) and `ExtWalk`
  definition (`ipv6_ext_walk.rs:191-226`) must have **empty diffs** from
  the source base. The WIP's +7 / +4 widening is the measured reject
  cause (§3).
- `MAX_EXT_HDRS`, walk advance/break statements, and `parse_l4` signature
  are unchanged.
- `USERSPACE_BRANCH_ARM_*` remains unchanged.

## 8. RED/GREEN cells and execution lane

**(a) Host-twin predicate/oracle cells.** Reuse
`userspace-dp/src/afxdp/frame/tests_shim_host_screen_16009.rs` and the
`worker_malformed_mask_for_test` oracle from `stateless.rs` (test-only).
Use the packed word, not a widened packet struct. Cover v4/v6 geometry,
source-route, atomic-fragment governing behavior, the v4 special
screen-state errors, and every ordinary mask/alarm/unresolved-zone
disposition, with C18/C19 and C22 explicitly marked as divergences below.

- C20 tests malformed IPv4 TLV both before and after a valid LSRR, with
  source-route OFF; malformed extraction error dominates either order;
- C21's exact pair is `[M=1, off=0][M=1, off=8]`, separate from C17.
  In `tests_shim_ext_parity.rs`, a recording observer must see exactly one
  callback before the second header's non-first break; atomic-then-
  non-atomic sees none. A failing observer must make the walk return
  `None`. The BPF C21 below proves the parser-to-scratch-to-gate path.
- C22's short capture with lying-long IPv4 total length, including the
  worker no-flag-only vs syn-frag-only oracle and shim's safe suppression;
  this is a disclosed divergence, never parity coverage.
- C23's **both IPv4 and IPv6: 16 profiles × 4 isolated Q1 packets per
  family (128 outcomes)**; each outcome must match the worker oracle and
  only its own enabled check. Also test known SYN first-fragment with
  syn-frag-only and negative controls: whole SYN, first-fragment ACK,
  non-first payload that resembles SYN, and URG|ACK to port 443 (not
  WinNuke);
- C18/C19 as deliberate non-parity cells: worker v6 tiny/zero-length
  behavior is tested, but the shim rejects those packets before the gate.

Also retain POD boundary, teardrop zero/short/MF-nonmultiple/legal-last,
ICMP/ICMPv6 fragments, IPv4 tiny declared flags, LSRR/SSRR, RH0/RH1/RH2
(RH2 passes), SYN-frag, SYN+FIN/no-flag/FIN-without-ACK/WinNuke,
IPv6 atomic fragment, clean packets, and no-screen/alarm/unresolved
controls. Fail-on-revert: removing any packed verdict or mask distinction
reds its cell.

**(b) BPF cells.** Reuse `host_screen_drop_16009_test.go`. Its
`BPF_PROG_TEST_RUN` helpers are defined in
`pkg/dataplane/userspace/xdp_shim_decouple_test.go:513,661,674,707`;
`land_drop_13953_test.go` is a consumer, not the definition site.
Use `loadUserspaceXDPTestCollection`, `runUserspaceXDPTestPacket`, and
the degraded-path stat assertions. A selected host-bound malformed packet
must return XDP_DROP and increment `host_screen_drop`; a transit twin must
retain the existing redirect and leave the shim host-screen counter
unchanged. BPF_PROG_TEST_RUN proves only the shim result—it MUST NOT be
used to claim a worker counter/event result.

Unless a cell overrides it: ctrl is enabled, binding ready, ingress
adjudicated, raw `(ifindex, VLAN)` resolves to a host-screen row with the
relevant bit set and alarm off, LAND passes, and local/interface-NAT/
proxy-NDP/session maps are mutually exclusive. For redirect controls an
empty XSK map may surface as XDP_DROP; assert `redirect_err`, absence of
`host_screen_drop`, and the expected degraded reason rather than relying
on the raw action alone.

| Cell | Selected packet / branch | Expected | Paired control / honest boundary |
|---|---|---|---|
| C1 | IPv4 MF=1, offset 0, four-byte payload | XDP_DROP, `host_screen_drop`+1 | **GEOMETRY ONLY**: worker `check_teardrop` tests payload geometry (`stateless.rs:178-183,222-242`); it is not overlap detection. Transit twin redirects with no shim host-screen count. |
| C2 | IPv4 valid LSRR, source-route enabled | DROP + counter | Same packet with source-route disabled: PASS, no counter. |
| C3 | IPv6 ICMPv6 non-first fragment, ICMP-fragment enabled | DROP + counter | IPv6 UDP non-first fragment: this check does not trip. |
| C4 | IPv4 POD: offset `0x1FFF`, extent makes sum > 65535 | DROP + counter | Sum exactly 65535 passes (`>` not `>=`). |
| C5 | IPv4 SYN first fragment, SYN-frag enabled | DROP + counter | Whole-packet SYN passes this check. |
| C6 | IPv4 first fragment, declared L4 length 8 bytes, flags unavailable | Row present: DROP even with syn-frag off or alarm on, including a `BadNumericUnresolved` alarm-on row | Row absent or unresolved: no tiny-only drop; synfrag-on alone is not the trigger (§4.3). |
| C7 | IPv6 RH0, source-route enabled | DROP + counter | RH2 passes. |
| C8 | IPv4 legal last fragment with 1–7 payload bytes | PASS | #9426 false-positive guard. |
| C9 | Alarm profile with C1 geometry trip | PASS, `host_screen_alarm`+1, no drop count | Alarm is only for ordinary mask trips. |
| C10 | C1 with unresolved raw zone | DROP by the explicit unresolved-geometry fail-closed policy | Tiny/error-only parse verdict with unresolved zone is not host-screen-dropped. |
| C11 | LAND packet, LAND on, malformed checks off | `land_drop`, not `host_screen_drop` | LAND stays at `lib.rs:791` before dispatch. |
| C12 | Clean TCP ACK to local | PASS; no screen counters | Common-path cost only. |
| C13 | Binding-not-ready, `is_degraded_local_or_control == true`, C1 | DROP at the selected local/control fallback gate | False/transit branch is unchanged; no global pre-binding gate (Q2). |
| C14 | Ctrl-disabled, adjudicated ifindex, C1 | DROP in selected `PassLocalControl` arm | Non-adjudicated ctrl-disabled input keeps existing drop and no host-screen count. |
| C15 | C1 geometry packet that also hits session `PASS_TO_KERNEL` | Exactly one `host_screen_drop`; worker counters are **not asserted** because worker never sees this packet | Transit twin: BPF cell asserts redirect and no shim host-screen count only. A separate worker-stage assertion below covers packets actually delivered to the worker. |
| C16 | IPv6 atomic Fragment header (offset 0, M=0) | PASS; it is not a fragment | All fragment checks enabled. |
| C17 | IPv6 `[atomic Fragment][non-atomic Fragment offset>0]` ICMPv6 | Drop under ICMP-fragment check because the later non-atomic header governs | This cell tests governing-header selection only; it makes **no duplicate-header assertion**. C16 is the single-atomic control. |
| C18 | IPv6 tiny first fragment, M=1, declared TCP L4 8 bytes | Existing `L3 PARSE_FAIL`; no `host_screen_drop` | Explicitly no v6 tiny host-screen/parity claim; worker extractor behavior is only the host-twin control. |
| C19 | IPv6 Fragment, wire Payload Length=0, captured TCP ACK bytes | Existing `L3 PARSE_FAIL`; no `host_screen_drop` | Worker treats zero as unbounded for its tiny check; this does not claim the BPF packet passes or parity. |
| C20 | IPv4 options with valid LSRR then malformed `[0x44,0x01]` (also test malformed-before-LSRR); source-route OFF, `BadNumericUnresolved` row with alarm on | `TruncatedIpv4Header` equivalent: DROP + `host_screen_drop` | Malformed extraction error drops on row presence regardless of alarm and precedes any route sighting; absent row/unresolved zone has no special parse-error drop. |
| C21 | IPv6 Fragment sequence `[M=1, off=0][M=1, off=8]`, `BadNumericUnresolved` row with alarm on, ordinary masks off | DROP + `host_screen_drop` from the duplicate-header bit | Separate from C17. Host recording observer sees one event before the second-header break; absent row with ordinary checks off has no special parse-error drop. |
| C22 | IPv4 IHL=5, MF=1/offset=0, `total_len=60`, capture ends at L4+8 (ports present, flags absent); run separate no-flag-only and syn-frag-only masks, other trips off; row at session-miss local | Shim passes both with no `host_screen_drop`; `tcp_flags_capture_unknown=1`, no ordinary trip, `tiny_declared_unknown=0` | Worker returns `Ok` with caller-stamped flags 0: no-flag-only drops `tcp-no-flag`, syn-frag-only passes. Shim safely suppresses both; disclosed divergence, never parity coverage. |
| C23 | Four isolated TCP shapes for each of IPv4 and IPv6 across all 16 masks | For each family/shape, DROP iff its own bit is enabled; otherwise PASS; all 128 outcomes match worker oracle | No shared TCP-family bit. Shapes: SYN\|FIN\|ACK; flags 0; FIN without ACK; URG\|ACK to port 139. Separately pin selective known SYN-first-fragment behavior and whole-SYN / first-fragment-ACK / non-first-SYN / URG\|ACK to port 443 negative controls. |
| C24 | WG handshake/cookie UDP type 1–3 to a steered destination port, exact-local or WG-owner-admitted listener, IPv4 LSRR, and no live session row | DROP at WG terminal pass; host counter +1 | Same shape with WG admission false and global transit destination redirects, no shim host-screen count. |
| C25 | Early-filter suite: IPv4 limited broadcast, IPv4 multicast, IPv6 multicast, each malformed by its family-appropriate route/fragment trigger | Selected early pass is screened and drops; disclosed **policy extension**, not worker parity | Non-owned IPv4/IPv6 link-local unicast and directed IPv4 broadcast are redirect/non-selected controls. Do not use exact-local link-local here: a later arm may screen it and the aggregate counter cannot identify the arm. |
| C26 | TCP SYN+FIN matching an installed session-hit `PASS_TO_KERNEL` row, `syn_fin` bit enabled | DROP at the session-hit terminal arm | Matching REDIRECT row or transit destination redirects; non-first fragments cannot hit an ordinary session row. Distinct from C15's double-count guard. |
| C27 | IPv6 NS/NA type 135/136, hop-limit 255, complete ICMPv6 header in first fragment (M=1, offset 0), unicast destination seeded only in interface-NAT map; ICMP-fragment enabled | DROP at NAT-external NDP terminal pass | Hop-limit 254 to same destination fails this predicate and redirects; map target is not also in proxy-NDP/local maps. |
| C28 | Same complete first-fragment NS/NA predicates as C27, but unicast destination seeded only in proxy-NDP map | DROP at proxy-NDP terminal pass | Hop-limit 254 control redirects; NAT-external and proxy-NDP target maps remain disjoint because NAT NDP is checked first. |
| C29 | IPv4 ICMP echo request/reply (type 8/0) with LSRR to interface-NAT-only local destination, source-route enabled | DROP at ICMP-to-interface-NAT local pass | Same packet to global transit redirects; no shim host-screen count. |
| C30 | C1 geometry packet or LSRR on session miss to an exact local destination | DROP at session-miss local pass | Also pin `169.254.x.x`/`fe80::x`: seeded exact-local rows drop; same malformed non-owned link-local destinations redirect. |
| C31 | Whole (non-fragmented) IPv4 LSRR + ESP (protocol 50) to configured interface-NAT destination | DROP at `interface_nat_tunnel_passes_to_kernel` terminal pass | Same whole ESP packet to global transit redirects; no shim host-screen count. |
| C32 | Native GRE enabled; non-fragmented outer IPv4 LSRR GRE to exact-local outer destination; clean inner TCP/UDP tuple selects `PASS_TO_KERNEL` | DROP at GRE-inner terminal pass on outer LSRR | Outer transit destination or inner REDIRECT/miss follows helper redirect. Outer fragments cannot select this arm; inner-screen parity remains S5. |
| C33 | Binding-not-ready; true local/control fallback predicate and malformed C1 | `XDP_DROP`; `host_screen_drop` + `transit_drop`, no binding fallback reason | Transit-false control is also `XDP_DROP`, but records binding fallback reason + `transit_drop` and no `host_screen_drop`; branch stat may appear in both. |
| C34 | Ctrl-disabled, adjudicated ifindex, malformed C1 to exact-local destination | DROP at ctrl-disabled `PassLocalControl` terminal pass | Transit destination records `ctrl_disabled`/`transit_drop`, no host-screen count; non-adjudicated ingress keeps pre-parse ctrl-disabled drop. Scratch is initialized on the ctrl-disabled re-parse too. |
| C35 | `BadNumericUnresolved` profile row carries conservative checks and `AlarmWithoutDrop`; SYN+FIN trip with alarm set | PASS; `host_screen_alarm`+1 and no drop count | Same ordinary trip with alarm false drops. Go builder must preserve the alarm bit. Parse/extractor errors C6/C20/C21 still drop on row presence even when this alarm bit is set. |

C24-C34 are the required 11-arm matrix: every terminal pass site gets
one selected malformed-pass cell and a transit/non-selected control.
The source anchors for all sites are in §1. C25's multicast behavior is
deliberately labeled as a policy extension because the worker does not
screen multicast; no link-local-unicast early-pass claim is allowed.
C35 independently tests `BadNumericUnresolved` alarm preservation.

**Worker-side assertion, separate from BPF_PROG_TEST_RUN:** feed an
actually worker-bound malformed twin through the `userspace-dp` stage-10
`txn_run_descriptor_with_screen_state` path. Assert `batch.screen_drops`
and the per-reason counter where the harness exposes it; assert a worker
event only if the test observes the event stream. This is a worker-stage
assertion, not an inference from the shim BPF test. A packet selected by
session-hit `PASS_TO_KERNEL` does not invoke the worker; that architectural
fact is not a BPF_PROG_TEST_RUN measurement.

**(c) Go cells:** table-test `buildUserspaceHostScreenEntries` for
full/audit/off/flood-only (present zero-mask row)/missing/inert/
`BadNumericUnresolved` with `AlarmWithoutDrop` both false and true/
no-screen/collision-poison/nil snapshot. Assert the true modifier is
preserved for the unresolved defined profile and inert reference, while
truly undefined refs remain false. Compare all ten `HOST_SCREEN_*` u16
constants against the Go mask builder; verify independent Q1 booleans for
all 16 masks and the 65536-entry capacity check.

**(d) Verifier cell:** complete-object regen per §7.2. RED = reject,
>850,000, or `override_consumed: true`; GREEN = ≤850,000, floor PASS,
and no override.

**(e) Execution lane and smoke:** run all BPF_PROG_TEST_RUN cells in the
**Class-R VM execution lane** (privileged VM with the supported kernel/
loader), not on a workstation. In that same Class-R VM, run an explicit
dual-stack smoke on the loaded object: IPv4 and IPv6 clean host pass,
selected malformed host-bound drop, and transit redirect control. The
transit worker-side assertion is separate as described above.

**(f) No-regression:** retain
`land_drop_13953_test.go`, `xdp_branch_stats_16241_test.go`,
`degraded_reason_agreement_8258_test.go` (must be green after all mirrors
land), `userspace_xdp_manifest_test.go`, and
`verify_userspace_shim_headroom_test.go`. Worker production screen code
is not changed by this plan; only the test oracle / worker-stage assertion
is added.

## 9. Risks and kill criteria (K1–K5)

- **K1 (hard landing gate):** after all B1-B5 parser/mask corrections and
  all 11 terminal calls are in the complete object, the verifier must
  report ≤850,000 processed insns, floor PASS, and no override. Any
  reject, >850,000, or consumed `XPF_SHIM_ALLOW_LOW_HEADROOM` kills this
  shape. Do not gate-override or revive the struct-widened WIP.
  **Never silently drop TCP coverage to get under budget.** If a reviewed
  re-plan removes Q1's four extra checks (SYN+FIN/no-flag/FIN-without-
  ACK/WinNuke), file conditional successor S7 with the exact title in
  §10 and transfer C23's 16-mask × 4-packet matrix for both IP families
  (128 outcomes), including mask bits and worker oracle, there. #16009
  cannot claim those checks until S7 passes. If the remaining core still
  fails, return to architecture step 0 (including redirect-to-worker); do
  not claim completion by narrowing again.
  A result in 830,000-850,000 also requires a written headroom-recovery
  follow-up.
- **K2 (scratch completeness):** every parsed packet reaching a terminal
  gate must have a current word. Initialize before optional writes,
  including IPv4 after the validated IHL slice and IPv6 before
  `:2410`; check every scratch read/write. Keep
  `tiny_declared_unknown` (worker row-gated error) distinct from
  `tcp_flags_capture_unknown` (suppress ordinary trips when flags were
  not read); neither fact may be inferred from the other. All ordinary
  TCP trip bits must be zero for capture-unknown flags. Any write/
  finalization failure returns `None` through the existing fail-closed
  parse path; gate-read failure drops. IPv6 duplicate detection is
  written in-walk; there is no v6 tiny-flags finalization. Any `Some`
  path with stale/incomplete scratch is a bypass and KILL.
- **K3 (zone-key skew):** use the exact `(ifindex,
  vlan-or-u16::MAX)` resolver as `land_gate` (`lib.rs:2610-2624`). A
  second key convention can make zones unresolved (availability loss) or
  silently pass. If sharing the resolver adds a map walk that blows K1,
  stop and re-plan around a shared outlined resolver.
- **K4 (transit and all pass arms):** call the gate only after the exact
  kernel-pass action is selected and before its pass counter/return. A
  common gate after LAND can drop transit before redirect selection.
  C24-C34 provide one selected malformed cell plus a non-selected/transit
  control for every arm; C1/C13-C15 add geometry, degraded, ctrl-disabled,
  and session-hit checks. BPF_PROG_TEST_RUN asserts shim outcomes only;
  the separate worker-stage test asserts actual worker batch drop count
  (and per-reason counter where the harness exposes it); BPF cells make
  no worker-counter or event-emission claim. Any omitted pass arm or
  pre-decision gate blocks the plan.
- **K5 (scope boundary):** no cross-packet fragment ranges, scan/sweep
  trackers, or SYN-cookie minting/validation may enter this change.
  The second-readable-non-atomic Fragment check is a bounded parse-shape
  error, not cross-packet overlap state. Those stateful semantics remain
  named successors (§10).

Other stated risks: early-filter multicast/limited-broadcast screening
is a policy extension because the worker does not screen multicast;
ordinary geometry on unresolved zone is deliberately fail-closed;
IPv6 tiny packets may hit the existing `L3 PARSE_FAIL` before the
host-screen gate; GRE-inner screening is outer-only (S5); claimed-zone
terminal-pass parity is explicitly out of scope (S6); and the aggregate
counter has no zone/reason attribution (S4). A cached session's screen
mask is read immediately before each terminal pass, so profile changes
apply to existing session-hit traffic when the map is synced. No row
under a resolved zone means no worker screen state, not “unresolved.”
The shim object, map pin/loader wiring, all reason mirrors, and
config-derived map sync must deploy together; rebuild the screen map
before activating the new object (`loader_userspace_shim.go:115-117`).
Flood meters remain in `pkg/nftables/host_inbound_screens.go`.

## 10. Successor issues to file (exact titles and acceptance)

File S1-S6 when the narrowed #16009 scope is accepted; these residues are
not closed by C1-C35. C1's MF=1, four-byte payload is **geometry only**,
not overlap. There is no measured true-overlap parity claim.

- **S1 — title:** `screen: host-bound fragment-overlap parity — worker fragment_overlap is not armed for non-IPsec LocalDelivery and shim kernel-PASS has no cross-fragment state`
  **Owner:** the shim terminal-arm owner (`userspace-xdp` and the
  `pkg/dataplane/userspace` execution test), plus the `userspace-dp`
  descriptor/reinject path and `fragment_overlap`; both shim disposition
  and worker admission/record behavior are in scope for this successor.
  **Acceptance requires both legs:**
  1. Add `local_delivery_host_pass_overlapping_pair_is_rejected_16009` to
     `userspace-dp/src/afxdp/tests_9950.rs`, using the reinjector harness
     pattern in `tests_fragment.rs:1141-1180`
     (`txn_run_descriptor_with_reinjector`). Send IPv4 UDP Frag A to local
     `10.0.61.1` on ifindex 24, fixed `(src,dst,ident,protocol)`,
     `frag_off=0x2000`, 16-byte payload `[0,16)`, and prove it is
     delivered. Then send Frag B with `frag_off=0x0001`, 16-byte payload
     `[8,24)` (overlap `[8,16)`); it MUST not reach slow-path
     reinjection and `FRAG_OVERLAP_DROPPED` delta is exactly 1. Control
     B′ uses `frag_off=0x0002`, 8-byte payload `[16,24)`; adjacent
     fragments are delivered with no overlap increment. Also reject Frag
     A at reinjection and prove its unaccepted range was not planted.
     The worker admission must be armed for LocalDelivery through the later
     reinject chokepoint (`poll_descriptor/mod.rs:11299-11328,13612ff`):
     the current pure check is at `:1791-1805`; existing record arms are
     IPsec passthrough `:2008-2025`, ForwardCandidate pre/post-key
     `:10638-10702`, and parked-neighbor retry
     (`neighbor_dispatch.rs:760,802`), none reachable from LocalDelivery.
  2. Add a shim pair cell in
     `pkg/dataplane/userspace/fragment_overlap_session_miss_local_16009_test.go`
     using the BPF_PROG_TEST_RUN helpers defined in
     `xdp_shim_decouple_test.go:513,661,674,707`. With no matching session
     row, drive the same pair through the selected session-miss local
     `cpumap_or_pass` arm (`userspace-xdp/src/lib.rs:1101-1120`) and assert
     that the overlapping second fragment is disposed, not silently
     `XDP_PASS`ed to the kernel. It must be shim-dropped or redirected to
     a worker-enforcing path; if redirected, follow it in an end-to-end
     harness and assert the worker overlap drop above (BPF_PROG_TEST_RUN
     alone proves no worker result). The two packets must not both be
     admitted/delivered; the adjacent-fragment control remains accepted.
- **S2 — title:** `screen: port-scan / IP-sweep parity for host-bound kernel-PASS traffic`
  **Owner:** worker stateful screen maintainers. The issue owns the
  stateful per-source/flow acceptance, not a second stateless shim bit.
- **S3 — title:** `screen: SYN-cookie challenge semantics for host-bound traffic bypassed by shim kernel-PASS`
  **Owner:** worker SYN-cookie path plus shim terminal-pass owner.
  The acceptance must distinguish a challenge from a stateless drop.
- **S4 — title:** `shim: preserve zone/reason drop events and per-reason counter fidelity for host-bound kernel-PASS screens`
  **Owner:** shim map/counter and worker telemetry maintainers.
  Acceptance expands beyond the worker event paths at
  `poll_stages.rs:1360-1374,1450-1504`:
  1. Replace the gate's boolean result with first-tripped reason plus
     disposition class. Preserve precedence: extractor attribution via
     `ScreenParseError::screen_reason` (`screen/packet.rs:324-334`), then
     SYN+FIN → no-flag → FIN-no-ACK → WinNuke → known SYN-frag
     (`stateless.rs:53-84`), then POD → teardrop → ICMP-fragment →
     source-route (`stateless.rs:317-329`).
  2. Add per-reason drop and alarm indices in the shim, Go
     `degradedPathReasonNames`, and Rust `DEGRADED_PATH_REASON_NAMES`;
     keep #8258/#9888 agreement/reachability and both hard-coded pins
     covered.
  3. Add sparse `(zone, reason, disposition)` attribution; the current
     reason-only `PerCpuArray` cannot carry a zone. Decide the Prometheus
     label/cardinality contract explicitly (today the Prometheus metric
     has only a `reason` label:
     `pkg/api/metrics_degraded_path_9040.go:44-53`,
     `metrics_descriptors_global.go:145-152`).
  4. Decide arm attribution separately. Branch stats are TRACE-gated and
     the host-screen gate normally pre-empts them; do not silently turn
     diagnostics into accounting.
  5. Event parity needs a real BPF-to-worker event channel and mapping to
     the worker `ScreenDrop` frame
     (`userspace-dp/src/afxdp/event_emit.rs:313-407,621-643`).
     The existing `userspace_trace` hash is TRACE-gated and lacks zone/
     screen reason while skipping ICMP (`lib.rs:412-428,2103-2133`); it
     is not an event substitute.
  6. Decide whether aggregate indices 21/22 remain totals or are retired
     when per-reason counters land; avoid double-counting.
  7. Distinguish profile trips, IPv4 tiny/malformed extraction, duplicate
     IPv6 Fragment, unresolved-zone fail-closed, and scratch/map failure;
     today all collapse into `host_screen_drop`.
- **S5 — title:** `shim: GRE-inner / decapsulated inner packets are outer-screened only on the kernel-PASS arm`
  **Owner:** native-GRE classifier and shim terminal-arm maintainers.
  Acceptance uses an inner-only malformed trip on GRE-inner
  `PASS_TO_KERNEL` plus a clean/redirect control; C32 deliberately proves
  only outer-screening.
- **S6 — title:** `shim: preserve claimed fabric-zone screens on all terminal kernel-PASS arms`
  **Owner:** `userspace-dp` session-map/fabric-publish boundary and
  `userspace-xdp/src/lib.rs` terminal-arm owner; `pkg/dataplane/userspace/`
  joins only if the chosen fix adds map/ABI state.
  Acceptance is **arm-by-arm**, not a single generic claim test: a
  claimed-zone-only trip plus a clean control for (1) session-hit
  `PASS_TO_KERNEL`, (2) session-miss local PASS before a session row,
  and (3) GRE-inner `PASS_TO_KERNEL`. Each trip must either use the
  validated claimed zone or remain worker-owned/redirected; none may
  silently PASS on raw-zone absence. The existing #16051 worker test and
  multi-zone session-hit demotion cover only part of this surface
  (§4.3).

**Conditional S7, file only if K1 re-planning removes Q1:** title
`shim: retain independent TCP-flag screen family if #16009 verifier ceiling rejects Q1`.
Owner: userspace-xdp shim plus Go mask/ABI maintainers. Transfer the four
independent Q1 bits and C23's 16-mask × 4-packet Q1 matrix for IPv4 and
IPv6 (128 outcomes); do not report those checks as completed by #16009.

Flood RATE meters are deliberately NOT a successor: they already exist in
`pkg/nftables/host_inbound_screens.go` (§1).

## 11. Self-assessment and questions for the three plan seats

**Self-assessment: PLAN-READY-shaped for a fresh plan-seat round, not
implementation-ready until all three seats converge and K1 is measured.**
The first three seats returned PLAN-NEEDS-MAJOR; this revision folds
B1-B12 and the F-A–F-G deltas while retaining the narrow option-1 decision.
Source facts were checked at `origin/master` `6c27f54cf2`; the verifier
outcome remains unmeasured. C1 is geometry only, true overlap is S1, and
terminal-pass parity is explicitly S6.

Candidate **Q1 is decided IN**, with four independent TCP mask bits and
all 16 masks × 4 packet shapes for both IPv4 and IPv6 (128 outcomes) in
C23 (§4.4).
Candidate **Q2 is decided NO**: no global pre-binding gate; gate only
inside the selected binding-not-ready local/control arm (§5.5).
Claimed-zone **Q-D is resolved by explicit scope-out to S6**, not left as
a plan-seat question.

Questions for the three plan seats:

1. **Arm/eligibility seat:** attack all 11 parsed-IP `lib.rs` insertion
   points and C24-C35's selected/control predicates (C24-C34 arm matrix,
   plus C35 alarm preservation). Are the WG/NDP/NAT/GRE fixtures
   sufficiently isolated to select only the named arm? Is C25's
   multicast/broadcast behavior clearly a policy extension, with
   non-owned link-local as the redirect control and exact-local link-local
   kept for C30? Does C15 avoid using BPF_PROG_TEST_RUN to claim a worker
   counter, and do C33's two DROP actions distinguish by counters?
2. **Parser/semantics seat:** attack B1-B5 and C20-C23/C35: independent
   TCP masks, common post-L4 placement, malformed IPv4 options before/
   after LSRR, duplicate readable non-atomic IPv6 headers and the exact
   `[M=1, off=0][M=1, off=8]` observer event before early break. Is the
   map-free generic walker callback and checked BPF scratch sink sound,
   including fail-closed lookup failure, with `ParsedPacket`/`ExtWalk`
   diffs empty? Does C22 remain a disclosed divergence and never parity
   coverage despite the worker's no-flag-only caller-stamped-zero result?
   Are C18/C19 honestly earlier parse-fail controls?
3. **Budget/ABI/residue seat:** is the ≤850,000 complete-object K1 proof
   (floor PASS, no override) sufficient, with the observer callback and
   checked scratch-map write measured only as part of the full-object
   processed-instruction count (no guessed callback number)? Are 21/22
   reachable and pinned across all three mirrors, including Go reachability
   and cap tests? Does the builder preserve `AlarmWithoutDrop` for both
   inert and `BadNumericUnresolved` refs, while C6/C20/C21 errors still
   drop on row presence? Does S4 resolve disposition classes, arm
   attribution, Prometheus cardinality, event transport, and aggregate
   retention without claiming that #16009 already provides telemetry
   parity?

## 12. Scope-size estimate and landing sequence

**Scope estimate [INFERENCE]:** approximately 800–1,100 production/config
lines changed or added (pure verdict + Go builder, parser scratch and
bounded scans, one outlined gate + 11 call sites, map/loader/pin wiring,
and reason mirrors), plus roughly 900–1,300 test lines (C1-C35, the
16-mask × 4-packet Q1 matrix for each IP family (128 outcomes), Go tests,
assertion). One engineering lane; no worker production screen change in
this narrowed plan. S1/S2/S3/S4/S5/S6 are separate successors, not hidden
work inside this estimate.

Landing sequence:
Implementation and landing commits use the subject format
`docs: <imperative summary> (#16009)`.

1. Salvage `host_screen.rs` verdict arithmetic with the `u16` independent
   mask; add the packed-word host twin and C23's complete dual-stack TCP
   matrix.
2. Add checked scratch writes: IPv4 TLV + malformed-options bits,
   declared-length tiny rule, and common post-L4 trips through both
   `first_fragment_l4` and `parse_l4`; IPv6 in-walk route/fragment and
   duplicate-header sightings. Keep `ParsedPacket`/`ExtWalk` diffs empty;
   do not add v6 tiny finalization.
3. Add the outlined gate at all 11 selected terminal pass arms; append
   reason indices 21/22 and wire/sync/pin the u16 map and all reason
   mirrors.
4. Regenerate and measure the **complete object**. Stop if K1 is red;
   reassign Q1 to S7 only through an explicit reviewed scope change, never
   by silent bit deletion.
5. Run Go builder/capacity/reason agreement cells and the
   `userspace-dp` worker-stage assertion; then run C1-C35 BPF cells and
   the dual-stack smoke in the Class-R VM lane.
6. Update `docs/afxdp-packet-processing.md`'s screen-parity paragraph,
   commit the regenerated manifest/gate-verdict artifacts with the
   implementation, and file the exact S1-S6 successors.
