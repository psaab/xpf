# DRAFT v4 — Fix the 183-red descriptor-enforcement baseline on the fixture-MAC gate (#10504)

- Status: DRAFT v4 (plan only; no production code, no test changes in this lane).
- Base: `7dcdd7383` (`sessions: share protocol filter contract across REST/gRPC/CLI (#10486)`), branch `fix/10504-fixture-mac`.
- Pinned research base: `b71c52d6` (issue body; our HEAD is newer — see STEP-0 drift note).
- Date: 2026-09-22.
- Sequencing: implementation starts after PR #10544 landed (blocked-by note quoted in §10).

## 1. Problem

The live full release run on this lane and the cited research baseline agree:
`FAILED. 6392 passed; 183 failed; 6 ignored` (6581 total). The cited family
splits are revocation 8/58, embedded-filter 28/36, fragment 45/19,
session_hit_authority 0/10; sibling filter-revocation control 6/0.

Root cause (single mechanism, three fixture/frame shapes): the AF_XDP poll boundary
rejects unicast frames whose destination MAC does not match the arrival interface
(`poll_descriptor/mod.rs:276-289` recycles the descriptor before ARP/NDP, decap,
learning, and all L3 resolution; `forwarding/fabric.rs:198-238` fail-closes to
`false` when no expected MAC exists). The red cells drive frames that can never pass
that gate, so they assert on sessions/outcomes the packet never reached. The failures
are pre-L3 preconditions, not policy verdicts:

- `policy_deny_snapshot()` (`test_fixtures.rs:951-1021`) leaves `reth1.0`/ifindex 24
  with `..Default::default()` (empty `hardware_addr`), while `build_txn_tcp_syn_frame_v4`
  (`tests_support.rs:994-1004`) and `build_txn_tcp_frame_v6` (`:1494-1508`) hardcode dst
  `02:bf:72:01:00:01`. `forwarding.egress.get(24).src_mac` is `[0;6]`, filtered out;
  no fabric fallback; `expected_mac` is `None` → `false` → recycle.
- `build_icmp_echo_frame_v4` (`tests_support.rs:24-45`) stamps dst `aa:bb:cc:dd:ee:ff`,
  which matches no interface in any fixture → always recycles.
- `eth_ipv4_frag_frame` / `frag_v4_transit_frame` (`tests_support.rs:2370-2540`) stamp
  dst `02:bf:72:00:80:08` (the WAN MAC) but tests ingress them on LAN (ifindex 24) →
  mismatch → recycle (or fail-close on the MAC-less LAN fixture).
- Cross-interface arrivals on MAC-complete fixtures: `inbound_dnat_snapshot`
  (`userspace-dp/src/afxdp/tests_support.rs:2232-2268`) extends `nat_snapshot`
  (`test_fixtures.rs:674-822`) with the real LAN/WAN MACs. The authority tests
  add their DMZ row at `tests_session_hit_authority_9519.rs:77-83`. Drivers
  address every frame to the LAN MAC while arriving on WAN (ifindex 12, MAC
  `02:bf:72:00:80:08`) or DMZ (ifindex 26, MAC `02:bf:72:02:00:01`) →
  `Some(expected) != dst` → recycle.
  This is the whole `tests_session_hit_authority_9519` family (0/10, all red inside the
  `admitted()` helper's `tx==1` assert) and the DNAT `admit_then_one_more_packet` cells.

Separately, six green survivors in the revocation file are vacuous: they assert only
the post-recycle zero state (`revoked==0` + `session_count==1`) with no hit/admission
witness, so a packet that never reaches L3 satisfies them. Two other survivors are
genuine (NAT64 with phase-1 `tx==1` + two-session + phase-2 hit witnesses; the
type-constrained-predicate direct forwarding-state check).

Separately, the only Make gate is blocked before Rust: `Makefile:99` orders
`test-go test-rust`, `:271` runs `pkg/refactoraudit` uncached, and
`TestStructMetricIsTypesNotFields6937` fails (Go calibration). That half is owned by
PR #10544 (#10496/#10497), not by this issue.

## 2. STEP-0 evidence

### 2.1 What was RUN on this base vs CITED (honesty boundary)

RUN (this lane, HEAD `7dcdd7383`, isolated `GOCACHE=/dev/shm/Eng10504/gocache`,
`GOTMPDIR=/dev/shm/Eng10504/gotmpdir`, Rust `CARGO_TARGET_DIR=/dev/shm/Eng10504/cargo-target`):

- Full release suite:
  `cargo +1.98.1 test --manifest-path userspace-dp/Cargo.toml --release --bin xpf-userspace-dp -- --test-threads=1`
  → `test result: FAILED. 6392 passed; 183 failed; 6 ignored; 0 measured; 0 filtered out; finished in 55.09s`.
  This is the full release suite, not a narrowed sample. The complete failure artifact
  is `artifact://59670`; its 183 distinct failure blocks were parsed for §3.
- Revocation family (part of that same full suite): 66 cells, 8 passed and 58
  failed. The eight names are enumerated in §5; subtraction from the 66 test
  declarations was checked against the 58 failure blocks in `artifact://59670`.
- Go calibration gate:
  `go test -count=1 -run TestStructMetricIsTypesNotFields6937 ./pkg/refactoraudit/`
  → `--- FAIL: TestStructMetricIsTypesNotFields6937 (2.70s)` /
  `structs_6937_test.go:95: CompileResult (32 fields, 21 types) flags; it is the
  just-UNDER calibration point for a floor of 20`. Make gate is blocked before Rust.
- Static census and component review (RUN): `poll_descriptor/mod.rs:276-289`,
  `forwarding/fabric.rs:198-238`, `test_fixtures.rs:674-822,951-1021`,
  `tests_support.rs` frame builders, revocation/authority/fragment/embedded drivers.

CITED (not re-run in this lane; retained as causality and provenance):

- The issue's 3/3 research lanes executed the same full count at pinned
  `b71c52d6`, with family splits revocation 8/58, embedded-filter 28/36,
  fragment 45/19, session_hit_authority 0/10, and filter-revocation control 6/0.
- One-field causality: adding the expected MAC to the shared fixture flips a red
  revocation cell green; removing it restores the `left: 0, right: 1` precondition
  red. This is cited research evidence; PLAN ONLY forbids repeating it by editing
  fixtures in this lane.
- PR #10544 validation records `GO=false make test` reaching Rust and observing
  6392 passed / 183 failed / 6 ignored; its Make/Go changes remain out of scope.

The live full run exactly matches the cited 6392/183/6 baseline on this HEAD, so
the STEP-0 census is closed before implementation.

### 2.2 Gate and symbol map (exact paths on this HEAD)

| Role | Path | Lines / symbol |
|---|---|---|
| MAC recycle (pre-L3) | `userspace-dp/src/afxdp/poll_descriptor/mod.rs` | 276-289 (`ingress_destination_mac_accepted` → `scratch_recycle`) |
| MAC accept / fail-close | `userspace-dp/src/afxdp/forwarding/fabric.rs` | 198-238 (`None => false`) |
| MAC-less fixture | `userspace-dp/src/afxdp/test_fixtures.rs` | 951-1021 (`policy_deny_snapshot`, reth1.0/24 `..Default::default()`) |
| MAC-complete fixture | `userspace-dp/src/afxdp/test_fixtures.rs` | 674-822 (`nat_snapshot`, LAN `02:bf:72:01:00:01`, WAN `02:bf:72:00:80:08`); `inbound_dnat_snapshot` extends it at `tests_support.rs:2232-2268` |
| LAN-MAC txn builders | `userspace-dp/src/afxdp/tests_support.rs` | 994-1004 (v4), 1494-1508 (v6) |
| WAN-MAC deny builder | `userspace-dp/src/afxdp/tests_support.rs` | 669-691 (`build_policy_deny_tcp_syn_frame`, dst `02:bf:72:00:80:08`) |
| Garbage-MAC ICMP builder | `userspace-dp/src/afxdp/tests_support.rs` | 24-45 (dst `aa:bb:cc:dd:ee:ff`) |
| WAN-MAC frag builders | `userspace-dp/src/afxdp/tests_support.rs` | 2370-2540 (`eth_ipv4_frag_frame`, `frag_v4_transit_frame/meta`) |
| Descriptor driver | `userspace-dp/src/afxdp/tests_support.rs` | 1051-1078 (`txn_run_descriptor` + neighbors/deliveries/shared/events variants) |
| Revocation drivers | `userspace-dp/src/afxdp/tests_policy_revocation_8356.rs` | 197-236 (no hit guard), 595-653 (ICMP, no hit guard), 1896-1944 (9384, HAS hit guard), 955-989 (9386, HAS hit guard), 1133-1187 (9382 two-phase, HAS tx+count guards) |
| Control pattern | `userspace-dp/src/afxdp/tests_filter_revocation_7212.rs` | 92-109 (`revocation_snapshot` patches LAN `hardware_addr` to the frame MAC) |
| Make aggregate | `Makefile` | 99 (`test: test-go test-rust`), 271 (`-count=1 ./pkg/refactoraudit/`), 362-371 (`test-rust` release + debug legs) |

### 2.3 Live revocation recount (this base)

The full release run above exercised all 66 revocation cells: **8 passed, 58
failed**, with 0 ignored in that filtered family. The eight passing names are
listed in §5 and independently obtained by subtracting the 58 failure names in
`artifact://59670` from the 66 `#[test]` declarations.

### 2.4 Base/provenance note

The issue cites research pinned to `b71c52d6`; this lane's HEAD is `7dcdd7383`.
The live full run on this HEAD nevertheless reproduces the exact cited denominator
and result: 6581 total, 6392 passed, 183 failed, 6 ignored. Therefore the plan's
STEP-0 census is live on the current lane, not a stale citation; implementation
still starts with a recount after rebasing onto #10544 as required by §10.

## 3. Failure-class census (183 reds)

The full-run artifact contains 183 distinct failure blocks. The table below is an
exhaustive failure-name/module census and sums exactly to 183; it is not, by
itself, proof of a root cause for every block. The 181 descriptor-path blocks all
stop before the intended L3 assertion and observe zero forward/session-hit/event
output. Source inspection plus the cited one-field experiment make M-MAC the
working attribution for those 181 blocks, but representative MAC instrumentation
or a post-fix recount must confirm each cell before implementation calls that
attribution final.

| Working class | Failing module/family | Reds | Representative first failed precondition |
|---|---|---:|---|
| M-MAC? | `tests_9950` | 10 | fragment anchor/premise forward is 0 |
| M-MAC? | `tests_decap_dnat_table` | 1 | decapped packet never reaches MissingNeighbor |
| M-MAC? | `tests_embedded_poll_filter` | 36 | embedded reversal/filter/event forward is 0/empty |
| M-MAC? | `tests_fragment` | 19 | fragment forward/association/filter precondition is 0 |
| M-MAC? | `tests_gre_local_delivery` | 4 | inner packet never reaches LocalDelivery |
| M-MAC? | `tests_host_bound_post_dnat_9529` | 9 | translated host-bound verdict/event is 0/empty |
| M-MAC? | `tests_nat64_tunnel` | 4 | NAT64 translation/drop precondition is 0 |
| M-MAC? | `tests_policy_inbound_nat` | 12 | translated policy forward/deny precondition is 0 |
| M-MAC? | `tests_policy_revocation_8356` | 58 | hit/tx/phase-1 admission precondition is 0 |
| M-MAC? | `tests_session_hit_authority_9519` | 10 | WAN admission or DMZ session hit is 0 |
| M-MAC? | `tests_session_ingress_identity` | 9 | LocalDelivery/transit install precondition is 0 |
| M-MAC? | `tests_txn_flow_cache` | 7 | trigger/flow-cache forward is 0 |
| M-MAC? | `wg::decap_tests` | 2 | VRF reply delivery is absent |
| H-TUN | `coordinator::tests::gre1881_mode_flip_to_wireguard_prunes_gre_entry` | 1 | TUN mode-flip cleanup remains non-empty; `TUNSETIFF` is denied |
| H-EXPECT | `session::routing_domain_wire::tests::empty_name_hash_panics_9752` | 1 | expected-panic contract does not panic |
| **Total** |  | **183** | 181 working M-MAC + 1 + 1 |

The M-MAC working attribution has three repair shapes, all backed by the source
map and cited one-field causality: M1 absent expected MAC (`policy_deny_snapshot`
LAN row); M2 destination MAC belongs to a different arrival interface (WAN/DMZ,
reverse, or fabric path); M3 unmatchable hardcoded destination (notably ICMP
`aa:bb:cc:dd:ee:ff`). The run did not instrument M1/M2/M3 or establish
per-cell causality, so this plan intentionally does not claim sub-counts.

- H-TUN and H-EXPECT are directly evidenced non-MAC residuals and are not
  repair targets for fixture-MAC work. H-TUN is separately owned by #10553;
  H-EXPECT is separately owned by #10552. Their independent disposition and
  explicit two-block residual denominator are in §4, §6, and §9.
- Class V — six vacuous survivors are green, not part of the 183-red sum, but are
  load-bearing. Five descriptor survivors receive positive hit guards; #6's
  ifindex-0 decline coverage moves to helper-level per §5/Q1.
- The cited family arithmetic is consistent: 58 revocation + 36 embedded +
  19 fragment + 10 authority = 123 red families; the remaining 60 failure blocks
  are 58 outside-family working M-MAC attributions plus H-TUN and H-EXPECT.


## 4. Fix strategy per failure class

INTERNAL FRAMEWORK ONLY: in-tree Rust fixtures/drivers/builders; no external CLIs,
companion scripts, or provider APIs. Production gate semantics UNCHANGED (no
test-only bypass, no `#[cfg(test)]` gate disable — the fail-closed MAC check is
correct; production AF_XDP ingress always carries a configured MAC).

- M1 (fixture regeneration, narrow): give `policy_deny_snapshot()`'s `reth1.0`/24 the
  LAN MAC `02:bf:72:01:00:01` (the same value `nat_snapshot` already uses, matching
  the txn builders). Audit every other snapshot builder for arrival interfaces lacking
  MACs; add MACs ONLY to interfaces that appear as `meta.ingress_ifindex` in some
  driven test. Explicitly DO NOT add a MAC to `st0.0`/tunnel rows (MAC-less is
  load-bearing there: `populate_egress` absence → to-zone 0 per the #6722 fixture
  comment) or to any interface whose MAC-lessness a test pins. Chosen over the
  control pattern (patching fixture MAC to whatever the frame carries,
  `tests_filter_revocation_7212.rs:101-108`): the control pattern works but inverts
  the dependency (fixture chases frames, WAN MAC on a LAN row). The fix direction is
  fixtures carry production-plausible distinct MACs, frames address the arrival.
- M2/M3 (builder parameterization + per-test repair): add a dst-MAC parameter to
  `build_txn_tcp_syn_frame_v4`, `build_txn_tcp_frame_v6`,
  `build_txn_tcp_syn_frame_v6`, `build_icmp_echo_frame_v4`,
  `build_icmp_echo_frame_v6`, `eth_ipv4_frag_frame`, and
  `build_policy_deny_tcp_syn_frame` (and thin wrappers where the call-site count
  favors it). The v6 SYN wrapper must carry the parameter through its
  `build_txn_tcp_frame_v6` call. Migrate the exact raw-hit checklist:
  txn-v4 104/18; v6 low-level 7/2 plus SYN wrapper 18/6; ICMP-v4 descriptor
  builder 24/7 plus the separate `frame/` pure-frame builder 17/6 (no-touch);
  ICMP-v6 7/3; fragment eth 9/2 plus transit wrapper 13/3; and deny-SYN 13/6.
  The combined ICMP-v4 41/13 regex is a census across both modules, not a
  descriptor migration denominator. The deny-SYN sites are M2 arrivals, not a
  generic default: `tests_support.rs:715-778`, `tests_nat64_tunnel.rs:897,974`,
  and `tests_embedded_poll_filter.rs` LAN-bound sites at `:2899,:3149,:3362,
  :3539,:3773,:3965`; `:3149` is the VLAN special arrival and must pass the
  logical-unit MAC. Also migrate `tests_gre_local_delivery.rs:643` and
  `poll_descriptor/filter_revalidation_7212_tests.rs:348`. The
  `tests_filter_revocation_7212.rs:212` occurrence is a control interaction:
  pass the new argument mechanically if the signature requires it, but preserve
  its WAN-MAC-on-LAN shape under the #10554 exemption; it is not an M-MAC repair.
  Each interface keeps its distinct production-plausible MAC (LAN
  `02:bf:72:01:00:01`, WAN `02:bf:72:00:80:08`, DMZ `02:bf:72:02:00:01`);
  reusing one MAC across rows is forbidden (it would mask cross-interface bugs
  the way the control's WAN-MAC-on-LAN patch does). Special arrivals repaired
  individually: VLAN-tagged (dst = logical-unit MAC per
  `resolve_ingress_logical_ifindex`), fabric-stamped (dst = matched fabric
  `local_mac` or parent egress MAC per the `fabric.rs:228-232` fallback order —
  verify against `fabric_admit_snapshot_9604`), foreign/DMZ arrivals (dst = DMZ
  MAC). The `ifindex==0` no-identity cell (§11 Q1) cannot pass any MAC gate by
  construction and gets re-scoped, not patched. The separate
  `frame/tests_support.rs` ICMP-v4 builder is pure-frame/no-descriptor and is
  explicitly no-touch; its 17/6 hits must remain outside the descriptor 24/7
  migration count, and B9 must verify no double-counting.
- V (driver preconditions, first): add `assert_eq!(dbg.session_hit, 1, …)`
  (session-hit drivers) or `assert_eq!(dbg.tx, 1, …)` + `session_count==2`
  (admission drivers) to `drive_one_packet_with_action`,
  `drive_one_icmp_packet`, and the inline ifindex-0 cell at
  `tests_policy_revocation_8356.rs:2141-2154` — mirroring the guards the
  9384/9386/9604/9382 drivers already carry. This runs BEFORE M1-M3 so five
  descriptor-driven vacuous greens convert to honest reds with a clear
  precondition signal; the sixth (#9513) is re-scoped to a helper-level
  assertion per §11 Q1. No currently-green cell outside the six turns red;
  existing reds may fail at an earlier guard. No outcome assert is weakened.
- G (consume, do not duplicate): rebase onto #10544; verify `make test` reaches Rust;
  no Makefile or `pkg/refactoraudit` changes in this issue.
- H-TUN (environment residual, no source fix here): independently rerun
  `coordinator::tests::gre1881_mode_flip_to_wireguard_prunes_gre_entry` in the
  required TUN-capable environment. The current failure includes `TUNSETIFF:
  Operation not permitted`; if privilege fixes it, record that prerequisite. If
  it remains red, #10553 owns the privileged-runner/coordinator disposition.
  This one block is outside the 181-cell M-MAC acceptance denominator. Never add
  a fixture-MAC exemption to make this cell green.
- H-EXPECT (semantic residual, no source fix here): the release leg
  deterministically strips the `debug_assert!` used by
  `empty_name_hash_panics_9752`; its `#[should_panic]` contract therefore
  remains a known release residual. Follow-up #10552 owns the cfg-gated
  debug/release pair modeled on the flow-cache precedent. This issue records
  the one named H-EXPECT block outside the 181-cell denominator; descriptor
  fixture changes cannot alter the expected-panic contract.
  M1-M3 acceptance must not silently absorb or weaken this contract.

Rejected alternatives: (a) disabling/softening the MAC gate under `#[cfg(test)]` —
  destroys the boundary the gate exists to enforce and would green every cell without
  proving anything; (b) per-test fixture MAC patches in the control style everywhere —
  scales as O(cells) patches with inverted semantics and masks cross-interface bugs;
  (c) weakening outcome asserts to tolerate recycle (e.g. `revoked==0` everywhere) —
  converts reds to vacuous greens, the exact defect class this issue closes.

## 5. The six vacuous survivors + two genuine (live revocation result)

The full release run is the live result: 8 passed / 58 failed of 66. The following
six passing cells are vacuous; the two remaining passing cells are genuine. This
classification is checked against the exact eight-name subtraction from
`artifact://59670`, not a prediction.

VACUOUS (assert `revoked==0` + `session_count==1`, no hit/tx guard; recycle satisfies
both):

1. `a_still_permitted_flow_survives_the_re_derivation_8356`
   (`tests_policy_revocation_8356.rs:323-339`; driver 197-236, no hit assert).
2. `a_re_derivation_leaves_the_reverse_companion_alone_8356` (`:349-366`; same driver).
3. `a_permit_rule_still_survives_the_widened_revoke_predicate_9381` (`:409-432`;
   same driver via `Some("permit")`).
4. `a_type_constrained_permit_declines_the_icmp_re_derivation_8618` (`:682-695`;
   ICMP driver 595-653, no hit assert; frame dst unmatchable + fixture MAC-less).
5. `a_still_permitted_icmp_flow_survives_the_re_derivation_8618` (`:699-707`; same).
6. `an_arrival_with_no_interface_identity_still_declines_9513` (`:2115-2155`; meta
   ifindex 0 → `egress.get(0)` None → recycle; asserts `revoked==0` + count 1, no
   hit assert — the intended decline gate is never reached). See §11 Q1:
   re-scope to helper-level coverage before M1; do not patch an unrepresentable
   descriptor arrival with a MAC.

GENUINE (stay green throughout; regression tripwires):

7. `an_unchanged_nat64_policy_with_a_mixed_family_destination_set_does_not_revoke_9382`
   (`:1785-1824`): `nat64_snapshot` (via `nat_snapshot`) carries the LAN MAC and the
   v6 frame dsts the LAN MAC on LAN ingress → phase-1 `tx==1` + 2 sessions, phase-2
   `session_hit==1`, `revoked==0`, 2 sessions. All witnesses pass for the right reason.
8. `the_type_constrained_predicate_is_per_protocol_8618` (`:713-735`): direct
   `forwarding.policy.icmp_verdict_may_depend_on_type` asserts; drives no descriptor;
   MAC gate unreachable.

Why exactly six (exclusion reasoning, checked per cell): every other survive-shaped
cell carries a hit/tx/phase-1 guard that reds on recycle — 9384 driver hit assert
(`:1935-1939`), 9386 driver hit assert (`:983-987`), 9604 `out.hit==1` asserts (all),
9382 `admit_then_one_more_packet` phase-1 `tx==1` + count==2 (`:1157-1166`), 9513
no-route hit assert (`:282-285`), default-reject inline hit assert (`:2303`),
`a_move_into_a_still_permitted_zone` inline hit assert (`:2029`). Revoke-shaped cells
(`revoked==1` / count==0) red on recycle by construction.

## 6. Exact contract per class (post-fix predicates)

- M1: for every descriptor-driven test, every interface appearing as
  `meta.ingress_ifindex` in that test has a non-zero `hardware_addr` in the built
  `ForwardingState` (`egress[src].src_mac != [0;6]` after logical-ingress resolution,
  or a matching fabric `local_mac`). Tunnel/non-arrival rows keep their existing
  MAC-less shape where pinned.
- M2/M3: every driven unicast frame's dst MAC equals the arrival interface's expected
  MAC under `ingress_destination_mac_accepted` (logical-unit MAC, else physical
  egress MAC, else fabric `local_mac`; broadcast/multicast exempt by the I/G-bit arm).
  No test relies on `None => false` recycle to reach its assertions except cells whose
  stated subject IS the MAC gate (none in the red set; gate-owning cells stay green).
- V: every revocation/outcome driver asserts a positive precondition before
  outcome asserts: five descriptor-driven survivors use `session_hit==1`;
  admission drivers use `tx==1` + `session_count==2` (pair). The ifindex-0
  survivor is covered by a helper-level re-scope before M1. For RED-on-revert
  evidence, retain the returned batch/counters from `txn_run_descriptor` (rename
  discarded `_batch` bindings as needed) and report
  `BatchCounters.validated_packets` from that value alongside
  `dbg.session_hit`; do not claim the recycle fingerprint from `dbg` alone.
- G: `make test` runs the Go leg AND the Rust leg on a clean tree (aggregate
  fail-dominant, exit nonzero iff either leg fails); `pkg/refactoraudit` passes
  uncached. Verified post-rebase, owned by #10544.
- H-TUN: this issue makes no claim about coordinator/TUN cleanup. The unfiltered
  release result has a baseline classified cohort of 183 = 181 M-MAC cells plus
  one H-TUN block and one H-EXPECT block; this is not an allowed-failure budget.
  H-TUN is owned by #10553 and requires a TUN-capable rerun or its separate
  disposition. A MAC fixture change cannot satisfy this contract.
- H-EXPECT: this issue makes no claim about the session panic contract. It is
  the second named block in the same 181 + 1 + 1 baseline cohort, owned by
  #10552; the release `debug_assert!` behavior is deterministic. The cfg-gated
  debug/release repair is out of scope here. Descriptor fixture changes cannot
  alter the expected-panic contract.

## 7. Invariants (MUST NOT break)

1. Production MAC-gate semantics byte-identical: `fabric.rs:198-238` and
   `poll_descriptor/mod.rs:276-289` unchanged (no test-only arms, no softening).
2. Fixture diffs are MAC/additive-only on the policy/zone/route/NAT/filter axes:
   no rule, zone id, route, neighbor, or filter verdict changes except where a cell's
   stated subject requires it (none anticipated).
3. No assert weakened anywhere; preconditions only added. The five descriptor V
   cells keep their outcome asserts (`revoked==0`, counts) and gain hit guards;
   #6's decline coverage moves to helper-level per §5/Q1.
4. Genuine survivors (§5 #7-8) stay green on every commit of the fix stack.
   The filter-revocation control 6/0 also remains a tripwire, and its post-
   `policy_deny_snapshot()` WAN-MAC-on-LAN overwrite is intentionally exempt
   from invariant 5 for this issue: it preserves the control's existing
   tripwire shape. Follow-up #10554 owns its later repair to a distinct-MAC
   shape; do not repair that control in this migration.
5. Distinct MACs per interface row in every touched fixture (no MAC aliasing
   across rows); the sole scoped exception is the filter-revocation control
   named in invariant 4 and owned by #10554. Frames address the arrival row.
6. Full release recount is the acceptance signal, not family spot-checks: all 181
   M-MAC working-attribution cells must be green with survivor witnesses; the
   H-TUN and H-EXPECT blocks remain separately owned residuals with explicit
   181 + 1 + 1 baseline cohort accounting, not an allowed post-fix failure
   budget, and issue references #10553/#10552. No unexplained red may be called
   a fixture-MAC success.

## 8. Risks (incl. fixture-churn blast radius)

- R1 Fixture-churn blast radius (largest): `policy_deny_snapshot` 71 sites / 13 files;
  `nat_snapshot` 171 / 23; `txn_run_descriptor` 232 / 19; txn v4 builder 104 / 18;
  v6 low-level builder 7 / 2 + SYN wrapper 18 / 6; ICMP-v4 descriptor builder
  24 / 7 + frame/ no-touch builder 17 / 6; ICMP-v6 7 / 3; frag builders 9 / 2 +
  transit wrapper 13 / 3; `build_policy_deny_tcp_syn_frame` 13 / 6.
  Builder-signature changes are mechanical but wide; a missed call site is a
  silent MAC mismatch (honest red via new guards, not silent green — the V-first
  ordering bounds this). Mitigation: `grep`-verified call-site migration
  checklists from the fan-out numbers in §12; V guards land first so every miss
  reds loudly. The combined ICMP-v4 41 / 13 regex is not a migration count.
- R2 MAC aliasing masking cross-interface bugs: fixed by invariant 5 (distinct MACs)
  + review checklist item per touched fixture. The filter-revocation control is
  the explicit temporary exception, preserved as a tripwire and tracked by #10554;
  no other touched fixture may alias.
- R3 Tunnel MAC-lessness (`st0.0`, xfrmi shapes): adding MACs there would flip
  to-zone 0 → zoned and break #6722/#9513 expectations. Mitigation: arrival-only MAC
  rule (§4 M1) + explicit no-touch list in the implementation PR.
- R4 `ifindex==0` cell unrepresentable via descriptor (§11 Q1): patching is impossible
  (no expected MAC can exist for ifindex 0); forcing it green via a gate exemption
  would weaken production. Mitigation: choose the helper-level re-scope before M1
  so the recount denominator is settled before fixture changes land; do not defer
  Q1 until after M2/M3.
- R5 Base/provenance: the live current-HEAD run exactly matches the pinned
  6392/183/6 denominator, but implementation still rebases onto #10544. Mitigation:
  repeat the unfiltered release recount after rebase and compare the exact module
  table in §3; any changed block receives a new evidence-backed class assignment.
  This is a revalidation risk, not an unresolved census.
- R6 PR #10544 interplay: file overlap is ZERO (that PR: `Makefile`,
  `docs/log/10496.md`, `docs/pr/10496-serial-gate-floor/plan.md`,
  `pkg/docsref/make_aggregate_10496_test.go`, `pkg/refactoraudit/structs_6937_test.go`;
  this issue: `userspace-dp/src/afxdp/**` fixtures/drivers only) — no merge conflicts
  expected on content, but the base moves. Mitigation: rebase-then-recount (§10).
- R7 Over-correction (breaking genuine greens): guarded by invariant 4 tripwires +
  per-commit family runs during implementation.
- R8 Fix-order inversion (fixtures before guards): would flip vacuous greens to
  genuine greens without ever proving the guards work, losing the RED-on-revert
  evidence. Mitigation: V drivers first, then M1, then M2/M3 (§10).

## 9. Test plan (how each class proves green + RED-on-revert)

- M1: `tests_policy_revocation_8356` TCP subset (drive_one_packet cells) flips
  revoke-cells red→green on outcome asserts with new hit guards passing;
  `cargo test --release --bin xpf-userspace-dp -- --test-threads=1
  tests_policy_revocation_8356` → 65/65 descriptor cells plus one helper-level
  #9513 proof (66 declarations covered) after Q1 helper move. Revert check:
  temporarily blank the LAN MAC → the five descriptor hit guards red (not
  outcome asserts alone); the helper-level #9513 pin has its own revert proof.
- M2: `tests_session_hit_authority_9519` → 10/10 (phase-1 `admitted()` tx==1
  passes); DNAT 9382 cells → green on phase-1 + outcome; 9604 reverse cells →
  green on `out.hit==1` + outcome; deny-SYN 13/6 sites → green with LAN arrival
  MACs. Revert check: restore one hardcoded LAN-MAC frame on a WAN arrival →
  that cell's hit/tx guard reds.
- M3: descriptor ICMP-v4 cells use the 24/7 afxdp builder migration; the
  separate `frame/` builder's 17/6 pure-frame cells remain no-touch. ICMP
  revocation cells (8618/9949/9386 groups) → green on hit + outcome;
  `tests_fragment.rs` → 33/33 with `frame/tests_fragment_term_extra.rs` 33/33
  unchanged (pure-frame control). Revert check: restore
  `aa:bb:cc:dd:ee:ff` dst on one descriptor ICMP cell → its hit guard reds.
  ICMP-v6 call sites are included in the 7-hit/3-file checklist. The
  implementation evidence must report the descriptor 24/7 and frame/ 17/6
  counts separately; the combined 41/13 regex is not a second migration set
  and must not be double-counted.
- V (RED-on-revert cells for the vacuous six — permanent guards, not throwaway):
  for §5 #1-5, the added `session_hit==1` guard is the revert cell: with the
  fix reverted (fixture MAC blanked or frame MAC mismatched), each fails AT THE
  GUARD with the retained-batch recycle fingerprint
  (`validated_packets==1`, `session_hit==0`, `revoked==0`). #6's helper-level
  re-scope has its own direct decline assertion and revert proof. The
  implementation PR must show, per survivor, the guard message and retained
  batch counter on revert (paste the assert text, not just FAIL).
- G: post-rebase `go test -count=1 ./pkg/refactoraudit/` PASS + `make -n test`
  sane + full `make test` reaching the Rust leg (owned by #10544; this issue
  only verifies). The exact Makefile Rust command is the acceptance runner,
  with the target cargo command above used for focused evidence.
- H-TUN: standalone rerun of
  `coordinator::tests::gre1881_mode_flip_to_wireguard_prunes_gre_entry` in a
  TUN-capable privileged runner; otherwise record the one residual block and
  #10553 disposition. It is not counted against the 181 M-MAC denominator.
- H-EXPECT: standalone debug-profile cfg-gated pair from #10552 must prove the
  intended panic/release assertion contract. The known release
  `#[should_panic]` residual is not counted against the 181 M-MAC denominator;
  do not claim this issue fixes it.
- Acceptance: run the exact post-#10544 `make test` Rust leg and retain the
  unfiltered denominator. This issue passes when all 181/181 M-MAC working-
  attribution cells are green, all six survivor witnesses are present, and the
  two named residual blocks are explicitly recorded as separately owned by
  #10553 (H-TUN) and #10552 (H-EXPECT). The `181 + 2 = 183` figure is baseline
  cohort accounting, not a post-fix allowance for 183 failures. If the
  denominator is unchanged, the expected aggregate after fixing those 181
  cells is `6573 passed / 2 failed / 6 ignored` (6581 total), with the two
  failures named and separately owned. This issue does not require a 0-failed
  release leg. Any additional red is unexplained until instrumented and routed
  separately.

## 10. Sequencing (what starts the day #10544 lands)

Blocked-by note (issue #10504, quoted verbatim — confirmed present):

> **Blocked by PR #10544 until it lands.** This issue's Rust fixture/MAC work is
> downstream of the paired Make aggregate and Go calibration fixes in #10496/#10497.
> Rebase and validate against #10544 before treating the acceptance as complete.
> Do not duplicate the serial aggregate or hermetic calibration changes in this
> issue; this issue owns the Rust fixtures, descriptor/MAC preconditions, and
> release-suite residual recount only.

Day-zero order (in this lane's successor implementation):

1. Rebase `fix/10504-fixture-mac` onto master containing #10544; confirm file overlap
   zero and tree builds.
2. Verify the Make gate reaches Rust: `go test -count=1 ./pkg/refactoraudit/` PASS;
   `make -n test`; then the real Rust leg runs (no longer blocked).
3. FULL release recount on the rebased base (same command as §2.1, unfiltered):
   re-anchor total/failed/ignored + all family splits; verify the exact §3 module
   census (181 working M-MAC candidates, H-TUN=1, H-EXPECT=1 unless the rebase
   changes it). Before calling any candidate M-MAC attribution final, collect
   representative test-only MAC instrumentation (ingress ifindex, expected MAC,
   frame dst, gate result) for each repair shape and compare the post-fix recount
   per cell. Any red fitting none of M1/M2/M3 is an H-NONMAC residual: preserve
   its first-failure evidence, file/route it separately, and exclude it from this
   issue's denominator rather than guessing.
4. Land V driver preconditions first: resolve Q1's helper-level #9513 move before
   M1; add five descriptor guards plus the helper assertion. No currently-green
   cell outside the six may turn red; existing reds may fail at an earlier guard.
   Family run proves the survivor witnesses and RED-on-revert messages.
5. Land M1 fixture MACs (revocation TCP + fragment LAN + embedded policy_deny cells
   flip red→green). Family runs per area; retain the control's scoped exception.
6. Land M2/M3 builder parameterization + per-test arrival-MAC repairs (authority,
   DNAT, reverse-path, ICMP v4/v6, deny-SYN, frag, embedded nat_based cells flip).
   Run the exact builder checklist in §4, report ICMP-v4 descriptor 24/7 versus
   frame/ 17/6 separately, and verify B9's frame/ duplicate is not
   double-counted. Family runs per area.
7. Full recount + RED-on-revert evidence per §9 (paste guard output for each of
   the five descriptor survivors and the helper-level #9513 proof). Record exactly
   181 M-MAC green plus the two named #10553/#10552 residual blocks, or route
   any additional red as H-NONMAC with evidence. Treat 181 + 1 + 1 = 183 as
   baseline cohort accounting; if unchanged, the expected aggregate is 6573
   passed / 2 failed / 6 ignored. Do not require release 0-failed.
8. Open the implementation PR (this DRAFT v4 becomes its plan section); parent
   lanes run delta plan review next — no reviewer dispatch from this lane.

## 11. Open questions (incl. PLAN-KILL)

- Q1 (re-scope): `an_arrival_with_no_interface_identity_still_declines_9513` drives
  meta ifindex 0, for which NO expected MAC can exist — the MAC gate correctly
  recycles before identity resolution. Move it to helper-level coverage (direct
  re-derivation call with no identity) before M1; do not express it as a
  descriptor arrival or delete the decline coverage. Owner: implementation
  lane + reviewer; decision is binding before fixture MACs land.
- Q2 (builder shape): use dst-MAC parameters on existing builders and carry them
  through both `build_txn_tcp_frame_v6` and its
  `build_txn_tcp_syn_frame_v6` wrapper. The checklist is txn-v6 low-level 7/2
  plus wrapper 18/6, ICMP-v4 descriptor 24/7 plus frame/ 17/6 no-touch,
  ICMP-v6 7/3, and the frag transit wrapper 13/3. Include
  `build_policy_deny_tcp_syn_frame` 13/6. The combined ICMP-v4 41/13 regex
  includes both modules and is not a migration denominator. The frame/ duplicate
  ICMP builder is pure-frame/no-descriptor and explicitly no-touch; verify B9
  does not double-count it. No hardcoded LAN, WAN, or garbage default may survive
  as a silent cross-interface path.
- Q3 (fabric arrivals): confirm `fabric_admit_snapshot_9604` MACs + `stamp_fabric_zone`
  dst (`02:bf:72:ff:00:01`) satisfy the `fabric.rs:216-232` fallback order
  (egress src_mac, else ingress src_mac, else fabric local_mac) post-fix; the
  9604 fabric trio is the proof set.
- Q4 (residual-60 attribution): arithmetic is closed, but the 58 outside-family
  M-MAC assignments remain working attribution until evidence closes them.
  Step 3 must capture representative MAC instrumentation for M1/M2/M3 (or
  equivalent post-fix/revert evidence) before calling each attribution final;
  an H-NONMAC branch routes any first failure that fits none.
- Q5 (fail-fast helper): yes, add a fixture-blaming plain `assert!` or explicit
  panic in `txn_run_descriptor`; this helper is already `#[cfg(test)]`-only
  (`afxdp/mod.rs:621-623`), so there is no production-shared-code concern and
  the release acceptance leg fails fast on a fixture mismatch. This is separate
  from H-EXPECT/#10552's cfg-gated session-test repair.
- K1 (baseline gone): rejected as a current PLAN-KILL premise. #10544 changed
  Make/Go only and the gate/fixtures/builders remain on this tip; step 3 still
  revalidates the baseline after rebase, but a changed denominator is handled
  by re-census and evidence, not by assuming the issue is killed.
- K2 (gate wrong): rejected. Production AF_XDP ingress has a configured MAC and
  the gate's fail-closed pre-L3 ordering is correct; no gate inversion or
  test-only bypass is in scope.

## 12. Blast-radius numbers (live on HEAD 7dcdd7383 unless marked CITED)

| # | Measure | Value | How reproduced |
|---|---|---|---|
| B1 | Full release suite (RUN on HEAD `7dcdd7383`) | 6392 passed / 183 failed / 6 ignored (6581 total) | Isolated full command in §2.1; failure artifact `artifact://59670` |
| B2 | Static `#[test]` / `#[ignore]` attrs (this HEAD, `userspace-dp/src/**/*.rs`) | 6672 / 8 (664 files) | In-repo source census; declaration count is independent of the filtered binary result |
| B3 | Revocation file cells | 66 (`tests_policy_revocation_8356.rs`) | `#[test]\\nfn` source census = 66; issue "59 of 67" corrected to 66 |
| B4 | Cited family splits (green/red) | revocation 8/58; embedded 28/36; fragment 45/19; authority 0/10; control 6/0 | Issue research provenance; live revocation 8/58 and full module census are §2.3/§3 |
| B5 | Residual reds outside cited families | 183 − (58+36+19+10) = 60 = 58 M-MAC + H-TUN 1 + H-EXPECT 1 | Exact arithmetic and module assignment in §3; no deferred remainder |
| B6 | `policy_deny_snapshot` fan-out | 71 sites / 13 files (top: tests_fragment 20, revocation 18, tests_9950 9, embedded 6, filter_revalidation 6, nat64_tunnel 4) | `policy_deny_snapshot\\(\\)` regex |
| B7 | `nat_snapshot` fan-out | 171 sites / 23 files | `nat_snapshot\\(\\)` regex |
| B8 | `txn_run_descriptor` fan-out | 232 sites / 19 files | `txn_run_descriptor\\(` regex |
| B9 | Frame-builder fan-out | txn-v4 104/18; txn-v6 low-level 7/2 + SYN wrapper 18/6; ICMP echo v4 descriptor 24/7 + frame/ 17/6 no-touch (combined regex 41/13 includes both and is not the migration denominator); ICMP echo v6 7/3; frag eth 9/2 + transit wrapper 13/3; deny-SYN 13/6 | per-symbol regex qualified by module (§2.1/§4), with no double-count across the descriptor migration and pure-frame control |
| B10 | Gate symbol fan-out | `ingress_destination_mac_accepted` 4 uses / 3 files (def + poll call site + tests) | regex |
| B11 | Fixture file sizes | `test_fixtures.rs` 2126 lines / 88K; `tests_support.rs` 2852 lines / 104K; `fabric.rs` 820; `poll_descriptor/mod.rs` 7312 (read-only) | `wc -l`, `du -sh` |
| B12 | PR #10544 file overlap with this issue | 0 paths (that PR: Makefile + 2 docs + 2 Go files; this issue: `userspace-dp/src/afxdp/**` only) | PR body Files(5) vs §2.2 map |
| B13 | Fix touch estimate (strategy §4) | builder audit uses the 195 raw-hit builder migration denominator: txn-v4 104 = 1 definition + 103 external uses; txn-v6 low-level 7 = 1 definition + 1 wrapper-internal use + 5 external uses; txn-v6 SYN wrapper 18 = 1 definition + 17 external uses; ICMP-v4 descriptor 24 = 1 definition + 23 external uses; ICMP-v6 7 = 1 definition + 6 external uses; frag eth 9 = 1 definition + 1 wrapper-internal use + 7 external uses; frag transit wrapper 13 = 1 definition + 12 external uses; deny-SYN 13 = 1 definition + 12 external uses. Thus 8 definitions + 2 wrapper-internal uses + 185 external uses = 195 builder migration hits. Five are mechanical frame/-dir co-touches (`frame/mod.rs` 1, `frame/tests_9782_copy.rs` 2 v4 + 2 SYN-wrapper) that still require signature migration but do not drive descriptors. The separate frame/ ICMP-v4 17/6 (1 definition + 16 uses) is pure-frame/no-touch, and the combined raw regex is 212, not a migration denominator. Fixtures: ~2 snapshot fns + arrival-row audit (~13 files read, ~6 edited); drivers: 2-3 fns + five descriptor guards + one helper-level guard; tests: 0 outcome asserts weakened | B6-B9 fan-out; exact per-site checklist at implementation |
| B14 | Go gate live proof | `TestStructMetricIsTypesNotFields6937` FAIL (CompileResult 32f/21t vs floor 20) | RUN §2.1 |

Evidence sources: in-repo source census for B2/B6-B10, `wc -l`/`du -sh` for B11,
and the internal issue/PR records (`issue://10504`, `issue://10544`, `issue://10552`,
`issue://10553`, `issue://10554`) for B4/B12 and the three separately owned
residual/repair dispositions.
