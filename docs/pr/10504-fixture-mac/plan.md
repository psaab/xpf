# DRAFT v1 — Fix the 183-red descriptor-enforcement baseline on the fixture-MAC gate (#10504)

- Status: DRAFT v1 (plan only; no production code, no test changes in this lane).
- Base: `7dcdd7383` (`sessions: share protocol filter contract across REST/gRPC/CLI (#10486)`), branch `fix/10504-fixture-mac`.
- Pinned research base: `b71c52d6` (issue body; our HEAD is newer — see STEP-0 drift note).
- Date: 2026-09-22.
- Sequencing: implementation starts the day PR #10544 lands (blocked-by note quoted in §10).

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
- Cross-interface arrivals on MAC-complete fixtures: `inbound_dnat_snapshot` /
  `nat_snapshot` (`test_fixtures.rs:674-745`) carry real MACs, but drivers address
  every frame to the LAN MAC while arriving on WAN (ifindex 12, MAC `02:bf:72:00:80:08`)
  or DMZ (ifindex 26, MAC `02:bf:72:02:00:01`) → `Some(expected) != dst` → recycle.
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
  `forwarding/fabric.rs:198-238`, `test_fixtures.rs:674-745,951-1021`,
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
| MAC-complete fixture | `userspace-dp/src/afxdp/test_fixtures.rs` | 674-822 (`nat_snapshot`, LAN `02:bf:72:01:00:01`, WAN `02:bf:72:00:80:08`) |
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

The full-run artifact contains 183 distinct failure blocks. The failure class
assignment below is exhaustive and sums exactly to 183. The 181 descriptor-path
failures all fail before their intended L3 behavior: the common MAC destination
gate recycles the frame (`poll_descriptor/mod.rs:276-289`) or fail-closes because
the expected MAC is absent (`forwarding/fabric.rs:216-237`). The first assertion
then observes zero forward/session-hit/event output. The module breakdown is the
reproducible census surface:

| Class | Failing module/family | Reds | Representative first failed precondition |
|---|---|---:|---|
| M-MAC | `tests_9950` | 10 | fragment anchor/premise forward is 0 |
| M-MAC | `tests_decap_dnat_table` | 1 | decapped packet never reaches MissingNeighbor |
| M-MAC | `tests_embedded_poll_filter` | 36 | embedded reversal/filter/event forward is 0/empty |
| M-MAC | `tests_fragment` | 19 | fragment forward/association/filter precondition is 0 |
| M-MAC | `tests_gre_local_delivery` | 4 | inner packet never reaches LocalDelivery |
| M-MAC | `tests_host_bound_post_dnat_9529` | 9 | translated host-bound verdict/event is 0/empty |
| M-MAC | `tests_nat64_tunnel` | 4 | NAT64 translation/drop precondition is 0 |
| M-MAC | `tests_policy_inbound_nat` | 12 | translated policy forward/deny precondition is 0 |
| M-MAC | `tests_policy_revocation_8356` | 58 | hit/tx/phase-1 admission precondition is 0 |
| M-MAC | `tests_session_hit_authority_9519` | 10 | WAN admission or DMZ session hit is 0 |
| M-MAC | `tests_session_ingress_identity` | 9 | LocalDelivery/transit install precondition is 0 |
| M-MAC | `tests_txn_flow_cache` | 7 | trigger/flow-cache forward is 0 |
| M-MAC | `wg::decap_tests` | 2 | VRF reply delivery is absent |
| H-TUN | `coordinator::tests::gre1881_mode_flip_to_wireguard_prunes_gre_entry` | 1 | TUN mode-flip cleanup remains non-empty; `TUNSETIFF` is denied |
| H-EXPECT | `session::routing_domain_wire::tests::empty_name_hash_panics_9752` | 1 | expected-panic contract does not panic |
| **Total** |  | **183** | 181 + 1 + 1 |

M-MAC has three repair shapes, all backed by the live source map and the cited
one-field causality result: M1 absent expected MAC (`policy_deny_snapshot` LAN
row); M2 destination MAC belongs to a different arrival interface (WAN/DMZ,
reverse, or fabric path); M3 unmatchable hardcoded destination (notably ICMP
`aa:bb:cc:dd:ee:ff`). The run was not instrumented to distinguish M1/M2/M3
inside each module, so this plan does not invent sub-counts; the exact accepted
census is M-MAC=181 by module, H-TUN=1, H-EXPECT=1. Those repair shapes and
their contracts are explicit in §4 and §6.

- Class V — six vacuous survivors are green, not part of the 183-red sum, but are
  load-bearing. They are named in §5 and receive positive hit/admission guards.
- The cited family arithmetic is consistent: 58 revocation + 36 embedded +
  19 fragment + 10 authority = 123 red families; the remaining 60 are exactly
  58 M-MAC module reds outside those cited families plus H-TUN and H-EXPECT.


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
  `build_txn_tcp_syn_frame_v4`, `build_txn_tcp_frame_v6`, `build_icmp_echo_frame_v4`,
  `build_icmp_echo_frame_v6`, `eth_ipv4_frag_frame` (and thin wrappers where the
  call-site count favors it); update all call sites (104 + 7 + 41 + 9 + 13 uses across
  18 + 2 + 13 + 2 + 3 files) to pass the arrival interface's MAC. Each interface keeps
  its distinct production-plausible MAC (LAN `02:bf:72:01:00:01`, WAN
  `02:bf:72:00:80:08`, DMZ `02:bf:72:02:00:01`); reusing one MAC across rows is
  forbidden (it would mask cross-interface bugs the way the control's WAN-MAC-on-LAN
  patch does). Special arrivals repaired individually: VLAN-tagged (dst = logical-unit
  MAC per `resolve_ingress_logical_ifindex`), fabric-stamped (dst = matched fabric
  `local_mac` or parent egress MAC per the `fabric.rs:228-232` fallback order —
  verify against `fabric_admit_snapshot_9604`), foreign/DMZ arrivals (dst = DMZ MAC).
  The `ifindex==0` no-identity cell (§9 Q1) cannot pass any MAC gate by construction
  and gets re-scoped, not patched.
- V (driver preconditions, first): add `assert_eq!(dbg.session_hit, 1, …)` (session-hit
  drivers) or `assert_eq!(dbg.tx, 1, …)` + `session_count==2` (admission drivers) to
  `drive_one_packet_with_action`, `drive_one_icmp_packet`, and any other outcome
  driver lacking them — mirroring the guards the 9384/9386/9604/9382 drivers already
  carry. This runs BEFORE M1-M3 so the six vacuous greens convert to honest reds with
  a clear precondition signal, then flip to honest greens as fixtures/frames land.
  No outcome assert is weakened; guards are added, never removed.
- G (consume, do not duplicate): rebase onto #10544; verify `make test` reaches Rust;
  no Makefile or `pkg/refactoraudit` changes in this issue.

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
   hit assert — the intended decline gate is never reached). See §9 Q1: unfixable by
   MAC patching; re-scope candidate.

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
- V: every revocation/outcome driver asserts a positive precondition before outcome
  asserts: session-hit drivers `session_hit==1`; admission drivers `tx==1` +
  `session_count==2` (pair). `validated_packets==1` holds wherever the driver exposes
  telemetry (MAC recycle happens after `validated_packets` increments, so the pair
  `validated==1, hit==0` is the recycle fingerprint vs `hit==1` admitted).
- G: `make test` runs the Go leg AND the Rust leg on a clean tree (aggregate
  fail-dominant, exit nonzero iff either leg fails); `pkg/refactoraudit` passes
  uncached. Verified post-rebase, owned by #10544.

## 7. Invariants (MUST NOT break)

1. Production MAC-gate semantics byte-identical: `fabric.rs:198-238` and
   `poll_descriptor/mod.rs:276-289` unchanged (no test-only arms, no softening).
2. Fixture diffs are MAC/additive-only on the policy/zone/route/NAT/filter axes:
   no rule, zone id, route, neighbor, or filter verdict changes except where a cell's
   stated subject requires it (none anticipated).
3. No assert weakened anywhere; preconditions only added. The six V cells keep their
   outcome asserts (`revoked==0`, counts) and gain hit guards.
4. Genuine survivors (§5 #7-8) and the filter-revocation control 6/0 stay green on
   every commit of the fix stack (tripwires against over-correction).
5. Distinct MACs per interface row in every touched fixture (no MAC aliasing across
   rows); frames address the arrival row.
6. Full release recount is the acceptance signal, not family spot-checks: residual
   must recount to 0 failed with all survivors carrying hit/admission witnesses.

## 8. Risks (incl. fixture-churn blast radius)

- R1 Fixture-churn blast radius (largest): `policy_deny_snapshot` 71 sites / 13 files;
  `nat_snapshot` 171 / 23; `txn_run_descriptor` 232 / 19; txn v4 builder 104 / 18;
  v6 builder 7 / 2; ICMP echo 41 / 13; frag builders 9 + 13 uses / 2 + 3 files;
  `build_policy_deny_tcp_syn_frame` 13 / 6. Builder-signature changes are mechanical
  but wide; a missed call site is a silent MAC mismatch (honest red via new guards,
  not silent green — the V-first ordering bounds this). Mitigation: `grep`-verified
  call-site migration checklists from the fan-out numbers in §12; V guards land first so
  every miss reds loudly.
- R2 MAC aliasing masking cross-interface bugs: fixed by invariant 5 (distinct MACs)
  + review checklist item per touched fixture.
- R3 Tunnel MAC-lessness (`st0.0`, xfrmi shapes): adding MACs there would flip
  to-zone 0 → zoned and break #6722/#9513 expectations. Mitigation: arrival-only MAC
  rule (§4 M1) + explicit no-touch list in the implementation PR.
- R4 `ifindex==0` cell unrepresentable via descriptor (§9 Q1): patching is impossible
  (no expected MAC can exist for ifindex 0); forcing it green via a gate exemption
  would weaken production. Mitigation: re-scope to helper-level or delete with
  reviewer sign-off; decided before M1 lands so the recount denominator is settled.
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
  revoke-cells red→green on outcome asserts with new hit guards passing; `cargo test
  --release --bin xpf-userspace-dp -- --test-threads=1 tests_policy_revocation_8356`
  → 66/66. Revert check: temporarily blank the LAN MAC → hit guards red (not outcome
  asserts alone).
- M2: `tests_session_hit_authority_9519` → 10/10 (phase-1 `admitted()` tx==1 passes);
  DNAT 9382 cells → green on phase-1 + outcome; 9604 reverse cells → green on
  `out.hit==1` + outcome. Revert check: restore one hardcoded LAN-MAC frame on a WAN
  arrival → that cell's hit/tx guard reds.
- M3: ICMP revocation cells (8618/9949/9386 groups) → green on hit + outcome; frag
  `tests_fragment.rs` → 32/32 with `frame/tests_fragment_term_extra.rs` 32/32
  unchanged (pure-frame control). Revert check: restore `aa:bb:cc:dd:ee:ff` dst on one
  ICMP cell → hit guard reds.
- V (RED-on-revert cells for the vacuous six — permanent guards, not throwaway):
  for each of §5 #1-6, the added `session_hit==1` guard IS the revert cell: with the
  fix reverted (fixture MAC blanked or frame MAC mismatched), the cell fails AT THE
  GUARD with the recycle fingerprint (`validated_packets==1`, `session_hit==0`,
  `revoked==0`), proving the outcome asserts below it are reached rather than
  incidentally satisfied. Implementation PR must show, per survivor, the guard message
  on revert (paste the `session_hit` assert text, not just FAIL). #6 additionally
  resolves Q1 (re-scope or helper-level move with its own revert logic).
- G: post-rebase `go test -count=1 ./pkg/refactoraudit/` PASS + `make -n test` sane +
  full `make test` reaching the Rust leg (owned by #10544; this issue only verifies).
- Acceptance: full `cargo test --release --bin xpf-userspace-dp -- --test-threads=1`
  recount → 0 failed, ignored set unchanged-or-explained, every survivor carrying a
  hit/admission witness (re-run the §5 table against live output); plus the
  `make test` Rust leg green post-#10544.

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
   re-anchor total/failed/ignored + all family splits; verify the exact §3 census
   (M-MAC=181, H-TUN=1, H-EXPECT=1 unless the rebase changes it), then attribute
   each M-MAC red to repair shape M1/M2/M3 and every green survivor to
   genuine/vacuous. This is the implementation baseline — no code until it exists.
4. Land V driver preconditions first (six survivors → honest reds; all other cells
   unaffected). Family run proves the only newly-red cells are the six.
5. Land M1 fixture MACs (revocation TCP + fragment LAN + embedded policy_deny cells
   flip red→green). Family runs per area.
6. Land M2/M3 builder parameterization + per-test arrival-MAC repairs (authority,
   DNAT, reverse-path, ICMP, frag, embedded nat_based cells flip). Family runs per
   area. Resolve Q1 (ifindex-0) before closing this step.
7. Full recount + RED-on-revert evidence per §9 (paste guard output for each of the
   six). Residual must be 0 failed.
8. Open the implementation PR (this DRAFT becomes its plan section); parent lanes run
   plan review next — no reviewer dispatch from this lane.

## 11. Open questions (incl. PLAN-KILL)

- Q1 (re-scope): `an_arrival_with_no_interface_identity_still_declines_9513` drives
  meta ifindex 0, for which NO expected MAC can exist — the MAC gate correctly
  recycles before identity resolution. Options: (a) move to helper-level (direct
  re-derivation call with no identity, no descriptor); (b) re-express as an unzoned
  (not missing) arrival via descriptor; (c) delete as unrepresentable, with the
  decline logic covered by the helper suite. Owner: implementer + reviewer; decision
  needed before step 6 closes. Recommendation: (a).
- Q2 (builder shape): dst-MAC param on existing builders vs new `_with_mac` helpers +
  wrapper: recommend param (single source, `grep`-verifiable migration); confirm with
  parent review. Either way the hardcoded LAN-MAC default must not survive as the
  silent path for cross-interface callers.
- Q3 (fabric arrivals): confirm `fabric_admit_snapshot_9604` MACs + `stamp_fabric_zone`
  dst (`02:bf:72:ff:00:01`) satisfy the `fabric.rs:216-232` fallback order (egress
  src_mac, else ingress src_mac, else fabric local_mac) post-fix; the 9604 fabric
  trio is the proof set.
- Q4 (residual-60 arithmetic is closed): the four cited families account for
  123 reds (58 + 36 + 19 + 10); the 60 outside them are exactly 58 M-MAC module
  reds plus H-TUN=1 and H-EXPECT=1, as shown in §3. After #10544 rebase, repeat
  the same block-name parse and change a class only if the observed first failure
  changes; do not leave an unclassified remainder.
- Q5 (fail-fast helper): should `txn_run_descriptor` (test-only path) `debug_assert`
  MAC coverage (arrival interface has expected MAC and frame dst matches/broadcast)
  to fail fast with a fixture-blaming message? Pro: instant diagnosis for future
  cells. Con: production-shared helper gains test-only logic (mitigable via
  `#[cfg(test)]` + `debug_assertions`). Recommendation: yes, `debug_assert`-only;
  confirm with parent.
- PLAN-KILL conditions (either kills or fundamentally redirects this plan):
  K1: the step-3 recount on the rebased base shows the 183 baseline GONE (0 failed,
  or failures with a different mechanism) — e.g. #10544 or an intervening PR already
  fixed/removed the MAC gate or the fixtures. Action: re-census; if nothing remains,
  close #10504 as obsoleted with the recount as evidence. K2: review determines the
  production MAC gate itself is wrong (should admit MAC-less test fixtures) —
  rejected a priori (production ingress always has a MAC; the gate is correct), but
  if overturned, the fix inverts (gate change + gate-owning tests, not fixtures).
  Neither is expected; both are checkable at step 3.

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
| B9 | Frame-builder fan-out | txn-v4 104/18; txn-v6 7/2; ICMP echo v4 41/13; frag eth 9/2 + transit 13/3; deny-SYN 13/6 | per-builder regex (§2.1) |
| B10 | Gate symbol fan-out | `ingress_destination_mac_accepted` 4 uses / 3 files (def + poll call site + tests) | regex |
| B11 | Fixture file sizes | `test_fixtures.rs` 2126 lines / 88K; `tests_support.rs` 2852 lines / 104K; `fabric.rs` 820; `poll_descriptor/mod.rs` 7312 (read-only) | `wc -l`, `du -sh` |
| B12 | PR #10544 file overlap with this issue | 0 paths (that PR: Makefile + 2 docs + 2 Go files; this issue: `userspace-dp/src/afxdp/**` only) | PR body Files(5) vs §2.2 map |
| B13 | Fix touch estimate (strategy §4) | fixtures: ~2 snapshot fns + arrival-row audit (~13 files read, ~6 edited); builders: 5 fns + ~165 call sites across ~30 files; drivers: 2-3 fns + guards; tests: 0 outcome asserts weakened | B6-B9 fan-out; exact file list at implementation |
| B14 | Go gate live proof | `TestStructMetricIsTypesNotFields6937` FAIL (CompileResult 32f/21t vs floor 20) | RUN §2.1 |

Evidence sources: in-repo source census for B2/B6-B10, `wc -l`/`du -sh` for B11,
and the internal issue/PR records (`issue://10504`, `pr://10544`) for B4/B12.
