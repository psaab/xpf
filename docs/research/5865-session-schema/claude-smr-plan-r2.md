# Claude SMR — plan review r2 (#5865)

Reviewing `plan.md` v2 @ `e8aaa5e1be5f`. v2 is a full rewrite after Codex r1
PLAN-KILL. Hostile pass on whether v2 resolves the r1 findings and whether it now
holds together.

## Verdict: PLAN-READY-WITH-NITS (2 refinements)

v2 resolves the r1 PLAN-KILL. The producer inventory (P1–P5) is the right frame,
the mixed-version retraction is correct and evidence-backed, and the export
truncation + resurrection defects are captured. Two refinements below sharpen the
recommendation and the fail-closed scope; neither is architectural.

## R1 findings — all addressed

- **Third producer (P4 sweep):** captured in Section 3 with the correct
  mechanism (BPF-compat store, `app_timeout=0`, fresh generation wins the guard,
  ABI cannot carry counter/NAT64). ✓
- **Mixed-version reachable:** Section 8 retracts the v1 rebuttal with the
  `system dataplane binary` + `manager_ha.go:458-472` upgrade-lag evidence and
  adopts a capability gate + fail-closed. ✓
- **Export truncation (P3):** Section 3/6 — fail-closed on the 4096 overflow. ✓
- **Resurrection:** Section 3/6/13-Q5. ✓
- **Factual corrections:** export source = worker `SessionTable` (Section 6.
  note), CLOSE deltas populate the fields (6.3), `0.0.0.0` vs empty (9),
  mandatory shared helper (6.2), `protocol_wire_v1.json` fixture (6.6), node→node
  `PolicyID` is fixed-payload (7). ✓

## Nits (fold into v3; not blockers)

### N1 — Phase 1's *standalone* steady-state value is marginal; couple B+C or relabel

The plan presents Phase 1 (additive JSON + capability gate + export fail-closed)
as a shippable first increment. Pressure-test what Phase 1 alone actually buys in
steady state: P4 re-degrades every ≤60 s regardless, and P4 **also clears the log
flags** (`publish_conntrack.rs` `log_flags: 0`) and zeroes AppTimeout /
PolicyCounterIdx / NAT64 source. P4 keeps only `PolicyID`. So after Phase 1:

- The JSON reconcile (P2) stops clobbering `PolicyID`/log flags — **but P4
  already preserved `PolicyID`, and P4 keeps clobbering everything else every
  60 s.**
- Net standalone steady-state gain of Phase 1 over status quo is **small**: it
  removes P2 as a degrader but leaves P4 dominant.

Phase 1's real value is (a) de-risking the eventual Phase 2, (b) correctness
during the brief pre-first-sweep window, and (c) genuine stream-loss cases.
Recommendation sharpening: **couple B+C** (land them together), or explicitly
relabel Phase 1 as a *de-risking increment*, not a partial fix a user would
perceive as materially improving failover correctness. The plan already says
"must not be represented as closing #5865" — extend that to "Phase 1 alone barely
moves the steady-state needle; the meaningful win requires Phase 2." This changes
the recommendation's emphasis, not its content.

### N2 — "incapable helper" must mean incapable on the AUTHORITATIVE path too

Section 8's fail-closed says "refuse JSON HA admission/export from an incapable
helper." But a helper old enough to omit the JSON keys is very likely also older
than #3301/#4565 and therefore **omits the same fields on the binary path** —
"refuse JSON, fall back to binary" then rescues nothing. The capability gate must
be defined as: *does the helper provide complete session metadata on the
authoritative (binary) transport at all?* If not, the daemon must **fail closed
on HA session sync entirely** (keep takeover/resync unready) for that helper, not
merely switch transports. State this explicitly so the gate isn't mis-scoped to
"JSON-only."

## Stress-tested and found sound

- **Producer inventory completeness.** P1–P5 covers the session-install
  producers; the binary bulk export (`export_all_sessions`, #4054) is the
  complete producer Phase 2 leans on. I could not find a sixth session-install
  writer on the userspace path.
- **Units / NAT64 parity** (Section 9) matches the binary encoder; the shared
  helper (6.2) is the right mechanism and is now mandatory.
- **Test plan** (Section 11): the "sweep-after-install no re-degradation" and
  "no-resurrection" sequence tests are the load-bearing regression guards, and
  the shared-projection golden test correctly supersedes v1's field-name-list
  test (which could not detect a *new* binary field).

## Required for PLAN-READY

Fold N1 (sharpen the phase recommendation toward coupling B+C / relabel Phase 1)
and N2 (capability gate scope). The open questions Q1–Q6 are legitimate
/engineer-phase decisions, not plan blockers. Pending Codex r2 concurrence.
