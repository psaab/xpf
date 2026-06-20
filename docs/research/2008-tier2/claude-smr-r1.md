# Claude-SMR r1 — hostile self-review of the #2008 Tier-2 research plan

Adversarial pass over `plan.md`. I tried to break my own dispositions, not
confirm them. Verdict per gap + an overall confidence call.

## Overall confidence: HIGH on the shipped/un-shipped split and the M5/M6
disposition; MEDIUM on M7 effort and the H13 Stage-2 framing; the one I am
least sure about is **M1's value-grade** (could be a clean reject or could hide
a real configstore divergence I did not prove).

## Per-gap hostile check

### M5 — confidence HIGH
- **Verified, not trusted.** `app_id: 0` hardcoded at `publish_conntrack.rs:175`
  and `:277` (grep, both arms). `AppNames` built at `compiler.go:526-545` and
  consumed at `server_sessions.go:149/195/602/625` — grepped, real. Catalog
  ship to Rust: `grep AppNames|app_catalog userspace-dp/` = **empty** —
  confirmed dead end-to-end.
- **Hole I checked:** is the catalog maybe shipped under a different name (e.g.
  embedded in `application_terms`)? No — `application_terms`
  (`policy.rs:236`, `parse_applications`) is the *per-policy* application set
  used for boolean policy match, with no numeric app_id. `CompiledApplications`
  is a `bool` matcher. So app_id is genuinely absent from the wire. Solid.
- **Residual risk I'm flagging:** the issue-body sketch cites
  `publish_conntrack.rs:107` and `xdp_policy.c:resolve_pkt_app_id` — the latter
  is **deleted (#1476)**. My plan re-grounds M5 on the userspace path, which is
  correct, but a reviewer trusting the issue line numbers will be confused. I
  called this out in the plan. Good.
- **One thing I did NOT verify:** whether stamping a non-zero app_id into the
  conntrack value has any HA session-sync wire implication. `mod.rs:159,206`
  already define `app_id: u16` in the sync value, so the field exists — but I
  did not confirm the Go session-sync decoder reads/writes it symmetrically. If
  it doesn't, M5 could need a small sync-path touch. **Effort stays M; flag for
  the implementer to verify the sync round-trip.** This is the one M5 unknown.

### M6 — confidence HIGH (on "large, defer")
- `grep alg_type userspace-dp/src` → only writer + tests, no consumer.
  `grep pinhole|expected_session|child_session` → empty. `feature-gaps.md:234`
  states it outright. The "this is large and unimplemented" call is rock-solid.
- **Self-criticism:** I left M6 as an option-level "decision needed" rather
  than forcing a plan. That is correct per the task ("lay out options, flag for
  decision") — but a reader wanting a yes/no won't get one. I stand by deferring;
  forcing a stateful-ALG plan here would be over-reach without a known consumer.

### M7 — confidence MEDIUM
- Literal equality at `engine.go:155`, 2-field whitelist at `:146-153`,
  `attributes-match` schema `children: nil` at `schema_system.go:659`,
  event struct 3 fields at `rpm.go:95-99` — all grepped/read, real.
- **Where I could be wrong:** I graded it "S–M, recommend S scoped to regex."
  The risk is the regex change is *not* purely additive — switching literal→regex
  silently changes the meaning of every existing `attributes-match` value
  (a literal `foo` is now a regex `foo`, which still matches `foo` but ALSO
  matches `foobar` as a substring unless anchored). **That is a behavior change
  for existing configs**, and Junos `matches` is regex (so it's the *correct*
  behavior), but it's not the no-op "swap" my plan's tone implies. The plan
  should (and the implementer must) treat anchoring/substring semantics
  deliberately and test it. I'm downgrading M7 confidence to MEDIUM on this
  basis and noting it here as the key M7 trap.
- Effort: still S for the code; the semantics-care + tests are what make it
  feel M. Net: keep it as Increment-2 item #1 but it is not as trivial as
  "literal→regex one-liner."

### M1 — confidence LOW-MEDIUM (deliberately)
- Parse/store/warn all verified (`compiler_system.go:126`, `types_system.go:47`,
  `compiler.go:1280`). The *gap exists*. What I could NOT do without a live
  experiment: **prove** whether xpf's eager group expansion already produces
  the same operator-visible result as Junos's persisted inheritance. My plan
  says "likely reject, prove equivalence first" — that's honest, but it means
  M1's disposition is genuinely unresolved, not concluded. I am flagging M1 as
  **the gap I could not fully classify**: it's either a clean
  reject-with-warning or a real configstore feature, and distinguishing them
  needs an apply-groups diff experiment I did not run. Correctly kept out of
  Increment-2.

### H13 — confidence MEDIUM-HIGH (Stage 1) / MEDIUM (Stage 2 framing)
- Absence verified (grep empty across pkg + userspace-dp). Accept-as-leaf via
  `ast_edit.go:151-165` no-schema-match path — verified. Busy-poll runtime
  verified (`userspace-dataplane-architecture.md:576,616`, poll loop in
  `poll_descriptor/mod.rs`). The Stage-1 schema+warn quick win is safe and
  correct.
- **Where I'm least sure:** I asserted "dataplane sleep maps onto NAPI-defer /
  idle-yield." That is my **inference** about Junos semantics, not a verified
  fact — I did not find Junos documentation in-tree defining exactly what
  `allow-dataplane-sleep` does (power state? PCIe ASPM? worker yield?). Stage 2
  could be a different mechanism than I sketched. This does **not** affect the
  Stage-1 recommendation (schema+warn is right regardless), but the Stage-2
  design sketch is speculative and I labeled it lab/needs-design precisely for
  that reason. A reviewer should not treat my Stage-2 mechanism as authoritative.

## Cross-cutting checks

- **Did I miss a Tier-2 gap?** The task names M1/M5/M6/M7/H13. I confirmed each
  is still un-shipped and did not silently drop any. H6/H1/Increment-1 correctly
  excluded as shipped (git log cited). No scope creep.
- **Did I over-promise any "feasible-increment"?** M5 is the one to watch — I
  graded it feasible-M but it touches the wire protocol + Rust hot path + wants
  a smoke run + possibly the sync round-trip. It is feasible but it is the
  *largest* of the three Increment-2 items; I ordered it last for that reason.
  M7's "S" hides the regex-semantics care (noted above). H13 Stage 1 is the
  cleanest.
- **Recommendation integrity:** Increment-2 = {M7-regex, H13-Stage1, M5}.
  Deferred = {M6, H13-Stage2, M1}. I'm confident in the *partition*; the
  residual uncertainty is in effort-precision (M5/M7) and M1's ultimate verdict.

## Things a hostile reviewer should still demand before engineering
1. **M5:** confirm the HA session-sync path reads/writes `app_id` symmetrically
   (the one unverified plumbing link).
2. **M7:** decide anchoring/substring semantics explicitly and test it — the
   regex switch is NOT behavior-preserving for existing literal values.
3. **M1:** run an apply-groups expansion diff (xpf vs expected Junos persisted
   form) to settle reject-vs-implement before any code.
4. **H13:** find an authoritative definition of Junos `allow-dataplane-sleep`
   semantics before Stage 2; Stage 1 needs no such gate.
