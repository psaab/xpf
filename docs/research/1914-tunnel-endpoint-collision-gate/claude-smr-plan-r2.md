# Claude SMR hostile plan review — #1914 r2

**Reviewer:** Claude (domain SMR + design). HOSTILE follow-up.
**Verdict: PLAN-READY** — every r1 finding (mine + Codex's + AGY's) is
resolved by a mechanism I verified against the code; no new fatal issue.

## My r1 findings — disposition

- **SMR F1 (view-1 narrowing unsound):** RESOLVED. §3.5-O1 + §4.2 now keep
  view 1 byte-identical (presence-only union); Defect-B residual is
  document-only. The split-supply and un-applied-nested-group
  counter-examples no longer apply because nothing narrows view 1.
- **SMR F2 (peer-group error fatal):** RESOLVED. §4.3 makes a failed
  per-node expansion contribute the empty set, symmetric on both nodes,
  preserving the node0-fallback.
- **SMR F3 (emitter package-purity):** RESOLVED. §4.1 mandates a config-pure
  emitter + builder intersects runtime ifaces; differential parity test
  mandated.

## Codex/AGY r1 findings — disposition (cross-checked)

- **Recursion + post-`usedIDs` readback (Codex F1 / AGY F2):** RESOLVED and
  VERIFIED. §4.2 routes views 2/3 through `compileInterfaces`, which I read:
  `compiler_interfaces.go:25` — ZERO references to the gate or
  `StableTunnelEndpointID` (`grep -c` = 0). So no recursion. The emitter is
  pre-`usedIDs` by construction (§4.1), so both colliders survive to the
  fold check → Defect A is caught.
- **Per-node error / node0-fallback (Codex F3 / AGY F1):** RESOLVED by §4.3.
- **Config-pure emitter (Codex F4 / AGY F4):** RESOLVED by §4.1.

## New hostile probes (r2)

1. **Does centralizing into one emitter risk diverging from the existing
   two sites?** NO — and r2 actually REDUCES drift vs r1. The emitter
   consumes the TYPED `*config.Config.Interfaces` (post-`compileInterfaces`),
   exactly the builder's domain. The AST-level canonicalization the #1910
   r2-r6 work hardened (leading-zero `unit 01`→1, overflow→bare ref,
   last-wins duplicate-unit) is ALREADY applied by `compileInterfaces` when
   it builds the int-keyed `Units` map — so the emitter never re-implements
   it. The emitter only reproduces the builder's iteration + non-WG src/dst
   gate + WG single-lowest-unit pick (`tunnels.go:138-191`). View 1's
   AST collector (which DOES carry the canonicalization) stays unchanged.
   The differential parity test (§6.6) pins emitter==builder-configured-set.
   Verified the typed map is int-keyed and last-wins is a compile-time
   property, so the emitter inherits it for free.
2. **Symmetry under the three-view union:** both nodes compute V1 (identical
   AST union) ∪ V2 (clone+expand node0, identical input) ∪ V3 (clone+expand
   node1, identical input), with identical error→empty handling. The union
   is a pure function of the candidate bytes. Confirmed no divergence path
   (matches Codex Info F5).
3. **Monotonicity:** the union only ADDS refs vs today's view-1-only gate,
   so it can only ADD rejects — it cannot start ACCEPTING a config the
   current gate rejects. The only relaxation is via NOT registering view-1
   phantoms, which r2 explicitly does NOT do (view 1 unchanged). So no
   regression in the reject set; pure strengthening for Defect A. Good.
4. **Lenient severity:** §6.2 keeps wildcard collisions warning (not error)
   on the lenient load/peer-sync path so an already-active config boots.
   Correct.

## Residual (accepted, documented)

Defect B's un-applied-group incomplete-non-WG phantom false-reject survives
(joint probability 1/65535 × half-configured-and-never-applied). §3.5-O4 +
§9 document it; the runtime belt is the backstop. This is the correct
trade — the alternative (narrowing view 1) provably re-opens a false-accept,
which is strictly worse. I am satisfied this is the right design call.

**PLAN-READY.** The design is sound, recursion-free, HA-symmetric, and the
SSOT factoring reduces (not increases) the historical drift risk.

---

## SMR r2 self-correction (post Codex r2)

I returned PLAN-READY for r2 but MISSED that "Defect B fixed for
applied-group cases" was false — Codex r2 F1 proved (and I re-verified live:
`gr-0/0/0.0`/`wg29715.0` both fold 44687, applied-group config still
false-rejects) that view 1's unchanged presence union over-registers for
APPLIED groups too, not just un-applied. Defect B is document-only entirely.
I also missed that the emitter must return `{Name, *TunnelConfig}` for the
builder. Both corrected in plan r3. My monotonicity argument stands; my
"reduces drift" argument stands; the design is sound — but my Defect-B
scoping claim was wrong and Codex was right. Per the project's
SMR-soft-pass watch (`feedback_triple_review_includes_claude_smr`), this is
exactly the self-correction the hostile cross-check exists to catch.
