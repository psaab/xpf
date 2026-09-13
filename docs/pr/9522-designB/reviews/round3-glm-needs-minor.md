# Adversarial PLAN review — ROUND 3 (FINAL, GLM)

**Target:** `docs/pr/9522-designB/plan.md` v3 @ `d8b87a3` (branch `fix/9522-learned-route-cap`, base `7ef226474`). All claims re-verified against head, not against v2's text.

---

## A. Round-2 closure verification (hostile)

**R2-1 (pre-bump serialization + NAK re-pair) — CLOSED in mechanism, one enumeration error (→ R3-1).** The RMW is real and exactly as v2 described: mint before `m.mu` at `pkg/dataplane/userspace/manager_generation.go:56-57`, unsynchronized shim RMW underneath. v3's `fibGenMu` held across {mint + send} for bumps AND transfer commits, plus the serial control socket (single-writer `requestLocked` discipline), makes mint-order = wire-order = helper-processing-order. The NAK re-pair rule (bump with current map value; equality admitted by the `<`-fence at `userspace-dp/src/afxdp/coordinator/mod.rs:1694-1701`) closes the shim-ahead residue. The Q1 consumer audit checks out against head: snapshot stampers are readers gating monotone-≥ (`server/handlers/snap…

**R2-2 (version fork, resolution (a)) — CLOSED.** `CONFIG_SNAPSHOT_PROTOCOL_VERSION = 16` confirmed with the Go lockstep-guard line intact (`userspace-dp/src/protocol/control.rs:131`); omitempty status-field precedent confirmed (`pkg/dataplane/userspace/protocol_status.go:78`); unknown-verb refusal arm is stateless per request, now at `server/handlers/snapshot.rs`-sibling `userspace-dp/src/server/handlers/mod.rs:360-363` — the "Go-side latch backstop, not helper behavior" framing is truthful. All four matrix rows are reachable and each row's claim is true under no-bump; I additionally traced the subtle rollback row: even WITHOUT helper restart, old-Go snapshots carrying learned-in-band coexist with a leftover retention partition correctly, because app…

**R2-3 (three rebuild paths) — CLOSED.** §5-1.7 names reconcile apply, armed same-plan refresh, disarmed twin; M2 no-wipe cell pins all three.

**R2-4 (ban scoping) — CLOSED.** Transfer-time gap-fill stays Go-computed (`pkg/dataplane/userspace/routes.go:740-853`, `learnedRouteGapKey` at `:878-883` canonicalized through `canonicalRoutePrefix`, `:513-518`); apply-time suppression is exact-key equality — different object, correctly un-banned.

**R2-5 (status pair) — CLOSED.** Commit critical section now sets `guard.status.last_fib_generation`, matching the existing assignment/restore discipline verifiable at `server/handlers/snapshot.rs:206-210` (and every rollback leg `:254-255, :325-326, :372-373, :434-435, :467-468`).

**R2-6 / R2-7 / R2-8 — CLOSED as written** (config-abort leg + honest quiet-window bound in §5-1.9/M1; latch as backstop in §5-Phase-3; echo-primary framing in §5-1.8).

---

## B. New findings

### REQUIRED (text-level; zero architectural content)

**R3-1. Q1's minter enumeration misses a live call site — the route-leak commit tail.** The plan's Q1 lists "ipmon `pendingFIBBump`, CompileConfig tail, transfer pre-bump" and demands "enumerate all three call sites or kill." At head there are **four** minters (three existing + the new one):

1. ipmon actuator — `pkg/daemon/daemon_ipmon.go:375` (documented under `d.applySem`, `:370-374`);
2. **route-leak commit tail — `pkg/daemon/daemon_apply_routing.go:426`** (the #5696 M19 fail-closed leg; named with its error treatment in the interface contract at `pkg/dataplane/dataplane.go:392-409`, which the plan never cites);
3. CompileConfig tail — `pkg/dataplane/compiler.go:466` → `compiler_fibgen.go:47`;
4. the new transfer pre-bump/commit.

All three existing sites funnel through `userspace.Manager.BumpFIBGeneration` (directly, or via `legacy_dataplane.go:302-308`), and the mint lives *inside* that method. So the sequencer's home decides coverage: placed **inside `Manager.BumpFIBGeneration`** (wrapping mint + bump-verb send) plus the transfer commit sender, "ALL minters through ONE sequencer" is true by construction and the missed call site is harmless; placed at daemon call sites, the leak tail is a silently missed minter — precisely the R2-1 failure mode. The plan never states where `fibGenMu` lives. **Fix (one paragraph):** answer Q1 in-plan with the four-site enumeration, cite `dataplane.go:392-409`, name the sequencer's home (inside the Manager), and add a source-walk guard test in th…

**R3-2. Strict-freshness refusal recovery is under-joined: duplicate detection must key on `last_committed`, not on any-seen commit — and the plan must say so.** Trace the interleave the prompt asks about: a status-tick full apply (stamping `readFIBGeneration()`, `manager_compile.go`-class sender, no `fibGenMu` — it doesn't mint) can read the freshly minted G+1 and write its `apply_snapshot` between the commit's mint and its socket write (two different mutexes order those two writes arbitrarily). Helper processes the apply first (validation fib → G+1, benignly admitted), then refuses `route_commit(G+1)` on strict `>`. Now: the NAK re-pair rule (equality bump) can **never** unblock a same-fib retry — G+1 is not > G+1 — so the only recovery is a r…

### MINOR

**R3-3. 90 s staging expiry semantics unspecified vs the plan's own budgets.** If total wall-clock from first chunk, a legitimate 1 M-route transfer (≈25–100 chunks × the plan's own 500 ms p99 per-chunk ceiling ≈ 12.5–50 s, plus socket/status contention measured in M1) brushes 90 s ⇒ abort + re-arm, potentially looping under load. State it idle-based (reset on each accepted chunk) or justify ≥ 2× the measured worst-case transfer. One line in §5-1.1.

**R3-4. Citation drift + Q3 answer.** `routes.go:789-792` → the file is `pkg/dataplane/userspace/routes.go` and the covered-set/gap logic sits at `:839-856`/`:878-883`; refusal arm is now `mod.rs:360-363` (was :339-342); `<`-fence at `coordinator/mod.rs:1694-1701`. On Q3: yes — generate the canonical-parity byte-vector fixtures from Go (`canonicalRoutePrefix` vs Rust canonicalization); the failure modes (missed suppression = double routes for one prefix; wrong suppression = silently dropped route) are exactly what cross-language drift produces, and Go-generated fixtures make the corpus mechanical.

**Accepted-risk note (no action):** "unknown nonce ⇒ adopt as epoch" flaps if two live senders hit one socket; excluded by single-writer socket ownership + same-package spawn bounds (`process_identity_restart_8899_test.go`), and matches the #6034 single-writer precedent the neighbor path already relies on.

---

## C. Hostile checks requested — each traced

- **Sequencer covers ipmon/Compile tails?** Yes, *if* homed inside the Manager (R3-1). No other direct shim minter exists (`m.bpfShim.BumpFIBGeneration` has exactly one caller, `manager_generation.go:57`); stampers are readers, gated benign.
- **Strict-freshness vs in-flight bump given serial socket?** Bump-vs-commit is ordered by `fibGenMu` + FIFO socket — sound. The full-apply interleave exists (different mutex), is refused, and converges — after R3-2's two-sentence join.
- **Nonce-fence reset vs replay?** Replayed commit after helper restart hits missing staging ⇒ loud refusal ⇒ echo re-arm (§5-1.5 event present). Replayed chunks after restart are idempotent-store or fenced. Bounded by single-writer reality.
- **Removal-path interim honestly fail-closed?** Yes. The gap the interim covers is *kernel-derived* coverage the helper cannot know (it never sees kernel routes — hence the Go-computed covered set, `routes.go:740-749`); "drops-more, bounded by transfer convergence" is stated in acceptance §2, not smuggled, M2-pinned.
- **Matrix rows reachable?** All four, verified against head anchors above, including the rollback row without helper restart.
- **Thresholds adequate?** M0 ceilings are well-posed (1 M ≥ 65k-master is the right anti-regression bar); ≤2× build/mem, ≤1× staging, ≤500 ms p99 are legitimate measured-gate budgets with kill legs. Only the 90 s expiry semantics need stating (R3-3).

---

## Verdict

**NEEDS-MINOR** — and this is terminal. Every R2 item is closed in mechanism against head; the design has been stable in shape for two rounds and every load-bearing joint now traces to code I re-read this round. The two required items are paragraph-level text closures inside §5-1.4/§5-1.5 and §11-Q1 (four-site minter enumeration with the sequencer's home + source-walk guard test; `last_committed`-keyed duplicate detection + the re-mint recovery leg), plus two one-line minors. None requires rework, none reopens an architectural question, and none justifies a round 4: close them as specified above, verify by diff, and the plan is shippable.
