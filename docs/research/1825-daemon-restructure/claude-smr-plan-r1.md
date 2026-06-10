# #1825 plan v1 — Claude SMR hostile review (round 1)

Reviewer: Claude SMR (domain: Go package architecture, control-plane
daemon design, refactoring economics). Target: plan.md @ 33a768abd.
Posture: hostile — I attempted to break the KILL in both directions
before accepting it.

## Verdict: PLAN-READY (Option D — PLAN-KILL), with two required
honesty amendments (below) that do not change the verdict.

## Attacks attempted

### A1 — "The method count is inflated / receiver-name variance"
Re-measured with receiver-name-agnostic grep: exactly **167** methods on
`*Daemon`, all spelled `func (d *Daemon)` (no variance). The plan's
number holds. Additionally found `*rgStateMachine` carries 20 methods of
its own — which *strengthens* the plan's claim that `rg_state.go` is the
self-contained exception, not the rule.

### A2 — "The neighbor measurement is cherry-picked; dhcp is the narrow seam"
Verified: `daemon_dhcp.go` touches only **9** distinct `d.*` members —
the narrowest seam in the package. But it is 215 LOC with 3 methods;
extracting it creates a subpackage smaller than the seam code it would
need. This answers plan Q3: no overlooked narrow-seam cluster of
meaningful size exists. The neighbor cluster is representative of the
clusters the issue actually named (`ha/`, `neighbor/`, `apply/`).

### A3 — "Leaf-callee extraction (Q2) is a cheaper win the plan dodges"
I tried to construct it: move pure free functions called by Daemon
methods (e.g. `rg_state.go`'s state machine, `host_tunables.go` compute
helpers) into `internal/` leaves. This is exactly Option C with the same
cost rows (5-15 exports each, test moves, quad-review PRs) and the same
zero-diagnosed-problem benefit. It is not a distinct cheaper path; the
plan's pricing covers it. No revision needed beyond noting it.

### A4 — "Dry audit is the wrong instrument — file COUNT, not file LOC,
is the complaint"
This is the strongest attack on the KILL. The audit measures per-file
LOC; #1825's complaint is 71 flat files. But the plan's rebuttal
survives: (a) prefix discipline already partitions the namespace; (b)
the only navigational consumers are maintainers with gopls/ripgrep; (c)
no defect has been traced to the layout (I checked the #1769/#1780/#1782
post-mortems — all root causes were logic/concurrency, none were
"edited the wrong file" or "missed coupling because files were
siblings"). Without a defect class, file-count aesthetics do not buy a
multi-PR rewrite or even scheduled Option C churn.

### A5 — "Defer, don't kill (Q5)"
Rejected. The conflict-exposure argument is the *weakest* leg (queues
drain), but legs 1-3 (god-object mechanics, single-importer surface,
dry audit) are time-invariant. A deferral would leave a zombie issue
that re-litigates this research after every queue drain. Kill with
standing guidance is the durable close; if a real defect class emerges,
a new issue with evidence reopens the question cheaply.

### A6 — "Q6: future second consumer"
Speculative. If a second binary ever needs daemon internals, the right
move is exporting a narrow facade then (3 identifiers today proves the
surface stays small), not pre-fracturing the package now. Verdict
unchanged.

## Required amendments (honesty, not verdict-changing)

1. **Section 5.2 should state the receiver-uniformity check** (all 167
   are `(d *Daemon)`) and the `rgStateMachine` 20-method counterpoint,
   so reviewers don't re-derive A1/A2.
2. **Section 9 / Option C table**: add `daemon_dhcp.go` (9 `d.*`
   members, 215 LOC) as the measured narrow-seam answer to Q3, marked
   "too small to justify a package".

## Answers to plan §12 open questions

- Q1: No evidenced defect class found (checked recent post-mortems). KILL stands.
- Q2: Leaf-callee extraction ≡ Option C; already priced. No.
- Q3: dhcp (9 members) is narrower but 215 LOC — value below seam cost.
- Q4: No wedge. A layout-establishing extraction with no diagnosed
  problem is churn that also *invites* follow-on churn (the wedge is the
  point of a wedge). The system/ precedent already establishes the
  pattern opportunistically.
- Q5: Kill, not defer (A5).
- Q6: Speculative; facade-on-demand beats pre-fracture (A6).
