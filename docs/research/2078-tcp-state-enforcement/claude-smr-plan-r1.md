# Claude SMR — hostile plan review r1 — #2078

Reviewer: Claude SMR (hostile pass). Base verified: `origin/master`
`4565a9ee1` (worktree `0a50ec640`). I re-verified every load-bearing
claim and both companion reviewers' findings against THIS base (not the
user's stale main checkout, which is behind and lacks #2008 M9 — a trap I
fell into once and corrected; see note at end).

## VERDICT: PLAN-KILL (recommend Path C2 — warn-and-document)

The plan's mechanical audit findings are accurate, but the research it was
supposed to do — survey the design space — **missed a decisive piece of
prior art that already answered the question**, and the one new capability
it recommends (Path B) cannot deliver one of its three knobs and rests on a
correctness model that source verification refutes. PLAN-KILL is not a
failure of the research; it is the correct research outcome, and it is the
outcome the project already chose for this exact family of knobs.

## Decisive finding (subsumes most others)

**[BLOCKER] There is an explicit, reviewed, in-source decision to keep this
entire TCP-session knob family config-only — the plan never engages it.**

Verified on the base:
- `pkg/config/types_security.go:110-128` — `TCPSessionConfig` carries a
  *fourth* sibling, `NoSequenceCheck` (#2008 M9), whose comment states the
  posture verbatim: "Typed-config only today, exactly like NoSynCheck /
  RstInvalidateSession: the userspace AF_XDP dataplane does not currently
  perform TCP sequence-number window validation, so there is nothing to
  skip yet. The field captures operator intent at commit ... and is the
  single seam a future sequence-checking dataplane would read."
- `docs/active-active-new-connections.md:840-890` already designed RST
  handling: "Suppress RST→CLOSED for ESTABLISHED sessions. Forward the RST
  to endpoints ... The `rst-invalidate-session` config flag ... overrides
  [it] ... for users who opt in, accepting the stream-death risk. Why
  suppress instead of sequence validation? BPF conntrack doesn't track TCP
  sequence numbers ... most stateful firewalls don't immediately kill
  sessions on RST without sequence validation."
- `8c2a0c3c8 #2008 M9` is an ancestor of the base — this was a real,
  merged, reviewed decision, not a draft.

So #2078 is not an open research question. The project already, knowingly,
chose "capture intent at commit, do not enforce in the dataplane" for the
whole family, *and already reasoned through the RST design the plan
re-derives from scratch in §3/RISK-2*. A research plan that recommends
reversing that decision for two of the four knobs must (a) cite the prior
decision, (b) justify the reversal, and (c) say what happens to
`no-sequence-check` and the suppress-RST model if you ship its siblings.
The plan does none of this. This omission alone is disqualifying for a
research deliverable, and it points straight at C2.

## Confirmed BLOCKERs from both companions (I re-verified)

**[BLOCKER] `no-syn-check-in-tunnel` has no implementable signal.** The plan
maps it to `metadata.fabric_ingress`. Verified: `ingress_is_fabric`
(`userspace-dp/src/afxdp/forwarding/mod.rs:293`) tests the **HA cluster
fabric link** (peer-owned-session cross-chassis redirect, per CLAUDE.md
"Fabric forwarding"), which is semantically unrelated to a Junos IPsec/GRE
security tunnel. `SessionMetadata` (`session/entry.rs:24-29`) carries
`fabric_ingress`/`is_reverse` and nothing tunnel-related; there is no
IPsec/GRE decap-ingress marker on the session-create path. Keying the knob
on `fabric_ingress` would silently relax syn-check for HA fabric traffic — a
latent HA hazard — and never fire on real tunnel traffic. The §6 "SMALL"
cost for this knob is unsupported; Path B as scoped cannot ship this knob.

**[BLOCKER] The install-site / origin model is wrong.** The plan's "gate
forward-create, not reverse" is too coarse. Verified: there are 8
`SessionOrigin` variants (`session/entry.rs`), and install happens with
`ReverseFlow`, `LocalMiss` (host-bound traffic to the firewall itself —
e.g. BGP/SSH re-attach with a non-SYN packet), `ForwardFlow`,
`MissingNeighborSeed`, plus the synced-session import variants. A gate keyed
on "not reverse" would wrongly drop host-bound `LocalMiss` mid-stream
sessions (management/control-plane re-attach) AND must not touch the
SyncImport path (or it breaks HA bulk-sync). The correct discriminator is
`origin == SessionOrigin::ForwardFlow`, which the plan never names. The
plan's line numbers (`poll_descriptor/mod.rs:487/1318/1520/2641`) are stale
by ~45-135 lines and `session/mod.rs` was split into
`install.rs`/`lookup.rs`/`expire.rs` (#2005) — so the entire §2/§3/§9
file:line apparatus is unreliable. The gate IS implementable (it's
`ForwardFlow`), but the plan as written does not demonstrate that.

## My own additional findings

**[MAJOR] The plan's §4 wire-parity-guard claim is wrong.** It says to
"extend" a FlowSnapshot reflection parity guard that exists "for the #1977
NUM_WIDTH siblings." Verified: the #1977 artifact
(`pkg/dataplane/userspace/flow_numwidth_agreement_test.go` /
`schema_validate_flow_numwidth_test.go`) is a numeric range-agreement test;
there is no Go↔Rust field-presence reflection guard, and bools have no
width. The real net is the round-trip decode test (§7). Stop implying a
guard exists. (Verified-favorable: no `deny_unknown_fields` in
`userspace-dp/src/protocol/`, so bool+omitempty+serde-default is genuinely
the #1961-safe subclass — that part of §4 is correct.)

**[MAJOR] Proportionality is the strongest argument and the plan undersells
its own honest case.** The audit rated #2078 LOW. The demonstrated harm is
*silent misleading* (operator sets a knob; it does nothing). C2 (commit-time
warning + a parity-gap doc note, folded across all four family knobs incl.
`no-sequence-check`) removes exactly that harm at zero dataplane risk and is
consistent with the already-chosen posture. Path B, even done correctly,
touches the session-create and session-hit hot paths for two rarely-used
LOW knobs, introduces a no-clean-rollout behavior change (RISK-1), a
spoofable-teardown vector (RISK-2, already documented as the accepted
tradeoff in active-active-new-connections.md), cannot deliver the in-tunnel
knob, and — per the prior decision — would leave `no-sequence-check`
inconsistently still-config-only. I cannot construct a benefit that beats
that risk.

**[MAJOR] RISK-1's recommended gate is incoherent (concur with companion
B).** "No-op unless the tcp-session stanza is configured" is non-Junos
(SRX syn-check is on by default regardless of stanza) and surprising (an
unrelated `established-timeout` set would silently flip syn-check on). The
only honest options are default-on (breaks every deployment that today
accepts mid-stream TCP, incl. asymmetric-routing/ECMP/post-failover synced
flows) or never-enforce. Open question #2 has no clean answer — itself an
argument for C2.

**[MINOR] HA failover test is no-regression, not new-feature.** §7 asserts
`make test-failover` "must pass 14/0," which proves no-regression, not that
syn-check/rst behave under failover (project memory:
"test-failover proves no-regression NOT the new feature"). If B were ever
pursued, the smoke must exercise the NEW path (synced session with no local
SYN; cross-chassis RST-teardown sync), not just assert the gate count.

**[MINOR] Missing observability + completeness.** §7 says "count it" but
names no `show security flow` counter or Prometheus gauge for the
syn-check drops — mandatory for a silent-drop knob per the
account-don't-unwind discipline (`docs/engineering-style.md:184-190`).
Schema completion is ALREADY done (`schema_security.go:243-246` — all
four knobs), contradicting §11/§E's open item; no schema work is needed
for either path.

## What the plan got RIGHT (verified, for fairness)
Dead-map claim (`SetFlowConfig` is `return nil` in the userspace path,
`loader.go:392`; TCPFlags packed into the retired `flow_config_map`); the
FlowSnapshot gap on both Go and Rust sides; no SYN gate at install; RST/FIN
only set `closing` + 30s; `meta.tcp_flags` free on the fast path; the
`state.x = snapshot.flow.x` threading pattern; Path A correctly rejected;
and — to its credit — the plan itself flags C2 as "a defensible PLAN-KILL,"
which is the conclusion all three reviewers reach.

## Recommendation
**PLAN-KILL #2078 with a Path-C2 follow-up:** emit a commit-time advisory
that `no-syn-check`, `no-syn-check-in-tunnel`, `rst-invalidate-session`
(and `no-sequence-check`) are accepted-but-not-enforced on the userspace
dataplane, and add/confirm a parity-gap note in the flow/dataplane docs +
`docs/active-active-new-connections.md` cross-reference. This is consistent
with the existing #2008 M9 reviewed decision, removes the only real harm
(silent misleading), and costs zero forwarding-path risk. The dead
`flow_config_map` TCPFlags write should be removed or comment-retired as
incidental cleanup. If a maintainer later has a concrete operator need to
*enforce* these, re-open with Path B re-grounded on `SessionOrigin::
ForwardFlow`, a real tunnel-decap signal (or drop the in-tunnel knob), a
resolved RISK-1 rollout, observability, and a new-path failover test.

---
*Note on base discipline:* my first source read hit the user's stale main
checkout (`/home/ps/git/bpfrx`, behind origin/master, no #2008) and briefly
suggested companion B had read the wrong tree. Re-checking against the
worktree base (the true origin/master) confirmed companion B was correct and
I was reading the stale tree — the inverse of the usual
[[feedback_verify_agent_branch_base]] trap. All findings above are against
the verified worktree base `0a50ec640` (parent `4565a9ee1`).
