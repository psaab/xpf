# Claude SMR — hostile plan review r2 (#4626 L01)

Reviewing `plan.md` @ `12ea93354` (v2, recommendation flipped to Path B′).
Written against my own revision as an adversary.

**Verdict: PLAN-NEEDS-MAJOR.** v2 corrected v1's factual errors, but its
*decisive argument* for the new recommendation does not survive contact with the
alternative it dismisses. I over-corrected toward the round-1 reviewer's
position.

---

## T1 (MAJOR) — the "default-value safety" argument does not discriminate B′ from D

§5.5 item 1 is the load-bearing reason v2 flipped:

> Under Path B′ every such zero reads as `unattributed` — fail-safe. Under Path
> C every such zero becomes a confident first-policy attribution — fail-dangerous.

That comparison is correct **and it is against Path C only.** Run the same test
against Path D with the corrected predicate `effective_attributed = policy_id !=
0 || attributed_bit`:

| Producer behaviour | Path B′ | Path D (corrected predicate) |
|---|---|---|
| Field forgotten / defaulted → `policy_id = 0`, bit clear | reserved → `unattributed` | not attributed → `unattributed` |
| Real non-zero id, bit forgotten | attributed correctly | `policy_id != 0` → attributed correctly |
| Real first policy, bit forgotten | attributed correctly (id is 1) | under-claim → `unattributed` (safe) |

**Every cell of Path D is fail-safe too.** The bit's zero value is the safe
value, and the corrected predicate means a forgotten bit can never *remove*
attribution from a non-zero id. So §5.5's argument 1 is true of B′ vs C and
silently generalised to B′ vs everything. That generalisation is what carried
the flip, and it is not sound.

## T2 (MAJOR) — with T1 removed, the remaining discriminators favour Path D

Re-running the comparison honestly:

| Axis | B′ | D |
|---|---|---|
| Default-value safety | safe | safe (T1) |
| Externally visible change | **Index, RT_FLOW ids and structured `policy_id` all shift by one** | **none** |
| Mixed-version window | needs a peer capability + ingress normalisation + egress downgrade | **none at all** — no id changes meaning, so an old peer's non-zero ids still resolve correctly on a new node and vice versa; only the id-0 population differs, and it degrades to today's behaviour in both directions |
| Day-one removal of both `continue` exclusions | after normalisation lands | yes, for locally installed sessions |
| Self-describing wire scalar | yes | no — a reader of `policy_id` alone still cannot tell |
| Snapshot self-consistency | yes — `policy_id,omitempty` stops omitting the first rule's id, which is *why* `DuplicatePolicyId` must exclude 0 | no — the first rule still serialises no id |
| Literal issue request | yes | no |
| Planes touched | numbering SSOT + 21 sites to classify + 2 ingress doors + 2 egress paths + capability | Rust `SessionMetadata`, event flags, JSON fallback, Go→Rust import, BPF publication, RT_FLOW codec, display/clear predicate |

The third row is the heavy one. §5.1 spends the plan's strongest analysis
establishing that the mixed-version hazard is *the* reason this issue was
deferred twice — and **Path D does not have one.** B′ answers the hazard with a
bidirectional translation layer that exists nowhere else in this codebase and
that must be maintained across any future numbering change. D answers it by not
creating it.

The second row is the next heaviest, and §6 already concedes it: B′ moves an
operator-facing Index and a durable audit field for every policy, to fix an
ambiguity affecting one.

**Provisional position: the recommendation should move to Path D**, with B′
documented as the runner-up chosen if reviewers weight the self-describing
scalar and the literal request above the numeric shift and the translation
layer. I am recording this as provisional rather than editing the recommendation
a second time in one round, because a plan whose recommendation oscillates each
round is signalling that the *knob* is wrong, not that the answer is converging.
The r2 Codex leg is being asked this question directly (plan Q9); the r3 fold
should settle it with two independent reads rather than a third unilateral flip.

## T3 (MAJOR) — Path D's costs are understated in v2 as well, and I verified one

§5.4 Path D says the bit can ride a free `LogFlags` bit at zero wire cost. The
cross-chassis carriage is real (`sync_protocol.go:170/285` encode, `:455/586`
decode; bits 2-5 free per `types.go:947-958`). But the shim→Go publication path
**hardcodes the byte to zero**: `log_flags: 0` at
`userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs:240` and `:382`. So the bit
cannot ride `LogFlags` from the helper to Go without first making that path
carry real flags — which raises its own question (what do the existing
`LogFlagSessionInit`/`SessionClose` bits do on that path today, if the byte is
always zero there?). Path D's plumbing estimate must include this, and the
question above should be answered before D is recommended, not after.

## T4 (MINOR) — §5.5's sequencing claim needs the window worked

§5.5 says the `SessionDeltaInfo` policy-id gap should land first because under
B′ a manufactured zero is harmless. True at the *end* state. But between the two
changes there is a window where the fallback stamps a real id under the OLD
numbering into a node running the NEW numbering — precisely the cross-space
condition the whole plan is built to prevent. Either the gap lands strictly
after the renumbering, or it lands first and stamps 0 (not a real id) until the
renumbering ships. The plan asserts an ordering without working that window.

## T5 (MINOR) — "MED" behavioural risk for B′ is generous

§8 rates B′'s behavioural-regression risk MED. During the upgrade window B′
reinterprets *every* peer-synced id until normalisation is active on both sides,
and the containment depends on a capability, two ingress doors and two egress
paths all being correct simultaneously. Against a codebase where §5.0.1 just
found a production path that silently drops the field entirely, HIGH is the
honest rating. A risk table that rates the recommended path lower than the
evidence supports is the table doing advocacy.

## What v2 got right and should keep regardless of the outcome

- The §5.0.1 finding stands on its own: `SessionDeltaInfo` carries no policy id,
  the fallback loop runs on a production cadence, and real sessions are stamped
  0 today. **File it as its own issue whatever this plan converges to.**
- The §5.2 retraction is correct and important: a uniform `+1` is
  arithmetically clean, costs no capacity, and the `divmod` objection was a
  namespace conflation.
- The second exclusion at `daemon_policy_invalidate.go:443-447` is real and any
  plan that names only the first is incomplete.
- The corrected Path D predicate (`policy_id != 0 || bit`) is necessary; v1's
  `attributed && ids[id]` would have stopped sweeping every non-zero id from an
  old peer.

---

**Verdict: PLAN-NEEDS-MAJOR** — T1 removes the flip's decisive argument, T2
shows the remaining discriminators favour Path D, T3 adds a verified cost to D
that must be priced before recommending it, T4/T5 are corrections to the
sequencing claim and the risk table. Fold with the r2 Codex leg and settle the
B′-vs-D choice with two independent reads.
