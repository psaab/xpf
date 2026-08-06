# Claude SMR — hostile plan review r3 (#4626 L01)

Reviewing `plan.md` @ `65c87b7e0` (v3.1, Path D recommended). Written against my
own revision as an adversary.

**Verdict: PLAN-READY-WITH-CONDITIONS.** The design is sound and the two prior
recommendations were correctly killed. Three specification gaps remain; each is
a concrete addition to the plan, not a redesign, and I state them as conditions
rather than nits because two of them are on the edit most likely to reintroduce
#6851's defect.

I checked the following things that could have failed and did not, so this is
not a soft pass:

- **No production code compares `LogFlags` by equality or bitmask-equality.**
  `grep -rn "LogFlags ==|LogFlags !=|\.LogFlags)" pkg/ --exclude '*_test.go'`
  returns **nothing**; the only equality is a round-trip assertion in
  `pkg/cluster/sync_test.go:373`, which a new bit still satisfies because it
  round-trips. So the "an old node ignores an unknown flag bit" claim
  (§11 Q3″) holds on the Go plane — a strict decoder or byte-equality consumer
  would have killed the carrier and there is none.
- **No production code branches on a session's `policy_id` being zero** in
  either plane (r1 §S4, re-checked at v3.1). So the discriminator's blast radius
  really is name resolution plus clear membership.
- **The carrier resolves.** `LogFlags` is synthesised Go-side from named delta
  booleans (`daemon_ha_userspace_convert.go:373-379/477-480`), so
  `publish_conntrack.rs`'s hardcoded `log_flags: 0` is not the blocker it
  looked like — and the delta struct already carries three sibling booleans, so
  the pattern exists.

---

## C1 (CONDITION) — the plan does not specify the conditional render form, and "make all three conditional" is WRONG

§7.3 says `UnattributedPolicyID`'s arm "must now be conditional on the
discriminator" and calls it the most delicate edit, then stops. That is the one
place a plan must be concrete, because there are three resolvers with three
different correct answers:

- **`ReservedPolicyName(id)`** is documented as the SSOT for "which ids must
  never reach a name map". Under Path D, `0` is no longer unconditionally
  reserved, so this function **can no longer answer for it**. Correct shape:
  narrow `ReservedPolicyName` to `DefaultPolicySentinelID` only, and add a
  separate attributed-aware entry point. Leaving `0` in `ReservedPolicyName` and
  bolting a condition onto its callers spreads the decision across call sites —
  exactly what the SSOT exists to prevent.
- **`SessionPolicyName(policyNames, id)`** gains the discriminator and returns
  `unattributed` when `!attributed && id == 0`, else consults the map. The
  reserved-before-lookup ordering stays load-bearing: `policyNames[0]` is
  populated, so any form that consults the map first restores the
  misattribution while still looking like a guard.
- **`PeerSessionPolicyName(peerName, id)`** — and this is the one a mechanical
  edit gets wrong. It must **also** take the discriminator, and override to
  `unattributed` only when `id == 0 && !attributed`. Reasoning: a
  **pre-#6851** peer resolves its own id-0 sessions through its populated map
  and sends **the first policy's name as data**, which is precisely the bypass
  #6851 documents; the local guard is the only thing that catches it, and under
  Path D the discriminator is what tells us to. Conversely a peer at #6851 or
  later already sends `unattributed`, and a Path-D peer sends the real name for
  its genuinely-attributed first-policy sessions — both of which must be kept.
  So: **not** "trust the peer now that we have a bit", and **not** "keep the
  unconditional override".

The plan must write these three forms out, and name the wrong-but-plausible
variants (map-first; unconditional override retained; peer trusted whenever
`peerName != ""`), because each is a one-line edit that passes review by
looking like a guard.

## C2 (CONDITION) — the `(N,false)` test cell must be built as a PEER-SYNCED row

§9.2 makes `(policy_id=N, bit=false)` the cell that binds the `!= 0` arm. The
logic is right — under `attributed && ...` that row stops being swept and the
test reds. But the cell is only meaningful if the fixture constructs it the way
production does: a **locally installed** session always has the bit set, so a
fixture that builds `(N,false)` through the local install path is describing a
state production never produces, and its mutation result says nothing about the
real population. The row must be built through the **peer-import** path.

This is the same class as "a fixture must alias like production": the cell is
the old-peer case, so it has to be an old-peer row.

## C3 (CONDITION) — the `SessionDeltaInfo` prerequisite is load-bearing for Path D's payoff, not just quality

§5.5 sequences the `SessionDeltaInfo` gap first and calls it "independently
worth doing". Under Path D it is stronger than that. If the fallback path keeps
carrying no policy id, every session it learns arrives as `(0, false)` and reads
`unattributed` — fail-safe, yes, but it means **that path permanently
under-attributes real policy-admitted sessions and permanently exempts them
from the deletion-clear**, which is the exact defect this issue exists to close,
merely relocated from "the first policy" to "whatever the fallback learned".

The plan should say so plainly: without the `SessionDeltaInfo` field, Path D
fixes the first policy and leaves a second population unattributed. That
promotes the prerequisite from sequencing preference to a required part of the
change, and it means the two must ship together or in that order — never the
reverse.

## Minor — one framing correction the plan should make

§5.0's intra-node channels (orphan helper on the unauthenticated event socket,
pinned-map flush dependence) were analysed as sources of **wrong-space ids**
under B′. §8 now says that under D they "drop from blocking to hardening"
because nothing changes space. That is right, but the plan should also say what
they *do* mean under D: an orphan helper feeds rows whose discriminator bit is
absent, so they read `unattributed`. Fail-safe, and therefore genuinely not
blocking — but the reader should be told the answer rather than told the
category changed.

---

**Verdict: PLAN-READY-WITH-CONDITIONS** — C1 (write out the three resolver
forms and their wrong variants), C2 (build the `(N,false)` cell through the
peer-import path), C3 (state that the `SessionDeltaInfo` field is required for
the payoff, not optional). None changes the design; all three are things an
implementer would otherwise have to re-derive, and C1 is on the edit with the
highest chance of silently restoring the defect #6851 fixed.
