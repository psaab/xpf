# Claude SMR — hostile plan review r1 (#4626 L01)

Reviewing `docs/research/4626-l01-policy-id-zero/plan.md` @ `f78ac55c7`
(base `origin/master` `b8b39a16a`). I authored plan v1; this pass is written
against it as an adversary, not as a synthesiser.

**Verdict: PLAN-NEEDS-MAJOR.** The recommendation is defensible but the plan
(a) accepts a one-release deprecation lag it does **not** have to accept,
(b) claims API preservation it does **not** deliver, and (c) carries an
imprecise count inside the argument a reviewer is being asked to trust.

---

## S1 (MAJOR) — Path C accepts a deprecation lag that HA-ingress normalisation removes

§5.4 Path C states the `continue` at `daemon_policy_invalidate.go:72-77`
"cannot be removed on day one and must lag by a release", and §11 Q4 then asks
reviewers whether that lag makes the whole change worthless. Both are premature:
the lag is an artefact of a design choice the plan did not make.

The reason 0 must stay excluded at release *N* is that an old peer keeps syncing
sessions stamped 0-meaning-nothing. But those sessions enter the local table
through exactly one door — the HA import path. **Normalising at that door
removes the population entirely:** rewrite `policy_id == 0` to
`NoPolicySentinelID` on HA import.

Why this is safe and loses nothing:

- An old peer's non-policy sessions (0 meaning "nothing") become the sentinel —
  which is what they mean.
- An old peer's *first-policy* sessions (0 meaning "policy 1") also become the
  sentinel. That is an under-claim — but it is **byte-identical to what the
  operator already sees today**, because #6851 renders id 0 as `unattributed` on
  every surface anyway, and because those sessions are already never swept by
  the current exclusion. **No behaviour regresses; the ambiguity is simply moved
  out of the table and into the one place that can absorb it.**
- After normalisation, no session in the local table carries 0 unless the LOCAL
  first policy admitted it. So the exclusion can be deleted at release *N*, and
  a first-policy delete correctly clears its own local sessions immediately.

The residual — a peer-synced first-policy session is not swept — is the already
documented #3395 P2 peer-after-reorder residual, not a new class.

This also answers §11 Q4 outright ("if release *N+1* never arrives, Path C ships
pure churn"): with ingress normalisation there is no *N+1* dependency, so the
strongest argument against the recommended path evaporates. A plan that leaves
that argument standing when it does not have to is under-designed.

**Required change:** fold ingress normalisation into Path C, move the
"must lag a release" claim to a *rejected alternative*, and rewrite Q4 to ask
the harder question instead — whether unconditional 0→sentinel rewriting on
import is the right call versus gating it on a peer capability, and what it
costs once BOTH nodes are new (a new peer's first-policy sessions would also be
flattened to the sentinel, which is a *display* under-claim that does not exist
today for a same-version pair).

## S2 (MAJOR) — §6 "Public API preservation" overclaims

§6 lists what is preserved and omits the one thing that genuinely changes:
**the numeric `policy_id` value that non-policy sessions expose on structured
surfaces.** It goes from `0` to `4294967294` on:

- the CLI session row (which prints `Policy name: <name>/<id>` — the *name* is
  unchanged, the *id* is not),
- the REST session objects (`pkg/api/sessions.go`) and the gRPC session entries
  (`pkg/grpcapi/server_sessions.go`), where `PolicyID` is its own structured
  field that automation consumes,
- durable RT_FLOW syslog records (`pkg/logging/ringbuf.go` — the record keeps
  its own `policy_id` field alongside the resolved name).

A section titled "Public API preservation" that does not name an
automation-visible field value change is misleading in the direction that
matters. The change is defensible — an automation that special-cased `0` was
already special-casing an ambiguous value, and the *rendered name* does not move
— but it must be stated, and the release note must carry it.

Note the asymmetry this creates with §5.3's own argument: the plan uses
"archived RT_FLOW records would disagree with a current Index" as a point
*against* renumbering, then does not acknowledge that Path C also changes an
archived record's numeric value for one population. The point still favours
Path C (one population vs. every policy) but the plan must make the comparison
honestly rather than by omission.

## S3 (MINOR, but it is the load-bearing kind) — the site count is wrong

§5.2 says "~14 open-coded encode sites". The actual count on `b8b39a16a` is
**21 production sites** (`grep -rn "MaxRulesPerPolicy + " --include='*.go' pkg/ cmd/`
minus tests and comments):

```
pkg/grpcapi/server_show_zones.go:233,309
pkg/grpcapi/server_show_policies_text.go:179,228,369,441
pkg/api/metrics.go:1220
pkg/api/security.go:256,344
pkg/cli/cli_show_security.go:88,126
pkg/cli/cli_show_security_dispatch.go:316,354
pkg/dataplane/compiler.go:924,1059
pkg/dataplane/maps_policy.go:45,268
pkg/dataplane/userspace/policycounters.go:239,248
pkg/dataplane/userspace/policies_ids.go:127
pkg/dataplane/userspace/policies.go:64          <- the SSOT
```

The count appears inside the argument for *why renumbering is expensive*. An
approximate number in a completeness argument is exactly how a missed site
survives review. Replace with the enumerated list.

## S4 (positive result the plan should carry, not leave implicit)

I grepped both planes for production code that branches on a **session's**
`policy_id` being zero:

- Rust: the only `policy_id == 0` / `!= 0` comparison in `userspace-dp/src` is
  `policy.rs:1814`, and it tests a **snapshot rule's** id in the
  `DuplicatePolicyId` preflight — not a session's.
- Go: **zero** `PolicyID == 0` / `!= 0` comparisons in `pkg/` outside tests.

That is a strong completeness result for Path C specifically: changing the value
stamped on non-policy sessions cannot alter any behaviour except (i) policy-name
resolution, which routes through `ReservedPolicyName`, and (ii) membership in
the deletion-clear's id set. It belongs in §7 as an invariant with the grep that
establishes it, so a future change that adds such a comparison is visibly
breaking a stated property.

## S5 (MINOR) — the mixed-version test in §9.5 is a proxy, and the plan should say so

§9.5's third bullet proposes simulating an old build by "calling the pre-change
resolver". That is not an old build; it is the new build's code with one
argument changed. It cannot catch a behaviour that lives in a *call site* the
new build no longer has. The honest framing is: this bullet binds the
*resolver's* behaviour on an unknown id, and the claim about what an actual old
binary does is established by **reading** the shipped resolver at the previous
release tag, not by a test. Say that rather than implying the test proves it.

## S6 (MINOR) — §11 Q2 is partly answerable from the tree and should be

Q2 asks whether a local session table can survive an xpfd restart. I can already
narrow it: `stopLocked` (`pkg/dataplane/userspace/process.go:197-227`) disables
the shim's ctrl flag, sends a `shutdown` control request and then reaps the
child, so a **graceful** xpfd stop takes the helper with it. The unanswered part
is narrower and should be stated as such: what happens when xpfd is **SIGKILLed**
and the helper is orphaned — the next xpfd unlinks and re-creates the control
socket (`process.go:45`) and spawns a fresh helper, so it does not adopt the
orphan's table, but the orphan retains its XSK bindings until it exits. Leaving
Q2 fully open when three-quarters of it is readable makes the reviewer redo work
the author could have done.

## What I did NOT find wrong

- The §5.1 analysis of why renumbering breaks both directions is correct and is
  the strongest part of the document.
- The §5.1 claim that an HA protocol version bump does not stop session sync is
  verified: `sync_admission.go` and `sync_conn.go` contain no `version`
  reference, and no production `sync*.go` reads `HAProtocolVersion` on the
  receive path. This is the finding that kills the "just gate it" reflex and it
  is properly evidenced.
- The §5.2 `divmod` boundary break is real: `walkPolicyRuleSlots` accepts
  `ruleIndex+span <= 256`, so index 255 is reachable, so a `+1`-shifted id of
  `(n+1)*256` is reachable and decodes as set `n+1` index 0 in
  `policyRuleIDForCounter`.
- §5.3's "no persisted state" result matches `pkg/configstore` having no
  `policy_id` reference at all.

---

**Verdict: PLAN-NEEDS-MAJOR** — fold S1 (ingress normalisation removes the
deprecation lag and invalidates Q4 as posed), S2 (state the automation-visible
value change in §6), S3 (enumerate the 21 sites), S4 (promote the no-comparison
result to a stated invariant), S5 and S6. The recommendation of Path C survives
this pass and is strengthened by S1; the plan document does not yet.
