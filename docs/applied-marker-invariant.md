# The applied/published/converged marker invariant — audit and analyzer verdict

**Issue:** #6533. **Verdict:** the prescribed `analysistest` rule is
PLAN-KILLED on measured evidence. The invariant it names is real and worth
knowing; the lexical rule proposed to check it is wrong in both directions.
**Base SHA for every measurement below:** `f4a5297be`.

This document exists so the rule is not prescribed an eighteenth time. Every
number here is reproducible from the commands given.

---

## The invariant

Code updates durable state to reflect an action it is *about* to take, then
performs the action. If the action fails, the state has already advanced, the
record of outstanding work is gone, and the retry/reconcile path that exists to
catch exactly this is structurally blind. Often the failure is logged and the
function returns success.

Two properties generalise:

- **I1** — an applied/published/converged marker is stamped **only** on a
  verified-success path.
- **I2** — every applier is reachable from a **periodic converger** whose
  predicate is `desired != applied`, never from a transition edge alone.

I2 is the load-bearing half. A generic `Debt`/`PendingAction` type is not the
answer: all the prior fixes invented storage, and what made them work was
pairing it with a driver. **Storage without a driver is the bug.**

None of that is in dispute. What follows is about whether a `go vet`-style rule
can check it.

---

## The proposed rule

> Any assignment to a field matching
> `/^(last|prev)?[Aa]pplied|[Pp]ublished|[Cc]onverged/` must be dominated by a
> nil-error check in the same function.

## Measurement 1 — the population is 43 sites, and it is heterogeneous

```
grep -rnE '^\s*[A-Za-z_][A-Za-z0-9_.]*\.(last|prev|Last|Prev)?([Aa]pplied|[Pp]ublished|[Cc]onverged)[A-Za-z0-9_]*\s*(=|:=)' \
  --include=*.go pkg/ cmd/ | grep -v '_test.go' | wc -l
```

**43** assignment sites in non-test code (**61** including tests). The "sixteen"
in the issue counts *bug instances*, not the sites a rule must adjudicate — the
false-positive denominator was never measured.

> **Reusable lesson.** An issue proposing a lint must state its **inspection
> population** — the sites the rule will adjudicate — not its **defect
> population** — the bugs that motivated it. Only the first bounds the
> false-positive rate, and only the first tells you whether the rule is
> affordable. Here the two differ by 43 to 16, and they are not even the same
> *kind* of thing: not one of the 16 is a member of the 43.

The majority of the 43 are structurally not "stamp a marker before a fallible
action":

| Shape | Example |
|---|---|
| Copy between two markers | `dst.publishedHash = src.publishedHash` (`pkg/feeds/feeds.go:427`) |
| Reset to zero — the *safe* direction, forcing re-converge | `fs.publishedHash = [32]byte{}` (`feeds.go:986`), `m.publishedSnapshot = 0` (`pkg/dataplane/userspace/process.go:433`), `t.appliedAddrs = nil` (`pkg/routing/tunnel.go:1263`) |
| Accumulator | `res.applied = append(res.applied, vip)` (`pkg/vrrp/instance_vip.go:211`) |
| Constructor init | `t.appliedRI = map[string]string{}` (`tunnel.go:134`) |
| Read-out into a view struct | `v.LastPublished = rt.lastPublished` (`pkg/ddns/surface_a.go:2052`) |

A dominance rule flags all of these.

## Measurement 2 — the rule misses the defects that motivated it (3 of 3 sampled)

Pre-fix code pulled from git history for three of the twelve instances the
issue names:

| Instance | Pre-fix defect | Why the rule does not fire |
|---|---|---|
| **#5646** `git show 3e1ca7e53^:pkg/feeds/feeds.go` | `fs.hash = res.hash` then a **void** `m.onUpdate()` | field is `hash` — no regex match; **and** no error existed to be dominated by (the fix changed the callback to `func() error`). Misses on both clauses. |
| **#5697** `git show 605488301` | `_ = bindingsMap.Update(idx, zeroBinding, …)` then `m.lastBindingIndices = newBindingIndices` | `lastBindingIndices` is not applied/published/converged. |
| **#5134** `git show 0f0c22037` | `if _, err := d.dp.ApplyConfig(…); err != nil { slog.Warn(…) }` and fall through | **no marker field is assigned at all** in the defective function. |

The reason is systematic, not luck. **The applied/published/converged vocabulary
is the remedy — each fix introduced it.** The defect's signature is the *absence*
of the concept. A rule keyed to the fix's vocabulary is structurally blind to the
pre-fix code.

> **This is "a probe keyed to the FIX tests the repair, not the property" in
> lint form**, and it generalises past this issue to every proposal of the shape
> *"lint for the pattern our fixes introduced."* That shape is self-defeating by
> construction: the pattern our fixes introduced is, by definition, absent from
> the code the fixes were needed for. The vocabulary a fix adds marks where
> someone already understood the problem — which is precisely where the bug is
> not. Before proposing such a rule, take two or three of the real pre-fix
> commits and check the rule reds on them. If it cannot, the rule is measuring
> the remedy's spelling.

## Measurement 3 — the rule false-positives the mechanisms held up as correct

The issue's own acceptance criterion requires that the rule "does not flag the
twelve correct historical mechanisms". It flags them, because they are correct
for reasons no intra-function dominance rule can see:

- `pkg/daemon/rg_state.go:169` — `s.applied = active` inside `MarkApplied()`.
  Correct via a **caller contract**: the caller verified the write. The function
  contains no error at all, so nothing can dominate the assignment.
- `pkg/dataplane/userspace/process_status.go:26` — `m.publishedSnapshot = …`
  guarded by a **status readback** (`m.lastStatus.LastSnapshotGeneration >=
  m.lastSnapshot.Generation`), which is a stronger check than a nil-error return
  and is not one.

## Measurement 4 — the rule's own flagship target is correct code, and covered

The issue states the rule "flags the sweep's Kea instance
(`dhcpserver.go:319`)". That instance was fixed by **#6535** (`270ed6cde`), and
the fix **deliberately keeps the marker advancing on failure**
(`pkg/dhcpserver/dhcpserver.go:348`):

```go
m.lastAppliedGen = gen
err := errors.Join(errs...)
// #6535: remember whether this attempt actually converged, so a
// converger can re-drive it. lastAppliedGen deliberately still advances
// on failure … a retry allocates a FRESH gen from applyGen, so it is
// never blocked by the superseded guard …
m.noteApplyOutcome(err)
```

Convergence is carried by `ClaimApplyRetry` → the daemon's reconcile loop
(`pkg/daemon/daemon_ha.go:1708`), and that end-to-end path is bound by
`pkg/daemon/dhcp_apply_converger_6535_test.go`: pass B re-drives `systemctl`
on a tick with no RG transition, which also proves the retry is not blocked by
the superseded guard.

The rule flags this. So does it flag the issue's second flagship, "the missing
`MarkApplied` behind the fence blackhole" — fixed by **#6530**
(`pkg/daemon/rg_state_fence_rearm_6530_test.go`).

**Both live targets are already gone. Every remaining hit is a false positive.**
That is the `//nolint` outcome, and a suppressed lint reads as a checked
property — strictly worse than no rule.

## Measurement 5 — alternative signals, rejected

Two name-independent signals do appear in the real defects. Both were measured
and neither is gateable:

| Signal | Count (non-test) | Why rejected |
|---|---|---|
| Discarded error, `_ = call(…)` — the #5697 shape | **197** | overwhelmingly legitimate (`Close`, `SetDeadline`); this is `errcheck`, not a marker rule |
| Void func-typed apply/publish/update field — the #5646 root shape (`func()` where `func() error` was needed) | **10** | all notification hooks (`onEventDrop`, `onAddressChange`, `onDataplaneEvent`); zero true positives |

#5134's shape — an error checked, logged, and then fallen through — is a
completely legitimate pattern thousands of times over and has no discriminating
static form at all.

---

## Verdict

The invariant is **semantic**, not lexical. Its correct implementations are
correct via caller contracts and readbacks; its violations do not use the
vocabulary. No rule over the marker-name population can separate the two.

**What would work, and what it costs.** The sound version is a compile-time
guard rather than a lint: a typed marker whose advance *takes the error* —
`m.Advance(gen, err)`, a no-op on non-nil — so a marker cannot be stamped
without the caller having the outcome in hand, paired with a registry a test
walks to assert every marker has a periodic driver (I2). That converts the
review-enforced invariant into one the compiler holds, which is the preference
in `docs/engineering-style.md`. It is a **43-site migration** touching the
dataplane manager's publish paths, not the "~30 lines plus a fixture" the issue
estimated, and it should be costed as its own piece of work rather than
smuggled in behind a lint.

**Until then this stays a review-enforced invariant.** When reviewing any code
that records "this work is done", ask the two questions the twelve prior bugs
failed to ask:

1. Does this marker advance on a path where the action might have failed? If
   yes — deliberately, as `pkg/dhcpserver` does — where is the convergence
   carried instead?
2. Is the applier reachable from a periodic converger, or only from a
   transition edge? An edge-only applier loses every failure.

## Measurement 3 — the typed marker is PLAN-KILLED; the lexical registry was later retired (#7343)

The triage above proposed two mechanisms. Classifying all **42** population
sites (the count in Measurement 1 was 43; one has since moved) settles which is
worth building, and the answer was not the one the cost estimate predicted.

**19 sites are structurally not markers.** Measurement 1 anticipated most of
this; reading the rest added two categories it did not list — **read-outs into a
display view or a returned snapshot** (`cli_show_security_filters.go`,
`sync_bulk.go`, `surface_a.go`) and one **log-dedup memo**
(`tunnels.go`'s `lastPublishedWgEndpoints`, which remembers what was last
*logged*, not what was applied).

**23 sites are real markers, and every one of them is already correct** — by
four different mechanisms:

| how it is correct | n |
|---|---|
| early return: the error path returned above the stamp | 11 |
| caller contract or explicit guard | 7 |
| status readback or dedup-skip — no error exists at all | 4 |
| advances on failure, deliberately (`pkg/dhcpserver`, #6535) | 1 |

**Exactly one site has a live, unreturned error in scope at the stamp**, and it
is the declared escape. This was checked rather than sampled: a scan for
enclosing functions that accumulate errors (`errors.Join` / `errs = append`)
flagged 5 of 42, deliberately over-reporting; two are zero-resets, two are
`manager_worker_arm` where the `errors.Join` sits inside an early `return` above
the stamp, and one is `dhcpserver`.

### Why `Advance(gen, err)` does not work here

The honest test proposed on #7343 was *"if a third of the real markers need the
escape hatch, the guard is not buying much."* The escape rate is **1 in 23**,
comfortably under that bar. **The mechanism still fails, for a different
reason.**

`Advance(gen, err)` makes the unsafe form unwritable by forcing the caller to
hold the outcome — but at 22 of 23 real markers **there is no error in scope to
pass**. Every one of those sites would migrate to a literal `Advance(gen, nil)`.

> A parameter that is `nil` at every call site encodes no contract. It is a
> no-op wearing the shape of a guarantee — and it is worse than nothing,
> because a reviewer seeing `Advance(gen, err)` would reasonably conclude the
> invariant is now type-enforced.

That is the same "looks checked, checks nothing" failure #6533 was killed for,
relocated from a lint into an API. A single `Advance` signature also flattens
four genuinely different correctness mechanisms: `rg_state.MarkApplied` contains
no error *by design*, `process_status`'s readback mirrors bookkeeping the helper
has *already confirmed*, and its dedup-skip advances when nothing was published
*and that is correct*.

### What #7343 built at the time: the driver registry (I2; now retired)

At the time, `pkg/refactoraudit/applied_marker_registry_7343_test.go` was item
2, intended to classify source assignments and name periodic re-drivers. The
inventory described below records what that test asserted historically; it is
not an active repository gate.


At the time, three lexical properties were asserted, and five mutations of
those checks red:

1. **Every population assignment is classified.** A new marker added anywhere in
   the tree arrives as an unclassified statement and fails. This is the
   recurrence guard: a marker added without a driver cannot land silently.
2. **Every registered marker names a driver symbol that exists.** Renaming or
   deleting a converger fails, which is the twelve-times-recurring defect.
3. **`pkg/dhcpserver`'s advance-on-failure is a first-class declaration** naming
   `ClaimApplyRetry` as its driver — not a `//nolint`, which is precisely the
   suppression #6533 was killed for.

The historical inventory was keyed on **(file, statement, count)**, not
`file:line`, to reduce line-drift churn.


**Current policy:** the lexical registry test and its source-text helpers were
removed. Counting assignments and searching for driver symbol spellings does
not exercise publication, rejection, or retry behavior and must not be
reintroduced as a source-text allowlist. Keep the two reviewer questions
above, and pin real state transitions with behavior tests at their owning
appliers, including rejection preserving published state and retry
convergence.
