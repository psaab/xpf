# Claude SMR hostile plan-review — #1387 residual (Path S) — round 1

Reviewer posture: adversarial. The job is to fail the plan if the
architecture is wrong, the scope is mis-framed, or a claim is
unverified. "It's a small render change" is not a pass on its own.

Verdict: **PLAN-NEEDS-MINOR → folds to PLAN-READY.** No blocker. Three
MAJORs and two MINORs below; all are addressable in the plan text and
none changes the recommended slice. After folding, Path S is sound.

---

## Did the plan correctly re-derive the issue state? (the prompt's core ask)

YES, and this is the most important finding. The prompt was written on
the assumption that "Kea DDNS config generation" might now be driveable.
The plan correctly establishes against source that:

- DDNS is *already shipped* (Inc-1 #2043 + Inc-2 #2066), verified by
  reading `ddns.go`, `daemon_ddns.go`, `types_system.go:850-935`,
  `schema_system.go:556-626`, and the README.
- DDNS was implemented via **direct RFC 2136**, not Kea D2 — so the
  prompt's literal phrasing ("Kea DDNS config generation … where the D2
  config + service lifecycle would slot in") describes a path the
  project *deliberately did not take.*
- The genuinely-unshipped, lab-free half is **stale lease cleanup**
  (Kea `expired-leases-processing`), confirmed by a repo-wide grep
  returning zero matches.

This is the right call. A weaker research pass would have dutifully
planned the D2 backend the prompt named and missed that it is redundant
+ already superseded. The plan instead recommends the residual slice
that actually closes the issue title. Good.

---

## MAJOR-1 — "byte-identical when off" claim needs the golden test to be a HARD gate, and the empty-`{}` case undermines it

The plan leans on H1 ("nil/disabled ⇒ byte-identical render") as the
cardinal compatibility invariant, but §5.4's `keaExpiredLeasesMap`
comment then muses about emitting an empty `{}` "so the operator sees
the feature is on." That is a contradiction in waiting: if
enabled-with-no-tuning emits `{}`, then H1 only holds for the
*disabled/nil* case, not "off." The plan must state crisply:

- **nil block OR `Enabled=false`** ⇒ key omitted ⇒ byte-identical. This
  is H1 and it is non-negotiable.
- **`Enabled=true` with no knobs** is a SEPARATE state; the empty-`{}`
  vs omit question (Open Q1) only applies there, and it does NOT touch
  H1.

Fold: tighten §5.4 + H1 to make the disabled path unconditionally
omit, and scope the `{}` musing strictly to the enabled-no-knobs case.
Otherwise a reviewer or the engineer could read the comment as "emit
`{}` whenever the struct is non-nil," which would break H1 for a
disabled-but-present block. **Verified against `dhcpserver.go:750-765`:
the omit path is the literal current output, so the test is
constructible.**

DISPOSITION: valid. Plan §5.4 comment + H1 wording must be tightened at
engineer time. Not a design change — a wording hazard. Recorded as a
binding note for the engineer.

## MAJOR-2 — the plan does not verify WHERE the DHCP-server compiler reads the block, only DDNS's site

§5.3 says "wherever the DHCP-server compiler lives — confirm." That is
an honest TODO, but it is load-bearing: the dual-AST + strict/lenient
discipline (H6, H7) only holds if the new compile code sits at the SAME
two sites as the existing DHCP-server / DDNS compile. If the engineer
adds it on the strict path only, a peer-synced or stored config with the
block would warn-reject incorrectly on lenient load — an HA config-sync
hazard of exactly the class the project has been bitten by (#1799,
#1796/#1797 flat-set compile-empty). The plan should name the concrete
function. From the inventory, DDNS compiles via `compiler.go` +
`compiler_dhcp_ddns_test.go` and there is a `validateDDNSBackendWarnings`
in `compiler.go`; the DHCP-server pool/group/static-binding compile is
the precedent to mirror. The engineer MUST locate
`compileDHCPLocalServer` (or equivalent) and the lenient counterpart and
add the block at both.

DISPOSITION: valid. The plan already flags it as a confirm-item, but the
HA-config-sync consequence of getting it half-right deserves promotion
from a `§5.3` parenthetical to a named risk. **Added as the rationale
behind R4; the engineer step-3 (Codex plan review) must confirm both
compile sites before code.** Not a blocker — it is exactly what plan
review + the existing `TestLoad_ToleratesStored*` suite catch.

## MAJOR-3 — Kea range claims are asserted but not verified against the running Kea version

§5.2/R3 assert "Kea has no hard upper bound on these timers" and "Kea
treats 0 as unlimited for the cap knobs." These are stated as fact but
the plan never cites the Kea version in the image (`bake.py` /
live-verified 3.0.3 per `dhcpserver.go:96`) nor the Kea docs. If a timer
of 0 is REJECTED by Kea 3.0.3 (some Kea versions reject `reclaim-timer-
wait-time: 0`), a commit setting it to 0 would take DHCP DOWN on the
fail-closed restart (R3, High). The plan correctly makes R3 High and
defers exact-range verification to engineer time — but it should not
ship the schema with `ValidateIntegerMin(0)` on the timers UNTIL that
verification is done. The conservative default is `ValidateIntegerMin(1)`
on the three *timers* (reclaim/flush/hold) and `Min(0)` only on the two
*cap* knobs where 0=unlimited is documented Kea behaviour.

DISPOSITION: valid and improves safety. **Recommend the plan flip the
three timer leaves to `ValidateIntegerMin(1)` in §5.2 and keep `Min(0)`
only on `max-leases` / `max-time`, with `unwarned-cycles` at `Min(0)`.**
This is the safer default; an operator who genuinely needs a timer of 0
is vanishingly rare and can be unblocked by a follow-up once Kea's
acceptance is confirmed. Folding this into the plan now.

## MINOR-1 — `make test-failover` mandate

§9/§10 correctly reason that Path S touches no HA code so the failover
mandate "does not strictly apply," but CLAUDE.md is categorical: "Any
change touching cluster, VRRP, session sync, or failover code MUST pass
`make test-failover`." Path S touches none of those, so the plan is
right — but it should say so in the affirmative ("Path S touches no
cluster/VRRP/session-sync/fabric code, so the test-failover mandate is
not triggered; standard deploy smoke applies") rather than the slightly
defensive "does not strictly apply." Cosmetic.

DISPOSITION: valid, cosmetic. Reworded reasoning is already present in
§9; acceptable as-is. No change required.

## MINOR-2 — "operator-visible symptom" claim in §2 is a touch overstated

§2 says expired rows mean "an expired lease's identity is not released
for reuse-accounting until reclamation runs." That is true for Kea's
*reuse* but the practical operator symptom is more accurately: (a)
memfile growth/startup-reload cost, and (b) `show dhcp-server` would
show stale leases *were it not for* the #2085 display filter — which the
plan itself notes already hides them. So the user-facing urgency is
lower than the framing implies (the display is already truthful). The
plan should be honest that the PRIMARY benefit is memfile hygiene +
correct Kea internal reuse, NOT fixing a visible `show` bug (that was
already fixed by #2085).

DISPOSITION: valid. Honest-framing discipline. The plan §2 already
credits #2085 with hiding the rows at display, so the framing is not
dishonest — but tighten the value statement in §3 to lead with "bounds
memfile growth + correct Kea reclamation/reuse" and NOT imply it fixes a
display defect. Folding a one-line clarification.

---

## Things the plan got RIGHT (defending the pass)

- **Scope discipline.** It refuses to build the kea-d2 backend the
  prompt named, with a concrete blast-radius argument (new daemon, new
  config, new HA-ownership story, not in the image). That is the
  correct call and it is well-defended (§6). PLAN-KILL for D2 is right.
- **The global-not-per-pool insight (H3).** Catching that Kea
  reclamation is per-`Dhcp4`/`Dhcp6`, not per-subnet, before code is
  exactly what plan review is for — a per-pool model would have been a
  wasted increment. Verified: Kea's `expired-leases-processing` is a
  top-level global block.
- **The 0=unlimited gotcha (H2).** This is the single subtle
  correctness trap in the whole feature and the plan caught it up front.
- **No new dependency, no protobuf, no metrics churn.** Correctly
  scoped as pure config-render; this keeps the PR tiny and reviewable.
- **Reuses the existing fail-closed Apply path (H5).** No service-
  lifecycle change; the reclamation block rides the same restart that
  the rest of the Kea config already does.

## Convergence check

After folding MAJOR-1 (tighten H1/§5.4 disabled-omit), MAJOR-2 (name the
lenient compile site as the binding engineer pre-flight), MAJOR-3 (timers
to `Min(1)`, caps to `Min(0)`), and MINOR-2 (honest value framing), the
plan has no remaining architectural objection. The recommended slice is
the right one, the design is faithful to the shipped DHCP-server render,
and every risk is either mitigated or correctly deferred to a named
engineer-time verification with a fail-closed backstop.

**SMR verdict: PLAN-READY (r2 after the four folds).** The folds are
edits to the plan text, not design changes; recording them and bumping
the plan to r2.

---

## Fold confirmation (applied to plan r2)

All four findings are now reflected in `plan.md` r2:

- **MAJOR-1** — §5.4 `keaExpiredLeasesMap` disabled/nil branch documented
  as the UNCONDITIONAL omit (= H1); the empty-`{}` musing rescoped
  strictly to the enabled-no-knobs state. H1 wording tightened.
- **MAJOR-2** — promoted to risk **R4** (Med→High): the engineer must add
  the compiler at BOTH the strict and lenient DHCP-server compile sites,
  confirmed in the Codex plan-review before code; named as a binding
  pre-flight.
- **MAJOR-3** — §5.2 schema: the three timers flipped to
  `ValidateIntegerMin(1)`; the two cap knobs stay `Min(0)` (0=unlimited);
  §10 schema test updated to pin the floor split; exact Kea-3.0.3
  acceptance is Open Q2.
- **MINOR-1** — cosmetic, no change (§9 already affirmative).
- **MINOR-2** — §3 value statement rewritten to lead with memfile hygiene
  + correct Kea reclamation/reuse and explicitly NOT a `show` defect fix
  (#2085 already truthful at display).

No architectural objection remains. **Final SMR verdict: PLAN-READY (r2).**
