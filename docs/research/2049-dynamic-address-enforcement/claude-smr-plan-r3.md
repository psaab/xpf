# Claude-SMR self-review — #2049/#2050 fail-safe decision recorded (r3)

Scope: finalize the plan to PLAN-READY by recording the operator's fail-safe
decision and resolving the one open item the r2 review left
(PLAN-NEEDS-MINOR): the deny-vs-allow empty-feed fail-open question (Q3/Q4).
COMPANION-FREE (Codex/AGY NOT run); plan-doc edits only; no production source
touched.

## Operator decision (recorded)

On persistent feed-fetch failure, **retain last-good prefixes INDEFINITELY**;
NEVER silently drop a feed to empty — an empty denylist is fail-OPEN.
Drop-to-empty is an EXPLICIT operator opt-in (the `hold-interval` knob; absent
= retain forever). Staleness is surfaced loudly: `slog.Warn` on enter-stale +
Prometheus `xpf_feed_seconds_since_last_success` / `xpf_feed_stale` + a `show`
stale indicator. This is implemented in the #2050 snapshot layer (PR #2056,
reworked + merging) which #2049 enforcement READS from.

## Edits made to plan.md

- **Header → r3.** Added the PLAN-READY banner: operator fail-safe recorded,
  Q3/Q4 resolved, #2049 sequenced strictly after #2050/PR #2056.
- **§3 #2050 step 5 (HoldInterval):** rewritten — default = retain last-good
  forever; drop-to-empty only on an explicit configured `hold-interval`; loud
  staleness regardless. (Was: "optionally drop to empty — see Q3.")
- **§3a (NEW) ENFORCEMENT-SEMANTICS:** states the empty-feed policy outcome per
  rule type. With retain-last-good there is normally no empty set after the
  first fetch. Two genuine empty cases enumerated: (1) startup before first
  fetch; (2) operator explicitly enabled drop + `hold-interval` elapsed.
  Outcome stated plainly: a deny-from-feed rule with no prefixes matches
  nothing (blocks nothing) = fail-OPEN; the default never reaches it, and the
  operator opted into that risk via the explicit drop knob. Allow-side empty =
  fall-through to default-deny (safe). NAT name resolves to no addresses.
  Adds the REQUIRED loud stale indicator (show + Prometheus, sourced from
  #2050 `FeedInfo.StaleSince`/`LastError`) so a stale-but-enforced feed is
  visible.
- **P-A2:** retitled "RESOLVED" — refresh-failure = retain-last-good-forever;
  startup-before-first-fetch = empty (the only default empty case); staleness
  surfaced loudly.
- **§5 risk table:** the empty-feed row bumped Med→High, marked RESOLVED with
  the Q3/Q4 disposition.
- **§8 Q3:** RESOLVED — zero-prefix HTTP-200 → retain last-good, DEFAULT (not a
  knob).
- **§8 Q4:** RESOLVED — default = retain forever (no drop); drop-to-empty only
  on explicit `hold-interval`. The r2 "match Junos = drop to empty after hold"
  fail-open recommendation REMOVED.
- **§9 sharpest-risk:** marked RESOLVED (the empty-feed fail-open vector is
  closed by the operator decision; only the bounded startup window remains).
- **§9 recommendation:** #2049 promoted from "PLAN-READY (pending re-review)"
  to **PLAN-READY**; added the strict sequencing note (#2049 after #2050/PR
  #2056 merges; it reads the retained snapshot from the feeds `Manager`).

## Verdict

**PLAN-READY (both #2050 and #2049).** No remaining open questions. Q1/Q2 carry
their r1 recommendations (reject shadowing at commit; ID shift is fine); Q3/Q4
are resolved by the operator fail-safe decision recorded here. The one prior
must-resolve safety item (empty-feed = fail-open denylist) is closed:
default-retain-last-good-forever + explicit-opt-in-drop + loud staleness.
#2049 is gated behind #2050/PR #2056 and reads the retained feed snapshot it
produces. The r2 re-target (runtime userspace snapshot path, not the retired
eBPF compiler) stands unchanged. COMPANION-FREE: Codex/AGY were not run;
recorded as a decision-finalization pass, not a fresh hostile pass.
