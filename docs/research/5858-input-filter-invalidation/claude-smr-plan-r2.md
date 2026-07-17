# Claude SMR — hostile plan review r2 — #5858 (plan v3, Path C)

**Plan:** `plan.md` @ v3 (commit `8e67369b6`). **Posture:** hostile on the *new*
design, not defending the pivot.

## Verdict: **PLAN-NEEDS-MINOR**

The pivot to precise per-tuple re-evaluation (drop only newly-denied; never touch
permitted flows) is the **correct** response to Codex r1 — it eliminates the SNAT
re-alloc break by construction and needs no HA wire change (field-by-field sync
encoding confirmed, `session_delta.rs:89-118`). But I found two issues that must
be fixed before PLAN-READY (one is a real correctness hole in the verdict split;
one makes the flow-cache fix actually race-free), plus one scope gap.

## Confirmed sound in v3
- Precise drop-only-denied removes the finding-6 NAT break by never dropping a
  permitted flow. ✔
- Local-only ingress stamp is genuinely off the wire (encoder is field-by-field,
  `session_delta.rs:89-118`). ✔
- Verdict-only comparison **mode** on the same `..`-free destructure resolves the
  finding-7 false dichotomy while keeping the #5293 compile-time guarantee. ✔

## BLOCKING findings

### SMR2-A (BLOCKING) — scope precise re-eval to PURELY-STATIC filters; the mixed-term verdict is ill-defined
`static_input_filter_verdict` (§5.2) cannot cleanly classify a filter that mixes
static and per-packet terms. Counter-example:
```
term A: from dscp 10 then accept      # per-packet
term B: from address X then discard   # static
```
For a 5-tuple with source X: a static eval (`TermMatchExtra::default()`, dscp=0)
sees A not match → B match → **Deny**. But the flow's actual dscp-10 packets take
A → **accept**. So the static verdict would **drop a permitted flow** (avail
regression) — or, if we defensively return `PerPacketDepends`, a genuinely denied
sub-flow (dscp≠10) **survives** (security gap). Term ordering × per-packet terms
makes the 5-tuple verdict genuinely indeterminate.

**Fix (and it's clean):** run precise re-eval **only** for filters that are
**purely static** — `!has_dscp_match_terms && !has_per_packet_l4_match_terms` on
**both** the old and new snapshot for that ifindex. This is exactly the set the
existing gated family purge **excludes** (its `.filter(has_dscp_match_terms)`),
i.e. exactly the #5858 gap. Filters that *have* dscp/per-packet terms are
**already** family-purged on **any** change — including a static term edit —
because `dscp_sensitive_filter_semantics_match` compares *all* terms (verified:
`cache_sensitive.rs:432-436` + the `.filter(has_dscp_match_terms)` gate at `:445`
only selects *which* filters, then compares them in full). So the two paths
partition cleanly with **no gap and no overlap**:
- purely-static filter changed → **precise re-eval** (5-tuple fully determines
  verdict; `TermMatchExtra::default()` is exact) → drop only denied.
- dscp/per-packet filter changed (static part included) → **existing family
  purge** (unchanged; its pre-existing SNAT-break on those rarer edits stays an
  out-of-scope, documented limitation).

Route by "**either** old **or** new snapshot has a dscp/per-packet term for that
ifindex → family purge; else precise re-eval," so a purely-static→mixed (or
reverse) transition in one commit is handled by the family purge (the mixed side
carries the flag). This removes §5.2's `PerPacketDepends` branch entirely for the
precise path and closes §11 Q2 by construction. **Without this scoping the plan
has a real drop-a-permitted-flow-or-miss-a-deny hole.**

### SMR2-B (BLOCKING) — make the flow-cache fix race-free with targeted eviction, not the validation re-read
§5.4(a) (re-read `validation` in the rotation iteration) is **not obviously
race-free**: `validation` and `forwarding` are separate ArcSwaps stored
consecutively (`snapshot_refresh.rs:354-355`). If `forwarding` is stored **before**
`validation`, a worker can read new `forwarding` (`:372`), re-read `validation`,
and still get the **old** generation (the coordinator hasn't stored the new one
yet) → old-generation flow-cache entries still match → bypass persists. The fix's
correctness then depends on an unstated store-order + acquire-ordering invariant.

**Fix:** make the **primary** flow-cache fix a **targeted eviction of each dropped
session's flow-cache entry** inside the re-eval walk (§5.4(b)). Path C drops a
*specific, known* set of keys; evicting their flow-cache entries (by the same
5-tuple / flow hash) is precise and **race-free** — it does not depend on
validation/forwarding store order at all. A permitted flow is not dropped and its
(correct) allow entry rightly stays. Keep §5.4(a) only as the latent-bug cleanup
for the *existing* DSCP/per-packet purge, explicitly noting it needs the
validation-before-forwarding store order to be race-free (or, better, drive the
flow-cache generation from the forwarding snapshot itself so there is a single
source and no skew). **Swap the recommendation: (b) primary, (a) supplementary.**

## Non-blocking

### SMR2-C (MINOR) — cover the reverse-companion ingress filter, or document the limitation
An input filter applies per **ingress** direction. The reverse companion (reply
traffic) ingresses the forward flow's **egress** interface, whose input filter is
a *different* interface's. If only the forward entry is stamped/re-evaluated, a
tightened **reverse-ingress** input filter does not revoke the flow (its replies
keep flowing). The dual-entry session table already holds a reverse entry — stamp
**each** entry with its own ingress logical ifindex at install and re-eval both,
so a deny on either direction's ingress interface revokes the flow. If deferring,
state it as an explicit limitation (forward-ingress only) in §10, not silence.

### SMR2-D (MINOR) — the O(all-sessions) walk per static-filter commit
The re-eval walks the whole table (no ingress-ifindex index) on every commit that
edits a purely-static filter — more frequent than DSCP/per-packet edits. Cold-path
and no worse than the existing family purge's walk, so acceptable for v1; keep the
by-ingress index as the §11 Q6 follow-up but say so plainly.

## Design-fork rulings (v3)
- **Fork 1 = C (precise).** Agree — the only SNAT-safe option; B/A drop permitted
  flows.
- **Fork 2 = verdict-only mode.** Agree.
- **Fork 3 = deltas + standby own-session re-eval.** Agree as default; the broad-
  deny BulkSync fallback (§11 Q3) should be named as the mitigation when denied >
  ring, not left open.
- **Failover window (§11 Q4).** Acceptable to document rather than fence, **iff**
  the plan states the bound (config-sync latency) and that it self-heals; a hard
  fence is correctly scoped out.

## To reach PLAN-READY
Fold SMR2-A (purely-static scoping — this is the important one) and SMR2-B
(targeted flow-cache eviction) into v4; land SMR2-C as either dual-entry stamping
or an explicit §10 limitation; name the broad-deny BulkSync fallback. Then this is
PLAN-READY. Re-dispatch Codex r2 on v4.
