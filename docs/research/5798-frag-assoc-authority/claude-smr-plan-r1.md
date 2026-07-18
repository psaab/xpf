# Claude SMR — hostile plan review, round 1
## Target: `docs/research/5798-frag-assoc-authority/plan.md` (#5798 + #5689 + PR #6095)

**Posture:** adversarial. Goal is to break the plan or find the case that makes
the association approach unsound. Verdict at the end.

---

## Attempt to PLAN-KILL

The two documented kill conditions were:

1. **"The false-miss on legitimate re-routing makes the association approach
   unsound."** — Attacked below (SMR-3). It does **not** hold: fragments of one
   datagram co-locate on one ingress in realistic topologies, and every miss
   fails **closed** (falls through to full enforcement). The false-miss is an
   availability nit bounded by the pre-#5689 behavior, not a security or
   soundness failure. The whole premise of fragment association — that a
   datagram's fragments share an ingress domain — is sound; the plan just makes
   the key encode that assumption instead of assuming it globally.
2. **"The authority truly can't be derived on the non-first-fragment consult
   path."** — **Refuted decisively.** `UserspaceDpMeta` (types/mod.rs ~L100–130)
   stamps `ingress_ifindex`, `ingress_vlan_id`, `ingress_zone`, `routing_table`,
   `protocol` on **every** packet including a non-first fragment, and
   `ingress_zone_override` / `packet_fabric_ingress` are in scope at the consult
   site. The authority is right there. No derivation machinery is needed.

**PLAN-KILL is NOT warranted.** The approach is sound and implementable. Verdict
is PLAN-READY, contingent on the findings below being reflected (SMR-1 was the
material one and has been folded into the plan).

---

## Findings

### SMR-1 (MUST-FIX — FOUND AND FIXED during review) — authority key alone does NOT satisfy #5798 fix #4

**Claim:** The first draft recommended "authority in the key → hit inherits the
decision." But #5798 required-fix #4 states a hit *"must not bypass per-packet
interface input-filter semantics."* I verified poll_descriptor
(`9e13d448`, ~L3826+): the interface input filter
(`evaluate_non_pbr_input_filter`), PBR, and zone policy live **only in the miss
`else` branch**. On a **same-domain HIT**, the code returns the cached decision
and skips them. So even with a perfect authority key, an ingress `filter input {
term { from is-fragment; then discard; } }` is **bypassed** for a non-first
fragment that hits a valid same-domain association.

**Failure scenario:** interface reth1.0 has `filter input drop-frags { from
is-fragment; then discard; }`. A first fragment of a permitted SNAT flow
installs an association. Its non-first fragment (same domain) HITS → forwards
translated → **the is-fragment discard term never runs.** The operator's
explicit fragment-drop policy is silently defeated.

**Resolution:** the recommendation is upgraded to **Path A⁺** = authority key
**plus** a consult reorder that runs the per-packet non-PBR input filter (+
screen) on the non-first fragment on **both** hit and miss. Folded into plan
§5 (constraint 8), §6 (Element 2), §10 (step 3), §11 (input-filter-on-hit
tests + RED gate). This is the single most important correction: the authority
key closes cross-domain *permit inheritance*; the reorder closes the
per-packet *input-filter bypass*. Both are required.

### SMR-2 (MAJOR, addressed) — "fail-closed" is overloaded; Path A can still forward untranslated on a cross-domain miss

**Claim:** The plan says Path A is "fail-closed." But when a cross-domain
non-first fragment misses and falls through to enforcement, if its **real**
domain permits it and NATs the flow, it is forwarded **untranslated** — the
exact #5689 confidentiality leak. So "fail-closed" is true only for the #5798
*permit-inheritance* axis, not the #5689 *untranslated-leak* axis.

**Assessment:** Correct, and the plan now says so explicitly (§8). Two distinct
properties must not be conflated: (a) never inherit a foreign domain's PERMIT
(Path A closes this — structural); (b) never forward a NAT-relevant fragment
untranslated on a miss (the **miss-classifier** closes this — deferred to Path C
/ a #5689 follow-up). Deferring (b) is acceptable because it is the
**pre-existing #6095-documented limitation** and Path A does not regress it — a
cross-domain fragment that previously *inherited-and-translated* (wrong domain!)
now *misses-and-enforces* (right domain), which is strictly safer. The plan
should not, and does not, claim Path A closes #5689's miss-leak. Acceptable as
scoped.

### SMR-3 (MINOR) — the re-routing false-miss is under-quantified for bonds/RETH

**Claim:** "fragments co-locate on one ingress" is topology-dependent. On a
**RETH/bond**, a NIC could hash fragments of one datagram across physical member
interfaces; if `meta.ingress_ifindex` is the member (not the logical reth),
Path A false-misses across members — more often than "pathological."

**Assessment:** Real, but bounded and safe. The miss fails **closed** to the
same enforcement the member identity drives (no security loss), and the fix is
to key on the effective *logical* ingress the enforcement uses. Plan §7 now
carries this as an explicit `/engineer` verification item (confirm
`ingress_ifindex` is logical vs member; key on logical if needed). Not a
blocker; the fail-closed direction is safe regardless.

### SMR-4 (MINOR) — the observability-only probe is a half-measure

**Claim:** The "best-effort coarse `(family,src,dst,ident)` probe to bump
`frag_domain_mismatch`" reintroduces exactly the coarse-key scan (and the
attacker shard-collision surface) that Path A exists to avoid, for a counter.
Either commit to Path B (first-class counter, at the cost of check-then-reject)
or drop the counter and rely on enforcement drop counters.

**Assessment:** Fair. The plan already flags the probe as optional and
forwarding-neutral, and Open-Question 1 asks the maintainer to decide. My
recommendation as reviewer: **default to dropping the probe** — the
enforcement-path drop for the fragment's real domain already accounts for it,
and the coarse scan is not worth the surface. Keep the counter idea as a
maintainer opt-in, not the default. (Non-blocking; a knob.)

### SMR-5 (MINOR) — generation guard interaction with the wider key

**Claim:** #5624's generation guard evicts an entry whose stamped generation ≠
current. Adding ingress dims to the key does not weaken that, but note: a
config commit that *re-homes an interface to a different zone* changes the
enforcement domain without changing `meta.ingress_ifindex`. Does the key still
protect?

**Assessment:** Yes — the generation guard covers it. A zone re-home bumps
`config_generation`, so any pre-commit association is evicted on lookup (§ the
`build_generation` guard advances on *every* commit). The ingress-ifindex key
plus the generation guard together mean: same ifindex + same generation ⟹ same
zone/filter/RI. No gap. Worth an explicit test (already in §11 "config-generation
change"). Non-blocking.

### SMR-6 (NIT) — reverse-direction key derivation is unspecified

**Claim:** Both NAT64 and #6095 are forward-only today; when the reverse (reply)
association lands, the "ingress domain" of a reply fragment is the *egress-side*
interface. The authority key builder must derive the reply's ingress domain from
the reply packet's own meta, not the forward flow's.

**Assessment:** True but out of scope (reverse is a deferred increment on both
paths). The plan notes it in §12 risks. The key builder is per-packet from
`meta`, so it naturally derives the reply's own ingress when reverse lands. NIT.

---

## Cross-checks performed

- **Is the consult truly a pre-enforcement short-circuit?** Verified: `else if
  let Some(hit) = { nat64_consult(...).or_else(|| nat_consult(...)) } { hit }
  else { <input filter / PBR / zone policy> }`. Confirmed hit bypasses all three.
- **Are all authority dims available at BOTH sites?** Verified `meta.*` fields +
  `ingress_zone_override` + `packet_fabric_ingress` are in scope at install
  (~L3254) and consult (~L3746).
- **Does the SSOT builder exist?** `nat64_fragment_fields` funnels both
  first/non-first key derivations — extending it keeps install/lookup
  byte-identical (#5798 fix #3). Confirmed.
- **Precedent for ingress-scoping?** `FlowCacheEntry.ingress_ifindex` +
  `FlowCacheStamp` — the flow cache already ingress+generation-scopes cached
  decisions. Confirmed the fragment cache is the outlier.
- **Does the fix need a BPF ABI / wire change?** No — every dim is already on
  `meta`; the key is Rust-internal. Confirmed.

---

## Verdict

**PLAN-READY** with **Path A⁺** (authority key + protocol-in-key + consult
reorder for the per-packet input filter), layered on PR #6095, closing #5798
(NAT64 root) **and** #6095's broadened ordinary bypass in one PR. Path C
(modular `fragment_assoc/` + miss-classifier for the #5689 miss-leak) is the
correct destination, staged as a tracked follow-up so an open HIGH is not gated
by a large refactor.

The one finding that would have made the plan unsound if missed — SMR-1, the
input-filter-on-hit bypass — was caught and folded in. The remaining findings
are scoping clarifications (SMR-2), verification items (SMR-3/5), and knobs
(SMR-4/6). None blocks PLAN-READY.

Recommended maintainer decisions before `/engineer`: (1) drop or keep the
observability probe (SMR-4); (2) confirm the Path-A-now / Path-C-later staging.

---

## External reviewer status (2-of-3 attempted; proceeded on Claude SMR)

Both external hostile reviewers were **infra-blocked** this session; retries
documented per the `/research` contract:

- **Codex** — hard-blocked. The background review job (`task-mrq6xuoi-1mfftq`)
  failed with `400 invalid_request_error: "The 'gpt-5.6-sol' model requires a
  newer version of Codex. Please upgrade to the latest app or CLI"`. A pinned
  model/CLI-version mismatch that cannot be resolved in-session; a retry
  reproduces the same 400. Not attempted further.
- **AGY** — blocked, two attempts. (1) The `agy:agy-rescue` wrapper went
  off-track and reviewed unrelated content (never opened the plan — the
  documented AGY low-signal failure mode). (2) The direct
  `agy_adversarial_review` MCP call auto-denied a required `command` permission
  in headless mode (`jetski: no output produced ... auto-denied`; `--dangerously-
  skip-permissions` not enabled), producing no review.

**Disposition:** proceeded with the **Claude SMR** as the sole completed hostile
review (it caught and folded the one material finding, SMR-1). The plan is
grounded in firsthand reading of the reference-base source at `9e13d448`, so the
verdict rests on verified code facts, not reviewer consensus alone. Re-running
Codex/AGY once their runtimes are healthy is a cheap pre-`/engineer` add-on but
is not blocking — the recommended Path A⁺ and its RED-on-revert gates are
independently verifiable at implementation time.
