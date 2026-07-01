# Research Plan — #3620: intrazone (same-zone) default behavior

- **Issue:** #3620 — "vSRX parity: investigate + decide intrazone (same-zone)
  default behavior — runtime has no `from_id == to_id` tier; verify premise
  before implementing"
- **Mode:** `/research` (plan-only; NO PR, NO production source changes)
- **Branch:** `research/3620-intrazone`
- **Base:** origin/master @ `bd2443c5e`
- **Revision:** r1
- **Disposition (recommended):** **PLAN-KILL — works-as-intended.** The
  governing premise ("Junos SRX/vSRX implicitly permits intrazone traffic by
  default") is **FALSE** for mainline SRX/vSRX. xpf's current behavior (same-zone
  traffic is subject to security policy and denied by `default-policy` when
  unmatched) **matches SRX exactly**. Building a `from_id == to_id`
  implicit-permit tier would make xpf *diverge* from SRX and would be a
  **security regression**.

---

## 1. Premise resolution (LEAD — this is the crux)

The entire issue (codex-review-121 H01-H03 + M01-M13 + L01-L12) is gated on one
factual premise:

> "Junos SRX/vSRX permits intrazone (same-zone, `from_id == to_id`) traffic by
> DEFAULT, and the Rust runtime has no such tier."

**Verdict: the premise is FALSE for mainline SRX/vSRX.** Authoritative Juniper
documentation establishes that SRX subjects intrazone traffic to the security
policy exactly like interzone traffic and DENIES it via `default-policy` (deny-all)
when unmatched. There is **no implicit runtime intrazone-permit** on SRX.

### 1.1 Authoritative Junos evidence

1. **`default-policy` is deny-all by default; applies to ANY unmatched packet.**
   Juniper — *default-policy* configuration-statement reference
   (`.../configuration-statement/security-edit-default-policy.html`):
   > "Configure the default security policy that defines the actions the device
   > takes on a packet that does not match any user-defined policy."
   > "Deny all traffic. Packets are dropped. **This is the default.**"
   The scope is "a packet that does not match any user-defined policy" — no
   carve-out for same-zone traffic.

2. **Intrazone traffic IS subject to policy lookup.** Juniper — *Security
   Policies Overview* (`.../concept/policy-overview.html`):
   > "Every time a packet attempts to pass from one zone to another **or between
   > two interfaces bound to the same zone**, the device checks for a policy that
   > permits such traffic."
   Combined with (1): unmatched intrazone traffic → `default-policy` deny-all.

3. **Juniper community, accepted answer (SRX, "intra zone traffic"):**
   > "No, in srx intra-zone traffic is **not allowed by default**. If you want to
   > allow this, you need a security policy with from-zone INTERNAL to-zone
   > INTERNAL."

4. **The ScreenOS legacy is the source of the confusion.** Legacy ScreenOS
   permitted intrazone traffic by default (governed by a per-zone
   `intrazone-block` knob that defaulted to *unblocked*). Mainline Junos SRX
   removed that implicit permit — there is no `intrazone-block` construct on SRX;
   intrazone is governed by ordinary security policy + `default-policy`.
   Third-party blogs that say "intrazone is allowed by default" are describing
   ScreenOS or the branch-SRX *factory-default configuration* (see 1.2), not the
   SRX runtime default.

### 1.2 The review's cited evidence is a CONFIGURED policy, not a runtime default

The review cites `docs/junos-cli-reference.md:213-218` as proof of an implicit
intrazone permit. Verbatim (origin/master `bd2443c5e`, lines 213-227):

```
Default policy: deny-all                       <-- the ACTUAL runtime default
Default policy log Profile ID: 0
Pre ID default policy: permit-all
Default HTTP Mux policy: permit-all
From zone: trust, To zone: trust
  Policy: default-permit, State: enabled, Index: 4, Scope Policy: 0, Sequence number: 1, Log Profile ID: 0
    Source addresses: any
    Destination addresses: any
    Applications: any
    ...
    Action: permit
  Policy: default-deny, State: enabled, Index: 5, ...
```

- Line 213 `Default policy: deny-all` **is** the runtime default — and it is
  deny, not permit.
- `default-permit` (line 218) is a **user-configured, named, indexed policy**:
  it has `State: enabled`, `Index: 4`, `Sequence number: 1`, explicit match
  criteria, and `Action: permit`, followed by a sibling named policy
  `default-deny` at `Index: 5`. It is a policy the operator (or the branch-SRX
  factory-default configuration) wrote. It is **not** an implicit runtime
  default.
- This is precisely the **branch SRX factory-default configuration** pattern.
  Juniper — *SRX3xx/5xxM factory-default settings*: the shipped config
  "allows all traffic from the trust zone to the untrust zone and allows all
  traffic between trusted zones (from the trust zone to intrazone trusted
  zones)." That permit is expressed as *configured policies in the shipped
  config*, not as a runtime default. Wipe the config and the runtime default is
  `deny-all` for both interzone and intrazone.

**Conclusion:** the review misread a configured factory-default policy named
"default-permit" (Index 4) as an implicit runtime intrazone default. The
reference doc itself shows the true runtime default one line above it:
`Default policy: deny-all`.

### 1.3 What this means for xpf

- If an operator (or a ported factory-default config) configures a
  `from-zone trust to-zone trust` permit policy, xpf's **exact zone-pair tier**
  already matches and permits it (Section 2, Tier 1). No gap.
- If no such policy exists, xpf falls to `default_action` (Deny). SRX does the
  same (`Default policy: deny-all`). No gap.

xpf therefore matches SRX intrazone semantics **today**, correctly and
fail-closed.

---

## 2. Current xpf runtime behavior (provenance, origin/master `bd2443c5e`)

Verified by direct read of origin/master (the local working checkout is ~1404
commits behind; all line numbers below are origin/master).

### 2.1 Rust dataplane — `userspace-dp/src/policy.rs`

`evaluate_policy_result_l3_aware` (fn at **line 2604**) evaluates, in order, all
inside a `if from_id != 0 && to_id != 0` guard (**line 2629**):

| Order | Tier | Lines |
|-------|------|-------|
| 1 | exact zone-pair (`zone_pair_index[(from,to)]`) | 2630-2651 |
| 2 | single-wildcard (`from_any_index[to] ∪ to_any_index[from]`, merged in config order) | 2667-2708 |
| 3 | both-any (`both_any_indices`) | 2709-2725 |
| 4 | junos-global (`global_indices`, per-rule scope check) | 2726-2758 |
| 5 | default: `default_counter.add(len)` then `action: state.default_action` | 2759, 2766, 2768 |

- **No `from_id == to_id` branch anywhere in policy.rs** (grep returns nothing).
  `from_id`/`to_id` are used symmetrically; same-zone traffic runs the identical
  pipeline as interzone.
- `PolicyState` (struct **line 1701**) has a **single** `default_action` field
  (**line 1702**); `impl Default` (**line 1774**) sets it to `PolicyAction::Deny`
  (**line 1777**).
- Default verdict stamps `DEFAULT_POLICY_SENTINEL_ID = u32::MAX` (const line
  705), bumps the one `default_counter` (struct field line 1747), and stamps
  `DEFAULT_POLICY_COUNTER_IDX = u32::MAX` (line 727). One default counter/ID for
  all default verdicts — no distinct intrazone handle.

### 2.2 Go mirror — `pkg/policymatch/policymatch.go`

- `Match` Tier 1 exact zone-pair (lines 372-381) requires
  `zpp.FromZone == q.FromZone && zpp.ToZone == q.ToZone`; a `trust→trust` query
  matches only if the operator configured a `trust→trust` set.
- Tier 5 default fallthrough (lines 443-444):
  `return Result{DefaultUsed: true, Action: cfg.Security.DefaultPolicy}` — same
  statement as the unknown-zone fallthrough (line 366). **Nothing branches on
  `q.FromZone == q.ToZone`.** Same-zone and interzone hit the identical Tier 5.

### 2.3 Show surfaces — `pkg/dataplane/userspace/policies.go`

- `walkPolicyRuleSlots` (fn line 243) ranges only over `cfg.Security.Policies`
  and `cfg.Security.GlobalPolicies`. No synthetic default-permit row is emitted.

### 2.4 Docs

- `docs/userspace-dataplane-architecture.md:610-613` documents the 5-tier model
  (exact → single-wildcard → both-any → junos-global → default) with **no**
  intrazone slot; lines 651-667 state unmatched flows "fall straight through to
  the default action (deny, per #3065)."

**Net:** xpf treats same-zone traffic identically to interzone; unmatched →
fail-closed `default_action = Deny`. This is the SRX behavior (Section 1).

---

## 3. Root-cause of the review finding

Codex review-121 anchored on `docs/junos-cli-reference.md:213-218` and read the
configured policy *name* "default-permit" as an *implicit runtime default*, then
(correctly) observed the runtime has no `from_id == to_id` tier and inferred a
parity gap. The observation about the runtime is accurate; the premise it was
measured against is wrong. The (independent) code-behavior confirmation agent for
this research even reproduced the same misconception in its closing line
("Junos/vSRX default behavior is intrazone-permit by default") — which is exactly
the ScreenOS-vs-SRX trap this research exists to defuse. The code findings in
Section 2 are solid; the Junos-semantics claim is refuted by Section 1.

---

## 4. Design options (measure twice)

### Option A — PLAN-KILL, works-as-intended (RECOMMENDED)

Do nothing to the runtime. xpf already matches SRX intrazone semantics. Close
the issue `plan-kill` with the premise-resolution reason. Optionally (Option A′)
add a one-paragraph docs clarification.

- **Pro:** correct-by-design; zero risk; no security regression; no new code on
  a fail-closed hot path.
- **Con:** none for correctness. The only residual is that a future reviewer
  could re-file the same misread (mitigated by Option A′).

### Option A′ — Option A + docs-only clarification (OPTIONAL, tiny)

Add a short note (to `docs/junos-cli-reference.md` near the sample, and/or a
`docs/feature-gaps.md` / vsrx-parity line) stating: "xpf matches mainline SRX —
intrazone (same-zone) traffic is subject to security policy and denied by
`default-policy` when unmatched; there is no implicit intrazone permit. The
`default-permit` policy in the `show security policies` sample is a *configured*
trust→trust policy (Index 4), i.e. the branch-SRX factory-default pattern, not a
runtime default." This is a trivial doc PR, NOT the heavyweight tier build; it
does not require a full `/research → /engineer` pipeline. It can be folded into
any nearby docs PR or done standalone.

### Option B — Build the `from_id == to_id` implicit-permit tier (REJECTED)

Implement the review's full fix (intrazone tier + typed default enum + distinct
counter/log + synthetic show row + tests).

- **Fatal flaw:** SRX has no such implicit permit (Section 1). Adding one makes
  xpf *permit* same-zone traffic that an operator's `default-policy deny-all`
  should block — a **silent security regression** and an *anti-parity* change
  (xpf would diverge FROM SRX, not toward it).
- **Rejected on correctness grounds**, independent of implementation cost.

### Option C — Add an OPT-IN `intrazone-permit` knob (REJECTED for this issue)

A per-zone or global knob defaulting to OFF that, when ON, permits unmatched
intrazone traffic (a ScreenOS-flavored compatibility mode).

- SRX/vSRX has no such knob; it is not a parity feature. No operator demand is
  cited. It adds config surface, a new default-verdict kind, counter/log/show
  plumbing, and HA/session-sync coverage for a behavior real SRX does not have.
- If genuine ScreenOS-migration demand ever appears, that is a *separate*
  feature request with its own issue and explicit off-by-default gating — not
  this parity issue. Out of scope; do not build speculatively.

---

## 5. Recommended disposition

**Option A — PLAN-KILL, works-as-intended.** Close #3620 with `plan-kill`.
Fold the optional Option A′ docs clarification opportunistically (not required
to close). Do **not** implement Option B or C.

Rationale: the premise is definitively false; the current behavior is correct
parity and fail-closed; the recommended non-action carries zero risk while the
tempting "fix" (Option B) is a security regression.

---

## 6. Risk table

| Disposition | Correctness vs SRX | Security | Blast radius | Verdict |
|-------------|--------------------|----------|--------------|---------|
| A (kill) | Matches SRX exactly | Fail-closed preserved | None | **RECOMMEND** |
| A′ (kill + docs) | Matches SRX | Fail-closed preserved | Docs only | Optional add-on |
| B (build tier) | **Diverges from SRX** (SRX has no implicit intrazone permit) | **Regression** — silently permits same-zone traffic default-deny should block | Hot policy path, PolicyState data model, counters, logs, show, HA sync, tests | **REJECT** |
| C (opt-in knob) | Non-SRX feature | Off-by-default bounds risk, but no parity value | Config schema + runtime + observability | REJECT for this issue |

Highest-severity risk is **shipping B**: a wrong "parity" build that is actually
a security regression. This research exists specifically to prevent that.

---

## 7. Why no build / test plan

No production code changes, so no runtime test plan. The verification performed
for this research:

1. Authoritative Junos-semantics resolution (Section 1) — Juniper docs +
   community accepted answer + branch-SRX factory-default cross-check.
2. Code-behavior confirmation against origin/master (Section 2) — exact tier
   ordering, absence of any `from_id == to_id` branch, single default
   counter/ID, Go-mirror parity, docs parity.

If Option A′ (docs) is later done, its "test" is a docs review confirming the
clarification is accurate against Sections 1-2.

Regression guard for the future: should anyone reopen this to build Option B/C,
the killing finding to address first is Section 1 — produce authoritative
Juniper evidence of an implicit runtime intrazone permit (not a configured
policy, not ScreenOS). None exists as of this research.

---

## 8. Rollout / docs impact

- Option A: none.
- Option A′: one clarifying paragraph in `docs/junos-cli-reference.md` (near the
  `show security policies` sample) and/or a vsrx-parity/feature-gaps line noting
  "intrazone = SRX-parity, policy-governed, no implicit permit." No behavior
  change, no schema change, no wire change.

---

## 9. Dedup / distinctness

Confirmed distinct from the deduped set:

- **#3042** — operator-simulator vs runtime divergence (different surface).
- **#3065 / #3363 / #3057 / #3534** — default-policy identity/counter/log/
  fail-open (the *interzone* default machinery; this issue is about whether an
  *intrazone* default even exists — it does not, per Section 1).
- **#3611** — junos-host self-zone (host-inbound), a different zone concept.

This issue's unique question — "does SRX implicitly permit intrazone?" — is
answered NO here and closed.

---

## 10. Open questions

- **Is there any SRX build/version with an implicit intrazone permit?** Not
  found. ScreenOS had it (via `intrazone-block` default-unblocked); mainline
  Junos SRX/vSRX does not. If a specific SRX release is ever cited with an
  implicit runtime intrazone permit, reopen with that citation.
- **Should Option A′ (docs) be done now?** Recommended but optional; it is a
  trivial standalone doc change and does not gate the kill.

---

## 11. References

Code (origin/master `bd2443c5e`):
- `userspace-dp/src/policy.rs` — `evaluate_policy_result_l3_aware` (2604), tiers
  (2630-2758), default (2759-2794); `PolicyState` (1701), `default_action`
  (1702), `impl Default` Deny (1774-1777); default consts (705, 716, 727),
  `default_counter` (1747).
- `pkg/policymatch/policymatch.go` — Tier 1 (372-381), Tier 5 default (443-444),
  unknown-zone fallthrough (366).
- `pkg/dataplane/userspace/policies.go` — `walkPolicyRuleSlots` (243).
- `docs/userspace-dataplane-architecture.md` — 5-tier model (610-613),
  fail-closed note (651-667).
- `docs/junos-cli-reference.md` — `show security policies` sample (213-227);
  `Default policy: deny-all` (213), configured `default-permit` policy (218-226).

Juniper documentation (authoritative):
- *default-policy* configuration statement — "Deny all traffic. Packets are
  dropped. This is the default."
  `www.juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/security-edit-default-policy.html`
- *Security Policies Overview* — "Every time a packet attempts to pass from one
  zone to another or between two interfaces bound to the same zone, the device
  checks for a policy that permits such traffic."
  `www.juniper.net/documentation/us/en/software/junos/security-policies/topics/concept/policy-overview.html`
- *SRX3xx / 5xxM factory-default settings* — factory config permits trust→trust
  intrazone via configured policies.
- Juniper community — "intra zone traffic" (SRX), accepted answer: "in srx
  intra-zone traffic is not allowed by default."
  `community.juniper.net/discussion/intra-zone-traffic`
