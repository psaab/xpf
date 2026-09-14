# PLAN-KILL

**Scoped to Design A v4 as specified—not kernel-assisted adjudication generally.** The final plan is not shippable: its eligibility checks still cannot establish the claimed routing equivalence.

Read-only review; branch ref matches `eee0e25bcbf9d211ca2d82355392465004dd92b4`. No runtime parity tests or measurements performed.

## Remaining blockers

### 1. Hash-mask exclusion does not cover effective hash policy

**Grounding:** `docs/pr/9522/plan.md:140-148,250-251,343-346`.

The assertion that `hash_policy` merely selects among supplied inputs is false. Linux distinguishes fixed L3/L4 policies, inner-L3 policy, and custom-field policy. `fib_multipath_hash_fields` governs the custom policy; an allowed mask does **not** establish that another active policy avoids flow-label or inner-header inputs. IPv6 L3 hashing includes flow-label semantics.

Consequently, checking mask bits alone can label an unsupported effective hashing configuration determinate. The explicit enumeration contract names the fields sysctls but does not define admission by **family × policy × effective inputs**.

The new observed-reinjection cells and MAIN-generality correction are genuine improvements, but tests cannot repair the erroneous admission rule.

**Required:** conservative, version-scoped admission for effective hash policies in both families; reject unsupported/unknown policies. Establish query-versus-packet parity for every admitted policy.

### 2. Parse-fail-closed cannot detect information the reader omitted

**Grounding:** `docs/pr/9522/plan.md:238-251`; `pkg/routing/rule_dscp_kernel_7796_test.go:108-155`.

V4 explicitly claims shape matching bounds independent-reader omission. It does not: a reader can omit an unknown kernel attribute and emit a perfectly parseable, apparently canonical rule. Recording `ip -Version` is not a capability guarantee.

The cited DSCP test validates one known selector—not arbitrary attribute visibility. Making raw attribute inspection a fallback only when iproute2 is absent leaves this gap in the primary path.

**Required:** authoritative raw-attribute coverage on every attestation, including fail-closed handling of unknown attributes, or an enforced and demonstrated complete kernel/reader compatibility boundary.

IPv6 enumeration and conservative uidrange handling close those particular sub-findings. They do not close attestation completeness.

### 3. Naming nft/NAT exclusions does not establish their absence

**Grounding:** `docs/pr/9522/plan.md:211-218,368-372`.

A best-effort “prerouting-mangle presence check” is not an enforceable exclusion contract:

- nft chain names are arbitrary; hook, type, priority and reachable rules matter.
- Prerouting NAT is not necessarily a mangle chain.
- Kernel-side NAT may exist outside the nft view.
- A per-build observation does not establish continued absence.

The plan neither specifies complete detection nor makes explicit administrative attestation a prerequisite for `complex=false`. “The operational exclusion draws the line; the check is the signal” acknowledges that detection is only advisory while the routing answer becomes authorization authority.

**Required:** a precisely enforced supported-topology boundary; incomplete inspection must not certify eligibility.

## Other round-3 dispositions

### G1: honest gate now, not approval

**Grounding:** `docs/pr/9522/plan.md:44-55,223-234`.

The withdrawal taxonomy and authorization-freshness formulation substantially repair blocker 3. G1 genuinely requires approval and explicitly kills Design A if rejected. **That closes the wording defect, not the outstanding authorization decision.** Final-round authorization is not approval of the weaker invariant.

### Fallback contradiction: closed

**Grounding:** `docs/pr/9522/plan.md:190-196`.

The default-deny drop now applies explicitly to uncapped indeterminate traffic. This resolves major 4.

### G2: exception is honest, but version path is not implementable as written

**Grounding:** `docs/pr/9522/plan.md:265-275,299,307`; `userspace-dp/src/protocol/control.rs:96-103,131`.

Path E now openly requests an exception. The unknown-field pin establishes decoding tolerance—not compliance with the security-field doctrine.

More concretely, **the checked-out protocol constant is already 16**, not 10. “Bump to v11” is therefore stale and would reuse an older version. Path V also contradicts unconditional “no version change” and absent-as-legacy invariants.

G2 remains a genuine pending decision, but its alternatives require reconciliation with the actual protocol before implementation.

### Capacity thresholds: still insufficient

**Grounding:** `docs/pr/9522/plan.md:204-209,327-340,382-385`.

D and the latency no-go are useful additions. However:

- A one-query deadline does not bound cumulative worker queueing.
- M4’s monotone-shrink test allows **zero security improvement**: equality passes even if essentially all capped misses remain delegated.
- M3 provides no minimum traffic-weighted adjudication coverage.
- The population kill threshold is still an unanswered question in §11.5.

Thus G3 has numbers but no meaningful security-effectiveness floor. Define the minimum improvement and acceptable fallback fraction under representative capacity pressure **before** measurement, with an explicit stop action.

**Bottom line:** preserve the corrected fallback semantics and explicit approval gates, but stop Design A v4. Effective-hash admission, authoritative attestation, and enforceable topology exclusion remain unresolved prerequisites to trusting the queried zone.
