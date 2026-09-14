# PLAN-KILL

**Scoped to Design A v3 as specified, not kernel-assisted adjudication generally.** The ingress correction is real, but mirror equality remains unproven, the uncertainty contract still contradicts itself, and the no-bump argument still violates the cited doctrine.

Read-only review of the supplied checkout. No execution, measurements, or independent commit verification.

## 1. Blocker — Equal listed tuples do not establish equal forwarding decisions

**Grounding:** `docs/pr/9522/plan.md:91-124,153-156,257-258`.

Switching to TUN ingress and ordinary RPDB traversal closes the **specific v2 origin-iif/forced-table error**. It does not establish the stronger “SAME member” assertion.

The proposed context omits IPv6 flow label and inner-packet hash inputs. These are not merely optional **rule selectors**: they can affect multipath selection independently of RPDB rules. The available kernel headers explicitly enumerate flow-label and inner-header hash fields:

- `/usr/src/linux-headers-6.18.5+deb14-common/include/net/ip_fib.h:500-516`
- The hash interface also accepts an `skb`, not just a `flowi4`: same file, `544-545`.

Rejecting a *flow-label rule* therefore does not reject *flow-label-dependent ECMP*. Neither the query, cache key, nor attestation covers this distinction. Cross-zone multipath was nevertheless removed from the indeterminate class.

The proposed “same tuple twice ⇒ same member” cell proves repeatability, not **query-versus-reinjected-packet equality**. Both queries could consistently select the wrong member.

**Required reset:** establish version-scoped GETROUTE-versus-input-path parity for both families and every admitted hash mode, or conservatively exclude configurations whose selected zone cannot be established. Test the two different paths, not two oracle calls.

Also, `tests_fragment.rs:826-841` documents one MAIN-resolution vector. It is not a universal proof that reinjection selects MAIN; the correct general target remains the RPDB result.

## 2. Blocker — Attestation still does not establish the capability boundary

**Grounding:** `docs/pr/9522/plan.md:95-98,121-124,175-188,229-232`.

Replacing `netlink.RuleList` addresses the known DSCP reader defect. It does **not** prove completeness:

- Bare `ip rule list` does not specify IPv6 enumeration.
- No minimum iproute2 capability/version or unknown-attribute visibility contract is defined. An independent reader can still omit attributes it does not understand.
- Rule enumeration does not attest multipath sysctls, pre-routing packet transformations, or namespace identity.
- “TUN ⇒ domain-independent” requires the resolver socket, TUN, rules, routes and interface mapping to belong to the same pinned network namespace. The plan does not specify that ownership.

The #7796 test verifies the presence and value of a **known DSCP selector**, not arbitrary attribute completeness: `pkg/routing/rule_dscp_kernel_7796_test.go:108-155`.

### UID claim: not closed

`INVALID (overflowuid)` at `plan.md:96` conflates different values:

- `INVALID_UID` is `KUIDT_INIT(-1)`: kernel header `include/linux/uidgid.h:50`.
- Default overflow UID is `65534`: `include/linux/highuid.h:41`.

The plan supplies no kernel-path proof for GETROUTE encoding and forwarded lookup semantics. Moreover, §5d rejects uidrange rules while §5a calls them proven inert. Pick one conservative contract; do not claim both.

### Other requested mirror probes

- **rpfilter:** effective zero is not guaranteed. `userspace-dp/src/slowpath.rs:1090-1103` explicitly leaves `conf/all/rp_filter` unchanged and only warns. This is an availability qualification, not evidence of a policy bypass.
- **Conntrack/pre-routing:** unresolved, not proven harmless. A route query does not itself establish that reinjection reaches routing with unchanged destination, mark and fragment context. Require a supported-topology invariant covering pre-routing transformations and reassembly.
- **TCP-MD5/MPTCP:** I found no grounded reason here to make these independent blockers. Their mention cannot substitute for resolving the concrete hash and context gaps.

## 3. Blocker — The weaker security invariant still needs approval, and its withdrawal claim is false

**Grounding:** `docs/pr/9522/plan.md:168-173`; `docs/pr/9522/reviews/round2-astra-plan-kill.md:34-44`.

Acknowledging a wrong-zone authorization window is progress. It is **not implementation-level closure** of the previous blocker: round 2 expressly required user approval of the weaker invariant.

Furthermore, “withdrawal ⇒ kernel drops” is false without qualification. Withdrawing the selected route can expose a covering route or another next hop. That is potentially a change of authorized zone, not necessarily an availability-only event.

TTL bounds cache-answer age; it does not by itself prove an end-to-end forwarding residual of ≤TTL, including reinjection delay. Nor does similar duration establish equivalence to the standing inter-push security behavior.

**Required revision:** classify changes by the resulting forwarding outcome, define precisely what the bound measures, and obtain explicit approval for the weaker authorization contract.

## 4. Major — The fallback table is improved, but contradicted immediately afterward

**Grounding:** `docs/pr/9522/plan.md:128-149`.

The table says:

> indeterminate + capped ⇒ delegation

The following paragraph says:

> indeterminate evaluates default action … deny ⇒ drops

Those disagree for capped/default-deny. The latter must explicitly apply **only to uncapped indeterminate traffic** if preservation is intended.

Restoring the gate genuinely removes the v2 availability regression. It does not close the security defect for the fallback population. “Bounded capped fallback” also needs care: capped/complex delegation can persist indefinitely.

## 5. Major — Tri-state encoding is fixed; protocol doctrine is not

**Grounding:** `docs/pr/9522/plan.md:183-198`; `userspace-dp/src/protocol/control.rs:96-103`; `userspace-dp/src/protocol/snapshot.rs:650-657`.

Absent-as-legacy is now representable and the mixed-version behavior is honestly described.

But the v9 doctrine **explicitly rejects** unchanged defective behavior as sufficient justification for ignoring a new security-relevant field. This attestation controls whether the helper performs the adjudication intended to fix #9522. Calling the defect “helper-local disposition” does not remove that dependency.

V10’s capped-miss disposition precedent is particularly direct. Require refusal/versioning, or an explicitly approved doctrine exception—not another assertion that unchanged behavior proves compatibility.

## 6. Major — Cost containment remains unquantified and can make the residual dominant

**Grounding:** `docs/pr/9522/plan.md:157-162,248-254,291-308`.

There is still **no numeric deadline** in §9: M2 promises to choose one later. There is also no burst/fairness bound or acceptable unrelated-flow latency threshold.

One outstanding query per worker bounds concurrency, not cumulative blocking. A global rate ceiling does not prevent concentration on one worker.

Negative caching helps repeated keys; a distinct-key workload still requires one query per miss until the ceiling sends traffic into unadjudicated fallback. M3 cannot assume that caching “holds” this class.

**Q3 population disposition:** I cannot honestly kill on deployment percentages without measurements. But the residual is not confined to complex-rule deployments: capacity exhaustion creates it on ordinary-rule boxes too. Measure:

- representative capped deployments’ attestation eligibility;
- traffic-weighted determinate versus fallback fractions;
- sustained admitted lookup capacity and unrelated-flow latency;
- baseline-versus-A permit throughput.

Define acceptance thresholds **before wiring**, rather than merely collecting numbers.

## Round-2 closure ledger

| Prior concern | V3 disposition |
|---|---|
| Origin ingress/forced table | Specific mismatch fixed; overall mirror equality remains open |
| Incomplete cache key | Listed-field omissions fixed; hash/context completeness remains open |
| TTL versus parity | Weaker promise acknowledged; approval and accurate bound missing |
| Sentinel fallback | Gate restored; contradictory default-deny sentence remains |
| Attestation | Known DSCP reader issue addressed; completeness unproven |
| Encoding/versioning | Encoding fixed; doctrine conflict remains |
| Synchronous cost | Ownership improved; quantitative acceptance missing |
| Alternative B | Satisfactorily deferred; pointer need not be deleted |

**Bottom line:** v3 has meaningful repairs, but still promotes an insufficiently characterized routing oracle to a real-zone authorization authority. Under its own mirror-equality-or-kill rule, it cannot proceed as specified.
