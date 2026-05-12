# TCP Head-Start Fairness Floor

Issue #1233 asks whether xpf should add a dataplane-only mechanism to
mask the iperf3 sender's TCP head-start effect. Current answer:
**do not add a new Approximate Fair Dropping (AFD)-style
leader-selective ECN/drop overlay or receive-window clamping mechanism
unless a fresh, multi-sample harness run produces an actionable fairness
failure.** This does not change xpf's existing CoS-admission/AQM ECN
behavior; it rejects a new per-flow TCP head-start policing loop in the
forwarding path.

## Evidence

The loss-cluster sweep in `docs/per-5-tuple/even-flows-recipe.md`
separates three effects:

- RSS placement determines the structural `Cstruct` ceiling.
- Worker CPU isolation affects per-worker capacity.
- The first iperf3 stream can retain a larger cwnd after the other
  streams join, even after `-O 30` warmup omission and long runs.

The strongest counterexample is the sub-saturation recipe: with fixed
source-port placement plus per-flow sender pacing, the same dataplane
delivered 12 flows within about 1.5% of each other. That makes the
head-start effect a sender/TCP behavior, not proof of an xpf scheduler
defect.

## Option A: Per-Flow AFD ECN/Drop Overlay

Per-flow ECN marking for TCP head-start correction is the #1211
Approximate Fair Dropping (AFD) design under a narrower name. It
requires:

- ECN-capable TCP endpoints that negotiated ECN on the flow.
- A per-flow lead/lag estimator in the forwarding path.
- A control loop that marks only the leading flow strongly enough to
  reduce cwnd, without causing oscillation or starving it.
- Hot-path accounting that does not add cross-worker cache-line
  contention.

It also acts late: by the time xpf can observe a head-start leader,
that flow already has a larger cwnd. If the sender does not react to
CE marks, the mechanism is inert; if it does react, convergence is
sender-algorithm dependent. Reopen this class only under the archived
#1211 revisit criteria in
`docs/per-5-tuple/path2-archive/CLOSING-RATIONALE.md` and
`docs/per-5-tuple/path2-archive/plan-v10.md`: a real harness FAIL,
ECN-responsive senders, no app/server bottleneck, and a prototype that
avoids contended shared per-packet writes.

## Option B: Receive-Window Clamping

Firewall-side RWND clamping would rewrite ACKs in the reverse
direction to reduce the advertised receive window of the leading
flow. It is technically possible, but it is not a clean xpf product
feature:

- The dataplane must track TCP window scale from SYN/SYN-ACK before
  it can compute a meaningful byte window.
- It must rewrite ACK headers and TCP checksums on every controlled
  flow in the reverse direction.
- It limits throughput by `min(cwnd, rwnd)`, so a bad target can drop
  aggregate throughput instead of transferring bandwidth to lagging
  flows.
- It interacts with receiver autotuning, delayed ACKs, zero-window
  probes, application receive buffers, and middlebox expectations.
- It changes TCP semantics for all affected applications, not just
  iperf3 test traffic.

RWND clamping is a last-resort traffic-policing feature, not the
right default response to a benchmark sender artifact.

## Accepted Path

For measurements whose purpose is to isolate dataplane fairness:

- Use sender-side pacing (`tc-fq`, `SO_MAX_PACING_RATE`, or iperf3
  `-b`) when the test intent is equal per-flow offered load.
- Use fixed or swept source ports when the test intent is a known RSS
  distribution.
- Publish verdict JSON keys `observed_cov`, `cstruct`, `gap`,
  `starved_flow_count`, `aggregate_mbps`, and the iperf CPU fields,
  plus the multi-sample mean/stdev/max CoV.

For production traffic, xpf's fairness contract remains
workload-relative. The PR #1217/#1220 gate passes only when there are
no starved flows, `observed_CoV ≤ Cstruct + epsilon` (`epsilon = 0.05`),
any configured RSS/workload expectation is satisfied, saturated runs
clear the aggregate-throughput gate, and optional mouse probes stay
within the p99 SLA. A saturated TCP sender that creates unequal offered
load is outside what a transparent AF_XDP firewall can fix without
becoming an endpoint-side pacing or TCP-policing device.

## Revisit Criteria

Open a new implementation issue only if all of these are true:

1. The current userspace dataplane fails the harness on a real
   workload after multi-sample measurement.
2. The failure is `observed_CoV - Cstruct > 0.05` or starvation, not
   merely a high absolute CoV caused by RSS structure.
3. Sender and receiver CPU are not the bottleneck.
4. The endpoints are known to be responsive to the proposed signal
   (ECN for ECN marking, receive-window limiting for RWND clamping).
5. The proposal includes a hot-path design with no contended shared
   per-packet writes, such as a shared atomic counter or cross-NUMA
   cache-line bounce in the forwarding loop.

## Resolution for #1233

Issue #1233 is resolved as documentation and measurement policy, not a
dataplane feature. The accepted mitigation is sender-side pacing/source
port control for test workloads, plus the multi-sample fairness gate
from PR #1220. Any future dataplane ECN/drop or RWND proposal must open
a new issue and satisfy the revisit criteria above.
