# Codex — hostile plan review r1 (#2562)

Adversarial design review of `docs/research/2562-nat64-frag/plan.md` (v1).
Verbatim agent result (harness tags stripped).

## 1. Bug Confirmation
FINDING [OK]: Non-first NAT64 fragments do not get NAT64 translation today —
confirmed. Parser makes non-first fragments flowless at
`userspace-dp/src/afxdp/frame/inspect.rs:1224-1234`; NAT64 classify is only in the
flow-backed cold path at `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1053-1055`;
flowless arm returns `nat: NatDecision::default()` at
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2884-2887`. Translators also fail
closed at `userspace-dp/src/nat64.rs:760-764` and `userspace-dp/src/nat64.rs:991-998`.

## 2. Share Conclusion
FINDING [MINOR]: Generic `SessionDecision`/`NatDecision` is data-sufficient, but
current egress API is not. `NatDecision` carries rewrite fields and `nat64` at
`nat/mod.rs:67-75`; forward NAT64 fills `snat_v4/dst_v4` at `nat64.rs:373-380`;
reverse decision maps back to original v6 addresses via `NatDecision::reverse` at
`nat/mod.rs:89-95` and `poll_descriptor/mod.rs:2368-2375`. However, reverse frame
build currently requires `Nat64ReverseInfo`, not just `decision.nat`, at
`afxdp/frame/mod.rs:246-253`. SHARE stands only if the NAT64 egress adaptation is
made explicit — the plan understates this coupling.

## 3. Process-Shared Refinement (plan §5.3)
FINDING [MAJOR]: The plan's "worker-local session" argument is partly wrong.
`SessionTable` is per-worker (`setup.rs:40`, `:120`; `session/mod.rs:447-457`), but
sessions are already published and replicated across all workers via `UpsertSynced`
at `poll_descriptor/mod.rs:2298-2322` and `:2594-2603`, enqueued at
`session_glue/mod.rs:722-731`, installed on peer workers at
`session_glue/commands/upsert_synced.rs:64-85`, and shared-lookup exists at
`shared_ops.rs:563-605`. The real blocker for a worker-local fragment cache is not
lack of cross-worker session visibility — it's that non-first fragments carry no
`SessionKey` derivable from `frame/inspect.rs:1224-1234` and `session/key.rs:10-16`.
Revise to "session is replicated to all workers, so a worker-local fragment cache
would work IFF the first fragment's worker installs the cache entry before any
non-first fragment arrives on any worker" — an ordering hazard, not a fundamental
sharing requirement.

FINDING [MINOR]: RSS fragment split is asserted but not verified from code. It is
NIC/RSS behavior. Cite ethtool evidence or hedge as an assumption.

## 4. ICMP Fragments
FINDING [OK]: Dropping fragmented ICMP/ICMPv6 is correct per RFC 7915 — the RFC
explicitly says these will not be translated. Implementation at `nat64.rs:1347-1353`
(deferred checksum) and `nat64.rs:1089-1094` (skipped recompute on non-first) also
shows why translation would be unsafe.

## 5. Verdict
FINDING [OK]: PLAN-DEFER is the right verdict. Bug is real, SHARE direction is
mostly sound, blocker on #3291 stage 4 is valid. Co-delivery (PLAN-READY) would be
premature given the cross-worker ordering hazard not addressed and the NAT64
reverse-egress adaptation understated.

## 6. RFC / Field Claims
FINDING [OK]: No material RFC 7915 fragment-field error found. v6→v4 low-16 ident
at `nat64.rs:819-823`, v4→v6 zero-extension at `nat64.rs:1047-1049`, length
accounting `-20-8`/`+20+8` consistent with `nat64.rs:851-852` and `nat64.rs:1079-1081`.

## Overall verdict: PLAN-DEFER
Two concrete errors corrected before deferring: (1) the cross-worker analysis
overstates the problem — sessions ARE replicated to all workers, so the real hazard
is first-fragment ordering rather than a process-shared cache requirement; (2) the
SHARE conclusion understates the NAT64 reverse-egress adaptation needed
(`Nat64ReverseInfo` vs `decision.nat`). Neither changes the verdict.

## Disposition (folded into plan v3)
- #3 (MAJOR) → §3.4 rewritten (sessions cross-worker visible via
  `publish_shared_session` + `replicate_session_upsert`), §5.3 reframed (L3+IP-ID
  index riding the existing replication machinery, not a new sharded mutex;
  ordering-race = miss-drop+counter), Q2/Q3 RESOLVED.
- #2 (MINOR) → §3.3/§5.1 refined to "data-sufficient, egress-API-insufficient".
- #3 (MINOR, RSS) → §3.4 hedged "asserted as NIC behavior, not proven from code".
- #1/#4/#5/#6 (OK) → confirm the bug, ICMP drop, verdict, and RFC field claims.
