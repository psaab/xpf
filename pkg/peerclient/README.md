# peerclient

Transport-neutral peer-proxy reconciliation shared by the CLI and
gRPC peer-proxy frontends (#16154).

The two frontends dial differently and stay different: pkg/cli's
`dialPeer` tries fab0 then fab1 behind a background TCP reachability
probe and returns nil when unreachable; pkg/grpcapi's `Server.dialPeer`
is ctx-bound and probes liveness with an RPC/GetStatus call, where a
`ResourceExhausted` response still means the peer is alive (#8597).
Unifying those dialers would flip wedged-server reachability and could
change fabric-auth / signed-request metadata handling, so only the
pure reconciliation table is shared here: `TimeoutFor` (proxy deadline
sizing), `IsDeadline` (deadline classification), and `Reconcile`
(post-deadline RG-ownership reconciliation, #15081).

Each frontend keeps its own dialer, its own RPC deadline construction,
and its own fabric-auth credential/token construction. `Reconcile`
takes an `Ownership` interface satisfied directly by
`*cluster.Manager`; it returns an `Outcome` verdict
(`OutcomeCommitted` / `OutcomeUnknown` / `OutcomeNone`, #16432) so the
frontends can map unknown to a distinct non-OK status without parsing
the message; its message templates are byte-pinned by
`peerclient_16154_test.go` against the pre-refactor twin wording.

## One "reached the peer" test (#18559)

`ProbeFabricTCP` is the TCP reachability probe both dialers run per fabric
address: `CLI.dialPeerReached` and `Server.dialPeerReached`. It is the single
transport-absence test behind the untargeted-failover fallback. A request
counts as never having reached the peer only when no fabric address accepted
a TCP connection: the connection was refused, the address was unreachable, or
no SYN-ACK arrived within `ProbeFabricTCPTimeout` (2 s). Only then may
`request chassis cluster failover redundancy-group N` on an owner fall back to
the break-before-make local resign.

A peer that accepted the connection and then answered anything has been
reached, and its answer is returned. That covers the gRPC dialer's
authenticated `GetStatus` probe failing (`Unauthenticated` under fabric-token
skew, or slower than 2 s) and any RPC error. The dialers themselves stay
separate, as above: they only share the probe and the rule.
