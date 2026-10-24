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
