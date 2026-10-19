package clusterfailover

import "time"

// Failover proxy budget (#15081).
//
// A forwarded node-targeted failover runs, on the peer, the full
// RequestPeerFailover sequence: a failover-ACK round-trip bounded by the
// cluster failoverAckTimeout (20s), the local commit-ready settle
// (localFailoverCommitTimeout, 3s default), and the failover-commit
// round-trip (also bounded by failoverAckTimeout). The daemon sizes the
// owner-side transfer-out lease as 2*localFailoverCommitTimeout+20s for
// the same worst-case post-ACK commit latency (daemon_ha_comms_wiring.go),
// so the proxy deadline that wraps the whole forwarded call must cover
// strictly more than one such lease window: two ACK/commit round-trips
// plus the settle.
//
// FailoverAckTimeout mirrors pkg/cluster's failoverAckTimeout (sync.go).
// It is duplicated here because pkg/cluster imports this package for the
// grammar (pkg/cli and pkg/grpcapi go through clusterfailover); importing
// pkg/cluster from here would cycle. A parity test in pkg/cluster pins
// the two constants together.
const FailoverAckTimeout = 20 * time.Second

// DefaultCommitSettle mirrors the daemon's default
// localFailoverCommitTimeout (pkg/daemon: 3s). Like FailoverAckTimeout it
// is the proxy-side copy of a value owned elsewhere; the daemon is not
// importable from the proxy layers.
const DefaultCommitSettle = 3 * time.Second

// ProxyFailoverTimeout is the deadline a node applies when it forwards a
// node-targeted cluster failover (KindRGFailoverNode / KindDataFailover)
// to its peer: 2*FailoverAckTimeout (request ACK + commit ACK) plus the
// commit settle, mirroring the daemon's
// 2*localFailoverCommitTimeout + 20s lease sizing at the defaults
// (46s vs 26s lease) with headroom for the gRPC hop itself.
//
// It replaces the flat 5s proxy deadline (#15081): a legitimate failover
// whose barrier ACK alone may be delayed 30+s by bulk session sync
// (daemon_ha_userspace_readiness.go) always exceeded 5s, so the operator
// received a bare DeadlineExceeded while the peer completed the transfer.
const ProxyFailoverTimeout = 2*FailoverAckTimeout + 2*DefaultCommitSettle

// IsFailoverActionString reports whether the wire action belongs to the
// failover family AND names an explicit target node — the only forms a
// node proxies to its peer. Malformed family members return false: they
// are rejected by ParseAction before any proxy dial, so sizing their
// (never-taken) proxy leg is moot. Non-failover actions return false.
func IsFailoverActionString(action string) bool {
	op, err := ParseAction(action)
	return err == nil && op.Targeted()
}
