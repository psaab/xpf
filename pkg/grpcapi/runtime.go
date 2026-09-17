package grpcapi

import (
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// grpcRuntime is the gRPC server's domain-specific dataplane
// surface. Lists exactly the methods the gRPC handlers consume on
// master. Narrower than dataplane.DataPlane; intentionally not
// exported.
type grpcRuntime interface {
	// Liveness probe — guards every counter / iter call site.
	IsLoaded() bool

	// Counters (read).
	ReadGlobalCounter(index uint32) (uint64, error)
	ReadInterfaceCounters(ifindex int) (dataplane.InterfaceCounterValue, error)
	ReadZoneCounters(zoneID uint16, direction int) (dataplane.CounterValue, error)
	ReadPolicyCounters(policyID uint32) (dataplane.CounterValue, error)
	ReadFilterConfig(filterID uint32) (dataplane.FilterConfig, error)
	ReadFilterCounters(ruleIdx uint32) (dataplane.CounterValue, error)
	ReadFloodCounters(zoneID uint16) (dataplane.FloodState, error)
	ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error)

	// Counters (clear) — diag/clear paths.
	ClearPolicyCounters() error
	ClearFilterCounters() error
	ClearNATRuleCounters() error
	ClearAllCounters() error

	// Session store (read).
	IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
	GetSessionV4(key dataplane.SessionKey) (dataplane.SessionValue, error)
	GetSessionV6(key dataplane.SessionKeyV6) (dataplane.SessionValueV6, error)
	SessionCount() (v4, v6 int)

	// Session store (clear / delete) — `clear security flow session ...`.
	ClearAllSessions() (v4 int, v6 int, err error)
	DeleteSession(key dataplane.SessionKey) error
	DeleteSessionV6(key dataplane.SessionKeyV6) error
	DeleteDNATEntry(key dataplane.DNATKey) error
	DeleteDNATEntryV6(key dataplane.DNATKeyV6) error

	// NAT bindings / system buffers.
	GetPersistentNAT() *dataplane.PersistentNATTable
	GetMapStats() []dataplane.MapStats
}

// sessionCursorIterator: optional cursor-based iteration; consumed via
// type assertion in server_sessions.go:getSessionsCursor.
type sessionCursorIterator interface {
	IterateSessionsFrom(cursor *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6From(cursor *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
}

// userspaceStatusProvider: probe for the userspace-specific Status() call.
type userspaceStatusProvider interface {
	Status() (dpuserspace.ProcessStatus, error)
}

// userspaceCrashProvider is the #7250 helper-crash accessor. Separate from
// userspaceStatusProvider for the reason given on its pkg/cli twin: the crash
// record is Manager state that survives the helper, ProcessStatus is the
// helper's own and is cleared when it dies.
type userspaceCrashProvider interface {
	HelperCrashState() (dpuserspace.HelperCrashRecord, bool)
}
// userspaceCrashHistoryProvider is the #8397 completed-episode accessor.
//
// Separate from userspaceCrashProvider because current crash state and
// recovered history have different lifetimes: a successful restart wipes the
// current record while the manager retains the episode in its history ring.
type userspaceCrashHistoryProvider interface {
	HelperCrashHistory() ([]dpuserspace.HelperCrashEpisode, int)
}

// userspaceControlProvider: superset of statusProvider used by the
// diag/control path (queue/binding admin, forwarding-armed, inject).
type userspaceControlProvider interface {
	userspaceStatusProvider
	SetForwardingArmed(bool) (dpuserspace.ProcessStatus, error)
	SetQueueState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
	SetBindingState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
	InjectPacket(dpuserspace.InjectPacketRequest) (dpuserspace.ProcessStatus, error)
}

// dpProbe returns the value that OPTIONAL-capability assertions must be
// made against.
//
// #2114/#6743-F1: the daemon hands Server.dp a live indirection
// (pkg/daemon's liveDataPlane) whose method set is exactly the MANDATORY
// grpcRuntime surface above. Asserting an optional capability directly on
// that value — the session cursor, Status(), AppliedNATView, the
// userspace controls, the policy-scheduler state — fails for a perfectly
// HEALTHY backend that implements it, silently degrading session paging to
// the O(N^2) fallback and blanking whole answer families. dataplane.Unwrap
// resolves to the backend published AT THIS INSTANT; it returns nil once
// the daemon has disowned the backend, so the probe still fails closed
// after a setDataplane(nil). For a plain backend — every test, every
// non-daemon embedder — it is the identity.
func (s *Server) dpProbe() any {
	if s == nil {
		return nil
	}
	return dataplane.Unwrap(s.dp)
}

// backendSessionCount and backendMapStats read the mandatory management
// surface off an ALREADY-RESOLVED backend (Codex PR #6743 r7-F3).
//
// The buffer renders in server_show_system.go take exactly one
// dataplane.Unwrap and must not take another: calling s.dp.SessionCount()
// or s.dp.GetMapStats() there would each be a fresh cell load, and a
// setDataplane(nil) landing between the publication check and the map read
// made the render print "No BPF maps available" — a claim about a LOADED
// backend's maps — for a daemon that had just lost its backend. Asserting
// off the single resolution keeps the whole render describing one instant.
//
// Both narrow interfaces are part of grpcDataPlane, so every value that can
// be stored in Server.dp satisfies them; the ok=false arms are the
// forward-compatibility answer for a future backend that does not.
func backendSessionCount(backend any) (v4, v6 int) {
	c, ok := backend.(interface{ SessionCount() (int, int) })
	if !ok {
		return 0, 0
	}
	return c.SessionCount()
}

func backendMapStats(backend any) []dataplane.MapStats {
	m, ok := backend.(interface{ GetMapStats() []dataplane.MapStats })
	if !ok {
		return nil
	}
	return m.GetMapStats()
}
