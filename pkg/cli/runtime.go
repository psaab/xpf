// Package cli — runtime interface used by the interactive Junos CLI.
//
// The migration target for #1517 (sub-#1451 S2): replace the legacy
// dataplane.DataPlane parameter/field with cliRuntime, a narrow
// CLI-specific surface that lists exactly the methods pkg/cli/*.go
// invokes via c.dp.*. This mirrors the pattern already shipped by
// pkg/api (apiRuntimeDataPlane), pkg/fwdstatus (DataPlaneAccessor),
// pkg/monitoriface (RuntimeDataPlane), and pkg/conntrack
// (RuntimeDomainProvider).
//
// cliRuntime is a strict subset of dataplane.DataPlane. Every concrete
// dataplane in the tree today (the legacy eBPF Manager, the userspace
// LegacyDataPlaneAdapter, the DPDK manager) already satisfies it.
package cli

import (
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// cliRuntime is the narrow, CLI-specific view of the dataplane.
//
// Do NOT widen this set without a callsite reason. If a new c.dp.<X>
// invocation appears in pkg/cli, add it here and audit whether it
// truly needs to be on the operator-CLI surface, or whether it should
// be served via a typed domain provider on c instead.
type cliRuntime interface {
	// Lifecycle / health
	IsLoaded() bool

	// Compilation (used by candidate-config preview)
	Compile(cfg *config.Config) (*dataplane.CompileResult, error)

	// Counters
	ReadGlobalCounter(idx uint32) (uint64, error)
	ReadInterfaceCounters(ifindex int) (dataplane.InterfaceCounterValue, error)
	ReadZoneCounters(zoneID uint16, direction int) (dataplane.CounterValue, error)
	ReadPolicyCounters(ruleID uint32) (dataplane.CounterValue, error)
	ReadFilterConfig(filterID uint32) (dataplane.FilterConfig, error)
	ReadFilterCounters(filterID uint32) (dataplane.CounterValue, error)
	ReadFloodCounters(zoneID uint16) (dataplane.FloodState, error)
	ReadNATPortCounter(id uint32) (uint64, error)
	ReadNATRuleCounter(id uint32) (dataplane.CounterValue, error)

	// Sessions
	SessionCount() (v4, v6 int)
	IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
	DeleteSession(key dataplane.SessionKey) error
	DeleteSessionV6(key dataplane.SessionKeyV6) error

	// DNAT static entry delete (used by filtered session clear)
	DeleteDNATEntry(key dataplane.DNATKey) error
	DeleteDNATEntryV6(key dataplane.DNATKeyV6) error

	// Clear-counter / clear-session bulk ops
	ClearAllCounters() error
	ClearAllSessions() (v4, v6 int, err error)
	ClearFilterCounters() error
	ClearNATRuleCounters() error
	ClearPolicyCounters() error

	// Map stats + persistent NAT table (used by show + clear NAT bindings)
	GetMapStats() []dataplane.MapStats
	GetPersistentNAT() *dataplane.PersistentNATTable
}

// cliUserspaceStatusProvider is implemented by dataplanes that expose
// the userspace helper's ProcessStatus snapshot (queue/binding/CoS).
// It replaces the inline `c.dp.(interface{ Status() ... })` probes that
// were in cli_show_chassis.go and cli_show_system.go — those two sites
// SPECIFICALLY, not every inline probe in the tree. Codex PR #6743 r7:
// anonymous-interface probes still exist for OTHER capabilities
// (cli_show_nat.go's deterministic-NAT view, pkg/api's NAT and system
// paths); they are correct because they all resolve through dpProbe()
// first, which is the property the #2114 canary fences — a named interface
// here is a readability choice, not the safety mechanism.
type cliUserspaceStatusProvider interface {
	Status() (dpuserspace.ProcessStatus, error)
}

// cliUserspaceCrashProvider is the #7250 helper-crash accessor.
//
// SEPARATE from cliUserspaceStatusProvider rather than folded into it: the
// crash record is Manager state that outlives the helper process, whereas
// ProcessStatus is the helper's own published status and is CLEARED when the
// helper dies. Widening the status interface would also have forced every
// existing implementor — including test fakes — to grow a method they have no
// use for.
type cliUserspaceCrashProvider interface {
	HelperCrashState() (dpuserspace.HelperCrashRecord, bool)
}

// cliUserspaceCrashHistoryProvider is the #8397 completed-episode accessor.
//
// Separate from cliUserspaceCrashProvider because current crash state and
// recovered history have different lifetimes: a successful restart wipes the
// current record while the manager retains the episode in its history ring.
type cliUserspaceCrashHistoryProvider interface {
	HelperCrashHistory() ([]dpuserspace.HelperCrashEpisode, int)
}

// cliUserspaceControlProvider extends the status provider with the
// mutating control operations used by `request chassis cluster
// data-plane userspace ...` (the sole CLI consumer, handled in
// cli_request.go:handleRequestChassisClusterDataPlane). Replaces the
// larger inline anonymous interface probe in cli_helpers.go's
// userspaceDataplaneControl helper.
type cliUserspaceControlProvider interface {
	cliUserspaceStatusProvider
	SetForwardingArmed(bool) (dpuserspace.ProcessStatus, error)
	SetQueueState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
	SetBindingState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
	InjectPacket(dpuserspace.InjectPacketRequest) (dpuserspace.ProcessStatus, error)
}

// dpProbe returns the value that OPTIONAL-capability assertions must be
// made against. See pkg/grpcapi/runtime.go's dpProbe for the full #2114 /
// #6743-F1 rationale: the daemon publishes a live indirection whose method
// set is exactly cliRuntime, so probing it directly erases
// cliUserspaceStatusProvider, cliUserspaceControlProvider, the session
// cursor and the applied-NAT view for a healthy backend. Unwrap is the
// identity for a plain backend and nil once the daemon has disowned one.
func (c *CLI) dpProbe() any {
	if c == nil {
		return nil
	}
	return dataplane.Unwrap(c.dp)
}

// backendSessionCount and backendMapStats read the mandatory management
// surface off an ALREADY-RESOLVED backend (Codex PR #6743 r7-F3).
//
// showSystemBuffers / showSystemBuffersDetail take exactly one
// dataplane.Unwrap and must not take another: c.dp.SessionCount() and
// c.dp.GetMapStats() are each a fresh cell load, and a setDataplane(nil)
// landing between the publication check and the map read made the render
// print "No BPF maps available" — a claim about a LOADED backend's maps —
// for a daemon that had just lost its backend. Asserting off the single
// resolution keeps the whole render describing one instant.
//
// Both narrow interfaces are part of cliRuntime, so every value that can be
// stored in CLI.dp satisfies them; the ok=false arms are the
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
