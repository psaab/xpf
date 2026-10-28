// Package cli — runtime interface used by the interactive Junos CLI.
//
// The migration target for #1517 (sub-#1451 S2): replace the legacy
// dataplane.DataPlane parameter/field with cliRuntime, a narrow
// CLI-specific surface that lists exactly the methods pkg/cli/*.go
// invokes via c.dp.*. This mirrors the pattern already shipped by
// pkg/api (apiRuntimeDataPlane), pkg/fwdstatus (DataPlaneAccessor),
// pkg/monitoriface (RuntimeDataPlane).
//
// cliRuntime is a strict subset of dataplane.DataPlane. Every concrete
// dataplane in the tree today (the legacy eBPF Manager, the userspace
// LegacyDataPlaneAdapter, the DPDK manager) already satisfies it.
package cli

import (
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dataplane/mgmtview"
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
	ReadZoneCounters(zoneID uint32, direction int) (dataplane.CounterValue, error)
	ReadPolicyCounters(ruleID uint32) (dataplane.CounterValue, error)
	ReadFilterConfig(filterID uint32) (dataplane.FilterConfig, error)
	ReadFilterCounters(filterID uint32) (dataplane.CounterValue, error)
	ReadFloodCounters(zoneID uint32) (dataplane.FloodState, error)
	ReadNATPortCounter(id uint32) (uint64, error)
	ReadNATRuleCounter(id uint32) (dataplane.CounterValue, error)

	// Sessions
	SessionCount() (v4, v6 int)
	IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
	DeleteSession(key dataplane.SessionKey) error
	DeleteSessionV6(key dataplane.SessionKeyV6) error

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

// cliUserspaceFIBProvider exposes the current worker-visible userspace FIB.
// It stays separate from Status because it is an operator-triggered,
// potentially large control-socket read rather than periodic telemetry.
type cliUserspaceFIBProvider interface {
	DumpFIB() (uint32, []dpuserspace.FibRouteWire, error)
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
// made against. It is the shared mgmtview.Probe: exactly one
// dataplane.Unwrap per call, resolved fresh against the backend
// published at this instant, never cached across backend replacement
// (#2114/#6743-F1; see mgmtview.Probe for the full rationale). The nil
// receiver answers nil so a probe after teardown fails closed.
func (c *CLI) dpProbe() any {
	if c == nil {
		return nil
	}
	return mgmtview.Probe(c.dp)
}

// backendSessionCount and backendMapStats read the mandatory management
// surface off an ALREADY-RESOLVED backend via the shared mgmtview
// helpers (Codex PR #6743 r7-F3).
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
	return mgmtview.SessionCount(backend)
}

func backendMapStats(backend any) []dataplane.MapStats {
	return mgmtview.MapStats(backend)
}
