// Package daemon — local typed probes used by daemon internals once
// the (*Daemon).legacyDP() escape hatch is gone (#1519, sub-#1451 S4).
//
// Each probe lists exactly the methods one daemon call site needs.
// All probes are package-private (lowercase identifiers) so they
// stay out of the daemon's public surface; downstream consumers
// (pkg/api, pkg/grpcapi, pkg/cli) declare their own narrow surfaces
// (apiRuntimeDataPlane, grpcRuntime, cliRuntime) and Go's structural
// typing accepts any value satisfying the matching shape at the
// call site without requiring cross-package interface imports.
//
// Compile-time assertions that every in-tree backend
// (*dataplane.Manager and *dataplane/userspace.LegacyDataPlaneAdapter)
// satisfies each probe live in runtime_probes_test.go.
package daemon

import (
	"context"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// dataplaneReadyProbe is the minimal lifecycle probe used by daemon
// internals to gate operations on a started dataplane. Both the
// legacy eBPF *dataplane.Manager and the userspace
// *LegacyDataPlaneAdapter implement it.
type dataplaneReadyProbe interface {
	IsLoaded() bool
}

// natSeeder is satisfied by backends that prime BPF NAT-port and
// session-ID maps after Start. The legacy eBPF Manager satisfies
// it directly; the userspace adapter inherits via the embedded
// bpfShim.
type natSeeder interface {
	SeedNATPortCounters()
	SeedSessionIDCounter(int)
}

// fibSyncStarter is satisfied by backends that maintain a userspace
// FIB. Both in-tree backends document StartFIBSync as a no-op (the
// kernel-side bpf_fib_lookup handles FIB resolution); the probe is
// retained for forward compatibility (DPDK had a real one before
// the #1525/#1527 retirement, and a future backend may need one).
type fibSyncStarter interface {
	StartFIBSync(context.Context)
}

// apiDataPlane mirrors pkg/api/handlers.go's apiRuntimeDataPlane
// shape so daemon_run.go can construct api.Config{DP: ...} without
// legacyDP(). Go's structural typing accepts any value satisfying
// this surface as assignable to api.Config.DP at the call site.
// Drift between this declaration and pkg/api's package-private
// apiRuntimeDataPlane will surface as a compile error at the
// assignment site (daemon_run.go).
type apiDataPlane interface {
	IsLoaded() bool
	IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
	GetSessionV4(dataplane.SessionKey) (dataplane.SessionValue, error)
	GetSessionV6(dataplane.SessionKeyV6) (dataplane.SessionValueV6, error)
	// SessionCount feeds REST /status from the live session table (#3929).
	SessionCount() (v4, v6 int)
	SessionCountContext(context.Context) (v4, v6 int, err error)
	ClearAllSessions() (int, int, error)

	ReadGlobalCounter(uint32) (uint64, error)
	ReadInterfaceCounters(int) (dataplane.InterfaceCounterValue, error)
	ReadZoneCounters(uint16, int) (dataplane.CounterValue, error)
	ReadPolicyCounters(uint32) (dataplane.CounterValue, error)
	ReadFilterConfig(uint32) (dataplane.FilterConfig, error)
	ReadFilterCounters(uint32) (dataplane.CounterValue, error)
	ReadNATRuleCounter(uint32) (dataplane.CounterValue, error)
	ReadNATPortCounter(uint32) (uint64, error)
	ClearAllCounters() error
	GetMapStats() []dataplane.MapStats
}

// grpcDataPlane mirrors pkg/grpcapi/runtime.go's grpcRuntime so
// daemon_run.go can construct grpcapi.Config{DP: ...} without
// legacyDP(). Shape locked from the #1554 merge (master 265d6de7,
// see pkg/grpcapi/runtime.go).
type grpcDataPlane interface {
	IsLoaded() bool

	ReadGlobalCounter(index uint32) (uint64, error)
	ReadInterfaceCounters(ifindex int) (dataplane.InterfaceCounterValue, error)
	ReadZoneCounters(zoneID uint16, direction int) (dataplane.CounterValue, error)
	ReadPolicyCounters(policyID uint32) (dataplane.CounterValue, error)
	ReadFilterConfig(filterID uint32) (dataplane.FilterConfig, error)
	ReadFilterCounters(ruleIdx uint32) (dataplane.CounterValue, error)
	ReadFloodCounters(zoneID uint16) (dataplane.FloodState, error)
	ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error)

	ClearPolicyCounters() error
	ClearFilterCounters() error
	ClearNATRuleCounters() error
	ClearAllCounters() error

	IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
	GetSessionV4(key dataplane.SessionKey) (dataplane.SessionValue, error)
	GetSessionV6(key dataplane.SessionKeyV6) (dataplane.SessionValueV6, error)
	SessionCount() (v4, v6 int)
	ClearAllSessions() (v4 int, v6 int, err error)
	DeleteSession(key dataplane.SessionKey) error
	DeleteSessionV6(key dataplane.SessionKeyV6) error
	DeleteDNATEntry(key dataplane.DNATKey) error
	DeleteDNATEntryV6(key dataplane.DNATKeyV6) error

	GetPersistentNAT() *dataplane.PersistentNATTable
	GetMapStats() []dataplane.MapStats
}

// cliDataPlane mirrors pkg/cli/runtime.go's cliRuntime so
// daemon_run.go can construct cli.New(...) without legacyDP().
// cliRuntime is package-private to pkg/cli (intentional, per
// pkg/cli/runtime.go:24-28); the daemon declares its own matching
// shape here and relies on Go's structural typing for the
// assignment. Drift between this declaration and cli.cliRuntime
// surfaces as a compile error at the cli.New(...) call site.
type cliDataPlane interface {
	IsLoaded() bool

	Compile(cfg *config.Config) (*dataplane.CompileResult, error)

	ReadGlobalCounter(idx uint32) (uint64, error)
	ReadInterfaceCounters(ifindex int) (dataplane.InterfaceCounterValue, error)
	ReadZoneCounters(zoneID uint16, direction int) (dataplane.CounterValue, error)
	ReadPolicyCounters(ruleID uint32) (dataplane.CounterValue, error)
	ReadFilterConfig(filterID uint32) (dataplane.FilterConfig, error)
	ReadFilterCounters(filterID uint32) (dataplane.CounterValue, error)
	ReadFloodCounters(zoneID uint16) (dataplane.FloodState, error)
	ReadNATPortCounter(id uint32) (uint64, error)
	ReadNATRuleCounter(id uint32) (dataplane.CounterValue, error)

	SessionCount() (v4, v6 int)
	IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
	DeleteSession(key dataplane.SessionKey) error
	DeleteSessionV6(key dataplane.SessionKeyV6) error

	DeleteDNATEntry(key dataplane.DNATKey) error
	DeleteDNATEntryV6(key dataplane.DNATKeyV6) error

	ClearAllCounters() error
	ClearAllSessions() (v4, v6 int, err error)
	ClearFilterCounters() error
	ClearNATRuleCounters() error
	ClearPolicyCounters() error

	GetMapStats() []dataplane.MapStats
	GetPersistentNAT() *dataplane.PersistentNATTable
}
