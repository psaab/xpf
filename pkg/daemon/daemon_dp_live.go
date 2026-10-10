package daemon

import (
	"errors"
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #2114 (Codex PR #6743 r4): the atomic cell fixes ACQUISITION — every
// daemon-side read of the runtime dataplane goes through dataplane().
// It does not, on its own, stop the acquired handle from ESCAPING: the
// three operator-facing management servers used to snapshot the
// interface value ONCE at startup and hold it for the daemon's
// lifetime, so a later setDataplane(nil) (the bootstrap-exit re-arm
// failure at daemon_run_bringup.go:502, or the retired-backend clear at
// daemon_run_naming.go:251) left gRPC, REST and the console CLI still
// dispatching into a backend the daemon had already disowned. The cell
// said "no dataplane"; `show`/`clear` said otherwise.
//
// liveDataPlane closes that gap by making the value the servers hold a
// daemon-owned indirection rather than a backend handle: every method
// re-reads the cell (one atomic load) and forwards to whatever is
// published AT CALL TIME, or reports unavailable. It is the same idiom
// the forwarding-status sampler already uses
// (forwardingStatusDaemonDataPlane, daemon_forwarding_status.go),
// widened from one method to the full management surface.
//
// SCOPE — what this does NOT do. This is a PUBLICATION protocol, not a
// LIFETIME protocol. It guarantees "the handle I dispatch into is the
// one the daemon currently publishes"; it does NOT bound the lifetime
// of a backend that is still published. The commit-confirmed rollback
// deliberately leaves a torn-down backend in the cell so a corrected
// commit can re-arm THAT object (bootstrap.go:470-475, and the
// retention contract pinned by TestDataplaneCell_RollbackRearmRecurrence),
// so between Teardown() and the re-arm a management call still reaches
// a detached backend and the retained-unarmed registry state proceeds
// exactly as it did pre-#2114. Closing that window needs a
// generation/lease on the backend itself — tracked as #6741, not
// solvable at this boundary.
//
// SCOPE — which consumers are converted. The three OPERATOR-FACING
// management surfaces (gRPC, REST, console CLI) route through
// liveDataPlane. Of the three DATA-PATH consumers, TWO deliberately keep
// their capture-once wiring and the third resolves from the cell itself:
//
//   - conntrack GC (daemon_run.go) and cluster SessionSync
//     (daemon_ha_sync.go) do not take a RuntimeDataPlane at all — they
//     take the DECOMPOSED dataplane.SessionStore / dataplane.Telemetry
//     domains, resolved once by SessionStoreOf/TelemetryOf. Making
//     those live would put an atomic load, an interface assertion and a
//     SessionStoreOf allocation on every per-session GC sweep and sync
//     step; both loops are also lifecycle-scoped to the commsCtx/daemon
//     ctx that the same code path cancels. These two are the remaining
//     capture-once wiring.
//   - the userspace event-stream loop (daemon_ha_userspace_stream.go) is
//     NOT capture-once: it re-resolves the EventStream provider, the
//     stream instance and the session-delta drainer from the cell on
//     EVERY poll tick (#6743 r6-F4 for the first two, r7-F1 for the
//     drainer). It does not go through liveDataPlane — those are
//     helper-specific optional capabilities, not the mandatory
//     management surface — but it obeys the same rule: no handle
//     survives a tick, so a disowned backend stops being polled. Its
//     commsCtx is cancelled only by stopClusterComms, never by a
//     dataplane disown, which is precisely why capture-once was wrong
//     there.
//
// The two capture-once consumers are stated as such in
// pkg/daemon/README.md rather than claimed converted.

// errDataplaneUnpublished is returned by every liveDataPlane forwarder
// when the daemon's cell is empty at call time. Callers that pre-check
// with IsLoaded() (the dominant shape across pkg/grpcapi and pkg/api:
// `dp == nil || !dp.IsLoaded()`) take their existing "dataplane not
// loaded" branch instead and never reach a forwarder.
//
// It is the EXPORTED dataplane.ErrNotPublished so a management server can
// tell "the daemon currently has no dataplane" apart from a backend
// failure: pkg/grpcapi matches it with errors.Is and answers
// codes.Unavailable, the same code its `dp == nil || !IsLoaded()`
// pre-checks return, instead of reporting daemon lifecycle state as
// codes.Internal (Codex PR #6743 r6-F3).
var errDataplaneUnpublished = dataplane.ErrNotPublished

// errDataplaneSurfaceUnsupported is returned when a dataplane IS
// published but does not implement the management surface. Both in-tree
// backends do (see the compile-time assertions below), so this is the
// forward-compatibility arm for a backend that implements
// RuntimeDataPlane without the operator query/clear methods — the same
// condition the pre-r4 call sites expressed by leaving Config.DP nil.
var errDataplaneSurfaceUnsupported = errors.New("published dataplane does not implement the management surface")

// liveDataPlaneSurface is the UNION of the three daemon-local management
// probes (apiDataPlane, grpcDataPlane, cliDataPlane in runtime_probes.go).
// liveDataPlane forwards to it, and the compile-time assertions at the
// bottom of this file require liveDataPlane to satisfy all three probes —
// so a method added to any probe that is missing here fails the build
// rather than silently dropping out of the live path.
type liveDataPlaneSurface interface {
	IsLoaded() bool

	Compile(cfg *config.Config) (*dataplane.CompileResult, error)

	ReadGlobalCounter(index uint32) (uint64, error)
	ReadInterfaceCounters(ifindex int) (dataplane.InterfaceCounterValue, error)
	ReadZoneCounters(zoneID uint16, direction int) (dataplane.CounterValue, error)
	ReadPolicyCounters(policyID uint32) (dataplane.CounterValue, error)
	ReadFilterConfig(filterID uint32) (dataplane.FilterConfig, error)
	ReadFilterCounters(ruleIdx uint32) (dataplane.CounterValue, error)
	ReadFloodCounters(zoneID uint16) (dataplane.FloodState, error)
	ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error)
	ReadNATPortCounter(id uint32) (uint64, error)

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

// liveDataPlane is the daemon-owned management-surface indirection over
// the #2114 cell. It is a VALUE type holding only the daemon pointer, so
// a copy stored in grpcapi.Server.dp / api.Server.dp / cli.CLI.dp carries
// no backend reference at all — there is nothing for a consumer to keep
// alive past a setDataplane(nil).
type liveDataPlane struct{ daemon *Daemon }

// Unwrap implements dataplane.LiveUnwrapper: it returns the backend the
// daemon publishes AT THE MOMENT OF THE CALL, or nil.
//
// Codex PR #6743 r6-F1. liveDataPlane has no embedded field, so its method
// set is exactly the 27 forwarders below — every OPTIONAL capability the
// management servers reach by asserting on `any` (LastApplyResult,
// Sessions, Telemetry, Status, AppliedNATView, the session cursor, the
// userspace controls) was ERASED the moment the servers started holding
// the adapter instead of the backend. That is not a lifecycle narrowing,
// it is a silent capability loss on a HEALTHY deployment: NAT-pool and
// userspace Prometheus families stop being emitted, NAT statistics report
// healthy zeros, and session paging falls back to the explicitly O(N^2)
// path. Enumerating the union into liveDataPlaneSurface would only move
// the failure to the next capability a backend gains.
//
// Unwrap is deliberately NOT a way to keep a backend across the daemon's
// lifecycle: it resolves through the same cell load as every forwarder and
// returns nil once the daemon has disowned the backend, so a probe made
// after a setDataplane(nil) fails its assertion and the consumer takes its
// "capability unavailable" branch.
//
// WHAT THE CALLER ACTUALLY HOLDS (Codex PR #6743 r7-N1). Not "a handle for
// the one call it is about to make" — several consumers legitimately keep
// the resolved handle for a whole OPERATION spanning multiple backend
// calls, and re-resolving mid-operation would be wrong, not safer:
//
//   - pkg/cli's request-chassis inject path and pkg/grpcapi's
//     userspace-inject action both resolve once, call Status() to build the
//     request, then InjectPacket() against the SAME provider — the second
//     call must land on the backend the first one described;
//   - the gRPC session-cursor loops iterate the cursor they resolved,
//     which is what makes them a cursor.
//
// So the guarantee is per-OPERATION, not per-call: the handle a consumer
// gets is the backend published when the operation began, and a
// setDataplane(nil) landing mid-operation is still serviced by that
// backend. No consumer caches it in a FIELD, so the window is bounded by
// the request, and the residual — a torn-down but not yet replaced backend
// still answering — is the same #6741 lifetime gap documented above, not a
// publication escape.
//
// It reads the cell DIRECTLY rather than going through resolve() for ONE
// reason: resolve narrows to liveDataPlaneSurface and returns an ERROR for
// a backend that does not implement the mandatory management surface, so
// Unwrap would hand back nil for a backend that is published and may well
// carry the optional capability being probed for. It is NOT because a
// conversion would drop methods — a successful Go interface conversion
// preserves the dynamic concrete type, so asserting an optional interface
// on a liveDataPlaneSurface value still sees the backend's full method set
// (Codex PR #6743 r7-N3 corrected the earlier claim here). Reading the cell
// directly is still the right implementation; only the stated reason was
// wrong.
func (a liveDataPlane) Unwrap() any {
	if a.daemon == nil {
		return nil
	}
	rt := a.daemon.dataplane()
	if rt == nil {
		return nil
	}
	return rt
}

// resolve performs the single per-call cell load. Every forwarder below
// starts here; no forwarder may cache the result across calls.
func (a liveDataPlane) resolve() (liveDataPlaneSurface, error) {
	if a.daemon == nil {
		return nil, errDataplaneUnpublished
	}
	rt := a.daemon.dataplane()
	if rt == nil {
		return nil, errDataplaneUnpublished
	}
	s, ok := rt.(liveDataPlaneSurface)
	if !ok {
		return nil, errDataplaneSurfaceUnsupported
	}
	return s, nil
}

// liveDataplane returns the management-surface indirection and whether it
// should be wired at all. ok=false ONLY when the daemon can never publish
// a dataplane (nil receiver, or --no-dataplane config-only mode where the
// cell stays empty for the daemon's lifetime); the call sites then leave
// Config.DP a genuine nil interface, exactly as before r4. In every other
// mode the servers get the live indirection — including bootstrap mode,
// where the backend is constructed but not armed and the forwarders
// simply report the current unarmed truth per call instead of freezing a
// startup-time verdict.
func (d *Daemon) liveDataplane() (liveDataPlane, bool) {
	if d == nil || d.opts.NoDataplane {
		return liveDataPlane{}, false
	}
	return liveDataPlane{daemon: d}, true
}

// --- forwarders -------------------------------------------------------
//
// Most methods resolve, then forward. ClearAllSessions is serialized with
// config applies and can retire published scan debt after a successful
// authoritative clear.

func (a liveDataPlane) IsLoaded() bool {
	s, err := a.resolve()
	if err != nil {
		return false
	}
	return s.IsLoaded()
}

func (a liveDataPlane) Compile(cfg *config.Config) (*dataplane.CompileResult, error) {
	s, err := a.resolve()
	if err != nil {
		return nil, err
	}
	return s.Compile(cfg)
}

func (a liveDataPlane) ReadGlobalCounter(index uint32) (uint64, error) {
	s, err := a.resolve()
	if err != nil {
		return 0, err
	}
	return s.ReadGlobalCounter(index)
}

func (a liveDataPlane) ReadInterfaceCounters(ifindex int) (dataplane.InterfaceCounterValue, error) {
	s, err := a.resolve()
	if err != nil {
		return dataplane.InterfaceCounterValue{}, err
	}
	return s.ReadInterfaceCounters(ifindex)
}

func (a liveDataPlane) ReadZoneCounters(zoneID uint16, direction int) (dataplane.CounterValue, error) {
	s, err := a.resolve()
	if err != nil {
		return dataplane.CounterValue{}, err
	}
	return s.ReadZoneCounters(zoneID, direction)
}

func (a liveDataPlane) ReadPolicyCounters(policyID uint32) (dataplane.CounterValue, error) {
	s, err := a.resolve()
	if err != nil {
		return dataplane.CounterValue{}, err
	}
	return s.ReadPolicyCounters(policyID)
}

func (a liveDataPlane) ReadFilterConfig(filterID uint32) (dataplane.FilterConfig, error) {
	s, err := a.resolve()
	if err != nil {
		return dataplane.FilterConfig{}, err
	}
	return s.ReadFilterConfig(filterID)
}

func (a liveDataPlane) ReadFilterCounters(ruleIdx uint32) (dataplane.CounterValue, error) {
	s, err := a.resolve()
	if err != nil {
		return dataplane.CounterValue{}, err
	}
	return s.ReadFilterCounters(ruleIdx)
}

func (a liveDataPlane) ReadFloodCounters(zoneID uint16) (dataplane.FloodState, error) {
	s, err := a.resolve()
	if err != nil {
		return dataplane.FloodState{}, err
	}
	return s.ReadFloodCounters(zoneID)
}

func (a liveDataPlane) ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error) {
	s, err := a.resolve()
	if err != nil {
		return dataplane.CounterValue{}, err
	}
	return s.ReadNATRuleCounter(counterID)
}

func (a liveDataPlane) ReadNATPortCounter(id uint32) (uint64, error) {
	s, err := a.resolve()
	if err != nil {
		return 0, err
	}
	return s.ReadNATPortCounter(id)
}

func (a liveDataPlane) ClearPolicyCounters() error {
	s, err := a.resolve()
	if err != nil {
		return err
	}
	return s.ClearPolicyCounters()
}

func (a liveDataPlane) ClearFilterCounters() error {
	s, err := a.resolve()
	if err != nil {
		return err
	}
	return s.ClearFilterCounters()
}

func (a liveDataPlane) ClearNATRuleCounters() error {
	s, err := a.resolve()
	if err != nil {
		return err
	}
	return s.ClearNATRuleCounters()
}

func (a liveDataPlane) ClearAllCounters() error {
	s, err := a.resolve()
	if err != nil {
		return err
	}
	return s.ClearAllCounters()
}

func (a liveDataPlane) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	s, err := a.resolve()
	if err != nil {
		return err
	}
	return s.IterateSessions(fn)
}

func (a liveDataPlane) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	s, err := a.resolve()
	if err != nil {
		return err
	}
	return s.IterateSessionsV6(fn)
}

func (a liveDataPlane) GetSessionV4(key dataplane.SessionKey) (dataplane.SessionValue, error) {
	s, err := a.resolve()
	if err != nil {
		return dataplane.SessionValue{}, err
	}
	return s.GetSessionV4(key)
}

func (a liveDataPlane) GetSessionV6(key dataplane.SessionKeyV6) (dataplane.SessionValueV6, error) {
	s, err := a.resolve()
	if err != nil {
		return dataplane.SessionValueV6{}, err
	}
	return s.GetSessionV6(key)
}

// MirrorExclusions forwards the #7357 §2 port-mirroring readback when the
// published backend keeps one (the userspace dataplane does; the retained BPF
// shim has no snapshot builder and so has nothing to report).
//
// A capability assertion rather than a widening of the dataplane interface:
// every other backend would have to grow a stub method that returns nil, and a
// stub that returns nil is indistinguishable from "there are no exclusions",
// which is the failure this whole issue is about. An absent capability is
// reported as absent.
func (a liveDataPlane) MirrorExclusions() []dpuserspace.MirrorExclusion {
	s, err := a.resolve()
	if err != nil {
		return nil
	}
	if m, ok := s.(interface {
		MirrorExclusions() []dpuserspace.MirrorExclusion
	}); ok {
		return m.MirrorExclusions()
	}
	return nil
}

func (a liveDataPlane) SessionCount() (v4, v6 int) {
	s, err := a.resolve()
	if err != nil {
		return 0, 0
	}
	return s.SessionCount()
}

// ClearAllSessions is serialized with config applies because a successful
// authoritative clear may retire a published policy-invalidation scan debt.
// It resolves the backend only after acquiring applySem.
func (a liveDataPlane) ClearAllSessions() (v4 int, v6 int, err error) {
	d := a.daemon
	locked := false
	if d != nil && d.applySem != nil {
		if err := d.applySem.Acquire(d.applyCancelCtx(), 1); err != nil {
			return 0, 0, err
		}
		locked = true
		defer d.applySem.Release(1)
	}
	s, err := a.resolve()
	if err != nil {
		return 0, 0, err
	}
	v4, v6, err = s.ClearAllSessions()
	if err == nil && locked {
		retired, reason := d.retirePolicyInvalidationScanDebtAfterFullClearLocked()
		if retired {
			slog.Info("full session clear retired published policy invalidation scan debt",
				"v4", v4, "v6", v6)
		} else {
			slog.Debug("full session clear did not retire policy invalidation scan debt",
				"reason", reason, "v4", v4, "v6", v6)
		}
	}
	return v4, v6, err
}

// retirePolicyInvalidationScanDebtAfterFullClearLocked relies on the
// authoritative all-sessions clear to remove rows omitted by an incomplete
// scan. It retires only a published target under known authority: an unapplied
// target could still admit sessions under its predecessor before a later
// publish, recreating the very gap the scan debt protects.
// Caller holds d.applySem.
func (d *Daemon) retirePolicyInvalidationScanDebtAfterFullClearLocked() (bool, string) {
	debt := d.policyInvalidationDebt
	if debt == nil || debt.scanFailure == nil {
		return false, "no published incomplete policy scan debt"
	}
	if policyInvalidationAppliedConfig(d.dataplane()) != debt.newCfg {
		return false, "helper authority does not match scan target"
	}
	if d.store != nil && d.store.ActiveConfig() != debt.newCfg {
		return false, "active store config does not match scan target"
	}
	d.policyInvalidationDebt = nil
	if d.policyInvalidationCapture == debt.capture {
		d.policyInvalidationCapture = nil
	}
	if plan := d.policyInvalidationPlan; plan != nil && plan.newCfg == debt.newCfg {
		d.policyInvalidationPlan = nil
	}
	if d.store != nil && debt.appliedDigest != "" {
		d.store.MarkAppliedDigest(debt.appliedDigest)
	}
	return true, ""
}

func (a liveDataPlane) DeleteSession(key dataplane.SessionKey) error {
	s, err := a.resolve()
	if err != nil {
		return err
	}
	return s.DeleteSession(key)
}

func (a liveDataPlane) DeleteSessionV6(key dataplane.SessionKeyV6) error {
	s, err := a.resolve()
	if err != nil {
		return err
	}
	return s.DeleteSessionV6(key)
}

func (a liveDataPlane) DeleteDNATEntry(key dataplane.DNATKey) error {
	s, err := a.resolve()
	if err != nil {
		return err
	}
	return s.DeleteDNATEntry(key)
}

func (a liveDataPlane) DeleteDNATEntryV6(key dataplane.DNATKeyV6) error {
	s, err := a.resolve()
	if err != nil {
		return err
	}
	return s.DeleteDNATEntryV6(key)
}

// GetPersistentNAT returns the CURRENTLY published backend's persistent
// NAT table, or nil. Consumers treat nil as "not available"
// (server_diag_system_action.go's clear-persistent-nat arm), so an empty
// cell degrades to that branch rather than handing back the disowned
// backend's table.
//
// Codex PR #6743 r6-F2: every caller must bind the result to a LOCAL and
// operate on that. Before r6 the three call sites read
// `dp.GetPersistentNAT()` two or three times in a row — nil-check, then
// .Len(), then .Clear() — which under the live indirection are SEPARATE
// cell loads, not one bounded expression. A setDataplane(nil) landing
// between the check and the use returned nil to a caller that had already
// proven non-nil, and the process nil-dereferenced. The local also makes
// the escape explicit: the pointer is live for the caller's operation and
// is bounded by the same #6741 lifetime gap documented above.
func (a liveDataPlane) GetPersistentNAT() *dataplane.PersistentNATTable {
	s, err := a.resolve()
	if err != nil {
		return nil
	}
	return s.GetPersistentNAT()
}

func (a liveDataPlane) GetMapStats() []dataplane.MapStats {
	s, err := a.resolve()
	if err != nil {
		return nil
	}
	return s.GetMapStats()
}

// Compile-time assertions.
//
// The first three are the DRIFT GUARD: liveDataPlane is what the gRPC,
// REST and CLI call sites assign, so a method added to any daemon-local
// probe without a matching forwarder here fails the build at this line
// rather than silently reverting that method to a capture-once path.
//
// The last two require both in-tree backends to satisfy the union, so
// resolve()'s errDataplaneSurfaceUnsupported arm is unreachable for
// anything shipped today.
var (
	_ apiDataPlane  = liveDataPlane{}
	_ grpcDataPlane = liveDataPlane{}
	_ cliDataPlane  = liveDataPlane{}

	_ liveDataPlaneSurface = (*dataplane.Manager)(nil)
	_ liveDataPlaneSurface = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
)
