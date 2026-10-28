package daemon

import (
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #17082 — bind the policy-scheduler latch interfaces to the types the daemon
// ACTUALLY PUBLISHES, at compile time.
//
// The scheduler resolved its dataplane surface by runtime type assertion
// through an optional-interface ladder that kept the non-latch
// SetPolicySchedulerActiveState / UpdatePolicyScheduleState arms. Both
// published types implement the latch methods; only the retired eBPF
// *dataplane.Manager satisfied the non-latch arm alone, and falling back to
// it silently dropped failClosed (#10906). The non-latch interfaces and
// their fallback arms are deleted in daemon_scheduler.go; this file supplies
// the compile-time edge the runtime assertions lack, in the same spirit as
// bulk_snapshot_published_type_9482.go: removing
// UpdatePolicyScheduleStateWithLatch (or the latch setter, or the
// heartbeat) from either published type now fails `go build ./pkg/daemon/`
// instead of converting a missing method into a silent no-op / fail-open.
//
// The population is every concrete type publishable as the userspace
// dataplane.RuntimeDataPlane: *dpuserspace.LegacyDataPlaneAdapter (what
// dpuserspace.Boot() returns) and *dpuserspace.Manager. The behavioural
// half — that the real published value actually reaches the latch updater
// with its failClosed argument intact — is
// policy_scheduler_published_type_17082_test.go.
var (
	_ policyScheduleFailClosedUpdater       = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
	_ policyScheduleFailClosedUpdater       = (*dpuserspace.Manager)(nil)
	_ policySchedulerActiveStateLatchSetter = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
	_ policySchedulerActiveStateLatchSetter = (*dpuserspace.Manager)(nil)
	_ policyScheduleHeartbeatUpdater        = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
	_ policyScheduleHeartbeatUpdater        = (*dpuserspace.Manager)(nil)
)
