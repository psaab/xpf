// Package cluster — backend-neutral runtime surface for SessionSync.
//
// Introduced as part of #1518 (sub-#1451 step S3) to remove the legacy
// dataplane.DataPlane parameter type from NewSessionSync /
// NewDualSessionSync / SetDataPlane. The cluster session-sync hot path
// already stores narrow domain interfaces (dataplane.SessionStore /
// dataplane.Telemetry) via SetRuntimeDomains; clusterRuntime is the
// matching boundary type so the public constructor signatures no
// longer name the legacy bridge.
//
// Both *pkg/dataplane.Manager (legacy eBPF) and
// *pkg/dataplane/userspace.LegacyDataPlaneAdapter (userspace) satisfy
// clusterRuntime via their existing Sessions()/Telemetry() methods,
// which already participate in dataplane.RuntimeDataPlane. Keeping
// clusterRuntime package-private (lower-case 'r') prevents accidental
// upward dependence and
// matches the pattern used by pkg/cli/runtime.go (#1517) and
// pkg/api / pkg/fwdstatus / pkg/monitoriface earlier
// in the #1451 migration sequence.
package cluster

import "github.com/psaab/xpf/pkg/dataplane"

// clusterRuntime is the backend-neutral runtime surface required by
// SessionSync. It captures exactly the domains the HA hot path needs:
// the session store (install/delete/iterate) and telemetry counters
// used by the sweep. The interface is intentionally narrow — adding
// methods here means SessionSync gains a new runtime dependency and
// requires a fresh adversarial review.
type clusterRuntime interface {
	Sessions() dataplane.SessionStore
	Telemetry() dataplane.Telemetry
}
