package userspace

import "sync/atomic"

type mapsSyncTelemetryCounters struct {
	rstSuppressionFailures  atomic.Uint64
	bindingsWatchdogRepairs atomic.Uint64
	bindingsWatchdogErrors  atomic.Uint64
	localAddrPruneSkipped   atomic.Uint64
}
