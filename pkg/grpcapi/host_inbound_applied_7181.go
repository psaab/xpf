package grpcapi

// HostInboundApplied mirrors daemon.HostInboundAppliedState without importing
// pkg/daemon, keeping the dependency edge one-way (the same reason
// bootstrapshow.Snapshot exists).
//
// #7181: the zone projections render DESIRED host-inbound config. This carries
// the APPLIED state — whether a kernel table is actually enforcing it — so a
// cold-boot failure can no longer be reported as a configured default-deny in
// force (codex-review-182:4394).
type HostInboundApplied struct {
	Known                bool
	Established          bool
	Generation           uint64
	LastApplyFailed      bool
	GapFenceActive       bool
	BarrierRetained      bool
	BarrierPendingDetail string
}

// AppliedStateLabel renders the tri-state verdict.
//
// The arm ORDER is load-bearing. `Established` is STICKY-TRUE — a failed render
// does not clear it, because the retained generation may still be protecting —
// so testing it first and returning "current" would report a box whose latest
// render failed as healthy. That conflation is the entire defect #7181 exists
// to remove, and re-introducing it at the rendering layer would leave the data
// correct and the operator misled.
func (h HostInboundApplied) AppliedStateLabel() string {
	switch {
	case !h.Established:
		return "not-established"
	case h.LastApplyFailed:
		return "stale"
	default:
		return "current"
	}
}
