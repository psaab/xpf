package daemon

import "time"

// HostInboundAppliedState is the operator-facing APPLIED state of the
// host-inbound nftables surface (`inet xpf_hostinbound`), as opposed to the
// DESIRED state every existing projection renders from config.
//
// #7181: before this, the observed-state machine #5644 built never left
// pkg/daemon — `hostInboundEnforced` had no exported accessor and no consumer
// outside daemon_nft.go — so REST, the CLI and gRPC could report a zone's
// host-inbound posture as configured while no table existed in the kernel. The
// review's words (codex-review-182:4394) were that "on a cold-boot #5644
// failure, diagnostics can report default-deny while no table exists".
//
// WHY THIS IS NOT A BOOL. `hostInboundEnforced` is deliberately STICKY-TRUE: it
// records that a protecting table loaded at SOME generation, and a later failed
// render does NOT clear it, because the retained (atomic-untouched) generation
// may still be protecting. Only a successful teardown clears it. So the bool
// alone cannot separate the two states an operator most needs separated:
//
//	established and CURRENT   — the most recent real render succeeded
//	established but STALE     — a later render FAILED; the retained generation
//	                            covers only what it covered when it loaded, and
//	                            an address that appeared since may be covered
//	                            only by an additive gap fence, or not at all
//
// The second row is not hypothetical: daemon_nft.go's day-2 branch exists to
// handle exactly it, computing the uncovered destinations and installing the
// #5789 gap fence for the difference. Rendering it as the first row is the
// confidently-wrong answer #5719 refused to ship on the counter side.
type HostInboundAppliedState struct {
	// Established mirrors hostInboundEnforced: a real load or scoped fallback
	// (a local-address or catalog-multicast ingress drop) has established some
	// host-inbound protection at a generation. FALSE is the cold-boot /
	// torn-down case — nothing has ever protected, so a projection must NOT
	// report configured default-deny as being in force.
	Established bool

	// Generation counts SUCCESSFUL real installs. Zero means none has ever
	// completed, and it moves only on the success path, so it is the thing to
	// compare across two reads to answer "did enforcement re-render since?".
	Generation uint64

	// LastApplyFailed is true when the most recent apply attempt failed. It is
	// what makes Established meaningful: Established && !LastApplyFailed is
	// "current", Established && LastApplyFailed is "stale, retained generation
	// still standing". It is NOT an error counter — it describes the latest
	// attempt only.
	LastApplyFailed bool

	// LastFailureAt is when that failure happened; zero when the last attempt
	// succeeded. Rendered so an operator can tell a failure from minutes ago
	// from one that has been standing since boot.
	LastFailureAt time.Time

	// GapFenceActive reports that the #5789 ADDITIVE gap fence
	// (inet xpf_hostinbound_gap) is installed — a later-appeared address is
	// being denied by a separate table because the retained real generation has
	// no rule for it. This is part of the applied truth: a box in this state is
	// enforcing through two tables, and an operator diagnosing reachability
	// needs to know which one is answering.
	GapFenceActive bool
}

// Current reports whether the applied surface is both established and not
// standing on a failed render. It is the single predicate a caller wanting a
// yes/no should use — NOT Established, which is sticky and answers a different
// question ("has enforcement ever been established").
func (s HostInboundAppliedState) Current() bool {
	return s.Established && !s.LastApplyFailed
}

// HostInboundApplied returns the applied-state latch for the host-inbound
// nftables surface.
//
// Safe on a nil receiver (returns the zero value, i.e. "nothing established"),
// because callers reach it from projection paths that run before or without a
// daemon in tests. The zero value is the SAFE default: it claims nothing.
func (d *Daemon) HostInboundApplied() HostInboundAppliedState {
	if d == nil {
		return HostInboundAppliedState{}
	}
	st := HostInboundAppliedState{
		Established:     d.hostInboundEnforced.Load(),
		Generation:      d.hostInboundApplyGen.Load(),
		LastApplyFailed: d.hostInboundLastApplyFailed.Load(),
		GapFenceActive:  d.hostInboundGapFenceActive.Load(),
	}
	if at := d.hostInboundLastFailureUnixNano.Load(); at != 0 {
		st.LastFailureAt = time.Unix(0, at)
	}
	return st
}

// noteHostInboundApplyFailed records that an apply attempt failed. The retained
// generation is unchanged and may still be protecting, which is why this sets a
// STALENESS flag rather than clearing Established.
func (d *Daemon) noteHostInboundApplyFailed(now time.Time) {
	d.hostInboundLastApplyFailed.Store(true)
	d.hostInboundLastFailureUnixNano.Store(now.UnixNano())
}

// noteHostInboundApplySucceeded records a successful real install: the
// generation advances, the staleness flag and its timestamp clear, and any gap
// fence is no longer active because the real table now covers the desired set.
func (d *Daemon) noteHostInboundApplySucceeded() {
	d.hostInboundApplyGen.Add(1)
	d.hostInboundLastApplyFailed.Store(false)
	d.hostInboundLastFailureUnixNano.Store(0)
	d.hostInboundGapFenceActive.Store(false)
}
