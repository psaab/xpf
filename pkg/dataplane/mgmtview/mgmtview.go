// Package mgmtview holds the shared optional-capability helpers for
// the management surfaces (pkg/api, pkg/cli, pkg/grpcapi).
//
// It deliberately does NOT define a combined "full" dataplane
// interface. The three mandatory surfaces stay separate by design —
// grpcRuntime (pkg/grpcapi), cliRuntime (pkg/cli) and
// apiRuntimeDataPlane (pkg/api) list different mandatory methods
// (CLI-only Compile/ReadNATPortCounter, API-only
// SessionCountContext/ReadNATPortCounter, and so on) — and surfaces
// compose their own mandatory sets. Only the byte-identical optional
// helpers move here: Probe, Unwrap, MapStats, SessionCount and the
// SessionCountContext shape.
//
// Optional caps are resolved per-answer from the current published
// backend — never cached across backend replacement. Probe performs
// exactly one dataplane.Unwrap per call; helpers taking an
// already-resolved backend (MapStats, SessionCount,
// SessionCountContext) perform no further Unwrap, so a render that
// binds Probe's result to a local describes exactly one backend
// publication (#2114/#6743).
package mgmtview

import (
	"context"

	"github.com/psaab/xpf/pkg/dataplane"
)

// Probe returns the value that OPTIONAL-capability assertions must
// be made against.
//
// #2114/#6743-F1: the daemon hands each surface a live indirection
// (pkg/daemon's liveDataPlane) whose method set is exactly that
// surface's MANDATORY runtime surface. Asserting an optional
// capability directly on that value — the session cursor, Status(),
// AppliedNATView, the userspace controls, the policy-scheduler
// state — fails for a perfectly HEALTHY backend that implements it,
// silently degrading session paging to the O(N^2) fallback and
// blanking whole answer families. dataplane.Unwrap resolves to the
// backend published AT THIS INSTANT; it returns nil once the daemon
// has disowned the backend, so the probe still fails closed after a
// setDataplane(nil). For a plain backend — every test, every
// non-daemon embedder — it is the identity. A nil provider probes
// to nil.
func Probe(provider any) any {
	if provider == nil {
		return nil
	}
	return dataplane.Unwrap(provider)
}

// Unwrap is an alias for Probe. Both names are kept because call
// sites read differently: Probe for a surface's stored provider,
// Unwrap for an arbitrary provider value. They are identical by
// construction — there is exactly one resolution implementation.
func Unwrap(provider any) any {
	return Probe(provider)
}

// mapStatsProvider is the optional GetMapStats capability shape.
type mapStatsProvider interface {
	GetMapStats() []dataplane.MapStats
}

// MapStats reads map statistics off an ALREADY-RESOLVED backend
// (#6743 r7-F3). It performs no Unwrap of its own: the caller takes
// exactly one Probe/Unwrap so map statistics and any sibling reads
// describe the same backend publication. A backend without the
// capability (including a nil backend) yields nil.
func MapStats(backend any) []dataplane.MapStats {
	m, ok := backend.(mapStatsProvider)
	if !ok {
		return nil
	}
	return m.GetMapStats()
}

// sessionCountProvider is the optional SessionCount capability shape.
type sessionCountProvider interface {
	SessionCount() (int, int)
}

// SessionCount reads the forward-only session count off an
// ALREADY-RESOLVED backend (#6743 r7-F3), performing no Unwrap of
// its own. A backend without the capability (including a nil
// backend) yields (0, 0).
func SessionCount(backend any) (v4, v6 int) {
	c, ok := backend.(sessionCountProvider)
	if !ok {
		return 0, 0
	}
	return c.SessionCount()
}

// sessionCountContextProvider is the SessionCountContext capability
// shape: a cancellable forward-only session count that discards
// partial totals on cancellation.
type sessionCountContextProvider interface {
	SessionCountContext(context.Context) (int, int, error)
}

// SessionCountContext reports whether backend implements the
// SessionCountContext shape and, if so, its result. ok is false
// when the backend (including a nil backend) lacks the capability,
// so callers that fall back to a session walk can distinguish
// "capability absent" from a genuine count error. It performs no
// Unwrap of its own; the backend must already be resolved.
func SessionCountContext(ctx context.Context, backend any) (v4, v6 int, err error, ok bool) {
	counter, ok := backend.(sessionCountContextProvider)
	if !ok {
		return 0, 0, nil, false
	}
	v4, v6, err = counter.SessionCountContext(ctx)
	return v4, v6, err, true
}
