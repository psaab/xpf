package grpcapi

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #6743 r2 B1: the gRPC server's optional-capability probe must resolve
// through dataplane.Unwrap, and nothing bound that.
//
// WHAT WAS UNBOUND, measured at 710a87569: severing the unwrap in
// (*Server).dpProbe — `return mgmtview.Probe(s.dp)` -> `return s.dp`
// (runtime.go) — left BUILD_RC=0 and FULL_RC=0 across the COMPLETE set of
// in-tree importers of this package (`./pkg/grpcapi/ ./pkg/cli/
// ./pkg/daemon/ ./pkg/api/ ./pkg/upgrade/ ./cmd/cli/`, enumerated with
// `go list`). No assertion fired anywhere.
//
// The r8 sweep that introduced this guard class bound pkg/api, pkg/cli,
// pkg/dataplane and pkg/dataplane/userspace — and missed pkg/grpcapi. The
// SAME one-line mutation in the sibling packages IS killed
// (pkg/cli/runtime.go by TestCLIProbe_StatusSurvivesLiveIndirection +
// TestCLIProbe_ControlProviderSurvivesLiveIndirection; pkg/api/api.go by
// TestRESTDpProbeResolvesThroughTheIndirection_6743 +
// TestRESTProbesOnADisownedCellAreEmpty_6743), which is exactly how the
// gap read as coverage: three identically-named `dpProbe` methods in three
// packages, two of them guarded.
//
// The pkg/daemon escape canary cannot catch it either: its own scope note
// lists "a helper that returns `s.dp` as `any`, and an assertion on ITS
// result" as a documented gap, and dpProbe() is that helper.
//
// CONSEQUENCE with the unwrap gone. s.dpProbe() returns the daemon's live
// indirection, whose method set is exactly the MANDATORY grpcRuntime
// surface, so EVERY optional probe answers "absent" for a perfectly
// HEALTHY backend: the session cursor (server_sessions.go, dropping every
// paged query into the explicitly O(N^2) fallback), the userspace
// status/control providers (server.go — `request chassis cluster
// data-plane userspace inject/queue/binding`), the WireGuard renders
// (server_show_security_text.go), the deterministic-NAT view
// (server_nat_deterministic.go), the policy-scheduler state
// (server_show_policies_text.go) and `show chassis forwarding`
// (server_show_forwarding.go, which then picks the NON-userspace
// fwdstatus.Build wrapper).
//
// WHY THE FIXTURE HAS THIS SHAPE. The indirection embeds the mandatory
// interface (satisfying it without implementing any optional method) and
// the backend carries the optional capabilities. If the indirection itself
// carried Status(), probing it directly would succeed and the mutation
// would be invisible — which is how this stayed unbound.

// grpcIndirection6743 is the live adapter: mandatory surface only, plus
// dataplane.LiveUnwrapper. The embedded interface is nil; no method on it
// is called by anything under test.
type grpcIndirection6743 struct {
	grpcRuntime
	backend any
}

func (g *grpcIndirection6743) Unwrap() any { return g.backend }

// grpcOptionalBackend6743 is the published backend. It carries TWO
// optional families on purpose — Status() (the userspace telemetry
// renders) and IterateSessionsFrom/IterateSessionsV6From (the session
// cursor) — because the severed probe erases both, and a guard that
// bound only one would leave the other's consequence unstated.
type grpcOptionalBackend6743 struct{ pid int }

func (b *grpcOptionalBackend6743) Status() (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{PID: b.pid}, nil
}

func (b *grpcOptionalBackend6743) IterateSessionsFrom(
	_ *dataplane.SessionKey,
	_ func(dataplane.SessionKey, dataplane.SessionValue) bool,
) error {
	return nil
}

func (b *grpcOptionalBackend6743) IterateSessionsV6From(
	_ *dataplane.SessionKeyV6,
	_ func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool,
) error {
	return nil
}

// TestGRPCDpProbeResolvesThroughTheIndirection_6743 is the fail-on-revert
// guard for the Unwrap in (*Server).dpProbe.
//
// RED-on-revert: `return mgmtview.Probe(s.dp)` -> `return s.dp` in
// pkg/grpcapi/runtime.go.
func TestGRPCDpProbeResolvesThroughTheIndirection_6743(t *testing.T) {
	backend := &grpcOptionalBackend6743{pid: 6743}
	live := &grpcIndirection6743{backend: backend}

	// PRECONDITION: the adapter must not itself expose either capability,
	// or the probe could "succeed" without unwrapping and this test would
	// pass under the revert.
	if _, ok := any(live).(userspaceStatusProvider); ok {
		t.Fatal("fixture broken: the indirection exposes Status(), so the Unwrap is unobservable")
	}
	if _, ok := any(live).(sessionCursorIterator); ok {
		t.Fatal("fixture broken: the indirection exposes the session cursor, so the Unwrap is unobservable")
	}

	s := &Server{dp: live}
	got := s.dpProbe()
	if got != any(backend) {
		t.Fatalf("dpProbe() = %T, want the PUBLISHED BACKEND %T. Returning the live "+
			"indirection erases every optional capability on a HEALTHY deployment "+
			"(#2114/#6743-F1).", got, backend)
	}
}

// TestGRPCOptionalCapabilitiesSurviveTheIndirection_6743 asserts the
// CONSEQUENCE rather than the identity: the two optional families the
// gRPC handlers reach by asserting on dpProbe()'s result must still be
// reachable when the daemon hands the server its live indirection.
//
// It is a separate body from the identity guard above so a future
// dpProbe that returns some third value which is neither the adapter nor
// the backend still has its user-visible effect asserted.
//
// RED-on-revert: the same one-line severance in runtime.go.
func TestGRPCOptionalCapabilitiesSurviveTheIndirection_6743(t *testing.T) {
	backend := &grpcOptionalBackend6743{pid: 6743}
	s := &Server{dp: &grpcIndirection6743{backend: backend}}

	provider, ok := s.dpProbe().(userspaceStatusProvider)
	if !ok {
		t.Fatal("Status() probe missed through the live indirection: every userspace " +
			"telemetry render (WireGuard, buffers, the inject/queue/binding controls) " +
			"answers \"requires the userspace dataplane\" for a HEALTHY helper")
	}
	st, err := provider.Status()
	if err != nil {
		t.Fatalf("Status(): %v", err)
	}
	if st.PID != 6743 {
		t.Fatalf("Status() came from PID %d, want 6743 — the probe resolved something "+
			"other than the published backend", st.PID)
	}

	if _, ok := s.dpProbe().(sessionCursorIterator); !ok {
		t.Fatal("session cursor missed through the live indirection: every paged " +
			"GetSessions query falls into the explicitly O(N^2) re-scan fallback")
	}
}

// TestGRPCProbesOnADisownedCellAreEmpty_6743 is the over-reach control,
// and a SEPARATE test on purpose: sharing a body with either binder would
// put it behind that body's t.Fatalf, where it could never be observed
// running under the mutation it exists to bound.
//
// Unwrap must not become "return the adapter when the cell is empty".
// Once the daemon has disowned the backend the probe must report absence
// so callers take their capability-unavailable branch rather than
// reaching a retired backend.
func TestGRPCProbesOnADisownedCellAreEmpty_6743(t *testing.T) {
	live := &grpcIndirection6743{backend: nil} // published nothing

	s := &Server{dp: live}
	if got := s.dpProbe(); got != nil {
		t.Errorf("dpProbe() on a disowned cell = %T, want nil — a probe made after "+
			"setDataplane(nil) must fail its assertion, not reach a retired backend", got)
	}
	if _, ok := s.dpProbe().(userspaceStatusProvider); ok {
		t.Error("the Status() probe SUCCEEDED on a disowned cell: a telemetry render " +
			"would dispatch into a backend the daemon no longer publishes")
	}
	// dataplane.Unwrap is what makes both of the above true; assert the
	// primitive too, so a failure here separates "the probe is wrong" from
	// "Unwrap is wrong".
	if got := dataplane.Unwrap(live); got != nil {
		t.Errorf("dataplane.Unwrap(disowned) = %T, want nil", got)
	}
}
