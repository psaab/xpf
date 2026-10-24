package api

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #6743 r8: the REST server's two optional-capability probes must resolve
// through dataplane.Unwrap, and nothing bound that.
//
// WHAT WAS UNBOUND, measured at b9be179a6 with `go vet` rc 0 before each cell:
//
//   - `dpProbe()` (api.go): `return mgmtview.Probe(s.dp)` -> `return s.dp`
//     left pkg/api AND pkg/daemon green.
//   - `fetchUserspaceStatus` (metrics_userspace.go):
//     `mgmtview.Probe(dp).(interface{ Status() ... })` -> `any(dp).(...)`
//     left both green.
//
// There IS a canary at pkg/daemon/daemon_dp_probe_canary_test.go, but it binds
// `(*Server).dpProbe()` in **pkg/daemon**. Same method name, different symbol,
// different package — the name collision reads as coverage and is not.
//
// WHY THE FIXTURE HAS THIS SHAPE. The daemon publishes a live indirection whose
// method set is exactly apiRuntimeDataPlane (#2114) — the MANDATORY management
// surface and nothing else. Optional capabilities live on the backend behind
// it. So the indirection below embeds the interface (satisfying it without
// implementing any optional method) and the backend carries Status(). If the
// indirection itself carried Status(), probing it directly would succeed and
// the mutation would be invisible — which is exactly how this stayed unbound.

// apiIndirection6743 is the live adapter: mandatory surface only, plus
// dataplane.LiveUnwrapper. The embedded interface is nil; no method on it is
// called by either probe under test.
type apiIndirection6743 struct {
	apiRuntimeDataPlane
	backend any
}

func (a *apiIndirection6743) Unwrap() any { return a.backend }

// apiStatusBackend6743 is the published backend: it carries the OPTIONAL
// Status() capability that the userspace metric families depend on.
type apiStatusBackend6743 struct{ pid int }

func (b *apiStatusBackend6743) Status() (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{PID: b.pid}, nil
}

// TestRESTDpProbeResolvesThroughTheIndirection_6743 is the fail-on-revert guard
// for the Unwrap in (*Server).dpProbe.
//
// RED-on-revert: `return mgmtview.Probe(s.dp)` -> `return s.dp` in
// pkg/api/api.go.
func TestRESTDpProbeResolvesThroughTheIndirection_6743(t *testing.T) {
	backend := &apiStatusBackend6743{pid: 6743}
	live := &apiIndirection6743{backend: backend}

	// PRECONDITION: the adapter must not itself expose the capability, or the
	// probe could "succeed" without unwrapping and this test would pass under
	// the revert.
	if _, ok := any(live).(interface {
		Status() (dpuserspace.ProcessStatus, error)
	}); ok {
		t.Fatal("fixture broken: the indirection exposes Status(), so the Unwrap is unobservable")
	}

	s := &Server{dp: live}
	got := s.dpProbe()
	if got != any(backend) {
		t.Fatalf("dpProbe() = %T, want the PUBLISHED BACKEND %T. Returning the live "+
			"indirection erases every optional capability on a HEALTHY deployment — the "+
			"NAT-pool and userspace Prometheus families blank out and the session cursor "+
			"falls back to the explicitly O(N^2) path (#2114/#6743-F1).", got, backend)
	}
}

// TestFetchUserspaceStatusResolvesThroughTheIndirection_6743 is the same guard
// for the direct unwrap in the metrics path, which is a SEPARATE production
// site: it does its own assertion rather than going through dpProbe().
//
// RED-on-revert: `mgmtview.Probe(dp).(interface{ Status() ... })` ->
// `any(dp).(interface{ Status() ... })` in pkg/api/metrics_userspace.go.
func TestFetchUserspaceStatusResolvesThroughTheIndirection_6743(t *testing.T) {
	backend := &apiStatusBackend6743{pid: 6743}
	live := &apiIndirection6743{backend: backend}

	got := fetchUserspaceStatus(live)
	if got == nil {
		t.Fatal("fetchUserspaceStatus(live indirection) = nil: the metrics path asserted " +
			"Status() on the ADAPTER, which declares only apiRuntimeDataPlane, so every " +
			"userspace metric family is suppressed on a healthy helper (#2114/#6743-F1)")
	}
	if got.PID != 6743 {
		t.Fatalf("status came from PID %d, want 6743 — the probe resolved something other "+
			"than the published backend", got.PID)
	}
}

// TestRESTProbesOnADisownedCellAreEmpty_6743 is the over-reach control for both
// guards above, and a SEPARATE test on purpose: sharing a body with either
// binder would put it behind that body's t.Fatalf, where it could never be
// observed running under the mutation it exists to bound.
//
// Unwrap must not become "return the adapter when the cell is empty". Once the
// daemon has disowned the backend the probes must report absence so callers
// take their capability-unavailable branch rather than reaching a retired
// backend.
//
// WHAT IT DOES AND DOES NOT STAY GREEN UNDER, measured rather than asserted —
// the two reverts are not symmetric and an earlier revision of this comment
// claimed they were:
//
//   - metrics revert (`any(dp).(...)`): this test stays GREEN. That revert
//     only changes which object is asserted against; a nil backend still
//     yields no Status(), so absence is still reported.
//   - dpProbe revert (`return s.dp`): this test also goes RED, correctly. That
//     revert removes the nil resolution as well as the unwrap, so a disowned
//     cell hands the caller a live-looking adapter. The extra RED is the
//     control reporting a SECOND consequence of the same edit, not a loss of
//     discrimination — the binder above still fails on its own assertion.
func TestRESTProbesOnADisownedCellAreEmpty_6743(t *testing.T) {
	live := &apiIndirection6743{backend: nil} // published nothing

	s := &Server{dp: live}
	if got := s.dpProbe(); got != nil {
		t.Errorf("dpProbe() on a disowned cell = %T, want nil — a probe made after "+
			"setDataplane(nil) must fail its assertion, not reach a retired backend", got)
	}
	if got := fetchUserspaceStatus(live); got != nil {
		t.Errorf("fetchUserspaceStatus on a disowned cell = %+v, want nil", got)
	}
	// dataplane.Unwrap is what makes both of the above true; assert the
	// primitive too, so a failure here separates "the probe is wrong" from
	// "Unwrap is wrong".
	if got := dataplane.Unwrap(live); got != nil {
		t.Errorf("dataplane.Unwrap(disowned) = %T, want nil", got)
	}
}
