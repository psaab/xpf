package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #16730: fabric blockers (#15918) were dropped by the emitter's hard-coded
// 14-name list, and unknown mapper values vanished. The emitter must render
// the shared vocabulary (fabric_* = 1 when active) and fold unknown values
// into blocker="other".

func emitBlockers16730(t *testing.T, blockers []string) map[string]float64 {
	t.Helper()
	c := newCollector(nil)
	dp := &takeoverReadinessDP13301{
		descriptorCoverageDP: &descriptorCoverageDP{Manager: dataplane.New()},
		readiness:            dpuserspace.HATakeoverReadiness{Ready: false, Blockers: blockers},
	}
	ch := make(chan prometheus.Metric, 64)
	c.emitHATakeoverReadiness13301(ch, dp)
	close(ch)
	out := map[string]float64{}
	for metric := range ch {
		var pb dto.Metric
		if err := metric.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		if pb.Gauge == nil {
			continue
		}
		for _, lp := range pb.GetLabel() {
			if lp.GetName() == "blocker" {
				out[lp.GetValue()] = pb.GetGauge().GetValue()
			}
		}
	}
	return out
}

func TestMetricsHATakeoverFabricBlockersEmitted16730(t *testing.T) {
	got := emitBlockers16730(t, []string{"fabric_not_converged", "fabric_peer_unresolved"})
	if got["fabric_not_converged"] != 1 {
		t.Fatalf("fabric_not_converged=%v, want 1 (emitted=%v)", got["fabric_not_converged"], got)
	}
	if got["fabric_peer_unresolved"] != 1 {
		t.Fatalf("fabric_peer_unresolved=%v, want 1 (emitted=%v)", got["fabric_peer_unresolved"], got)
	}
	if got["forwarding_unsupported"] != 0 {
		t.Fatalf("forwarding_unsupported=%v, want 0 for fabric-only blockers", got["forwarding_unsupported"])
	}
	// Every vocabulary name must have a series (0 or 1), including other.
	for _, name := range dpuserspace.HATakeoverBlockers {
		if _, ok := got[name]; !ok {
			t.Fatalf("missing blocker series %q in %v", name, got)
		}
	}
}

func TestMetricsHATakeoverSnapshotUnpublishedEmitted16730(t *testing.T) {
	got := emitBlockers16730(t, []string{dpuserspace.HATakeoverBlockerSnapshotUnpublished})
	if got["snapshot_unpublished"] != 1 {
		t.Fatalf("snapshot_unpublished=%v, want 1 (emitted=%v)", got["snapshot_unpublished"], got)
	}
	if got["forwarding_unsupported"] != 0 {
		t.Fatalf("forwarding_unsupported=%v, want 0", got["forwarding_unsupported"])
	}
}

func TestMetricsHATakeoverUnknownBlockerFoldsToOther16730(t *testing.T) {
	got := emitBlockers16730(t, []string{"totally_new_blocker_xyz"})
	if got["other"] != 1 {
		t.Fatalf("other=%v, want 1 for unknown blocker (emitted=%v)", got["other"], got)
	}
	// Known blockers must remain 0 when only an unknown is active.
	if got["helper_down"] != 0 || got["fabric_not_converged"] != 0 {
		t.Fatalf("known blockers spuriously active: %v", got)
	}
}

func TestMetricsHATakeoverReadyNoBlockers16730(t *testing.T) {
	// Control: no blockers -> all series present at 0, other included.
	got := emitBlockers16730(t, nil)
	for _, name := range dpuserspace.HATakeoverBlockers {
		if v, ok := got[name]; !ok || v != 0 {
			t.Fatalf("blocker %q = (%v,%v), want (0,true) with no blockers: %v", name, v, ok, got)
		}
	}
}
