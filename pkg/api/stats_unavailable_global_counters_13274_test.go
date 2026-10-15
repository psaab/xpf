package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type userspaceGlobalStatsDP13274 struct {
	*dpuserspace.LegacyDataPlaneAdapter
}

func (d *userspaceGlobalStatsDP13274) IsLoaded() bool { return true }

func (d *userspaceGlobalStatsDP13274) ReadGlobalCounter(idx uint32) (uint64, error) {
	switch idx {
	case dataplane.GlobalCtrFlowCacheFlush, dataplane.GlobalCtrFlowCacheInvalidate,
		dataplane.GlobalCtrTCEgressPackets, dataplane.GlobalCtrFabricRedirect:
		return d.LegacyDataPlaneAdapter.ReadGlobalCounter(idx)
	default:
		return uint64(idx) + 1, nil
	}
}

func TestGlobalStatsHandlerReturnsAvailableCountersWithUnsupportedUserspaceStats13274(t *testing.T) {
	adapter := dpuserspace.NewLegacyDataPlaneAdapter(dpuserspace.New())
	s := &Server{dp: &userspaceGlobalStatsDP13274{LegacyDataPlaneAdapter: adapter}}
	rr := httptest.NewRecorder()
	s.globalStatsHandler(rr, httptest.NewRequest(http.MethodGet, "/api/v1/statistics/global", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("global stats status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool        `json:"success"`
		Data    GlobalStats `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rr.Body.String())
	}
	if !resp.Success {
		t.Fatalf("response success=false body=%s", rr.Body.String())
	}
	if want := uint64(dataplane.GlobalCtrFlowCacheHit) + 1; resp.Data.FlowCacheHits != want {
		t.Errorf("FlowCacheHits = %d, want %d", resp.Data.FlowCacheHits, want)
	}
	wantUnavailable := []string{"tc_egress_packets", "fabric_redirects", "flow_cache_flushes", "flow_cache_invalidations"}
	if len(resp.Data.UnavailableCounters) != len(wantUnavailable) {
		t.Fatalf("unavailable counters = %v, want %v", resp.Data.UnavailableCounters, wantUnavailable)
	}
	for i, want := range wantUnavailable {
		if got := resp.Data.UnavailableCounters[i]; got != want {
			t.Errorf("unavailable counter[%d] = %q, want %q", i, got, want)
		}
	}
}
