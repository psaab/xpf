// #3426: REST /statistics/global must surface the same global counters the
// gRPC reader exposes. Before this fix REST `GlobalStats` had no
// nat64_translations and no host_inbound_allowed field, and stats.go never
// read GlobalCtrNAT64Xlate / GlobalCtrHostInbound, so REST could not represent
// either counter even though gRPC GetGlobalStats and Prometheus do.
//
// FAIL-ON-REVERT: dropping either struct field or its readCounter() call in
// globalStatsHandler returns the field as a zero (or drops it entirely), so the
// value-equality assertions below go RED.
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// idxValueAPIDP is a loaded apiRuntimeDataPlane whose global-counter reads
// return a distinct, index-derived value so a test can prove a specific
// counter index was actually read into a specific response field.
type idxValueAPIDP struct {
	*dataplane.Manager
}

func (d *idxValueAPIDP) IsLoaded() bool { return true }

func (d *idxValueAPIDP) ReadGlobalCounter(idx uint32) (uint64, error) {
	// Unique per index, non-zero, and far from any field's zero value so a
	// dropped read (which would leave the field at 0) is unambiguous.
	return uint64(idx)*1000 + 7, nil
}

func TestGlobalStatsHandlerSurfacesNAT64AndHostInbound(t *testing.T) {
	s := &Server{dp: &idxValueAPIDP{Manager: dataplane.New()}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/statistics/global", nil)
	s.globalStatsHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("globalStatsHandler status = %d, want %d. body=%s",
			rr.Code, http.StatusOK, rr.Body.String())
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

	wantNAT64 := uint64(dataplane.GlobalCtrNAT64Xlate)*1000 + 7
	if resp.Data.NAT64Translations != wantNAT64 {
		t.Errorf("NAT64Translations = %d, want %d (must read GlobalCtrNAT64Xlate)",
			resp.Data.NAT64Translations, wantNAT64)
	}

	wantHostInbound := uint64(dataplane.GlobalCtrHostInbound)*1000 + 7
	if resp.Data.HostInboundAllowed != wantHostInbound {
		t.Errorf("HostInboundAllowed = %d, want %d (must read GlobalCtrHostInbound)",
			resp.Data.HostInboundAllowed, wantHostInbound)
	}

	wantUnknownVLAN := uint64(dataplane.GlobalCtrUnknownVLANDrops)*1000 + 7
	if resp.Data.UnknownVLANDrops != wantUnknownVLAN {
		t.Errorf("UnknownVLANDrops = %d, want %d", resp.Data.UnknownVLANDrops, wantUnknownVLAN)
	}
	wantDstMAC := uint64(dataplane.GlobalCtrDstMACDrops)*1000 + 7
	if resp.Data.DstMACDrops != wantDstMAC {
		t.Errorf("DstMACDrops = %d, want %d", resp.Data.DstMACDrops, wantDstMAC)
	}

	// Sanity: the pre-existing deny counter still reads its own (distinct)
	// index, guarding against a copy-paste that points both at the same slot.
	wantDeny := uint64(dataplane.GlobalCtrHostInboundDeny)*1000 + 7
	if resp.Data.HostInboundDeny != wantDeny {
		t.Errorf("HostInboundDeny = %d, want %d", resp.Data.HostInboundDeny, wantDeny)
	}
}
