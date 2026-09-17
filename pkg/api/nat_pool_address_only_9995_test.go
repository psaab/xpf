package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type natAddressOnlyAPIDP9995 struct {
	*dataplane.Manager
	status dpuserspace.ProcessStatus
	result *dataplane.ApplyResult
}

func (d *natAddressOnlyAPIDP9995) IsLoaded() bool { return true }
func (d *natAddressOnlyAPIDP9995) Status() (dpuserspace.ProcessStatus, error) {
	return d.status, nil
}
func (d *natAddressOnlyAPIDP9995) LastApplyResult() *dataplane.ApplyResult {
	return d.result.Clone()
}

// TestNATPoolStatsAddressOnlyIsNotApplicable9995 is a FAIL-ON-REVERT guard
// for the REST structured surface. Port no-translation preserves the source
// port, so the helper's UsedPorts=0 is not a port-availability measurement.
func TestNATPoolStatsAddressOnlyIsNotApplicable9995(t *testing.T) {
	store := newNATPoolStatsAPIStore(t)
	cfg := store.ActiveConfig()
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool == nil {
		t.Fatal("fixture: source pool p1 missing")
	}
	pool.PortNoTranslation = true

	dp := &natAddressOnlyAPIDP9995{
		Manager: dataplane.New(),
		status: dpuserspace.ProcessStatus{SourceNATPools: []dpuserspace.SourceNATPoolStatus{
			{PoolName: "p1", AddressCount: 1, PortLow: 1024, PortHigh: 2023, UsedPorts: 0},
		}},
		result: &dataplane.ApplyResult{},
	}
	s := &Server{store: store, dp: dp}
	rr := httptest.NewRecorder()
	s.natPoolStatsHandler(rr, httptest.NewRequest("GET", "/api/v1/security/nat/source/pools", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool               `json:"success"`
		Data    []NATPoolStatsInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("unexpected response data: %+v", resp.Data)
	}
	got := resp.Data[0]
	if got.Utilization != "NOT APPLICABLE" {
		t.Fatalf("address-only REST utilization = %q, want NOT APPLICABLE", got.Utilization)
	}
	if got.TotalPorts != 0 || got.UsedPorts != 0 || got.AvailablePorts != 0 {
		t.Fatalf("address-only REST port figures = total %d used %d available %d, want all zero/N/A",
			got.TotalPorts, got.UsedPorts, got.AvailablePorts)
	}
	if got.UsedPortsKnown {
		t.Fatal("address-only REST response marked the non-applicable port sample as known")
	}

	// Control: the same live status remains measurable for a normal PAT pool.
	pool.PortNoTranslation = false
	dp.status.SourceNATPools[0].UsedPorts = 100
	rr = httptest.NewRecorder()
	s.natPoolStatsHandler(rr, httptest.NewRequest("GET", "/api/v1/security/nat/source/pools", nil))
	var control struct {
		Data []NATPoolStatsInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &control); err != nil {
		t.Fatalf("unmarshal control response: %v", err)
	}
	if len(control.Data) != 1 || control.Data[0].Utilization == "NOT APPLICABLE" {
		t.Fatalf("normal PAT control lost numeric utilization: %+v", control.Data)
	}
}
