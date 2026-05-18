package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

type natApplyResultAPIDP struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
	calls  int
}

func (d *natApplyResultAPIDP) IsLoaded() bool {
	return true
}

func (d *natApplyResultAPIDP) LastApplyResult() *dataplane.ApplyResult {
	d.calls++
	return d.result.Clone()
}

func (d *natApplyResultAPIDP) ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{Packets: uint64(counterID), Bytes: uint64(counterID) * 100}, nil
}

func newNATStatsAPIStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(`set security nat source rule-set trust-to-untrust from zone trust
set security nat source rule-set trust-to-untrust to zone untrust
set security nat source rule-set trust-to-untrust rule r1 match source-address 10.0.0.0/8
set security nat source rule-set trust-to-untrust rule r1 then source-nat interface
set security nat source rule-set trust-to-untrust rule r2 match source-address 172.16.0.0/12
set security nat source rule-set trust-to-untrust rule r2 then source-nat interface`); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func TestNATRuleStatsHandlerReadsApplyResultOnce(t *testing.T) {
	dp := &natApplyResultAPIDP{
		Manager: dataplane.New(),
		result: &dataplane.ApplyResult{
			NATCounterIDs: map[string]uint32{
				"trust-to-untrust/r1": 31,
				"trust-to-untrust/r2": 32,
			},
		},
	}
	s := &Server{store: newNATStatsAPIStore(t), dp: dp}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/nat/source/rules", nil)
	s.natRuleStatsHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	if dp.calls != 1 {
		t.Fatalf("LastApplyResult() calls = %d, want 1", dp.calls)
	}

	var resp struct {
		Success bool               `json:"success"`
		Data    []NATRuleStatsInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}
	if len(resp.Data) != 2 {
		t.Fatalf("len(resp.Data) = %d, want 2", len(resp.Data))
	}
	hits := make(map[string]uint64, len(resp.Data))
	for _, rule := range resp.Data {
		hits[rule.RuleName] = rule.HitPackets
	}
	if hits["r1"] != 31 || hits["r2"] != 32 {
		t.Fatalf("hit packets = %+v, want r1=31 r2=32", hits)
	}
}
