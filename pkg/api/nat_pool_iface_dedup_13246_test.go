package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestNATPoolStatsHandlerDeduplicatesInterfaceRules13246(t *testing.T) {
	s := &Server{store: newIfaceNATStatsAPIStore(t), dp: &natIfaceSNATSessionsDP{
		Manager: dataplane.New(),
		result:  &dataplane.ApplyResult{ZoneIDs: map[string]uint16{"trust": 2, "wan": 5, "guest": 4}},
	}}
	rr := httptest.NewRecorder()
	s.natPoolStatsHandler(rr, httptest.NewRequest("GET", "/api/v1/security/nat/source/pools", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data []NATPoolStatsInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	var rows []NATPoolStatsInfo
	for _, p := range resp.Data {
		if p.Name == "trust->wan" {
			rows = append(rows, p)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("trust->wan interface rows = %d, want 1: %+v", len(rows), rows)
	}
	if rows[0].UsedPorts != 3 {
		t.Fatalf("trust->wan UsedPorts = %d, want 3", rows[0].UsedPorts)
	}
}
