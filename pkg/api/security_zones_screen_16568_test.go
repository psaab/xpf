package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16568: REST zonesHandler must mirror the gRPC screen_disposition.

func TestZonesHandlerScreenDisposition16568(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{
		Screen: map[string]*config.ScreenProfile{
			"corp":  {Name: "corp", TCP: config.TCPScreen{SynFlood: &config.SynFloodConfig{AttackThreshold: 500}}},
			"audit": {Name: "audit", AlarmWithoutDrop: true},
		},
		Zones: map[string]*config.ZoneConfig{
			"trust": {Name: "trust", ScreenProfile: "corp"},
			"inert": {Name: "inert", ScreenProfile: "audit"},
			"ghost": {Name: "ghost", ScreenProfile: "missing"},
		},
	}}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	store.SetCompiledForTesting(cfg)
	s := &Server{store: store}
	rr := httptest.NewRecorder()
	s.zonesHandler(rr, httptest.NewRequest("GET", "/api/v1/security/zones", nil))
	if rr.Code != 200 {
		t.Fatalf("zonesHandler status = %d; body: %s", rr.Code, rr.Body.String())
	}
	var envelope struct {
		Data []ZoneInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	byName := map[string]ZoneInfo{}
	for _, z := range envelope.Data {
		byName[z.Name] = z
	}
	want := map[string]string{"trust": "enforcing", "inert": "inert", "ghost": "undefined"}
	for name, w := range want {
		if got := byName[name].ScreenDisposition; got != w {
			t.Errorf("%s: ScreenDisposition = %q, want %q", name, got, w)
		}
	}
}
