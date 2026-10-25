package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16556: REST zonesHandler must expose unbound_interfaces for a member
// claimed by two zones (bound to NEITHER at runtime), mirroring gRPC
// GetZones. Control member must not be listed.

func TestZonesHandlerUnboundInterfaces16556(t *testing.T) {
	text := `
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
    ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } }
}
security {
    zones {
        security-zone trust { interfaces [ ge-0/0/0.0 ge-0/0/1.0 ]; }
        security-zone untrust { interfaces [ ge-0/0/0.0 ]; }
    }
}
`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("Parse() errors = %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
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
		t.Fatalf("unmarshal zones: %v; body: %s", err, rr.Body.String())
	}
	zones := envelope.Data
	byName := map[string]ZoneInfo{}
	for _, z := range zones {
		byName[z.Name] = z
	}
	for _, name := range []string{"trust", "untrust"} {
		z, ok := byName[name]
		if !ok {
			t.Fatalf("zone %q missing from %v", name, zones)
		}
		found := false
		for _, u := range z.UnboundInterfaces {
			if u == "ge-0/0/0.0" {
				found = true
			}
			if u == "ge-0/0/1.0" {
				t.Fatalf("%s marks control unbound: %v", name, z.UnboundInterfaces)
			}
		}
		if !found {
			t.Fatalf("%s UnboundInterfaces = %v, want ge-0/0/0.0", name, z.UnboundInterfaces)
		}
	}
}
