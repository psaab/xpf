package api

import (
	"encoding/json"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestWriteInterfacesDetailDuplicateMembership18446(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skipf("detail renderer fixture requires loopback: %v", err)
	}

	duplicate := renderInterfacesDetail18446(t, `
interfaces {
    lo { unit 0 { family inet { address 127.0.0.1/8; } } }
}
security {
    zones {
        security-zone trust { interfaces [ lo.0 ]; }
        security-zone untrust { interfaces [ lo.0 ]; }
    }
}
`)
	wantUnbound := "  Zone: (none) " + config.ZoneInterfaceQuarantineUnboundQualifierFor([]string{"trust", "untrust"})
	if !strings.Contains(duplicate, wantUnbound) {
		t.Fatalf("duplicate membership detail missing quarantined/unbound row %q:\n%s", wantUnbound, duplicate)
	}
	for _, ordinary := range []string{"  Zone: trust\n", "  Zone: untrust\n"} {
		if strings.Contains(duplicate, ordinary) {
			t.Fatalf("duplicate membership rendered ordinary binding %q:\n%s", strings.TrimSpace(ordinary), duplicate)
		}
	}

	unique := renderInterfacesDetail18446(t, `
interfaces {
    lo { unit 0 { family inet { address 127.0.0.1/8; } } }
}
security {
    zones {
        security-zone trust { interfaces [ lo.0 ]; }
    }
}
`)
	if !strings.Contains(unique, "  Zone: trust\n") {
		t.Fatalf("unique binding detail changed; missing Zone: trust:\n%s", unique)
	}
	if strings.Contains(unique, "UNBOUND") {
		t.Fatalf("unique binding rendered quarantined:\n%s", unique)
	}
}

func renderInterfacesDetail18446(t *testing.T, text string) string {
	t.Helper()
	tree, errs := config.NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("config parse errors: %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}

	rr := httptest.NewRecorder()
	(&Server{}).writeInterfacesDetail(rr, cfg, "")
	if rr.Code != 200 {
		t.Fatalf("writeInterfacesDetail status = %d; body: %s", rr.Code, rr.Body.String())
	}
	var response Response
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal response: %v; body: %s", err, rr.Body.String())
	}
	data, ok := response.Data.(map[string]any)
	if !ok {
		t.Fatalf("response data type = %T, want map", response.Data)
	}
	output, ok := data["output"].(string)
	if !ok {
		t.Fatalf("response output type = %T, want string", data["output"])
	}
	return output
}
