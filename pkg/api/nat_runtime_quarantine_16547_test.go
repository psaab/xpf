package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #16547: REST twin of the gRPC runtime-quarantine cells.

type natVerdictsAPIDP struct {
	*dataplane.Manager
	verdicts dpuserspace.AppliedNATSnapshotVerdicts
}

func (d *natVerdictsAPIDP) IsLoaded() bool { return true }
func (d *natVerdictsAPIDP) AppliedNATSnapshotVerdicts() dpuserspace.AppliedNATSnapshotVerdicts {
	return d.verdicts
}

func decodeNATObjects(t *testing.T, h http.HandlerFunc, path string) []struct {
	NotInstalled       bool   `json:"not_installed"`
	NotInstalledReason string `json:"not_installed_reason"`
	TotalPorts         int    `json:"total_ports"`
} {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d body %s", path, rec.Code, rec.Body.String())
	}
	var env struct {
		Data []struct {
			NotInstalled       bool   `json:"not_installed"`
			NotInstalledReason string `json:"not_installed_reason"`
			TotalPorts         int    `json:"total_ports"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("%s: decode: %v", path, err)
	}
	return env.Data
}

func TestRESTNATRuntimeQuarantine16547(t *testing.T) {
	srv := natRESTServer(t, sourceCfg7473("203.0.113.10/32"))
	srv.dp = &natVerdictsAPIDP{Manager: dataplane.New(), verdicts: dpuserspace.AppliedNATSnapshotVerdicts{
		Available:      true,
		SourceNATRules: map[string]string{"r1": "iface_snat_egress_overlap"},
		SourceNATPools: map[string]string{"p1": "iface_snat_egress_overlap"},
		NAT64Rules:     map[string]string{},
	}}

	rules := decodeNATObjects(t, srv.natRuleStatsHandler, "/api/v1/security/nat/rules")
	if len(rules) != 1 || !rules[0].NotInstalled {
		t.Fatalf("natRuleStatsHandler: quarantined rule not marked: %+v", rules)
	}
	if !strings.Contains(rules[0].NotInstalledReason, "interface") {
		t.Errorf("reason = %q, want interface-overlap prose", rules[0].NotInstalledReason)
	}
	src := decodeNATObjects(t, srv.natSourceHandler, "/api/v1/security/nat/source")
	if len(src) != 1 || !src[0].NotInstalled {
		t.Fatalf("natSourceHandler: quarantined rule not marked: %+v", src)
	}
	pools := decodeNATObjects(t, srv.natPoolStatsHandler, "/api/v1/security/nat/source/pools")
	if len(pools) != 1 || !pools[0].NotInstalled {
		t.Fatalf("natPoolStatsHandler: quarantined pool not marked: %+v", pools)
	}
	if pools[0].TotalPorts != 0 {
		t.Errorf("quarantined pool total_ports = %d, want 0", pools[0].TotalPorts)
	}
}

func TestRESTNATRuntimeControlArmed16547(t *testing.T) {
	srv := natRESTServer(t, sourceCfg7473("203.0.113.10/32"))
	srv.dp = &natVerdictsAPIDP{Manager: dataplane.New(), verdicts: dpuserspace.AppliedNATSnapshotVerdicts{
		Available:      true,
		SourceNATRules: map[string]string{},
		SourceNATPools: map[string]string{},
		NAT64Rules:     map[string]string{},
	}}
	rules := decodeNATObjects(t, srv.natRuleStatsHandler, "/api/v1/security/nat/rules")
	if len(rules) != 1 || rules[0].NotInstalled {
		t.Fatalf("armed control marked not_installed: %+v", rules)
	}
}
