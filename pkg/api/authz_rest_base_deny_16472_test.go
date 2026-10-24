package api

import (
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
)

// #16472 REST twin: the REST show-text gate shared the gRPC gate's
// selector-spelling-only defect, so it shares the fix (canonical forms
// of the executed line and of the bare charge). These cells drive the
// real authorizeRESTCommand evaluator.

func restCfg16472(t *testing.T, deny, allow string) *config.Config {
	t.Helper()
	lc := &config.LoginClass{Name: "ops", DenyCommands: deny, AllowCommands: allow}
	if deny != "" {
		lc.DenyLeavesPresent = []string{"deny-commands"}
	}
	if allow != "" {
		lc.AllowLeavesPresent = []string{"allow-commands"}
	}
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{Classes: []*config.LoginClass{lc}}
	cfg.Security.Zones = map[string]*config.ZoneConfig{"trust": {}, "untrust": {}}
	return cfg
}

func TestRESTBaseDeny16472(t *testing.T) {
	s := &Server{}
	for _, tc := range []struct {
		name, deny, allow, url string
		wantDeny               bool
	}{
		{"fw filter base deny", `^show firewall$`, "", "/api/v1/show-text?topic=firewall-filter:F1", true},
		{"fw filter selector spelling (charge asymmetry)", `^show firewall filter$`, "", "/api/v1/show-text?topic=firewall-filter:F1", true},
		{"route table base deny", `^show route$`, "", "/api/v1/show-text?topic=route-table:inet.0", true},
		{"screen statistics base deny", `^show security screen statistics$`, "", "/api/v1/show-text?topic=screen-statistics:trust", true},
		{"screen ids rescue", `^show security screen$`, "", "/api/v1/show-text?topic=screen-ids-option:prof1", false},
		{"policies detail filtered base deny", `^show security policies$`, "", "/api/v1/show-text?topic=policies-detail&filter=from-zone%20trust%20to-zone%20untrust", true},
		{"policies detail unfiltered base", `^show security policies$`, "", "/api/v1/show-text?topic=policies-detail", false},
		{"zones detail filtered rescue", `^show security zones$`, "", "/api/v1/show-text?topic=zones-detail&filter=trust", false},
		{"unrelated deny allowed", `^show version$`, "", "/api/v1/show-text?topic=firewall-filter:F1", false},
		{"allow base satisfies", "", `^show firewall$`, "/api/v1/show-text?topic=firewall-filter:F1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := restCfg16472(t, tc.deny, tc.allow)
			r := httptest.NewRequest("GET", tc.url, nil)
			err := s.authorizeRESTCommand(r, cfg, authz.Principal{Class: "ops"})
			if denied := err != nil; denied != tc.wantDeny {
				t.Errorf("REST %s under deny=%q allow=%q: denied=%v, want %v (err=%v) (#16472)", tc.url, tc.deny, tc.allow, denied, tc.wantDeny, err)
			}
		})
	}
}
