package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15207: never wire encoding.
func TestAppTimeoutNeverWire15207(t *testing.T) {
	cfg := appTimeoutCfg(map[string]*config.Application{
		"never-web": {Name: "never-web", Protocol: "tcp", DestinationPort: "443", InactivityTimeoutNever: true},
	})
	terms, ok := expandUserspacePolicyApplications(cfg, []string{"never-web"})
	if !ok || len(terms) != 1 {
		t.Fatalf("expand ok=%v terms=%v", ok, terms)
	}
	if terms[0].InactivityTimeout != 86401 {
		t.Fatalf("never wire=%d want 86401", terms[0].InactivityTimeout)
	}
}
