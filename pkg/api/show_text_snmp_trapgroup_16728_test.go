package api

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16728: REST show-text `snmp` must mask the trap-group name (the v1/v2c
// trap community since #15052) unconditionally, like the query community.
// RED-on-revert: printing the raw map key re-leaks the canary.
func TestShowTextSNMPTrapGroupRedacted16728(t *testing.T) {
	const canary = "API-TRAPSECRET-16728"
	s := stageShowTextConfig(t, []string{
		"set snmp community LEAK-SNMP-COMMUNITY authorization read-only",
		"set snmp trap-group " + canary + " targets 192.0.2.10",
	})
	out := renderShowTextBody(t, s, "snmp")
	if strings.Contains(out, canary) {
		t.Errorf("trap-group community leaked over REST show-text:\n%s", out)
	}
	if strings.Contains(out, "LEAK-SNMP-COMMUNITY") {
		t.Errorf("community control leaked over REST show-text:\n%s", out)
	}
	if !strings.Contains(out, config.SecretDataPlaceholder+": 192.0.2.10") {
		t.Errorf("missing masked trap-group line:\n%s", out)
	}
	if !strings.Contains(out, "192.0.2.10") {
		t.Errorf("trap target over-redacted:\n%s", out)
	}
}
