package configstore

import (
	"path/filepath"
	"strings"
	"testing"
)

// #16731: ShowActiveRedacted / ShowCandidateRedacted (CLI show
// configuration, gRPC ShowConfig, REST /api/v1/config/show for PermView)
// must mask the unmodelled Junos credential leaves that commit clean, on
// both the candidate (pre-commit) and active (post-commit) renders.
func TestShowRedactedCredentialShape16731(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	lines := []string{
		"interfaces pp0 unit 0 ppp-options chap default-chap-secret LEAK16731-CHAP",
		"interfaces pp0 unit 0 ppp-options pap local-password LEAK16731-PAP",
		"system services outbound-ssh client c1 secret LEAK16731-OSSH",
		"services security-intelligence authentication auth-token LEAK16731-SECINTEL",
		"snmp v3 snmp-community idx1 community-name LEAK16731-COMMNAME",
		"system services dhcp-local-server group g1 authentication password LEAK16731-DHCPGRP",
		"system services dhcp-local-server authentication password LEAK16731-DHCPGLOB",
		"system services dhcpv6-local-server group g6 authentication password LEAK16731-DHCP6",
		"forwarding-options dhcp-relay server-group sg1 192.0.2.1",
		"forwarding-options dhcp-relay group rg active-server-group sg1",
		"forwarding-options dhcp-relay group rg authentication password LEAK16731-RELAY",
		"snmp v3 snmp-community idx1 security-name secname16731",
	}
	secrets := []string{"LEAK16731-CHAP", "LEAK16731-PAP", "LEAK16731-OSSH", "LEAK16731-SECINTEL", "LEAK16731-COMMNAME", "LEAK16731-DHCPGRP", "LEAK16731-DHCPGLOB", "LEAK16731-DHCP6", "LEAK16731-RELAY"}
	for _, line := range lines {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
	cand := s.ShowCandidateRedacted(nil)
	for _, sec := range secrets {
		if strings.Contains(cand, sec) {
			t.Errorf("candidate redacted leaked %q:\n%s", sec, cand)
		}
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit (premise: rows commit clean): %v", err)
	}
	s.ExitConfigure()
	active := s.ShowActiveRedacted(nil)
	for _, sec := range secrets {
		if strings.Contains(active, sec) {
			t.Errorf("active redacted leaked %q:\n%s", sec, active)
		}
	}
	if !strings.Contains(active, "##SECRET-DATA##") {
		t.Errorf("active redacted missing placeholder:\n%s", active)
	}
	if !strings.Contains(active, "secname16731") {
		t.Errorf("non-secret security-name over-masked:\n%s", active)
	}
}
