package config

import (
	"strings"
	"testing"
)

// TestSNMPInertKnobAdvisories is the RED-on-revert guard for #4306 S-5 (SNMP
// half): the security-relevant SNMP knobs that commit clean but do nothing
// must emit a loud accept-with-advisory, and the advisory must NOT echo the
// community NAME (an SNMP community string is a secret).
func TestSNMPInertKnobAdvisories(t *testing.T) {
	tree := buildTree4303(t, []string{
		"set snmp view myview oid 1.3.6.1.2.1 include",
		"set snmp community SUPERSECRETCOMMUNITY view myview",
		"set snmp community SUPERSECRETCOMMUNITY authorization read-only",
		"set snmp trap-options source-address 10.0.0.1",
		"set snmp health-monitor",
		"set snmp rmon",
	})
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected an accepted-inert SNMP config: %v", err)
	}
	all := strings.Join(c.Warnings, "\n")
	for _, want := range []string{
		"snmp view",
		"trap-options source-address",
		"health-monitor",
		"rmon",
		"community view",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing advisory %q; warnings:\n%s", want, all)
		}
	}
	// The community string must never appear in an advisory.
	if strings.Contains(all, "SUPERSECRETCOMMUNITY") {
		t.Errorf("advisory echoed the secret community string; warnings:\n%s", all)
	}
}

// TestSystemInertKnobAdvisories is the RED-on-revert guard for #4306 S-5
// (system half): login banner/retry, ntp boot-server/authentication-key/
// source-address, internet-options extras, and ssh rate-limit each emit an
// advisory, and the NTP authentication-key VALUE is never echoed.
func TestSystemInertKnobAdvisories(t *testing.T) {
	tree := buildTree4303(t, []string{
		`set system login message "authorized use only"`,
		`set system login announcement "maintenance saturday"`,
		"set system login retry-options tries-before-disconnect 3",
		"set system ntp boot-server 10.0.0.9",
		"set system ntp authentication-key 1 type md5 value NTPSECRETKEY",
		"set system ntp source-address 10.0.0.2",
		"set system internet-options tcp-mss 1400",
		"set system services ssh rate-limit 20",
	})
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected an accepted-inert system config: %v", err)
	}
	all := strings.Join(c.Warnings, "\n")
	for _, want := range []string{
		"login message",
		"login announcement",
		"login retry-options",
		"ntp boot-server",
		"ntp authentication-key",
		"ntp source-address",
		"internet-options",
		"ssh rate-limit",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing advisory %q; warnings:\n%s", want, all)
		}
	}
	if strings.Contains(all, "NTPSECRETKEY") {
		t.Errorf("advisory echoed the NTP authentication-key value; warnings:\n%s", all)
	}
}
