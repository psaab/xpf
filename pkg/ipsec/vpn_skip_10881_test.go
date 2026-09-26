package ipsec

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func captureWarnings10881(t *testing.T) *bytes.Buffer {
	t.Helper()
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &output
}

func compileTolerantIKEAuth10881(t *testing.T) *config.Config {
	t.Helper()
	commands := []string{
		"set security ike proposal bad-prop authentication-method dss-signatures",
		"set security ike proposal bad-prop encryption-algorithm aes-256-cbc",
		"set security ike proposal bad-prop authentication-algorithm sha-256",
		"set security ike proposal bad-prop dh-group group14",
		"set security ike policy bad-pol proposals bad-prop",
		"set security ike policy bad-pol pre-shared-key ascii-text secret-bad",
		"set security ike gateway bad-gw address 203.0.113.1",
		"set security ike gateway bad-gw ike-policy bad-pol",
		"set security ipsec vpn bad gateway bad-gw",
		"set security ipsec vpn bad bind-interface st0.0",
		"set security ike proposal good-prop authentication-method pre-shared-keys",
		"set security ike proposal good-prop encryption-algorithm aes-256-cbc",
		"set security ike proposal good-prop authentication-algorithm sha-256",
		"set security ike proposal good-prop dh-group group14",
		"set security ike policy good-pol proposals good-prop",
		"set security ike policy good-pol pre-shared-key ascii-text secret-good",
		"set security ike gateway good-gw address 203.0.113.2",
		"set security ike gateway good-gw ike-policy good-pol",
		"set security ipsec vpn healthy gateway good-gw",
		"set security ipsec vpn healthy bind-interface st0.0",
	}
	tree := &config.ConfigTree{}
	for _, command := range commands {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	if err := config.SchemaValidate(tree, nil); err == nil || !strings.Contains(err.Error(), "dss-signatures") {
		t.Fatalf("strict schema error = %v, want rejection naming dss-signatures", err)
	}
	compiled, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile must preserve the existing config: %v", err)
	}
	if got := compiled.Security.IPsec.IKEProposals["bad-prop"].AuthMethod; got != "dss-signatures" {
		t.Fatalf("tolerant compile auth method = %q, want dss-signatures", got)
	}
	return compiled
}

func TestMalformedJunosPSKSkipsVPNAndStillTerminatesRemovedSA10881(t *testing.T) {
	warnings := captureWarnings10881(t)
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)
	if err := m.Apply(vpnCfg("removed", "healthy")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}

	// Removing a previously loaded connection while a different VPN inherits
	// a malformed policy-level key must still complete Apply and reach the
	// normal stale-SA teardown.
	rec.listSAs = liveSA("removed")
	next := vpnCfg("bad", "healthy")
	next.Gateways = map[string]*config.IPsecGateway{
		"bad-gw": {Name: "bad-gw", Address: "10.0.2.1", IKEPolicy: "bad-pol"},
	}
	next.IKEPolicies = map[string]*config.IKEPolicy{
		"bad-pol": {Name: "bad-pol", Proposals: []string{"bad-prop"}, PSK: config.Secret("$9$garbage")},
	}
	next.IKEProposals = map[string]*config.IKEProposal{
		"bad-prop": {
			Name:          "bad-prop",
			AuthMethod:    "pre-shared-keys",
			EncryptionAlg: "aes-256-cbc",
			AuthAlg:       "sha-256",
			DHGroup:       14,
		},
	}
	next.VPNs["bad"].Gateway = "bad-gw"
	next.VPNs["bad"].PSK = ""
	if err := m.Apply(next); err != nil {
		t.Fatalf("Apply with one malformed PSK must preserve healthy VPNs: %v", err)
	}

	gotTerminated := rec.terminateCalls()
	if len(gotTerminated) != 1 || gotTerminated[0] != "removed" {
		t.Fatalf("terminated connections = %v, want [removed]", gotTerminated)
	}
	generated, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("reading applied swanctl config: %v", err)
	}
	doc := parseSwanctlDoc(t, string(generated))
	doc.at(t, "connections").hasNoChild(t, "bad")
	doc.at(t, "connections", "healthy")
	doc.at(t, "secrets").hasNoChild(t, "ike-bad")
	doc.at(t, "secrets", "ike-healthy")
	if report := warnings.String(); !strings.Contains(report, "vpn=bad") || !strings.Contains(report, "malformed pre-shared key") {
		t.Fatalf("malformed-PSK skip must be reported with VPN name and reason, got %q", report)
	}
}

func TestTolerantUnknownIKEAuthSkipsOnlyVPN10881(t *testing.T) {
	warnings := captureWarnings10881(t)
	compiled := compileTolerantIKEAuth10881(t)
	m := newRecordingManager(t, &swanctlRecorder{})
	if err := m.Apply(&compiled.Security.IPsec); err != nil {
		t.Fatalf("Apply after tolerant compile must retain healthy VPN: %v", err)
	}

	generated, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("reading applied swanctl config: %v", err)
	}
	doc := parseSwanctlDoc(t, string(generated))
	doc.at(t, "connections").hasNoChild(t, "bad")
	doc.at(t, "connections", "healthy")
	doc.at(t, "secrets").hasNoChild(t, "ike-bad")
	doc.at(t, "secrets", "ike-healthy")
	if report := warnings.String(); !strings.Contains(report, "vpn=bad") || !strings.Contains(report, "dss-signatures") {
		t.Fatalf("unknown-auth skip must be reported with VPN name and reason, got %q", report)
	}
}
