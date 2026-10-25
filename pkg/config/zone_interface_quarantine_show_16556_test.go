package config

import (
	"strings"
	"testing"
)

// #16556: the shared per-interface verdict behind every show surface.
// On a tolerant load an interface claimed by two zones is bound to
// NEITHER at runtime; ZoneInterfaceQuarantineExclusions / Reason /
// Claimants must name both claimants, and the control (single claimant)
// must stay clean. Fail-on-revert: drop the Exclusions derivation (or
// revert renderers to the authored list) and these go RED.

func quarantineCfg16556(t *testing.T) *Config {
	t.Helper()
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
		"set security zones security-zone untrust interfaces ge-0/0/0.0",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

func TestZoneInterfaceQuarantineVerdict16556(t *testing.T) {
	cfg := quarantineCfg16556(t)

	exclusions := ZoneInterfaceQuarantineExclusions(cfg)
	claimants, ok := exclusions["ge-0/0/0.0"]
	if !ok {
		t.Fatalf("contested ge-0/0/0.0 missing from exclusions: %v", exclusions)
	}
	if len(claimants) != 2 || claimants[0] != "trust" || claimants[1] != "untrust" {
		t.Fatalf("claimants = %v, want [trust untrust]", claimants)
	}
	if _, ok := exclusions["ge-0/0/1.0"]; ok {
		t.Fatalf("singly-claimed ge-0/0/1.0 quarantined: %v", exclusions)
	}

	reason := ZoneInterfaceQuarantineReason(cfg, "trust", "ge-0/0/0.0")
	for _, want := range []string{"ge-0/0/0.0", "trust", "untrust", "bound to neither"} {
		if !strings.Contains(reason, want) {
			t.Fatalf("reason %q does not name %q", reason, want)
		}
	}
	if got := ZoneInterfaceQuarantineReason(cfg, "trust", "ge-0/0/1.0"); got != "" {
		t.Fatalf("control member reason = %q, want empty", got)
	}
	if got := ZoneInterfaceQuarantineReason(nil, "trust", "ge-0/0/0.0"); got != "" {
		t.Fatalf("nil-cfg reason = %q, want empty", got)
	}

	if got := ZoneInterfaceQuarantineClaimants(cfg, "ge-0/0/0.0"); len(got) != 2 {
		t.Fatalf("Claimants = %v, want two claimants", got)
	}
	if got := ZoneInterfaceQuarantineClaimants(cfg, "ge-0/0/1.0"); got != nil {
		t.Fatalf("control Claimants = %v, want nil", got)
	}

	rows := ZoneInterfaceQuarantineClaimantsForRows(cfg)
	if len(rows["ge-0/0/0.0"]) != 2 {
		t.Fatalf("rows[ge-0/0/0.0] = %v, want two claimants", rows["ge-0/0/0.0"])
	}
	if _, ok := rows["ge-0/0/1.0"]; ok {
		t.Fatalf("control row quarantined: %v", rows)
	}

	alarms := ZoneInterfaceQuarantineAlarmWarnings(cfg)
	if len(alarms) != 1 || !strings.Contains(alarms[0], "ge-0/0/0.0") ||
		!strings.Contains(alarms[0], "trust") || !strings.Contains(alarms[0], "untrust") {
		t.Fatalf("alarm warnings = %v, want one line naming ge-0/0/0.0 + both zones", alarms)
	}

	// The builder's runtime map must agree: contested key unbound, control bound.
	zoneMap := InterfaceZoneMap(cfg)
	if got := zoneMap["ge-0/0/0.0"]; got != "" {
		t.Fatalf("runtime map binds contested key to %q, want unbound", got)
	}
	if got := zoneMap["ge-0/0/1.0"]; got != "trust" {
		t.Fatalf("runtime map control = %q, want trust", got)
	}

	qualifier := ZoneInterfaceQuarantineUnboundQualifierFor(claimants)
	if qualifier != "[UNBOUND — claimed by zones trust and untrust]" {
		t.Fatalf("qualifier = %q", qualifier)
	}
}
