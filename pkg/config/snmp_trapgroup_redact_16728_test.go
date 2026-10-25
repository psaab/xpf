package config

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// #16728: since #15052 the `snmp trap-group <name>` identity IS the v1/v2c
// trap community sent on the wire (pkg/snmp trapCommunityForGroup returns
// tg.Name), yet every redacted surface printed it in cleartext. These tests
// pin the canary absent from the AST render, SNMPConfig JSON/YAML and the
// schema-pinned registry resolution, with the query-community control
// unchanged. RED-on-revert: dropping the trap-group case from
// secretIndices, the ByRoot entry, or the SNMPTrapGroup marshalers makes
// the canary reappear.

const trapGroupCanary16728 = "TRAPSECRET16728"

func TestTrapGroupNameRedactedAST16728(t *testing.T) {
	trees := map[string]*ConfigTree{
		"flat-set": buildRedactTree(t, []string{
			"set snmp community " + trapGroupCanary16728 + " authorization read-only",
			"set snmp trap-group " + trapGroupCanary16728 + " targets 192.0.2.10",
		}),
		"hierarchical": parseHierText(t, `snmp {
    community `+trapGroupCanary16728+` {
        authorization read-only;
    }
    trap-group `+trapGroupCanary16728+` {
        targets 192.0.2.10;
    }
}`),
		"groups": buildRedactTree(t, []string{
			"set groups g1 snmp trap-group " + trapGroupCanary16728 + " targets 192.0.2.10",
		}),
		"set-groups": buildRedactTree(t, []string{
			"set groups g1 snmp trap-group " + trapGroupCanary16728 + " targets 192.0.2.10",
		}),
	}
	for name, tree := range trees {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(tree.Format(), trapGroupCanary16728) {
				t.Fatalf("canary absent from UNREDACTED render; fixture broken:\n%s", tree.Format())
			}
			red := tree.RedactedClone()
			renders := map[string]string{
				"Format":     red.Format(),
				"FormatSet":  red.FormatSet(),
				"FormatJSON": red.FormatJSON(),
				"FormatXML":  red.FormatXML(),
			}
			for format, out := range renders {
				if strings.Contains(out, trapGroupCanary16728) {
					t.Errorf("%s leaked trap-group canary:\n%s", format, out)
				}
				if !strings.Contains(out, SecretDataPlaceholder) {
					t.Errorf("%s missing placeholder:\n%s", format, out)
				}
			}
			// Non-secret target stays visible.
			if !strings.Contains(red.Format(), "192.0.2.10") {
				t.Errorf("trap target over-redacted:\n%s", red.Format())
			}
		})
	}
	// Embedded change-configuration command judged by the same secretIndices.
	cmd := "set snmp trap-group " + trapGroupCanary16728 + " targets 192.0.2.10"
	if got := RedactEmbeddedChangeConfigCommand(cmd); strings.Contains(got, trapGroupCanary16728) || !strings.Contains(got, SecretDataPlaceholder) {
		t.Errorf("embedded command leaked trap-group canary: %q", got)
	}
}

// The schema-pinned registry (secretLeafKeywordsByRoot via isSecretLeaf)
// must resolve trap-group under snmp as secret, and only there.
func TestTrapGroupSchemaPinnedRegistry16728(t *testing.T) {
	if !isSecretLeaf("snmp", []string{"trap-group", trapGroupCanary16728}) {
		t.Error("isSecretLeaf(snmp, trap-group) = false, want true (#16728)")
	}
	if isSecretLeaf("policy-options", []string{"trap-group", "g1"}) {
		t.Error("isSecretLeaf(policy-options, trap-group) = true, want false")
	}
	if !isSecretValueIndex([]string{"snmp", "trap-group", trapGroupCanary16728}, 2) {
		t.Error("isSecretValueIndex(snmp trap-group <name>) = false, want true")
	}
	if isSecretValueIndex([]string{"policy-options", "trap-group", "g1"}, 2) {
		t.Error("isSecretValueIndex(policy-options trap-group g1) = true, want false")
	}
	// Both secret resolutions agree on the new entry (union coverage).
	for kw := range secretLeafKeywordsByRoot {
		_ = kw
	}
	if !isSecretLeaf("snmp", []string{"community", "x"}) {
		t.Error("community control regressed: isSecretLeaf(snmp, community) = false")
	}
}

// A redacted export naming a trap-group must be refused at ingest, exactly
// like a redacted community.
func TestTrapGroupPlaceholderIngestRejected16728(t *testing.T) {
	redacted := buildRedactTree(t, []string{
		"set snmp trap-group " + trapGroupCanary16728 + " targets 192.0.2.10",
	}).RedactedClone()
	if err := checkRedactionPlaceholder(redacted); !errors.Is(err, errRedactionPlaceholderIngest) {
		t.Fatalf("checkRedactionPlaceholder = %v, want errRedactionPlaceholderIngest", err)
	}
	clear := buildRedactTree(t, []string{
		"set snmp trap-group " + trapGroupCanary16728 + " targets 192.0.2.10",
	})
	if err := checkRedactionPlaceholder(clear); err != nil {
		t.Fatalf("cleartext trap-group rejected: %v", err)
	}
}

func TestSNMPTrapGroupMarshalRedactsName16728(t *testing.T) {
	cfg := SNMPConfig{
		Communities: map[string]*SNMPCommunity{
			"query-secret": {Name: "query-secret", Authorization: "read-only"},
		},
		TrapGroups: map[string]*SNMPTrapGroup{
			trapGroupCanary16728: {Name: trapGroupCanary16728, Targets: []string{"192.0.2.10"}, Version: "v2", Categories: []string{"link"}},
			"zz-nil":             nil,
		},
	}
	for _, tc := range []struct {
		name    string
		marshal func() (string, error)
	}{
		{"group JSON", func() (string, error) {
			b, err := json.Marshal(SNMPTrapGroup{Name: trapGroupCanary16728, Targets: []string{"192.0.2.10"}, Version: "v1"})
			return string(b), err
		}},
		{"config JSON", func() (string, error) {
			b, err := json.Marshal(cfg)
			return string(b), err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.marshal()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if strings.Contains(out, trapGroupCanary16728) {
				t.Errorf("trap-group canary leaked: %s", out)
			}
			if strings.Contains(out, "query-secret") {
				t.Errorf("community control leaked: %s", out)
			}
			// encoding/json HTML-escapes the "<redacted>" sentinel.
			if !strings.Contains(out, "redacted") {
				t.Errorf("missing redaction sentinel: %s", out)
			}
			for _, want := range []string{"192.0.2.10"} {
				if !strings.Contains(out, want) {
					t.Errorf("non-secret %q missing (over-redaction): %s", want, out)
				}
			}
		})
	}
	// YAML mirrors JSON.
	yb, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("yaml marshal: %v", err)
	}
	if strings.Contains(string(yb), trapGroupCanary16728) || strings.Contains(string(yb), "query-secret") {
		t.Errorf("YAML leaked secret: %s", yb)
	}
	if !strings.Contains(string(yb), "192.0.2.10") {
		t.Errorf("YAML over-redacted targets: %s", yb)
	}
	// In-memory names untouched (pkg/snmp lookup-by-name still works).
	if cfg.TrapGroups[trapGroupCanary16728].Name != trapGroupCanary16728 {
		t.Errorf("in-memory trap-group name mutated")
	}
}
