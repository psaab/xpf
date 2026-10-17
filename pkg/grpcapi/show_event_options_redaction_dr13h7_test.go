package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14413 (DR13-H7): a live credential embedded in an event-options
// `then change-configuration commands` payload must never render verbatim on
// the PermView surfaces: RedactedClone().Format()/FormatSet()/FormatJSON()/
// FormatXML() and `show event-options` (gRPC + CLI). The stored command must
// stay raw (the event engine executes it); redaction is render-time only.
const (
	dr13h7QuotedPSK   = "PSK-DISTINCTIVE-7Q"
	dr13h7UnquotedPSK = "PSK-UNQUOTED-7Q"
	dr13h7EventText   = `
event-options {
    policy p1 {
        events ping_test_failed;
        then {
            change-configuration {
                commands "set security ike policy p1 pre-shared-key ascii-text PSK-DISTINCTIVE-7Q";
                commands "set system host-name foo";
                commands "set system login user bob class operator";
            }
        }
    }
}
`
	dr13h7UnquotedLine = `set event-options policy p1 then change-configuration commands set security ike policy p1 pre-shared-key ascii-text PSK-UNQUOTED-7Q`
)

func dr13h7ParseHier(t *testing.T, text string) *config.ConfigTree {
	t.Helper()
	tree, errs := config.NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("NewParser: %v", errs)
	}
	return tree
}

func dr13h7FlatTree(t *testing.T, lines ...string) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, line := range lines {
		toks, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(toks); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}

func dr13h7AssertNoPSK(t *testing.T, label, rendered string, psps ...string) {
	t.Helper()
	for _, psk := range psps {
		if strings.Contains(rendered, psk) {
			t.Errorf("%s leaked embedded PSK %q verbatim:\n%s", label, psk, rendered)
		}
	}
	if !strings.Contains(rendered, config.SecretDataPlaceholder) {
		t.Errorf("%s did not render %s placeholder:\n%s", label, config.SecretDataPlaceholder, rendered)
	}
	for _, control := range []string{"set system host-name foo", "set system login user bob class operator"} {
		if !strings.Contains(rendered, control) {
			t.Errorf("%s dropped non-secret control %q:\n%s", label, control, rendered)
		}
	}
}

// TestEventOptionsEmbeddedPSKRedactedClone14413 covers the AST display path:
// quoted (one-token) and unquoted (multi-token) embedded credential commands,
// hierarchical and flat-set shapes, across all four RedactedClone formats.
func TestEventOptionsEmbeddedPSKRedactedClone14413(t *testing.T) {
	hier := dr13h7ParseHier(t, dr13h7EventText)
	flat := dr13h7FlatTree(t,
		`set event-options policy p1 events ping_test_failed`,
		`set event-options policy p1 then change-configuration commands "set security ike policy p1 pre-shared-key ascii-text `+dr13h7QuotedPSK+`"`,
		`set event-options policy p1 then change-configuration commands "set system host-name foo"`,
		`set event-options policy p1 then change-configuration commands "set system login user bob class operator"`,
	)
	unquoted := dr13h7FlatTree(t,
		`set event-options policy p1 events ping_test_failed`,
		dr13h7UnquotedLine,
		`set event-options policy p1 then change-configuration commands "set system host-name foo"`,
		`set event-options policy p1 then change-configuration commands "set system login user bob class operator"`,
	)

	for _, tc := range []struct {
		name string
		tree *config.ConfigTree
		psk  string
	}{
		{"hierarchical quoted", hier, dr13h7QuotedPSK},
		{"flat-set quoted", flat, dr13h7QuotedPSK},
		{"flat-set unquoted", unquoted, dr13h7UnquotedPSK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			redacted := tc.tree.RedactedClone()
			dr13h7AssertNoPSK(t, "Format()", redacted.Format(), tc.psk)
			dr13h7AssertNoPSK(t, "FormatSet()", redacted.FormatSet(), tc.psk)
			dr13h7AssertNoPSK(t, "FormatJSON()", redacted.FormatJSON(), tc.psk)
			dr13h7AssertNoPSK(t, "FormatXML()", redacted.FormatXML(), tc.psk)
			// The live tree must be untouched: execution reads raw commands.
			if strings.Contains(tc.tree.Format(), config.SecretDataPlaceholder) && strings.Contains(tc.tree.Format(), "pre-shared-key") {
				// Only fail if the source tree itself was mutated at the secret.
				if !strings.Contains(tc.tree.Format(), tc.psk) {
					t.Errorf("source tree was mutated by RedactedClone:\n%s", tc.tree.Format())
				}
			}
		})
	}
}

// TestEventOptionsEmbeddedPSKCompiledStaysRaw14413 pins that compilation
// (the execution source) still stores the raw command.
func TestEventOptionsEmbeddedPSKCompiledStaysRaw14413(t *testing.T) {
	cfg, err := config.CompileConfig(dr13h7ParseHier(t, dr13h7EventText))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.EventOptions) != 1 {
		t.Fatalf("policies = %d, want 1", len(cfg.EventOptions))
	}
	joined := strings.Join(cfg.EventOptions[0].ThenCommands, "\n")
	if !strings.Contains(joined, dr13h7QuotedPSK) {
		t.Fatalf("compiled ThenCommands lost raw PSK (execution broken): %q", joined)
	}
	if len(cfg.EventOptions[0].ThenCommands) != 3 {
		t.Fatalf("ThenCommands = %q, want 3 commands", cfg.EventOptions[0].ThenCommands)
	}
}

// TestShowEventOptionsRedactsEmbeddedPSK14413 covers the gRPC show surface.
// The CLI twin lives in pkg/cli (same helper, unexported gRPC method here).
func TestShowEventOptionsRedactsEmbeddedPSK14413(t *testing.T) {
	cfg, err := config.CompileConfig(dr13h7ParseHier(t, dr13h7EventText))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	var buf strings.Builder
	(&Server{}).showEventOptions(cfg, &buf)
	out := buf.String()
	dr13h7AssertNoPSK(t, "show event-options (gRPC)", out, dr13h7QuotedPSK)
	// Stored config still raw after display.
	if !strings.Contains(strings.Join(cfg.EventOptions[0].ThenCommands, "\n"), dr13h7QuotedPSK) {
		t.Fatalf("show mutated stored ThenCommands: %q", cfg.EventOptions[0].ThenCommands)
	}
}

// TestEventOptionsEmbeddedPSKCompareAndBlock14413 covers the compare surface
// and the `commands { … }` block shape plus a bracket list: every shape the
// compiler reader accepts must redact, and FormatCompareRedacted must keep
// secret-equality (same PSK diffs clean, different PSK diffs as changed)
// without ever rendering the value.
func TestEventOptionsEmbeddedPSKCompareAndBlock14413(t *testing.T) {
	blockText := `
event-options {
    policy p1 {
        events ping_test_failed;
        then {
            change-configuration {
                commands {
                    "set security ike policy p1 pre-shared-key ascii-text PSK-DISTINCTIVE-7Q";
                    "set system host-name foo";
                }
                commands [ "set security ike policy p1 pre-shared-key ascii-text PSK-DISTINCTIVE-7Q" "set system host-name foo" ];
            }
        }
    }
}
`
	block := dr13h7ParseHier(t, blockText)
	redacted := block.RedactedClone()
	for name, rendered := range map[string]string{
		"Format()": redacted.Format(), "FormatSet()": redacted.FormatSet(),
		"FormatJSON()": redacted.FormatJSON(), "FormatXML()": redacted.FormatXML(),
	} {
		if strings.Contains(rendered, dr13h7QuotedPSK) {
			t.Errorf("%s (block/bracket) leaked embedded PSK:\n%s", name, rendered)
		}
		if !strings.Contains(rendered, "set system host-name foo") {
			t.Errorf("%s (block/bracket) dropped non-secret control:\n%s", name, rendered)
		}
	}

	same := config.FormatCompareRedacted(dr13h7ParseHier(t, dr13h7EventText), dr13h7ParseHier(t, dr13h7EventText))
	if strings.Contains(same, dr13h7QuotedPSK) {
		t.Errorf("FormatCompareRedacted (identical) leaked PSK:\n%s", same)
	}
	if strings.Contains(same, config.SecretDataPlaceholder) {
		t.Errorf("FormatCompareRedacted (identical trees) should not render the placeholder:\n%s", same)
	}
	changedText := strings.Replace(dr13h7EventText, dr13h7QuotedPSK, "PSK-OTHER-9Z", 1)
	diff := config.FormatCompareRedacted(dr13h7ParseHier(t, dr13h7EventText), dr13h7ParseHier(t, changedText))
	if strings.Contains(diff, dr13h7QuotedPSK) || strings.Contains(diff, "PSK-OTHER-9Z") {
		t.Errorf("FormatCompareRedacted (changed PSK) leaked a PSK:\n%s", diff)
	}
	if !strings.Contains(diff, "secret fingerprint") {
		t.Errorf("FormatCompareRedacted (changed PSK) lost the fingerprint metadata:\n%s", diff)
	}
}

// TestRedactEmbeddedChangeConfigCommand14413 pins the shared helper directly:
// credential leaves mask (with the qualifier kept), gated keywords obey
// their AST context, non-secret and delete commands pass through verbatim,
// and a GRE `key` (non-secret) is never masked.
func TestRedactEmbeddedChangeConfigCommand14413(t *testing.T) {
	cases := []struct{ in, notContain, contain string }{
		{"set security ike policy p1 pre-shared-key ascii-text PSK-DISTINCTIVE-7Q", "PSK-DISTINCTIVE-7Q", "pre-shared-key ascii-text \"" + config.SecretDataPlaceholder + "\""},
		{"set protocols bgp group g authentication-key BGPSECRET14413", "BGPSECRET14413", config.SecretDataPlaceholder},
		{"set protocols ospf area 0 interface ge-0/0/0 authentication md5 1 key MD5SECRET14413", "MD5SECRET14413", config.SecretDataPlaceholder},
		{"set snmp community COMMUNITYSECRET14413 authorization read-only", "COMMUNITYSECRET14413", config.SecretDataPlaceholder},
		{"set system services dynamic-dns provider cf api-token TOKEN14413", "TOKEN14413", config.SecretDataPlaceholder},
		{"set interfaces ge-0/0/0 unit 0 tunnel key 12345", "", "tunnel key 12345"},
		{"set system host-name foo", "", "set system host-name foo"},
		{"delete security ike policy p1 pre-shared-key", "", "delete security ike policy p1 pre-shared-key"},
		{"set system login user bob class operator", "", "set system login user bob class operator"},
	}
	for _, tc := range cases {
		got := config.RedactEmbeddedChangeConfigCommand(tc.in)
		if tc.notContain != "" && strings.Contains(got, tc.notContain) {
			t.Errorf("RedactEmbeddedChangeConfigCommand(%q) = %q, still contains secret", tc.in, got)
		}
		if !strings.Contains(got, tc.contain) {
			t.Errorf("RedactEmbeddedChangeConfigCommand(%q) = %q, want substring %q", tc.in, got, tc.contain)
		}
	}
}
