package config

import (
	"strings"
	"testing"
)

// #17844: the trap-group name IS the v1/v2c trap community since #15052, and
// #16728 masked it on AST/JSON/YAML/CLI/REST/gRPC surfaces — but the compiler
// diagnostics in compileSNMP still embedded tgName verbatim: the strict
// commit errors and the lenient (tolerant-load / peer-sync) cfg.Warnings for
// unknown statements, invalid categories, the no-emitted-category advisory
// and zero-target groups. A commit error is echoed to the committing
// terminal/log and warnings ride tolerant-load paths, so the credential
// leaked to any reader of those outputs.
//
// Fix contract pinned here: every trap-group diagnostic renders the fixed
// SecretDataPlaceholder token in place of the group name, on BOTH the strict
// error branch and the lenient warning branch, while non-secret operands
// (the offending statement key, the invalid category, the target address)
// stay named so the operator can still fix the config. The in-memory group
// (map key + Name, read by pkg/snmp for the wire community) must retain the
// real value.
//
// RED-on-revert: restoring any `tgName` operand in the six format sites
// re-leaks the canary below into the corresponding error/warning.

const trapGroupDiagCanary17844 = "CFG-TRAPSECRET-17844"

// compileTrapGroupDiag17844 compiles `lines` on the requested path and
// returns the collected diagnostic text (error string plus all warnings),
// so every assertion greps the same surface the operator would read.
func compileTrapGroupDiag17844(t *testing.T, lines []string, lenient bool) (string, *Config, error) {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	var cfg *Config
	var err error
	if lenient {
		cfg, err = CompileConfigLenient(tree)
	} else {
		cfg, err = CompileConfig(tree)
	}
	var b strings.Builder
	if err != nil {
		b.WriteString(err.Error())
		b.WriteString("\n")
	}
	if cfg != nil {
		for _, w := range cfg.Warnings {
			b.WriteString(w)
			b.WriteString("\n")
		}
		if cfg.System.SNMP != nil {
			if tg := cfg.System.SNMP.TrapGroups[trapGroupDiagCanary17844]; tg != nil {
				if tg.Name != trapGroupDiagCanary17844 {
					t.Errorf("in-memory trap-group Name mutated: got %q, want the real group name", tg.Name)
				}
			}
		}
	}
	return b.String(), cfg, err
}

func trapGroupDiagCases17844() []struct {
	name     string
	lines    []string
	control  string // non-secret operand that must stay visible
	needErr  bool   // strict path must reject
	warnSub  string // lenient path must warn with this substring
	wantWarn bool
} {
	canary := trapGroupDiagCanary17844
	return []struct {
		name     string
		lines    []string
		control  string
		needErr  bool
		warnSub  string
		wantWarn bool
	}{
		{
			name:     "unknown-statement",
			lines:    []string{"set snmp trap-group " + canary + " tragets 192.0.2.10"},
			control:  "tragets",
			needErr:  true,
			warnSub:  "unknown statement",
			wantWarn: true,
		},
		{
			name: "invalid-category",
			lines: []string{
				"set snmp trap-group " + canary + " targets 192.0.2.10",
				"set snmp trap-group " + canary + " categories nosuchcat",
			},
			control:  "nosuchcat",
			needErr:  true,
			warnSub:  "invalid trap category",
			wantWarn: true,
		},
		{
			// Valid-but-unemitted category: advisory warning on BOTH paths
			// (no strict error) — the sixth tgName site.
			name: "unemitted-category-advisory",
			lines: []string{
				"set snmp trap-group " + canary + " targets 192.0.2.10",
				"set snmp trap-group " + canary + " categories authentication",
			},
			control:  "authentication",
			needErr:  false,
			warnSub:  "no category xpf emits",
			wantWarn: true,
		},
		{
			name:     "no-targets",
			lines:    []string{"set snmp trap-group " + canary + " version v2"},
			control:  "no targets configured",
			needErr:  true,
			warnSub:  "no targets configured",
			wantWarn: true,
		},
	}
}

// TestTrapGroupCompilerDiagnosticsRedacted17844 — strict (commit) path.
func TestTrapGroupCompilerDiagnosticsRedacted17844(t *testing.T) {
	for _, tc := range trapGroupDiagCases17844() {
		t.Run(tc.name+"/strict", func(t *testing.T) {
			out, _, err := compileTrapGroupDiag17844(t, tc.lines, false)
			if tc.needErr && err == nil {
				t.Fatalf("strict compile accepted %s config; diagnostics:\n%s", tc.name, out)
			}
			if !tc.needErr && err != nil {
				t.Fatalf("strict compile rejected %s config: %v", tc.name, err)
			}
			if strings.Contains(out, trapGroupDiagCanary17844) {
				t.Fatalf("trap community LEAKED in strict diagnostics:\n%s", out)
			}
			if !strings.Contains(out, SecretDataPlaceholder) {
				t.Fatalf("strict diagnostics missing redaction placeholder %q:\n%s", SecretDataPlaceholder, out)
			}
			if !strings.Contains(out, tc.control) {
				t.Fatalf("strict diagnostics dropped non-secret operand %q:\n%s", tc.control, out)
			}
		})
	}
}

// TestTrapGroupCompilerWarningsRedacted17844 — lenient (tolerant load /
// peer-sync) path: cfg.Warnings must carry the same redaction.
func TestTrapGroupCompilerWarningsRedacted17844(t *testing.T) {
	for _, tc := range trapGroupDiagCases17844() {
		t.Run(tc.name+"/lenient", func(t *testing.T) {
			out, cfg, err := compileTrapGroupDiag17844(t, tc.lines, true)
			if err != nil {
				t.Fatalf("lenient compile must not fail on %s (brick-on-restart): %v", tc.name, err)
			}
			if strings.Contains(out, trapGroupDiagCanary17844) {
				t.Fatalf("trap community LEAKED in lenient warnings:\n%s", out)
			}
			if tc.wantWarn {
				if !hasWarningSubstr(cfg.Warnings, tc.warnSub) {
					t.Fatalf("lenient warnings missing %q: %v", tc.warnSub, cfg.Warnings)
				}
				if !strings.Contains(out, SecretDataPlaceholder) {
					t.Fatalf("lenient warnings missing redaction placeholder %q:\n%s", SecretDataPlaceholder, out)
				}
				if !strings.Contains(out, tc.control) {
					t.Fatalf("lenient warnings dropped non-secret operand %q:\n%s", tc.control, out)
				}
			}
			// The compiled group itself is NOT a diagnostic: the wire
			// community (map key + Name) must survive compilation intact.
			if cfg != nil && cfg.System.SNMP != nil {
				if _, ok := cfg.System.SNMP.TrapGroups[trapGroupDiagCanary17844]; !ok {
					t.Fatalf("compiled config lost the trap group under its real name; groups=%v", cfg.System.SNMP.TrapGroups)
				}
			}
		})
	}
}

// TestTrapGroupCompilerValidGroupClean17844 — control: a well-formed group
// named with the canary compiles warning-free on both paths (no placeholder
// spam), proving the diagnostics are the only redacted surface.
func TestTrapGroupCompilerValidGroupClean17844(t *testing.T) {
	lines := []string{
		"set snmp trap-group " + trapGroupDiagCanary17844 + " targets 192.0.2.10",
		"set snmp trap-group " + trapGroupDiagCanary17844 + " categories link",
	}
	for _, lenient := range []bool{false, true} {
		out, cfg, err := compileTrapGroupDiag17844(t, lines, lenient)
		if err != nil {
			t.Fatalf("lenient=%v: valid trap-group rejected: %v", lenient, err)
		}
		if cfg == nil || len(cfg.Warnings) != 0 {
			t.Fatalf("lenient=%v: valid trap-group produced warnings: %v", lenient, cfg.Warnings)
		}
		if strings.Contains(out, SecretDataPlaceholder) {
			t.Fatalf("lenient=%v: valid trap-group diagnostics contain placeholder:\n%s", lenient, out)
		}
		tg := cfg.System.SNMP.TrapGroups[trapGroupDiagCanary17844]
		if tg == nil || len(tg.Targets) != 1 || tg.Targets[0] != "192.0.2.10" {
			t.Fatalf("lenient=%v: compiled group = %+v, want one target 192.0.2.10", lenient, tg)
		}
	}
}
