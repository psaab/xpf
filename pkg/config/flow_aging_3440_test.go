package config

import (
	"strings"
	"testing"
)

// #3440 H2: `security flow aging` was an opaque untyped schema node, so the
// schema walker skipped the whole subtree and the compiler parsed each value
// with a bare strconv.Atoi and stored it with no bounds / cross-field check.
// A negative early-ageout (cast to a huge uint64 in gc.SetAgingConfig), an
// out-of-range watermark (>100 percent), a low >= high oscillation, and an
// unknown leaf all committed cleanly.
//
// These tests pin the typed schema + strict gate. FAIL-ON-REVERT:
//   - revert the typed schema leaves (schema_security.go) and the bounds
//     subtests below go green on the BAD value (the schema gate no longer
//     rejects them).
//   - revert validateFlowAgingStrict / its dispatch (compiler_validate_strict.go
//     + compiler.go) and the cross-field + unknown-leaf subtests go green on
//     the BAD config.
//   - revert the #3440 H1 warning (compiler_validate_warn.go) and
//     TestFlowAgingConfigOnlyWarning fails.

// flowAgingSchemaCheck runs the commit-check typed-leaf gate (SchemaValidate)
// on a flat-set line, the same gate the live config-mode `set` completer
// walks.
func flowAgingSchemaCheck(t *testing.T, cmd string) error {
	t.Helper()
	tree := &ConfigTree{}
	path, err := ParseSetCommand(cmd)
	if err != nil {
		t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath(%q): %v", cmd, err)
	}
	return SchemaValidate(tree, nil)
}

func TestFlowAgingSchemaRejectsBadValues(t *testing.T) {
	bad := []struct {
		name string
		line string
		want string
	}{
		{"early-ageout-negative", "set security flow aging early-ageout -1", "early-ageout"},
		{"early-ageout-non-numeric", "set security flow aging early-ageout soon", "early-ageout"},
		{"early-ageout-over-max", "set security flow aging early-ageout 90000", "early-ageout"},
		{"high-watermark-over-100", "set security flow aging high-watermark 150", "high-watermark"},
		{"high-watermark-negative", "set security flow aging high-watermark -5", "high-watermark"},
		{"low-watermark-over-100", "set security flow aging low-watermark 200", "low-watermark"},
		{"low-watermark-non-numeric", "set security flow aging low-watermark eighty", "low-watermark"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			err := flowAgingSchemaCheck(t, tc.line)
			if err == nil {
				t.Fatalf("expected schema gate to reject %q, got nil", tc.line)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name the offending leaf %q", err.Error(), tc.want)
			}
		})
	}
}

func TestFlowAgingSchemaAcceptsValidValues(t *testing.T) {
	good := []string{
		"set security flow aging early-ageout 20",
		"set security flow aging early-ageout 0",
		"set security flow aging high-watermark 90",
		"set security flow aging low-watermark 80",
		"set security flow aging high-watermark 100",
		"set security flow aging low-watermark 0",
	}
	for _, line := range good {
		if err := flowAgingSchemaCheck(t, line); err != nil {
			t.Fatalf("schema gate rejected a well-formed line %q: %v", line, err)
		}
	}
}

func TestFlowAgingStrictCrossFieldAndUnknown(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		want  string
	}{
		{
			name: "low-ge-high-oscillates",
			lines: []string{
				"set security flow aging high-watermark 90",
				"set security flow aging low-watermark 95",
			},
			want: "low-watermark 95 must be less than high-watermark 90",
		},
		{
			name: "low-equals-high",
			lines: []string{
				"set security flow aging high-watermark 90",
				"set security flow aging low-watermark 90",
			},
			want: "must be less than high-watermark",
		},
		{
			name:  "unknown-leaf",
			lines: []string{"set security flow aging bogus 5"},
			want:  "bogus",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.lines)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to reject %v, got nil error", tc.lines)
			}
			if !strings.Contains(err.Error(), "security flow aging") {
				t.Fatalf("error %q does not name `security flow aging`", err.Error())
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

// TestFlowAgingStrictAcceptsValidCrossField asserts a sane low < high config
// (and the disabled / single-watermark forms) commit cleanly — anti-over-reject.
func TestFlowAgingStrictAcceptsValidCrossField(t *testing.T) {
	tree := buildTree(t, []string{
		"set security flow aging early-ageout 20",
		"set security flow aging high-watermark 90",
		"set security flow aging low-watermark 80",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit rejected a well-formed aging config: %v", err)
	}
	if cfg.Security.Flow.AgingEarlyAgeout != 20 ||
		cfg.Security.Flow.AgingHighWatermark != 90 ||
		cfg.Security.Flow.AgingLowWatermark != 80 {
		t.Fatalf("aging values not compiled: %+v", cfg.Security.Flow)
	}
}

// TestFlowAgingStrictLenientDowngrades asserts the tolerant load / peer-sync
// path downgrades the bad cross-field config to a warning so an
// already-persisted or peer-synced config still boots (#3440 / #1960
// no-brick); the userspace dataplane does not enforce aging anyway (#3440 H1).
func TestFlowAgingStrictLenientDowngrades(t *testing.T) {
	tree := buildTree(t, []string{
		"set security flow aging high-watermark 90",
		"set security flow aging low-watermark 95",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile hard-failed on a bad aging config (no-brick violated): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "flow aging") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient path did not record a flow-aging warning: %v", cfg.Warnings)
	}
}

// TestFlowAgingConfigOnlyWarning pins the #3440/#10890 advisory: configured
// aging values remain unwired even though userspace has a separate fixed
// half-open shedding rule at 90% of each worker's cap.
func TestFlowAgingConfigOnlyWarning(t *testing.T) {
	tree := buildTree(t, []string{
		"set security flow aging early-ageout 20",
		"set security flow aging high-watermark 75",
		"set security flow aging low-watermark 60",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "security flow aging configured but accepted-only") &&
			strings.Contains(w, "fixed 90%") &&
			strings.Contains(w, "values do not control that policy") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected the #3440/#10890 fixed-policy advisory, got warnings: %v", cfg.Warnings)
	}
}

// TestFlowAgingNoWarningWhenUnset asserts the advisory is silent when no aging
// knob is configured (anti-noise).
func TestFlowAgingNoWarningWhenUnset(t *testing.T) {
	tree := buildTree(t, []string{
		"set security flow allow-dns-reply",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "security flow aging configured but accepted-only") {
			t.Fatalf("unexpected aging advisory with no aging config: %v", cfg.Warnings)
		}
	}
}
