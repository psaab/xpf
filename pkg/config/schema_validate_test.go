package config_test

// Tests for the #1319 typed-leaf schema gate. SchemaValidate itself
// lives in pkg/cmdtree (the validators it dispatches to live in
// pkg/config); we exercise it end-to-end through configstore.Commit /
// CommitCheck in the configstore tests, and exercise the validators +
// AST walker here against parsed AST trees.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
)

// schemaCheck parses a Junos hierarchical config snippet and runs
// SchemaValidate against the resulting AST. apply-groups expansion is
// exercised through configstore tests because configstore owns the
// commit/load ordering relative to the compiler.
func schemaCheck(t *testing.T, input string) error {
	t.Helper()
	p := config.NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	return cmdtree.SchemaValidate(tree, nil)
}

func flatSchemaCheck(t *testing.T, cmds ...string) error {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return cmdtree.SchemaValidate(tree, nil)
}

func TestSchemaValidate_TransmitRate_RejectsGarbage(t *testing.T) {
	err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            transmit-rate asd;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for transmit-rate asd, got nil")
	}
	if !strings.Contains(err.Error(), "transmit-rate") {
		t.Fatalf("error should reference transmit-rate: %v", err)
	}
	if !strings.Contains(err.Error(), "asd") {
		t.Fatalf("error should quote bad input: %v", err)
	}
}

func TestSchemaValidate_TransmitRate_AcceptsValid(t *testing.T) {
	if err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            transmit-rate 1g;
        }
    }
}`); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSchemaValidate_TransmitRate_AcceptsExactModifier(t *testing.T) {
	if err := schemaCheck(t, `class-of-service {
	    schedulers {
	        be {
            transmit-rate 1g {
                exact;
            }
        }
    }
}`); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSchemaValidate_TransmitRate_AcceptsSplitExactModifier(t *testing.T) {
	if err := flatSchemaCheck(t,
		"set class-of-service schedulers be transmit-rate 1g",
		"set class-of-service schedulers be transmit-rate exact",
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSchemaValidate_TransmitRate_RejectsSplitExactWithoutRate(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate exact")
	if err == nil {
		t.Fatal("expected error for transmit-rate exact without a sibling rate, got nil")
	}
	if !strings.Contains(err.Error(), "transmit-rate") {
		t.Fatalf("error should reference transmit-rate: %v", err)
	}
}

func TestSchemaValidate_TransmitRate_RejectsTooSmall(t *testing.T) {
	err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            transmit-rate 1;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for transmit-rate 1, got nil")
	}
}

func TestSchemaValidate_TransmitRate_RejectsMissingValue(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate")
	if err == nil {
		t.Fatal("expected error for transmit-rate with no value, got nil")
	}
	if !strings.Contains(err.Error(), "missing value") {
		t.Fatalf("error should describe missing value: %v", err)
	}
}

func TestSchemaValidate_TransmitRate_RejectsUnknownModifier(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate 1g typo")
	if err == nil {
		t.Fatal("expected error for unknown transmit-rate modifier, got nil")
	}
	if !strings.Contains(err.Error(), "unknown modifier") {
		t.Fatalf("error should describe unknown modifier: %v", err)
	}
}

func TestSchemaValidate_Priority_AcceptsStrictHigh(t *testing.T) {
	if err := schemaCheck(t, `class-of-service {
	    schedulers {
        be {
            priority strict-high;
        }
    }
}`); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSchemaValidate_Priority_RejectsUnknown(t *testing.T) {
	err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            priority foo;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for priority foo, got nil")
	}
	if !strings.Contains(err.Error(), "priority") {
		t.Fatalf("error should reference priority: %v", err)
	}
}

func TestSchemaValidate_BufferSize_AcceptsBytes(t *testing.T) {
	if err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            buffer-size 16m;
        }
    }
}`); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSchemaValidate_BufferSize_RejectsBareInteger(t *testing.T) {
	err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            buffer-size 50;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for ambiguous bare-integer buffer-size 50, got nil")
	}
}

func TestSchemaValidate_BufferSize_AcceptsPercent(t *testing.T) {
	if err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            buffer-size 10%;
        }
    }
}`); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSchemaValidate_BufferSize_AcceptsQuotedPercent(t *testing.T) {
	if err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            buffer-size "12.5%";
        }
    }
}`); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSchemaValidate_BufferSize_RejectsGarbage(t *testing.T) {
	err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            buffer-size purple;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for buffer-size purple, got nil")
	}
}

func TestSchemaValidate_BufferSize_RejectsUnknownModifier(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be buffer-size 16m typo")
	if err == nil {
		t.Fatal("expected error for unknown buffer-size modifier, got nil")
	}
	if !strings.Contains(err.Error(), "unknown modifier") {
		t.Fatalf("error should describe unknown modifier: %v", err)
	}
}

func TestSchemaValidate_BufferSize_RejectsMissingValue(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be buffer-size")
	if err == nil {
		t.Fatal("expected error for buffer-size with no value, got nil")
	}
}

func TestSchemaValidate_BufferSize_RejectsBareIntegerGreaterThan100(t *testing.T) {
	err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            buffer-size 150;
        }
    }
	}`)
	if err == nil {
		t.Fatal("expected error for ambiguous bare-integer buffer-size 150, got nil")
	}
}

func TestSchemaValidate_BufferSize_RejectsZeroPercent(t *testing.T) {
	err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            buffer-size 0%;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for zero percent buffer-size, got nil")
	}
	if !strings.Contains(err.Error(), "buffer-size") {
		t.Fatalf("error should reference buffer-size: %v", err)
	}
}

// FlatSetSyntax exercises the alternate AST shape that ParseSetCommand
// + tree.SetPath produces: Keys=["schedulers","be","transmit-rate","1g"]
// (when input is `set class-of-service schedulers be transmit-rate 1g`).
func TestSchemaValidate_FlatSetSyntax_RejectsGarbage(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate asd")
	if err == nil {
		t.Fatal("expected error for flat-set transmit-rate asd, got nil")
	}
	if !strings.Contains(err.Error(), "transmit-rate") {
		t.Fatalf("error should reference transmit-rate: %v", err)
	}
}

func TestSchemaValidate_FlatSetSyntax_AcceptsValid(t *testing.T) {
	cmds := []string{
		"set class-of-service schedulers be transmit-rate 1g",
		"set class-of-service schedulers be priority strict-high",
		"set class-of-service schedulers be buffer-size 16m",
	}
	if err := flatSchemaCheck(t, cmds...); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestSchemaValidate_AcceptedSchedulerValuesCompileAsValidated(t *testing.T) {
	tree := &config.ConfigTree{}
	cmds := []string{
		"set class-of-service schedulers be transmit-rate 8",
		"set class-of-service schedulers be transmit-rate exact",
		"set class-of-service schedulers be buffer-size 16m",
	}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	if err := cmdtree.SchemaValidate(tree, nil); err != nil {
		t.Fatalf("schema validate: %v", err)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	sched := cfg.ClassOfService.Schedulers["be"]
	if sched == nil {
		t.Fatal("expected be scheduler")
	}
	if got := sched.TransmitRateBytes; got != 1 {
		t.Fatalf("transmit-rate bytes/sec = %d, want 1", got)
	}
	if !sched.TransmitRateExact {
		t.Fatal("expected transmit-rate exact")
	}
	if got := sched.BufferSizeBytes; got != 16000000 {
		t.Fatalf("buffer-size bytes = %d, want 16000000", got)
	}
}

func TestSchemaValidate_PercentBufferSizeCompilesAsPercentNotZeroBytes(t *testing.T) {
	tree := &config.ConfigTree{}
	cmds := []string{
		"set class-of-service schedulers be transmit-rate 8",
		"set class-of-service schedulers be buffer-size 10%",
	}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	if err := cmdtree.SchemaValidate(tree, nil); err != nil {
		t.Fatalf("schema validate: %v", err)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	sched := cfg.ClassOfService.Schedulers["be"]
	if sched == nil {
		t.Fatal("expected be scheduler")
	}
	if got := sched.BufferSizePercent; got != 10 {
		t.Fatalf("buffer-size percent = %v, want 10", got)
	}
	if got := sched.BufferSizeBytes; got != 0 {
		t.Fatalf("buffer-size bytes = %d, want 0 for percent form", got)
	}
}

// Negative: nodes outside the schedulers subtree are NOT validated.
// This guards the "only schedulers in this PR" scope contract.
func TestSchemaValidate_OutsideSchedulersIgnored(t *testing.T) {
	// `buffer-size purple` under a different parent should not error
	// at SchemaValidate (no typed-leaf metadata for it elsewhere).
	if err := schemaCheck(t, `class-of-service {
    interfaces {
        ge-0/0/1 {
            unit 0 {
                shaping-rate 10g {
                    burst-size purple-not-validated;
                }
                scheduler-map edge-map;
            }
        }
    }
}`); err != nil {
		t.Fatalf("expected schedulers-only scope; got error on interfaces subtree: %v", err)
	}
}

// Validator unit tests — keep these close to the validator code so a
// failed test points at the validator rather than the AST walker.

func TestValidateRate(t *testing.T) {
	good := []string{"100", "100k", "10m", "1g", "10g", "8k"}
	for _, g := range good {
		if err := config.ValidateRate(g, nil); err != nil {
			t.Errorf("ValidateRate(%q): unexpected error %v", g, err)
		}
	}
	bad := []string{"", "1", "7", "asd", "-1", "1x", "1.0z"}
	for _, b := range bad {
		if err := config.ValidateRate(b, nil); err == nil {
			t.Errorf("ValidateRate(%q): expected error", b)
		}
	}
}

func TestValidateByteSize(t *testing.T) {
	good := []string{"16m", "256k", "1g"}
	for _, g := range good {
		if err := config.ValidateByteSize(g, nil); err != nil {
			t.Errorf("ValidateByteSize(%q): unexpected error %v", g, err)
		}
	}
	bad := []string{"", "0", "50", "100", "150", "purple", "-5", "1.5"}
	for _, b := range bad {
		if err := config.ValidateByteSize(b, nil); err == nil {
			t.Errorf("ValidateByteSize(%q): expected error", b)
		}
	}
}

func TestValidateByteSizeOrPercent(t *testing.T) {
	good := []string{"16m", "256k", "1g", "10%", "12.5%"}
	for _, g := range good {
		if err := config.ValidateByteSizeOrPercent(g, nil); err != nil {
			t.Errorf("ValidateByteSizeOrPercent(%q): unexpected error %v", g, err)
		}
	}
	bad := []string{"", "0", "50", "100", "purple", "-5", "1.5", "0%", "-1%", "101%", "NaN%"}
	for _, b := range bad {
		if err := config.ValidateByteSizeOrPercent(b, nil); err == nil {
			t.Errorf("ValidateByteSizeOrPercent(%q): expected error", b)
		}
	}
}

func TestValidateEnum(t *testing.T) {
	v := config.ValidateEnum([]string{"low", "high"})
	if err := v("low", nil); err != nil {
		t.Errorf("ValidateEnum low: unexpected error %v", err)
	}
	if err := v("LOW", nil); err == nil {
		t.Errorf("ValidateEnum LOW: expected case-sensitive error")
	}
	if err := v("foo", nil); err == nil {
		t.Errorf("ValidateEnum foo: expected error")
	}
}

func TestValidateInteger(t *testing.T) {
	v := config.ValidateInteger(0, 100)
	if err := v("50", nil); err != nil {
		t.Errorf("ValidateInteger 50: unexpected error %v", err)
	}
	if err := v("200", nil); err == nil {
		t.Errorf("ValidateInteger 200: expected out-of-range error")
	}
	if err := v("abc", nil); err == nil {
		t.Errorf("ValidateInteger abc: expected non-integer error")
	}
}

func TestValidatePercent(t *testing.T) {
	v := config.ValidatePercent(0, 100)
	if err := v("50", nil); err != nil {
		t.Errorf("ValidatePercent 50: unexpected error %v", err)
	}
	if err := v("0.5", nil); err != nil {
		t.Errorf("ValidatePercent 0.5: unexpected error %v", err)
	}
	if err := v("150", nil); err == nil {
		t.Errorf("ValidatePercent 150: expected out-of-range error")
	}
}
