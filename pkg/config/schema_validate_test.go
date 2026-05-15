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

// schemaCheck parses a Junos hierarchical config snippet, expands
// groups, and runs SchemaValidate against the resulting AST.
func schemaCheck(t *testing.T, input string) error {
	t.Helper()
	p := config.NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
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

func TestSchemaValidate_BufferSize_AcceptsPercent(t *testing.T) {
	if err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            buffer-size 50;
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

func TestSchemaValidate_BufferSize_RejectsPercentOver100(t *testing.T) {
	err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            buffer-size 150;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for buffer-size 150 (out of 0..100), got nil")
	}
}

func TestSchemaValidate_ShapingRate_RejectsGarbage(t *testing.T) {
	err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            shaping-rate not-a-rate;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for shaping-rate not-a-rate, got nil")
	}
}

// FlatSetSyntax exercises the alternate AST shape that ParseSetCommand
// + tree.SetPath produces: Keys=["schedulers","be","transmit-rate","1g"]
// (when input is `set class-of-service schedulers be transmit-rate 1g`).
func TestSchemaValidate_FlatSetSyntax_RejectsGarbage(t *testing.T) {
	tree := &config.ConfigTree{}
	cmds := []string{
		"set class-of-service schedulers be transmit-rate asd",
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
	err := cmdtree.SchemaValidate(tree, nil)
	if err == nil {
		t.Fatal("expected error for flat-set transmit-rate asd, got nil")
	}
	if !strings.Contains(err.Error(), "transmit-rate") {
		t.Fatalf("error should reference transmit-rate: %v", err)
	}
}

func TestSchemaValidate_FlatSetSyntax_AcceptsValid(t *testing.T) {
	tree := &config.ConfigTree{}
	cmds := []string{
		"set class-of-service schedulers be transmit-rate 1g",
		"set class-of-service schedulers be priority strict-high",
		"set class-of-service schedulers be buffer-size 16m",
		"set class-of-service schedulers ef shaping-rate 5g",
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
		t.Fatalf("expected no error, got %v", err)
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
	bad := []string{"", "asd", "-1", "1x", "1.0z"}
	for _, b := range bad {
		if err := config.ValidateRate(b, nil); err == nil {
			t.Errorf("ValidateRate(%q): expected error", b)
		}
	}
}

func TestValidateByteSizeOrPercent(t *testing.T) {
	good := []string{"0", "50", "100", "16m", "256k", "1g"}
	for _, g := range good {
		if err := config.ValidateByteSizeOrPercent(g, nil); err != nil {
			t.Errorf("ValidateByteSizeOrPercent(%q): unexpected error %v", g, err)
		}
	}
	bad := []string{"", "purple", "150", "-5", "1.5"}
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
