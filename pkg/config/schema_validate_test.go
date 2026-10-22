package config_test

// Tests for the #1319 typed-leaf schema gate. SchemaValidate (and the
// generic walker it drives) lives in pkg/config and validates the AST
// against setSchema; we exercise it end-to-end through configstore.Commit
// / CommitCheck in the configstore tests, and exercise the validators +
// AST walker here against parsed AST trees.

import (
	"strings"
	"testing"

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
	return config.SchemaValidate(tree)
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
	return config.SchemaValidate(tree)
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
	if err := config.SchemaValidate(tree); err != nil {
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
	if err := config.SchemaValidate(tree); err != nil {
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

// TestSchemaValidate_AcceptsLegacyDPDKSubStanza is migrated from the
// retired pkg/cmdtree schema_validate_test.go (#1528 fixture-strength
// gate). After #1319 PR 1 the generic walker fans out across ALL
// top-level subtrees (the class-of-service-only early-return is gone), so
// this test now guards a sharper invariant: walking the whole AST must
// still be a no-op for untyped subtrees like the orphaned legacy
// `system dataplane ...` sub-stanzas that survive the
// rewriteRetiredDataplaneType bridge. The cos block forces typed-leaf
// validation to fire; the untyped DPDK leaves must be ignored, not
// rejected (rejecting them would preempt the operator-facing
// ErrDPDKDataplaneRetired path and break stored-config rolling upgrade).
func TestSchemaValidate_AcceptsLegacyDPDKSubStanza(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, line := range []string{
		// class-of-service schedulers block — triggers typed validation.
		"set class-of-service schedulers be-sched transmit-rate 1g",
		"set class-of-service schedulers be-sched priority low",
		"set class-of-service schedulers be-sched buffer-size 10%",
		// Legacy DPDK shape — untyped, must NOT be rejected.
		"set system dataplane-type dpdk",
		"set system dataplane cores 2-5",
		"set system dataplane memory 2048",
		"set system dataplane socket-mem \"1024,1024\"",
		"set system dataplane rx-mode adaptive",
		"set system dataplane rx-mode idle-threshold 256",
		"set system dataplane rx-mode resume-threshold 32",
		"set system dataplane rx-mode sleep-timeout 100",
		"set system dataplane ports 0000:03:00.0 interface wan0",
		"set system dataplane ports 0000:03:00.0 rx-mode polling",
		"set system dataplane ports 0000:03:00.0 cores 2-3",
		"set system dataplane ports 0000:06:00.0 interface trust0",
	} {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	if tree.FindChild("class-of-service") == nil {
		t.Fatal("fixture invalid: class-of-service subtree missing")
	}
	if err := config.SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected legacy DPDK sub-stanza alongside valid cos block: %v", err)
	}
}

// Negative: untyped leaves outside the schedulers subtree are NOT
// validated even though the walker now descends all subtrees. This guards
// the "opt-in per leaf" scope contract.
func TestSchemaValidate_OutsideSchedulersIgnored(t *testing.T) {
	// A still-untyped CoS reference leaf (the dscp classifier NAME bound
	// to an interface unit is resolved at compile-warn, not schema-typed)
	// should not error at SchemaValidate. shaping-rate/burst-size — the
	// prior example here — are now typed by #4217, so they no longer
	// illustrate an untyped leaf.
	if err := schemaCheck(t, `class-of-service {
    interfaces {
        ge-0/0/1 {
            unit 0 {
                classifiers {
                    dscp purple-not-validated;
                }
                scheduler-map edge-map;
            }
        }
    }
}`); err != nil {
		t.Fatalf("expected schedulers-only scope; got error on interfaces subtree: %v", err)
	}
}

// Compiler-faithful contract (resolved across Codex review rounds 1-7).
//
// The schedulers compiler (compileClassOfService + namedInstances) reads
// scheduler leaves ONLY from each instance node's CHILDREN; tokens packed
// into an instance node's own Keys beyond the scheduler name are NOT
// compiled. The typed-leaf gate mirrors this exactly: it validates the
// child leaves where the compiler reads them, and does not reject malformed
// packed tails the compiler silently discards (rejecting those would be a
// behaviour change beyond #1319's compiled-leaf-only scope).
//
// The flat-set `set class-of-service schedulers <name> <leaf> <value>`
// shape — the actual symptom-2 path — lands the typed leaf as a CHILD of
// `schedulers <name>`, so it is compiled and IS validated.

// TestSchemaValidate_ChildLeafGarbageRejected covers the compiler-reachable
// shapes: a typed leaf carried as a CHILD of the scheduler instance (the
// flat-set path and the canonical hierarchical block). Garbage values are
// rejected; valid values pass.
func TestSchemaValidate_ChildLeafGarbageRejected(t *testing.T) {
	// Canonical hierarchical block: the typed leaf is a genuine CHILD of the
	// scheduler instance, which the compiler reads — garbage rejects.
	reject := []string{
		`class-of-service { schedulers { be { transmit-rate asd; } } }`,
		`class-of-service { schedulers { be { priority foo; } } }`,
		`class-of-service { schedulers { be { buffer-size purple; } } }`,
	}
	for _, in := range reject {
		if err := schemaCheck(t, in); err == nil {
			t.Fatalf("expected rejection for child-leaf garbage %q, got nil", in)
		}
	}
	// Packed single-node shorthand (`schedulers be transmit-rate asd` as ONE
	// node with no children). This block asserted the OPPOSITE until issue
	// 8867, on the premise that "the compiler does NOT compile the packed tail
	// -- it names the scheduler `be` and discards `transmit-rate asd`", which
	// made rejecting it out of #1319 scope.
	//
	// That premise was true when it was written and is now false. Admitting
	// `schedulers transmit-rate` to compactNormalizeInScope made the compiler
	// fold the packed tail, and nothing re-checked this cell. Measured:
	//
	//	class-of-service { schedulers be transmit-rate 1g; }        rateBytes=125000000
	//	class-of-service { schedulers { be { transmit-rate 1g; } } } rateBytes=125000000
	//
	// The value is compiled and reaches the dataplane. So the packed spelling
	// IS compiler-reachable and garbage in it must be rejected, exactly as the
	// braced spelling's garbage is. The cell passed only because the validator
	// could not see the packed tail either -- two gaps agreeing, which is what
	// made the stale premise invisible.
	for _, in := range []string{
		`class-of-service { schedulers be transmit-rate asd; }`,
		`class-of-service { schedulers be priority foo; }`,
	} {
		if err := schemaCheck(t, in); err == nil {
			t.Fatalf("packed shorthand %q compiles its value, so garbage must be rejected; got nil", in)
		}
	}
	accept := []string{
		`class-of-service { schedulers be transmit-rate 1g; }`,
		`class-of-service { schedulers { be { transmit-rate 1g { exact; } } } }`,
		`class-of-service { schedulers { be buffer-size 16m; } }`,
		`class-of-service { schedulers { be priority strict-high; } }`,
	}
	for _, in := range accept {
		if err := schemaCheck(t, in); err != nil {
			t.Fatalf("expected child-leaf valid %q to pass, got %v", in, err)
		}
	}
}

// TestSchemaValidate_FlatSetSymptom2 is the actual #1319 symptom-2 path:
// `set class-of-service schedulers be <leaf> <garbage>` lands the leaf as a
// child of `schedulers be` and is compiled — so commit-check must reject the
// garbage. These are the cases an operator actually types.
func TestSchemaValidate_FlatSetSymptom2(t *testing.T) {
	reject := [][]string{
		{"set class-of-service schedulers be transmit-rate asd"},
		{"set class-of-service schedulers be priority foo"},
		{"set class-of-service schedulers be buffer-size purple"},
		{"set class-of-service schedulers be transmit-rate 1g typo"},
		{"set class-of-service schedulers be transmit-rate exact"}, // exact, no rate
	}
	for _, cmds := range reject {
		if err := flatSchemaCheck(t, cmds...); err == nil {
			t.Fatalf("expected rejection for flat-set %v, got nil", cmds)
		}
	}
	// Valid scheduler, including the split-modifier form (two child leaves).
	if err := flatSchemaCheck(t,
		"set class-of-service schedulers be transmit-rate 1g",
		"set class-of-service schedulers be transmit-rate exact",
		"set class-of-service schedulers be priority high",
		"set class-of-service schedulers be buffer-size 16m",
	); err != nil {
		t.Fatalf("expected valid flat-set scheduler to pass, got %v", err)
	}
}

// TestSchemaValidate_ModifierTrailingGarbage: a known modifier child must
// not swallow trailing garbage. `transmit-rate 1g { exact bogus; }`
// (hierarchical) and the flat `exact -> bogus` nesting both carry an extra
// `bogus` past the known `exact` modifier and must be rejected.
func TestSchemaValidate_ModifierTrailingGarbage(t *testing.T) {
	if err := schemaCheck(t, `class-of-service { schedulers { be { transmit-rate 1g { exact bogus; } } } }`); err == nil {
		t.Fatal("expected rejection for `exact bogus` trailing garbage, got nil")
	}
	if err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate 1g exact bogus"); err == nil {
		t.Fatal("expected rejection for flat `transmit-rate 1g exact bogus`, got nil")
	}
	if err := schemaCheck(t, `class-of-service { schedulers { be { transmit-rate 1g { exact; } } } }`); err != nil {
		t.Fatalf("expected clean `exact` modifier to pass, got %v", err)
	}
}

// TestSchemaValidate_ExtraTokenStillValidatesChildLeaves: an unknown extra
// token in a container/instance identity must not hide CHILD leaves from
// validation. The compiler still names the scheduler and walks its children,
// so child-leaf garbage under an extra token must still be rejected. The
// extra token itself is an opt-in skip (Codex r5/r6).
func TestSchemaValidate_ExtraTokenStillValidatesChildLeaves(t *testing.T) {
	for _, in := range []string{
		`class-of-service { schedulers { be extra { transmit-rate asd; } } }`,
		`class-of-service { schedulers be extra { transmit-rate asd; } }`,
	} {
		if err := schemaCheck(t, in); err == nil {
			t.Fatalf("expected rejection for extra-token nested child garbage %q, got nil", in)
		}
	}
	if err := schemaCheck(t, `class-of-service { schedulers { be extra { transmit-rate 1g; } } }`); err != nil {
		t.Fatalf("expected extra-token with valid child leaf to pass, got %v", err)
	}
}

// TestSchemaValidate_PresenceTokenDoesNotHideSiblingLeaves reproduces
// Codex r7: a KNOWN presence-only token in the instance identity
// (`schedulers be surplus-sharing { priority foo; }`) must not cause the
// child `priority foo` to be validated under the presence token's (empty)
// schema instead of the scheduler schema. The compiler names the scheduler
// `be`, ignores the `surplus-sharing` Keys token, and applies `priority
// foo` — so the gate must reject the garbage priority.
func TestSchemaValidate_PresenceTokenDoesNotHideSiblingLeaves(t *testing.T) {
	for _, in := range []string{
		`class-of-service { schedulers { be surplus-sharing { priority foo; } } }`,
		`class-of-service { schedulers { be equal-flow-enforcement { transmit-rate asd; } } }`,
	} {
		if err := schemaCheck(t, in); err == nil {
			t.Fatalf("expected rejection for presence-token-hidden garbage %q, got nil", in)
		}
	}
	if err := schemaCheck(t, `class-of-service { schedulers { be surplus-sharing { priority high; } } }`); err != nil {
		t.Fatalf("expected presence-token with valid sibling leaf to pass, got %v", err)
	}
}

// TestSetPathGrouping_Golden pins the flat-set grouping produced by
// SetPath over setSchema. #1319 PR 1 adds typed-leaf FIELDS to schemaNode
// (valueType/valueDesc/valueExamples/validator) but MUST NOT add or alter
// any `children` map — SetPath's replace-vs-container decision keys on
// children==nil (ast_edit.go:196), so flipping a leaf to a container is a
// grouping regression. This golden re-serializes a representative config
// (including the schedulers typed leaves and the `destination-port <lo> to
// <hi>` value-tail/range shape) and asserts the round-trip is byte-stable.
// If a future edit adds children to a typed leaf, the schedulers grouping
// changes here and this test fires.
//
// Codex minor #2: to actually exercise the `children == nil` REPLACE path
// (ast_edit.go:196 — a single-value leaf with no children is replaced, not
// appended), `priority` is set TWICE with different values. With
// children==nil the second set replaces the first, so only the latter value
// survives in the golden. If `priority` ever gained a children map, SetPath
// would treat it as a named container and APPEND a duplicate sibling instead
// of replacing — producing two `priority` lines and failing this golden.
func TestSetPathGrouping_Golden(t *testing.T) {
	tree := &config.ConfigTree{}
	cmds := []string{
		"set class-of-service schedulers be transmit-rate 1g",
		"set class-of-service schedulers be transmit-rate exact",
		"set class-of-service schedulers be priority strict-high",
		"set class-of-service schedulers be priority medium-high",
		"set class-of-service schedulers be buffer-size 16m",
		"set firewall family inet filter f1 term t1 from destination-port 20000 to 20003",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
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
	const golden = `set class-of-service schedulers be transmit-rate 1g
set class-of-service schedulers be transmit-rate exact
set class-of-service schedulers be priority medium-high
set class-of-service schedulers be buffer-size 16m
set firewall family inet filter f1 term t1 from destination-port 20000 to 20003
set security policies from-zone trust to-zone untrust policy p1 match source-address any
set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
`
	if got := tree.FormatSet(); got != golden {
		t.Fatalf("SetPath grouping changed (typed-leaf fields must not alter grouping):\n--- got ---\n%s\n--- want ---\n%s", got, golden)
	}
}

// Validator unit tests — keep these close to the validator code so a
// failed test points at the validator rather than the AST walker.

func TestValidateRate(t *testing.T) {
	good := []string{"100", "100k", "10m", "1g", "10g", "8k"}
	for _, g := range good {
		if err := config.ValidateRate(g); err != nil {
			t.Errorf("ValidateRate(%q): unexpected error %v", g, err)
		}
	}
	bad := []string{"", "1", "7", "asd", "-1", "1x", "1.0z"}
	for _, b := range bad {
		if err := config.ValidateRate(b); err == nil {
			t.Errorf("ValidateRate(%q): expected error", b)
		}
	}
}

func TestValidateByteSize(t *testing.T) {
	good := []string{"16m", "256k", "1g"}
	for _, g := range good {
		if err := config.ValidateByteSize(g); err != nil {
			t.Errorf("ValidateByteSize(%q): unexpected error %v", g, err)
		}
	}
	bad := []string{"", "0", "50", "100", "150", "purple", "-5", "1.5"}
	for _, b := range bad {
		if err := config.ValidateByteSize(b); err == nil {
			t.Errorf("ValidateByteSize(%q): expected error", b)
		}
	}
}

func TestValidateByteSizeOrPercent(t *testing.T) {
	good := []string{"16m", "256k", "1g", "10%", "12.5%"}
	for _, g := range good {
		if err := config.ValidateByteSizeOrPercent(g); err != nil {
			t.Errorf("ValidateByteSizeOrPercent(%q): unexpected error %v", g, err)
		}
	}
	bad := []string{"", "0", "50", "100", "purple", "-5", "1.5", "0%", "-1%", "101%", "NaN%"}
	for _, b := range bad {
		if err := config.ValidateByteSizeOrPercent(b); err == nil {
			t.Errorf("ValidateByteSizeOrPercent(%q): expected error", b)
		}
	}
}

func TestValidateEnum(t *testing.T) {
	v := config.ValidateEnum([]string{"low", "high"})
	if err := v("low"); err != nil {
		t.Errorf("ValidateEnum low: unexpected error %v", err)
	}
	if err := v("LOW"); err == nil {
		t.Errorf("ValidateEnum LOW: expected case-sensitive error")
	}
	if err := v("foo"); err == nil {
		t.Errorf("ValidateEnum foo: expected error")
	}
}

func TestValidateInteger(t *testing.T) {
	v := config.ValidateInteger(0, 100)
	if err := v("50"); err != nil {
		t.Errorf("ValidateInteger 50: unexpected error %v", err)
	}
	if err := v("200"); err == nil {
		t.Errorf("ValidateInteger 200: expected out-of-range error")
	}
	if err := v("abc"); err == nil {
		t.Errorf("ValidateInteger abc: expected non-integer error")
	}
}

func TestValidatePercent(t *testing.T) {
	v := config.ValidatePercent(0, 100)
	if err := v("50"); err != nil {
		t.Errorf("ValidatePercent 50: unexpected error %v", err)
	}
	if err := v("0.5"); err != nil {
		t.Errorf("ValidatePercent 0.5: unexpected error %v", err)
	}
	if err := v("150"); err == nil {
		t.Errorf("ValidatePercent 150: expected out-of-range error")
	}
	// NaN/Inf bypass the `<`/`>` range check (both comparisons are false
	// for NaN) and reach the userspace snapshot where json.Marshal fails
	// on non-finite floats (#4877). Reject them at commit-check.
	for _, bad := range []string{"NaN", "nan", "+Inf", "-Inf", "Inf", "Infinity"} {
		if err := v(bad); err == nil {
			t.Errorf("ValidatePercent %q: expected non-finite rejection", bad)
		}
	}
	// A NaN/Inf guard must not reject an in-range finite value.
	vf := config.ValidatePercent(0, 1)
	if err := vf("0.5"); err != nil {
		t.Errorf("ValidatePercent(0,1) 0.5: unexpected error %v", err)
	}
}
