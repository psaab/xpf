package config

import (
	"strings"
	"testing"
)

func TestCoSFairnessRSSExpectationQueueKeyIsTyped11796(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set class-of-service fairness rss-expectation interface ge-0/0/2 queue nope balanced",
		"set system dataplane-type userspace",
	)
	err := SchemaValidate(tree, nil)
	if err == nil {
		t.Fatal("SchemaValidate accepted a non-numeric RSS expectation queue key")
	}
	if !IsTypedLeafSchemaError(err) {
		t.Fatalf("SchemaValidate error = %v, want typed-leaf error for tolerant-path warning", err)
	}
}

func TestCoSFairnessRSSExpectationBadQueueWarnsAndDrops11796(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set class-of-service fairness rss-expectation interface ge-0/0/2 queue nope balanced",
		"set class-of-service fairness rss-expectation interface ge-0/0/2 queue 7 balanced",
		"set system dataplane-type userspace",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict compile accepted a non-numeric RSS expectation queue")
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected a malformed RSS expectation queue: %v", err)
	}
	if !warningContains11796(cfg.Warnings, `queue "nope"`, "rss-expectation") {
		t.Fatalf("lenient compile did not warn about the malformed RSS queue: %v", cfg.Warnings)
	}
	got := cfg.ClassOfService.FairnessExpectations
	if len(got) != 1 || got[0].QueueID != 7 || got[0].RSSExpectation != "balanced" {
		t.Fatalf("lenient compile expectations = %#v, want only the valid queue 7 expectation", got)
	}
}

func TestCoSFairnessRSSExpectationInvalidValueWarnsAndDrops11796(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set class-of-service fairness rss-expectation interface ge-0/0/2 queue 4 max-worker-flow-share not-a-share",
		"set class-of-service fairness rss-expectation interface ge-0/0/2 queue 7 balanced",
		"set system dataplane-type userspace",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict compile accepted an invalid RSS expectation value")
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected an invalid RSS expectation value: %v", err)
	}
	if !warningContains11796(cfg.Warnings, "max-worker-flow-share", "rss-expectation") {
		t.Fatalf("lenient compile did not warn about the invalid RSS expectation value: %v", cfg.Warnings)
	}
	got := cfg.ClassOfService.FairnessExpectations
	if len(got) != 1 || got[0].QueueID != 7 || got[0].RSSExpectation != "balanced" {
		t.Fatalf("lenient compile expectations = %#v, want only the valid queue 7 expectation", got)
	}
}

func TestCoSFairnessRSSExpectationConflictingDuplicateWarns11796(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set class-of-service fairness rss-expectation interface ge-0/0/2 queue 4 balanced",
		"set class-of-service fairness rss-expectation interface ge-0/0/2 queue 4 cstruct-max 0.25",
		"set class-of-service fairness rss-expectation interface ge-0/0/2 queue 7 balanced",
		"set system dataplane-type userspace",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict compile accepted conflicting RSS expectations for one queue")
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected conflicting RSS expectations: %v", err)
	}
	if !warningContains11796(cfg.Warnings, "multiple expectations configured", "rss-expectation") {
		t.Fatalf("lenient compile did not warn about the conflicting RSS expectation: %v", cfg.Warnings)
	}
	got := cfg.ClassOfService.FairnessExpectations
	if len(got) != 1 || got[0].QueueID != 7 || got[0].RSSExpectation != "balanced" {
		t.Fatalf("lenient compile expectations = %#v, want only the valid queue 7 expectation", got)
	}
}

func TestCoSFairnessRSSExpectationDuplicateLeafWarnsAndDrops11796(t *testing.T) {
	parser := NewParser(`
class-of-service {
    fairness {
        rss-expectation {
            interface ge-0/0/2 {
                queue 4 {
                    balanced;
                    balanced;
                }
                queue 7 { balanced; }
            }
        }
    }
}
system { dataplane-type userspace; }
`)
	tree, parseErrs := parser.Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse errors: %v", parseErrs)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict compile accepted duplicate hierarchical RSS expectation leaves")
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected duplicate hierarchical RSS expectation leaves: %v", err)
	}
	if !warningContains11796(cfg.Warnings, "duplicate balanced expectation leaf", "rss-expectation") {
		t.Fatalf("lenient compile did not warn about duplicate RSS expectation leaves: %v", cfg.Warnings)
	}
	got := cfg.ClassOfService.FairnessExpectations
	if len(got) != 1 || got[0].QueueID != 7 || got[0].RSSExpectation != "balanced" {
		t.Fatalf("lenient compile expectations = %#v, want only the valid queue 7 expectation", got)
	}
}

// TestCoSFairnessRSSExpectationFlatRunCannotHideAlias11796 keeps a same-line
// SetPath chain from accepting only its first RSS expectation.
func TestCoSFairnessRSSExpectationFlatRunCannotHideAlias11796(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set class-of-service fairness rss-expectation interface ge-0/0/2 queue 4 active-workers 2 at-least-active-workers 3",
		"set system dataplane-type userspace",
	)
	if _, err := CompileConfig(tree); err == nil ||
		!strings.Contains(err.Error(), "duplicate at-least-active-workers expectation") {
		t.Fatalf("strict compile error = %v, want duplicate active-workers alias diagnostic", err)
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected duplicate RSS aliases: %v", err)
	}
	if !warningContains11796(cfg.Warnings, "duplicate at-least-active-workers expectation") {
		t.Fatalf("lenient compile did not warn about the duplicate RSS aliases: %v", cfg.Warnings)
	}
	if got := len(cfg.ClassOfService.FairnessExpectations); got != 0 {
		t.Fatalf("lenient compile retained %d row(s) after a duplicate alias, want the malformed row omitted", got)
	}
}

// TestCoSFairnessRSSExpectationCompactFlagsNormalize11796 ensures the compact
// flag spellings preserve the same any/balanced rows as their block forms.
func TestCoSFairnessRSSExpectationCompactFlagsNormalize11796(t *testing.T) {
	fixtures := map[string]string{
		"block": `class-of-service { fairness { rss-expectation { interface ge-0/0/2 {
			queue 4 { any; }
			queue 5 { balanced; }
		} } } }`,
		"compact": `class-of-service { fairness { rss-expectation { interface ge-0/0/2 {
			queue 4 any;
			queue 5 balanced;
		} } } }`,
	}
	for name, text := range fixtures {
		t.Run(name, func(t *testing.T) {
			tree, parseErrs := NewParser(text).Parse()
			if len(parseErrs) != 0 {
				t.Fatalf("parse errors: %v", parseErrs)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("strict compile rejected %s RSS flags: %v", name, err)
			}
			got := cfg.ClassOfService.FairnessExpectations
			if len(got) != 2 {
				t.Fatalf("%s RSS rows = %#v, want queue 4 any and queue 5 balanced", name, got)
			}
			gotByQueue := map[uint8]string{}
			for _, row := range got {
				gotByQueue[row.QueueID] = row.RSSExpectation
			}
			if len(gotByQueue) != 2 || gotByQueue[4] != "any" || gotByQueue[5] != "balanced" {
				t.Fatalf("%s RSS rows = %#v, want queue 4 any and queue 5 balanced", name, got)
			}
		})
	}
}

func warningContains11796(warnings []string, parts ...string) bool {
	for _, warning := range warnings {
		if !strings.Contains(warning, "rss-expectation") {
			continue
		}
		matches := true
		for _, part := range parts {
			if !strings.Contains(warning, part) {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}
