package docsref

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validateMakeAggregate checks the observable contract of the unprivileged
// aggregate without pinning incidental recipe spelling. In particular, the
// test target must not become a prerequisite list again: make stops before
// the second prerequisite when the first one fails.
func validateMakeAggregate(mk string) error {
	lines := strings.Split(mk, "\n")
	target := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "test:") {
			target = i
			break
		}
	}
	if target < 0 {
		return fmt.Errorf("no line-anchored test: target found")
	}
	if strings.TrimSpace(lines[target]) != "test:" {
		return fmt.Errorf("test target has prerequisites: %q", lines[target])
	}

	var recipe []string
	started := false
	for _, line := range lines[target+1:] {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(line, "\t") {
			if started {
				break
			}
			return fmt.Errorf("non-recipe line inside test target: %q", line)
		}
		started = true
		recipe = append(recipe, trimmed)
	}
	if len(recipe) == 0 {
		return fmt.Errorf("test target has no recipe")
	}

	goLeg, rustLeg := -1, -1
	statusInit := false
	for i, line := range recipe {
		if strings.HasPrefix(line, "@status=0;") || strings.HasPrefix(line, "status=0;") {
			statusInit = true
		}
		if strings.HasPrefix(line, "$(MAKE) test-go ") {
			if !strings.Contains(line, "||") {
				return fmt.Errorf("Go leg does not capture failure: %q", line)
			}
			if goLeg >= 0 {
				return fmt.Errorf("duplicate Go leg")
			}
			goLeg = i
		}
		if strings.HasPrefix(line, "$(MAKE) test-rust ") {
			if !strings.Contains(line, "||") {
				return fmt.Errorf("Rust leg does not capture failure: %q", line)
			}
			if rustLeg >= 0 {
				return fmt.Errorf("duplicate Rust leg")
			}
			rustLeg = i
		}
	}
	if !statusInit {
		return fmt.Errorf("aggregate does not initialize a failure status")
	}
	if goLeg < 0 || rustLeg < 0 {
		return fmt.Errorf("aggregate legs missing: test-go=%d test-rust=%d", goLeg, rustLeg)
	}
	if goLeg >= rustLeg {
		if goLeg == rustLeg {
			return fmt.Errorf("Go and Rust legs must occupy distinct recipe lines")
		}
		return fmt.Errorf("Go leg must run before Rust leg")
	}
	exit := -1
	for i, line := range recipe {
		if strings.Contains(line, "exit $$status") {
			exit = i
			break
		}
	}
	if exit <= rustLeg {
		return fmt.Errorf("trailing exit $$status is missing or precedes Rust leg")
	}
	return nil
}

func TestMakefileSerialAggregate10496(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	if err := validateMakeAggregate(string(b)); err != nil {
		t.Fatalf("Makefile aggregate contract: %v", err)
	}

	// A prerequisite-form aggregate is the exact regression: it can mention
	// both legs and still silently skip Rust after a red Go leg.
	brokenPrerequisites := "test: test-go test-rust\n" +
		"\t@status=0; $(MAKE) test-go || status=$$?; " +
		"$(MAKE) test-rust || status=$$?; exit $$status\n"
	if err := validateMakeAggregate(brokenPrerequisites); err == nil {
		t.Fatal("prerequisite-form aggregate passed the serial contract")
	}

	// An echo-only recipe must not satisfy command-token checks: prose that
	// prints the right words never executes either leg.
	echoOnly := "test:\n" +
		"\t@echo \"$(MAKE) test-go || $(MAKE) test-rust || exit $$status\"\n"
	if err := validateMakeAggregate(echoOnly); err == nil {
		t.Fatal("echo-only recipe passed the aggregate contract")
	}

	// A missing target is a zero-denominator control: a canary that finds no
	// target must fail rather than report a vacuous pass.
	if err := validateMakeAggregate("test-go:\n\t@true\n"); err == nil {
		t.Fatal("Makefile without a test target passed the aggregate contract")
	}
}
