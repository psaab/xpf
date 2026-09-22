package docsref

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validateMakeAggregate pins the unprivileged aggregate's load-bearing shape:
// a line-anchored test target with no prerequisites, a failure-status
// initializer ordered before both legs, two distinct TAB-indented recipe
// lines running "$(MAKE) test-go || status=$$?" / the test-rust analog with
// contiguous capture, a trailing "exit $$status" command, and the NOT EXAMINED
// announcement between the Rust leg and the exit. In particular, the test
// target must not become a prerequisite list again: make stops before the
// second prerequisite when the first one fails.
func capturedLeg(line, target string) bool {
	suffix := target + " || status=$$?"
	return line == suffix || line == suffix+"; \\"
}

func initializedStatus(line string) bool {
	return line == "@status=0; \\" || line == "status=0; \\"
}

func announcesNotExamined(line string) bool {
	return (strings.HasPrefix(line, "echo ") || strings.HasPrefix(line, "printf ")) &&
		strings.Contains(line, "NOT EXAMINED")
}

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
	statusInit := -1
	for i, line := range recipe {
		if initializedStatus(line) {
			if statusInit >= 0 {
				return fmt.Errorf("duplicate status initialization")
			}
			statusInit = i
		}
		if capturedLeg(line, "$(MAKE) test-go") {
			if goLeg >= 0 {
				return fmt.Errorf("duplicate Go leg")
			}
			goLeg = i
		}
		if capturedLeg(line, "$(MAKE) test-rust") {
			if rustLeg >= 0 {
				return fmt.Errorf("duplicate Rust leg")
			}
			rustLeg = i
		}
	}
	if goLeg < 0 || rustLeg < 0 {
		return fmt.Errorf("aggregate legs missing or lack contiguous status capture: "+
			"test-go=%d test-rust=%d", goLeg, rustLeg)
	}
	if statusInit < 0 {
		return fmt.Errorf("aggregate does not initialize a failure status")
	}
	if statusInit > goLeg {
		return fmt.Errorf("failure status initializes after the Go leg")
	}
	if goLeg >= rustLeg {
		return fmt.Errorf("Go leg must run before Rust leg")
	}
	exit := -1
	for i, line := range recipe {
		if line == "exit $$status" {
			if exit >= 0 {
				return fmt.Errorf("duplicate trailing exit $$status")
			}
			exit = i
		}
	}
	if exit <= rustLeg {
		return fmt.Errorf("trailing exit $$status is missing or precedes Rust leg")
	}
	announced := false
	for i, line := range recipe {
		if i > rustLeg && i < exit && announcesNotExamined(line) {
			announced = true
			break
		}
	}
	if !announced {
		return fmt.Errorf("test target lacks the NOT EXAMINED announcement between the Rust leg and the trailing exit")
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

	// Valid leg prefixes with a swallowed status and echoed exit must still
	// fail: token presence alone cannot prove the shell control flow.
	brokenCapture := "test:\n" +
		"\t@status=0; \\\n" +
		"\t$(MAKE) test-go || status=$$?; \\\n" +
		"\t$(MAKE) test-rust || status=$$?; \\\n" +
		"\t@echo \"exit $$status\"\n"
	if err := validateMakeAggregate(brokenCapture); err == nil {
		t.Fatal("echoed exit passed the aggregate status contract")
	}

	lateStatus := "test:\n" +
		"\t$(MAKE) test-go || status=$$?; \\\n" +
		"\t$(MAKE) test-rust || status=$$?; \\\n" +
		"\tstatus=0; \\\n" +
		"\texit $$status\n"
	if err := validateMakeAggregate(lateStatus); err == nil {
		t.Fatal("late status initialization passed the aggregate contract")
	}

	// A swapped leg order must fail: the Go leg runs first, and the order
	// check is what pins it.
	swappedOrder := "test:\n" +
		"\t@status=0; \\\n" +
		"\t$(MAKE) test-rust || status=$$?; \\\n" +
		"\t$(MAKE) test-go || status=$$?; \\\n" +
		"\texit $$status\n"
	if err := validateMakeAggregate(swappedOrder); err == nil ||
		!strings.Contains(err.Error(), "must run before Rust leg") {
		t.Fatalf("swapped leg order did not trip the order check: %v", err)
	}

	// A bare leg without contiguous capture swallows its failure: without
	// set -e the next command overwrites $?, the R1 false all-clear.
	droppedCapture := "test:\n" +
		"\t@status=0; \\\n" +
		"\t$(MAKE) test-go; \\\n" +
		"\t$(MAKE) test-rust || status=$$?; \\\n" +
		"\texit $$status\n"
	if err := validateMakeAggregate(droppedCapture); err == nil ||
		!strings.Contains(err.Error(), "lack contiguous status capture") {
		t.Fatalf("dropped capture did not trip the capture check: %v", err)
	}

	// A capture line that resets status after the submake can erase a red
	// result. The capture must therefore be the complete continued command.
	failureReset := "test:\n" +
		"\t@status=0; \\\n" +
		"\t$(MAKE) test-go || status=$$?; status=0; \\\n" +
		"\t$(MAKE) test-rust || status=$$?; \\\n" +
		"\techo \"NOT EXAMINED\"; \\\n" +
		"\texit $$status\n"
	if err := validateMakeAggregate(failureReset); err == nil ||
		!strings.Contains(err.Error(), "lack contiguous status capture") {
		t.Fatalf("failure-reset capture did not trip the exact-capture check: %v", err)
	}

	// An initializer that runs another command can bypass status setup before
	// either leg. Only the complete initializer continuation is accepted.
	brokenInitializer := "test:\n" +
		"\t@status=0; exit 0; \\\n" +
		"\t$(MAKE) test-go || status=$$?; \\\n" +
		"\t$(MAKE) test-rust || status=$$?; \\\n" +
		"\techo \"NOT EXAMINED\"; \\\n" +
		"\texit $$status\n"
	if err := validateMakeAggregate(brokenInitializer); err == nil ||
		!strings.Contains(err.Error(), "initialize a failure status") {
		t.Fatalf("broken initializer did not trip the initializer check: %v", err)
	}

	// Legs without any trailing exit leave the aggregate's status on the
	// floor: the last command's exit becomes the target's.
	missingExit := "test:\n" +
		"\t@status=0; \\\n" +
		"\t$(MAKE) test-go || status=$$?; \\\n" +
		"\t$(MAKE) test-rust || status=$$?; \\\n" +
		"\techo done\n"
	if err := validateMakeAggregate(missingExit); err == nil ||
		!strings.Contains(err.Error(), "trailing exit") {
		t.Fatalf("missing exit did not trip the exit check: %v", err)
	}

	// Legs and exit without the announcement recreate the #7766 shape: the
	// gate would stop saying what it did not examine.
	missingAnnouncement := "test:\n" +
		"\t@status=0; \\\n" +
		"\t$(MAKE) test-go || status=$$?; \\\n" +
		"\t$(MAKE) test-rust || status=$$?; \\\n" +
		"\texit $$status\n"
	if err := validateMakeAggregate(missingAnnouncement); err == nil ||
		!strings.Contains(err.Error(), "NOT EXAMINED") {
		t.Fatalf("missing announcement did not trip the announcement check: %v", err)
	}

	// A missing target is a zero-denominator control: a canary that finds no
	// target must fail rather than report a vacuous pass.
	if err := validateMakeAggregate("test-go:\n\t@true\n"); err == nil {
		t.Fatal("Makefile without a test target passed the aggregate contract")
	}
}
