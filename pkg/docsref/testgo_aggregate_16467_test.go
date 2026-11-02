package docsref

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testGoLegs16467 are the four legs test-go must run, in order: the
// tree-wide vet, the full ./... test leg, the -count=1 tree-census leg,
// and the build-tag census. The census is LAST (#16467): it compiles
// build-tagged files the default legs exclude, and it must not be able
// to keep the test legs from running.
var testGoLegs16467 = []struct {
	name  string
	match func(line string) bool
}{
	{"vet", func(l string) bool { return l == "$(GO) vet ./... || keep $$?; \\" }},
	{"test ./...", func(l string) bool {
		// #18778: an explicit -timeout, so a package cut off at go test's
		// 10m default cannot read as an ordinary failure.
		return l == `bash ./scripts/go-test-json.sh "$(GOTESTJSON)" "$(GO)" -timeout $(GOTEST_TIMEOUT) ./... || keep $$?; \`
	}},
	{"uncached census packages", func(l string) bool {
		return strings.Contains(l, "-count=1") && strings.Contains(l, "./pkg/docsref/") &&
			strings.Contains(l, "-timeout $(GOTEST_TIMEOUT)") &&
			strings.HasSuffix(l, "|| keep $$?; \\")
	}},
	{"build-tag census", func(l string) bool {
		return l == "sh scripts/go-buildtag-census.sh || keep $$?; \\"
	}},
}

// validateTestGoAggregate16467 pins the #16467 shape of test-go: a
// prerequisite-anchored target (test-race-dp stays a prerequisite — it
// is a separate earlier gate, not one of the legs this issue reorders)
// whose recipe is ONE continued shell invocation: a status initializer,
// the GOTESTJSON truncate, every leg with contiguous `|| keep $$?`
// capture in the declared order, and a trailing `exit $$status`. Any
// leg on its own recipe line, or without capture, or out of order,
// restores the defect: make stops the recipe at that leg and the
// remaining legs never run.
func validateTestGoAggregate16467(mk string) error {
	lines := strings.Split(mk, "\n")
	target := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "test-go:") {
			target = i
			break
		}
	}
	if target < 0 {
		return fmt.Errorf("no line-anchored test-go: target found")
	}
	if strings.TrimSpace(lines[target]) != "test-go: test-race-dp" {
		return fmt.Errorf("test-go target must keep its test-race-dp prerequisite: %q", lines[target])
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
			return fmt.Errorf("non-recipe line inside test-go target: %q", line)
		}
		started = true
		recipe = append(recipe, trimmed)
	}
	if len(recipe) == 0 {
		return fmt.Errorf("test-go target has no recipe")
	}
	// One continued invocation: every recipe line but the last must end
	// in a continuation, or each line gets its own shell and `status`
	// does not survive to the trailing exit.
	for i, line := range recipe[:len(recipe)-1] {
		if !strings.HasSuffix(line, "\\") {
			return fmt.Errorf("test-go recipe line %d is not continued — each leg would run in its own shell and abort at the first failure: %q", i, line)
		}
	}
	if recipe[0] != "@status=0; \\" {
		return fmt.Errorf("test-go recipe does not open with the status initializer: %q", recipe[0])
	}
	truncate := -1
	for i, line := range recipe {
		if line == `[ -z "$(GOTESTJSON)" ] || : > "$(GOTESTJSON)"; \` {
			truncate = i
			break
		}
	}
	if truncate < 0 {
		return fmt.Errorf("test-go recipe lost the one-time GOTESTJSON truncate")
	}
	// #18778: VOID (exit 3) is sticky. Every leg reports through keep(),
	// which never overwrites a status of 3, so a timed-out leg followed by
	// another failing leg still ends the recipe "Error 3".
	keepIdx := -1
	for i, line := range recipe {
		if line == `keep() { [ "$$status" -eq 3 ] || status=$$1; }; \` {
			keepIdx = i
			break
		}
	}
	if keepIdx < 0 {
		return fmt.Errorf("test-go recipe lost the sticky-VOID keep() helper (#18778)")
	}
	prev := keepIdx
	for _, leg := range testGoLegs16467 {
		idx := -1
		for i, line := range recipe {
			if leg.match(line) {
				if idx >= 0 {
					return fmt.Errorf("duplicate %s leg in test-go", leg.name)
				}
				idx = i
			}
		}
		if idx < 0 {
			return fmt.Errorf("test-go is missing its %s leg with contiguous status capture", leg.name)
		}
		if idx <= prev {
			return fmt.Errorf("%s leg runs out of order: legs must run vet, test ./..., uncached census packages, build-tag census", leg.name)
		}
		if leg.name != "vet" && idx <= truncate {
			return fmt.Errorf("%s leg runs before the GOTESTJSON truncate", leg.name)
		}
		prev = idx
	}
	if recipe[len(recipe)-1] != "exit $$status" {
		return fmt.Errorf("test-go recipe does not end with the trailing exit $$status: %q", recipe[len(recipe)-1])
	}
	return nil
}

// TestMakefileTestGoRunsAllLegs16467 binds the #16467 fix to the wiring
// that makes it live: at the pre-fix shape each test-go leg was its own
// recipe line, so a red build-tag census aborted the recipe before
// `go test ./...` ran — a deliberately broken tagged file removed the
// whole Go suite's signal.
//
// FAIL-ON-REVERT: move the census back above the test legs, drop a
// leg's `|| keep $$?` capture, or give a leg its own recipe line.
func TestMakefileTestGoRunsAllLegs16467(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	if err := validateTestGoAggregate16467(string(b)); err != nil {
		t.Fatalf("Makefile test-go aggregate contract (#16467): %v", err)
	}

	// The pre-fix shape: census as its own recipe line before the test
	// legs. Make would stop there and never invoke go test ./...
	preFix := "test-go: test-race-dp\n" +
		"\t$(GO) vet ./...\n" +
		"\tsh scripts/go-buildtag-census.sh\n" +
		"\tbash ./scripts/go-test-json.sh \"$(GOTESTJSON)\" \"$(GO)\" ./...\n"
	if err := validateTestGoAggregate16467(preFix); err == nil {
		t.Fatal("pre-fix per-line shape passed the test-go aggregate contract")
	}

	// Census after the test legs but as its own recipe line: a red
	// census-first ordering is gone, yet the one-shell status capture
	// is still missing, so a red vet would abort before the tests.
	ownLine := "test-go: test-race-dp\n" +
		"\t@status=0; \\\n" +
		"\tkeep() { [ \"$$status\" -eq 3 ] || status=$$1; }; \\\n" +
		"\t$(GO) vet ./... || keep $$?; \\\n" +
		"\t[ -z \"$(GOTESTJSON)\" ] || : > \"$(GOTESTJSON)\"; \\\n" +
		"\tbash ./scripts/go-test-json.sh \"$(GOTESTJSON)\" \"$(GO)\" -timeout $(GOTEST_TIMEOUT) ./... || keep $$?; \\\n" +
		"\tbash ./scripts/go-test-json.sh \"$(GOTESTJSON)\" \"$(GO)\" -timeout $(GOTEST_TIMEOUT) -count=1 ./pkg/docsref/ || keep $$?; \\\n" +
		"\texit $$status\n" +
		"\tsh scripts/go-buildtag-census.sh\n"
	if err := validateTestGoAggregate16467(ownLine); err == nil {
		t.Fatal("census on its own trailing recipe line passed the test-go aggregate contract")
	}

	// A leg without contiguous capture swallows its failure.
	droppedCapture := "test-go: test-race-dp\n" +
		"\t@status=0; \\\n" +
		"\tkeep() { [ \"$$status\" -eq 3 ] || status=$$1; }; \\\n" +
		"\t$(GO) vet ./...; \\\n" +
		"\t[ -z \"$(GOTESTJSON)\" ] || : > \"$(GOTESTJSON)\"; \\\n" +
		"\tbash ./scripts/go-test-json.sh \"$(GOTESTJSON)\" \"$(GO)\" -timeout $(GOTEST_TIMEOUT) ./... || keep $$?; \\\n" +
		"\tbash ./scripts/go-test-json.sh \"$(GOTESTJSON)\" \"$(GO)\" -timeout $(GOTEST_TIMEOUT) -count=1 ./pkg/docsref/ || keep $$?; \\\n" +
		"\tsh scripts/go-buildtag-census.sh || keep $$?; \\\n" +
		"\texit $$status\n"
	if err := validateTestGoAggregate16467(droppedCapture); err == nil ||
		!strings.Contains(err.Error(), "vet") {
		t.Fatalf("dropped vet capture did not trip the leg check: %v", err)
	}

	// Census before the test legs, all captured: ordering alone must
	// trip, because that is the exact #16467 suppression.
	censusFirst := "test-go: test-race-dp\n" +
		"\t@status=0; \\\n" +
		"\tkeep() { [ \"$$status\" -eq 3 ] || status=$$1; }; \\\n" +
		"\t$(GO) vet ./... || keep $$?; \\\n" +
		"\t[ -z \"$(GOTESTJSON)\" ] || : > \"$(GOTESTJSON)\"; \\\n" +
		"\tsh scripts/go-buildtag-census.sh || keep $$?; \\\n" +
		"\tbash ./scripts/go-test-json.sh \"$(GOTESTJSON)\" \"$(GO)\" -timeout $(GOTEST_TIMEOUT) ./... || keep $$?; \\\n" +
		"\tbash ./scripts/go-test-json.sh \"$(GOTESTJSON)\" \"$(GO)\" -timeout $(GOTEST_TIMEOUT) -count=1 ./pkg/docsref/ || keep $$?; \\\n" +
		"\texit $$status\n"
	if err := validateTestGoAggregate16467(censusFirst); err == nil ||
		!strings.Contains(err.Error(), "out of order") {
		t.Fatalf("census-first order did not trip the order check: %v", err)
	}

	// A missing target is a zero-denominator control.
	if err := validateTestGoAggregate16467("test:\n\t@true\n"); err == nil {
		t.Fatal("Makefile without a test-go target passed the aggregate contract")
	}
}
