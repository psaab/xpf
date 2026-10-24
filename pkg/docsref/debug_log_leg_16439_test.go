package docsref

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// #16439: Leg 3 of `make test-rust` is the only gate that builds the
// userspace-dp test binary with `--features debug-log`. Four cells
// discriminate only under that feature (one lives in a
// `#[cfg(feature = "debug-log")]` module; the other three gate their
// assertions on `cfg!(feature = "debug-log")`), so Leg 3 names them
// exactly, requires each exactly once in Cargo's `--list` output
// before running any, and the docs/ci-gate-contract row must name
// the leg. This census pins that shape so a renamed cell, a dropped
// roster entry, or a leg that degenerates to substring filters or a
// bare `cargo test` (0 passed == green) fails here at census speed,
// before the expensive Rust legs run.
//
// Mutation proofs (each must red this test):
//   - rename a Rust cell: the Makefile variable, the Rust source and
//     the log roster no longer agree with this registry;
//   - drop a cell from DEBUG_LOG_CELLS_16439: roster != registry;
//   - widen `--exact <cells>` to bare substring filters: the leg
//     prose check below trips;
//   - delete the pre-run `--list` grep: the list-check prose trips;
//   - remove Leg 3 from docs/ci-gate-contract.md: that row trips.

var debugLogCells16439 = []string{
	"afxdp::worker::loop_body::debug_report::policy_revoked_sessions_fold_tests::accumulate_carries_policy_revoked_sessions_10021",
	"afxdp::tx::dispatch::tests::enqueue_failure::direct_tx_tuple_mismatch_recycles_frame_exactly_once",
	"afxdp::tx::dispatch::tests::enqueue_failure::direct_tx_pat_translation_is_not_a_tuple_mismatch_9782",
	"afxdp::tx::dispatch::tests::segmentation::segmentation_pat_translation_survives_expected_ports_9782",
}

// rustCellFiles maps each cell to the source file that must still
// define a `#[test] fn <leaf>` for it — a rename in Rust without a
// matching Makefile update trips here even before Cargo lists.
var rustCellFiles16439 = map[string]string{
	debugLogCells16439[0]: "userspace-dp/src/afxdp/worker/loop_body/debug_report.rs",
	debugLogCells16439[1]: "userspace-dp/src/afxdp/tx/dispatch/tests/enqueue_failure.rs",
	debugLogCells16439[2]: "userspace-dp/src/afxdp/tx/dispatch/tests/enqueue_failure.rs",
	debugLogCells16439[3]: "userspace-dp/src/afxdp/tx/dispatch/tests/segmentation.rs",
}

func validateDebugLogLeg16439(makefile, contract, log string, rustFnDefined func(cell string) bool) error {
	// 1. The leg variable holds exactly the registry, in order.
	varLine := ""
	for _, line := range strings.Split(makefile, "\n") {
		if strings.HasPrefix(line, "DEBUG_LOG_CELLS_16439 :=") {
			if varLine != "" {
				return fmt.Errorf("duplicate DEBUG_LOG_CELLS_16439 definition")
			}
			varLine = strings.TrimSpace(strings.TrimPrefix(line, "DEBUG_LOG_CELLS_16439 :="))
		}
	}
	if varLine == "" {
		return fmt.Errorf("Makefile has no DEBUG_LOG_CELLS_16439 := definition (Leg 3 missing?)")
	}
	if got := strings.Fields(varLine); strings.Join(got, " ") != strings.Join(debugLogCells16439, " ") {
		return fmt.Errorf("DEBUG_LOG_CELLS_16439 = %q, want exactly %q", varLine, strings.Join(debugLogCells16439, " "))
	}

	// 2. The recipe actually runs the feature build, exact-named, with
	// the fail-closed --list census before execution.
	recipe := ""
	for _, line := range strings.Split(makefile, "\n") {
		if strings.Contains(line, "DEBUG_LOG_CELLS_16439") && strings.HasPrefix(line, "\t") {
			recipe = line
		}
	}
	if recipe == "" {
		return fmt.Errorf("no test-rust recipe line consumes DEBUG_LOG_CELLS_16439")
	}
	for _, want := range []string{
		"--features debug-log --bin xpf-userspace-dp -- --list",
		"--features debug-log --bin xpf-userspace-dp -- --test-threads=1 --exact $(DEBUG_LOG_CELLS_16439)",
		"grep -c -F -x",
	} {
		if !strings.Contains(recipe, want) {
			return fmt.Errorf("Leg 3 recipe missing %q: %s", want, strings.TrimSpace(recipe))
		}
	}
	// The census must precede the run inside the one sh -c line.
	if strings.Index(recipe, "-- --list") > strings.Index(recipe, "--exact $(DEBUG_LOG_CELLS_16439)") {
		return fmt.Errorf("Leg 3 runs the cells before listing them; the fail-closed order is list-then-run")
	}

	// 3. Every registered cell is still defined as a Rust #[test] fn.
	for _, cell := range debugLogCells16439 {
		if !rustFnDefined(cell) {
			return fmt.Errorf("cell %s is no longer defined as a #[test] fn in %s", cell, rustCellFiles16439[cell])
		}
	}

	// 4. The gate-contract row names Leg 3, so the documented gate
	// set cannot silently lose it.
	if !strings.Contains(contract, "Leg 3") || !strings.Contains(contract, "debug-log") || !strings.Contains(contract, "#16439") {
		return fmt.Errorf("docs/ci-gate-contract.md does not document Leg 3 (debug-log, #16439)")
	}

	// 5. The issue log names exactly this roster.
	var logged []string
	for _, cell := range debugLogCells16439 {
		if strings.Contains(log, cell) {
			logged = append(logged, cell)
		}
	}
	if len(logged) != len(debugLogCells16439) {
		return fmt.Errorf("docs/log/16439.md names %d of %d Leg 3 cells", len(logged), len(debugLogCells16439))
	}
	return nil
}

func rustFnDefined16439(root string) func(string) bool {
	return func(cell string) bool {
		rel, ok := rustCellFiles16439[cell]
		if !ok {
			return false
		}
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			return false
		}
		leaf := cell[strings.LastIndex(cell, "::")+2:]
		re := regexp.MustCompile(`(?m)#\[test\]\s*\n\s*(?:pub\s+)?fn\s+` + regexp.QuoteMeta(leaf) + `\s*\(`)
		return re.Match(b)
	}
}

func TestDebugLogLeg16439(t *testing.T) {
	root := repoRoot(t)
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	contract, err := os.ReadFile(filepath.Join(root, "docs/ci-gate-contract.md"))
	if err != nil {
		t.Fatalf("read docs/ci-gate-contract.md: %v", err)
	}
	log, err := os.ReadFile(filepath.Join(root, "docs/log/16439.md"))
	if err != nil {
		t.Fatalf("read docs/log/16439.md: %v", err)
	}
	if err := validateDebugLogLeg16439(string(mk), string(contract), string(log), rustFnDefined16439(root)); err != nil {
		t.Fatalf("debug-log Leg 3 contract: %v", err)
	}

	// Mutation self-checks: each broken variant must be rejected.
	good := string(mk)
	broken := map[string]string{
		"leg variable dropped":    strings.Replace(good, "DEBUG_LOG_CELLS_16439 :=", "DEBUG_LOG_CELLS_GONE :=", 1),
		"one cell dropped":        strings.Replace(good, " "+debugLogCells16439[3], "", 1),
		"feature flag dropped":    strings.Replace(good, "--features debug-log --bin xpf-userspace-dp -- --test-threads=1", "--features debug-log-off --bin xpf-userspace-dp -- --test-threads=1", 1),
		"exact widened":           strings.Replace(good, "--exact $(DEBUG_LOG_CELLS_16439)", "$(DEBUG_LOG_CELLS_16439)", 1),
		"list census dropped":     strings.Replace(good, "grep -c -F -x", "grep -c -F", 1),
		"recipe consumer dropped": strings.Replace(good, "--exact $(DEBUG_LOG_CELLS_16439)", "--exact SOME_OTHER_CELLS", 1),
	}
	for name, variant := range broken {
		if variant == good {
			t.Fatalf("mutation %q did not change the Makefile fixture", name)
		}
		if err := validateDebugLogLeg16439(variant, string(contract), string(log), rustFnDefined16439(root)); err == nil {
			t.Fatalf("mutation %q still validates; the census would not catch it", name)
		}
	}
	if err := validateDebugLogLeg16439(good, "no leg here", string(log), rustFnDefined16439(root)); err == nil {
		t.Fatalf("contract without Leg 3 still validates")
	}
	missing := func(string) bool { return false }
	if err := validateDebugLogLeg16439(good, string(contract), string(log), missing); err == nil {
		t.Fatalf("renamed-away Rust cells still validate")
	}
}
