package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUniformGatesPriorityDoctrine17260 pins the #17260 gate-order
// doctrine: cross-gate first-error identity and tolerant-warning order
// are unpinned artefacts of execution order, not priority contracts.
// The touched gate files must keep that sentence in the
// runUniformGates header (exactly once) and must not reintroduce
// steal / dead-last positional-priority doctrine. True relative-order
// facts (functional dependencies and precedences pinned by behaviour
// tests) are unaffected: they are phrased as "runs after X" /
// "surfaces first", never as steal/dead-last doctrine.
func TestUniformGatesPriorityDoctrine17260(t *testing.T) {
	dir := goldenPkgDir(t)

	const unpinnedSentence = "first-error identity and tolerant-warning order are unpinned artefacts of execution order, not priority contracts"
	const executionOrder = "#11794 -> #14397 -> #16628/#17680 -> #15935 -> #11823 -> #12089 -> #15001 -> #15278 -> #15717 -> #12217 -> #16770"

	files := []string{
		"compiler_uniformgates.go",
		"compiler_uniformgates_interface_addr.go",
		"compiler_validate_strict_ri_member_collision.go",
		"compiler_validate_strict_routing_instance_type_9814.go",
	}

	// False positional claims are forbidden; the pinned relative-order
	// precedence facts remain valid and are intentionally not blanket-banned.
	banned := []string{
		"steal",
		"dead-last",
		"dead last",
		"end of the phase",
		"after every established gate",
		"after every existing gate",
		"after every gate",
		"after all existing uniform gates",
		"after all gates so",
	}

	for _, name := range files {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(b)
		lower := strings.ToLower(src)
		for _, phrase := range banned {
			if strings.Contains(lower, phrase) {
				t.Errorf("%s: doctrine phrase %q reintroduced (#17260: gate order is an unpinned artefact, not a priority contract)", name, phrase)
			}
		}
		if name == "compiler_uniformgates.go" {
			if n := strings.Count(src, unpinnedSentence); n != 1 {
				t.Errorf("compiler_uniformgates.go: unpinned-contract sentence occurs %d times, want exactly 1 in the runUniformGates header", n)
			}
			if !strings.Contains(src, executionOrder) {
				t.Errorf("compiler_uniformgates.go: execution-order chain %q missing from header", executionOrder)
			}
		}
	}
}
