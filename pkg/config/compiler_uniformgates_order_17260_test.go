package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestUniformGatesPriorityDoctrine17260 pins the #17260 gate-order
// doctrine: cross-gate first-error identity and tolerant-warning order
// are unpinned artefacts of execution order, not priority contracts,
// except where explicitly pinned by NAT registry #16145 and RI-collision
// precedence tests #9821. It scans every compiler_uniformgates*.go
// production file and the RI/login tests with precedence-specific prose,
// checking the qualified sentence in runUniformGates' attached doc comment.
func TestUniformGatesPriorityDoctrine17260(t *testing.T) {
	dir := goldenPkgDir(t)

	const unpinnedSentence = "Cross-gate first-error identity and tolerant-warning order are unpinned " +
		"artefacts of execution order, not priority contracts, except where explicitly " +
		"pinned by NAT registry #16145 and RI-collision precedence tests #9821."
	const executionOrder = "#11794 -> #14397 -> #16628/#17680 -> #15935 -> #11823 -> #12089 -> #15001 -> #15278 -> #15717 -> #12217 -> #16770"

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read config directory: %v", err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "compiler_uniformgates") ||
			!strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, name)
	}
	sort.Strings(files)
	files = append(files, "ri_member_collision_9821_test.go", "login_class_gate_15717_test.go")

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
	subrunHeaderBanned := []string{
		"verbatim contiguous slice",
		"exact flat gate sequence",
		"first-failing-gate-wins",
		"invariant #6",
		"invariant #7",
		"warning-accumulation order",
		"see rununiformgates.",
	}
	slotPriorityFiles := map[string]struct{}{
		"compiler_uniformgates.go":                {},
		"compiler_uniformgates_interface_addr.go": {},
	}
	slotPriorityBanned := []string{
		"keep priority",
		"first-error slot",
		"wins the",
	}

	for _, name := range files {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(b)
		lower := strings.ToLower(src)
		normalizedLower := strings.Join(strings.Fields(lower), " ")
		for _, phrase := range banned {
			if strings.Contains(lower, phrase) {
				t.Errorf("%s: doctrine phrase %q reintroduced (#17260: cross-gate order is unpinned except for explicitly pinned NAT and RI precedences)", name, phrase)
			}
		}
		if _, checkSlots := slotPriorityFiles[name]; checkSlots {
			for _, phrase := range slotPriorityBanned {
				if strings.Contains(lower, phrase) {
					t.Errorf("%s: unpinned slot-priority phrase %q reintroduced", name, phrase)
				}
			}
		}

		parsed, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		foundMainHeader := false
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !strings.HasPrefix(fn.Name.Name, "runUniformGates") || fn.Doc == nil {
				continue
			}
			doc := strings.Join(strings.Fields(fn.Doc.Text()), " ")
			docLower := strings.ToLower(doc)
			if fn.Name.Name == "runUniformGates" {
				foundMainHeader = true
				if n := strings.Count(doc, unpinnedSentence); n != 1 {
					t.Errorf("compiler_uniformgates.go: qualified doctrine sentence occurs %d times, want exactly 1 in the attached runUniformGates doc comment", n)
				}
				if !strings.Contains(doc, executionOrder) {
					t.Errorf("compiler_uniformgates.go: execution-order chain %q missing from the attached runUniformGates doc comment", executionOrder)
				}
				continue
			}
			for _, phrase := range subrunHeaderBanned {
				if strings.Contains(docLower, phrase) {
					t.Errorf("%s: subrun header phrase %q duplicates obsolete cross-gate doctrine", name, phrase)
				}
			}
		}
		if name == "compiler_uniformgates.go" && !foundMainHeader {
			t.Fatal("compiler_uniformgates.go: attached runUniformGates doc comment missing")
		}
		if strings.Contains(normalizedLower, "reproduce the exact flat gate sequence") {
			t.Errorf("%s: obsolete flat-sequence boilerplate reintroduced", name)
		}
	}
}
