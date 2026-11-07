package configstore

import (
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8964: the retired-dataplane rewriter could not see a value carried on the
// stanza's OWN Keys, which is where the packed spelling puts it.
//
//	braced   Keys=[system]                       Children=[[dataplane-type ebpf]]
//	packed   Keys=[system dataplane-type ebpf]   Children=[]
//
// `systemBlocksOf` finds the stanza in BOTH -- measured, systemBlocks=1 either
// way -- so this was never a walk that missed the node. It was a lookup that
// could not see half the spellings of the thing it exists to neutralise.
//
// The consequence is a boot failure, not a dropped setting: the compiler HARD
// REJECTS a retired value (ErrEBPFDataplaneRetired), so a token left behind
// fails Store.Load and the node comes up with ActiveConfig()==nil.
//
// Inert today only because `system dataplane-type` is not an admitted compact
// pair, so the compiler drops the packed tail anyway. One line in
// compactNormalizeInScope ends that.
func TestRetiredDataplaneTypeRewrittenInBothSpellings8964(t *testing.T) {
	for _, tc := range []struct {
		name, text  string
		wantRewrite int
	}{
		{"braced", `system { dataplane-type ebpf; }`, 1},
		{"packed", `system dataplane-type ebpf;`, 1},
		// CONTROL: a zero from a rewriter is a claim about the rewriter until
		// something in the same run makes it fire. These two make the zeros
		// above meaningful by showing the walk reaches non-retired input and
		// declines it.
		{"control/other leaf", `system { host-name fw1; }`, 0},
		{"control/live value", `system { dataplane-type userspace; }`, 0},
		{"control/packed live", `system dataplane-type userspace;`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, perrs := config.NewParser(tc.text).Parse()
			if len(perrs) > 0 || tree == nil {
				t.Fatalf("fixture did not parse: %v", perrs)
			}
			if got := rewriteRetiredDataplaneType(tree, LoadCaller); got != tc.wantRewrite {
				t.Errorf("rewrites = %d, want %d — a retired dataplane-type the "+
					"rewriter leaves behind is HARD-REJECTED by the compiler, so "+
					"Store.Load fails and the node boots with no active config (#8964)",
					got, tc.wantRewrite)
			}
			// And the value must be GONE from the tree the caller keeps, not
			// merely uncounted. rewriteRetiredDataplaneType mutates in place,
			// so this is the same tree Store.Load goes on to compile.
			if strings.Contains(renderTree8964(tree), "ebpf") {
				t.Errorf("`ebpf` survives in the tree after rewriting: %s\n"+
					"  The count is not the property — the tree the caller KEEPS "+
					"is. A rewrite that lands on a copy reports success and "+
					"changes nothing (#8964).", renderTree8964(tree))
			}
		})
	}
}

// The braced path must keep working, and the leaf must be REMOVED rather than
// blanked: a `dataplane-type` with no value reaches the compiler as a different
// malformed input, not as an absent statement.
func TestRetiredRewriteRemovesRatherThanBlanks8964(t *testing.T) {
	for _, text := range []string{
		`system { dataplane-type ebpf; host-name fw1; }`,
		`system dataplane-type ebpf;`,
	} {
		tree, perrs := config.NewParser(text).Parse()
		if len(perrs) > 0 || tree == nil {
			t.Fatalf("fixture did not parse: %v", perrs)
		}
		if rewriteRetiredDataplaneType(tree, LoadCaller) != 1 {
			t.Fatalf("expected one rewrite for %q (#8964)", text)
		}
		rendered := renderTree8964(tree)
		if strings.Contains(rendered, "dataplane-type") {
			t.Errorf("`dataplane-type` remains after the rewrite of %q: %s — it "+
				"must be removed, not left with an empty value (#8964)", text, rendered)
		}
	}
	// The sibling on the braced fixture must survive: removing the retired leaf
	// must not take the rest of the stanza with it.
	tree, _ := config.NewParser(`system { dataplane-type ebpf; host-name fw1; }`).Parse()
	rewriteRetiredDataplaneType(tree, LoadCaller)
	if !strings.Contains(renderTree8964(tree), "host-name") {
		t.Errorf("the rewrite removed a sibling statement as well: %s (#8964)",
			renderTree8964(tree))
	}
}
func TestRetiredPackedTailPreservesAlignedKeyProvenance17263(t *testing.T) {
	system := &config.Node{
		Keys:            []string{"system", "dataplane-type", "ebpf", "host-name", "fw1"},
		KeysQuoted:      []bool{false, false, false, false, true},
		KeysBracketed:   []bool{false, true, true, true, true},
		BracketedClosed: true,
		IsLeaf:          true,
	}
	if got := rewriteRetiredPackedTail(system, LoadCaller); got != 1 {
		t.Fatalf("rewrites = %d, want 1", got)
	}
	if want := []string{"system", "host-name", "fw1"}; !reflect.DeepEqual(system.Keys, want) {
		t.Fatalf("rewritten keys = %v, want %v", system.Keys, want)
	}
	if want := []bool{false, false, true}; !reflect.DeepEqual(system.KeysQuoted, want) {
		t.Fatalf("rewritten KeysQuoted = %v, want %v", system.KeysQuoted, want)
	}
	if want := []bool{false, true, true}; !reflect.DeepEqual(system.KeysBracketed, want) {
		t.Fatalf("rewritten KeysBracketed = %v, want %v", system.KeysBracketed, want)
	}
	if !system.BracketedClosed {
		t.Fatal("rewritten packed node lost BracketedClosed")
	}
}

func renderTree8964(t *config.ConfigTree) string {
	if t == nil {
		return "<nil>"
	}
	return t.Format()
}
