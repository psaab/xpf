package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// #17263: Node key provenance (Keys / KeysQuoted / KeysBracketed /
// BracketedClosed) is maintained only through ast_keys.go helpers.
// These tests pin the mask-length invariant, the leaf-list bracket
// propagation (including the aligned member cache), the closed-carry
// guard, and the redaction mask drop.

func assertNodeKeyInvariant17263(t *testing.T, label string, tree *ConfigTree) {
	t.Helper()
	if v := checkNodeKeyInvariant(tree); len(v) != 0 {
		t.Fatalf("%s: %d key-provenance invariant violations: %v", label, len(v), v)
	}
}

func TestNodeKeyInvariant17263(t *testing.T) {
	fixtures := map[string]string{
		"closed protocol list with inactive sibling": `policy-options {
 policy-statement P {
  term T from protocol [ ospf bgp ] then accept;
 }
}
system {
 inactive: host-name parked;
}`,
		"quoted event commands": `event-options {
  policy p {
    then {
      change-configuration {
        commands [ "set" "system host-name x" ];
      }
    }
  }
}`,
		"bracketed container": `security { zones { security-zone trust { interfaces [ ge-0/0/0 ge-0/0/1 ] { host-inbound-traffic { system-services ssh; } } } } }`,
		"group inline name-server union": `groups {
    g {
        system {
            name-server [ 1.1.1.1 2.2.2.2 ];
        }
    }
}
apply-groups g;
system {
    name-server 9.9.9.9;
}`,
	}
	for name, src := range fixtures {
		t.Run(name, func(t *testing.T) {
			base := parseHierText(t, src)
			assertNodeKeyInvariant17263(t, "parsed", base)
			assertNodeKeyInvariant17263(t, "Clone", base.Clone())
			assertNodeKeyInvariant17263(t, "WithoutInactive", base.WithoutInactive())
			expanded := base.Clone()
			if err := expanded.ExpandGroups(); err != nil {
				t.Fatalf("ExpandGroups: %v", err)
			}
			assertNodeKeyInvariant17263(t, "ExpandGroups", expanded)
			assertNodeKeyInvariant17263(t, "RedactedClone", base.RedactedClone())
		})
	}
}

func TestMergeLeafListBracketProvenance17263(t *testing.T) {
	// q26 unit fixture: a bracketed destination extended by a bare member
	// must keep an aligned bracket mask.
	dst := &Node{Keys: []string{"protocol", "static", "direct"}, IsLeaf: true}
	dst.setKeysBracketed([]bool{false, true, true}, true)
	src := &Node{Keys: []string{"protocol", "bgp"}, IsLeaf: true}
	mergeLeafListInto(dst, src)
	if want := []string{"protocol", "static", "direct", "bgp"}; !reflect.DeepEqual(dst.Keys, want) {
		t.Fatalf("merged keys = %v, want %v", dst.Keys, want)
	}
	if want := []bool{false, true, true, false}; !reflect.DeepEqual(dst.KeysBracketed, want) {
		t.Fatalf("merged KeysBracketed = %v (len %d, keys len %d), want %v",
			dst.KeysBracketed, len(dst.KeysBracketed), len(dst.Keys), want)
	}
	if !dst.BracketedClosed {
		t.Fatal("merged node lost BracketedClosed")
	}

	// Sibling arm: the last sibling grows by one bracketed member.
	first := &Node{Keys: []string{"export", "A"}, IsLeaf: true}
	last := &Node{Keys: []string{"export", "B"}, IsLeaf: true}
	last.setKeysBracketed([]bool{false, true}, true)
	src2 := &Node{Keys: []string{"export", "C"}, IsLeaf: true}
	src2.setKeysBracketed([]bool{false, true}, true)
	mergeLeafListIntoSiblings16541([]*Node{first, last}, src2)
	if want := []string{"export", "B", "C"}; !reflect.DeepEqual(last.Keys, want) {
		t.Fatalf("sibling keys = %v, want %v", last.Keys, want)
	}
	if want := []bool{false, true, true}; !reflect.DeepEqual(last.KeysBracketed, want) {
		t.Fatalf("sibling KeysBracketed = %v, want %v", last.KeysBracketed, want)
	}

	// Closed-carry positive: a provenance-less destination adopts the
	// closed bit from a closed bracketed source member.
	dst3 := &Node{Keys: []string{"protocol", "bgp"}, IsLeaf: true}
	src3 := &Node{Keys: []string{"protocol", "static"}, IsLeaf: true}
	src3.setKeysBracketed([]bool{false, true}, true)
	mergeLeafListInto(dst3, src3)
	if want := []bool{false, false, true}; !reflect.DeepEqual(dst3.KeysBracketed, want) {
		t.Fatalf("carry KeysBracketed = %v, want %v", dst3.KeysBracketed, want)
	}
	if !dst3.BracketedClosed {
		t.Fatal("closed bracketed source member did not carry BracketedClosed onto a bare destination")
	}

	// Mixed negative control: a destination that already carries bracket
	// provenance but was NOT closed must not be laundered to closed.
	dst4 := &Node{Keys: []string{"protocol", "static"}, IsLeaf: true}
	dst4.setKeysBracketed([]bool{false, true})
	src4 := &Node{Keys: []string{"protocol", "direct"}, IsLeaf: true}
	src4.setKeysBracketed([]bool{false, true}, true)
	mergeLeafListInto(dst4, src4)
	if want := []string{"protocol", "static", "direct"}; !reflect.DeepEqual(dst4.Keys, want) {
		t.Fatalf("mixed keys = %v, want %v", dst4.Keys, want)
	}
	if want := []bool{false, true, true}; !reflect.DeepEqual(dst4.KeysBracketed, want) {
		t.Fatalf("mixed KeysBracketed = %v, want %v", dst4.KeysBracketed, want)
	}
	if dst4.BracketedClosed {
		t.Fatal("merge laundered an unclosed destination to BracketedClosed")
	}
}

func TestMergeLeafListBracketCachePropagation17263(t *testing.T) {
	newSrc := func() *Node {
		src := &Node{Keys: []string{"protocol", "static", "direct"}, IsLeaf: true, fromGroups: []string{"g1"}}
		src.setKeysBracketed([]bool{false, true, true}, true)
		return src
	}
	newDst := func() *Node {
		return &Node{Keys: []string{"protocol", "bgp"}, IsLeaf: true, fromGroups: []string{"inline"}}
	}
	wantKeys := []string{"protocol", "bgp", "static", "direct"}
	wantMask := []bool{false, false, true, true}

	dst := newDst()
	src := newSrc()
	mergeLeafListInto(dst, src)
	if !reflect.DeepEqual(dst.Keys, wantKeys) {
		t.Fatalf("first union keys = %v, want %v", dst.Keys, wantKeys)
	}
	if !reflect.DeepEqual(dst.KeysBracketed, wantMask) {
		t.Fatalf("first union KeysBracketed = %v, want %v", dst.KeysBracketed, wantMask)
	}
	members := leafListMemberGroupsForNode9862(dst)
	var cachedBits []bool
	for _, m := range members {
		cachedBits = append(cachedBits, m.bracketed)
	}
	if want := []bool{false, true, true}; !reflect.DeepEqual(cachedBits, want) {
		t.Fatalf("cached member bracket bits = %v, want %v", cachedBits, want)
	}

	// Clone via cloneNodes: the aligned cache must retain the bits, and a
	// second union reading the CACHED branch must reproduce the result.
	clone := cloneNodes([]*Node{dst})[0]
	clonedMembers := leafListMemberGroupsForNode9862(clone)
	var clonedBits []bool
	for _, m := range clonedMembers {
		clonedBits = append(clonedBits, m.bracketed)
	}
	if want := []bool{false, true, true}; !reflect.DeepEqual(clonedBits, want) {
		t.Fatalf("cloned cached bracket bits = %v, want %v (clone dropped the bit)", clonedBits, want)
	}
	fresh := &Node{Keys: []string{"protocol", "bgp"}, IsLeaf: true}
	mergeLeafListInto(fresh, clone)
	if !reflect.DeepEqual(fresh.Keys, wantKeys) {
		t.Fatalf("second union keys = %v, want %v", fresh.Keys, wantKeys)
	}
	if !reflect.DeepEqual(fresh.KeysBracketed, wantMask) {
		t.Fatalf("second union KeysBracketed = %v, want %v (cached branch dropped the bit)",
			fresh.KeysBracketed, wantMask)
	}
}

func TestRedactJoinedTailDropsStaleMasks17263(t *testing.T) {
	n := &Node{Keys: []string{"commands", "# comment", "discarded"}, IsLeaf: true}
	n.setKeysQuoted([]bool{false, true, false})
	n.setKeysBracketed([]bool{false, true, true}, true)
	tree := &ConfigTree{Children: []*Node{n}}

	// A non-empty comment-only tail is masked as one payload key, changing
	// the key count and making both old per-key masks stale.
	redactEmbeddedPayloads([]embeddedPayloadSite{{node: n, start: 1, joined: true}}, false)
	if len(n.Keys) != 2 || n.Keys[0] != "commands" {
		t.Fatalf("redacted tail keys = %v, want a two-key replacement", n.Keys)
	}
	if n.KeysQuoted != nil || n.KeysBracketed != nil {
		t.Fatalf("redacted tail kept stale masks: quoted=%v bracketed=%v keys=%v",
			n.KeysQuoted, n.KeysBracketed, n.Keys)
	}
	if n.BracketedClosed {
		t.Fatal("redacted tail kept stale BracketedClosed")
	}
	assertNodeKeyInvariant17263(t, "redacted", tree)
}

func TestKeyAccessorsRejectSkewedMask17263(t *testing.T) {
	n := &Node{
		Keys:          []string{"a", "b", "c", "d"},
		KeysQuoted:    []bool{false, true, false},
		KeysBracketed: []bool{false, true, false},
	}
	for i := range len(n.Keys) {
		if n.KeyQuoted(i) {
			t.Fatalf("KeyQuoted(%d) answered from a skewed mask", i)
		}
		if n.KeyBracketed(i) {
			t.Fatalf("KeyBracketed(%d) answered from a skewed mask", i)
		}
	}
	if v := checkNodeKeyInvariant(&ConfigTree{Children: []*Node{n}}); len(v) != 2 {
		t.Fatalf("invariant violations = %v, want 2 (one per skewed mask)", v)
	}
	emptyMask := &Node{
		Keys:          []string{"a"},
		KeysQuoted:    []bool{},
		KeysBracketed: []bool{},
	}
	if v := checkNodeKeyInvariant(&ConfigTree{Children: []*Node{emptyMask}}); len(v) != 2 {
		t.Fatalf("invariant violations for empty non-nil masks = %v, want 2", v)
	}
	appended := &Node{
		Keys:          []string{"a", "b"},
		KeysQuoted:    []bool{false, true},
		KeysBracketed: []bool{false, true},
	}
	appended.appendKey("c", false, false)
	assertNodeKeyInvariant17263(t, "appendKey", &ConfigTree{Children: []*Node{appended}})
	skewed := &Node{Keys: []string{"a", "b"}, KeysBracketed: []bool{true}}
	skewed.appendKey("c", false, false)
	if want := []bool{true, false, false}; !reflect.DeepEqual(skewed.KeysBracketed, want) {
		t.Fatalf("appendKey did not zero-pad a skewed prefix: %v, want %v", skewed.KeysBracketed, want)
	}
	assertNodeKeyInvariant17263(t, "appendKey zero-padded skewed prefix", &ConfigTree{Children: []*Node{skewed}})

	// An all-bare appendKey sequence must not materialise mask fields in
	// the persisted JSON (byte-identity for provenance-free nodes).
	bare := &Node{Keys: []string{"protocol"}, IsLeaf: true}
	bare.appendKey("bgp", false, false)
	bare.appendKey("static", false, false)
	out, err := json.Marshal(bare)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(out), "KeysQuoted") || strings.Contains(string(out), "KeysBracketed") {
		t.Fatalf("all-bare appendKey materialised mask fields: %s", out)
	}
}

func TestReplaceKeysMisalignedClosedClearsBit17263(t *testing.T) {
	// Kimi delta pin: a misaligned bracket mask with closed=true must not
	// leave BracketedClosed trusted after the mask is discarded.
	n := &Node{Keys: []string{"a", "b"}}
	n.ReplaceKeys([]string{"a", "b"}, nil, []bool{true}, true)
	if n.KeysBracketed != nil {
		t.Fatalf("KeysBracketed = %v, want nil (misaligned mask discarded)", n.KeysBracketed)
	}
	if n.BracketedClosed {
		t.Fatal("BracketedClosed stayed true after its mask was discarded")
	}
	// Control: aligned closed mask keeps the bit.
	m := &Node{Keys: []string{"a", "b"}}
	m.ReplaceKeys([]string{"a", "b"}, nil, []bool{false, true}, true)
	if !m.BracketedClosed {
		t.Fatal("aligned closed bracket lost BracketedClosed")
	}
}
