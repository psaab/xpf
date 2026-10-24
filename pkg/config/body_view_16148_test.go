package config

import (
	"fmt"
	"strings"
	"testing"
)

// #16148 (W2.3 R4-narrowed) — BodyView, screen family first.
//
// The falsifying experiment for the per-family campaign: does a shared
// BodyView (Children/Find over the existing packedBodyChildren expansion,
// with a per-family expansion where the family's order legitimately
// differs) reproduce the OLD screen-family expander's output —
// screenFamilyBody / screenFamilyBodyChain — on every hierarchical /
// flat / packed / bracketed form, and delete a bespoke expander in doing
// so? If the first families delete nothing, the campaign stops; this
// family deletes screenFamilyBodyChain (its bracketed single-chain walk
// is inlined into screenFamilyBody, the one remaining screen expander,
// and every screen reader now goes through the view).
//
// Differential discipline: the view is compared against the surviving
// old expander (screenFamilyBody) node-for-node, AND the bracketed
// chain shape is compared against a verbatim copy of the deleted
// screenFamilyBodyChain kept ONLY in this test file. A test that only
// exercised the view could pass while the view diverged.

func renderNodes16148(nodes []*Node) string {
	var sb strings.Builder
	for i, n := range nodes {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(renderNode16148(n))
	}
	return sb.String()
}

func renderNode16148(n *Node) string {
	if n == nil {
		return "<nil>"
	}
	s := fmt.Sprintf("[%s leaf=%v", strings.Join(n.Keys, " "), n.IsLeaf)
	if len(n.Children) > 0 {
		s += " " + renderNodes16148(n.Children)
	}
	return s + "]"
}

// deletedChain16148 is a verbatim copy of the pre-#16148
// screenFamilyBodyChain, retained in the test only as the differential
// oracle for the bracketed shape. Production code must not call it.
func deletedChain16148(node *Node, schema *schemaNode, consumed int, cur *schemaNode) *Node {
	tail := node.Keys[consumed:]
	var head, last *Node
	for len(tail) > 0 {
		n := 1
		var refined *schemaNode
		if cur != nil {
			if childSchema := resolveSchemaChild(cur, tail[0]); childSchema != nil {
				if c, r := consumeNodeKeys(tail, childSchema); c > 0 && c <= len(tail) {
					n, refined = c, r
				}
			}
		}
		next := &Node{Keys: append([]string(nil), tail[:n]...), IsLeaf: true}
		if last == nil {
			head = next
		} else {
			last.Children = []*Node{next}
			last.IsLeaf = false
		}
		last = next
		tail = tail[n:]
		cur = refined
	}
	if len(node.Children) > 0 && last != nil {
		last.Children = append(last.Children, node.Children...)
		last.IsLeaf = false
	}
	clone := *node
	clone.Keys = append([]string(nil), node.Keys[:consumed]...)
	clone.Children = []*Node{head}
	clone.IsLeaf = false
	return &clone
}

var screenFamilyCases16148 = []struct {
	name     string
	keys     []string
	children []*Node
	fam      string
}{
	{"icmp single flag", []string{"icmp", "ping-death"}, nil, "icmp"},
	{"icmp two flags", []string{"icmp", "ping-death", "fragment"}, nil, "icmp"},
	{"icmp flood threshold", []string{"icmp", "flood", "threshold", "900"}, nil, "icmp"},
	{"icmp unknown", []string{"icmp", "bogus-check"}, nil, "icmp"},
	{"tcp land", []string{"tcp", "land"}, nil, "tcp"},
	{"tcp syn-flood siblings", []string{"tcp", "syn-flood", "alarm-threshold", "100", "attack-threshold", "500"}, nil, "tcp"},
	{"tcp syn-flood three siblings", []string{"tcp", "syn-flood", "alarm-threshold", "100", "attack-threshold", "500", "timeout", "30"}, nil, "tcp"},
	{"tcp land bogus tail", []string{"tcp", "land", "bogus-tail"}, nil, "tcp"},
	{"ip ip-sweep missing threshold kw", []string{"ip", "ip-sweep", "7777"}, nil, "ip"},
	{"ip tear-drop", []string{"ip", "tear-drop", "source-route-option"}, nil, "ip"},
	{"udp flood", []string{"udp", "flood", "threshold", "900"}, nil, "udp"},
	{"limit-session src", []string{"limit-session", "source-ip-based", "100"}, nil, "limit-session"},
	{"icmp flood packed plus braced", []string{"icmp", "flood"}, []*Node{{Keys: []string{"threshold", "900"}, IsLeaf: true}}, "icmp"},
	{"tcp syn-flood packed plus braced", []string{"tcp", "syn-flood"}, []*Node{{Keys: []string{"attack-threshold", "300"}, IsLeaf: true}}, "tcp"},
}

func screenFamNode16148(keys []string, children []*Node, bracketTail bool) *Node {
	n := &Node{Keys: append([]string(nil), keys...), Children: children}
	if bracketTail && len(keys) > 1 {
		br := make([]bool, len(keys))
		for i := 1; i < len(keys); i++ {
			br[i] = true
		}
		n.setKeysBracketed(br, true)
	}
	return n
}

// TestBodyViewScreenFamilyDifferential16148 is the decisive acceptance
// check for the first adopted family: old expander vs BodyView output.
func TestBodyViewScreenFamilyDifferential16148(t *testing.T) {
	idsSchema := refScreenIdsOption.resolve()
	if idsSchema == nil {
		t.Fatal("screen ids-option schema unresolved")
	}
	for _, tc := range screenFamilyCases16148 {
		t.Run(tc.name, func(t *testing.T) {
			famSchema := resolveSchemaChild(idsSchema, tc.fam)
			if famSchema == nil {
				t.Fatalf("family schema %q unresolved", tc.fam)
			}
			// (a) view-based screen reader == surviving old expander.
			old := screenFamilyBody(screenFamNode16148(tc.keys, tc.children, false), famSchema)
			viaPacked := screenPackedBody(screenFamNode16148(tc.keys, tc.children, false), famSchema)
			if viaPacked == screenFamNode16148(tc.keys, tc.children, false) {
				t.Fatal("unreachable fixture check")
			}
			// screenPackedBody tries the shared view first; where it
			// declines, the screen view must produce exactly the old
			// expander's node. Compare canonical renderings.
			if renderNode16148(old) != renderNode16148(viaPacked) {
				// The shared view may legitimately win on modelled
				// forms (it is tried first); that divergence is pinned
				// separately below. Here require the screen view itself
				// to match the old expander.
				viaScreenView := screenBodyNode(screenFamNode16148(tc.keys, tc.children, false), famSchema)
				if renderNode16148(old) != renderNode16148(viaScreenView) {
					t.Fatalf("screen BodyView diverges from old screenFamilyBody:\n  old: %s\n  new: %s\n  screenPackedBody: %s",
						renderNode16148(old), renderNode16148(viaScreenView), renderNode16148(viaPacked))
				}
			}
			// (b) the screen view's Children == old expander's Children.
			oldKids := screenFamilyBody(screenFamNode16148(tc.keys, tc.children, false), famSchema).Children
			newKids := screenBodyView(screenFamNode16148(tc.keys, tc.children, false), famSchema).Children()
			if renderNodes16148(oldKids) != renderNodes16148(newKids) {
				t.Fatalf("screen BodyView.Children diverges:\n  old: %s\n  new: %s",
					renderNodes16148(oldKids), renderNodes16148(newKids))
			}
			// (c) authored node untouched.
			probe := screenFamNode16148(tc.keys, tc.children, false)
			_ = screenBodyView(probe, famSchema).Children()
			if fmt.Sprintf("%v/%d", tc.keys, len(tc.children)) != fmt.Sprintf("%v/%d", probe.Keys, len(probe.Children)) {
				t.Fatalf("view mutated the authored node: %v/%d", probe.Keys, len(probe.Children))
			}
		})
	}

	// Bracketed tails: the (now inlined) chain in screenFamilyBody must
	// equal the deleted screenFamilyBodyChain verbatim copy.
	for _, keys := range [][]string{
		{"icmp", "ping-death", "fragment"},
		{"tcp", "syn-fin", "land"},
		{"udp", "flood", "bogus"},
	} {
		t.Run("bracketed "+strings.Join(keys, " "), func(t *testing.T) {
			famSchema := resolveSchemaChild(idsSchema, keys[0])
			node := screenFamNode16148(keys, nil, true)
			consumed, cur := consumeNodeKeys(node.Keys, famSchema)
			want := deletedChain16148(screenFamNode16148(keys, nil, true), famSchema, consumed, cur)
			got := screenFamilyBody(screenFamNode16148(keys, nil, true), famSchema)
			if renderNode16148(want) != renderNode16148(got) {
				t.Fatalf("bracketed chain diverges from deleted screenFamilyBodyChain:\n  old: %s\n  new: %s",
					renderNode16148(want), renderNode16148(got))
			}
			// Through the view-based family reader too.
			viaView := screenBodyNode(screenFamNode16148(keys, nil, true), famSchema)
			if renderNode16148(want) != renderNode16148(viaView) {
				t.Fatalf("screenBodyNode bracketed output diverges:\n  old: %s\n  new: %s",
					renderNode16148(want), renderNode16148(viaView))
			}
		})
	}
}

// TestBodyViewChildrenFind16148 pins the view's own contract.
func TestBodyViewChildrenFind16148(t *testing.T) {
	idsSchema := refScreenIdsOption.resolve()
	node := &Node{Keys: []string{"ids-option", "P", "icmp", "ping-death"}}
	v := bodyViewOf(node, idsSchema)
	kids := v.Children()
	if len(kids) != 1 || kids[0].Name() != "icmp" {
		t.Fatalf("Children = %s, want one [icmp ...] child", renderNodes16148(kids))
	}
	icmp := v.Find("icmp")
	if icmp == nil || len(icmp.Children) != 1 || icmp.Children[0].Name() != "ping-death" {
		t.Fatalf("Find(icmp) = %s, want [icmp [ping-death]]", renderNode16148(icmp))
	}
	if got := v.Find("tcp"); got != nil {
		t.Fatalf("Find(tcp) = %s, want nil", renderNode16148(got))
	}
	if got := v.FindAll("icmp"); len(got) != 1 {
		t.Fatalf("FindAll(icmp) = %d nodes, want 1", len(got))
	}
	if got := v.FindAll("tcp"); got != nil {
		t.Fatalf("FindAll(tcp) = %v, want nil", got)
	}
	if got := bodyViewOf(node, nil).Children(); len(got) != 0 {
		t.Fatalf("nil-schema Children = %v, want authored (none)", got)
	}
	if got := bodyViewOf(nil, idsSchema).Children(); got != nil {
		t.Fatalf("nil-node Children = %v, want nil", got)
	}
	if got := bodyViewOf(nil, idsSchema).Node(); got != nil {
		t.Fatalf("nil-node Node = %v, want nil", got)
	}
	// withExpansion: Find runs over the custom expansion's children.
	famSchema := resolveSchemaChild(idsSchema, "tcp")
	sv := screenBodyView(&Node{Keys: []string{"tcp", "land", "bogus-tail"}}, famSchema)
	if got := sv.Find("land"); got == nil {
		t.Fatal("screen view Find(land) = nil, want the land node (unknown tail chained under it)")
	}
}

// TestBodyViewPlainBranchZeroAlloc16148 is the allocation gate.
func TestBodyViewPlainBranchZeroAlloc16148(t *testing.T) {
	idsSchema := refScreenIdsOption.resolve()
	child := &Node{Keys: []string{"icmp"}, Children: []*Node{{Keys: []string{"ping-death"}, IsLeaf: true}}}
	node := &Node{Keys: []string{"ids-option", "P"}, Children: []*Node{child}}

	v := bodyViewOf(node, idsSchema)
	kids := v.Children()
	if len(kids) != 1 || &kids[0] != &node.Children[0] {
		t.Fatal("plain-branch Children must return the authored slice unchanged")
	}
	if v.Node() != node {
		t.Fatal("plain-branch Node must return the authored pointer")
	}
	if testing.AllocsPerRun(100, func() {
		_ = bodyViewOf(node, idsSchema).Children()
		_ = bodyViewOf(node, idsSchema).Node()
		_ = bodyViewOf(node, idsSchema).Find("icmp")
	}) != 0 {
		t.Fatal("plain-branch BodyView must not allocate")
	}
	if testing.AllocsPerRun(100, func() {
		_ = packedBodyChildren(node, idsSchema)
		_ = packedBody(node, idsSchema)
	}) != 0 {
		t.Fatal("plain-branch packedBodyChildren/packedBody must not allocate")
	}
}

// TestBodyViewScreenEndToEnd16148 asserts the three compile channels
// agree across hierarchical / flat / packed spellings after the move.
func TestBodyViewScreenEndToEnd16148(t *testing.T) {
	cases := []struct {
		name       string
		hier       string
		flat       string
		wantStrict bool
		wantSub    string
	}{
		{"icmp packed flag", "icmp ping-death;", "icmp ping-death", false, "ping-death=true"},
		{"tcp syn-flood packed siblings", "tcp syn-flood alarm-threshold 100 attack-threshold 500;", "tcp syn-flood alarm-threshold 100 attack-threshold 500", false, "attack=500"},
		{"tcp unknown packed", "tcp bogus-check;", "tcp bogus-check", true, "unknown=[tcp bogus-check]"},
		{"icmp bracketed refusal", "icmp [ ping-death fragment ];", "icmp [ ping-death fragment ]", true, "unknown=[icmp ping-death fragment]"},
		{"tcp malformed tail", "tcp land bogus-tail;", "tcp land bogus-tail", true, "tcp land bogus-tail"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hStrict, hSchema, hSum := screenChannels9421(t, screenHierTree9421(t, tc.hier))
			fStrict, fSchema, fSum := screenChannels9421(t, screenFlatTree9421(t, tc.flat))
			if (hStrict != nil) != (fStrict != nil) {
				t.Fatalf("strict verdict diverges: hier=%v flat=%v", hStrict, fStrict)
			}
			if got := hStrict != nil; got != tc.wantStrict {
				t.Fatalf("strict reject=%v want %v (err=%v)", got, tc.wantStrict, hStrict)
			}
			if (hSchema != nil) != (fSchema != nil) {
				t.Fatalf("SchemaValidate verdict diverges: hier=%v flat=%v", hSchema, fSchema)
			}
			if hSum != fSum {
				t.Fatalf("compiled profile diverges:\n  hier: %s\n  flat: %s", hSum, fSum)
			}
			if !strings.Contains(hSum, tc.wantSub) {
				t.Fatalf("profile %s does not contain %q", hSum, tc.wantSub)
			}
		})
	}
}
