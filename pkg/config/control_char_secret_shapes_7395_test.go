package config

import (
	"strconv"
	"strings"
	"testing"
)

const sentinel7395 = "SENTINEL-CREDENTIAL-VALUE"

// The #1798 validators must behave identically in BOTH AST shapes (CLAUDE.md
// dual-shape rule):
//
//   - FLAT (set syntax): the keyword and its value collapse onto ONE node's Keys.
//   - HIERARCHICAL (block parse): they are SEPARATE chained nodes.
//
// #6625's fix keyed on keys[0], which is the keyword in the flat shape and the
// VALUE in the hierarchical one — so it covered one shape and left the other
// publishing the credential twice over (#7395).

func flatLeaf7395(path []string, kw, val string) []*Node {
	var head, cur *Node
	for _, k := range path {
		n := &Node{Keys: []string{k}}
		if head == nil {
			head = n
		} else {
			cur.Children = []*Node{n}
		}
		cur = n
	}
	leaf := &Node{Keys: []string{kw, val}, IsLeaf: true}
	if cur == nil {
		return []*Node{leaf}
	}
	cur.Children = []*Node{leaf}
	return []*Node{head}
}

func hierLeaf7395(path []string, kw, val string) []*Node {
	var head, cur *Node
	for _, k := range append(append([]string(nil), path...), kw, val) {
		n := &Node{Keys: []string{k}}
		if head == nil {
			head = n
		} else {
			cur.Children = []*Node{n}
		}
		cur = n
	}
	cur.IsLeaf = true
	return []*Node{head}
}

// secretLeaves7395 covers every disambiguation class, not one keyword: the
// unconditional keywords, the format-qualifier case, and all three
// CONTEXT-gated generic keywords whose secrecy depends on an ancestor.
func secretLeaves7395() map[string]struct {
	path []string
	kw   string
} {
	return map[string]struct {
		path []string
		kw   string
	}{
		"authentication-key":               {[]string{"chassis", "cluster"}, "authentication-key"},
		"pre-shared-key":                   {[]string{"security", "ike", "policy", "p1"}, "pre-shared-key"},
		"private-key":                      {[]string{"interfaces", "wg0", "unit", "0"}, "private-key"},
		"tsig-secret":                      {[]string{"system", "services", "dynamic-dns", "provider", "p1"}, "tsig-secret"},
		"api-key":                          {[]string{"system", "services", "rest-api"}, "api-key"},
		"password (context: dynamic-dns)":  {[]string{"system", "services", "dynamic-dns", "provider", "p1"}, "password"},
		"api-token (context: dynamic-dns)": {[]string{"system", "services", "dynamic-dns", "provider", "p1"}, "api-token"},
		"community (context: snmp)":        {[]string{"system", "snmp"}, "community"},
		"key (context: authentication md5)": {[]string{
			"protocols", "ospf", "area", "0", "interface", "ge-0/0/0", "authentication", "md5", "1",
		}, "key"},
		"api-auth named-key secret": {
			[]string{"system", "services", "web-management", "api-auth", "key", "automation"},
			"secret",
		},
	}
}

// TestControlCharSecretRedactedInBothShapes_7395 is the fail-on-revert gate for
// all FOUR cells: {strict, lenient} x {flat, hierarchical}.
//
// Before this, exactly one of the four redacted. The hierarchical shape defeated
// the predicate entirely, and the lenient sanitizer was never fixed at all —
// and that one is the worse surface, because its caller LOGS every path it
// returns and it runs on Store.Load at BOOT and Store.SyncApply on every HA
// peer-sync. A persisted key with a stray tab was re-published every boot.
func TestControlCharSecretRedactedInBothShapes_7395(t *testing.T) {
	for name, leaf := range secretLeaves7395() {
		for shape, build := range map[string]func([]string, string, string) []*Node{
			"flat": flatLeaf7395,
			"hier": hierLeaf7395,
		} {
			t.Run(name+"/"+shape+"/strict", func(t *testing.T) {
				err := validateNodesControlChars(build(leaf.path, leaf.kw, "\t"+sentinel7395), "")
				if err == nil {
					t.Fatal("setup: a control character must still be REJECTED; if it is now " +
						"accepted this case exercises no error render")
				}
				if strings.Contains(err.Error(), sentinel7395) {
					t.Fatalf("the credential reached the commit error:\n%v", err)
				}
			})
			t.Run(name+"/"+shape+"/lenient", func(t *testing.T) {
				tree := &ConfigTree{Children: build(leaf.path, leaf.kw, "\t"+sentinel7395)}
				got := SanitizeTreeControlChars(tree)
				if len(got) == 0 {
					t.Fatal("setup: nothing was sanitized; this case exercises no path render")
				}
				for _, p := range got {
					if strings.Contains(p, sentinel7395) {
						t.Fatalf("the credential reached a LOGGED sanitize path (boot / HA "+
							"peer-sync): %q", p)
					}
				}
			})
		}
	}
}

// TestNonSecretValueStillRenderedInBothShapes_7395 is the over-reach guard.
//
// A validator that stopped echoing EVERY value would satisfy the gate above
// completely and destroy a real diagnostic: for a description the offending
// value is exactly what the operator needs to see.
//
// It asserts the QUOTED form, not a bare substring — the rendered PATH also
// contains the value (sanitized), so a Contains() check passes whether or not
// the value branch ran.
func TestNonSecretValueStillRenderedInBothShapes_7395(t *testing.T) {
	const plain = "PLAIN-DESCRIPTION-VALUE"
	for shape, build := range map[string]func([]string, string, string) []*Node{
		"flat": flatLeaf7395,
		"hier": hierLeaf7395,
	} {
		t.Run(shape+"/strict", func(t *testing.T) {
			err := validateNodesControlChars(
				build([]string{"interfaces", "ge-0/0/0"}, "description", "\t"+plain), "")
			if err == nil {
				t.Fatal("expected rejection")
			}
			if want := strconv.Quote("\t" + plain); !strings.Contains(err.Error(), want) {
				t.Fatalf("a NON-secret leaf must still render its value as %s — blanket "+
					"suppression is a lost diagnostic, not a fix. got:\n%v", want, err)
			}
		})
		t.Run(shape+"/lenient", func(t *testing.T) {
			tree := &ConfigTree{Children: build([]string{"interfaces", "ge-0/0/0"}, "description", "\t"+plain)}
			got := SanitizeTreeControlChars(tree)
			if len(got) != 1 || !strings.Contains(got[0], plain) {
				t.Fatalf("the lenient path must still NAME a non-secret value: %q", got)
			}
		})
	}
}

// TestPolicyOptionsCommunityStaysLegible_7395 pins the #4097 diagnostic that
// motivates root-gating `community`: under snmp it is the credential, under
// policy-options it is a BGP route-target name and the operator needs to see
// WHICH member carried the newline. The union of the two secret resolutions
// must not blanket-redact it.
func TestPolicyOptionsCommunityStaysLegible_7395(t *testing.T) {
	const rt = "65000:100"
	err := validateNodesControlChars(
		flatLeaf7395([]string{"policy-options"}, "community", "\t"+rt), "")
	if err == nil {
		t.Fatal("expected rejection")
	}
	if !strings.Contains(err.Error(), rt) {
		t.Fatalf("a policy-options community is a route target, not a credential, and must "+
			"stay legible (#4097). got:\n%v", err)
	}
}

// TestBothSecretResolutionsAgree_7395 binds the tree's TWO secret-leaf lists
// together.
//
// #6625 added secretLeafKeywords (secret.go) beside the secretIndices
// resolution the raw-AST display paths already used (ast_redact.go). Two lists
// answering one question is how the next credential keyword gets added to one
// and not the other — and the drift is silent in the direction that matters: a
// leaf redacted in `show configuration` but echoed by a commit error.
//
// The validators now take their UNION, so neither list alone can under-redact.
// This asserts the union actually covers each list, which is what makes that
// claim true rather than aspirational.
func TestBothSecretResolutionsAgree_7395(t *testing.T) {
	for kw := range secretLeafKeywords {
		fp := []string{"chassis", "cluster", kw, sentinel7395}
		if !isSecretValueIndex(fp, 3) {
			t.Errorf("secretLeafKeywords lists %q but the validators' resolution does not "+
				"mark its value secret — a credential the commit error would publish", kw)
		}
	}
	// And the reverse: everything secretIndices knows must be covered too.
	for _, tc := range []struct {
		fp  []string
		idx int
	}{
		{[]string{"system", "snmp", "community", sentinel7395}, 3},
		{[]string{"protocols", "ospf", "area", "0", "interface", "ge-0/0/0",
			"authentication", "md5", "1", "key", sentinel7395}, 10},
		{[]string{"system", "services", "dynamic-dns", "provider", "p1",
			"aws-secret-key", sentinel7395}, 6},
	} {
		if !isSecretValueIndex(tc.fp, tc.idx) {
			t.Errorf("secretIndices marks %v[%d] secret but the validators' resolution does not",
				tc.fp, tc.idx)
		}
	}
}
