package config

import (
	_ "embed"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// #16163 Phase A (R6A): schemaNode invariant census.
//
// This is a census/test ONLY. It adds, removes, and renames NO schemaNode
// field and introduces NO constructor (typedLeaf/enumLeaf/... are Phase B
// and stay deferred until this allow-list burns down). It is a
// differently-filtered second instrument over the existing setSchema
// literals: it walks the live tree by pointer identity (so shared nodes
// reachable under `groups <*>`, routing-instances, and RI protocols are
// counted once, with their first reachable path as the identity) and
// asserts the invariants that schema.go's comments document but nothing
// policed:
//
//	R1  validator / treeValidator are mutually exclusive (schema.go:294).
//	R2  tailValidator owns acceptance: validator MUST be nil (schema.go:316).
//	    treeValidator is in the same per-token slot checkValue picks before
//	    the tail branch can ever run, so it is exclusive with tail too.
//	R3  keyValidator / keyValidatorPos are mutually exclusive (schema.go:340).
//	R4  a validator without a non-ValueAny valueType is silently never
//	    invoked (#9206, value_type.go:118-123: the typed-leaf walk arm is
//	    the conjunction isTypedLeaf() && validator != nil). Exception: a
//	    tailValidator leaf, whose acceptance is owned by the tail path and
//	    whose valueType is completion-only — its validator is already
//	    forbidden by R2, so R4's validator here means validator/treeValidator.
//	R4b the reverse direction, for EVERY valueType (not just the R9 enum
//	    leaves): valueType != ValueAny with no validator, treeValidator,
//	    tailValidator, or nodeValidator is completion-only — the typed
//	    walk arm never fires, so the advertised type checks nothing.
//	    Same for keyValueType != ValueAny with no keyValidator/
//	    keyValidatorPos.
//	R5  a nodeValidator only runs on an exact schema-key match and is
//	    unreachable when a tailValidator on the same node takes precedence
//	    in walkSchemaNode (tail dispatch returns before the nodeValidator
//	    arm), so tailValidator+nodeValidator means one of them is dead.
//	R6  a typed value slot (valueType != ValueAny) and a typed key slot
//	    (keyValidator/keyValidatorPos/keyValueType) must not both be set on
//	    one node: schema.go:326-329 forbids valueType on a key-slot
//	    container because it flips the walker into the typed-LEAF branch.
//	    The sole legitimate shape is the syslog wildcard leaf, whose
//	    keyword IS its facility identity and whose value IS its severity —
//	    it carries keyValidator AND valueType on a wildcard node by design
//	    (#6844/#2008). Those four shared destinations are allow-listed.
//	R7  scalar:true is only honoured when isScalarValueLeaf() holds; a
//	    scalar tag on a typed/multi/container node silently degrades to a
//	    no-op (schema.go:379-382), which hides that the author expected
//	    trailing-token rejection that never runs.
//	R8  midKeyword and midKeywordAt must be set together (the walk and
//	    completion both test midKeyword != "" and index by midKeywordAt).
//	R9  (enum census, test-only — never a 37th schemaNode field): every
//	    ValueEnumOf leaf that carries valueExamples must have every example
//	    accepted by its own validator/treeValidator (an example the gate
//	    rejects teaches the operator a spelling commit refuses) and every
//	    example must surface in `?` completion for the value slot.
//	    treeValidator leaves are probed against an empty schemaRefs (their
//	    examples are built-in names that must validate with no candidate
//	    definitions); a validator panic is reported as a violation.
//	R10 value metadata without a type (valueDesc/valueExamples with
//	    valueType == ValueAny) never surfaces through the typed-value
//	    completion arm and never validates: appendTypedValueCompletions
//	    returns early on !isTypedLeaf, and validateTypedLeaf is only
//	    reached for typed leaves. Same for keyValueDesc/keyValueExamples
//	    with keyValueType == ValueAny (appendTypedKeyCompletions returns
//	    early). A keyValidator WITHOUT keyValueType is NOT a violation:
//	    key validation predates the typed-key metadata and does not
//	    require it — only dead key DESC/EXAMPLES are flagged.
//
// Violations found on the initial tree are recorded in
// testdata/schema_node_violations_16163.txt, one `<rule> | <path> | <reason>`
// per line. The test asserts set-equality in BOTH directions against the
// CURRENT tree: a new violation reds, and a fixed violation whose line
// stays reds. Monotonicity is anchored separately to a recorded
// BASELINE (schemaNodeBaseline16163, the initial 10-entry key set frozen
// below): the allow-list must always be a SUBSET of that baseline, so
// deleting a line and re-adding a different violation can never launder
// a new defect through a same-size list — shrink-only is measured
// against the baseline, not just against today's equality. Each
// allow-listed entry carries a reason so the burn-down is auditable; an
// entry without a reason, a duplicate entry, or an entry for a path/rule
// that does not exist fails the test.
//
// Positive control: TestSchemaNodeCensusSeededViolations16163 builds
// fixture nodes locally (never inserted into setSchema) with each seeded
// defect and requires the census predicate to report exactly the seeded
// rule(s) — including the issue's canonical validator+tailValidator node —
// and to stay silent on a well-formed typed leaf, enum leaf, key-slot
// container, tail leaf, and scalar leaf. A census that cannot see a seeded
// violation cannot be trusted when it reports the real tree clean.

//go:embed testdata/schema_node_violations_16163.txt
var schemaNodeAllowlist16163 string

// schemaNodeBaseline16163 is the frozen initial violation key set
// (rule | path) recorded when the census first landed (#16163, head
// 59fb3928f0, 1882 unique nodes, 10 entries). It is the monotonic
// anchor: the allow-list file must remain a subset of this set for
// the life of the census. Fixing a violation REMOVES its line from
// the file (this entry stays as history); adding any key not in this
// set — even by swapping it for a fixed one — fails the test. Entries
// here may be deleted only in the same commit that deletes the
// corresponding allow-list line after the violation is verifiably
// gone from the tree.
var schemaNodeBaseline16163 = map[string]bool{
	"scalar-not-honoured | groups <*> security zones security-zone advanced-connection-tracking mode":    true,
	"scalar-not-honoured | groups <*> security zones security-zone advanced-connection-tracking timeout": true,
	"scalar-not-honoured | groups <*> security zones security-zone white-list":                           true,
	"scalar-not-honoured | groups <*> system host-name":                                                  true,
	"scalar-not-honoured | groups <*> system services dhcp-local-server dhcp-socket-type":                true,
	"valueType+keySlot | groups <*> system syslog console <*>":                                           true,
	"valueType+keySlot | groups <*> system syslog file <*>":                                              true,
	"valueType+keySlot | groups <*> system syslog host <*>":                                              true,
	"valueType+keySlot | groups <*> system syslog user <*>":                                              true,
	"valueMetadata-without-valueType | groups <*> policy-options policy-statement term from protocol":    true,
}

type censusNode16163 struct {
	path string
	node *schemaNode
}

// collectCensusNodes16163 walks setSchema by pointer identity. Shared
// subtrees (groups mirrors, RI protocols, syslog destinations) appear
// once, keyed by their first reachable path; every later alias of the
// same pointer is not re-reported, because a violation is a property of
// the node literal, not of how many paths reach it.
func collectCensusNodes16163() []censusNode16163 {
	seen := map[*schemaNode]bool{}
	var out []censusNode16163
	var walk func(path string, n *schemaNode)
	walk = func(path string, n *schemaNode) {
		if n == nil || seen[n] {
			return
		}
		seen[n] = true
		p := path
		if p == "" {
			p = "<root>"
		}
		out = append(out, censusNode16163{path: p, node: n})
		keys := make([]string, 0, len(n.children))
		for k := range n.children {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			walk(strings.TrimSpace(path+" "+k), n.children[k])
		}
		if n.wildcard != nil {
			walk(strings.TrimSpace(path+" <*>"), n.wildcard)
		}
	}
	walk("", setSchema)
	return out
}

// censusViolations16163 returns "RULE | path" keys (reason is carried by
// the allow-list file, not recomputed here) for one node.
func censusViolations16163(path string, n *schemaNode) []string {
	var out []string
	add := func(rule string) { out = append(out, rule+" | "+path) }
	if n.validator != nil && n.treeValidator != nil {
		add("validator+treeValidator")
	}
	if n.tailValidator != nil && n.validator != nil {
		add("tailValidator+validator")
	}
	if n.tailValidator != nil && n.treeValidator != nil {
		add("tailValidator+treeValidator")
	}
	if n.keyValidator != nil && n.keyValidatorPos != nil {
		add("keyValidator+keyValidatorPos")
	}
	hasPerToken := n.validator != nil || n.treeValidator != nil
	if hasPerToken && n.valueType == ValueAny {
		// tailValidator leaves cannot reach here with a per-token
		// validator without also tripping R2 above; the conjunction
		// that silences them is isTypedLeaf()==false.
		add("validator-without-valueType")
	}
	// Reverse direction (all types, not just ValueEnumOf/R9): a typed
	// value slot with NO validator of any kind is completion-only —
	// SchemaValidate's typed arm requires validator||treeValidator, so
	// the value is never checked while `?` advertises it as typed.
	// A tailValidator owns its slot, and a nodeValidator may own the
	// whole node (e.g. security log host), so both count as owners.
	if n.valueType != ValueAny && !hasPerToken && n.tailValidator == nil && n.nodeValidator == nil {
		add("valueType-without-validator")
	}
	// Key-slot mirror: a typed key slot whose examples/desc surface in
	// completion but which no key validator ever checks.
	if n.keyValueType != ValueAny && n.keyValidator == nil && n.keyValidatorPos == nil {
		add("keyValueType-without-keyValidator")
	}
	if n.tailValidator != nil && n.nodeValidator != nil {
		add("tailValidator+nodeValidator")
	}
	keySlot := n.keyValidator != nil || n.keyValidatorPos != nil || n.keyValueType != ValueAny
	if n.valueType != ValueAny && keySlot {
		add("valueType+keySlot")
	}
	if n.scalar && !n.isScalarValueLeaf() {
		add("scalar-not-honoured")
	}
	if (n.midKeyword == "") != (n.midKeywordAt == 0) {
		add("midKeyword-mismatch")
	}
	// R10: dead metadata (no type => never surfaced by the value arm).
	// A tailValidator owns its own completion via its valueType, so a
	// tail node is checked by the same rule without exception: with
	// valueType==ValueAny its examples are equally dead.
	if n.valueType == ValueAny && (n.valueDesc != "" || len(n.valueExamples) > 0) {
		add("valueMetadata-without-valueType")
	}
	if n.keyValueType == ValueAny && (n.keyValueDesc != "" || len(n.keyValueExamples) > 0) {
		add("keyMetadata-without-keyValueType")
	}
	return out
}

func parseAllowlist16163(t *testing.T, raw string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for i, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, " | ")
		if len(parts) != 3 {
			t.Fatalf("allow-list line %d malformed (want `<rule> | <path> | <reason>`): %q", i+1, line)
		}
		key := parts[0] + " | " + parts[1]
		if parts[2] == "" {
			t.Fatalf("allow-list line %d has empty reason: %q", i+1, line)
		}
		if _, dup := out[key]; dup {
			t.Fatalf("allow-list duplicate entry: %q", key)
		}
		out[key] = parts[2]
	}
	return out
}

func TestSchemaNodeInvariantCensus16163(t *testing.T) {
	nodes := collectCensusNodes16163()
	if len(nodes) < 1000 {
		t.Fatalf("census walked only %d unique schemaNodes; setSchema walk is broken (want >1000)", len(nodes))
	}
	got := map[string]bool{}
	var gotList []string
	for _, cn := range nodes {
		for _, v := range censusViolations16163(cn.path, cn.node) {
			if !got[v] {
				got[v] = true
				gotList = append(gotList, v)
			}
		}
	}
	// R9 enum census (also a violation source, keyed separately).
	for _, v := range enumCensusViolations16163(t, nodes) {
		if !got[v] {
			got[v] = true
			gotList = append(gotList, v)
		}
	}
	sort.Strings(gotList)

	allow := parseAllowlist16163(t, schemaNodeAllowlist16163)

	// Monotonic baseline: the allow-list may only ever SHRINK relative
	// to the frozen initial set. An entry outside the baseline means a
	// post-landing violation was allow-listed instead of fixed — even
	// if a fixed entry was removed in the same change to keep the size
	// constant. This is checked independently of the current-tree
	// equality below, which alone cannot distinguish that swap.
	var outsideBaseline []string
	for k := range allow {
		if !schemaNodeBaseline16163[k] {
			outsideBaseline = append(outsideBaseline, k)
		}
	}
	sort.Strings(outsideBaseline)
	if len(outsideBaseline) > 0 {
		t.Errorf("%d allow-list entr(ies) OUTSIDE the frozen #16163 baseline (the list may only shrink vs the baseline, never grow or swap):\n%s",
			len(outsideBaseline), strings.Join(outsideBaseline, "\n"))
	}
	if len(allow) > len(schemaNodeBaseline16163) {
		t.Errorf("allow-list size %d exceeds baseline size %d (shrink-only violated)", len(allow), len(schemaNodeBaseline16163))
	}

	var newViolations, stale []string
	for _, v := range gotList {
		if _, ok := allow[v]; !ok {
			newViolations = append(newViolations, v)
		}
	}
	for k := range allow {
		if !got[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	if len(newViolations) > 0 {
		t.Errorf("%d NEW schemaNode invariant violation(s) not in %s (fix the node, or if deliberate add a line with a reason — the list may only shrink):\n%s",
			len(newViolations), "testdata/schema_node_violations_16163.txt", strings.Join(newViolations, "\n"))
	}
	if len(stale) > 0 {
		t.Errorf("%d STALE allow-list entr(ies) in %s no longer violate (remove the line — the list may only shrink):\n%s",
			len(stale), "testdata/schema_node_violations_16163.txt", strings.Join(stale, "\n"))
	}
	t.Logf("schemaNode census: %d unique nodes, %d allow-listed violation(s) across %d node(s)",
		len(nodes), len(gotList), countViolatedNodes16163(nodes))
}

func countViolatedNodes16163(nodes []censusNode16163) int {
	c := 0
	for _, cn := range nodes {
		if len(censusViolations16163(cn.path, cn.node)) > 0 {
			c++
		}
	}
	return c
}

// enumCensusViolations16163 implements R9. It returns violation keys for
// ValueEnumOf leaves whose examples fail their own validator or do not
// appear in completion. treeValidator leaves are validated against an
// empty schemaRefs (their examples are built-in names that must validate
// without any candidate-tree definition); a panic is a violation, not a
// skip, because an example that panics the validator is not an example.
func enumCensusViolations16163(t *testing.T, nodes []censusNode16163) []string {
	t.Helper()
	var out []string
	for _, cn := range nodes {
		n := cn.node
		if n.valueType != ValueEnumOf {
			continue
		}
		if n.validator == nil && n.treeValidator == nil && n.tailValidator == nil {
			out = append(out, "enum-without-validator | "+cn.path)
			continue
		}
		for _, ex := range n.valueExamples {
			if err := enumExampleErr16163(n, ex); err != nil {
				out = append(out, fmt.Sprintf("enum-example-rejected | %s | example %q: %v", cn.path, ex, err))
			}
			if !enumExampleInCompletion16163(n, ex) {
				out = append(out, "enum-example-not-in-completion | "+cn.path+" | example "+ex)
			}
		}
	}
	return out
}

func enumExampleErr16163(n *schemaNode, ex string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("validator panicked: %v", r)
		}
	}()
	if n.validator != nil {
		return n.validator(ex, nil)
	}
	if n.treeValidator != nil {
		return n.treeValidator(ex, &schemaRefs{})
	}
	return nil // tailValidator owns the whole tail; single-token probe N/A
}

func enumExampleInCompletion16163(n *schemaNode, ex string) bool {
	for _, c := range appendTypedValueCompletions(nil, n) {
		if c.Name == ex {
			return true
		}
	}
	return false
}

// TestSchemaNodeCensusSeededViolations16163 is the positive control. Each
// fixture is a local node (never part of setSchema) carrying exactly the
// seeded defect(s); the census MUST name the expected rule and MUST NOT
// invent others. Without this, a predicate bug that reports nothing would
// pass the census above on any tree.
func TestSchemaNodeCensusSeededViolations16163(t *testing.T) {
	accept := func(string, *Config) error { return nil }
	acceptTree := func(string, *schemaRefs) error { return nil }
	acceptTail := func([]string, [][]string) error { return nil }
	acceptNode := func(*Node, *schemaNode) error { return nil }
	acceptPos := func(int, string, *Config) error { return nil }

	cases := []struct {
		name string
		node *schemaNode
		want []string // rule prefixes
	}{
		{
			name: "validator plus tailValidator (issue canonical seed)",
			node: &schemaNode{desc: "x", args: 1, valueType: ValueEnumOf, validator: accept, tailValidator: acceptTail},
			want: []string{"tailValidator+validator"},
		},
		{
			name: "validator plus treeValidator",
			node: &schemaNode{desc: "x", args: 1, valueType: ValueEnumOf, validator: accept, treeValidator: acceptTree},
			want: []string{"validator+treeValidator"},
		},
		{
			name: "keyValidator plus keyValidatorPos",
			node: &schemaNode{desc: "x", args: 2, keyValidator: accept, keyValidatorPos: acceptPos, children: map[string]*schemaNode{}},
			want: []string{"keyValidator+keyValidatorPos"},
		},
		{
			name: "validator without valueType (#9206 silent leaf)",
			node: &schemaNode{desc: "x", args: 1, validator: accept},
			want: []string{"validator-without-valueType"},
		},
		{
			name: "tailValidator plus nodeValidator (dead arm)",
			node: &schemaNode{desc: "x", args: 1, valueType: ValueRateOrPercent, tailValidator: acceptTail, nodeValidator: acceptNode},
			want: []string{"tailValidator+nodeValidator"},
		},
		{
			name: "valueType on key-slot container",
			node: &schemaNode{desc: "x", args: 1, valueType: ValueCIDR, validator: accept, keyValidator: accept, children: map[string]*schemaNode{}},
			want: []string{"valueType+keySlot"},
		},
		{
			name: "scalar on typed leaf (tag silently ignored)",
			node: &schemaNode{desc: "x", args: 1, scalar: true, valueType: ValueInteger, validator: accept},
			want: []string{"scalar-not-honoured"},
		},
		{
			name: "midKeyword without position",
			node: &schemaNode{desc: "x", args: 2, midKeyword: "to-zone"},
			want: []string{"midKeyword-mismatch"},
		},
		{
			name: "well-formed typed leaf stays silent",
			node: &schemaNode{desc: "x", args: 1, valueType: ValueInteger, valueDesc: "n", valueExamples: []string{"1"}, validator: accept},
			want: nil,
		},
		{
			name: "well-formed tail leaf stays silent",
			node: &schemaNode{desc: "x", args: 1, valueType: ValueRateOrPercent, valueExamples: []string{"10m"}, tailValidator: acceptTail},
			want: nil,
		},
		{
			name: "well-formed key-slot container stays silent",
			node: &schemaNode{desc: "x", args: 1, keyValueType: ValueCIDR, keyValueDesc: "cidr", keyValueExamples: []string{"10.0.0.0/24"}, keyValidator: accept, children: map[string]*schemaNode{}},
			want: nil,
		},
		{
			name: "well-formed scalar leaf stays silent",
			node: &schemaNode{desc: "x", args: 1, scalar: true},
			want: nil,
		},
		{
			name: "well-formed enum leaf stays silent",
			node: &schemaNode{desc: "x", args: 1, valueType: ValueEnumOf, valueDesc: "a|b", valueExamples: []string{"a"}, validator: ValidateEnum([]string{"a", "b"})},
			want: nil,
		},
		{
			name: "valueType without any validator (R4b, non-enum)",
			node: &schemaNode{desc: "x", args: 1, valueType: ValueInteger, valueDesc: "n", valueExamples: []string{"1"}},
			want: []string{"valueType-without-validator"},
		},
		{
			name: "keyValueType without key validator (R4b key slot)",
			node: &schemaNode{desc: "x", args: 1, keyValueType: ValueCIDR, keyValueDesc: "cidr", children: map[string]*schemaNode{}},
			want: []string{"keyValueType-without-keyValidator"},
		},
		{
			name: "tail-owned typed leaf stays silent under R4b",
			node: &schemaNode{desc: "x", args: 1, valueType: ValueRateOrPercent, tailValidator: acceptTail},
			want: nil,
		},
		{
			name: "nodeValidator-owned typed leaf stays silent under R4b",
			node: &schemaNode{desc: "x", args: 1, valueType: ValueHostname, nodeValidator: acceptNode},
			want: nil,
		},
	}
	for _, tc := range cases {
		got := censusViolations16163("fixture "+tc.name, tc.node)
		var gotRules []string
		for _, g := range got {
			gotRules = append(gotRules, strings.SplitN(g, " | ", 2)[0])
		}
		sort.Strings(gotRules)
		want := append([]string(nil), tc.want...)
		sort.Strings(want)
		if strings.Join(gotRules, ",") != strings.Join(want, ",") {
			t.Errorf("%s: census rules = %v, want %v (full: %v)", tc.name, gotRules, want, got)
		}
	}

	// Enum positive control: an example its own validator rejects must red.
	bad := &schemaNode{desc: "x", args: 1, valueType: ValueEnumOf, valueExamples: []string{"bogus"}, validator: ValidateEnum([]string{"a", "b"})}
	viol := enumCensusViolations16163(t, []censusNode16163{{path: "fixture bad-enum", node: bad}})
	if len(viol) == 0 || !strings.Contains(strings.Join(viol, "\n"), "enum-example-rejected") {
		t.Errorf("seeded bad enum example not caught by R9 census: %v", viol)
	}
	// And the seeded validator+tailValidator node, inserted as a fixture
	// node list, is caught by the full predicate (not just the unit arm).
	seeded := &schemaNode{desc: "x", args: 1, valueType: ValueEnumOf, validator: accept, tailValidator: acceptTail}
	if v := censusViolations16163("fixture seeded", seeded); len(v) != 1 || !strings.HasPrefix(v[0], "tailValidator+validator") {
		t.Errorf("seeded validator+tailValidator fixture: got %v, want exactly [tailValidator+validator]", v)
	}
}

// TestDNSProxyDefaultDomainWildcard16163 pins the #16163 fold fix: the
// dns-proxy default-domain leaf documents `*` as "for all domains" and
// TestDNSProxyWarned strict-compiles that spelling, so its validator
// must accept `*` explicitly while still rejecting malformed domains —
// and plain ValidateDNSDomain (system domain-name, DHCP pool domains)
// must keep rejecting `*`, because the wildcard is a dns-proxy-only
// named exception, not a domain.
func TestDNSProxyDefaultDomainWildcard16163(t *testing.T) {
	for _, ok := range []string{"*", "example.net", "corp.example.net."} {
		if err := ValidateDNSProxyDefaultDomain(ok, nil); err != nil {
			t.Errorf("ValidateDNSProxyDefaultDomain(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"bad_domain", "-bad.net", "exa mple.net", "**"} {
		if err := ValidateDNSProxyDefaultDomain(bad, nil); err == nil {
			t.Errorf("ValidateDNSProxyDefaultDomain(%q) = nil, want rejection", bad)
		}
	}
	if err := ValidateDNSDomain("*", nil); err == nil {
		t.Error("ValidateDNSDomain(\"*\") = nil, want rejection (wildcard is dns-proxy-only)")
	}
	// Strict commit path: the documented wildcard spelling must survive
	// SchemaValidate (this is the exact arm TestDNSProxyWarned exercises
	// through CompileConfig's gate in configstore, probed directly here).
	tree := &ConfigTree{}
	path, err := ParseSetCommand("set system services dns dns-proxy default-domain *")
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatal(err)
	}
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate must accept dns-proxy default-domain *: %v", err)
	}
	badTree := &ConfigTree{}
	badPath, err := ParseSetCommand("set system services dns dns-proxy default-domain bad_domain")
	if err != nil {
		t.Fatal(err)
	}
	if err := badTree.SetPath(badPath); err != nil {
		t.Fatal(err)
	}
	if err := SchemaValidate(badTree, nil); err == nil {
		t.Fatal("SchemaValidate must reject dns-proxy default-domain bad_domain")
	}
}
