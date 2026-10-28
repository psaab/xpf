package config

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// #17172: `security ike gateway` and `security ipsec gateway` were two
// hand-copied schema literals plus two hand-copied compiler readers. They
// diverged twice: #13540 in the reader, and the DPD packedStatements flag
// in the schema (braced packed DPD passed under `ike`, false-rejected
// under `ipsec`). Both now come from gatewaySchemaNode /
// compileGatewayInstances. This test is the parity guard: it reflect-diffs
// every comparable schemaNode field of the two subtrees, asserts fresh
// pointers (identity-keyed censuses must still see two paths), and pins
// the production CheckText-equivalent strict gate for the braced packed
// DPD spelling under both parents. Flipping one field on one parent (the
// pre-fix DPD divergence) must red this test — verified by mutation.

func gatewaySubtree17172(t *testing.T, parent string) *schemaNode {
	t.Helper()
	sec := setSchema.children["security"]
	if sec == nil {
		t.Fatal("security schema missing")
	}
	branch := sec.children[parent]
	if branch == nil {
		t.Fatalf("security %s missing", parent)
	}
	gw := branch.children["gateway"]
	if gw == nil {
		t.Fatalf("security %s gateway missing", parent)
	}
	return gw
}

// diffGatewayNodes17172 compares all scalar schemaNode fields and recurses
// into children/wildcard. Func fields (validators) cannot be compared by
// value; they are compared by presence and by behaviour on probe inputs at
// the caller for typed leaves. Slices are compared elementwise.
func diffGatewayNodes17172(t *testing.T, path string, a, b *schemaNode) {
	t.Helper()
	if a == nil || b == nil {
		t.Errorf("%s: nil mismatch ike=%v ipsec=%v", path, a != nil, b != nil)
		return
	}
	if a == b {
		t.Errorf("%s: ike and ipsec share the same *schemaNode pointer — factory must return fresh pointers per call (identity-keyed censuses)", path)
	}
	type scalars struct {
		args, midKeywordAt, keyValueType, valueType                   int
		desc, placeholder, midKeyword, packedValueSibling, valueDesc  string
		multi, absorbBeforeWildcard, allChildKeysAreValues, valueList bool
		packedTail, packedStatements, blockValue, groupReplace        bool
		rangeSeparator, scalar, allowEmptyValue, identityBareDN       bool
		compoundKey, closedWorld, closedWorldOpaque, packedFlatRun    bool
	}
	sa := scalars{a.args, a.midKeywordAt, int(a.keyValueType), int(a.valueType), a.desc, a.placeholder, a.midKeyword, a.packedValueSibling, a.valueDesc, a.multi, a.absorbBeforeWildcard, a.allChildKeysAreValues, a.valueList, a.packedTail, a.packedStatements, a.blockValue, a.groupReplace, a.rangeSeparator, a.scalar, a.allowEmptyValue, a.identityBareDN, a.compoundKey, a.closedWorld, a.closedWorldOpaque, a.packedFlatRun}
	sb := scalars{b.args, b.midKeywordAt, int(b.keyValueType), int(b.valueType), b.desc, b.placeholder, b.midKeyword, b.packedValueSibling, b.valueDesc, b.multi, b.absorbBeforeWildcard, b.allChildKeysAreValues, b.valueList, b.packedTail, b.packedStatements, b.blockValue, b.groupReplace, b.rangeSeparator, b.scalar, b.allowEmptyValue, b.identityBareDN, b.compoundKey, b.closedWorld, b.closedWorldOpaque, b.packedFlatRun}
	if sa != sb {
		t.Errorf("%s: scalar fields differ\n ike=%+v\n ipsec=%+v", path, sa, sb)
	}
	if !reflect.DeepEqual(a.valueExamples, b.valueExamples) {
		t.Errorf("%s: valueExamples differ %q vs %q", path, a.valueExamples, b.valueExamples)
	}
	if !reflect.DeepEqual(a.keyValueExamples, b.keyValueExamples) {
		t.Errorf("%s: keyValueExamples differ %q vs %q", path, a.keyValueExamples, b.keyValueExamples)
	}
	if !reflect.DeepEqual(a.valueDesc, b.valueDesc) || a.keyValueDesc != b.keyValueDesc {
		t.Errorf("%s: valueDesc/keyValueDesc differ", path)
	}
	// Func-typed fields: presence parity (behaviour parity for typed leaves
	// is exercised via SchemaValidate cells below).
	if (a.validator == nil) != (b.validator == nil) {
		t.Errorf("%s: validator presence differs", path)
	}
	if (a.treeValidator == nil) != (b.treeValidator == nil) {
		t.Errorf("%s: treeValidator presence differs", path)
	}
	if (a.nodeValidator == nil) != (b.nodeValidator == nil) {
		t.Errorf("%s: nodeValidator presence differs", path)
	}
	if (a.tailValidator == nil) != (b.tailValidator == nil) {
		t.Errorf("%s: tailValidator presence differs", path)
	}
	if (a.keyValidator == nil) != (b.keyValidator == nil) {
		t.Errorf("%s: keyValidator presence differs", path)
	}
	if (a.keyValidatorPos == nil) != (b.keyValidatorPos == nil) {
		t.Errorf("%s: keyValidatorPos presence differs", path)
	}
	if (a.blockChildValidator == nil) != (b.blockChildValidator == nil) {
		t.Errorf("%s: blockChildValidator presence differs", path)
	}
	if a.valueHint != b.valueHint {
		t.Errorf("%s: valueHint differs %v vs %v", path, a.valueHint, b.valueHint)
	}
	// Children keys.
	var ka, kb []string
	for k := range a.children {
		ka = append(ka, k)
	}
	for k := range b.children {
		kb = append(kb, k)
	}
	sort.Strings(ka)
	sort.Strings(kb)
	if !reflect.DeepEqual(ka, kb) {
		t.Errorf("%s: children differ %v vs %v", path, ka, kb)
		return
	}
	for _, k := range ka {
		diffGatewayNodes17172(t, path+"/"+k, a.children[k], b.children[k])
	}
	if (a.wildcard == nil) != (b.wildcard == nil) {
		t.Errorf("%s: wildcard presence differs", path)
	} else if a.wildcard != nil {
		diffGatewayNodes17172(t, path+"/*", a.wildcard, b.wildcard)
	}
}

func TestGatewayGrammarsIdentical17172(t *testing.T) {
	ike := gatewaySubtree17172(t, "ike")
	ipsec := gatewaySubtree17172(t, "ipsec")
	// Positive control: grammar is non-trivial.
	if len(ike.children) < 10 {
		t.Fatalf("positive control: ike gateway has only %d children", len(ike.children))
	}
	if _, ok := ike.children["local-identity"]; !ok {
		t.Fatal("positive control: local-identity missing under ike gateway")
	}
	diffGatewayNodes17172(t, "gateway", ike, ipsec)
	// Validator closures cannot be compared by value; their behaviour
	// parity is covered by the SchemaValidate cells in
	// TestGatewayBracedPackedDPDIdentical17172 (typed DPD leaves).
}

func TestGatewayBracedPackedDPDIdentical17172(t *testing.T) {
	// The live pre-fix divergence: braced packed DPD under ipsec was
	// false-rejected ("unknown modifier threshold") while ike accepted.
	// Assert identical strict SchemaValidate + compiled DPD values.
	for _, parent := range []string{"ike", "ipsec"} {
		t.Run(parent, func(t *testing.T) {
			text := fmt.Sprintf("security { %s { gateway g1 { dead-peer-detection { interval 20 threshold 3; } } } }", parent)
			tree, perrs := NewParser(text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse: %v", perrs[0])
			}
			if err := SchemaValidate(tree); err != nil {
				t.Fatalf("SchemaValidate rejected braced packed DPD under %s: %v", parent, err)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			gw := cfg.Security.IPsec.Gateways["g1"]
			if gw == nil {
				t.Fatal("gateway g1 not compiled")
			}
			if !gw.DPDEnable || gw.DPDInterval != 20 || gw.DPDThreshold != 3 {
				t.Fatalf("DPD compiled = enable=%v interval=%d threshold=%d, want true/20/3", gw.DPDEnable, gw.DPDInterval, gw.DPDThreshold)
			}
		})
	}
	// Typed-value behaviour parity under both parents (validator closures
	// must agree, not just be present).
	for _, parent := range []string{"ike", "ipsec"} {
		tree, perrs := NewParser(fmt.Sprintf("security { %s { gateway g1 { dead-peer-detection { interval banana; } } } }", parent)).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse %s: %v", parent, perrs[0])
		}
		if err := SchemaValidate(tree); err == nil || !strings.Contains(err.Error(), "banana") {
			t.Errorf("%s: interval banana must be rejected naming the value, got %v", parent, err)
		}
	}
}
