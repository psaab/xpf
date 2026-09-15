package config

import (
	"reflect"
	"testing"
)

// These use explicit inet so they reproduce on the pre-#9899 base, before the
// shallower implicit-inet schema exposes them to the general-purpose censuses.
func TestFlexMatchRunConservation9899(t *testing.T) {
	for _, shape := range []string{"braced-run", "flat-run", "packed-range"} {
		var tree *ConfigTree
		if shape == "flat-run" {
			tree = buildFilterTree(t,
				"set firewall family inet filter F term T from flexible-match-range range R bit-length 8 byte-offset 9",
				"set firewall family inet filter F term T from flexible-match-range range R match-value 0x11",
				"set firewall family inet filter F term T then discard")
		} else if shape == "packed-range" {
			tree = fwTree9875(t, `term T { from { flexible-match-range { range R bit-length 8 byte-offset 9 match-value 0x11; } } then { discard; } }`)
		} else {
			tree = fwTree9875(t, `term T { from { flexible-match-range { range R { bit-length 8 byte-offset 9; match-value 0x11; } } } then { discard; } }`)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatal(err)
		}
		term := firstInetTerm(t, cfg, "F")
		want := &FlexMatchConfig{MatchStart: "layer-3", BitLength: 8, ByteOffset: 9, Value: 0x11, Mask: 0xFF}
		if !reflect.DeepEqual(term.FlexMatch, want) || len(term.UnknownFlexMatch) != 0 {
			t.Errorf("%s: run lost configured match fields: got=%+v unknown=%q want=%+v", shape, term.FlexMatch, term.UnknownFlexMatch, want)
		}
	}
}

func TestFlexMatchSameNameConservation9899(t *testing.T) {
	for _, body := range []string{
		`from { flexible-match-range { range R { byte-offset 9; } range R { bit-length 8; match-value 0x11; } } }`,
		`from { flexible-match-range { range R { byte-offset 9; } } } from { flexible-match-range { range R { bit-length 8; match-value 0x11; } } }`,
		`from { flexible-match-range { range { R { byte-offset 9; } R { bit-length 8; match-value 0x11; } } } }`,
	} {
		tree := fwTree9875(t, `term T { `+body+` then { discard; } }`)
		before := tree.Clone()
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Errorf("same named range must merge: %v", err)
			continue
		}
		term := firstInetTerm(t, cfg, "F")
		want := &FlexMatchConfig{MatchStart: "layer-3", BitLength: 8, ByteOffset: 9, Value: 0x11, Mask: 0xFF}
		if !reflect.DeepEqual(term.FlexMatch, want) || !reflect.DeepEqual(term.FlexMatchRangeNames, []string{"R"}) {
			t.Errorf("same-name blocks lost fields or defaulted before merge: got=%+v names=%q want=%+v", term.FlexMatch, term.FlexMatchRangeNames, want)
		}
		if !reflect.DeepEqual(tree, before) {
			t.Fatal("compilation mutated candidate")
		}
	}
	tree := fwTree9875(t, `term T { from { flexible-match-range { range R { byte-offset 9; } range S { bit-length 8; } } } then { discard; } }`)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("distinct ranges bypassed the existing cardinality gate")
	}
}
