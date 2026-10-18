package cmdtree

import (
	"strings"
	"testing"
)

// #14688: after a dynamic value, Canonicalize must not resolve sibling
// modifiers that take no selector (interfaces terse/queue/statistics/
// tunnel, zones terse) or repeated filter keys (CoS name/type).

func TestCanonicalizePostDynamicSibling14688(t *testing.T) {
	for _, line := range []string{
		"show interfaces ge-0/0/0 terse",
		"show interfaces ge-0/0/0 queue",
		"show interfaces ge-0/0/0 queue detail",
		"show interfaces ge-0/0/0 statistics",
		"show interfaces ge-0/0/0 tunnel",
		"show security zones trust terse",
		"show class-of-service classifier public-cls name secret-cls",
		"show class-of-service classifier name public-cls name secret-cls",
		"show class-of-service classifier public-cls type dscp type ieee-802.1",
		"show class-of-service rewrite-rule public-cls name secret-cls",
	} {
		if _, res := Canonicalize(OperationalTree, strings.Fields(line)); res == CanonicalOK {
			t.Errorf("%q canonicalized OK; post-dynamic sibling / repeated key must be refused", line)
		}
	}
	for _, line := range []string{
		"show interfaces ge-0/0/0",
		"show interfaces ge-0/0/0 detail",
		"show interfaces ge-0/0/0 extensive",
		"show interfaces terse",
		"show interfaces queue",
		"show interfaces queue ge-0/0/0",
		"show security zones trust",
		"show security zones detail",
		"show security zones trust detail",
		"show class-of-service classifier public-cls",
		"show class-of-service classifier name public-cls",
		"show class-of-service classifier public-cls type dscp",
		"show class-of-service classifier name public-cls type dscp",
		"show class-of-service classifier type dscp name public-cls",
	} {
		if _, res := Canonicalize(OperationalTree, strings.Fields(line)); res != CanonicalOK {
			t.Errorf("%q: %v, want CanonicalOK (control)", line, res)
		}
	}
}

func TestParseCoSRejectsDuplicate14688(t *testing.T) {
	for _, args := range [][]string{
		{"public-cls", "name", "secret-cls"},
		{"name", "a", "name", "b"},
		{"type", "dscp", "type", "ieee-802.1"},
		{"a", "type", "dscp", "type", "ieee-802.1"},
		{"name", "a", "type", "dscp", "name", "b"},
	} {
		if _, _, err := ParseCoSNameTypeArgs(args); err == nil {
			t.Errorf("ParseCoSNameTypeArgs(%q) = nil error, want duplicate rejection", args)
		}
	}
	for _, tc := range []struct {
		args               []string
		wantName, wantType string
	}{
		{[]string{"rw-dscp"}, "rw-dscp", ""},
		{[]string{"rw-dscp", "type", "ieee-802.1"}, "rw-dscp", "ieee-802.1"},
		{[]string{"name", "type", "type", "dscp"}, "type", "dscp"},
		{[]string{"type", "dscp", "name", "type"}, "type", "dscp"},
	} {
		n, ty, err := ParseCoSNameTypeArgs(tc.args)
		if err != nil || n != tc.wantName || ty != tc.wantType {
			t.Errorf("ParseCoSNameTypeArgs(%q) = (%q,%q,%v), want (%q,%q,nil)", tc.args, n, ty, err, tc.wantName, tc.wantType)
		}
	}
}
