package config

import (
	"strings"
	"testing"
)

func TestPackedNestedValueListRunsRejected18370(t *testing.T) {
	const lists = `policy-options {
    prefix-list pl1 { 10.0.0.0/8; }
    prefix-list pl2 { 10.1.0.0/16; }
}`
	const natPrefix = `security {
    zones { security-zone trust; security-zone untrust; }
    nat { source { rule-set rs {
        from zone trust;
        to zone untrust;
        rule r match source-address %s { unexpected { 192.0.2.0/24; } }
    } } }
}`
	cases := []struct {
		name, text, leaf string
		applyGroups      bool
	}{
		{
			name: "firewall bracketed prefix-list run",
			text: lists + ` firewall { family inet { filter f {
                term t from source-prefix-list [ pl1 pl2 ] {
                    unexpected { 10.0.0.0/8; }
                }
            } } }`,
			leaf: "source-prefix-list",
		},
		{
			name: "firewall bracketed single prefix-list with except block",
			text: lists + ` firewall { family inet { filter f { term t {
                from source-prefix-list [ pl1 ] except { unexpected { 10.0.0.0/8; } }
                then accept; } } } }`,
			leaf: "source-prefix-list",
		},
		{
			name: "firewall bracketed prefix-list run with except block",
			text: lists + ` firewall { family inet { filter f { term t {
                from source-prefix-list [ pl1 pl2 ] except { unexpected { 10.0.0.0/8; } }
                then accept; } } } }`,
			leaf: "source-prefix-list",
		},
		{
			name: "firewall bracketed destination prefix-list with except block",
			text: lists + ` firewall { family inet { filter f { term t {
                from destination-prefix-list [ pl1 ] except { unexpected { 10.0.0.0/8; } }
                then accept; } } } }`,
			leaf: "destination-prefix-list",
		},
		{
			name: "NAT bracketed address run",
			text: natPrefixConfig18370(natPrefix, "[ 10.0.0.0/8 192.168.0.0/16 ]"),
			leaf: "source-address",
		},
		{
			name: "NAT unbracketed address run",
			text: natPrefixConfig18370(natPrefix, "10.0.0.0/8 192.168.0.0/16"),
			leaf: "source-address",
		},
		{
			name: "apply-groups inherited unbracketed prefix-list run",
			text: lists + ` groups { g { firewall { family inet { filter f {
                term t from source-prefix-list pl1 pl2 {
                    unexpected { 10.0.0.0/8; }
                }
            } } } } }
            firewall { apply-groups g; }`,
			leaf:        "source-prefix-list",
			applyGroups: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHierText(t, tc.text)
			walkTree := tree
			if tc.applyGroups {
				walkTree = tree.Clone()
				if err := walkTree.ExpandGroups(); err != nil {
					t.Fatalf("expand apply-groups fixture: %v", err)
				}
			}
			assertNestedListRefused18366(t, SchemaValidate(walkTree), tc.leaf)
			_, err := CompileConfig(tree)
			assertNestedListRefused18366(t, err, tc.leaf)
			_, err = CompileConfigLenient(tree)
			assertNestedListRefused18366(t, err, tc.leaf)
		})
	}
}

func natPrefixConfig18370(template, values string) string {
	return strings.Replace(template, "%s", values, 1)
}

func TestValidPackedMultiValueControls18370(t *testing.T) {
	controls := []struct {
		name, text string
	}{
		{
			name: "firewall prefix-list references",
			text: `policy-options {
    prefix-list pl1 { 10.0.0.0/8; }
    prefix-list pl2 { 10.1.0.0/16; }
}
firewall { family inet { filter f { term t from source-prefix-list [ pl1 pl2 ] then accept; } } }`,
		},
		{
			name: "NAT source-address values",
			text: `security {
    zones { security-zone trust; security-zone untrust; }
    nat { source { rule-set rs {
        from zone trust;
        to zone untrust;
        rule r match source-address [ 10.0.0.0/8 192.168.0.0/16 ] then source-nat interface;
    } } }
}`,
		},
		{
			name: "firewall bracketed prefix-list with except modifier",
			text: `policy-options {
    prefix-list pl1 { 10.0.0.0/8; }
}
firewall { family inet { filter f { term t {
    from { source-prefix-list [ pl1 ] except; }
    then accept;
} } } }`,
		},
		{
			name: "firewall unbracketed prefix-list before then sibling",
			text: `policy-options {
    prefix-list pl1 { 10.0.0.0/8; }
}
firewall { family inet { filter f { term t from source-prefix-list pl1 then accept; } } }`,
		},
	}
	for _, tc := range controls {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHierText(t, tc.text)
			if err := SchemaValidate(tree); err != nil {
				t.Fatalf("SchemaValidate rejected valid packed list: %v", err)
			}
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("strict compile rejected valid packed list: %v", err)
			}
			if _, err := CompileConfigLenient(tree); err != nil {
				t.Fatalf("lenient compile rejected valid packed list: %v", err)
			}
		})
	}
}
