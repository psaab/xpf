package config

import (
	"strings"
	"testing"
)

// #12243: policy wildcard tokens are valid policy matches, not address-book
// entries. An unreferenced set bypasses the #3149 policy-side resolver mirror,
// but reaches compileAddressBook at apply; every wildcard then misses AddrIDs
// and aborts the whole apply. The book-wide gate must reject it at commit.
func TestUnreferencedAddressSetWildcardRejectedAtCommit12243(t *testing.T) {
	for _, tc := range []struct {
		keyword string
		leaf    string
	}{
		{keyword: "any", leaf: "address"},
		{keyword: "any-ipv4", leaf: "address"},
		{keyword: "any-ipv6", leaf: "address"},
		{keyword: "any4", leaf: "address"},
		{keyword: "any6", leaf: "address"},
		{keyword: "any", leaf: "address-set"},
	} {
		t.Run(tc.leaf+"/"+tc.keyword, func(t *testing.T) {
			cmds := []string{
				"set security address-book global address web 10.0.0.1/32",
				"set security address-book global address-set S " + tc.leaf + " " + tc.keyword,
				"set security address-book global address-set S address web",
			}
			tree := buildAppMatchTree(t, cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("strict compile accepted unreferenced set S with wildcard member %q", tc.keyword)
			}
			for _, want := range []string{"address-set S", tc.leaf, tc.keyword, "wildcard"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("CompileConfig error %q does not name %q", err, want)
				}
			}
		})
	}
}

func TestUnreferencedAddressSetWithNamedMembersStillCommits12243(t *testing.T) {
	tree := buildAppMatchTree(t,
		"set security address-book global address web 10.0.0.1/32",
		"set security address-book global address-set S address web",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict compile rejected an unreferenced set with a defined member: %v", err)
	}
}
