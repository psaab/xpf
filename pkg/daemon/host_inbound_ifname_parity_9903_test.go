package daemon

import (
	"strings"
	"testing"
)

// #9903 F-126 — text-renderer half of the parity cell. The netlink builder
// refuses a >15-byte ifname at plan time (p.fail in iifnameMatch,
// pkg/nftables); the text renderer keeps the token VERBATIM so the kernel
// refuses the load loudly (#6512 doctrine) instead of installing a
// truncated never-matching rule. This cell pins verbatim rendering —
// truncating or sanitizing here would diverge the builders into a silent
// never-match at the kernel while netlink refuses. It asserts rendering
// only, never kernel refusal.
func TestTextRendersOverlongIfnameVerbatim9903(t *testing.T) {
	long := "1234567890123456"
	single := nftIifnameSet([]string{long})
	if !strings.Contains(single, `"`+long+`"`) {
		t.Fatalf("single-ifname text must carry the overlong token verbatim, got %q", single)
	}
	set := nftIifnameSet([]string{"ge-0/0/0", long})
	if !strings.Contains(set, `"`+long+`"`) || !strings.Contains(set, `"ge-0/0/0"`) {
		t.Fatalf("set-form text must carry every token verbatim, got %q", set)
	}
	boundary := nftIifnameSet([]string{"123456789012345"})
	if !strings.Contains(boundary, `"123456789012345"`) {
		t.Fatalf("15-byte boundary token must render intact, got %q", boundary)
	}
}
