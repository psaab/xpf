package feeds

import (
	"strings"
	"testing"
)

// TestFeedRefusesTheDefaultRoute9248 is #9248 item 1. Feed prefixes become the
// address set a policy matches, so a default-route line in remote content would
// widen every policy on that dynamic address to "any".
func TestFeedRefusesTheDefaultRoute9248(t *testing.T) {
	res, err := parseFeed(strings.NewReader("0.0.0.0/0\n::/0\n198.51.100.0/24\n2001:db8::/32\n"))
	if err != nil {
		t.Fatalf("a feed with real prefixes beside a default route must still install them: %v", err)
	}
	for _, p := range res.prefixes {
		if p == "0.0.0.0/0" || p == "::/0" {
			t.Errorf("default route %s was installed", p)
		}
	}
	if len(res.prefixes) != 2 {
		t.Errorf("installed %v, want exactly the two real prefixes", res.prefixes)
	}
	if res.invalidLines != 2 {
		t.Errorf("invalidLines=%d, want 2: a refused default route must mark the feed degraded", res.invalidLines)
	}
	sampled := strings.Join(res.invalidSample, "|")
	if !strings.Contains(sampled, "default route refused") {
		t.Errorf("sample %q does not say why the line was dropped", sampled)
	}
}

// A feed whose only entry is the default route has no usable prefixes, so the
// fetch fails and the last-good set stays enforced -- the existing zero-prefix
// rule -- instead of installing "match anything".
func TestFeedOfOnlyTheDefaultRouteKeepsLastGood9248(t *testing.T) {
	if _, err := parseFeed(strings.NewReader("0.0.0.0/0\n")); err == nil ||
		!strings.Contains(err.Error(), "whole-address-space") {
		t.Fatalf("err=%v, want a refusal that names the default route", err)
	}
}

// NON-REGRESSION: short but real prefixes still install. Bogon feeds carry
// 224.0.0.0/3-shaped entries; a floor above /0 would silently empty them.
func TestFeedKeepsShortRealPrefixes9248(t *testing.T) {
	// The /24 keeps the feed non-empty if a mutant over-refuses the short
	// prefixes, so the cell fails on the assertion that names the defect rather
	// than on the zero-prefix rule.
	res, err := parseFeed(strings.NewReader("224.0.0.0/3\n0.0.0.0/8\n::/8\n198.51.100.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.prefixes) != 4 || res.invalidLines != 0 {
		t.Errorf("prefixes=%v invalidLines=%d, want all four installed and none refused", res.prefixes, res.invalidLines)
	}
}

// The refusal is on the prefix that would be INSTALLED. An IPv4-mapped IPv6
// prefix of length 96 renders as 0.0.0.0/0, so a mask-length check passes it.
func TestFeedRefusesAMappedDefaultRoute9248(t *testing.T) {
	res, err := parseFeed(strings.NewReader("::ffff:0:0/96\n::ffff:10.0.0.0/104\n"))
	if err != nil {
		t.Fatalf("a feed with a real mapped prefix beside a mapped default route must install it: %v", err)
	}
	for _, p := range res.prefixes {
		if p == "0.0.0.0/0" || p == "::/0" {
			t.Errorf("a mapped default route was installed as %s", p)
		}
	}
	if len(res.prefixes) != 1 || res.invalidLines != 1 {
		t.Errorf("prefixes=%v invalidLines=%d, want the one real mapped prefix installed and the "+
			"mapped default route refused", res.prefixes, res.invalidLines)
	}
}
