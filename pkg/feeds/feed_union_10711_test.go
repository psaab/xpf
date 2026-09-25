package feeds

import (
	"strings"
	"testing"
)

// TestFeedUnionHalvesRefused10711 is #10711 item 1: two narrower prefixes that
// jointly cover the whole IPv4 space must be refused like a single /0 line
// (#9248). A feed listing 0.0.0.0/1 and 128.0.0.0/1 installs "match anything"
// at every policy consumer if the union is not checked.
func TestFeedUnionHalvesRefused10711(t *testing.T) {
	_, err := parseFeed(strings.NewReader("0.0.0.0/1\n128.0.0.0/1\n"))
	if err == nil || !strings.Contains(err.Error(), "whole") || !strings.Contains(err.Error(), "10711") {
		t.Fatalf("err=%v, want a whole-space union refusal naming #10711", err)
	}
}

// The same reassembly in IPv6: ::/1 and 8000::/1 jointly cover ::/0.
func TestFeedUnionHalvesIPv6Refused10711(t *testing.T) {
	_, err := parseFeed(strings.NewReader("::/1\n8000::/1\n"))
	if err == nil || !strings.Contains(err.Error(), "whole") || !strings.Contains(err.Error(), "10711") {
		t.Fatalf("err=%v, want a whole-space union refusal naming #10711", err)
	}
}

// NON-REGRESSION: the check is on the UNION, not on short prefixes. A feed
// covering three quarters of v4 (plus an unrelated real prefix to keep the
// assertion on the union rule rather than the zero-prefix rule) installs.
func TestFeedLargeButPartialAccepted10711(t *testing.T) {
	res, err := parseFeed(strings.NewReader("0.0.0.0/1\n128.0.0.0/2\n198.51.100.0/24\n"))
	if err != nil {
		t.Fatalf("a large-but-partial feed must install: %v", err)
	}
	if len(res.prefixes) != 3 || res.invalidLines != 0 {
		t.Errorf("prefixes=%v invalidLines=%d, want all three installed and none refused", res.prefixes, res.invalidLines)
	}
}

// A half-range from each family is still partial coverage in both families.
func TestFeedPartialCoverageAcrossFamiliesAccepted10711(t *testing.T) {
	res, err := parseFeed(strings.NewReader("0.0.0.0/1\n8000::/1\n"))
	if err != nil {
		t.Fatalf("partial coverage in each family must install: %v", err)
	}
	if len(res.prefixes) != 2 || res.invalidLines != 0 {
		t.Errorf("prefixes=%v invalidLines=%d, want both halves installed and none refused", res.prefixes, res.invalidLines)
	}
}

// The union rule generalizes past exact halves: four /2s (and overlapping
// tilings such as /1 + /2 + /2) also cover the whole space and are refused.
func TestFeedUnionQuartersRefused10711(t *testing.T) {
	for name, body := range map[string]string{
		"four /2s":        "0.0.0.0/2\n64.0.0.0/2\n128.0.0.0/2\n192.0.0.0/2\n",
		"overlapping partition": "0.0.0.0/1\n128.0.0.0/2\n192.0.0.0/2\n",
	} {
		if _, err := parseFeed(strings.NewReader(body)); err == nil ||
			!strings.Contains(err.Error(), "whole") || !strings.Contains(err.Error(), "10711") {
			t.Errorf("%s: err=%v, want a whole-space union refusal naming #10711", name, err)
		}
	}
}
