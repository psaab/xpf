package config

import (
	"fmt"
	"strings"
	"testing"
)

// TestValidateVRFOverlapWarningCap_5194 is the #5194 A3-b3-F5 fail-on-revert
// guard. validateVRFOverlap ran an uncapped O(P^2) prefix-pair scan on every
// strict AND tolerant compile with no warning cap and no operation budget. The
// fix caps the advisory count and the total comparisons and appends a single
// truncation notice so a pathological config cannot flood commit output or
// dominate commit latency.
//
// Fail-on-revert: remove the warning cap / truncation notice and this goes RED —
// all overlapping pairs emit a warning (far more than vrfOverlapMaxWarnings) and
// no truncation notice appears.
func TestValidateVRFOverlapWarningCap_5194(t *testing.T) {
	const nPrefixes = vrfOverlapMaxWarnings + 20 // exceed the advisory cap

	mkTerms := func(ri string) []*FirewallFilterTerm {
		terms := make([]*FirewallFilterTerm, 0, nPrefixes)
		for i := 0; i < nPrefixes; i++ {
			terms = append(terms, &FirewallFilterTerm{
				Name:            fmt.Sprintf("%s-t%d", ri, i),
				RoutingInstance: ri,
				// Each RI carries the SAME set of distinct /24s, so every
				// vrfA[i] exactly overlaps vrfB[i] — nPrefixes overlaps total.
				SourceAddresses: []string{fmt.Sprintf("10.0.%d.0/24", i)},
			})
		}
		return terms
	}

	// Two filters so the terms land in two distinct routing-instances.
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{
			0: {Number: 0, FilterInputV4: "fa"},
			1: {Number: 1, FilterInputV4: "fb"},
		}},
	}
	cfg.Firewall.FiltersInet = map[string]*FirewallFilter{
		"fa": {Name: "fa", Terms: mkTerms("vrfA")},
		"fb": {Name: "fb", Terms: mkTerms("vrfB")},
	}

	warnings, _, _ := validateVRFOverlap(cfg, true /* #7924: budget test measures WARNINGS, not the reject */)

	// Overlap advisories are capped, plus exactly one truncation notice.
	if len(warnings) != vrfOverlapMaxWarnings+1 {
		t.Fatalf("warnings = %d, want %d capped advisories + 1 truncation notice",
			len(warnings), vrfOverlapMaxWarnings+1)
	}
	last := warnings[len(warnings)-1]
	if !strings.Contains(last, "truncated") {
		t.Fatalf("final warning must be the truncation notice, got: %q", last)
	}
	// At least one real overlap advisory must precede the notice.
	if !strings.Contains(warnings[0], "overlapping L3") {
		t.Fatalf("first warning must be an overlap advisory, got: %q", warnings[0])
	}
}

// TestValidateVRFOverlapUnderCapNoTruncation_5194 guards against a false
// truncation notice: a small config well under the caps reports its overlaps
// with no truncation notice appended.
func TestValidateVRFOverlapUnderCapNoTruncation_5194(t *testing.T) {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{
			0: {Number: 0, FilterInputV4: "fa"},
			1: {Number: 1, FilterInputV4: "fb"},
		}},
	}
	cfg.Firewall.FiltersInet = map[string]*FirewallFilter{
		"fa": {Name: "fa", Terms: []*FirewallFilterTerm{
			{Name: "a", RoutingInstance: "vrfA", SourceAddresses: []string{"10.0.0.0/24"}},
		}},
		"fb": {Name: "fb", Terms: []*FirewallFilterTerm{
			{Name: "b", RoutingInstance: "vrfB", SourceAddresses: []string{"10.0.0.0/24"}},
		}},
	}
	warnings, _, _ := validateVRFOverlap(cfg, true /* #7924: budget test measures WARNINGS, not the reject */)
	if len(warnings) != 1 {
		t.Fatalf("one overlap => 1 warning, got %d: %v", len(warnings), warnings)
	}
	if strings.Contains(warnings[0], "truncated") {
		t.Fatalf("under-cap scan must not append a truncation notice, got: %q", warnings[0])
	}
}
