package config

import (
	"strings"
	"testing"
)

// #17256: the NAT64 `match source-address-name` arm of
// validateNAT64ScopeStrict hand-tested ab.Addresses/ab.AddressSets
// instead of the shared NAT name predicate.
// The shared path must preserve two distinct rules:
//
//   - a DEFINED-but-statically-unresolvable name (empty set,
//     description-only address/set, prefix-less address) is rejected
//     at NAT64 as well as by the SNAT twin via
//     policyMatchAddressBookResolves (#3425); and
//   - a closure that is empty ONLY because a dns-name is cold /
//     lookup-failed stays admitted (#15930/#16595 parity). The shared
//     resolver must surface this state without blanket-exempting a
//     mixed cold-DNS + statically-empty closure.
//
// The direct feed-binding divergence was already closed by #16550 and
// is pinned by TestNAT64SourceAddressNameFeedBindingAdmitted16550. The
// live residual is defined-but-unresolvable static names. The shared
// resolver also classifies DNS-only transient emptiness separately so
// preserving #15930 does not hide a statically empty sibling.
//
// RED-on-revert: restoring the hand existence test makes every reject
// cell below compile clean again. Breaking the shared feedBinding
// carve-out turns the NAT64 feed cell and the SNAT feed cells red
// together (single source).

func nat64UnresolvableLines(nameLine string) []string {
	return nat64ScopeLines(
		nameLine,
		"set security nat nat64 rule-set rs1 match source-address-name scope-name",
	)
}

func TestNAT64SourceAddressNameUnresolvableRejected17256(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
	}{
		{"empty-set", "set security address-book global address-set scope-name description empty"},
		{"prefixless-address", "set security address-book global address scope-name description placeholder"},
		{"nested-empty-set", ""}, // built below
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := nat64UnresolvableLines(tc.line)
			if tc.name == "nested-empty-set" {
				lines = nat64ScopeLines(
					"set security address-book global address-set inner-empty description empty",
					"set security address-book global address-set scope-name address-set inner-empty",
					"set security nat nat64 rule-set rs1 match source-address-name scope-name",
				)
			}
			_, err := compileNAT64Scope(t, lines)
			if err == nil {
				t.Fatalf("%s: NAT64 source-address-name resolving to nothing must be rejected at strict commit (#17256/#3425 parity)", tc.name)
			}
			if !strings.Contains(err.Error(), `security nat nat64 rule-set "rs1"`) ||
				!strings.Contains(err.Error(), `source-address-name "scope-name"`) {
				t.Fatalf("%s: error must name the NAT64 rule-set and name, got: %v", tc.name, err)
			}
			if !strings.Contains(err.Error(), "does not resolve") {
				t.Fatalf("%s: error must carry the shared unresolvable diagnostic, got: %v", tc.name, err)
			}
			// Lenient path warns, never bricks (#1960).
			if _, lerr := CompileConfigLenient(compileNAT64ScopeTree(t, lines)); lerr != nil {
				t.Fatalf("%s: lenient path must not brick: %v", tc.name, lerr)
			}
		})
	}
}

// The SNAT twin disposition for the identical input, pinned beside the
// NAT64 cells so the parity claim is executable, not prose.
func TestNAT64SourceAddressNameUnresolvableSNATTwin17256(t *testing.T) {
	tree := buildTree(t, emptySetSNATSource("scope-name"))
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("SNAT twin must reject the defined-but-empty name (#3425)")
	}
}

// Cold dns-name closure: admitted at NAT64 (#15930) exactly as the
// policy gate admits a DNS-unavailable closure (#16595/#17782).
func TestNAT64SourceAddressNameColdDNSAdmitted17256(t *testing.T) {
	_, err := compileNAT64Scope(t, nat64ScopeLines(
		"set security address-book global address scope-name dns-name clients.example.net",
		"set security nat nat64 rule-set rs1 match source-address-name scope-name",
	))
	if err != nil {
		t.Fatalf("cold dns-name NAT64 scope must commit (#15930): %v", err)
	}
}

// Mixed closure: one cold dns-name member plus one statically empty
// member. The empty member is statically proven, so the closure must
// still reject — DNS tolerance is attributed, never a blanket exempt.
func TestNAT64SourceAddressNameMixedColdDNSAndEmptyRejected17256(t *testing.T) {
	_, err := compileNAT64Scope(t, nat64ScopeLines(
		"set security address-book global address cold-dns dns-name clients.example.net",
		"set security address-book global address-set inner-empty description empty",
		"set security address-book global address-set scope-name address cold-dns",
		"set security address-book global address-set scope-name address-set inner-empty",
		"set security nat nat64 rule-set rs1 match source-address-name scope-name",
	))
	if err == nil {
		t.Fatal("mixed cold-DNS + statically-empty closure must reject (#17256)")
	}
	if !strings.Contains(err.Error(), "does not resolve") {
		t.Fatalf("error must carry the shared unresolvable diagnostic, got: %v", err)
	}
	// Sol/GLM: the culprit named must be the static member, not the
	// tolerated cold-DNS member walked first.
	if !strings.Contains(err.Error(), "inner-empty") {
		t.Fatalf("error must name the static culprit inner-empty, got: %v", err)
	}
	if strings.Contains(err.Error(), "cold-dns") && !strings.Contains(err.Error(), "inner-empty") {
		t.Fatalf("error names only the tolerated DNS member, got: %v", err)
	}
}
