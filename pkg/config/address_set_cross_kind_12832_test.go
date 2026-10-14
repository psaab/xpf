package config

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// TestCrossKindStrictAddressSetBounds12832 pins the commit-time gate to the
// same cross-kind graph traversal as expandAddressSetLeaves. The public
// ExpandAddressSet result remains the dataplane set-ID graph; its direct
// address member continues to name the referenced set rather than flattening
// its leaves.
func TestCrossKindStrictAddressSetBounds12832(t *testing.T) {
	cycle := &AddressBook{
		Addresses: map[string]*Address{},
		AddressSets: map[string]*AddressSet{
			"A": {Name: "A", Addresses: []string{"B"}},
			"B": {Name: "B", Addresses: []string{"A"}},
		},
	}
	for _, tc := range []struct {
		name    string
		ab      *AddressBook
		wantErr string
	}{
		{name: "five-edge-chain-is-admissible", ab: crossKindChain12502(5)},
		{name: "six-edge-chain-is-rejected", ab: crossKindChain12502(6),
			wantErr: "address-set nesting too deep (max 5): s6"},
		{name: "cross-kind-cycle-is-rejected", ab: cycle,
			wantErr: `cycle detected in address-set "A"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Security.AddressBook = tc.ab
			err := validateAddressSetMembersDefinedStrict(cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("strict validation rejected admissible graph: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("strict validation error = %v; want substring %q",
					err, tc.wantErr)
			}
		})
	}

	// Exercise the public strict compile gate and the tolerant warning path.
	lines := []string{"set security address-book global address a0 192.0.2.1/32"}
	for i := 0; i <= 6; i++ {
		member := "a0"
		if i < 6 {
			member = fmt.Sprintf("s%d", i+1)
		}
		lines = append(lines, fmt.Sprintf("set security address-book global address-set s%d address %s", i, member))
	}
	if _, err := CompileConfig(buildTree(t, lines)); err == nil ||
		!strings.Contains(err.Error(), "address-set nesting too deep (max 5): s6") {
		t.Fatalf("strict compile error = %v; want cross-kind depth error", err)
	}
	lenient, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	warned := false
	for _, warning := range lenient.Warnings {
		if strings.Contains(warning, "address-set nesting too deep (max 5): s6") {
			warned = true
			break
		}
	}
	if !warned {
		t.Fatalf("tolerant compile omitted cross-kind depth warning: %v", lenient.Warnings)
	}

	// A shared child is not a cycle: validation's visited set is path-local.
	diamond := &AddressBook{
		Addresses: map[string]*Address{"leaf": {Name: "leaf", Value: "192.0.2.1/32"}},
		AddressSets: map[string]*AddressSet{
			"root":   {Name: "root", Addresses: []string{"left", "right"}},
			"left":   {Name: "left", Addresses: []string{"shared"}},
			"right":  {Name: "right", Addresses: []string{"shared"}},
			"shared": {Name: "shared", Addresses: []string{"leaf"}},
		},
	}
	cfg := &Config{}
	cfg.Security.AddressBook = diamond
	if err := validateAddressSetMembersDefinedStrict(cfg); err != nil {
		t.Fatalf("strict validation rejected cross-kind diamond: %v", err)
	}

	// A same-named address wins, so the set entry does not form a graph edge.
	collision := &AddressBook{
		Addresses: map[string]*Address{
			"B": {Name: "B", Value: "192.0.2.2/32"},
		},
		AddressSets: map[string]*AddressSet{
			"A": {Name: "A", Addresses: []string{"B"}},
			"B": {Name: "B", Addresses: []string{"A"}},
		},
	}
	cfg.Security.AddressBook = collision
	if err := validateAddressSetMembersDefinedStrict(cfg); err != nil {
		t.Fatalf("strict validation followed shadowed set collision: %v", err)
	}

	graph := &AddressBook{
		Addresses: map[string]*Address{},
		AddressSets: map[string]*AddressSet{
			"A": {Name: "A", Addresses: []string{"B"}},
			"B": {Name: "B", Addresses: []string{"leaf"}},
		},
	}
	if got, err := ExpandAddressSet("A", graph); err != nil ||
		!reflect.DeepEqual(got, []string{"B"}) {
		t.Fatalf("ExpandAddressSet(A) = %v, %v; want graph member [B]", got, err)
	}
}
