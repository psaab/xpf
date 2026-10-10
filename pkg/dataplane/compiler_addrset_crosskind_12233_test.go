package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

type crossKindMembershipDP12233 struct {
	idProbeDP
	memberships [][2]uint32
}

func (dp *crossKindMembershipDP12233) SetAddressMembership(memberID, setID uint32) error {
	dp.memberships = append(dp.memberships, [2]uint32{memberID, setID})
	return nil
}

func crossKindAddressBookConfig12233(outerSet string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"h1": {Name: "h1", Value: "10.9.0.1/32"},
		},
		AddressSets: map[string]*config.AddressSet{
			"B":      {Name: "B", Addresses: []string{"h1"}},
			outerSet: {Name: outerSet, Addresses: []string{"B"}},
		},
	}
	return cfg
}

func TestCompileAddressBookCrossKindSetMemberOrderIndependent12233(t *testing.T) {
	for _, tc := range []struct {
		name           string
		outerSet       string
		wantIDs        map[string]uint32
		wantMembership [][2]uint32
	}{
		{
			name:           "A before B",
			outerSet:       "A",
			wantIDs:        map[string]uint32{"h1": 1, "A": 2, "B": 3},
			wantMembership: [][2]uint32{{1, 1}, {3, 2}, {1, 3}},
		},
		{
			name:           "Z after B",
			outerSet:       "Z",
			wantIDs:        map[string]uint32{"h1": 1, "B": 2, "Z": 3},
			wantMembership: [][2]uint32{{1, 1}, {1, 2}, {2, 3}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := crossKindAddressBookConfig12233(tc.outerSet)
			dp := &crossKindMembershipDP12233{}
			result := newValidationResult()
			if err := compileAddressBook(dp, cfg, result); err != nil {
				t.Fatalf("compileAddressBook: %v", err)
			}
			if len(result.AddrIDs) != len(tc.wantIDs) {
				t.Fatalf("AddrIDs = %v, want exactly %v", result.AddrIDs, tc.wantIDs)
			}
			for name, want := range tc.wantIDs {
				if got := result.AddrIDs[name]; got != want {
					t.Errorf("AddrIDs[%q] = %d, want %d; all IDs: %v", name, got, want, result.AddrIDs)
				}
			}
			if len(dp.memberships) != len(tc.wantMembership) {
				t.Fatalf("memberships = %v, want %v", dp.memberships, tc.wantMembership)
			}
			for _, want := range tc.wantMembership {
				found := false
				for _, got := range dp.memberships {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("membership %v missing from %v", want, dp.memberships)
				}
			}
		})
	}
}
