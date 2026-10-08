// #12085: interface-mode SNAT registers its interface-NAT address for EVERY
// to-side scope row of the §5.7 derivation matrix — to-zone, to-interface,
// to-routing-instance, and unscoped — not only for non-empty ToZone. The shared
// fixture is also consumed by the Rust twin test, pinning equal address sets.
package userspace

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

type natIfaceScopeFixture12085 struct {
	Interfaces []InterfaceSnapshot `json:"interfaces"`
	Zones      []ZoneSnapshot      `json:"zones"`
	Cases      []struct {
		Name string                `json:"name"`
		Rule SourceNATRuleSnapshot `json:"rule"`
		Want []string              `json:"want"`
	} `json:"cases"`
}

func readNATIfaceScopeFixture12085(t *testing.T) natIfaceScopeFixture12085 {
	t.Helper()
	path := filepath.Join("..", "..", "..", "userspace-dp", "tests", "fixtures", "nat_iface_scope_12085.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shared Go/Rust matrix fixture %s: %v", path, err)
	}
	var fixture natIfaceScopeFixture12085
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode shared Go/Rust matrix fixture: %v", err)
	}
	return fixture
}

func natIfaceScopeSnapshot12085(f natIfaceScopeFixture12085, rule SourceNATRuleSnapshot) *ConfigSnapshot {
	return &ConfigSnapshot{
		Interfaces: f.Interfaces,
		Zones:      f.Zones,
		SourceNAT:  []SourceNATRuleSnapshot{rule},
	}
}

func TestBuildNATTranslatedLocalAddressExclusions12085Matrix(t *testing.T) {
	fixture := readNATIfaceScopeFixture12085(t)
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			snapshot := natIfaceScopeSnapshot12085(fixture, tc.Rule)
			gotV4, gotV6 := buildNATTranslatedLocalAddressExclusions(snapshot)
			got := make([]string, 0, len(gotV4)+len(gotV6))
			for key := range gotV4 {
				var octets [4]byte
				binary.BigEndian.PutUint32(octets[:], key)
				got = append(got, netip.AddrFrom4(octets).String())
			}
			for key := range gotV6 {
				got = append(got, netip.AddrFrom16(key).String())
			}
			sort.Strings(got)
			want := append([]string(nil), tc.Want...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("Go interface-NAT exclusion set = %v, want matrix set %v", got, want)
			}

			local := buildLocalAddressEntries(snapshot)
			for _, entry := range local {
				var addr string
				if entry.v4 {
					var octets [4]byte
					binary.BigEndian.PutUint32(octets[:], entry.v4Key)
					addr = netip.AddrFrom4(octets).String()
				} else {
					addr = netip.AddrFrom16(entry.v6Key.Addr).String()
				}
				for _, excluded := range want {
					if addr == excluded {
						t.Fatalf("excluded egress address %s still appears in LOCAL entries", addr)
					}
				}
			}

			nat := buildInterfaceNATAddressEntries(snapshot)
			natGot := make([]string, 0, len(nat))
			for _, entry := range nat {
				if entry.v4 {
					var octets [4]byte
					binary.BigEndian.PutUint32(octets[:], entry.v4Key)
					natGot = append(natGot, netip.AddrFrom4(octets).String())
				} else {
					natGot = append(natGot, netip.AddrFrom16(entry.v6Key.Addr).String())
				}
			}
			sort.Strings(natGot)
			if !reflect.DeepEqual(natGot, want) {
				t.Fatalf("Go interface-NAT entries = %v, want matrix set %v", natGot, want)
			}
		})
	}
}

func TestBuildNATTranslatedLocalAddressExclusions12085Guards(t *testing.T) {
	fixture := readNATIfaceScopeFixture12085(t)
	base := fixture.Cases[len(fixture.Cases)-1].Rule // unscoped row
	base.Off = true
	if v4, v6 := buildNATTranslatedLocalAddressExclusions(natIfaceScopeSnapshot12085(fixture, base)); len(v4)+len(v6) != 0 {
		t.Fatalf("off rule minted exclusions: v4=%v v6=%v", v4, v6)
	}
	base.Off = false
	base.InterfaceMode = false
	if v4, v6 := buildNATTranslatedLocalAddressExclusions(natIfaceScopeSnapshot12085(fixture, base)); len(v4)+len(v6) != 0 {
		t.Fatalf("pool-mode rule minted exclusions: v4=%v v6=%v", v4, v6)
	}
}
