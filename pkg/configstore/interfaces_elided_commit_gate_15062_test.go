package configstore

import (
	"reflect"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15062 (A01-01): a top-level brace-elided interface must meet the
// SAME day-0 / commit gate as the braced spelling through CheckText
// (compileTreeStrict: SchemaValidate on the expanded view, then strict
// compile). Before the fold moved into normalizeCompactStanzas, the
// elided `interfaces fxp0 { ... }` validated clean here and compiled a
// phantom `unit` interface, dropping fxp0's address — the day-0
// management-interface loss the issue calls out.

func ifaceNames15062(cfg *config.Config) []string {
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for n := range cfg.Interfaces.Interfaces {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func TestElidedInterfaceMeetsBracedCheckTextGate15062(t *testing.T) {
	cells := []struct {
		name, elided, braced string
		wantIface            string
		wantAddr             string
	}{
		{"fxp0 address",
			`interfaces fxp0 { unit 0 { family inet { address 10.9.9.2/24; } } }`,
			`interfaces { fxp0 { unit 0 { family inet { address 10.9.9.2/24; } } } }`,
			"fxp0", "10.9.9.2/24"},
		{"ge address and mtu",
			`interfaces ge-0/0/0 { mtu 9000; unit 0 { family inet { address 10.9.9.1/24; } } }`,
			`interfaces { ge-0/0/0 { mtu 9000; unit 0 { family inet { address 10.9.9.1/24; } } } }`,
			"ge-0/0/0", "10.9.9.1/24"},
		{"dhcp unit",
			`interfaces ge-0/0/1 { unit 0 { family inet { dhcp; } } }`,
			`interfaces { ge-0/0/1 { unit 0 { family inet { dhcp; } } } }`,
			"ge-0/0/1", ""},
	}
	for _, c := range cells {
		t.Run(c.name, func(t *testing.T) {
			elided, err := CheckText(c.elided, -1)
			if err != nil {
				t.Fatalf("elided CheckText refused: %v (#15062)", err)
			}
			braced, err := CheckText(c.braced, -1)
			if err != nil {
				t.Fatalf("braced CheckText refused: %v", err)
			}
			if got, want := ifaceNames15062(elided), ifaceNames15062(braced); !reflect.DeepEqual(got, want) {
				t.Fatalf("elided interfaces %v != braced %v (#15062)", got, want)
			}
			if got := ifaceNames15062(elided); len(got) != 1 || got[0] != c.wantIface {
				t.Fatalf("elided compiled interfaces %v, want [%s] (#15062)", got, c.wantIface)
			}
			ic := elided.Interfaces.Interfaces[c.wantIface]
			if c.wantAddr != "" {
				u0 := ic.Units[0]
				if u0 == nil || len(u0.Addresses) != 1 || u0.Addresses[0] != c.wantAddr {
					t.Fatalf("elided %s unit0 = %+v, want address %s (#15062)", c.wantIface, u0, c.wantAddr)
				}
			}
			if c.name == "ge address and mtu" && ic.MTU != 9000 {
				t.Fatalf("elided ge-0/0/0 MTU=%d, want 9000 (#15062)", ic.MTU)
			}
			if c.name == "dhcp unit" {
				u0 := ic.Units[0]
				if u0 == nil || !u0.DHCP {
					t.Fatalf("elided ge-0/0/1 unit0 = %+v, want DHCP (#15062)", u0)
				}
			}
		})
	}
}

// An invalid interface name in the elided spelling must be refused
// exactly as in the braced spelling (ValidateInterfaceName, #6834):
// folding must not launder a bad name past the typed gate.
func TestElidedInterfaceBadNameRefusedLikeBraced15062(t *testing.T) {
	elided := `interfaces "ge 0" { unit 0 { family inet { address 10.9.9.1/24; } } }`
	braced := `interfaces { "ge 0" { unit 0 { family inet { address 10.9.9.1/24; } } } }`
	_, elidedErr := CheckText(elided, -1)
	_, bracedErr := CheckText(braced, -1)
	if (elidedErr == nil) != (bracedErr == nil) {
		t.Fatalf("elided bad-name verdict %v != braced %v (#15062)", elidedErr, bracedErr)
	}
	if elidedErr == nil {
		t.Fatalf("bad interface name accepted in both spellings; expected ValidateInterfaceName refusal (#15062)")
	}
}
