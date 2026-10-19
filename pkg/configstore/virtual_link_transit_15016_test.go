package configstore

import (
	"strings"
	"testing"
)

// #15016 (A12-04): CheckText (the operator commit channel) must reject a
// virtual link whose effective transit is the backbone or a stub/NSSA
// area, and accept a valid VL through a normal transit area.
func TestVirtualLinkTransitCheckText15016(t *testing.T) {
	const base = `routing-options { autonomous-system 65000; router-id 10.0.0.1; } `
	for _, tc := range []struct {
		name, text, want string
	}{
		{"default transit backbone",
			`protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0; virtual-link 10.0.0.2; } } }`, "backbone"},
		{"explicit transit stub",
			`protocols { ospf { area 0.0.0.1 { area-type stub; interface ge-0/0/0.0; virtual-link 10.0.0.2; } } }`, "stub"},
		{"explicit transit nssa",
			`protocols { ospf { area 0.0.0.1 { interface ge-0/0/0.0; virtual-link 10.0.0.2 { transit-area 0.0.0.2; } } area 0.0.0.2 { area-type nssa; interface ge-0/0/1.0; } } }`, "nssa"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CheckText(base+tc.text, 0)
			if err == nil {
				t.Fatalf("%s committed; it renders a line FRR refuses", tc.name)
			}
			if !strings.Contains(err.Error(), "virtual-link") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s refused without naming virtual-link/%s: %v", tc.name, tc.want, err)
			}
		})
	}
	good := `protocols { ospf { area 0.0.0.1 { interface ge-0/0/0.0; virtual-link 10.0.0.2; } } }`
	if _, err := CheckText(base+good, 0); err != nil {
		t.Fatalf("valid virtual-link through normal transit area refused: %v", err)
	}
}
