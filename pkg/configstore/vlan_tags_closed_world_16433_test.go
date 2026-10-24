package configstore

import (
	"strings"
	"testing"
)

// #16433: the operator commit-check (CheckText) must reject every
// non-`outer <vid>` `vlan-tags` spelling in both config shapes. Before
// the fix each reject row below committed as a single-tag VlanID=100.

func TestCheckTextVlanTagsClosedWorld16433(t *testing.T) {
	rejects := []struct {
		name  string
		text  string
		inner bool
	}{
		{"flat inner-range", "set interfaces ge-0/0/0 flexible-vlan-tagging\nset interfaces ge-0/0/0 unit 0 vlan-tags outer 100 inner-range 1-200\nset interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24\n", true},
		{"flat inner-list", "set interfaces ge-0/0/0 flexible-vlan-tagging\nset interfaces ge-0/0/0 unit 0 vlan-tags outer 100 inner-list [ 10 20 ]\nset interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24\n", true},
		{"flat inner-vlan-id-range", "set interfaces ge-0/0/0 flexible-vlan-tagging\nset interfaces ge-0/0/0 unit 0 vlan-tags outer 100 inner-vlan-id-range 1-200\nset interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24\n", true},
		{"flat bogus tail", "set interfaces ge-0/0/0 flexible-vlan-tagging\nset interfaces ge-0/0/0 unit 0 vlan-tags outer 100 bogus 7\nset interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24\n", false},
		{"hier inner-range", "interfaces { ge-0/0/0 { flexible-vlan-tagging; unit 0 { vlan-tags outer 100 inner-range 1-200; family inet { address 10.0.1.1/24; } } } }", true},
		{"hier inner-list", "interfaces { ge-0/0/0 { flexible-vlan-tagging; unit 0 { vlan-tags { outer 100; inner-list 10 20; } family inet { address 10.0.1.1/24; } } } }", true},
		{"hier bogus tail", "interfaces { ge-0/0/0 { flexible-vlan-tagging; unit 0 { vlan-tags outer 100 bogus 7; family inet { address 10.0.1.1/24; } } } }", false},
	}
	for _, tc := range rejects {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CheckText(tc.text, -1)
			if err == nil {
				t.Fatalf("CheckText accepted %s", tc.name)
			}
			if tc.inner {
				if !strings.Contains(err.Error(), "#5879") || !strings.Contains(err.Error(), "QinQ") {
					t.Fatalf("%s: error %q does not name the #5879 QinQ gate", tc.name, err.Error())
				}
				return
			}
			if !strings.Contains(err.Error(), "#16433") {
				t.Fatalf("%s: error %q does not name #16433", tc.name, err.Error())
			}
		})
	}
	for name, text := range map[string]string{
		"flat outer-only": "set interfaces ge-0/0/0 flexible-vlan-tagging\nset interfaces ge-0/0/0 unit 0 vlan-tags outer 100\nset interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24\n",
		"hier outer-only": "interfaces { ge-0/0/0 { flexible-vlan-tagging; unit 0 { vlan-tags outer 100; family inet { address 10.0.1.1/24; } } } }",
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := CheckText(text, -1)
			if err != nil {
				t.Fatalf("CheckText rejected valid outer-only: %v", err)
			}
			u := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
			if u == nil || u.VlanID != 100 || u.InnerVlanID != 0 {
				t.Fatalf("%s: got %+v, want VlanID=100 Inner=0", name, u)
			}
		})
	}
}
