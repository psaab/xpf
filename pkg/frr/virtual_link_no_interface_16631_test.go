package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16631: a virtual link whose transit area renders no interface in
// this config must be omitted — ospfd refuses `area X virtual-link N`
// on a non-ABR and the whole FRR reload hard-fails. This is the render
// belt behind the daemon HA filter (which drops the same VLs after RG
// demotion); it covers direct/tolerant renders that never pass the
// filter.
//
// FAIL-ON-REVERT: remove the #16631 belt in renderOSPF16125 and the
// no-interface / disabled-only / withdrawn cells render the VL again.

func TestVirtualLinkNoTransitInterfaceOmitted16631(t *testing.T) {
	m := New()
	cases := []struct {
		name string
		ospf *config.OSPFConfig
		want string // VL line that must survive, "" = none
	}{
		{
			name: "transit area has no interface at all",
			ospf: &config.OSPFConfig{Areas: []*config.OSPFArea{
				{ID: "0.0.0.1", VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.2", TransitArea: "0.0.0.1"}}},
				{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/0.0"}}},
			}},
		},
		{
			name: "transit area absent from config",
			ospf: &config.OSPFConfig{Areas: []*config.OSPFArea{
				{ID: "0.0.0.1", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/0.0"}},
					VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.2", TransitArea: "0.0.0.9"}}},
			}},
		},
		{
			name: "transit interface disabled only",
			ospf: &config.OSPFConfig{Areas: []*config.OSPFArea{
				{ID: "0.0.0.1", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/0.0", Disable: true}},
					VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.2", TransitArea: "0.0.0.1"}}},
			}},
		},
		{
			name: "transit interface claimed by backbone first",
			ospf: &config.OSPFConfig{Areas: []*config.OSPFArea{
				{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/0.0"}}},
				{ID: "0.0.0.1", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/0.0"}},
					VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.2", TransitArea: "0.0.0.1"}}},
			}},
		},
		{
			name: "transit interface rejected for keyless MD5",
			ospf: &config.OSPFConfig{Areas: []*config.OSPFArea{
				{ID: "0.0.0.1", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/0.0", AuthType: "md5"}},
					VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.2", TransitArea: "0.0.0.1"}}},
			}},
		},
		{
			name: "transit interface rejected for keyless simple auth",
			ospf: &config.OSPFConfig{Areas: []*config.OSPFArea{
				{ID: "0.0.0.1", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/0.0", AuthType: "simple"}},
					VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.2", TransitArea: "0.0.0.1"}}},
			}},
		},
		{
			name: "control transit renders interface",
			ospf: &config.OSPFConfig{Areas: []*config.OSPFArea{
				{ID: "0.0.0.1", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/0.0"}},
					VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.2", TransitArea: "0.0.0.1"}}},
			}},
			want: "area 0.0.0.1 virtual-link 10.0.0.2\n",
		},
		{
			name: "control integer transit spelling matches dotted area",
			ospf: &config.OSPFConfig{Areas: []*config.OSPFArea{
				{ID: "0.0.0.1", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/0.0"}},
					VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.2", TransitArea: "1"}}},
			}},
			want: "area 1 virtual-link 10.0.0.2\n",
		},
		{
			name: "mixed one VL kept one dropped",
			ospf: &config.OSPFConfig{Areas: []*config.OSPFArea{
				{ID: "0.0.0.1", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/0.0"}},
					VirtualLinks: []*config.OSPFVirtualLink{
						{NeighborID: "10.0.0.2", TransitArea: "0.0.0.1"},
						{NeighborID: "10.0.0.3", TransitArea: "0.0.0.2"},
					}},
				{ID: "0.0.0.2"},
			}},
			want: "area 0.0.0.1 virtual-link 10.0.0.2\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := m.generateProtocols(tc.ospf, nil, nil, nil, nil, "", 0, nil, nil)
			if tc.want == "" {
				if strings.Contains(got, "virtual-link") {
					t.Errorf("VL rendered with no transit interface:\n%s", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("valid VL %q missing:\n%s", tc.want, got)
			}
			activation := strings.Index(got, " ip ospf area 0.0.0.1\n")
			if activation < 0 || strings.Index(got, tc.want) <= activation {
				t.Errorf("VL must follow actual transit activation:\n%s", got)
			}
			if tc.name == "mixed one VL kept one dropped" && strings.Contains(got, "virtual-link 10.0.0.3") {
				t.Errorf("VL with interfaceless transit rendered:\n%s", got)
			}
		})
	}
}
