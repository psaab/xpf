package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9820 (Path D): the area render belt omits the area stanza line, the
// per-interface `ip ospf area` line (keeping the block's other settings),
// and the OSPFv3 per-interface `ipv6 ospf6 area` line for area IDs the commit
// gate refuses (mapped, padded, malformed). Well-formed IDs render through
// their current FRR grammar.
//
// NOTE on belt attribution: post-tightening, every value FRRSingleToken
// rejects is also rejected by ValidateOSPFArea, so the token arm is
// defense-in-depth with no standalone behavioral cell — the combined belt is
// what these cells prove.
//
// FAIL-ON-REVERT: drop validFRROSPFArea from any of the three sites and
// the corresponding omission cell renders the raw ID again.

// Direct render cells against hand-built protocol configs.
func TestOSPFAreaBeltOmitsBadIDs_9820(t *testing.T) {
	m := &Manager{}
	for _, tc := range []struct {
		name string
		id   string
	}{
		{"spaced", "0 1"},
		{"mapped", "::ffff:192.0.2.1"},
		{"padded", " 0.0.0.0 "},
		{"leading-newline", "\n0.0.0.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := m.generateProtocols(ospfForBelt9820(tc.id), nil, nil, nil, nil, "", 0, nil, nil)
			if strings.Contains(got, tc.id) {
				t.Fatalf("bad area id %q reached frr.conf:\n%s", tc.id, got)
			}
			// The interface block and its non-area settings survive;
			// only the activation line is omitted.
			for _, want := range []string{
				"interface trust0\n",
				" ip ospf cost 10\n",
				" ip ospf hello-interval 5\n",
				" ip ospf bfd\n",
			} {
				if !strings.Contains(got, want) {
					t.Fatalf("non-area setting %q missing after omission:\n%s", want, got)
				}
			}
			if strings.Contains(got, "ip ospf area ") {
				t.Fatalf("area activation line must be omitted:\n%s", got)
			}
		})
	}
}

func ospfForBelt9820(id string) *config.OSPFConfig {
	return &config.OSPFConfig{
		RouterID: "1.1.1.1",
		Areas: []*config.OSPFArea{{
			ID:       id,
			AreaType: "stub",
			Interfaces: []*config.OSPFInterface{
				{Name: "trust0", Cost: 10, HelloInterval: 5, BFD: true},
			},
		}},
	}
}

func TestOSPFAreaBeltWellFormedByteIdentical_9820(t *testing.T) {
	m := &Manager{}
	got := m.generateProtocols(ospfWellFormed9820(), nil, nil, nil, nil, "", 0, nil, nil)
	for _, want := range []string{
		" area 0.0.0.1 stub\n",
		" area 0.0.0.0 virtual-link 10.0.0.2\n",
		"interface trust0\n ip ospf area 0.0.0.1\nexit\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("well-formed area line %q missing:\n%s", want, got)
		}
	}
}

func ospfWellFormed9820() *config.OSPFConfig {
	return &config.OSPFConfig{
		RouterID: "1.1.1.1",
		Areas: []*config.OSPFArea{{
			ID:       "0.0.0.1",
			AreaType: "stub",
			Interfaces: []*config.OSPFInterface{
				{Name: "trust0"},
			},
			VirtualLinks: []*config.OSPFVirtualLink{
				{NeighborID: "10.0.0.2", TransitArea: "0.0.0.0"},
			},
		}},
	}
}

func TestOSPFv3AreaBelt_9820(t *testing.T) {
	m := &Manager{}
	// Bad IDs are omitted by the belt. Unlike OSPFv2's area line above,
	// OSPFv3 activation is now the FRR 10.6 interface-node command
	// `ipv6 ospf6 area`, not the removed router-level `interface ... area`.
	bad := &config.OSPFv3Config{
		RouterID: "1.1.1.1",
		Areas: []*config.OSPFv3Area{{
			ID:         "::ffff:192.0.2.1",
			Interfaces: []*config.OSPFv3Interface{{Name: "trust0"}},
		}},
	}
	if got := m.generateProtocols(nil, bad, nil, nil, nil, "", 0, nil, nil); strings.Contains(got, "::ffff") {
		t.Fatalf("bad ospf3 area id reached frr.conf:\n%s", got)
	}
	good := &config.OSPFv3Config{
		RouterID: "1.1.1.1",
		Areas: []*config.OSPFv3Area{{
			ID:         "0.0.0.0",
			Interfaces: []*config.OSPFv3Interface{{Name: "trust0"}},
		}},
	}
	if got := m.generateProtocols(nil, good, nil, nil, nil, "", 0, nil, nil); !strings.Contains(got, "interface trust0\n ipv6 ospf6 area 0.0.0.0\nexit\n") {
		t.Fatalf("well-formed ospf3 interface-node area line changed:\n%s", got)
	}
}

func TestOSPFAreaBeltVRFCovered_9820(t *testing.T) {
	m := &Manager{}
	bad := ospfForBelt9820("0 1")
	if got := m.generateProtocols(bad, nil, nil, nil, nil, "vrf-tenant", 0, nil, nil); strings.Contains(got, "0 1") {
		t.Fatalf("bad area id reached VRF frr.conf:\n%s", got)
	}
	good := ospfWellFormed9820()
	got := m.generateProtocols(good, nil, nil, nil, nil, "vrf-tenant", 0, nil, nil)
	if !strings.Contains(got, "router ospf vrf vrf-tenant\n") ||
		!strings.Contains(got, " ip ospf area 0.0.0.1\n") {
		t.Fatalf("well-formed VRF area changed:\n%s", got)
	}
}

// Lenient-compile→render integration: the tolerant compiler stores the
// raw `"0 1"` area ID, and the renderer omits every line carrying it.
func TestOSPFAreaBeltLenientIntegration_9820(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{`set protocols ospf area "0 1" interface ge-0/0/0.0`} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand: %v", err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must NOT fail: %v", err)
	}
	if cfg.Protocols.OSPF == nil || len(cfg.Protocols.OSPF.Areas) != 1 ||
		cfg.Protocols.OSPF.Areas[0].ID != "0 1" {
		t.Fatalf("lenient compile must retain the raw area id: %+v", cfg.Protocols.OSPF)
	}
	m := &Manager{}
	got := m.generateProtocols(cfg.Protocols.OSPF, nil, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "0 1") {
		t.Fatalf("tolerant render emitted the raw area id:\n%s", got)
	}
	if !strings.Contains(got, "interface ge-0/0/0.0\n") {
		t.Fatalf("interface block must survive area omission:\n%s", got)
	}
}
