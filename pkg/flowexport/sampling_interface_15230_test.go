package flowexport

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15230 A46-05: interface sampling must be enforced per interface, not
// per zone. ge-0/0/0.0 (sampled input, v4) and ge-0/0/1.0 (unsampled) share
// zone trust; ge-0/0/2.0 is untrust. A flow ingressing on the unsampled
// interface must not be exported merely because its zone-mate is sampled,
// and must not consume a 1-in-N slot. The sampled interface's flow is the
// control. FAIL-ON-REVERT: zone-only ShouldExport exports both.
func samplingInterfaceConfig15230(t *testing.T) *config.Config {
	t.Helper()
	text := `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet { address 10.0.0.1/24; sampling { input; } }
            family inet6 { address 2001:db8::1/64; sampling { input; } }
        }
    }
    ge-0/0/1 {
        unit 0 {
            family inet { address 10.0.1.1/24; }
            family inet6 { address 2001:db8:0:1::1/64; }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet { address 192.0.2.1/24; }
            family inet6 { address 2001:db8:1::1/64; }
        }
    }
}
security {
    zones {
        security-zone trust { interfaces { ge-0/0/0.0; ge-0/0/1.0; } }
        security-zone untrust { interfaces { ge-0/0/2.0; } }
    }
}
`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func TestSamplingPerInterface15230(t *testing.T) {
	cfg := samplingInterfaceConfig15230(t)
	zoneIDs := map[string]uint16{"trust": 2, "untrust": 3}
	sz := BuildSamplingZones(cfg, zoneIDs)

	// The per-interface maps must distinguish the two trust interfaces.
	if d, ok := sz.sampledInterface("ge-0/0/0.0", false); !ok || !d.Input {
		t.Fatalf("ge-0/0/0.0 v4 sampling = %+v ok=%v, want Input", d, ok)
	}
	if _, ok := sz.sampledInterface("ge-0/0/1.0", false); ok {
		t.Fatal("ge-0/0/1.0 must not appear in the v4 sampled-interface set")
	}

	ec := &ExportConfig{SamplingZones: sz, SamplingRate: 2}
	// Unsampled ingress interface: denied twice, no slot consumed.
	if ec.ShouldExportIface(2, 3, false, "ge-0/0/1.0", "") {
		t.Fatal("flow on unsampled ge-0/0/1.0 exported via sampled zone-mate ge-0/0/0.0")
	}
	if ec.ShouldExportIface(2, 3, false, "ge-0/0/1.0", "") {
		t.Fatal("unsampled-interface flow exported on second call (slot consumed?)")
	}
	if ev, sel, zf := ec.SamplingStats(); ev != 0 || sel != 0 || zf != 2 {
		t.Fatalf("stats after unsampled denies = evaluated %d selected %d zoneFiltered %d, want 0/0/2", ev, sel, zf)
	}
	// Sampled ingress interface control: rate 2 samples the second call in.
	if ec.ShouldExportIface(2, 3, false, "ge-0/0/0.0", "") {
		t.Fatal("first sampled-interface flow must be sampled out at rate 2")
	}
	if !ec.ShouldExportIface(2, 3, false, "ge-0/0/0.0", "") {
		t.Fatal("second sampled-interface flow must be sampled in at rate 2")
	}
	// IPv6 twin on the unsampled interface is likewise denied.
	ec6 := &ExportConfig{SamplingZones: sz}
	if ec6.ShouldExportIface(2, 3, true, "ge-0/0/1.0", "") {
		t.Fatal("IPv6 flow on unsampled ge-0/0/1.0 exported")
	}
	if !ec6.ShouldExportIface(2, 3, true, "ge-0/0/0.0", "") {
		t.Fatal("IPv6 flow on sampled ge-0/0/0.0 not exported")
	}
	// A record naming no interface at all keeps zone semantics (legacy
	// producers); a record naming an unsampled interface is denied above.
	ecU := &ExportConfig{SamplingZones: sz}
	if !ecU.ShouldExportIface(2, 3, false, "", "") {
		t.Fatal("nameless record must keep zone semantics")
	}
	// Egress direction: output sampled only on ge-0/0/0.0 in a second config
	// shape is covered by the zone fallback tests; here egress via the
	// unsampled interface with no ingress match must also deny.
	if ecU.ShouldExportIface(3, 2, false, "ge-0/0/2.0", "ge-0/0/1.0") {
		t.Fatal("flow egressing unsampled ge-0/0/1.0 exported via zone-mate output")
	}
}

// TestSamplingPerInterfaceLegacyFallback15230 pins the neighbouring
// legitimate behaviour: configs whose ExportConfig was built by hand with
// only per-zone maps (no per-interface data) keep the exact zone semantics,
// and a config with no sampling anywhere stays export-all even when an
// interface name is supplied.
func TestSamplingPerInterfaceLegacyFallback15230(t *testing.T) {
	zoneOnly := &ExportConfig{SamplingZones: FamilySamplingDirs{
		V4: map[uint16]SamplingDir{2: {Input: true}},
		V6: map[uint16]SamplingDir{2: {Input: true}},
	}}
	if !zoneOnly.ShouldExportIface(2, 3, false, "ge-0/0/1.0", "") {
		t.Fatal("zone-only config must retain zone semantics (no per-interface data)")
	}
	if zoneOnly.ShouldExportIface(1, 3, false, "ge-0/0/1.0", "") {
		t.Fatal("zone-only config must still deny unmatched zones")
	}
	open := &ExportConfig{}
	if !open.ShouldExportIface(2, 3, false, "ge-0/0/1.0", "") {
		t.Fatal("unrestricted config must export regardless of interface")
	}
	// FlowDirection follows the same per-interface selection.
	cfg := samplingInterfaceConfig15230(t)
	ec := &ExportConfig{SamplingZones: BuildSamplingZones(cfg, map[string]uint16{"trust": 2, "untrust": 3})}
	if got := ec.FlowDirectionIface(2, 3, false, "ge-0/0/0.0", ""); got != 0 {
		t.Fatalf("FlowDirectionIface sampled ingress = %d, want 0", got)
	}
	if got := ec.FlowDirectionIface(2, 3, false, "ge-0/0/1.0", ""); got != 0 {
		t.Fatalf("FlowDirectionIface unsampled = %d, want 0 (default)", got)
	}
}
