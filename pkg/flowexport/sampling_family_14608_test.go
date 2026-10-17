package flowexport

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14608: interface sampling is per-family. `family inet sampling input`
// on the trust unit must NOT select IPv6 flows, and an unselected IPv6
// flow must not consume a 1-in-N slot; the twin `family inet6 sampling
// input` MUST select IPv6 flows. The probe runs through the real parser
// -> compiler -> BuildSamplingZones -> ShouldExport path.
//
// FAIL-ON-REVERT: on the pre-fix code the two compiler arms wrote one
// family-less SamplingInput/SamplingOutput pair, BuildSamplingZones had
// no family dimension, and ShouldExport had no family parameter — an
// inet-only config exported the IPv6 trust->untrust close (RED evidence
// in docs/log/14608.md).

// samplingFamilyConfig14608 compiles a two-interface, two-zone config
// where the trust unit carries sampling input under exactly one family
// (family == "" means no sampling at all).
func samplingFamilyConfig14608(t *testing.T, family string) *config.Config {
	t.Helper()
	sampling := ""
	if family != "" {
		sampling = "family " + family + " { sampling { input; } }"
	}
	text := `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet { address 10.0.0.1/24; }
            family inet6 { address 2001:db8::1/64; }
            ` + sampling + `
        }
    }
    ge-0/0/1 {
        unit 0 {
            family inet { address 192.0.2.1/24; }
            family inet6 { address 2001:db8:1::1/64; }
        }
    }
}
security {
    zones {
        security-zone trust { interfaces { ge-0/0/0.0; } }
        security-zone untrust { interfaces { ge-0/0/1.0; } }
    }
}
`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func TestSamplingPerFamily14608(t *testing.T) {
	zoneIDs := map[string]uint16{"trust": 2, "untrust": 3}

	t.Run("inet only: IPv6 not exported and consumes no slot", func(t *testing.T) {
		cfg := samplingFamilyConfig14608(t, "inet")
		unit := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
		if !unit.SamplingV4Input || unit.SamplingV6Input || unit.SamplingV6Output {
			t.Fatalf("compiled flags = v4in:%v v6in:%v v6out:%v, want true/false/false",
				unit.SamplingV4Input, unit.SamplingV6Input, unit.SamplingV6Output)
		}
		sz := BuildSamplingZones(cfg, zoneIDs)
		// #14608 global rule: inet sampled somewhere -> inet6 fails
		// closed with a non-nil empty map.
		if sz.V6 == nil || len(sz.V6) != 0 {
			t.Fatalf("inet-only sampling: V6 = %#v, want non-nil empty (fail closed)", sz.V6)
		}
		if d, ok := sz.V4[2]; !ok || !d.Input || d.Output {
			t.Fatalf("trust V4 = %+v (ok=%v), want Input=true Output=false", sz.V4[2], ok)
		}
		ec := &ExportConfig{SamplingZones: sz, SamplingRate: 2}
		// IPv6 trust->untrust: NOT exported, on either of two calls (the
		// second call proves no 1-in-N slot was consumed by the first).
		if ec.ShouldExport(2, 3, true) {
			t.Fatal("IPv6 flow exported with only family inet sampling configured")
		}
		if ec.ShouldExport(2, 3, true) {
			t.Fatal("IPv6 flow exported on second call: an unselected family consumed a 1-in-N slot")
		}
		if ev, sel, _ := ec.SamplingStats(); ev != 0 || sel != 0 {
			t.Fatalf("IPv6 evaluations consumed sampling state: evaluated=%d selected=%d, want 0/0", ev, sel)
		}
		// IPv4 trust->untrust IS eligible: rate 2 samples the second call in.
		if ec.ShouldExport(2, 3, false) {
			t.Fatal("first eligible IPv4 flow must be sampled out at rate 2")
		}
		if !ec.ShouldExport(2, 3, false) {
			t.Fatal("second eligible IPv4 flow must be sampled in at rate 2")
		}
	})

	t.Run("inet6 only: IPv6 exported, IPv4 not", func(t *testing.T) {
		cfg := samplingFamilyConfig14608(t, "inet6")
		ec := &ExportConfig{SamplingZones: BuildSamplingZones(cfg, zoneIDs), SamplingRate: 2}
		if ec.ShouldExport(2, 3, false) || ec.ShouldExport(2, 3, false) {
			t.Fatal("IPv4 flow exported with only family inet6 sampling configured")
		}
		if ec.ShouldExport(2, 3, true) {
			t.Fatal("first eligible IPv6 flow must be sampled out at rate 2")
		}
		if !ec.ShouldExport(2, 3, true) {
			t.Fatal("second eligible IPv6 flow must be sampled in at rate 2")
		}
	})

	t.Run("inet only: reverse direction also unselected", func(t *testing.T) {
		// Sampling input lives on trust; an IPv6 untrust->trust close is
		// likewise unselected (its family fails closed, and egress trust
		// has no output sampling in either family).
		cfg := samplingFamilyConfig14608(t, "inet")
		ec := &ExportConfig{SamplingZones: BuildSamplingZones(cfg, zoneIDs)}
		if ec.ShouldExport(3, 2, true) {
			t.Fatal("IPv6 untrust->trust exported with only inet trust-input sampling")
		}
		// IPv4 is also unselected in this direction: ingress untrust has
		// no input sampling and egress trust has no output sampling.
		if ec.ShouldExport(3, 2, false) {
			t.Fatal("IPv4 untrust->trust exported (no input on untrust, no output on trust)")
		}
	})

	t.Run("no sampling anywhere stays export-all", func(t *testing.T) {
		cfg := samplingFamilyConfig14608(t, "")
		sz := BuildSamplingZones(cfg, zoneIDs)
		if !sz.unrestricted() {
			t.Fatalf("no sampling anywhere: zones = %#v, want unrestricted (both nil)", sz)
		}
		ec := &ExportConfig{SamplingZones: sz}
		if !ec.ShouldExport(2, 3, false) || !ec.ShouldExport(2, 3, true) {
			t.Fatal("export-all broken when no interface sampling is configured")
		}
	})
}
