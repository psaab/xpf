package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// classifyCfg9821 builds a zone with a declared dotted interface whose unit
// carries an ssh override: queries on padded spellings must resolve through
// the declared-aware split, not the cfg-free first-dot canonicalization.
func classifyCfg9821() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"p.0": {Name: "p.0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0},
			1: {Number: 1},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"z": {
			Name:               "z",
			Interfaces:         []string{"p.0.1"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ntp"}},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"p.0.1": {SystemServices: []string{"ssh"}},
			},
		},
	}
	return cfg
}

// TestClassifyPaddedDeclaredUnitResolves9821 pins D6 site 1: a query for
// `p.0.01` finds the override authored as `p.0.1` (admit ssh), instead of
// missing onto the zone set (ntp).
func TestClassifyPaddedDeclaredUnitResolves9821(t *testing.T) {
	cfg := classifyCfg9821()
	got := ClassifyHostInboundForInterface(cfg, "z", "p.0.01", hi5579TCP, true, 22, nil, "ip")
	if got.Status != HostInboundTokenAdmit || got.Token != "ssh" {
		t.Fatalf("padded query status = (%v,%q) — want ssh token-admit via the canonical override", got.Status, got.Token)
	}
	canon := ClassifyHostInboundForInterface(cfg, "z", "p.0.1", hi5579TCP, true, 22, nil, "ip")
	if canon.Status != got.Status || canon.Token != got.Token {
		t.Errorf("canonical query (%v,%q) disagrees with padded (%v,%q) — spellings must agree",
			canon.Status, canon.Token, got.Status, got.Token)
	}
}

// TestResolveDottedPhysicalRedirects9821 pins D6 site 2a: a bare `p.0`
// (declared, dotted) IS a physical ref and hits the logical-unit rejection
// with a Base-relative redirect — it must not bypass on dot-presence into a
// misleading "unknown ingress-interface".
func TestResolveDottedPhysicalRedirects9821(t *testing.T) {
	cfg := classifyCfg9821()
	err := ResolveHostInboundIngressInterface(cfg, "z", "p.0")
	if err == nil {
		t.Fatal("bare p.0 accepted — want the physical-interface redirect")
	}
	if !strings.Contains(err.Error(), "physical interface") || !strings.Contains(err.Error(), "p.0.0") {
		t.Errorf("bare p.0 error = %q — want the physical redirect naming p.0.0", err)
	}
}

// TestResolvePaddedDeclaredUnitValidates9821 pins D6 site 2b (advisory/
// runtime key parity): `p.0.01` validates against the zone its canonical
// unit binds — the same Literal key the runtime map carries.
func TestResolvePaddedDeclaredUnitValidates9821(t *testing.T) {
	cfg := classifyCfg9821()
	if err := ResolveHostInboundIngressInterface(cfg, "z", "p.0.01"); err != nil {
		t.Errorf("padded query rejected: %v — want validation via the canonical unit key", err)
	}
	if err := ResolveHostInboundIngressInterface(cfg, "z", "p.0.1"); err != nil {
		t.Errorf("canonical query rejected: %v", err)
	}
}
