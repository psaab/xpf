package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7515 — the networkd row's VRFName (rendered as `KeepMaster=yes` since
// #18597; formerly a `VRF=vrf-mgmt` stanza networkd could not resolve) is the
// third site of the management-interface class. It must agree with the
// daemon's management-VRF set: if it drifts, `networkctl reconfigure` releases
// a binding the daemon just made, or pins one the daemon never made.
//
// The assertion is against config.IsManagementIfName, not a prefix literal. The
// name list below is a probe POPULATION mirrored from the sibling tests — a
// drifted list only weakens coverage here, while a duplicated EXPECTATION would
// silently encode which of the three sites is trusted.
var mgmtIfNameCases7515 = []string{
	"fxp0", "em0", "fab0", "fab1",
	"emu0", "embed0", "fabric0", "fxpanel0",
	"ge-0/0/0", "reth0", "lo0", "start0", "e0", "f0",
}

// TestNetworkdVRFStanzaAgreesWithManagementSSOT7515 drives the real networkd
// model builder and reads VRFName (the KeepMaster=yes source) off the emitted
// models.
//
// FAIL-ON-REVERT: put the raw prefix list back at the emitter and this stays
// green only while the two coincide — narrow or widen either side alone and it
// reds, in either direction.
func TestNetworkdVRFStanzaAgreesWithManagementSSOT7515(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{}
	ifCache := map[string]*net.Interface{}
	for i, name := range mgmtIfNameCases7515 {
		cfg.Interfaces.Interfaces[name] = &config.InterfaceConfig{
			Name:  name,
			Units: map[int]*config.InterfaceUnit{0: {Number: 0, Addresses: []string{"10.0.0.1/24"}}},
		}
		ln := config.LinuxIfName(name)
		// A HardwareAddr is REQUIRED: the builder skips any interface whose MAC
		// is empty (`if mac == "" { continue }`), so a fixture without one emits
		// no models at all and every assertion below would be vacuous. The
		// precondition at the end of this test is what caught that.
		ifCache[ln] = &net.Interface{
			Index:        i + 1,
			Name:         ln,
			HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, byte(i + 1)},
		}
	}

	result := &CompileResult{ifCache: ifCache}
	buildInterfaceNetworkdModels(cfg, result, map[string]bool{})

	seen := map[string]bool{}
	for _, mi := range result.ManagedInterfaces {
		seen[mi.Name] = true
		// Recover the CONFIG name this model came from, so the SSOT is asked
		// the same question the emitter was.
		var cfgName string
		for name := range cfg.Interfaces.Interfaces {
			if config.LinuxIfName(name) == mi.Name {
				cfgName = name
				break
			}
		}
		if cfgName == "" {
			continue
		}
		gotMgmt := mi.VRFName == "vrf-mgmt"
		if want := config.IsManagementIfName(cfgName); gotMgmt != want {
			t.Errorf("%s: networkd VRFName=%q (management=%v), but config.IsManagementIfName = %v. "+
				"A divergence here means networkctl reconfigure strips a binding the daemon "+
				"made, or preserves one it never made (#7515)", cfgName, mi.VRFName, gotMgmt, want)
		}
	}
	if len(seen) == 0 {
		t.Fatal("precondition: the networkd builder emitted no managed interfaces at all, so " +
			"every assertion above was vacuous")
	}
}
