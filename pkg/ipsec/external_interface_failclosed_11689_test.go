package ipsec

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #11689: an external-interface that cannot supply a local address must not
// omit local_addrs and silently let charon bind every local interface. Cover a
// typo, an interface deleted after authoring, and a configured interface whose
// kernel link has no address; each must skip only the affected VPN and name the
// original interface in the warning.
func TestRenderConfigFailsClosedOnUnresolvableExternalInterface_11689(t *testing.T) {
	for _, tc := range []struct {
		name             string
		iface            string
		configured       bool
		deletedAfterEdit bool
	}{
		{
			name:  "typo",
			iface: "xpf-11689-typo00",
		},
		{
			name:             "deleted interface",
			iface:            "xpf-11689-delete0",
			configured:       true,
			deletedAfterEdit: true,
		},
		{
			name:       "kernel miss",
			iface:      "xpf-11689-kernel00",
			configured: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			interfaces := map[string]*config.InterfaceConfig{}
			if tc.configured {
				interfaces[tc.iface] = &config.InterfaceConfig{
					Name: tc.iface,
					Units: map[int]*config.InterfaceUnit{
						0: {Number: 0},
					},
				}
			}
			cfg := &config.Config{
				Interfaces: config.InterfacesConfig{Interfaces: interfaces},
				Security: config.SecurityConfig{IPsec: config.IPsecConfig{
					Gateways: map[string]*config.IPsecGateway{
						"missing": {Name: "missing", Address: "203.0.113.1", ExternalIface: tc.iface + ".0"},
					},
					VPNs: map[string]*config.IPsecVPN{
						"missing-vpn": {PSK: "fixture-secret", Gateway: "missing", LocalID: "10.0.1.0/24", RemoteID: "10.0.2.0/24"},
						"healthy":     {PSK: "fixture-secret", Gateway: "203.0.113.2", LocalID: "10.0.3.0/24", RemoteID: "10.0.4.0/24"},
					},
				}},
			}
			if tc.deletedAfterEdit {
				// Model deletion after the gateway reference was authored: the
				// committed reference remains, but the current interface config
				// no longer supplies an address.
				delete(cfg.Interfaces.Interfaces, tc.iface)
			}

			prepared := PrepareConfig(cfg)
			if got := prepared.Gateways["missing"].LocalAddress; got != "" {
				t.Fatalf("unresolvable external-interface unexpectedly resolved to %q", got)
			}
			warnings := captureWarnings10881(t)
			got, rendered, err := (&Manager{}).renderConfig(prepared)
			if err != nil {
				t.Fatalf("renderConfig: %v", err)
			}
			// #15024: missing-vpn renders under gateway missing when not skipped.
			if rendered["missing"] {
				t.Fatalf("VPN using unresolved external-interface %q rendered and would bind all local addresses:\n%s", tc.iface, got)
			}
			if !rendered["healthy"] {
				t.Fatalf("healthy sibling VPN was dropped alongside the unresolved external-interface:\n%s", got)
			}
			parseSwanctlDoc(t, got).at(t, "connections").hasNoChild(t, "missing")
			parseSwanctlDoc(t, got).at(t, "connections").hasNoChild(t, "missing-vpn")
			if !strings.Contains(warnings.String(), tc.iface+".0") {
				t.Fatalf("warning does not name external interface %q: %s", tc.iface+".0", warnings.String())
			}
		})
	}
}

// #13124 (D10-07): the bindless selector fence must fence exactly the VPNs the
// production render loads. An unresolved external-interface is skipped by
// renderConfig (fail-closed, #11689), so its selectors must not be fenced; the
// healthy single-stack-mismatch gateway (v6 peer, v4-only interface) resolves
// through the family fallback and must stay fenced. Config-only replay must
// also make that fallback, avoiding a spurious ErrGenerationUnvalidatable.
func TestRenderedVPNSetMatchesProductionRenderAndReplayFallback_13124(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"wan0": {Name: "wan0", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"192.0.2.10/24"}},
			}},
			"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0},
			}},
		}},
		Security: config.SecurityConfig{IPsec: config.IPsecConfig{
			Gateways: map[string]*config.IPsecGateway{
				"unres-gw":    {Name: "unres-gw", Address: "203.0.113.1", ExternalIface: "ge-0/0/0.0"},
				"fallback-gw": {Name: "fallback-gw", Address: "2001:db8::1", ExternalIface: "wan0.0"},
			},
			VPNs: map[string]*config.IPsecVPN{
				"vpn-unres":    {PSK: "fixture-secret", Gateway: "unres-gw", LocalID: "10.0.1.0/24", RemoteID: "10.0.2.0/24"},
				"vpn-fallback": {PSK: "fixture-secret", Gateway: "fallback-gw", LocalID: "10.0.3.0/24", RemoteID: "10.0.4.0/24"},
			},
		}},
	}
	prepared := PrepareConfig(cfg)
	_, runtimeRendered, err := (&Manager{}).renderConfig(prepared)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	// #15024: the production rendered set is connection-keyed (gateways).
	if runtimeRendered["unres-gw"] {
		t.Fatal("FIXTURE: production render must skip vpn-unres (#11689)")
	}
	if !runtimeRendered["fallback-gw"] {
		t.Fatal("FIXTURE: production render must load vpn-fallback via single-stack fallback")
	}
	if got := prepared.Gateways["fallback-gw"].LocalAddress; got != "192.0.2.10" {
		t.Fatalf("FIXTURE: PrepareConfig fallback LocalAddress = %q, want 192.0.2.10", got)
	}

	renderedSet := RenderedVPNSet(cfg)
	if renderedSet["vpn-unres"] {
		t.Error("RenderedVPNSet fences vpn-unres, which the production render skips — its bindless selector fence would blackhole cleartext for an SA that never establishes")
	}
	if !renderedSet["vpn-fallback"] {
		t.Error("RenderedVPNSet drops vpn-fallback, which the production render loads — its selectors would be unfenced")
	}

	replay, runtime := prepareConfigFromConfig(cfg)
	if got := replay.Gateways["fallback-gw"].LocalAddress; got != "192.0.2.10" {
		t.Errorf("prepareConfigFromConfig fallback LocalAddress = %q, want 192.0.2.10 (single-stack family fallback)", got)
	}
	if runtime["fallback-gw"] {
		t.Errorf("prepareConfigFromConfig marks fallback-gw runtime-dependent, so ExpectedLoadedConns would spuriously fail with ErrGenerationUnvalidatable")
	}
	replayCfg := *cfg
	security := cfg.Security
	ipsecCfg := security.IPsec
	ipsecCfg.Gateways = map[string]*config.IPsecGateway{"fallback-gw": cfg.Security.IPsec.Gateways["fallback-gw"]}
	ipsecCfg.VPNs = map[string]*config.IPsecVPN{"vpn-fallback": cfg.Security.IPsec.VPNs["vpn-fallback"]}
	security.IPsec = ipsecCfg
	replayCfg.Security = security
	if _, err := ExpectedLoadedConns(&replayCfg); err != nil {
		t.Errorf("ExpectedLoadedConns must validate the single-stack fallback generation from config alone: %v", err)
	}
}

// A resolvable external-interface remains an explicit local bind in swanctl;
// the fail-closed render belt is only for a genuine resolution miss.
func TestRenderConfigKeepsResolvedExternalInterfaceLocalBind_11689(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"wan0": {Name: "wan0", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"198.51.100.7/24"}},
			}},
		}},
		Security: config.SecurityConfig{IPsec: config.IPsecConfig{
			Gateways: map[string]*config.IPsecGateway{
				"gw": {Name: "gw", Address: "203.0.113.1", ExternalIface: "wan0.0"},
			},
			VPNs: map[string]*config.IPsecVPN{
				"tun": {PSK: "fixture-secret", Gateway: "gw", LocalID: "10.0.1.0/24", RemoteID: "10.0.2.0/24"},
			},
		}},
	}
	got, rendered, err := (&Manager{}).renderConfig(PrepareConfig(cfg))
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	// #15024: tun renders under gateway gw.
	if !rendered["gw"] {
		t.Fatalf("resolvable external-interface was skipped:\n%s", got)
	}
	parseSwanctlDoc(t, got).at(t, "connections", "gw").requireSetting(t, "local_addrs", "198.51.100.7")
}

// Config-only generation validation cannot know whether the live kernel will
// provide an external-interface address; it must keep the connection candidate
// visible so ExpectedLoadedConns reports it as unvalidatable, not as absent.
func TestExpectedLoadedConnsExternalInterfaceMissRemainsUnvalidatable_11689(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{IPsec: config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "203.0.113.1", ExternalIface: "xpf-11689-kernel00.0"},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {PSK: "fixture-secret", Gateway: "gw", LocalID: "10.0.1.0/24", RemoteID: "10.0.2.0/24"},
		},
	}}}
	if _, err := ExpectedLoadedConns(cfg); !errors.Is(err, ErrGenerationUnvalidatable) {
		t.Fatalf("ExpectedLoadedConns error = %v, want ErrGenerationUnvalidatable for the unresolved runtime address", err)
	}
}
