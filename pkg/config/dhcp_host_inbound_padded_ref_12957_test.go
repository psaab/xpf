package config

import (
	"strings"
	"testing"
)

// #12957 (follow-up #12842): a padded DHCP group ref (`ge-0/0/1.00`) must draw
// the same #6460 advisory its canonical spelling would. #12843 canonicalized
// the zone-map lookup; the EFFECTIVE-POLICY probes
// (InterfaceHostInboundOverride / InterfaceHostInboundEffective) canonicalize
// internally only through the compiled stamp, so on a config without stamps a
// padded ref missed a canonically-keyed interface override: the #6515 replace
// semantics were silently skipped (zone admits dhcp + override omits it — no
// warning) or the override's admission was ignored (zone omits dhcp + override
// admits it — a false warning with an unneeded zone remedy).

// mkPadded12957 builds a hand-built (stamp-free) config: interface ge-0/0/1
// with unit 1, zone untrust holding ge-0/0/1.1, a dhcp-local-server group
// bound to the PADDED ref ge-0/0/1.01, and the given zone-level services and
// interface-level overrides.
func mkPadded12957(zoneSvc []string, overrides map[string][]string) *Config {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{1: {Number: 1}}},
	}
	z := &ZoneConfig{
		Interfaces:         []string{"ge-0/0/1.1"},
		HostInboundTraffic: &HostInboundTraffic{SystemServices: zoneSvc},
	}
	for k, v := range overrides {
		if z.InterfaceHostInbound == nil {
			z.InterfaceHostInbound = map[string]*HostInboundTraffic{}
		}
		z.InterfaceHostInbound[k] = &HostInboundTraffic{SystemServices: v}
	}
	cfg.Security.Zones = map[string]*ZoneConfig{"untrust": z}
	cfg.System.DHCPServer.DHCPLocalServer = mkDHCPGroups("g1", "ge-0/0/1.01")
	return cfg
}

func TestPaddedDHCPGroupRefResolvesOverridePolicy12957(t *testing.T) {
	t.Run("override-admits", func(t *testing.T) {
		// Zone omits dhcp; the canonically-keyed override admits it. The
		// override governs (#6515), so no warning may fire — at pristine
		// master the padded probe missed the override and warned with the
		// zone remedy.
		w := validateDHCPServerHostInboundBypassWarnings(mkPadded12957(
			[]string{"ssh"}, map[string][]string{"ge-0/0/1.1": {"dhcp"}}))
		if len(w) != 0 {
			t.Fatalf("padded ref must see the canonically-keyed override that admits dhcp, got %v", w)
		}
	})

	t.Run("override-omits", func(t *testing.T) {
		// Zone admits dhcp; the canonically-keyed override omits it. The
		// override REPLACES the zone set (#6515), so the advisory must fire
		// with the interface-level remedy — at pristine master the missed
		// override let the zone-level token answer and the advisory was
		// silently skipped.
		w := validateDHCPServerHostInboundBypassWarnings(mkPadded12957(
			[]string{"dhcp"}, map[string][]string{"ge-0/0/1.1": {"ssh"}}))
		if !hasWarn6460(w, `override omits "dhcp"`) ||
			!hasWarn6460(w, `to interface "ge-0/0/1.01" in zone "untrust"`) {
			t.Fatalf("padded ref must be held to the canonically-keyed override that omits dhcp, got %v", w)
		}
	})

	t.Run("authored-spelling-override", func(t *testing.T) {
		// #12843's authored-spelling guarantee stands: an override keyed by
		// the group ref's own padded spelling still applies.
		w := validateDHCPServerHostInboundBypassWarnings(mkPadded12957(
			[]string{"ssh"}, map[string][]string{"ge-0/0/1.01": {"dhcp"}}))
		if len(w) != 0 {
			t.Fatalf("same-spelling override must still admit dhcp, got %v", w)
		}
	})

	t.Run("both-spellings-union", func(t *testing.T) {
		// Both spellings declare an override: one interface identity, so the
		// interface level is the UNION (the compiled stamp unions
		// same-identity unit keys) and it admits dhcp — no warning.
		w := validateDHCPServerHostInboundBypassWarnings(mkPadded12957([]string{"ssh"}, map[string][]string{
			"ge-0/0/1.1":  {"ping"},
			"ge-0/0/1.01": {"dhcp"},
		}))
		if len(w) != 0 {
			t.Fatalf("same-identity overrides union to admit dhcp, got %v", w)
		}
	})
}

// TestPaddedDHCPGroupRefCompiledAdvisory12957 pins the compiled path end to
// restrictive zone (the #12842 review residual — the managed-routing gate got
// the canonicalization, this advisory now provably has it on both planes:
// zone lookup and effective policy).
func TestPaddedDHCPGroupRefCompiledAdvisory12957(t *testing.T) {
	base := []string{
		"set interfaces ge-0/0/1 unit 1 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.1",
		"set system services dhcp-local-server group g1 interface ge-0/0/1.01",
	}

	// (e) Restrictive zone: the advisory must fire for the padded ref.
	cfg, err := CompileConfig(buildTree(t, append(append([]string{}, base...),
		"set security zones security-zone trust host-inbound-traffic system-services ssh")))
	if err != nil {
		t.Fatalf("(e) compile: %v", err)
	}
	if got := warningsContaining(cfg.Warnings, "(#6460)"); len(got) != 1 ||
		!strings.Contains(got[0], `serves interface "ge-0/0/1.01" (security zone "trust")`) {
		t.Fatalf("(e) padded ref must draw the #6460 advisory against the restrictive zone, got %v", cfg.Warnings)
	}

	// (f) Canonical-keyed interface override that omits dhcp while the zone
	// admits it: the override governs and the advisory fires with the
	// interface-level remedy.
	cfgF, err := CompileConfig(buildTree(t, append(append([]string{}, base...),
		"set security zones security-zone trust host-inbound-traffic system-services dhcp",
		"set security zones security-zone trust interfaces ge-0/0/1.1 host-inbound-traffic system-services ssh")))
	if err != nil {
		t.Fatalf("(f) compile: %v", err)
	}
	gotF := warningsContaining(cfgF.Warnings, "(#6460)")
	if len(gotF) != 1 || !strings.Contains(gotF[0], `override omits "dhcp"`) ||
		!strings.Contains(gotF[0], `to interface "ge-0/0/1.01" in zone "trust"`) {
		t.Fatalf("(f) padded ref must be held to the canonically-keyed override, got %v", cfgF.Warnings)
	}

	// (g) The override admitting dhcp silences the advisory.
	cfgG, err := CompileConfig(buildTree(t, append(append([]string{}, base...),
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set security zones security-zone trust interfaces ge-0/0/1.1 host-inbound-traffic system-services dhcp")))
	if err != nil {
		t.Fatalf("(g) compile: %v", err)
	}
	if got := warningsContaining(cfgG.Warnings, "(#6460)"); len(got) != 0 {
		t.Fatalf("(g) canonically-keyed override admitting dhcp must silence the advisory, got %v", got)
	}
}
