package daemon

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

func tighteningScopeCfg(t *testing.T, wanServices []string, lanServices []string) *config.Config {
	t.Helper()
	cfg := hostInboundTestConfig()
	cfg.Security.Zones["wan"].HostInboundTraffic = &config.HostInboundTraffic{SystemServices: wanServices}
	cfg.Security.Zones["lan"].HostInboundTraffic = &config.HostInboundTraffic{SystemServices: lanServices}
	return cfg
}

// kept10752 builds one address's evidence bucket for stash construction.
func kept10752(custom uint64, customSamples []string, other uint64, otherSamples []string) keptAddrEvidence {
	return keptAddrEvidence{custom: custom, customSamples: customSamples, other: other, otherSamples: otherSamples}
}

func TestHostInboundTightenedScopes10752(t *testing.T) {
	full := []string{"any-service"}
	named := []string{"ssh"}
	for _, tc := range []struct {
		name   string
		oldW   []string
		oldL   []string
		newW   []string
		newL   []string
		mutate func(old, new *config.Config)
		want   []string
	}{
		{
			name: "any-service-to-named fires with zone and iface scopes",
			oldW: full, oldL: full, newW: named, newL: full,
			want: []string{"zone:wan", "zone:wan|iface:reth0.50"},
		},
		{
			name: "no change stays silent",
			oldW: named, oldL: named, newW: named, newL: named,
		},
		{
			name: "loosening stays silent",
			oldW: named, oldL: named, newW: full, newL: full,
		},
		{
			name: "staying open stays silent",
			oldW: full, oldL: full, newW: full, newL: full,
		},
		{
			name: "override narrowing fires for the iface scope only",
			oldW: named, oldL: named, newW: named, newL: named,
			mutate: func(old, new *config.Config) {
				old.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
					"reth0.50": {SystemServices: full},
				}
				new.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
					"reth0.50": {SystemServices: named},
				}
			},
			want: []string{"zone:wan|iface:reth0.50"},
		},
		{
			name: "override added over open zone fires zone and iface scopes",
			oldW: full, oldL: named, newW: full, newL: named,
			mutate: func(old, new *config.Config) {
				new.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
					"reth0.50": {SystemServices: named},
				}
			},
			// The zone stanza is textually unchanged, but its full-admit
			// stopped applying anywhere (the only member is now covered),
			// and the member narrowed full→named: both are real narrowings
			// of effective enforcement.
			want: []string{"zone:wan", "zone:wan|iface:reth0.50"},
		},
		{
			name: "deleted full-admit zone fires",
			oldW: full, oldL: named, newW: named, newL: named,
			mutate: func(old, new *config.Config) {
				delete(new.Security.Zones, "wan")
			},
			want: []string{"zone:wan", "zone:wan|iface:reth0.50"},
		},
		{
			name: "zone stanza narrowed but all members overridden stays silent",
			oldW: full, oldL: named, newW: named, newL: named,
			mutate: func(old, new *config.Config) {
				for _, cfg := range []*config.Config{old, new} {
					cfg.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
						"reth0.50": {SystemServices: named},
					}
				}
			},
			// The zone-level token was effective nowhere (the only member
			// enforces its override in both generations), so narrowing it
			// changes no enforcement.
			want: nil,
		},
		{
			name: "deleted full-admit override fires for the iface scope",
			oldW: named, oldL: named, newW: named, newL: named,
			mutate: func(old, new *config.Config) {
				old.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
					"reth0.50": {SystemServices: full},
				}
			},
			want: []string{"zone:wan|iface:reth0.50"},
		},
		{
			name: "bare physical override covering units suppresses the zone scope",
			oldW: full, oldL: named, newW: named, newL: named,
			mutate: func(old, new *config.Config) {
				for _, cfg := range []*config.Config{old, new} {
					cfg.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
						"reth0": {SystemServices: named},
					}
				}
			},
			// The bare-physical override covers reth0.50, so the zone
			// stanza is effective nowhere in either generation.
			want: nil,
		},
		{
			name: "physical plus unit union removing the physical full leg fires",
			oldW: named, oldL: named, newW: named, newL: named,
			mutate: func(old, new *config.Config) {
				old.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
					"reth0":    {SystemServices: full},
					"reth0.50": {SystemServices: named},
				}
				new.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
					"reth0.50": {SystemServices: named},
				}
			},
			// Effective admission is the physical∪unit union (#3720): full
			// before, ssh after. An exact-unit-only resolver sees ssh→ssh
			// and misses the transition — this case REDs on it.
			want: []string{"zone:wan|iface:reth0.50"},
		},
		{
			name: "physical plus unit union adding a physical full leg loosens silently",
			oldW: named, oldL: named, newW: named, newL: named,
			mutate: func(old, new *config.Config) {
				old.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
					"reth0.50": {SystemServices: named},
				}
				new.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
					"reth0":    {SystemServices: full},
					"reth0.50": {SystemServices: named},
				}
			},
			// Union goes ssh→full: a loosening, so no transition.
			want: nil,
		},
		{
			name: "override replacement dropping an exempt token fires iface only",
			oldW: named, oldL: named, newW: named, newL: named,
			mutate: func(old, new *config.Config) {
				old.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
					"reth0.50": {SystemServices: named, Protocols: []string{"bgp"}},
				}
				new.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
					"reth0.50": {SystemServices: named},
				}
			},
			want: []string{"zone:wan|iface:reth0.50"},
		},
		{
			name: "union leg deletion dropping the unit token fires",
			oldW: named, oldL: named, newW: named, newL: named,
			mutate: func(old, new *config.Config) {
				old.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
					"reth0":    {SystemServices: named},
					"reth0.50": {Protocols: []string{"bgp"}},
				}
				new.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
					"reth0": {SystemServices: named},
				}
			},
			// Effective union goes {ssh,bgp}→{ssh}: the bgp removal is a
			// token narrowing of the interface scope.
			want: []string{"zone:wan|iface:reth0.50"},
		},
		{
			name: "named removal of exempt token fires",
			oldW: []string{"ssh"}, oldL: named,
			newW: named, newL: named,
			mutate: func(old, new *config.Config) {
				old.Security.Zones["wan"].HostInboundTraffic.Protocols = []string{"bgp"}
			},
			want: []string{"zone:wan", "zone:wan|iface:reth0.50"},
		},
		{
			name: "named removal of catalogued-only token stays silent",
			oldW: []string{"ssh", "dns"}, oldL: named,
			newW: []string{"dns"}, newL: named,
		},
		{
			name: "bare protocol removal fires",
			oldW: named, oldL: named, newW: named, newL: named,
			mutate: func(old, new *config.Config) {
				old.Security.Zones["wan"].HostInboundTraffic.Protocols = []string{"ospf"}
			},
			want: []string{"zone:wan", "zone:wan|iface:reth0.50"},
		},
		{
			// The expansion fires via unguarded SERVICE members (ntp,
			// traceroute, dhcp, rsh, ...) — bgp is a protocol and plays
			// no role here (the old name claimed otherwise).
			name: "services-all to named fires via unguarded service members",
			oldW: []string{"all"}, oldL: named,
			newW: []string{"ssh"}, newL: named,
			want: []string{"zone:wan", "zone:wan|iface:reth0.50"},
		},
		{
			name: "protocols-all to named fires via unguarded protocol members",
			oldW: named, oldL: named, newW: named, newL: named,
			mutate: func(old, new *config.Config) {
				old.Security.Zones["wan"].HostInboundTraffic.Protocols = []string{"all"}
				new.Security.Zones["wan"].HostInboundTraffic.Protocols = []string{"ospf"}
			},
			want: []string{"zone:wan", "zone:wan|iface:reth0.50"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldCfg := tighteningScopeCfg(t, tc.oldW, tc.oldL)
			newCfg := tighteningScopeCfg(t, tc.newW, tc.newL)
			if tc.mutate != nil {
				tc.mutate(oldCfg, newCfg)
			}
			got := hostInboundTightenedScopes(oldCfg, newCfg)
			if len(got) != len(tc.want) {
				t.Fatalf("scopes = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("scopes = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestHostInboundTightenedScopesSkipsLifelinesAndNil10752(t *testing.T) {
	if got := hostInboundTightenedScopes(nil, &config.Config{}); got != nil {
		t.Fatalf("nil old must yield nil, got %v", got)
	}
	oldCfg := &config.Config{Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
		"mgmt": {Name: "mgmt", Interfaces: []string{"fxp0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"any-service"}}},
	}}}
	newCfg := &config.Config{Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
		"mgmt": {Name: "mgmt", Interfaces: []string{"fxp0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}}}
	if got := hostInboundTightenedScopes(oldCfg, newCfg); len(got) != 0 {
		t.Fatalf("lifeline-only narrowing must stay silent, got %v", got)
	}
}

func TestWithTighteningWarningsProjectsCopy10752(t *testing.T) {
	oldCfg := tighteningScopeCfg(t, []string{"any-service"}, []string{"ssh"})
	newCfg := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	newCfg.Warnings = []string{"foreign advisory"}
	d := &Daemon{}
	wan := netip.MustParseAddr("172.16.50.8")
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		wan: kept10752(2, []string{"tcp 172.16.50.8:2222→203.0.113.7:40000"},
			1, []string{"tcp 172.16.50.8:179→203.0.113.7:40001"}),
	})

	resp := d.withTighteningWarningsForResponse10752(newCfg, oldCfg, newCfg)
	if resp == newCfg {
		t.Fatal("firing projection must return a copy, never the applied pointer")
	}
	if len(resp.Warnings) != 3 || resp.Warnings[0] != "foreign advisory" {
		t.Fatalf("response warnings = %v, want [foreign advisory, custom line, other line]", resp.Warnings)
	}
	if !strings.Contains(resp.Warnings[1], "zone:wan") || !strings.Contains(resp.Warnings[1], "2222") ||
		!strings.Contains(resp.Warnings[1], "custom-port") {
		t.Errorf("custom line must name scope + count + sample: %q", resp.Warnings[1])
	}
	if !strings.Contains(resp.Warnings[2], "exempt/bare-protocol") || !strings.Contains(resp.Warnings[2], "179") {
		t.Errorf("other line must name exempt/bare class + sample: %q", resp.Warnings[2])
	}
	if len(newCfg.Warnings) != 1 {
		t.Fatalf("applied warnings = %v, want the input untouched", newCfg.Warnings)
	}
}

func TestWithTighteningWarningsIdentityCases10752(t *testing.T) {
	openCfg := tighteningScopeCfg(t, []string{"any-service"}, []string{"ssh"})
	namedCfg := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	wan := netip.MustParseAddr("172.16.50.8")
	lan := netip.MustParseAddr("10.0.61.1")
	d := &Daemon{}
	// No transition (identical configs) + evidence → identity.
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		wan: kept10752(3, nil, 0, nil),
	})
	if resp := d.withTighteningWarningsForResponse10752(namedCfg, namedCfg, namedCfg); resp != namedCfg {
		t.Error("no transition must return the input pointer")
	}
	// Transition + zero evidence → identity.
	d.recordKeptSuspicious10752(nil)
	if resp := d.withTighteningWarningsForResponse10752(namedCfg, openCfg, namedCfg); resp != namedCfg {
		t.Error("zero kept must return the input pointer")
	}
	// Transition + evidence on an UNRELATED zone only → identity (no
	// misattribution: a zone-B residual must not name a zone-A tightening).
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		lan: kept10752(2, []string{"tcp 10.0.61.1:2222→203.0.113.7:40000"}, 0, nil),
	})
	if resp := d.withTighteningWarningsForResponse10752(namedCfg, openCfg, namedCfg); resp != namedCfg {
		t.Error("cross-scope evidence must stay silent (no intersected scope)")
	}
	// Nil response (failed apply) → nil.
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		wan: kept10752(3, nil, 0, nil),
	})
	if resp := d.withTighteningWarningsForResponse10752(nil, openCfg, namedCfg); resp != nil {
		t.Error("nil response must stay nil")
	}
}

// TestWithTighteningWarningsFiltersMixedEvidence10752 pins per-address,
// per-class attribution: when matching-scope and unrelated-scope evidence
// coexist, the warning renders ONLY the intersecting counts and samples.
// A global-counts implementation inflates the count and can show the
// unrelated sample — both RED here.
func TestWithTighteningWarningsFiltersMixedEvidence10752(t *testing.T) {
	openCfg := tighteningScopeCfg(t, []string{"any-service"}, []string{"ssh"})
	namedCfg := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	wan := netip.MustParseAddr("172.16.50.8")
	lan := netip.MustParseAddr("10.0.61.1")
	d := &Daemon{}

	// Mixed scope: WAN tightening with WAN customs (2) plus unchanged-LAN
	// customs (9). The custom line must show 2 with the WAN sample only.
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		wan: kept10752(2, []string{"tcp 172.16.50.8:2222→203.0.113.7:40000"}, 0, nil),
		lan: kept10752(9, []string{"tcp 10.0.61.1:2222→203.0.113.7:40001"}, 0, nil),
	})
	resp := d.withTighteningWarningsForResponse10752(namedCfg, openCfg, namedCfg)
	if resp == namedCfg {
		t.Fatal("intersecting evidence must warn, got identity")
	}
	if len(resp.Warnings) != 1 {
		t.Fatalf("warnings = %v, want [custom line]", resp.Warnings)
	}
	line := resp.Warnings[0]
	if !strings.Contains(line, "leaves 2 box-oriented custom-port") {
		t.Errorf("custom line must show the WAN-only count 2: %q", line)
	}
	if !strings.Contains(line, "172.16.50.8:2222") {
		t.Errorf("custom line must show the WAN sample: %q", line)
	}
	if strings.Contains(line, "10.0.61.1") {
		t.Errorf("custom line must not leak the unrelated LAN sample: %q", line)
	}
	if !strings.Contains(line, "(zone:wan, zone:wan|iface:reth0.50)") {
		t.Errorf("custom line must name the narrowed WAN scopes: %q", line)
	}

	// Mixed class: WAN customs plus LAN exempt/bare with a WAN-only
	// narrowing. The LAN class must be omitted entirely (no other clause).
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		wan: kept10752(1, []string{"tcp 172.16.50.8:2222→203.0.113.7:40000"}, 0, nil),
		lan: kept10752(0, nil, 5, []string{"tcp 10.0.61.1:179→203.0.113.7:40001"}),
	})
	fresh := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	resp = d.withTighteningWarningsForResponse10752(fresh, openCfg, fresh)
	if resp == fresh {
		t.Fatal("intersecting evidence must warn, got identity")
	}
	joined := strings.Join(resp.Warnings, "\n")
	if strings.Contains(joined, "exempt/bare-protocol") || strings.Contains(joined, "10.0.61.1") {
		t.Fatalf("unrelated-zone class must be omitted entirely, got %v", resp.Warnings)
	}
	if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "leaves 1 box-oriented custom-port") {
		t.Fatalf("warnings = %v, want [custom line count 1]", resp.Warnings)
	}
}

// twoUnitWanCfg10752 returns a config whose wan zone spans two addressed
// member units, for same-zone/different-interface isolation tests.
func twoUnitWanCfg10752(t *testing.T, wanServices []string) *config.Config {
	t.Helper()
	cfg := hostInboundTestConfig()
	cfg.Interfaces.Interfaces["reth0"].Units[60] = &config.InterfaceUnit{
		Number: 60, VlanID: 60, Addresses: []string{"172.16.60.8/24"},
	}
	cfg.Security.Zones["wan"].Interfaces = []string{"reth0.50", "reth0.60"}
	cfg.Security.Zones["wan"].HostInboundTraffic = &config.HostInboundTraffic{SystemServices: wanServices}
	return cfg
}

// TestWithTighteningWarningsSameZoneInterfaceIsolation10752 pins
// interface-identity attribution inside one zone: narrowing reth0.50's
// override must never name itself from evidence on reth0.60's address, and
// reth0.50's own evidence must name exactly the narrowed interface scope.
func TestWithTighteningWarningsSameZoneInterfaceIsolation10752(t *testing.T) {
	oldCfg := twoUnitWanCfg10752(t, []string{"any-service"})
	newCfg := twoUnitWanCfg10752(t, []string{"any-service"})
	newCfg.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
		"reth0.50": {SystemServices: []string{"ssh"}},
	}
	if got := hostInboundTightenedScopes(oldCfg, newCfg); len(got) != 1 || got[0] != "zone:wan|iface:reth0.50" {
		t.Fatalf("tightened = %v, want [zone:wan|iface:reth0.50]", got)
	}
	d := &Daemon{}

	// Evidence solely on the UNCHANGED sibling interface stays silent: the
	// narrowed scope must never name itself from another interface's flow.
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		netip.MustParseAddr("172.16.60.8"): kept10752(3,
			[]string{"tcp 172.16.60.8:2222→203.0.113.7:40000"}, 0, nil),
	})
	if resp := d.withTighteningWarningsForResponse10752(newCfg, oldCfg, newCfg); resp != newCfg {
		t.Fatalf("sibling-interface evidence must stay silent, got %v", resp.Warnings)
	}

	// Positive control: evidence on the NARROWED interface names exactly
	// that scope (the zone scope never narrowed, so it must not appear).
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		netip.MustParseAddr("172.16.50.8"): kept10752(1,
			[]string{"tcp 172.16.50.8:2222→203.0.113.7:40001"}, 0, nil),
	})
	fresh := twoUnitWanCfg10752(t, []string{"any-service"})
	fresh.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
		"reth0.50": {SystemServices: []string{"ssh"}},
	}
	resp := d.withTighteningWarningsForResponse10752(fresh, oldCfg, fresh)
	if resp == fresh {
		t.Fatal("intersecting interface evidence must warn, got identity")
	}
	if len(resp.Warnings) != 1 {
		t.Fatalf("warnings = %v, want [custom line]", resp.Warnings)
	}
	if !strings.Contains(resp.Warnings[0], "(zone:wan|iface:reth0.50)") {
		t.Errorf("custom line must name exactly the narrowed interface scope: %q", resp.Warnings[0])
	}
}

// TestWithTighteningWarningsOldAddressMoved10752 pins the load-bearing OLD
// property: the narrowed address moved out of wan (into lan) in the NEW
// generation, so only OLD-config ownership attributes its flow to the wan
// tightening. A NEW-views implementation stays silent (or misattributes to
// lan) — RED here.
func TestWithTighteningWarningsOldAddressMoved10752(t *testing.T) {
	oldCfg := tighteningScopeCfg(t, []string{"any-service"}, []string{"ssh"})
	newCfg := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	newCfg.Security.Zones["wan"].Interfaces = nil
	newCfg.Security.Zones["lan"].Interfaces = []string{"reth1.0", "reth0.50"}
	d := &Daemon{}
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		netip.MustParseAddr("172.16.50.8"): kept10752(1,
			[]string{"tcp 172.16.50.8:2222→203.0.113.7:40000"}, 0, nil),
	})
	resp := d.withTighteningWarningsForResponse10752(newCfg, oldCfg, newCfg)
	if resp == newCfg {
		t.Fatal("flow on an old-wan address must warn on the wan tightening, got identity")
	}
	joined := strings.Join(resp.Warnings, "\n")
	if !strings.Contains(joined, "zone:wan") || !strings.Contains(joined, "172.16.50.8:2222") {
		t.Fatalf("warning must name zone:wan with the moved-address sample, got %v", resp.Warnings)
	}
	if strings.Contains(joined, "zone:lan") {
		t.Fatalf("warning must not attribute to the new zone, got %v", resp.Warnings)
	}
}

// TestApplyAndSyncCommittedWarnsTighteningStranded10752 drives the real
// commit funnel: old any-service → new named, with this attempt's sweep
// observing a stranded box-oriented custom flow (via the conntrack seam).
// The returned response must carry the tightening line on a copy while the
// applied object keeps only its validation warnings. A pre-seeded stale
// stash (kept=99) must NOT leak through — the funnel clears per attempt.
func TestApplyAndSyncCommittedWarnsTighteningStranded10752(t *testing.T) {
	d, _, _ := minimalApplyCtxDaemon(t)
	origInstaller, origDelete := nftInstaller, conntrackDeleteFilters
	origRange, origListeners := readEphemeralPortRange, readLocalTCPListenerPorts
	defer func() {
		nftInstaller, conntrackDeleteFilters = origInstaller, origDelete
		readEphemeralPortRange, readLocalTCPListenerPorts = origRange, origListeners
	}()
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { return nil },
	}
	readEphemeralPortRange = func() (uint16, uint16) { return 32768, 60999 }
	readLocalTCPListenerPorts = func() map[uint16]bool { return map[uint16]bool{} }
	stale := boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 2222)
	conntrackDeleteFilters = func(family netlink.InetFamily, filters ...netlink.CustomConntrackFilter) (uint, error) {
		var n uint
		for _, f := range filters {
			if f.MatchConntrackFlow(stale) {
				n++
			}
		}
		return n, nil
	}

	oldActive := tighteningScopeCfg(t, []string{"any-service"}, []string{"ssh"})
	compiled := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	compiled.Warnings = []string{"foreign advisory"}
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		netip.MustParseAddr("198.51.100.9"): kept10752(99, []string{"stale"}, 0, nil),
	})
	got, err := d.applyAndSyncCommitted(oldActive, compiled, peerSyncNever)
	if err != nil {
		t.Fatalf("applyAndSyncCommitted: %v", err)
	}
	if got == compiled {
		t.Fatal("response must project onto a copy when stranded flows are observed")
	}
	found := false
	for _, w := range got.Warnings {
		if strings.Contains(w, "zone:wan") && strings.Contains(w, "2222") {
			found = true
			if strings.Contains(w, "99") || strings.Contains(w, "stale") {
				t.Fatalf("stale pre-seeded evidence leaked into the warning: %q", w)
			}
		}
	}
	if !found {
		t.Fatalf("no tightening warning naming zone:wan + 2222 in %v", got.Warnings)
	}
	if len(compiled.Warnings) != 1 {
		t.Fatalf("applied warnings = %v, want only the foreign line", compiled.Warnings)
	}
}

// TestApplyAndSyncCommittedSilentCrossScope10752 is the funnel-level
// misattribution guard: wan tightens, but the only stranded flow lives on a
// lan address. The response must be the applied pointer itself (silent),
// since no tightened scope intersects the stranded flow.
func TestApplyAndSyncCommittedSilentCrossScope10752(t *testing.T) {
	d, _, _ := minimalApplyCtxDaemon(t)
	origInstaller, origDelete := nftInstaller, conntrackDeleteFilters
	origRange, origListeners := readEphemeralPortRange, readLocalTCPListenerPorts
	defer func() {
		nftInstaller, conntrackDeleteFilters = origInstaller, origDelete
		readEphemeralPortRange, readLocalTCPListenerPorts = origRange, origListeners
	}()
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { return nil },
	}
	readEphemeralPortRange = func() (uint16, uint16) { return 32768, 60999 }
	readLocalTCPListenerPorts = func() map[uint16]bool { return map[uint16]bool{} }
	otherZone := boxOrientedFlow(config.HostInboundProtoTCP, "10.0.61.1", 2222)
	conntrackDeleteFilters = func(family netlink.InetFamily, filters ...netlink.CustomConntrackFilter) (uint, error) {
		for _, f := range filters {
			f.MatchConntrackFlow(otherZone)
		}
		return 0, nil
	}

	oldActive := tighteningScopeCfg(t, []string{"any-service"}, []string{"ssh"})
	compiled := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	got, err := d.applyAndSyncCommitted(oldActive, compiled, peerSyncNever)
	if err != nil {
		t.Fatalf("applyAndSyncCommitted: %v", err)
	}
	if got != compiled {
		t.Fatalf("cross-scope evidence must stay silent (identity response), got warnings %v", got.Warnings)
	}
}

// TestApplyAndSyncCommittedWarnsExemptRemoval10752 covers named→named
// narrowing that drops an exempt token (bgp): no full-admit scope is lost,
// but the token removal strands unguarded box-oriented 179 flows, so the
// commit must warn naming the zone with the exempt/bare clause.
func TestApplyAndSyncCommittedWarnsExemptRemoval10752(t *testing.T) {
	d, _, _ := minimalApplyCtxDaemon(t)
	origInstaller, origDelete := nftInstaller, conntrackDeleteFilters
	origRange, origListeners := readEphemeralPortRange, readLocalTCPListenerPorts
	defer func() {
		nftInstaller, conntrackDeleteFilters = origInstaller, origDelete
		readEphemeralPortRange, readLocalTCPListenerPorts = origRange, origListeners
	}()
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { return nil },
	}
	readEphemeralPortRange = func() (uint16, uint16) { return 32768, 60999 }
	readLocalTCPListenerPorts = func() map[uint16]bool { return map[uint16]bool{} }
	stale := boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 179)
	conntrackDeleteFilters = func(family netlink.InetFamily, filters ...netlink.CustomConntrackFilter) (uint, error) {
		for _, f := range filters {
			f.MatchConntrackFlow(stale)
		}
		return 0, nil
	}

	oldActive := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	oldActive.Security.Zones["wan"].HostInboundTraffic.Protocols = []string{"bgp"}
	compiled := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	got, err := d.applyAndSyncCommitted(oldActive, compiled, peerSyncNever)
	if err != nil {
		t.Fatalf("applyAndSyncCommitted: %v", err)
	}
	if got == compiled {
		t.Fatal("exempt-token removal with stranded flows must warn")
	}
	found := false
	for _, w := range got.Warnings {
		if strings.Contains(w, "zone:wan") && strings.Contains(w, "exempt/bare-protocol") && strings.Contains(w, "179") {
			found = true
		}
		if strings.Contains(w, "custom-port") {
			t.Fatalf("exempt-only evidence must not emit a custom clause: %q", w)
		}
	}
	if !found {
		t.Fatalf("no exempt/bare warning naming zone:wan + 179 in %v", got.Warnings)
	}
}

// TestApplyAndSyncCommittedWarnsBareRemoval10752 covers named→named narrowing
// that drops a bare-protocol token (ospf): box-oriented proto-89 flows are
// kept with no guard, so the commit must warn with the exempt/bare clause.
func TestApplyAndSyncCommittedWarnsBareRemoval10752(t *testing.T) {
	d, _, _ := minimalApplyCtxDaemon(t)
	origInstaller, origDelete := nftInstaller, conntrackDeleteFilters
	origRange, origListeners := readEphemeralPortRange, readLocalTCPListenerPorts
	defer func() {
		nftInstaller, conntrackDeleteFilters = origInstaller, origDelete
		readEphemeralPortRange, readLocalTCPListenerPorts = origRange, origListeners
	}()
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { return nil },
	}
	readEphemeralPortRange = func() (uint16, uint16) { return 32768, 60999 }
	readLocalTCPListenerPorts = func() map[uint16]bool { return map[uint16]bool{} }
	stale := boxOrientedFlow(89, "172.16.50.8", 0)
	conntrackDeleteFilters = func(family netlink.InetFamily, filters ...netlink.CustomConntrackFilter) (uint, error) {
		for _, f := range filters {
			f.MatchConntrackFlow(stale)
		}
		return 0, nil
	}

	oldActive := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	oldActive.Security.Zones["wan"].HostInboundTraffic.Protocols = []string{"ospf"}
	compiled := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	got, err := d.applyAndSyncCommitted(oldActive, compiled, peerSyncNever)
	if err != nil {
		t.Fatalf("applyAndSyncCommitted: %v", err)
	}
	if got == compiled {
		t.Fatal("bare-protocol removal with stranded flows must warn")
	}
	found := false
	for _, w := range got.Warnings {
		if strings.Contains(w, "zone:wan") && strings.Contains(w, "exempt/bare-protocol") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no exempt/bare warning naming zone:wan in %v", got.Warnings)
	}
}
