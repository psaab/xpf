package daemon

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
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
			name: "loosening named-with-exempt to full-admit stays silent",
			oldW: named, oldL: named, newW: full, newL: named,
			mutate: func(old, new *config.Config) {
				old.Security.Zones["wan"].HostInboundTraffic.Protocols = []string{"bgp"}
			},
			// New full-admit covers every old token: without the
			// neu.full guard the empty new token set reads p:bgp as
			// removed and this loosening spuriously warns.
		},
		{
			name: "loosening named-with-bare-protocol to full-admit stays silent",
			oldW: named, oldL: named, newW: full, newL: named,
			mutate: func(old, new *config.Config) {
				old.Security.Zones["wan"].HostInboundTraffic.Protocols = []string{"ospf"}
			},
		},
		{
			name: "loosening named-with-range to full-admit stays silent",
			oldW: []string{"ssh", "traceroute"}, oldL: named,
			newW: full, newL: named,
		},
		{
			name: "loosening override union to full-admit stays silent",
			oldW: named, oldL: named, newW: named, newL: named,
			mutate: func(old, new *config.Config) {
				old.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
					"reth0.50": {SystemServices: named, Protocols: []string{"bgp"}},
				}
				new.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
					"reth0.50": {SystemServices: full},
				}
			},
		},
		{
			name: "zone-inherit loosening to override-full stays silent",
			oldW: named, oldL: named, newW: named, newL: named,
			mutate: func(old, new *config.Config) {
				old.Security.Zones["wan"].HostInboundTraffic.Protocols = []string{"bgp"}
				new.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
					"reth0.50": {SystemServices: full},
				}
			},
			// The zone scope disappears (sole member now
			// override-covered), but the replacement member's
			// new effective state is full-admit — a loosening,
			// not a bgp-removal tightening.
		},
		{
			name: "full-to-full zone replacement stays silent",
			oldW: full, oldL: named, newW: full, newL: named,
			mutate: func(old, new *config.Config) {
				new.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
					"reth0.50": {SystemServices: full},
				}
			},
			// The zone scope disappears into a full-admit
			// replacement: no full-admit loss anywhere.
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
			got, _ := hostInboundTightenedScopes(oldCfg, newCfg)
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
	if got, _ := hostInboundTightenedScopes(nil, &config.Config{}); got != nil {
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
	if got, _ := hostInboundTightenedScopes(oldCfg, newCfg); len(got) != 0 {
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
	if len(resp.Warnings) != 4 || resp.Warnings[0] != "foreign advisory" {
		t.Fatalf("response warnings = %v, want [foreign advisory, custom line, other line, silent-class pointer]", resp.Warnings)
	}
	if !strings.Contains(resp.Warnings[1], "zone:wan") || !strings.Contains(resp.Warnings[1], "2222") ||
		!strings.Contains(resp.Warnings[1], "custom-port") {
		t.Errorf("custom line must name scope + count + sample: %q", resp.Warnings[1])
	}
	if !strings.Contains(resp.Warnings[2], "exempt/bare-protocol") || !strings.Contains(resp.Warnings[2], "179") {
		t.Errorf("other line must name exempt/bare class + sample: %q", resp.Warnings[2])
	}
	if !strings.Contains(resp.Warnings[3], "cannot observe") || !strings.Contains(resp.Warnings[3], "Removal procedures") {
		t.Errorf("third line must be the silent-class pointer: %q", resp.Warnings[3])
	}
	if len(newCfg.Warnings) != 1 {
		t.Fatalf("applied warnings = %v, want the input untouched", newCfg.Warnings)
	}
}

func TestWithTighteningWarningsIdentityCases10752(t *testing.T) {
	openCfg := tighteningScopeCfg(t, []string{"any-service"}, []string{"ssh"})
	namedCfg := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	wan := netip.MustParseAddr("172.16.50.8")
	d := &Daemon{}
	// No transition (identical configs) + evidence → identity.
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		wan: kept10752(3, nil, 0, nil),
	})
	if resp := d.withTighteningWarningsForResponse10752(namedCfg, namedCfg, namedCfg); resp != namedCfg {
		t.Error("no transition must return the input pointer")
	}
	// Nil response (failed apply) → nil.
	if resp := d.withTighteningWarningsForResponse10752(nil, openCfg, namedCfg); resp != nil {
		t.Error("nil response must stay nil")
	}
}

// TestWithTighteningWarningsAdvisory10752 pins the transition-only advisory:
// narrowed scopes with zero intersecting evidence (nothing observed, or
// evidence only on addresses outside every narrowed scope) still warn —
// exactly one line, honest zero-observed wording, no observed-flow claim,
// and no leak of unrelated evidence into counts, samples, or scope naming.
func TestWithTighteningWarningsAdvisory10752(t *testing.T) {
	openCfg := tighteningScopeCfg(t, []string{"any-service"}, []string{"ssh"})
	namedCfg := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	lan := netip.MustParseAddr("10.0.61.1")
	d := &Daemon{}

	check := func(t *testing.T, resp *config.Config, input *config.Config) {
		t.Helper()
		if resp == input {
			t.Fatal("transition with zero intersecting evidence must warn (advisory), got identity")
		}
		if len(resp.Warnings) != 1 {
			t.Fatalf("advisory warnings = %v, want exactly one line", resp.Warnings)
		}
		line := resp.Warnings[0]
		for _, want := range []string{"host-inbound tightening (zone:wan, zone:wan|iface:reth0.50)",
			"observed no stranded flows", "cannot observe", "verify/delete", "Removal procedures"} {
			if !strings.Contains(line, want) {
				t.Errorf("advisory line missing %q: %q", want, line)
			}
		}
		for _, leak := range []string{"custom-port", "exempt/bare-protocol", "10.0.61.1", "leaves 2"} {
			if strings.Contains(line, leak) {
				t.Errorf("advisory line must not claim observed flows or leak unrelated evidence (%q): %q", leak, line)
			}
		}
		if len(input.Warnings) != 0 {
			t.Fatalf("applied warnings = %v, want the input untouched", input.Warnings)
		}
	}

	// Transition + zero evidence → advisory.
	d.recordKeptSuspicious10752(nil)
	check(t, d.withTighteningWarningsForResponse10752(namedCfg, openCfg, namedCfg), namedCfg)

	// Transition + evidence on an UNRELATED zone only → advisory (the
	// narrowing still needs manual verification for silent classes; the
	// unrelated residual must not name it, inflate it, or sample it).
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		lan: kept10752(2, []string{"tcp 10.0.61.1:2222→203.0.113.7:40000"}, 0, nil),
	})
	fresh := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	check(t, d.withTighteningWarningsForResponse10752(fresh, openCfg, fresh), fresh)

	// Range-only narrowing (traceroute removal) with zero kept flows →
	// advisory. Ranges are sweep-silent by design (indistinguishable from
	// ephemeral clients), so without the transition advisory this order
	// would warn nowhere.
	rangeOld := tighteningScopeCfg(t, []string{"ssh", "traceroute"}, []string{"ssh"})
	rangeNew := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	if got, _ := hostInboundTightenedScopes(rangeOld, rangeNew); len(got) != 2 {
		t.Fatalf("traceroute removal must narrow the wan scopes, got %v", got)
	}
	d.recordKeptSuspicious10752(nil)
	check(t, d.withTighteningWarningsForResponse10752(rangeNew, rangeOld, rangeNew), rangeNew)
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
	if len(resp.Warnings) != 2 {
		t.Fatalf("warnings = %v, want [custom line, silent-class pointer]", resp.Warnings)
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
	if len(resp.Warnings) != 2 || !strings.Contains(resp.Warnings[0], "leaves 1 box-oriented custom-port") {
		t.Fatalf("warnings = %v, want [custom line count 1, pointer]", resp.Warnings)
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
	if got, _ := hostInboundTightenedScopes(oldCfg, newCfg); len(got) != 1 || got[0] != "zone:wan|iface:reth0.50" {
		t.Fatalf("tightened = %v, want [zone:wan|iface:reth0.50]", got)
	}
	d := &Daemon{}

	// Evidence solely on the UNCHANGED sibling interface → advisory only:
	// no evidence line, no sibling-address leak.
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		netip.MustParseAddr("172.16.60.8"): kept10752(3,
			[]string{"tcp 172.16.60.8:2222→203.0.113.7:40000"}, 0, nil),
	})
	resp := d.withTighteningWarningsForResponse10752(newCfg, oldCfg, newCfg)
	if resp == newCfg {
		t.Fatal("narrowed addressed scope with zero intersecting evidence must carry the advisory")
	}
	if len(resp.Warnings) != 1 {
		t.Fatalf("warnings = %v, want exactly the advisory line", resp.Warnings)
	}
	line := resp.Warnings[0]
	if !strings.Contains(line, "(zone:wan|iface:reth0.50)") || !strings.Contains(line, "observed no stranded flows") {
		t.Errorf("advisory must name exactly the narrowed interface scope with zero-observed wording: %q", line)
	}
	for _, leak := range []string{"172.16.60.8", "custom-port", "exempt/bare-protocol"} {
		if strings.Contains(line, leak) {
			t.Errorf("advisory must not leak sibling-interface evidence (%q): %q", leak, line)
		}
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
	resp = d.withTighteningWarningsForResponse10752(fresh, oldCfg, fresh)
	if resp == fresh {
		t.Fatal("intersecting interface evidence must warn, got identity")
	}
	if len(resp.Warnings) != 2 {
		t.Fatalf("warnings = %v, want [custom line, pointer]", resp.Warnings)
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

// TestWithTighteningWarningsPerClassNaming10752 pins per-class scope
// naming: two narrowed interfaces with opposite evidence classes must
// name exactly their own scope on each line. A shared named set puts
// both scopes on both lines — RED here.
func TestWithTighteningWarningsPerClassNaming10752(t *testing.T) {
	oldCfg := twoUnitWanCfg10752(t, []string{"ssh"})
	oldCfg.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
		"reth0.50": {SystemServices: []string{"any-service"}},
		"reth0.60": {SystemServices: []string{"any-service"}},
	}
	newCfg := twoUnitWanCfg10752(t, []string{"ssh"})
	newCfg.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
		"reth0.50": {SystemServices: []string{"ssh"}},
		"reth0.60": {SystemServices: []string{"ssh"}},
	}
	if got, _ := hostInboundTightenedScopes(oldCfg, newCfg); len(got) != 2 {
		t.Fatalf("tightened = %v, want both narrowed interface scopes", got)
	}
	d := &Daemon{}
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		netip.MustParseAddr("172.16.50.8"): kept10752(1,
			[]string{"tcp 172.16.50.8:2222→203.0.113.7:40000"}, 0, nil),
		netip.MustParseAddr("172.16.60.8"): kept10752(0, nil, 1,
			[]string{"tcp 172.16.60.8:179→203.0.113.7:40001"}),
	})
	resp := d.withTighteningWarningsForResponse10752(newCfg, oldCfg, newCfg)
	if resp == newCfg {
		t.Fatal("intersecting evidence must warn, got identity")
	}
	if len(resp.Warnings) != 3 {
		t.Fatalf("warnings = %v, want [custom line, other line, pointer]", resp.Warnings)
	}
	if !strings.Contains(resp.Warnings[0], "(zone:wan|iface:reth0.50)") ||
		strings.Contains(resp.Warnings[0], "reth0.60") {
		t.Errorf("custom line must name exactly the custom-evidence scope: %q", resp.Warnings[0])
	}
	if !strings.Contains(resp.Warnings[1], "(zone:wan|iface:reth0.60)") ||
		strings.Contains(resp.Warnings[1], "reth0.50") {
		t.Errorf("other line must name exactly the exempt-evidence scope: %q", resp.Warnings[1])
	}
}

// TestWithTighteningWarningsVIPOverrideIsolation10752 pins VIP unit
// attribution: a VIP on an override-covered member enforces the
// override, so its evidence must not name a zone-stanza narrowing.
// Zone-granular fallback names zone:wan here — RED on the old rule.
func TestWithTighteningWarningsVIPOverrideIsolation10752(t *testing.T) {
	mkCfg := func(zoneServices []string) *config.Config {
		cfg := twoUnitWanCfg10752(t, zoneServices)
		cfg.Interfaces.Interfaces["reth0"].Units[50].VRRPGroups = map[string]*config.VRRPGroup{
			"1": {ID: 1, VirtualAddresses: []string{"172.16.50.100"}},
		}
		cfg.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
			"reth0.50": {SystemServices: []string{"any-service"}},
		}
		return cfg
	}
	oldCfg := mkCfg([]string{"any-service"})
	newCfg := mkCfg([]string{"ssh"})
	vip := netip.MustParseAddr("172.16.50.100")
	found := false
	for _, v := range dpuserspace.BuildZoneHostInboundViews(oldCfg) {
		for _, raw := range append(append([]string(nil), v.V4Addrs...), v.V6Addrs...) {
			if ip, err := netip.ParseAddr(raw); err == nil && ip.Unmap() == vip {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("sanity: the VIP must be present in the OLD views for this test to mean anything")
	}
	d := &Daemon{}
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		vip: kept10752(1, []string{"tcp 172.16.50.100:2222→203.0.113.7:40000"}, 0, nil),
	})
	resp := d.withTighteningWarningsForResponse10752(newCfg, oldCfg, newCfg)
	if resp == newCfg {
		t.Fatal("narrowed addressed scopes must carry at least the advisory, got identity")
	}
	if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "observed no stranded flows") {
		t.Fatalf("VIP evidence on an unchanged override must yield advisory-only, got %v", resp.Warnings)
	}
	if strings.Contains(resp.Warnings[0], "172.16.50.100") {
		t.Fatalf("advisory must not leak the VIP flow: %q", resp.Warnings[0])
	}
}

// TestHostInboundScopesForAddrsProvenance10752 pins group provenance
// directly: a derived address (stable link-local shape) attributes to
// its view's member units — singleton or grouped — while a bare-only
// group contributes the zone, and stanza precision survives multi-view
// membership (a static never gains sibling scopes).
func TestHostInboundScopesForAddrsProvenance10752(t *testing.T) {
	oldCfg := twoUnitWanCfg10752(t, []string{"any-service"})
	oldCfg.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
		"reth0.50": {SystemServices: []string{"ssh"}},
	}
	ll := netip.MustParseAddr("fe80::bf72:1:2")
	views := []dpuserspace.ZoneHostInboundView{
		{Zone: "wan", Interfaces: []string{"reth0.50"}, V6Addrs: []string{"fe80::bf72:1:2"}},
	}
	got := hostInboundScopesForAddrs10752(oldCfg, views, []netip.Addr{ll})
	if len(got[ll]) != 1 || got[ll][0] != "zone:wan|iface:reth0.50" {
		t.Fatalf("singleton-view derived addr = %v, want [zone:wan|iface:reth0.50] (override applies, no zone scope)", got[ll])
	}
	// Grouped view: every owned member unit is a provenance owner (.60
	// enforces the zone stanza, so the zone joins through it).
	views[0].Interfaces = []string{"reth0.50", "reth0.60"}
	got = hostInboundScopesForAddrs10752(oldCfg, views, []netip.Addr{ll})
	want := map[string]bool{"zone:wan|iface:reth0.50": true, "zone:wan|iface:reth0.60": true, "zone:wan": true}
	if len(got[ll]) != 3 {
		t.Fatalf("grouped-view derived addr = %v, want the two iface scopes + zone", got[ll])
	}
	for _, scope := range got[ll] {
		if !want[scope] {
			t.Fatalf("grouped-view derived addr = %v, want %v", got[ll], want)
		}
	}
	// Bare-only group: cannot form a unit scope, contributes the zone.
	views[0].Interfaces = []string{"reth0"}
	got = hostInboundScopesForAddrs10752(oldCfg, views, []netip.Addr{ll})
	if len(got[ll]) != 1 || got[ll][0] != "zone:wan" {
		t.Fatalf("bare-group derived addr = %v, want [zone:wan]", got[ll])
	}
	// Per-group fallback: a shared derived address keeps zone coverage
	// from its bare group alongside pins from unit groups.
	views = []dpuserspace.ZoneHostInboundView{
		{Zone: "wan", Interfaces: []string{"reth0"}, V6Addrs: []string{"fe80::bf72:1:2"}},
		{Zone: "wan", Interfaces: []string{"reth0.50"}, V6Addrs: []string{"fe80::bf72:1:2"}},
	}
	got = hostInboundScopesForAddrs10752(oldCfg, views, []netip.Addr{ll})
	want = map[string]bool{"zone:wan|iface:reth0.50": true, "zone:wan": true}
	if len(got[ll]) != 2 {
		t.Fatalf("shared derived addr = %v, want [iface + zone]", got[ll])
	}
	for _, scope := range got[ll] {
		if !want[scope] {
			t.Fatalf("shared derived addr = %v, want %v", got[ll], want)
		}
	}
	// Stanza precision survives multi-view membership: a static addr on
	// .50 keeps its unit scopes only, never sibling scopes.
	views = []dpuserspace.ZoneHostInboundView{
		{Zone: "wan", Interfaces: []string{"reth0.50", "reth0.60"}, V4Addrs: []string{"172.16.50.8"}},
	}
	wan := netip.MustParseAddr("172.16.50.8")
	got = hostInboundScopesForAddrs10752(oldCfg, views, []netip.Addr{wan})
	if len(got[wan]) != 1 || got[wan][0] != "zone:wan|iface:reth0.50" {
		t.Fatalf("stanza addr in multi view = %v, want [zone:wan|iface:reth0.50]", got[wan])
	}
}

// TestWithTighteningWarningsTokenOnlyCustomsAdvisory10752 is the T2(1)
// negative pin: a token-only narrowing (ospf removal, no full-admit
// loss) never admitted customs, so an observed already-denied custom
// flow is unchanged-authorization — not stranded — and the commit must
// carry the transition-only advisory, never a customs line.
func TestWithTighteningWarningsTokenOnlyCustomsAdvisory10752(t *testing.T) {
	oldCfg := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	oldCfg.Security.Zones["wan"].HostInboundTraffic.Protocols = []string{"ospf"}
	newCfg := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	d := &Daemon{}
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		netip.MustParseAddr("172.16.50.8"): kept10752(1,
			[]string{"tcp 172.16.50.8:2222→203.0.113.7:40000"}, 0, nil),
	})
	resp := d.withTighteningWarningsForResponse10752(newCfg, oldCfg, newCfg)
	if resp == newCfg {
		t.Fatal("token-only narrowing with observed customs must carry the advisory, got identity")
	}
	if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "observed no stranded flows") {
		t.Fatalf("token-only customs must yield advisory-only, got %v", resp.Warnings)
	}
	if strings.Contains(resp.Warnings[0], "2222") || strings.Contains(resp.Warnings[0], "custom-port") {
		t.Fatalf("advisory must not claim the unchanged custom flow: %q", resp.Warnings[0])
	}
	// Positive control: the same flow IS stranded by a full-admit loss.
	fullOld := tighteningScopeCfg(t, []string{"any-service"}, []string{"ssh"})
	fullNew := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		netip.MustParseAddr("172.16.50.8"): kept10752(1,
			[]string{"tcp 172.16.50.8:2222→203.0.113.7:40000"}, 0, nil),
	})
	resp = d.withTighteningWarningsForResponse10752(fullNew, fullOld, fullNew)
	if resp == fullNew {
		t.Fatal("full-admit loss with customs must warn, got identity")
	}
	if !strings.Contains(resp.Warnings[0], "leaves 1 box-oriented custom-port") {
		t.Fatalf("full-admit loss must emit the customs line, got %v", resp.Warnings)
	}
}

// TestHostInboundSweepCustomTokenPorts10752 pins the customs carve-out
// universe: p:rip/p:ripng plus p:bfd Echo 3785 admit sweep-custom
// tuples today. bgp (exempt), ospf (bare), traceroute (range), dns
// (catalogued), ntp (exempt) are excluded by rule; bfd Control
// (3784/4784) is excluded by the conformant-ephemeral call while Echo
// 3785 stays; sap is excluded by the demonstrated-default call (no
// supported fixed-9875 sender).
func TestHostInboundSweepCustomTokenPorts10752(t *testing.T) {
	m := hostInboundSweepCustomTokenPorts10752()
	if got := m["p:rip"]; len(got) != 1 || got[0] != "17/520" {
		t.Errorf(`p:rip ports = %v, want ["17/520"]`, got)
	}
	if got := m["p:ripng"]; len(got) != 1 || got[0] != "17/521" {
		t.Errorf(`p:ripng ports = %v, want ["17/521"]`, got)
	}
	if got := m["p:bfd"]; len(got) != 1 || got[0] != "17/3785" {
		t.Errorf(`p:bfd ports = %v, want ["17/3785"] (Echo only, Control excluded)`, got)
	}
	for _, tok := range []string{"p:bgp", "p:ospf", "p:sap", "p:ldp", "p:msdp", "s:dns", "s:ntp", "s:ssh", "s:traceroute", "s:dhcp"} {
		if got, ok := m[tok]; ok {
			t.Errorf("token %s must not admit sweep-custom tuples, got %v", tok, got)
		}
	}
}

// TestWithTighteningWarningsRipRemovalWarnsCustoms10752 is the rip
// carve-out RED pin: p:rip removal is token-only, but the named token
// DID admit sweep-custom-classified flows (fixed-sport UDP 520 below
// the ephemeral floor), so a kept box:520 flow is genuinely stranded
// and must emit the customs evidence line — not the advisory. The
// collector leg pins the sweep classification; the projection leg
// pins the line. The ospf-removal/unrelated-2222 negative control
// stays advisory (see the token-only test above).
func TestWithTighteningWarningsRipRemovalWarnsCustoms10752(t *testing.T) {
	cfg := hostInboundFlushTestConfig("snmp")
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
	filter := buildHostInboundConntrackFlushFilter(views, unzonedV4, unzonedV6, nil)
	if filter == nil {
		t.Fatal("expected a filter for the enforcing configuration")
	}
	if filter.MatchConntrackFlow(boxOrientedFlow(config.HostInboundProtoUDP, "172.16.50.8", 520)) {
		t.Fatal("denied box-oriented rip tuple must be kept (catalog miss), not flushed")
	}
	if got, _ := filter.keptSuspiciousReport(); got != 1 {
		t.Fatalf("kept-suspicious count = %d, want 1 (box:520 UDP is sweep-custom)", got)
	}

	oldCfg := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	oldCfg.Security.Zones["wan"].HostInboundTraffic.Protocols = []string{"rip"}
	newCfg := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	d := &Daemon{}
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		netip.MustParseAddr("172.16.50.8"): kept10752(1,
			[]string{"udp 172.16.50.8:520→203.0.113.7:520"}, 0, nil),
	})
	resp := d.withTighteningWarningsForResponse10752(newCfg, oldCfg, newCfg)
	if resp == newCfg {
		t.Fatal("rip removal with a kept 520 flow must warn, got identity")
	}
	if len(resp.Warnings) != 2 {
		t.Fatalf("warnings = %v, want [custom line, pointer]", resp.Warnings)
	}
	line := resp.Warnings[0]
	if !strings.Contains(line, "(zone:wan, zone:wan|iface:reth0.50)") ||
		!strings.Contains(line, "leaves 1 box-oriented custom-port") ||
		!strings.Contains(line, "172.16.50.8:520") {
		t.Errorf("custom line must name the narrowed scopes with the 520 sample: %q", line)
	}
}

// TestWithTighteningWarningsBfdEchoRemovalWarnsCustoms10752 is the BFD
// Echo carve-in RED pin: p:bfd removal is token-only, but FRR echo-mode
// (operator-enabled, non-default) sends fixed sport=dport=3785, which
// the sweep records as customs — so a kept 3785→3785 flow is genuinely
// stranded and must emit the customs evidence line, not the advisory.
// The collector leg also pins the Control-shape negative control:
// RFC-conformant ephemeral-sport Control (49152+) stays sweep-silent.
func TestWithTighteningWarningsBfdEchoRemovalWarnsCustoms10752(t *testing.T) {
	origRange := readEphemeralPortRange
	readEphemeralPortRange = func() (uint16, uint16) { return 32768, 60999 }
	defer func() { readEphemeralPortRange = origRange }()
	cfg := hostInboundFlushTestConfig("snmp")
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
	filter := buildHostInboundConntrackFlushFilter(views, unzonedV4, unzonedV6, nil)
	if filter == nil {
		t.Fatal("expected a filter for the enforcing configuration")
	}
	mkFlow := func(sport, dport uint16) *netlink.ConntrackFlow {
		return &netlink.ConntrackFlow{Forward: netlink.IPTuple{
			SrcIP: net.ParseIP("172.16.50.8"), DstIP: net.ParseIP("203.0.113.7"),
			Protocol: config.HostInboundProtoUDP, SrcPort: sport, DstPort: dport,
		}}
	}
	if filter.MatchConntrackFlow(mkFlow(3785, 3785)) {
		t.Fatal("denied echo-shaped tuple must be kept (catalog miss), not flushed")
	}
	if filter.MatchConntrackFlow(mkFlow(50000, 3784)) {
		t.Fatal("denied control-shaped tuple must be kept (catalog miss), not flushed")
	}
	if got, _ := filter.keptSuspiciousReport(); got != 1 {
		t.Fatalf("kept-suspicious count = %d, want 1 (echo recorded, control silent)", got)
	}

	oldCfg := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	oldCfg.Security.Zones["wan"].HostInboundTraffic.Protocols = []string{"bfd"}
	newCfg := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	d := &Daemon{}
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		netip.MustParseAddr("172.16.50.8"): kept10752(1,
			[]string{"udp 172.16.50.8:3785→203.0.113.7:3785"}, 0, nil),
	})
	resp := d.withTighteningWarningsForResponse10752(newCfg, oldCfg, newCfg)
	if resp == newCfg {
		t.Fatal("bfd removal with a kept echo flow must warn, got identity")
	}
	if len(resp.Warnings) != 2 {
		t.Fatalf("warnings = %v, want [custom line, pointer]", resp.Warnings)
	}
	line := resp.Warnings[0]
	if !strings.Contains(line, "(zone:wan, zone:wan|iface:reth0.50)") ||
		!strings.Contains(line, "leaves 1 box-oriented custom-port") ||
		!strings.Contains(line, "172.16.50.8:3785") {
		t.Errorf("custom line must name the narrowed scopes with the echo sample: %q", line)
	}
}

// TestWithTighteningWarningsLooseningToFullStaysSilent10752 is the
// response-level loosening pin: named-with-exempt to any-service is no
// transition, so even observed evidence stays projection-silent.
func TestWithTighteningWarningsLooseningToFullStaysSilent10752(t *testing.T) {
	oldCfg := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	oldCfg.Security.Zones["wan"].HostInboundTraffic.Protocols = []string{"bgp"}
	newCfg := tighteningScopeCfg(t, []string{"any-service"}, []string{"ssh"})
	d := &Daemon{}
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		netip.MustParseAddr("172.16.50.8"): kept10752(1,
			[]string{"tcp 172.16.50.8:2222→203.0.113.7:40000"}, 1,
			[]string{"tcp 172.16.50.8:179→203.0.113.7:40001"}),
	})
	if resp := d.withTighteningWarningsForResponse10752(newCfg, oldCfg, newCfg); resp != newCfg {
		t.Fatalf("loosening to full-admit must stay silent, got %v", resp.Warnings)
	}
}

// TestWithTighteningWarningsShadowReplacementStaysSilent10752 pins the
// user-visible symptom: zone-inherit ssh+bgp loosened by adding a
// full-admit override must stay fully silent (no spurious advisory),
// even with observed evidence on the member address.
func TestWithTighteningWarningsShadowReplacementStaysSilent10752(t *testing.T) {
	oldCfg := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	oldCfg.Security.Zones["wan"].HostInboundTraffic.Protocols = []string{"bgp"}
	newCfg := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	newCfg.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
		"reth0.50": {SystemServices: []string{"any-service"}},
	}
	d := &Daemon{}
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		netip.MustParseAddr("172.16.50.8"): kept10752(1,
			[]string{"tcp 172.16.50.8:2222→203.0.113.7:40000"}, 1,
			[]string{"tcp 172.16.50.8:179→203.0.113.7:40001"}),
	})
	if resp := d.withTighteningWarningsForResponse10752(newCfg, oldCfg, newCfg); resp != newCfg {
		t.Fatalf("shadow-replacement loosening must stay silent, got %v", resp.Warnings)
	}
}

// TestWithTighteningWarningsPerClassNamingBothZones10752 is the
// cross-zone per-class pin: both zones narrow with opposite evidence
// classes, and each line must name only its own class's scopes.
func TestWithTighteningWarningsPerClassNamingBothZones10752(t *testing.T) {
	oldCfg := tighteningScopeCfg(t, []string{"any-service"}, []string{"any-service"})
	newCfg := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	d := &Daemon{}
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		netip.MustParseAddr("172.16.50.8"): kept10752(1,
			[]string{"tcp 172.16.50.8:2222→203.0.113.7:40000"}, 0, nil),
		netip.MustParseAddr("10.0.61.1"): kept10752(0, nil, 5,
			[]string{"tcp 10.0.61.1:179→203.0.113.7:40001"}),
	})
	resp := d.withTighteningWarningsForResponse10752(newCfg, oldCfg, newCfg)
	if resp == newCfg {
		t.Fatal("intersecting evidence must warn, got identity")
	}
	if len(resp.Warnings) != 3 {
		t.Fatalf("warnings = %v, want [custom line, other line, pointer]", resp.Warnings)
	}
	custom, other := resp.Warnings[0], resp.Warnings[1]
	if !strings.Contains(custom, "(zone:wan, zone:wan|iface:reth0.50)") ||
		!strings.Contains(custom, "172.16.50.8:2222") ||
		strings.Contains(custom, "zone:lan") || strings.Contains(custom, "10.0.61.1") {
		t.Errorf("custom line must name/render WAN only: %q", custom)
	}
	if !strings.Contains(other, "(zone:lan, zone:lan|iface:reth1.0)") ||
		!strings.Contains(other, "10.0.61.1:179") ||
		strings.Contains(other, "zone:wan") || strings.Contains(other, "172.16.50.8") {
		t.Errorf("other line must name/render LAN only: %q", other)
	}
}

// TestWithTighteningWarningsVIPNarrowingWarnsInterface10752 is the
// VIP positive pin: all units overridden, one override narrows, and
// that unit's VIP has retained evidence — the commit must emit the
// exact interface-scoped evidence line, not the zero-observed
// advisory. Zone-granular fallback yields the advisory — RED there.
func TestWithTighteningWarningsVIPNarrowingWarnsInterface10752(t *testing.T) {
	mkCfg := func(member50 []string) *config.Config {
		cfg := twoUnitWanCfg10752(t, []string{"ssh"})
		cfg.Interfaces.Interfaces["reth0"].Units[50].VRRPGroups = map[string]*config.VRRPGroup{
			"1": {ID: 1, VirtualAddresses: []string{"172.16.50.100"}},
		}
		cfg.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
			"reth0.50": {SystemServices: member50},
			"reth0.60": {SystemServices: []string{"any-service"}},
		}
		return cfg
	}
	oldCfg := mkCfg([]string{"any-service"})
	newCfg := mkCfg([]string{"ssh"})
	if got, _ := hostInboundTightenedScopes(oldCfg, newCfg); len(got) != 1 || got[0] != "zone:wan|iface:reth0.50" {
		t.Fatalf("tightened = %v, want [zone:wan|iface:reth0.50]", got)
	}
	vip := netip.MustParseAddr("172.16.50.100")
	d := &Daemon{}
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		vip: kept10752(1, []string{"tcp 172.16.50.100:2222→203.0.113.7:40000"}, 0, nil),
	})
	resp := d.withTighteningWarningsForResponse10752(newCfg, oldCfg, newCfg)
	if resp == newCfg {
		t.Fatal("VIP evidence on a narrowed override must warn, got identity")
	}
	if len(resp.Warnings) != 2 {
		t.Fatalf("warnings = %v, want [custom line, pointer]", resp.Warnings)
	}
	if !strings.Contains(resp.Warnings[0], "(zone:wan|iface:reth0.50)") ||
		!strings.Contains(resp.Warnings[0], "172.16.50.100:2222") {
		t.Errorf("custom line must name the narrowed VIP unit with its sample: %q", resp.Warnings[0])
	}
}

// TestWithTighteningWarningsGroupedDerivedEvidence10752 is the
// production-grouped shape: two IPv6 RETH units in one zone/RG, both
// overridden any-service, sharing one production view with their
// derived stable link-local. Tightening both overrides to ssh with
// retained customs on the LL must emit evidence lines naming both
// narrowed interface scopes — zone-only fallback drops the evidence
// (the zone-default key narrows nowhere here) and falsely claims
// zero observed.
func TestWithTighteningWarningsGroupedDerivedEvidence10752(t *testing.T) {
	mkCfg := func(memberServices []string) *config.Config {
		cfg := &config.Config{}
		cfg.Chassis.Cluster = &config.ClusterConfig{
			ClusterID:        7,
			NodeID:           0,
			NodeIDSet:        true,
			RedundancyGroups: []*config.RedundancyGroup{{ID: 1}},
		}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"reth0": {Name: "reth0", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{
				50: {Number: 50, VlanID: 50, Addresses: []string{"2001:db8:50::8/64"}},
				60: {Number: 60, VlanID: 60, Addresses: []string{"2001:db8:60::8/64"}},
			}},
		}
		cfg.Security.Zones = map[string]*config.ZoneConfig{
			"wan": {
				Name:               "wan",
				Interfaces:         []string{"reth0.50", "reth0.60"},
				HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
				InterfaceHostInbound: map[string]*config.HostInboundTraffic{
					"reth0.50": {SystemServices: memberServices},
					"reth0.60": {SystemServices: memberServices},
				},
			},
		}
		return cfg
	}
	oldCfg := mkCfg([]string{"any-service"})
	newCfg := mkCfg([]string{"ssh"})
	if got, _ := hostInboundTightenedScopes(oldCfg, newCfg); len(got) != 2 {
		t.Fatalf("tightened = %v, want both narrowed interface scopes", got)
	}
	ll := cluster.StableRethLinkLocal(7, 1)
	llAddr := netip.MustParseAddr(ll.String())
	grouped := false
	for _, v := range dpuserspace.BuildZoneHostInboundViews(oldCfg) {
		hasLL := false
		for _, raw := range append(append([]string(nil), v.V4Addrs...), v.V6Addrs...) {
			if ip, err := netip.ParseAddr(raw); err == nil && ip.Unmap() == llAddr {
				hasLL = true
			}
		}
		if hasLL && len(v.Interfaces) >= 2 {
			grouped = true
		}
	}
	if !grouped {
		t.Fatal("sanity: the stable LL must share a multi-interface production view for this test to mean anything")
	}
	d := &Daemon{}
	d.recordKeptSuspicious10752(map[netip.Addr]keptAddrEvidence{
		llAddr: kept10752(1, []string{"udp [" + llAddr.String() + "]:2222→203.0.113.7:40000"}, 0, nil),
	})
	resp := d.withTighteningWarningsForResponse10752(newCfg, oldCfg, newCfg)
	if resp == newCfg {
		t.Fatal("grouped derived evidence on narrowed overrides must warn, got identity")
	}
	if len(resp.Warnings) != 2 {
		t.Fatalf("warnings = %v, want [custom line, pointer]", resp.Warnings)
	}
	if !strings.Contains(resp.Warnings[0], "(zone:wan|iface:reth0.50, zone:wan|iface:reth0.60)") {
		t.Errorf("custom line must name both narrowed owner scopes: %q", resp.Warnings[0])
	}
}

// TestWithTighteningWarningsSilentAddressless10752 pins the advisory's
// address gate: a real transition on scopes owning no address in either
// generation can strand nothing and offers nothing to verify, so the
// commit stays silent.
func TestWithTighteningWarningsSilentAddressless10752(t *testing.T) {
	mkCfg := func(services []string) *config.Config {
		cfg := hostInboundTestConfig()
		cfg.Security.Zones["ghost"] = &config.ZoneConfig{
			Name:               "ghost",
			Interfaces:         []string{"reth9.9"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: services},
		}
		return cfg
	}
	oldCfg := mkCfg([]string{"any-service"})
	newCfg := mkCfg([]string{"ssh"})
	if got, _ := hostInboundTightenedScopes(oldCfg, newCfg); len(got) != 2 {
		t.Fatalf("tightened = %v, want the ghost zone + iface scopes (the gate, not the transition, must silence this)", got)
	}
	d := &Daemon{}
	d.recordKeptSuspicious10752(nil)
	if resp := d.withTighteningWarningsForResponse10752(newCfg, oldCfg, newCfg); resp != newCfg {
		t.Fatalf("addressless narrowing must stay silent, got %v", resp.Warnings)
	}
}

// TestApplyAndSyncCommittedWarnsTighteningStranded10752 drives the real
// commit funnel: old any-service → new named, with this attempt's sweep
// observing a stranded box-oriented custom flow (via the conntrack seam).
// The returned response must carry the tightening line plus the silent-class
// pointer on a copy while the applied object keeps only its validation
// warnings. A pre-seeded stale stash (kept=99) must NOT leak through — the
// funnel clears per attempt.
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
	found, pointer := false, false
	for _, w := range got.Warnings {
		if strings.Contains(w, "zone:wan") && strings.Contains(w, "2222") {
			found = true
			if strings.Contains(w, "99") || strings.Contains(w, "stale") {
				t.Fatalf("stale pre-seeded evidence leaked into the warning: %q", w)
			}
		}
		if strings.Contains(w, "cannot observe") {
			pointer = true
		}
	}
	if !found {
		t.Fatalf("no tightening warning naming zone:wan + 2222 in %v", got.Warnings)
	}
	if !pointer {
		t.Fatalf("observed evidence must append the silent-class pointer in %v", got.Warnings)
	}
	if len(compiled.Warnings) != 1 {
		t.Fatalf("applied warnings = %v, want only the foreign line", compiled.Warnings)
	}
}

// TestApplyAndSyncCommittedAdvisoryCrossScope10752 is the funnel-level
// misattribution guard: wan tightens, but the only stranded flow lives on a
// lan address. The response must carry exactly the transition-only advisory
// (the narrowing still needs manual verification for silent classes) —
// never an evidence line naming wan from lan's flow.
func TestApplyAndSyncCommittedAdvisoryCrossScope10752(t *testing.T) {
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
	if got == compiled {
		t.Fatal("cross-scope narrowing must carry the transition-only advisory, got identity")
	}
	if len(got.Warnings) != 1 {
		t.Fatalf("warnings = %v, want exactly the advisory line", got.Warnings)
	}
	line := got.Warnings[0]
	for _, want := range []string{"zone:wan", "observed no stranded flows", "Removal procedures"} {
		if !strings.Contains(line, want) {
			t.Errorf("advisory line missing %q: %q", want, line)
		}
	}
	for _, leak := range []string{"custom-port", "exempt/bare-protocol", "10.0.61.1", "2222"} {
		if strings.Contains(line, leak) {
			t.Errorf("advisory must not name wan from lan's flow (%q): %q", leak, line)
		}
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
	found, pointer := false, false
	for _, w := range got.Warnings {
		if strings.Contains(w, "zone:wan") && strings.Contains(w, "exempt/bare-protocol") && strings.Contains(w, "179") {
			found = true
		}
		if strings.Contains(w, "custom-port") {
			t.Fatalf("exempt-only evidence must not emit a custom clause: %q", w)
		}
		if strings.Contains(w, "cannot observe") {
			pointer = true
		}
	}
	if !found {
		t.Fatalf("no exempt/bare warning naming zone:wan + 179 in %v", got.Warnings)
	}
	if !pointer {
		t.Fatalf("observed evidence must append the silent-class pointer in %v", got.Warnings)
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
	found, pointer := false, false
	for _, w := range got.Warnings {
		if strings.Contains(w, "zone:wan") && strings.Contains(w, "exempt/bare-protocol") {
			found = true
		}
		if strings.Contains(w, "cannot observe") {
			pointer = true
		}
	}
	if !found {
		t.Fatalf("no exempt/bare warning naming zone:wan in %v", got.Warnings)
	}
	if !pointer {
		t.Fatalf("observed evidence must append the silent-class pointer in %v", got.Warnings)
	}
}
