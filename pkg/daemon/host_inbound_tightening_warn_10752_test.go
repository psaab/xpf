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
			name: "all-to-named-minus-bgp fires via expansion",
			oldW: []string{"all"}, oldL: named,
			newW: []string{"ssh"}, newL: named,
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
	d.recordKeptSuspicious10752(2, []string{"tcp 172.16.50.8:2222→203.0.113.7:40000"},
		1, []string{"tcp 172.16.50.8:179→203.0.113.7:40001"}, []netip.Addr{wan})

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
	d.recordKeptSuspicious10752(3, nil, 0, nil, []netip.Addr{wan})
	if resp := d.withTighteningWarningsForResponse10752(namedCfg, namedCfg, namedCfg); resp != namedCfg {
		t.Error("no transition must return the input pointer")
	}
	// Transition + zero evidence → identity.
	d.recordKeptSuspicious10752(0, nil, 0, nil, nil)
	if resp := d.withTighteningWarningsForResponse10752(namedCfg, openCfg, namedCfg); resp != namedCfg {
		t.Error("zero kept must return the input pointer")
	}
	// Transition + evidence on an UNRELATED zone only → identity (no
	// misattribution: a zone-B residual must not name a zone-A tightening).
	d.recordKeptSuspicious10752(2, []string{"tcp 10.0.61.1:2222→203.0.113.7:40000"}, 0, nil, []netip.Addr{lan})
	if resp := d.withTighteningWarningsForResponse10752(namedCfg, openCfg, namedCfg); resp != namedCfg {
		t.Error("cross-scope evidence must stay silent (no intersected zone)")
	}
	// Nil response (failed apply) → nil.
	d.recordKeptSuspicious10752(3, nil, 0, nil, []netip.Addr{wan})
	if resp := d.withTighteningWarningsForResponse10752(nil, openCfg, namedCfg); resp != nil {
		t.Error("nil response must stay nil")
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
	d.recordKeptSuspicious10752(99, []string{"stale"}, 0, nil, nil)
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
// since no tightened zone contains stranded flows.
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
