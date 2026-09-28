package daemon

import (
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
			name: "override added over open zone fires for the iface scope only",
			oldW: full, oldL: named, newW: full, newL: named,
			mutate: func(old, new *config.Config) {
				new.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
					"reth0.50": {SystemServices: named},
				}
			},
			want: []string{"zone:wan|iface:reth0.50"},
		},
		{
			name: "deleted full-admit zone fires",
			oldW: full, oldL: named, newW: named, newL: named,
			mutate: func(old, new *config.Config) {
				delete(new.Security.Zones, "wan")
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
			got := hostInboundTightenedFullAdmitScopes(oldCfg, newCfg)
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
	if got := hostInboundTightenedFullAdmitScopes(nil, &config.Config{}); got != nil {
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
	if got := hostInboundTightenedFullAdmitScopes(oldCfg, newCfg); len(got) != 0 {
		t.Fatalf("lifeline-only narrowing must stay silent, got %v", got)
	}
}

func TestWithTighteningWarningsProjectsCopy10752(t *testing.T) {
	oldCfg := tighteningScopeCfg(t, []string{"any-service"}, []string{"ssh"})
	newCfg := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	newCfg.Warnings = []string{"foreign advisory"}
	d := &Daemon{}
	d.recordKeptSuspicious10752(2, []string{"tcp 172.16.50.8:2222→203.0.113.7:40000"})

	resp := d.withTighteningWarningsForResponse10752(newCfg, oldCfg, newCfg)
	if resp == newCfg {
		t.Fatal("firing projection must return a copy, never the applied pointer")
	}
	if len(resp.Warnings) != 2 || resp.Warnings[0] != "foreign advisory" {
		t.Fatalf("response warnings = %v, want [foreign advisory, tightening line]", resp.Warnings)
	}
	line := resp.Warnings[1]
	for _, want := range []string{"zone:wan", "2", "2222", "HIGH-residual", "docs/host-inbound-service-matrix.md"} {
		if !strings.Contains(line, want) {
			t.Errorf("warning line must contain %q: %q", want, line)
		}
	}
	if len(newCfg.Warnings) != 1 {
		t.Fatalf("applied warnings = %v, want the input untouched", newCfg.Warnings)
	}
}

func TestWithTighteningWarningsIdentityCases10752(t *testing.T) {
	openCfg := tighteningScopeCfg(t, []string{"any-service"}, []string{"ssh"})
	namedCfg := tighteningScopeCfg(t, []string{"ssh"}, []string{"ssh"})
	d := &Daemon{}
	// No transition (identical configs) + evidence → identity.
	d.recordKeptSuspicious10752(3, nil)
	if resp := d.withTighteningWarningsForResponse10752(namedCfg, namedCfg, namedCfg); resp != namedCfg {
		t.Error("no transition must return the input pointer")
	}
	// Transition + zero evidence → identity.
	d.recordKeptSuspicious10752(0, nil)
	if resp := d.withTighteningWarningsForResponse10752(namedCfg, openCfg, namedCfg); resp != namedCfg {
		t.Error("zero kept must return the input pointer")
	}
	// Nil response (failed apply) → nil.
	d.recordKeptSuspicious10752(3, nil)
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
	d.recordKeptSuspicious10752(99, []string{"stale"})
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
