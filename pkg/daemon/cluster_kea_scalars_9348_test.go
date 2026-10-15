package daemon

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9348: filterDHCPConfigForMasterRGs reconstructed its result field by field
//
//	var result config.DHCPServerConfig
//	result.DHCPLocalServer = &config.DHCPLocalServerConfig{Groups: filtered}
//
// which names exactly the fields the author knew about and silently drops the
// rest. Measured before the fix — SIX fields, not the two the issue was filed
// with:
//
//	v4 SocketType    src="udp" filtered=""
//	v4 ExpiredLeases src=true  filtered=false
//	v6 SocketType    src="udp" filtered=""
//	v6 ExpiredLeases src=true  filtered=false
//	DynamicDNS       src=true  filtered=false
//	DynamicDNSv6     src=true  filtered=false
//
// The two that MATTER are the family-level Kea scalars: a CLUSTERED node
// rendered Kea without the operator's `expired-leases-processing` (#1387 — Kea
// fell back to its built-in reclamation defaults) and without
// `dhcp-socket-type` (#7318 — Kea fell back to `raw`), while a STANDALONE node
// rendered both from the same committed config. #7318 exists because `raw` does
// not work on some substrates, so on a cluster that leaf read as applied and was
// not.
//
// The DDNS pair is harmless, and that was CHECKED rather than assumed: this
// result reaches only dhcpserver.Manager (the Kea render), and the DDNS policy
// is read straight off the ACTIVE config by
// ddns.Manager.ReconcileScoped(ctx, &cfg.System.DHCPServer, opts). pkg/dhcpserver
// never reads DynamicDNS at all.
//
// FAIL-ON-REVERT: restore the field-by-field construction and every cell here
// goes RED.

func keaScalarCfg9348(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth1":    {Name: "reth1", RedundancyGroup: 1},
		"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth1"},
	}
	family := func() *config.DHCPLocalServerConfig {
		return &config.DHCPLocalServerConfig{
			Groups: map[string]*config.DHCPServerGroup{
				"g1": {Name: "g1", Interfaces: []string{"reth1.0"}},
			},
			SocketType:    "udp",
			ExpiredLeases: &config.DHCPExpiredLeasesConfig{},
		}
	}
	cfg.System.DHCPServer.DHCPLocalServer = family()
	cfg.System.DHCPServer.DHCPv6LocalServer = family()
	cfg.System.DHCPServer.DynamicDNS = &config.DHCPDynamicDNSConfig{}
	cfg.System.DHCPServer.DynamicDNSv6 = &config.DHCPDynamicDNSConfig{}
	return cfg
}

func TestClusterFilterKeepsFamilyKeaScalars9348(t *testing.T) {
	cfg := keaScalarCfg9348(t)
	out := (&Daemon{}).filterDHCPConfigForMasterRGsWithMasters(cfg, map[int]bool{})
	if out == nil {
		t.Fatal("filtered result is nil; nothing below is measured")
	}
	if out.DHCPLocalServer == nil || out.DHCPv6LocalServer == nil {
		t.Fatalf("a family was dropped entirely: v4=%v v6=%v",
			out.DHCPLocalServer != nil, out.DHCPv6LocalServer != nil)
	}
	for _, c := range []struct {
		fam string
		got *config.DHCPLocalServerConfig
	}{{"v4", out.DHCPLocalServer}, {"v6", out.DHCPv6LocalServer}} {
		if c.got.SocketType != "udp" {
			t.Errorf("%s dhcp-socket-type = %q, want \"udp\" — a clustered node would render Kea with "+
				"the default `raw`, which is what #7318 exists to override", c.fam, c.got.SocketType)
		}
		if c.got.ExpiredLeases == nil {
			t.Errorf("%s expired-leases-processing was dropped — a clustered node falls back to Kea's "+
				"built-in reclamation defaults (#1387)", c.fam)
		}
		// The narrowing this function is FOR must still happen.
		if len(c.got.Groups) == 0 {
			t.Errorf("%s groups were dropped; the filter narrowed everything away", c.fam)
		}
	}
	if out.DynamicDNS == nil || out.DynamicDNSv6 == nil {
		t.Errorf("the DDNS policies were dropped: v4=%v v6=%v (harmless today — pkg/dhcpserver never "+
			"reads them — but carried by construction so nobody has to re-derive that)",
			out.DynamicDNS != nil, out.DynamicDNSv6 != nil)
	}
}

// THE CLASS GUARD, and the reason this is not just two field assertions.
//
// The defect is reconstruct-by-enumeration: the NEXT field added to either
// struct is dropped by the same code for the same reason, and nothing about
// adding it would prompt anyone to look here. Rather than a field-COUNT
// assertion (which would cry wolf on a field the copy already carries), this
// walks the source reflectively and asserts every non-zero field that is not
// deliberately narrowed survives the filter.
func TestClusterFilterCarriesEveryFieldItDoesNotNarrow9348(t *testing.T) {
	cfg := keaScalarCfg9348(t)
	src := cfg.System.DHCPServer
	out := (&Daemon{}).filterDHCPConfigForMasterRGsWithMasters(cfg, map[int]bool{})
	if out == nil {
		t.Fatal("filtered result is nil")
	}

	// Fields this function legitimately REPLACES rather than copies.
	narrowedOuter := map[string]bool{"DHCPLocalServer": true, "DHCPv6LocalServer": true}
	narrowedFamily := map[string]bool{"Groups": true}

	assertCarried := func(what string, srcV, outV reflect.Value, narrowed map[string]bool) {
		tp := srcV.Type()
		checked := 0
		for i := 0; i < tp.NumField(); i++ {
			f := tp.Field(i)
			if !f.IsExported() || narrowed[f.Name] {
				continue
			}
			sf, of := srcV.Field(i), outV.Field(i)
			if sf.IsZero() {
				t.Errorf("%s: fixture leaves %s zero, so its carriage is not being measured", what, f.Name)
				continue
			}
			checked++
			if of.IsZero() {
				t.Errorf("%s: field %s was DROPPED by filterDHCPConfigForMasterRGs. The result must be a "+
					"COPY with only the narrowed fields swapped; reconstructing it field by field drops "+
					"whatever the author did not name, which is #9348.", what, f.Name)
			}
		}
		// Positive control: a reflective walk that examined nothing would
		// report a clean result for a completely broken function.
		if checked == 0 {
			t.Fatalf("%s: the reflective walk checked ZERO fields — the scan is broken, so its verdict "+
				"is meaningless", what)
		}
	}

	assertCarried("DHCPServerConfig",
		reflect.ValueOf(src), reflect.ValueOf(*out), narrowedOuter)
	assertCarried("DHCPLocalServerConfig(v4)",
		reflect.ValueOf(*src.DHCPLocalServer), reflect.ValueOf(*out.DHCPLocalServer), narrowedFamily)
	assertCarried("DHCPLocalServerConfig(v6)",
		reflect.ValueOf(*src.DHCPv6LocalServer), reflect.ValueOf(*out.DHCPv6LocalServer), narrowedFamily)
}

// The filter must not mutate the shared active config on its way (#9141's
// class, re-asserted here because this change touches the same function).
func TestClusterFilterStillDoesNotMutateTheSource9348(t *testing.T) {
	cfg := keaScalarCfg9348(t)
	before := cfg.System.DHCPServer.DHCPLocalServer.Groups["g1"].Interfaces[0]
	_ = (&Daemon{}).filterDHCPConfigForMasterRGsWithMasters(cfg, map[int]bool{})
	if got := cfg.System.DHCPServer.DHCPLocalServer.Groups["g1"].Interfaces[0]; got != before {
		t.Fatalf("the active config was mutated: %q -> %q", before, got)
	}
}

// WIRING BIND. Every cell above calls filterDHCPConfigForMasterRGs directly, so
// all of them stay green if desiredClusterDHCPConfig — the single entry point
// the commit path, both RG transition edges and the #6535 converger all use —
// stops calling it. Mutation M4 severed exactly that and SURVIVED, so the bind
// is added rather than assumed.
//
// The observable that separates delegating from not: the filter RESOLVES a RETH
// logical name to its physical member's Linux name, so a delegating
// desiredClusterDHCPConfig yields `ge-0-0-1.0` where the authored config says
// `reth1.0`. A scalar assertion could not see this — the unfiltered config
// carries the scalars too.
func TestDesiredClusterDHCPConfigDelegatesToTheFilter9348(t *testing.T) {
	cfg := keaScalarCfg9348(t)
	d := &Daemon{}

	got := d.desiredClusterDHCPConfigWithMasters(cfg, map[int]bool{})
	if got == nil {
		t.Fatal("desiredClusterDHCPConfig returned nil for a config with configured groups")
	}
	if got.DHCPLocalServer == nil {
		t.Fatal("v4 family missing from the desired config")
	}
	g := got.DHCPLocalServer.Groups["g1"]
	if g == nil {
		t.Fatal("group g1 missing from the desired config")
	}
	if len(g.Interfaces) == 0 {
		t.Fatal("group g1 has no interfaces")
	}
	if g.Interfaces[0] == "reth1.0" {
		t.Fatalf("desiredClusterDHCPConfig returned the AUTHORED interface %q — it is not routing "+
			"through filterDHCPConfigForMasterRGs, so Kea would be handed a RETH logical name that is "+
			"not a kernel device, and the master-RG narrowing never runs either", g.Interfaces[0])
	}
	if g.Interfaces[0] != "ge-0-0-1" && g.Interfaces[0] != "ge-0-0-1.0" {
		t.Fatalf("unexpected resolved interface %q", g.Interfaces[0])
	}

	// And the scalars survive through this entry point too, which is the path
	// production actually takes.
	if got.DHCPLocalServer.SocketType != "udp" || got.DHCPLocalServer.ExpiredLeases == nil {
		t.Errorf("the Kea scalars were dropped on the desiredClusterDHCPConfig path: SocketType=%q ExpiredLeases=%v",
			got.DHCPLocalServer.SocketType, got.DHCPLocalServer.ExpiredLeases != nil)
	}

	// Control: a config with no DHCP server at all still yields nil, so the
	// assertions above are about delegation and not about always returning
	// something.
	empty := &config.Config{}
	if out := d.desiredClusterDHCPConfigWithMasters(empty, map[int]bool{}); out != nil {
		t.Errorf("a config with no dhcp-server produced %+v, want nil", out)
	}
}
