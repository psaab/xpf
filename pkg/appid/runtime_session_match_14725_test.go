package appid

// #14725 (D19-03): three legs verified on origin/master.
//
// Leg 1 — SessionMatchesWithIndex only did resolved == filter, while the
// compiler desugars a multi-term application into <parent>-<term> leaves
// grouped under ApplicationSets[parent], and operators can also filter by
// any application-set (user or predefined). show/clear ... application
// <parent-or-set> matched zero sessions.
// Leg 2 — resolveTupleFallbackWithIndex considered only the 15-entry
// builtinFallbacks, so a catalogued predefined app outside that table
// (junos-rdp, ...) never labelled an unstamped session; and a present-but-
// nil user entry (#4865 tolerated) both failed consider (nil skip) and
// shadowed the predefined definition, yielding UNKNOWN.
// Leg 3 — when a same-tier tie needed full-universe IDs, the code re-ranked
// BOTH candidates by fullIDs, whose displaced placement differs from the
// active OFF catalog (referenced-only when AppID is off; referenced+set
// members otherwise). An uncatalogued collider stealing/inverting that
// order let an unreferenced app beat the referenced app that actually owns
// appNames[H]; fully uncatalogued ties keep the full-universe ranking
// (#12225 AppID-on parity).

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compile14725(t *testing.T, lines []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// Leg 1, end-to-end through the real compiler: multi-term parent, explicit
// application-set, predefined set, nested set, and control negatives.
func TestSessionMatchesMultiTermAndSets_14725(t *testing.T) {
	cfg := compile14725(t, []string{
		"set applications application web-multi term t1 protocol tcp destination-port 8080",
		"set applications application web-multi term t2 protocol tcp destination-port 8443",
		"set applications application alpha-web protocol tcp destination-port 8081",
		"set applications application beta-web protocol tcp destination-port 8082",
		"set applications application-set web-set application alpha-web",
		"set applications application-set web-set application beta-web",
		"set applications application-set outer-set application-set web-set",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application web-multi",
		"set security policies from-zone trust to-zone untrust policy p1 match application web-set",
		"set security policies from-zone trust to-zone untrust policy p1 match application outer-set",
		"set security policies from-zone trust to-zone untrust policy p1 match application junos-sip",
		"set security policies from-zone trust to-zone untrust policy p1 match application junos-rdp",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
	})
	cfg.Services.ApplicationIdentification = true

	cat, err := BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}
	idOf := func(name string) uint16 {
		t.Helper()
		for id, n := range cat.AppNames {
			if n == name {
				return id
			}
		}
		t.Fatalf("app %q not in catalog %v", name, cat.AppNames)
		return 0
	}
	idx := NewFallbackIndex(cfg)
	match := func(filter string, appID uint16, proto uint8, src, dst uint16) bool {
		return SessionMatchesWithIndex(filter, cat.AppNames, cfg, idx, proto, src, dst, appID)
	}

	t1, t2 := idOf("web-multi-t1"), idOf("web-multi-t2")
	// Parent filter matches both term leaves; term filter stays exact.
	if !match("web-multi", t1, 6, 40000, 8080) || !match("web-multi", t2, 6, 40000, 8443) {
		t.Fatal("application web-multi must match its term sessions")
	}
	if !match("web-multi-t1", t1, 6, 40000, 8080) || match("web-multi-t1", t2, 6, 40000, 8443) {
		t.Fatal("term filter must stay exact")
	}
	// Explicit set, nested set, and predefined-set filters.
	alpha, beta := idOf("alpha-web"), idOf("beta-web")
	if !match("web-set", alpha, 6, 40000, 8081) || !match("web-set", beta, 6, 40000, 8082) {
		t.Fatal("application-set web-set must match member sessions")
	}
	if !match("outer-set", alpha, 6, 40000, 8081) {
		t.Fatal("nested application-set outer-set must match member sessions")
	}
	sipUDP := idOf("junos-sip-udp")
	if !match("junos-sip", sipUDP, 17, 40000, 5060) {
		t.Fatal("predefined set junos-sip must match member sessions")
	}
	// Negatives: different app, case sensitivity (#5820), UNKNOWN sentinel.
	rdp := idOf("junos-rdp")
	if match("web-multi", rdp, 6, 40000, 3389) {
		t.Fatal("web-multi must not match a junos-rdp session")
	}
	if match("WEB-MULTI", t1, 6, 40000, 8080) {
		t.Fatal("set filter must stay case-exact")
	}
	if match("web-multi", 0, 6, 40000, 8080) {
		t.Fatal("UNKNOWN session must not match a set filter")
	}
	// Unstamped + AppID off: resolved leaf via tuple fallback still matches parent.
	cfg.Services.ApplicationIdentification = false
	idx = NewFallbackIndex(cfg)
	if !SessionMatchesWithIndex("web-multi", cat.AppNames, cfg, idx, 6, 40000, 8080, 0) {
		t.Fatal("unstamped term session must match parent filter via tuple fallback")
	}
}

// Leg 2: catalogued predefined apps beyond builtinFallbacks label unstamped
// sessions; unreferenced ones stay UNKNOWN (#12731); nil-shadow does not kill
// the predefined definition; a non-nil redefinition still shadows; an
// application-set reference catalogs its predefined members.
func TestTupleFallbackPredefinedCatalog_14725(t *testing.T) {
	mk := func(refs []string) (*config.Config, Catalog) {
		cfg := &config.Config{}
		cfg.Services.ApplicationIdentification = false
		for _, ref := range refs {
			cfg.Security.GlobalPolicies = append(cfg.Security.GlobalPolicies,
				&config.Policy{Name: "ref-" + ref, Match: config.PolicyMatch{Applications: []string{ref}}})
		}
		cat, err := BuildCatalog(cfg)
		if err != nil {
			t.Fatalf("BuildCatalog: %v", err)
		}
		return cfg, cat
	}

	// junos-rdp is in PredefinedApplications but not builtinFallbacks.
	cfg, cat := mk([]string{"junos-rdp"})
	if got := ResolveSessionName(cat.AppNames, cfg, 6, 40000, 3389, 0); got != "junos-rdp" {
		t.Fatalf("unstamped tcp/3389 = %q, want junos-rdp", got)
	}
	if !SessionMatches("junos-rdp", cat.AppNames, cfg, 6, 40000, 3389, 0) {
		t.Fatal("SessionMatches(junos-rdp) must match unstamped tcp/3389")
	}
	// A second non-builtin predefined with a port range.
	cfg, cat = mk([]string{"junos-irc"})
	if got := ResolveSessionName(cat.AppNames, cfg, 6, 40000, 6665, 0); got != "junos-irc" {
		t.Fatalf("unstamped tcp/6665 = %q, want junos-irc", got)
	}

	// #12731 control: unreferenced predefined stays UNKNOWN.
	cfg, cat = mk([]string{"junos-ssh"})
	if got := ResolveSessionName(cat.AppNames, cfg, 6, 40000, 3389, 0); got != Unknown {
		t.Fatalf("unreferenced junos-rdp tuple = %q, want UNKNOWN", got)
	}

	// Set-referenced predefined members are catalogued, so they win too.
	cfg, cat = mk([]string{"junos-sip"})
	if got := ResolveSessionName(cat.AppNames, cfg, 17, 40000, 5060, 0); got != "junos-sip-udp" {
		t.Fatalf("unstamped udp/5060 via junos-sip set = %q, want junos-sip-udp", got)
	}

	// Nil user entry (#4865) must not shadow the predefined definition on
	// the fallback path. Here the catalog is built from a config without
	// the nil entry (BuildCatalog skips nil apps by design, #4865), while
	// the fallback runs against the leniently loaded config that carries
	// it: the predefined junos-http definition must still label tcp/80.
	// Run several times: the predefined loop iterates a Go map.
	for range 20 {
		nilCfg := &config.Config{Applications: config.ApplicationsConfig{Applications: map[string]*config.Application{
			"junos-http": nil,
		}}}
		nilCfg.Services.ApplicationIdentification = false
		cleanCfg := &config.Config{}
		cleanCfg.Services.ApplicationIdentification = false
		cleanCfg.Security.GlobalPolicies = []*config.Policy{{Name: "ref", Match: config.PolicyMatch{Applications: []string{"junos-http"}}}}
		cleanCat, err := BuildCatalog(cleanCfg)
		if err != nil {
			t.Fatalf("BuildCatalog: %v", err)
		}
		if got := ResolveSessionName(cleanCat.AppNames, nilCfg, 6, 40000, 80, 0); got != "junos-http" {
			t.Fatalf("nil-shadowed tcp/80 = %q, want junos-http", got)
		}
	}

	// Non-nil redefinition still shadows (control, #11817 shape).
	reCfg := &config.Config{Applications: config.ApplicationsConfig{Applications: map[string]*config.Application{
		"junos-http": {Name: "junos-http", Protocol: "tcp", DestinationPort: "8080"},
	}}}
	reCfg.Services.ApplicationIdentification = false
	reCfg.Security.GlobalPolicies = []*config.Policy{{Name: "ref", Match: config.PolicyMatch{Applications: []string{"junos-http"}}}}
	reCat, err := BuildCatalog(reCfg)
	if err != nil {
		t.Fatalf("BuildCatalog redefined: %v", err)
	}
	if got := ResolveSessionName(reCat.AppNames, reCfg, 6, 40000, 80, 0); got != Unknown {
		t.Fatalf("redefined junos-http tcp/80 = %q, want UNKNOWN", got)
	}
	if got := ResolveSessionName(reCat.AppNames, reCfg, 6, 40000, 8080, 0); got != "junos-http" {
		t.Fatalf("redefined junos-http tcp/8080 = %q, want junos-http", got)
	}
}

// Leg 3: a referenced app must not lose its active-catalog slot to an
// uncatalogued collider under the full-universe re-rank; fully uncatalogued
// ties keep the #12225 full-universe (AppID-on) winner.
func TestTupleFallbackCataloguedBeatsUncataloguedCollider_14725(t *testing.T) {
	if config.StableAppID("svc-217") != config.StableAppID("svc-396") {
		t.Skip("fixture stale: svc-217/svc-396 no longer collide")
	}
	mkCfg := func(names ...string) *config.Config {
		apps := make(map[string]*config.Application, len(names))
		for _, n := range names {
			apps[n] = &config.Application{Name: n, Protocol: "tcp", DestinationPort: "9101"}
		}
		cfg := &config.Config{Applications: config.ApplicationsConfig{Applications: apps}}
		cfg.Services.ApplicationIdentification = false
		return cfg
	}
	offNames := func(refs ...string) map[uint16]string {
		ids, err := config.AssignStableAppIDsQuiet(refs)
		if err != nil {
			t.Fatalf("AssignStableAppIDsQuiet: %v", err)
		}
		out := make(map[uint16]string, len(ids))
		for n, id := range ids {
			out[id] = n
		}
		return out
	}

	// Referenced svc-396 owns the OFF slot; unreferenced svc-217 must not steal it.
	cfg := mkCfg("svc-217", "svc-396")
	if got := resolveTupleFallbackWithIndex(6, 40000, 9101, cfg, offNames("svc-396"), NewFallbackIndex(cfg)); got != "svc-396" {
		t.Fatalf("referenced svc-396 vs unreferenced collider = %q, want svc-396", got)
	}
	// Referenced svc-217 owns the slot; the displaced full-universe winner
	// svc-396 is uncatalogued and must not steal it.
	cfg = mkCfg("svc-217", "svc-396")
	if got := resolveTupleFallbackWithIndex(6, 40000, 9101, cfg, offNames("svc-217"), NewFallbackIndex(cfg)); got != "svc-217" {
		t.Fatalf("referenced svc-217 vs unreferenced collider = %q, want svc-217", got)
	}
	// A catalogued candidate in the tier (mmm-middle) is not displaced
	// by an uncatalogued displaced winner (svc-396 at full ID 1): the
	// catalogued candidate keeps the tier. (svc-396 still wins fully
	// uncatalogued ties — control below.)
	cfg = mkCfg("svc-217", "svc-396", "mmm-middle")
	if got := resolveTupleFallbackWithIndex(6, 40000, 9101, cfg, offNames("mmm-middle"), NewFallbackIndex(cfg)); got != "mmm-middle" {
		t.Fatalf("referenced mmm-middle with uncatalogued colliders = %q, want mmm-middle", got)
	}
	// Predefined collider: uncatalogued collider-1057 must not beat referenced svc-396.
	cfg = mkCfg("collider-1057", "svc-396")
	if got := resolveTupleFallbackWithIndex(6, 40000, 9101, cfg, offNames("svc-396"), NewFallbackIndex(cfg)); got != "svc-396" {
		t.Fatalf("referenced svc-396 vs uncatalogued collider-1057 = %q, want svc-396", got)
	}
	// Control: fully uncatalogued tie keeps full-universe ranking (#12225).
	cfg = mkCfg("svc-217", "svc-396", "mmm-middle")
	if got := resolveTupleFallbackWithIndex(6, 40000, 9101, cfg, nil, NewFallbackIndex(cfg)); got != "svc-396" {
		t.Fatalf("fully uncatalogued tie = %q, want svc-396", got)
	}
}
