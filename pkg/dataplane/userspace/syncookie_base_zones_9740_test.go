package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestNodesWithDifferentScreenedZonesDeriveTheSameKey9740: the helper's
// SYN-cookie machinery is global, so the screened-zone set is not a key input.
// Two nodes that screen different zones must derive one key, or a cookie minted
// by one fails on the other after a failover. The same holds for one node
// across a commit that changes its screened zones, or every cookie minted before
// the commit fails.
func TestNodesWithDifferentScreenedZonesDeriveTheSameKey9740(t *testing.T) {
	cluster := func() *config.ClusterConfig { return keyedCluster9173("psk-A", "psk-old") }
	key0, ring0 := buildSYNCookieKeys(synCookieCfg9173(cluster(), "", "fw0"), synCookieT0_9173)
	if len(key0) != 32 || ring0 == nil {
		t.Fatalf("premise: SYN-cookie protection must be active, got key %q ring %v", key0, ring0)
	}

	for name, mutate := range map[string]func(*config.Config){
		"a differently named screened zone": func(cfg *config.Config) {
			cfg.Security.Zones = map[string]*config.ZoneConfig{"dmz": {Name: "dmz", ScreenProfile: "flood"}}
		},
		"an added screened zone": func(cfg *config.Config) {
			cfg.Security.Zones["untrust"] = &config.ZoneConfig{Name: "untrust", ScreenProfile: "flood"}
		},
		"a different screen profile name": func(cfg *config.Config) {
			cfg.Security.Screen["flood-b"] = &config.ScreenProfile{
				Name: "flood-b",
				TCP:  config.TCPScreen{SynFlood: &config.SynFloodConfig{AttackThreshold: 50}},
			}
			cfg.Security.Zones["trust"].ScreenProfile = "flood-b"
		},
	} {
		cfg := synCookieCfg9173(cluster(), "", "fw1")
		mutate(cfg)
		key, ring := buildSYNCookieKeys(cfg, synCookieT0_9173)
		if key != key0 || !reflect.DeepEqual(ring, ring0) {
			t.Fatalf("%s changed the SYN-cookie key (%q, want %q): the zone set is not a key input "+
				"(the helper binds each cookie to its zone's name), and a node that differs in it "+
				"cannot validate its peer's cookies (#9740)", name, key, key0)
		}
	}

	// Control: with no screened zone no zone can challenge, so there is still no key.
	none := synCookieCfg9173(cluster(), "", "fw1")
	none.Security.Zones = map[string]*config.ZoneConfig{"trust": {Name: "trust"}}
	if key, ring := buildSYNCookieKeys(none, synCookieT0_9173); key != "" || ring != nil {
		t.Fatalf("no screened zone must mean no SYN-cookie key, got %q %v", key, ring)
	}
	// Control: the secret still moves the key, so the equality above is not a constant.
	if other, _ := buildSYNCookieKeys(synCookieCfg9173(keyedCluster9173("psk-B", "psk-old"), "", "fw0"), synCookieT0_9173); other == key0 {
		t.Fatal("a different authentication-key derived the same key")
	}
}
