package ra

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12533 sink: only Pinned+covered delegated prefixes are exempt.

func pinnedCfg12533(pfx *config.RAPrefix, pins []string, prot []string) *config.RAInterfaceConfig {
	c := &config.RAInterfaceConfig{Interface: "trust0", Prefixes: []*config.RAPrefix{pfx}}
	c.PinnedPrefixes = pins
	c.ProtectedPrefixes = prot
	return c
}

func TestBuildRAPinnedExempt12533(t *testing.T) {
	// Pinned+covered ULA emitted.
	cfg := pinnedCfg12533(&config.RAPrefix{Prefix: "fd00:1234::/64", OnLink: true, Autonomous: true, Delegated: true, Pinned: true},
		[]string{"fd00:1234::/48"}, nil)
	if got := rawPrefixInfosForClassTest(t, cfg); len(got) != 1 {
		t.Fatalf("pinned covered ULA: got %d PIOs want 1", len(got))
	}
	// Pinned but not covered -> refused.
	cfg = pinnedCfg12533(&config.RAPrefix{Prefix: "fd00:9999::/64", OnLink: true, Autonomous: true, Delegated: true, Pinned: true},
		[]string{"fd00:1234::/48"}, nil)
	if got := rawPrefixInfosForClassTest(t, cfg); len(got) != 0 {
		t.Fatalf("pinned uncovered ULA: got %d want 0", len(got))
	}
	// Covered but not Pinned -> refused (pin alone without provenance insufficient).
	cfg = pinnedCfg12533(&config.RAPrefix{Prefix: "fd00:1234::/64", OnLink: true, Autonomous: true, Delegated: true, Pinned: false},
		[]string{"fd00:1234::/48"}, nil)
	if got := rawPrefixInfosForClassTest(t, cfg); len(got) != 0 {
		t.Fatalf("unpinned-marked covered ULA: got %d want 0", len(got))
	}
	// Pinned+covered overlapping protected emitted.
	cfg = pinnedCfg12533(&config.RAPrefix{Prefix: "2606:4700:1111::/64", OnLink: true, Autonomous: true, Delegated: true, Pinned: true},
		[]string{"2606:4700::/32"}, []string{"2606:4700:1111::/64"})
	if got := rawPrefixInfosForClassTest(t, cfg); len(got) != 1 {
		t.Fatalf("pinned covered overlap: got %d want 1", len(got))
	}
	// Unpinned overlap refused (control).
	cfg = pinnedCfg12533(&config.RAPrefix{Prefix: "2606:4700:1111::/64", OnLink: true, Autonomous: true, Delegated: true},
		nil, []string{"2606:4700:1111::/64"})
	if got := rawPrefixInfosForClassTest(t, cfg); len(got) != 0 {
		t.Fatalf("unpinned overlap: got %d want 0", len(got))
	}
	// Operator-authored unaffected.
	cfg = pinnedCfg12533(&config.RAPrefix{Prefix: "fd00:1234::/64", OnLink: true, Autonomous: true, Delegated: false},
		nil, nil)
	if got := rawPrefixInfosForClassTest(t, cfg); len(got) != 1 {
		t.Fatalf("operator ULA: got %d want 1", len(got))
	}
}

func TestConfigEqualPinned12533(t *testing.T) {
	mk := func(pinned bool, pins []string) *config.RAInterfaceConfig {
		c := &config.RAInterfaceConfig{Interface: "trust0", Prefixes: []*config.RAPrefix{{Prefix: "fd00:1234::/64", Delegated: true, Pinned: pinned}}}
		c.PinnedPrefixes = pins
		return c
	}
	if configEqual(mk(true, []string{"fd00:1234::/48"}), mk(false, []string{"fd00:1234::/48"})) {
		t.Fatal("Pinned flip must not be equal")
	}
	if configEqual(mk(true, []string{"fd00:1234::/48"}), mk(true, []string{"fd00:9999::/48"})) {
		t.Fatal("pin set change must not be equal")
	}
	if !configEqual(mk(true, []string{"fd00:1234::/48"}), mk(true, []string{"fd00:1234::/48"})) {
		t.Fatal("identical pinned must be equal")
	}
}
