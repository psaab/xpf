package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14378 (DR4-H6) agreement pin, userspace half: every next-hop the
// userspace snapshot installs for a strict-compiled '@' static route
// must be the canonical `ip@interface` / `@interface` string, which —
// after the compiler split — is re-synthesised from the structured
// Address+Interface entry. This is the same string the FRR half
// (pkg/frr TestStaticNextHopAtInterfaceRendersFRR_14378) renders as
// `ip route <dst> <ip> <iface>`, so both FIBs carry the route.
//
// Note: pre-fix this snapshot half alone passes (the raw scalar was
// already the '@' string) — the disagreement is pinned jointly with
// the config-compiler and FRR tests, which are RED pre-fix.
func TestStaticNextHopAtInterfaceUserspaceSnapshot_14378(t *testing.T) {
	tree, perrs := config.NewParser(`
routing-options {
    static {
        route 192.0.2.0/24 { next-hop "10.0.0.1@eth0"; }
        route 198.51.100.0/24 { next-hop "@eth0"; }
    }
}`).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	snaps, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	want := map[string]string{
		"192.0.2.0/24":    "10.0.0.1@eth0",
		"198.51.100.0/24": "@eth0",
	}
	for dest, nh := range want {
		found := false
		for _, s := range snaps {
			if s.Destination == dest && len(s.NextHops) == 1 && s.NextHops[0] == nh {
				found = true
			}
			for _, h := range s.NextHops {
				if strings.Contains(h, "@") && h != nh && s.Destination == dest {
					t.Errorf("snapshot %s next-hop = %q, want %q", dest, h, nh)
				}
			}
		}
		if !found {
			t.Errorf("userspace snapshot missing %s -> %s; got %+v", dest, nh, snaps)
		}
	}
}
