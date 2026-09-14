package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9820 GPT-P2: padded static operands render nothing (the pre-existing
// netip shape belt drops them). The strict schema gate refuses them, so
// these cells pin the tolerant-render half: a leniently loaded padded
// value is omitted, never emitted raw.

// Direct cells: padding fails the shape belt.
func TestStaticPaddingRendersNothing_9820(t *testing.T) {
	m := &Manager{}
	paddedDst := &config.StaticRoute{
		Destination: " 2001:db8::/32 ",
		Preference:  5,
		NextHops:    []config.NextHopEntry{{Address: "2001:db8::1"}},
	}
	if got := m.generateStaticRoute(paddedDst, "", nil, nil); strings.TrimSpace(got) != "" {
		t.Fatalf("padded destination must render nothing, got:\n%s", got)
	}
	paddedNH := &config.StaticRoute{
		Destination: "2001:db8::/32",
		Preference:  5,
		NextHops: []config.NextHopEntry{
			{Address: " 2001:db8::1 "},
			{Address: "2001:db8::2"},
		},
	}
	got := m.generateStaticRoute(paddedNH, "", nil, nil)
	if strings.Contains(got, " 2001:db8::1 ") {
		t.Fatalf("padded next-hop reached frr.conf:\n%s", got)
	}
	if !strings.Contains(got, "ipv6 route 2001:db8::/32 2001:db8::2 5\n") {
		t.Fatalf("good ECMP member missing:\n%s", got)
	}
}

// Lenient-compile→render integration: quoted padding survives the
// tolerant compile raw and is omitted at render.
func TestStaticPaddingLenientIntegration_9820(t *testing.T) {
	tree, perrs := config.NewParser(`
routing-options {
    static {
        route " 2001:db8::/32 " {
            next-hop 2001:db8::1;
        }
        route 2001:db8:1::/48 {
            next-hop " 2001:db8::9 ";
            next-hop 2001:db8::2;
        }
    }
}`).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must NOT fail: %v", err)
	}
	m := &Manager{}
	var b strings.Builder
	for _, sr := range cfg.RoutingOptions.StaticRoutes {
		b.WriteString(m.generateStaticRoute(sr, "", nil, nil))
	}
	got := b.String()
	if strings.Contains(got, "2001:db8::9") {
		t.Fatalf("padded next-hop reached frr.conf:\n%s", got)
	}
	if strings.Contains(got, "2001:db8::/32") {
		t.Fatalf("padded destination reached frr.conf:\n%s", got)
	}
	if !strings.Contains(got, "ipv6 route 2001:db8:1::/48 2001:db8::2 5\n") {
		t.Fatalf("good member missing:\n%s", got)
	}
}
