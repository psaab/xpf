package frr

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestNoInstallStaticRouteIsNotRendered11328(t *testing.T) {
	m := New()
	noInstall := &config.StaticRoute{
		Destination: "10.99.0.0/16",
		NoInstall:   true,
		NextHops: []config.NextHopEntry{
			{Address: "10.0.0.1"},
			{Address: "10.0.0.2"},
		},
	}
	if got := m.generateStaticRoute(noInstall, "", nil, nil, nil); got != "" {
		t.Fatalf("FRR rendered a no-install route: %q", got)
	}
	if staticRouteRendersFIB(noInstall) {
		t.Fatal("no-install route counted as an installed FIB route")
	}

	control := *noInstall
	control.NoInstall = false
	if got, want := m.generateStaticRoute(&control, "", nil, nil, nil),
		"ip route 10.99.0.0/16 10.0.0.1\nip route 10.99.0.0/16 10.0.0.2\n"; got != want {
		t.Fatalf("ordinary ECMP control render = %q, want %q", got, want)
	}
}
