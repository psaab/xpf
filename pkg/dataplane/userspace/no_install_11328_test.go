package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestNoInstallStaticRouteIsAbsentFromHelperFIB11328(t *testing.T) {
	stubRuleListHermetic(t)
	tree := &config.ConfigTree{}
	for _, command := range []string{
		"set routing-options static route 10.99.0.0/16 next-hop [ 10.0.0.1 10.0.0.2 ] no-install",
		"set routing-options static route 10.100.0.0/16 next-hop 10.0.0.3",
	} {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.Warnings) != 0 {
		t.Fatalf("compile warnings = %v, want none", cfg.Warnings)
	}
	noInstall := cfg.RoutingOptions.StaticRoutes[0]
	if !noInstall.NoInstall || len(noInstall.NextHops) != 2 ||
		noInstall.NextHops[0].Address != "10.0.0.1" || noInstall.NextHops[1].Address != "10.0.0.2" {
		t.Fatalf("compiled no-install route = %+v, want exactly the two authored gateways and NoInstall=true", noInstall)
	}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	var foundControl bool
	for _, route := range routes {
		switch route.Destination {
		case "10.99.0.0/16":
			t.Fatalf("no-install route reached the helper FIB: %+v", route)
		case "10.100.0.0/16":
			if len(route.NextHops) != 1 || route.NextHops[0] != "10.0.0.3" {
				t.Fatalf("ordinary control route = %+v, want its configured next-hop", route)
			}
			foundControl = true
		}
	}
	if !foundControl {
		t.Fatal("ordinary control route was not published to the helper FIB")
	}
}
