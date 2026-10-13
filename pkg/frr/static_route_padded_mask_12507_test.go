package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12507: the netip-based render belt (validFRRRoutePrefix) refuses every
// zero-padded mask, so a "10.0.0.0/08" static route used to reach the userspace
// FIB but never FRR or the kernel. The compiler now writes helper-supported
// padding canonically, so FRR renders the same prefix the FIB installs. A
// helper-refused spelling ("/008") stays out of frr.conf, as before; strict
// commit rejects it and the userspace helper refuses its snapshot.
func TestStaticRoutePaddedMaskRendersCanonical12507(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set routing-options static route 10.0.0.0/08 discard",
		"set routing-options rib inet6.0 static route 2001:db8::/032 discard",
		"set routing-options static route 11.0.0.0/008 discard",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	var rendered strings.Builder
	for _, routes := range [][]*config.StaticRoute{cfg.RoutingOptions.StaticRoutes, cfg.RoutingOptions.Inet6StaticRoutes} {
		for _, sr := range routes {
			rendered.WriteString(New().generateStaticRoute(sr, "", nil, nil, nil))
		}
	}
	got := rendered.String()
	for _, want := range []string{"ip route 10.0.0.0/8 Null0", "ipv6 route 2001:db8::/32 Null0"} {
		if !strings.Contains(got, want) {
			t.Fatalf("FRR render missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "11.0.0.0") {
		t.Fatalf("helper-refused spelling reached frr.conf:\n%s", got)
	}
}
