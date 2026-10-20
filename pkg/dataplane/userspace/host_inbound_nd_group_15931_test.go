package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15931 (F2): the view grouping key must include the effective except
// set. A zone enumerating every `all`-expansion protocol except ndp
// (positives identical to the expansion-minus-ndp, no except stanza)
// and an interface override authoring `protocols all` + `ndp except`
// have IDENTICAL positive token sets; only the interface withdraws the
// ND default. They must land in distinct views, the interface's view
// carrying the exclusion, or the kernel helper sees no exclusion and
// the unscoped ND accept re-admits ND on the excluded interface.
func TestHostInboundGroupingKeepsNDPExceptDistinct15931(t *testing.T) {
	cfg := compileNDGroup15931(t)
	views := BuildZoneHostInboundViews(cfg)
	var defaultView, exceptView *ZoneHostInboundView
	for i := range views {
		v := &views[i]
		if v.Zone != "trust" {
			continue
		}
		if ndpExcluded(v.ProtocolsExcept) {
			exceptView = v
		} else if len(v.V6Addrs) > 0 || len(v.V4Addrs) > 0 {
			defaultView = v
		}
	}
	if exceptView == nil {
		t.Fatalf("no view carries the interface ndp except; views=%+v", views)
	}
	if defaultView == nil {
		t.Fatalf("no default (non-except) view survived; views=%+v", views)
	}
	if exceptView == defaultView {
		t.Fatal("except and default collapsed into one view")
	}
	// The except view must own the overridden interface's address only.
	found := false
	for _, a := range append(append([]string{}, exceptView.V4Addrs...), exceptView.V6Addrs...) {
		if a == "10.0.1.1" {
			found = true
		}
		if a == "10.0.0.1" {
			t.Fatalf("except view swallowed the zone-default address: %+v", exceptView)
		}
	}
	if !found {
		t.Fatalf("except view does not own ge-0/0/1.0's address: %+v", exceptView)
	}
}

func compileNDGroup15931(t *testing.T) *config.Config {
	t.Helper()
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet6 address 2001:db8:1::1/64",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
	}
	// Zone: every all-expansion protocol except ndp, explicitly.
	for _, tok := range config.HostInboundAllExpansionProtocols() {
		if tok == "ndp" {
			continue
		}
		lines = append(lines, "set security zones security-zone trust host-inbound-traffic protocols "+tok)
	}
	// Interface ge-0/0/1.0: protocols all + ndp except (same positives).
	lines = append(lines,
		"set security zones security-zone trust interfaces ge-0/0/1.0 host-inbound-traffic protocols all",
		"set security zones security-zone trust interfaces ge-0/0/1.0 host-inbound-traffic protocols ndp except",
	)
	tree := &config.ConfigTree{}
	for _, l := range lines {
		pp, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(pp); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}
