package config

import (
	"reflect"
	"testing"
)

// #8939 at `forwarding-options dhcp-relay group <g> overrides`: a packed run set
// only its FIRST override.
//
//	overrides always-broadcast forward-only maximum-hop-count 4
//	  packed  bcast=true fwdonly=FALSE hops=0
//	  split   bcast=true fwdonly=true  hops=4
//
// `forward-only` is the one worth naming: without it the relay also floods the
// request onto the broadcast domain, which is the behaviour an operator sets
// forward-only to STOP. The packed spelling gave them the broadcast without the
// restriction — more traffic than they asked for, silently.
func TestDHCPRelayOverridesPackedRun8939(t *testing.T) {
	build := func(t *testing.T, lines ...string) *DHCPRelayGroup {
		t.Helper()
		tr := &ConfigTree{}
		lines = append([]string{
			"set forwarding-options dhcp-relay server-group sg 192.0.2.1",
			"set forwarding-options dhcp-relay group G active-server-group sg",
		}, lines...)
		for _, l := range lines {
			p, err := ParseSetCommand(l)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", l, err)
			}
			if err := tr.SetPath(p); err != nil {
				t.Fatalf("SetPath: %v", err)
			}
		}
		c, err := CompileConfig(tr)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if c.ForwardingOptions.DHCPRelay == nil || len(c.ForwardingOptions.DHCPRelay.Groups) == 0 {
			t.Fatal("no dhcp-relay group compiled")
		}
		for _, g := range c.ForwardingOptions.DHCPRelay.Groups {
			return g
		}
		return nil
	}

	split := build(t,
		"set forwarding-options dhcp-relay group G overrides always-broadcast",
		"set forwarding-options dhcp-relay group G overrides forward-only",
		"set forwarding-options dhcp-relay group G overrides maximum-hop-count 4")
	// REFERENCE ARM.
	if !split.AlwaysBroadcast || !split.ForwardOnly || split.MaximumHopCount != 4 {
		t.Fatalf("the SPLIT control set bcast=%v fwdonly=%v hops=%d — the comparison would "+
			"prove nothing", split.AlwaysBroadcast, split.ForwardOnly, split.MaximumHopCount)
	}

	packed := build(t,
		"set forwarding-options dhcp-relay group G overrides always-broadcast forward-only maximum-hop-count 4")
	if !reflect.DeepEqual(packed, split) {
		t.Errorf("packed bcast=%v fwdonly=%v hops=%d, split bcast=%v fwdonly=%v hops=%d",
			packed.AlwaysBroadcast, packed.ForwardOnly, packed.MaximumHopCount,
			split.AlwaysBroadcast, split.ForwardOnly, split.MaximumHopCount)
	}

	// NARROWNESS. `always-broadcast` alone must not also set forward-only — a
	// fix that set every override whenever the container appeared would satisfy
	// the comparison and silently RESTRICT relaying the operator left open,
	// which is the opposite failure and just as wrong.
	only := build(t, "set forwarding-options dhcp-relay group G overrides always-broadcast")
	if !only.AlwaysBroadcast {
		t.Error("the single-override spelling lost its own override")
	}
	if only.ForwardOnly || only.MaximumHopCount != 0 {
		t.Errorf("`always-broadcast` alone also set fwdonly=%v hops=%d",
			only.ForwardOnly, only.MaximumHopCount)
	}
}
