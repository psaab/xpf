package config

import (
	"reflect"
	"testing"
)

// #8939 at `protocols bgp multipath`: a packed run set only its FIRST option.
//
//	set protocols bgp multipath ibgp multiple-as
//	  -> MultipathIBGP=true  MultipathMultipleAS=FALSE
//
// SetPath nests the second option onto the first's Keys rather than making them
// siblings — `[multipath] > [ibgp multiple-as]` — and the compile loop read
// `mc.Name()` and dropped the rest.
//
// The consequence is a routing one: `multiple-as` is what lets eBGP multipath
// span differing AS paths, and losing it silently narrows the path set the
// operator asked for. FRR renders from these two booleans.
func TestBGPMultipathPackedRunKeepsBothOptions8939(t *testing.T) {
	build := func(t *testing.T, lines ...string) *Config {
		t.Helper()
		lines = append([]string{"set protocols bgp local-as 65001"}, lines...)
		tr := &ConfigTree{}
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
		return c
	}

	packed := build(t, "set protocols bgp multipath ibgp multiple-as")
	split := build(t,
		"set protocols bgp multipath ibgp",
		"set protocols bgp multipath multiple-as")

	// REFERENCE ARM FIRST. If the split spelling did not set both, the
	// comparison below would be between two equally broken results — the
	// levelling-down shape.
	if b := split.Protocols.BGP; b == nil || !b.MultipathIBGP || !b.MultipathMultipleAS {
		t.Fatalf("the SPLIT control did not set both options (%+v) — the comparison would "+
			"prove nothing", b)
	}
	if !reflect.DeepEqual(packed, split) {
		pb, sb := packed.Protocols.BGP, split.Protocols.BGP
		t.Errorf("the packed spelling does not match the split one:\n"+
			"  packed ibgp=%v multipleAS=%v\n  split  ibgp=%v multipleAS=%v",
			pb.MultipathIBGP, pb.MultipathMultipleAS, sb.MultipathIBGP, sb.MultipathMultipleAS)
	}

	// NARROWNESS. Each option alone must still set only itself — a fix that
	// simply set both booleans whenever `multipath` appeared would satisfy
	// everything above and enable multipath the operator did not ask for.
	for _, tc := range []struct {
		opt                string
		wantIBGP, wantMult bool
	}{
		{"ibgp", true, false},
		{"multiple-as", false, true},
	} {
		t.Run("only "+tc.opt, func(t *testing.T) {
			b := build(t, "set protocols bgp multipath "+tc.opt).Protocols.BGP
			if b.MultipathIBGP != tc.wantIBGP || b.MultipathMultipleAS != tc.wantMult {
				t.Errorf("`multipath %s` gave ibgp=%v multipleAS=%v, want %v/%v",
					tc.opt, b.MultipathIBGP, b.MultipathMultipleAS, tc.wantIBGP, tc.wantMult)
			}
		})
	}
}
