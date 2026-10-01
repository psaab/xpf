package config

import (
	"reflect"
	"testing"
)

func build8939i(t *testing.T, lines ...string) *Config {
	t.Helper()
	tr := &ConfigTree{}
	for _, l := range lines {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tr.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	c, err := CompileConfig(tr)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return c
}

// #8939 at `security nat source pool <name>`: a packed run set only the first
// option, dropping the pool's ROUTING-INSTANCE — which is what binds the
// translated address to a VRF. A pool bound to the wrong table translates into
// the wrong tenant's routing domain, and that is a cross-tenant outcome from a
// spelling.
func TestNATSourcePoolPackedRun8939(t *testing.T) {
	const addr = "set security nat source pool PL address 10.0.0.1/32"
	split := build8939i(t, addr,
		"set security nat source pool PL port-overloading-factor 4",
		"set security nat source pool PL routing-instance RI")
	get := func(c *Config) *NATPool {
		for _, p := range c.Security.NAT.SourcePools {
			return p
		}
		return nil
	}
	s := get(split)
	if s == nil || s.RoutingInstance == "" {
		t.Fatalf("the SPLIT control did not set the routing-instance: %+v", s)
	}
	packed := build8939i(t, addr,
		"set security nat source pool PL port-overloading-factor 4 routing-instance RI")
	if !reflect.DeepEqual(packed, split) {
		t.Errorf("packed %+v\nsplit  %+v", get(packed), s)
	}

	// NARROWNESS: the factor alone must not bind a routing-instance. Inventing
	// a VRF binding is the same cross-tenant failure pointed the other way.
	only := get(build8939i(t, addr, "set security nat source pool PL port-overloading-factor 4"))
	if only.RoutingInstance != "" {
		t.Errorf("`port-overloading-factor` alone bound routing-instance %q", only.RoutingInstance)
	}
}

// #8939 at `forwarding-options sampling instance <i> family inet|inet6 output`:
// a packed run dropped the export SOURCE-ADDRESS.
//
// Flow records then leave with whatever source the stack picks — and the
// collector keys the exporting device's identity on that source, so records
// arrive attributed to the wrong device, or to none.
func TestSamplingOutputPackedRun8939(t *testing.T) {
	for _, fam := range []string{"inet", "inet6"} {
		t.Run(fam, func(t *testing.T) {
			base := "set forwarding-options sampling instance I family " + fam + " output "
			source := "10.0.0.1"
			if fam == "inet6" {
				source = "2001:db8::1"
			}
			split := build8939i(t, base+"inline-jflow", base+"source-address "+source)
			packed := build8939i(t, base+"inline-jflow source-address "+source)
			if !reflect.DeepEqual(packed, split) {
				t.Errorf("packed and split differ for family %s", fam)
			}
			// The reference arm: the split spelling must actually record a
			// source-address, or the equality above is between two empties.
			s := split.ForwardingOptions.Sampling
			if s == nil || len(s.Instances) == 0 {
				t.Fatalf("the SPLIT control compiled no sampling instance")
			}
			inst := s.Instances["I"]
			if inst == nil {
				t.Fatal("the SPLIT control omitted sampling instance I")
			}
			compiledFamily := inst.FamilyInet
			if fam == "inet6" {
				compiledFamily = inst.FamilyInet6
			}
			if compiledFamily == nil {
				t.Fatalf("the SPLIT control omitted family %s", fam)
			}
			if compiledFamily.SourceAddress != source {
				t.Errorf("split source-address = %q, want %q", compiledFamily.SourceAddress, source)
			}
			if compiledFamily.InlineJflowSourceAddress != source {
				t.Errorf("split inline-jflow source-address = %q, want %q",
					compiledFamily.InlineJflowSourceAddress, source)
			}
		})
	}
}
