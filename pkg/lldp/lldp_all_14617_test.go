package lldp

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"
)

// #14617: `protocols lldp interface all` must expand to every managed
// interface (per-interface disable wins) via the interfaceByNameFn /
// list seam, instead of looking up a kernel device literally named "all".

func cfgFor14617(ifaces ...LLDPInterface) *LLDPConfig {
	return &LLDPConfig{Interfaces: ifaces}
}

func TestApplyExpandsAll14617(t *testing.T) {
	// Managed set: ge-0/0/0, ge-0/0/1, fxp0. Disable fxp0 explicitly.
	SetInterfacesForTesting(func() ([]net.Interface, error) {
		return []net.Interface{
			{Name: "ge-0-0-0"}, {Name: "ge-0-0-1"}, {Name: "fxp0"},
		}, nil
	})
	t.Cleanup(func() { SetInterfacesForTesting(nil) })

	// All kernel names resolve; socket setup fails so we observe via unresolved=nil
	// and via attempted lookups. Track lookups.
	var looked []string
	SetInterfaceByNameForTesting(func(name string) (*net.Interface, error) {
		looked = append(looked, name)
		for _, n := range []string{"ge-0-0-0", "ge-0-0-1", "fxp0"} {
			if name == n {
				return &net.Interface{Name: name}, nil
			}
		}
		return nil, errors.New("no such interface: " + name)
	})
	FailIfSessionForTesting(errors.New("injected"))
	t.Cleanup(func() { SetInterfaceByNameForTesting(nil); FailIfSessionForTesting(nil) })

	m := New()
	t.Cleanup(m.Stop)
	unresolved := m.Apply(context.Background(), cfgFor14617(
		LLDPInterface{Name: "all"},
		LLDPInterface{Name: "fxp0", Disable: true},
	))
	if len(unresolved) != 0 {
		t.Fatalf("unresolved=%v, want nil (all expanded, fxp0 disabled)", unresolved)
	}
	slices.Sort(looked)
	// fxp0 must NOT be looked up (disabled wins); ge-* must be.
	if slices.Contains(looked, "fxp0") {
		t.Errorf("disabled fxp0 was looked up: %v", looked)
	}
	if slices.Contains(looked, "all") {
		t.Errorf("literal 'all' was looked up as kernel device: %v", looked)
	}
	for _, want := range []string{"ge-0-0-0", "ge-0-0-1"} {
		if !slices.Contains(looked, want) {
			t.Errorf("managed %s not attempted, looked=%v", want, looked)
		}
	}
	// `all` is resolvable exactly when a managed interface exists.
	if !InterfaceResolvable("all") {
		t.Errorf("InterfaceResolvable(all) must be true when managed interfaces exist")
	}
	if !ExpandsAllInterfaces(cfgFor14617(LLDPInterface{Name: "all"})) {
		t.Errorf("ExpandsAllInterfaces must be true for enabled all")
	}
	if ExpandsAllInterfaces(cfgFor14617(LLDPInterface{Name: "all", Disable: true})) {
		t.Errorf("disabled all must not count as expansion")
	}
}

// Enumeration failure reports "all" as unresolved retry debt and keeps
// explicit entries; loopback is never expanded.
func TestApplyAllEnumerationFailure14617(t *testing.T) {
	SetInterfacesForTesting(func() ([]net.Interface, error) {
		return nil, errors.New("enumerate boom")
	})
	t.Cleanup(func() { SetInterfacesForTesting(nil) })
	SetInterfaceByNameForTesting(func(name string) (*net.Interface, error) {
		if name == "ge-0-0-0" {
			return &net.Interface{Name: name}, nil
		}
		return nil, errors.New("no such interface: " + name)
	})
	FailIfSessionForTesting(errors.New("injected"))
	t.Cleanup(func() { SetInterfaceByNameForTesting(nil); FailIfSessionForTesting(nil) })
	m := New()
	t.Cleanup(m.Stop)
	got := m.Apply(context.Background(), cfgFor14617(
		LLDPInterface{Name: "all"}, LLDPInterface{Name: "ge-0/0/0"}))
	if !slices.Equal(got, []string{"all"}) {
		t.Fatalf("unresolved=%v, want [all] on enumeration failure", got)
	}
	if InterfaceResolvable("all") {
		t.Fatalf("all must be unresolvable when enumeration fails/empty")
	}
}

// Loopback and explicit-duplicate handling: `lo` never starts, and an
// explicitly enabled interface covered by `all` is attempted once.
func TestApplyAllSkipsLoopbackAndDedups14617(t *testing.T) {
	SetInterfacesForTesting(func() ([]net.Interface, error) {
		return []net.Interface{
			{Name: "lo", Flags: net.FlagLoopback},
			{Name: "ge-0-0-0"},
		}, nil
	})
	t.Cleanup(func() { SetInterfacesForTesting(nil) })
	counts := map[string]int{}
	SetInterfaceByNameForTesting(func(name string) (*net.Interface, error) {
		counts[name]++
		return &net.Interface{Name: name}, nil
	})
	FailIfSessionForTesting(errors.New("injected"))
	t.Cleanup(func() { SetInterfaceByNameForTesting(nil); FailIfSessionForTesting(nil) })
	m := New()
	t.Cleanup(m.Stop)
	_ = m.Apply(context.Background(), cfgFor14617(
		LLDPInterface{Name: "all"}, LLDPInterface{Name: "ge-0/0/0"}))
	if counts["lo"] != 0 {
		t.Errorf("loopback must never be looked up, counts=%v", counts)
	}
	if counts["ge-0-0-0"] != 1 {
		t.Errorf("explicit+all duplicate must be attempted once, counts=%v", counts)
	}
	if got := ManagedInterfaceNames(); !slices.Equal(got, []string{"ge-0-0-0"}) {
		t.Errorf("ManagedInterfaceNames=%v, want [ge-0-0-0]", got)
	}
}
