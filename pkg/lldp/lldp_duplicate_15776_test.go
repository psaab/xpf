package lldp

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"
)

// #15776: duplicate / override-disabled interfaces must not fail open
// into duplicate LLDP sessions in Manager.Apply.

func TestDedupInterfaces15776(t *testing.T) {
	got := dedupInterfaces15776([]LLDPInterface{
		{Name: "ge-0/0/0"},
		{Name: "ge-0/0/0", Disable: true},
		{Name: "ge-0/0/1"},
		{Name: "ge-0-0-1", Disable: true}, // kernel spelling of ge-0/0/1
	})
	want := []LLDPInterface{{Name: "ge-0/0/0", Disable: true}, {Name: "ge-0/0/1", Disable: true}}
	if !slices.Equal(got, want) {
		t.Fatalf("dedup = %+v, want %+v", got, want)
	}
	// Enable-only duplicates collapse to one enabled entry.
	got = dedupInterfaces15776([]LLDPInterface{{Name: "fxp0"}, {Name: "fxp0"}})
	if len(got) != 1 || got[0].Disable {
		t.Fatalf("dedup enabled dup = %+v, want one enabled", got)
	}
}

func TestApplyDuplicateDisabledDoesNotStart15776(t *testing.T) {
	var looked []string
	SetInterfaceByNameForTesting(func(name string) (*net.Interface, error) {
		looked = append(looked, name)
		return &net.Interface{Name: name}, nil
	})
	t.Cleanup(func() { SetInterfaceByNameForTesting(nil) })
	FailIfSessionForTesting(errors.New("injected"))
	t.Cleanup(func() { FailIfSessionForTesting(nil) })

	m := New()
	t.Cleanup(m.Stop)
	// Enabled duplicate first, disabled second — pre-fix both reached
	// Apply and the enabled one started a session.
	unresolved := m.Apply(context.Background(), &LLDPConfig{Interfaces: []LLDPInterface{
		{Name: "ge-0/0/0"},
		{Name: "ge-0/0/0", Disable: true},
		{Name: "ge-0/0/1"},
		{Name: "ge-0/0/1"},
	}})
	if len(unresolved) != 0 {
		t.Fatalf("unresolved=%v, want nil", unresolved)
	}
	if slices.Contains(looked, "ge-0-0-0") {
		t.Errorf("override-disabled ge-0/0/0 was looked up (fail open): %v", looked)
	}
	// ge-0/0/1 looked up exactly once despite duplicate entries.
	n := 0
	for _, s := range looked {
		if s == "ge-0-0-1" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("ge-0-0-1 lookups=%d, want 1: %v", n, looked)
	}
}
