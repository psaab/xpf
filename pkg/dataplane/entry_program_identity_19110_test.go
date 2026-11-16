package dataplane

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// #19110: the userspace takeover readiness reads the loaded entry program's
// identity while holding its own mutex. That read must have NO side effect: on
// an obsolete registry, lookupProgramLocked counts the access and logs a WARN,
// and EntryProgramIdentity must do neither.
func TestEntryProgramIdentityHasNoSideEffect19110(t *testing.T) {
	m := regTestManager6741()
	if p := m.EntryProgramIdentity(); p != nil {
		t.Fatalf("fresh registry: %v, want nil", p)
	}
	prog := &ebpf.Program{}
	m.mu.Lock()
	m.registryGeneration = 1
	m.programs[m.xdpEntryProgramLocked()] = prog
	m.mu.Unlock()
	if p := m.EntryProgramIdentity(); p != prog {
		t.Fatalf("loaded registry: %v, want the entry program %v", p, prog)
	}

	m.mu.Lock()
	m.registryObsoleteFrom = m.registryGeneration // Teardown retained the registry
	m.mu.Unlock()
	logs := captureLogs(t)
	if p := m.EntryProgramIdentity(); p != nil {
		t.Errorf("an obsolete registry served %v as the loaded program", p)
	}
	if got := m.ObsoleteRegistryAccesses(); got != 0 {
		t.Errorf("the identity read counted %d obsolete access(es); it must have no side effect", got)
	}
	if strings.Contains(logs.String(), "superseded generation") {
		t.Error("the identity read logged the obsolete-registry WARN; it must have no side effect")
	}
	// Control: the side-effecting lookup on the SAME state does both.
	m.lookupProgramLocked(m.xdpEntryProgramLocked())
	if m.ObsoleteRegistryAccesses() != 1 || !strings.Contains(logs.String(), "superseded generation") {
		t.Error("fixture: lookupProgramLocked on the obsolete registry neither counted nor logged")
	}
}
