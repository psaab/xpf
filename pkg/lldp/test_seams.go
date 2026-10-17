package lldp

import "net"

// Test-only helpers for pkg/lldp. They live in the production package so tests
// in DEPENDENT packages (pkg/daemon) can drive Apply's failure modes without
// real NICs or CAP_NET_RAW. That matters for #6794 specifically: the recovery
// guard spans both packages, and a test that could only reach these seams from
// inside pkg/lldp would bind Apply's RETURN VALUE while leaving the caller free
// to ignore it — which was the whole defect. Not for production callers.
// Mirrors the pkg/configstore/test_seams.go convention.

// SetInterfaceByNameForTesting overrides the kernel interface lookup used by
// Manager.Apply AND by InterfaceResolvable — deliberately the same seam, so a
// test cannot make those two disagree in a way production never could. Pass nil
// to restore net.InterfaceByName.
func SetInterfaceByNameForTesting(fn func(string) (*net.Interface, error)) {
	if fn == nil {
		interfaceByNameFn = net.InterfaceByName
		return
	}
	interfaceByNameFn = fn
}

// FailIfSessionForTesting makes every per-interface socket setup fail with err,
// so Apply can be exercised without CAP_NET_RAW: name resolution still runs
// (which is what #6794's unresolved set reports), and no real socket is opened
// or goroutine started. Pass nil to restore the real newIfSession.
func FailIfSessionForTesting(err error) {
	if err == nil {
		newIfSessionFn = newIfSession
		return
	}
	newIfSessionFn = func(*net.Interface) (*ifSession, error) { return nil, err }
}

// SetInterfacesForTesting overrides the kernel interface enumeration
// used by the `all` expansion (#14617) and by ManagedInterfaceNames /
// AllInterfacesResolvable. Pass nil to restore net.Interfaces.
func SetInterfacesForTesting(fn func() ([]net.Interface, error)) {
	if fn == nil {
		interfacesFn = net.Interfaces
		return
	}
	interfacesFn = fn
}
