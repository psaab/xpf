package authz

import (
	"net"

	"github.com/psaab/xpf/pkg/osident"
)

// passwd.go contains test seams for the UID resolver used by authz.
//
// Account-name resolution lives in pkg/osident, the single source of truth
// shared with the CLI. See osident.lookupPasswd and
// TestRESTAndCLIAgreeOnAnAmbiguousUID_6645 for the duplicate-UID invariant.

// SetPasswdPathForTest points the shared UID resolver at path and restores the
// previous value through the returned function. Test-only; it lets authz
// package tests exercise principal construction against a fixture without
// depending on the accounts present on the machine running the suite.
//
// This forwards to osident's test seam, keeping all consumers on the same
// passwd fixture and resolver.
func SetPasswdPathForTest(path string) (restore func()) {
	return osident.SetPasswdPathForTest(path)
}

// SetProcNetTCPPathsForTest points the socket-table parser at fixtures and
// restores the previous values through the returned function. Test-only; it
// lets the parser be exercised against known kernel output (including the
// TIME_WAIT/UID-0 row the ESTABLISHED requirement exists to reject, and the
// v4-mapped-in-tcp6 row) without needing to provoke those states on a live
// socket.
func SetProcNetTCPPathsForTest(v4, v6 string) (restore func()) {
	prev4, prev6 := procNetTCPPath, procNetTCP6Path
	procNetTCPPath, procNetTCP6Path = v4, v6
	return func() { procNetTCPPath, procNetTCP6Path = prev4, prev6 }
}

// setLocalAddrsForTest fixes the host address list LookupPeer consults when it
// finds no socket, so the "is this caller on our own box" decision is
// deterministic instead of depending on the machine's interfaces. Test-only,
// unexported: only pkg/authz's own tests need it.
func setLocalAddrsForTest(addrs []net.Addr) (restore func()) {
	prev := localAddrsFn
	localAddrsFn = func() ([]net.Addr, error) { return addrs, nil }
	resetLocalAddrCacheForTest()
	return func() { localAddrsFn = prev; resetLocalAddrCacheForTest() }
}
