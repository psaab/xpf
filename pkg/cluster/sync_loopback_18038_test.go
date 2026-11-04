package cluster

import (
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// loopbackDialable18038 reports whether a loopback TCP connect completes in
// the current namespace. A bare net.Listen is NOT proof: the kernel accepts a
// 127.0.0.1 bind in a namespace whose lo is still down, so only a dialed
// connection separates "routable" from "bindable but unroutable" — the gap
// that let fixture listeners log green while every fixture dial failed
// ENETUNREACH under the #18038 testguard runner.
func loopbackDialable18038() bool {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer ln.Close()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// ensureLoopbackRoutable18038 makes 127.0.0.1 routable before a fixture dials
// a real loopback pair. #18038's testguard runner executes named tests in a
// private network namespace whose lo exists but is DOWN and unaddressed:
// 127.0.0.1 binds still succeed there, while every dial — a fixture's own
// net.Dial, or the production fabricConnectLoop dial behind
// TestConnectDialerIsTheNoiseInitiator7163 — fails ENETUNREACH, which for the
// 7163 cell parks ln.Accept until the test timeout because the dial loop
// retries silently forever. Bringing lo up installs 127.0.0.1/8 and its local
// routes, restoring exactly the transport these fixtures were built on. On a
// runner whose loopback is already routable this is a no-op that touches
// nothing. Shared by the pkg/cluster fixture cells (the pkg/daemon repairs of
// #18933/#18935 are package-private there and cannot be imported).
func ensureLoopbackRoutable18038(t *testing.T) {
	t.Helper()
	if loopbackDialable18038() {
		return
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("resolve lo to bring up loopback for the fixture (127.0.0.1 not dialable): %v", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatalf("bring up lo for the fixture (#18038 private namespace): %v", err)
	}
	if !loopbackDialable18038() {
		t.Fatal("127.0.0.1 still not dialable after LinkSetUp(lo): the fixture cannot connect")
	}
}
