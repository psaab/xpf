package routing

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	keepalive12083NetnsChild = "XPF_12083_NETNS_CHILD"
	keepalive12083VRF        = "vrf-ka12083"
	keepalive12083Source     = "198.51.100.1"
	keepalive12083Peer       = "198.51.100.2"
)

// TestKeepaliveVRFLocalSourceAvoidsStructuralUnknown12083 checks the
// runner classification seam: a VRF-local source must use the transport
// device and complete a probe, rather than becoming structural-unknown.
func TestKeepaliveVRFLocalSourceAvoidsStructuralUnknown12083(t *testing.T) {
	conn := &fakeProbeConn{replyFn: func(seq int, data []byte) [][]byte {
		return [][]byte{buildEchoReply(seq, data)}
	}}
	original := listenICMP
	var bindDevice string
	listenICMP = func(network, source, device string) (probeConn, error) {
		bindDevice = device
		return conn, nil
	}
	defer func() { listenICMP = original }()

	tm := &tunnelManager{ops: newKaOps()}
	state, gen := newKAState(true, 3, 1)
	state.SourceAddr = keepalive12083Source
	state.RemoteAddr = keepalive12083Peer
	state.transportInstance = "ka12083"
	tm.keepaliveTick("gr-12083", state, icmpProber{}, gen, 0)
	state.mu.Lock()
	unknown, kind, failures, lastSuccess := state.Unknown, state.UnknownKind, state.Failures, state.LastSuccess
	state.mu.Unlock()
	if unknown || kind == UnsupportedStructural || failures != 0 || lastSuccess.IsZero() {
		t.Fatalf("VRF-local source state unknown=%t kind=%v failures=%d lastSuccess=%v; want known Alive", unknown, kind, failures, lastSuccess)
	}
	if bindDevice != keepalive12083VRF {
		t.Fatalf("VRF bind device = %q, want %q", bindDevice, keepalive12083VRF)
	}
}

// TestKeepaliveScopedICMPSocketRoundTrip12083 exercises the custom
// SO_BINDTODEVICE socket path with a real loopback echo. The test seam maps
// the synthetic instance device to loopback; the VRF bind target itself is
// asserted by TestKeepaliveVRFLocalSourceAvoidsStructuralUnknown12083.
func TestKeepaliveScopedICMPSocketRoundTrip12083(t *testing.T) {
	original := listenICMP
	var bindDevice string
	listenICMP = func(network, source, device string) (probeConn, error) {
		bindDevice = device
		return listenBoundICMP(network, source, "lo")
	}
	defer func() { listenICMP = original }()

	result, kind, reason := (icmpProber{}).Probe("test-instance", "127.0.0.1", "127.0.0.1", 12083, []byte("ka12083!"), time.Second)
	if result != ProbeAlive || kind != UnsupportedNone {
		t.Fatalf("loopback probe over scoped socket = result %v, kind %v, reason %q; want Alive", result, kind, reason)
	}
	if bindDevice != "vrf-test-instance" {
		t.Fatalf("requested bind device = %q, want vrf-test-instance", bindDevice)
	}
}

// TestTunnelKeepaliveVRFHeldSourcePeerAlive12083 is the kernel half of
// #12083. The source and peer exist only on interfaces enslaved to the
// transport VRF; a global-context ICMP socket cannot bind the source.
func TestTunnelKeepaliveVRFHeldSourcePeerAlive12083(t *testing.T) {
	if os.Getenv(keepalive12083NetnsChild) == "1" {
		tunnelKeepaliveVRFNetnsChild12083(t)
		return
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare not available")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("iproute2 not available")
	}
	if out, err := exec.Command("unshare", "-rn", "true").CombinedOutput(); err != nil {
		if os.Getenv("XPF_REQUIRE_NETNS") == "" {
			t.Skipf("netns unavailable (%v): %s", err, out)
		}
		t.Fatalf("netns unavailable (XPF_REQUIRE_NETNS is set): %v\n%s", err, out)
	}

	cmd := exec.Command("unshare", "-rn", os.Args[0], "-test.run=^TestTunnelKeepaliveVRFHeldSourcePeerAlive12083$", "-test.v")
	cmd.Env = append(os.Environ(), keepalive12083NetnsChild+"=1")
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), "NETNS-CHILD-SKIPPED-12083") {
		if os.Getenv("XPF_REQUIRE_NETNS") != "" {
			t.Fatalf("ICMP datagram sockets unavailable with XPF_REQUIRE_NETNS set:\n%s", out)
		}
		t.Skipf("ICMP datagram socket capability unavailable in netns: %s", out)
	}
	if err != nil || !strings.Contains(string(out), "NETNS-CHILD-PASSED-12083") {
		t.Fatalf("VRF-held source/peer keepalive cell failed (%v):\n%s", err, out)
	}
}

func tunnelKeepaliveVRFNetnsChild12083(t *testing.T) {
	t.Helper()
	fmt.Println("NETNS-CHILD-STARTED-12083")
	probeConn, err := listenICMP("udp4", "0.0.0.0", "")
	if err != nil {
		fmt.Printf("NETNS-CHILD-SKIPPED-12083: ICMP datagram socket setup: %v\n", err)
		t.Skipf("ICMP datagram socket setup unavailable: %v", err)
	}
	_ = probeConn.Close()
	for _, args := range [][]string{
		{"link", "add", keepalive12083VRF, "type", "vrf", "table", "212083"},
		{"link", "set", keepalive12083VRF, "up"},
		{"link", "add", "ka12083a", "type", "veth", "peer", "name", "ka12083b"},
		{"link", "set", "ka12083a", "master", keepalive12083VRF},
		{"link", "set", "ka12083b", "master", keepalive12083VRF},
		{"addr", "add", keepalive12083Source + "/24", "dev", "ka12083a"},
		{"addr", "add", keepalive12083Peer + "/24", "dev", "ka12083b"},
		{"link", "set", "ka12083a", "up"},
		{"link", "set", "ka12083b", "up"},
	} {
		out, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %s failed (%v): %s", strings.Join(args, " "), err, out)
		}
	}

	result, kind, reason := (icmpProber{}).Probe("ka12083", keepalive12083Source, keepalive12083Peer, 1, []byte("ka12083!"), time.Second)
	if result != ProbeAlive || kind != UnsupportedNone {
		t.Fatalf("VRF-held source/peer probe = result %v, kind %v, reason %q; want Alive (the source is local in %s)", result, kind, reason, keepalive12083VRF)
	}
	fmt.Println("NETNS-CHILD-PASSED-12083")
}
