package snmp

import (
	"net"
	"sync"
	"testing"
	"time"
)

// TestNormalizeTrapDialAddr13127 pins target normalization: bracketed IPv6
// without a port must not be double-bracketed, and a trailing empty port must
// receive the :162 default rather than being treated as UDP port 0.
func TestNormalizeTrapDialAddr13127(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"127.0.0.1", "127.0.0.1:162"},
		{"127.0.0.1:162", "127.0.0.1:162"},
		{"127.0.0.1:", "127.0.0.1:162"},
		{"::1", "[::1]:162"},
		{"[::1]", "[::1]:162"},
		{"[::1]:162", "[::1]:162"},
		{"[2001:db8::1]", "[2001:db8::1]:162"},
		{"[::ffff:127.0.0.1]", "[::ffff:127.0.0.1]:162"},
	} {
		if got := normalizeTrapDialAddr(tc.in); got != tc.want {
			t.Errorf("normalizeTrapDialAddr(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestSendTrapOnVRFBracketedIPv6Delivers13127 pins #13127 D10-10: a
// bracketed IPv6 target without a port must deliver to the same receiver as
// the valid unbracketed spelling. Before the fix the first Dial fails with
// "missing port in address" because JoinHostPort double-brackets the host.
func TestSendTrapOnVRFBracketedIPv6Delivers13127(t *testing.T) {
	receiver, err := net.ListenPacket("udp6", "[::1]:162")
	if err != nil {
		t.Skipf("cannot bind [::1]:162: %v", err)
	}
	defer receiver.Close()

	for _, target := range []string{"[::1]", "::1"} {
		pkt := []byte("trap-" + target)
		if err := sendTrapOnVRF(target, pkt, ""); err != nil {
			t.Fatalf("sendTrapOnVRF(%q): %v", target, err)
		}
		_ = receiver.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64)
		n, _, err := receiver.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read trap from %q: %v", target, err)
		}
		if got := string(buf[:n]); got != string(pkt) {
			t.Fatalf("trap from %q = %q, want %q", target, got, pkt)
		}
	}
}

// TestAgentAddrForBracketedIPv4MappedTarget13127 pins the v1 agent-addr
// lookup alongside a valid unbracketed control. Both spellings must resolve
// to the same local IPv4 source, not 0.0.0.0 (#13127 D10-10).
func TestAgentAddrForBracketedIPv4MappedTarget13127(t *testing.T) {
	want := agentAddrForTargetOnVRF("::ffff:127.0.0.1", "")
	if want == ([4]byte{}) {
		t.Fatal("control target ::ffff:127.0.0.1 resolved to 0.0.0.0; environment cannot route loopback via udp4")
	}
	if got := agentAddrForTargetOnVRF("[::ffff:127.0.0.1]", ""); got != want {
		t.Fatalf("agentAddrForTargetOnVRF([::ffff:127.0.0.1]) = %v, want %v", got, want)
	}
}

// TestSetVRFDeviceConcurrentAccess13127 drives the #13127 race arm: setter
// updates must synchronize with asynchronous trap and v1-address readers.
func TestSetVRFDeviceConcurrentAccess13127(t *testing.T) {
	a := &Agent{}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 200 {
				a.SetVRFDevice("lo")
				a.SetVRFDevice("")
			}
		}()
		go func() {
			defer wg.Done()
			for range 200 {
				_ = a.sendTrapViaVRF("127.0.0.1", []byte{1})
				_ = a.buildLinkTrapV1("public", "127.0.0.1", true, 5, "ge-0-0-0")
			}
		}()
	}
	wg.Wait()
}
