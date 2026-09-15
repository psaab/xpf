package snmp

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestServePerSourceBudget9917 is the F-139 RED cell, behavioral on the base
// surface (no new API): flood the Serve loop from one source and assert the
// per-source budget sheds the excess while a second source is still served.
// RED on base (no budget: every datagram answered).
func TestServePerSourceBudget9917(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	a.conn = srv
	done := make(chan struct{})
	go func() { a.Serve(); close(done) }()
	defer func() { a.Stop(); <-done }()

	srvAddr := srv.LocalAddr().(*net.UDPAddr)
	flood, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, srvAddr)
	if err != nil {
		t.Fatalf("flood dial: %v", err)
	}
	defer flood.Close()
	ctrl, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")}, srvAddr)
	if err != nil {
		t.Fatalf("control dial: %v", err)
	}
	defer ctrl.Close()

	pkt := buildV2cGetRequest("public", 1, oidSysContact)
	const sent = 400
	for i := 0; i < sent; i++ {
		if _, err := flood.Write(pkt); err != nil {
			t.Fatalf("flood write %d: %v", i, err)
		}
	}
	// Control source interleaves after the flood: it must be served regardless.
	const ctrlSent = 5
	for i := 0; i < ctrlSent; i++ {
		if _, err := ctrl.Write(pkt); err != nil {
			t.Fatalf("control write %d: %v", i, err)
		}
	}

	buf := make([]byte, 4096)
	ctrlGot := 0
	if err := ctrl.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("control deadline: %v", err)
	}
	for ctrlGot < ctrlSent {
		if _, _, err := ctrl.ReadFromUDP(buf); err != nil {
			t.Fatalf("control source got %d/%d responses: %v (second source must stay served under a first-source flood)", ctrlGot, ctrlSent, err)
		}
		ctrlGot++
	}

	// Drain the flood responses until a quiet window proves the shed remainder
	// is never coming (shed = no response, as with unknown-community drops).
	floodGot := 0
	for {
		if err := flood.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			t.Fatalf("flood deadline: %v", err)
		}
		if _, _, err := flood.ReadFromUDP(buf); err != nil {
			break // quiet window: server answered all it will
		}
		floodGot++
	}
	if floodGot >= sent {
		t.Fatalf("F-139: flood source served %d/%d (no per-source budget); want the excess shed", floodGot, sent)
	}
	t.Logf("flood source served %d/%d, control %d/%d", floodGot, sent, ctrlGot, ctrlSent)
}
