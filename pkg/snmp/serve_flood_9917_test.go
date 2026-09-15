package snmp

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestServePerSourceBudget9917 is the F-139 enforcement cell: flood the Serve
// loop from one source and assert the per-source budget sheds the excess while
// a second source is still served. The oracle is the shed call-site counter
// under a frozen budget clock -- exact, with no timing dependence -- not the
// count of arrived UDP datagrams (buffer loss or a quiet-window timeout must
// neither false-pass an unbudgeted agent nor false-fail a correct one). RED on
// base (no budget: shed stays 0).
func TestServePerSourceBudget9917(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})
	frozen := time.Unix(1_700_000_000, 0)
	a.serveBudget.now = func() time.Time { return frozen }

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

	// The control source's own bucket is full: all five must arrive, proving a
	// second source stays served under a first-source flood and the loop is
	// alive to observe the shed below.
	buf := make([]byte, 4096)
	if err := ctrl.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("control deadline: %v", err)
	}
	for i := 0; i < ctrlSent; i++ {
		if _, _, err := ctrl.ReadFromUDP(buf); err != nil {
			t.Fatalf("control source got %d/%d responses: %v", i, ctrlSent, err)
		}
	}
	// Drain the flood responses until a quiet window (best-effort drain only;
	// the shed counter below is the oracle, not this count).
	floodGot := 0
	for {
		if err := flood.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			t.Fatalf("flood deadline: %v", err)
		}
		if _, _, err := flood.ReadFromUDP(buf); err != nil {
			break
		}
		floodGot++
	}
	// Frozen clock: no refill, no service charge (elapsed 0), global burst far
	// above 405 -- so exactly burst-many flood requests admit and the rest shed.
	const wantShed = sent - snmpServeBurstPerSource
	deadline := time.Now().Add(5 * time.Second)
	for a.serveBudget.shed.Load() != wantShed && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := a.serveBudget.shed.Load(); got != wantShed {
		t.Fatalf("F-139: shed = %d, want exactly %d (burst %d of %d flood admitted, rest shed)",
			got, wantShed, snmpServeBurstPerSource, sent)
	}
	if floodGot < 1 {
		t.Fatalf("flood source got %d responses, want >= 1 (loop must serve it too)", floodGot)
	}
	t.Logf("shed %d/%d flood, control %d/%d, flood responses drained %d",
		wantShed, sent, ctrlSent, ctrlSent, floodGot)
}
