package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dhcp"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/logging"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// lockedPacketDropStream15227 serializes Send (the handler sends from a
// worker goroutine) against the test's polling reads.
type lockedPacketDropStream15227 struct {
	mu   sync.Mutex
	ctx  context.Context
	sent []string
}

func (m *lockedPacketDropStream15227) Send(r *pb.MonitorPacketDropResponse) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, r.Line)
	return nil
}
func (m *lockedPacketDropStream15227) lines() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.sent...)
}
func (m *lockedPacketDropStream15227) Context() context.Context { return m.ctx }
func (m *lockedPacketDropStream15227) SetHeader(metadata.MD) error {
	return nil
}
func (m *lockedPacketDropStream15227) SendHeader(metadata.MD) error { return nil }
func (m *lockedPacketDropStream15227) SetTrailer(metadata.MD)       {}
func (m *lockedPacketDropStream15227) SendMsg(any) error            { return nil }
func (m *lockedPacketDropStream15227) RecvMsg(any) error            { return nil }

func TestDHCPRenewResolvesOperatorSpellings15227(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet { dhcp; }
        }
    }
    ge-0/0/3 {
        vlan-tagging;
        unit 7 {
            vlan-id 50;
            family inet6 { dhcpv6; }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("no active config")
	}
	// Premise: the compiled units carry the DHCP flags + vlan-id the
	// resolver reads, so a failure below measures resolution, not fixture drift.
	ifc3 := cfg.Interfaces.Interfaces["ge-0/0/3"]
	if ifc3 == nil || ifc3.Units[7] == nil || !ifc3.Units[7].DHCPv6 || ifc3.Units[7].VlanID != 50 {
		t.Fatalf("fixture premise broken: ge-0/0/3 = %+v", ifc3)
	}

	mgr := dhcp.NewManagerForTesting(func(ctx context.Context, iface string, af dhcp.AddressFamily) {
		<-ctx.Done()
	})
	// Clients keyed exactly as buildDHCPClientSpecs keys them.
	mgr.Reconcile([]dhcp.ClientSpec{
		{Iface: "ge-0-0-0", Family: dhcp.AFInet},
		{Iface: "ge-0-0-3.50", Family: dhcp.AFInet6},
	})
	deadline := time.Now().Add(5 * time.Second)
	for len(mgr.RunningClientHandlesForTesting()) != 2 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if len(mgr.RunningClientHandlesForTesting()) != 2 {
		t.Fatalf("premise: running clients = %v, want 2 keyed clients", mgr.RunningClientHandlesForTesting())
	}
	defer mgr.StopAll()

	s := &Server{store: store, dhcp: mgr}
	for _, target := range []string{"ge-0/0/0", "ge-0/0/3.7"} {
		resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "dhcp-renew", Target: target})
		if err != nil {
			t.Errorf("dhcp-renew %q: %v (pre-fix this is the false 'no DHCP client running' refusal)", target, err)
			continue
		}
		if !strings.Contains(resp.Message, "DHCP renewal initiated") {
			t.Errorf("dhcp-renew %q message = %q", target, resp.Message)
		}
	}
	// Controls: unknown interface and a unit with no client stay NotFound,
	// and no client was started for them.
	for _, target := range []string{"ge-0/0/9", "ge-0/0/3.9"} {
		_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "dhcp-renew", Target: target})
		if status.Code(err) != codes.NotFound {
			t.Errorf("dhcp-renew %q code = %v, want NotFound (err=%v)", target, status.Code(err), err)
		}
	}
}

func TestMonitorPacketDropSkipsPermitScreenAlarm15227(t *testing.T) {
	eb := logging.NewEventBuffer(16)
	s := &Server{store: packetDropTestStore(t), eventBuf: eb}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream := &lockedPacketDropStream15227{ctx: ctx}
	// TrySubscribe is live-only (no replay): publish only once the
	// handler has opened the stream — its opening line is sent after
	// TrySubscribe succeeds, so it is the subscription witness.
	done := make(chan error, 1)
	go func() {
		done <- s.MonitorPacketDrop(&pb.MonitorPacketDropRequest{Node: "local", Count: 2}, stream)
	}()
	deadline := time.Now().Add(5 * time.Second)
	subscribed := false
	for time.Now().Before(deadline) {
		if len(stream.lines()) > 0 {
			subscribed = true
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !subscribed {
		t.Fatal("MonitorPacketDrop never opened the stream")
	}
	eb.Add(logging.EventRecord{
		Time: time.Now(), Type: "SCREEN_DROP", Action: "permit",
		ScreenCheck: "syn-flood", SrcAddr: "10.0.1.1:1234", DstAddr: "10.0.2.1:80",
		Protocol: "TCP", ProtocolNum: 6, IngressIface: "ge-0/0/0",
	})
	eb.Add(logging.EventRecord{
		Time: time.Now(), Type: "SCREEN_DROP", Action: "deny",
		ScreenCheck: "syn-flood", SrcAddr: "10.0.1.2:1234", DstAddr: "10.0.2.1:80",
		Protocol: "TCP", ProtocolNum: 6, IngressIface: "ge-0/0/0",
	})
	eb.Add(logging.EventRecord{
		Time: time.Now(), Type: "POLICY_DENY", Action: "deny",
		SrcAddr: "10.0.1.3:1234", DstAddr: "10.0.2.1:80",
		Protocol: "TCP", ProtocolNum: 6, IngressIface: "ge-0/0/0", PolicyName: "deny-all",
	})
	// Count=2 terminates the stream deterministically after the deny
	// screen line and the policy line — if the permit alarm were
	// rendered it would consume the first count slot instead.
	if err := <-done; err != nil {
		t.Fatalf("MonitorPacketDrop: %v", err)
	}
	joined := strings.Join(stream.lines(), "\n")
	if strings.Contains(joined, "10.0.1.1") {
		t.Fatalf("permit screen alarm rendered as a packet drop (A43-05):\n%s", joined)
	}
	if !strings.Contains(joined, "10.0.1.2") || !strings.Contains(joined, "Dropped by SCREEN:syn-flood") {
		t.Fatalf("deny screen line missing/changed:\n%s", joined)
	}
	if !strings.Contains(joined, "10.0.1.3") || !strings.Contains(joined, "Dropped by FLOW:Policy deny-all") {
		t.Fatalf("policy deny control line missing/changed:\n%s", joined)
	}
}
