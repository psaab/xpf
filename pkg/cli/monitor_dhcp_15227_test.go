package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/logging"
)

// TestPacketDropLoopSkipsPermitScreenAlarm15227 is the local-CLI twin of
// A43-05: a SCREEN record with action=permit (forwarded alarm) must not
// be rendered/counted as a packet drop, while the deny screen line is
// unchanged.
func TestPacketDropLoopSkipsPermitScreenAlarm15227(t *testing.T) {
	eb := logging.NewEventBuffer(16)
	c := &CLI{eventBuf: eb}
	done := make(chan error, 1)
	// Subscribe is live-only: run the command, wait until it has
	// subscribed (its cmdCancel is installed), then publish.
	out := captureStdout(t, func() {
		go func() { done <- c.handleMonitorSecurityPacketDrop([]string{"count", "1"}) }()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			c.cmdMu.Lock()
			ready := c.cmdCancel != nil
			c.cmdMu.Unlock()
			if ready {
				break
			}
			time.Sleep(time.Millisecond)
		}
		eb.Add(logging.EventRecord{
			Time: time.Now(), Type: "SCREEN_DROP", Action: "permit",
			ScreenCheck: "syn-flood", SrcAddr: "10.0.1.1:1234", DstAddr: "10.0.2.1:80",
			Protocol: "TCP", IngressIface: "ge-0/0/0",
		})
		eb.Add(logging.EventRecord{
			Time: time.Now(), Type: "SCREEN_DROP", Action: "deny",
			ScreenCheck: "syn-flood", SrcAddr: "10.0.1.2:1234", DstAddr: "10.0.2.1:80",
			Protocol: "TCP", IngressIface: "ge-0/0/0",
		})
		// count 1: returns after the FIRST rendered drop. If the permit
		// alarm were rendered it would be that first line.
		if err := <-done; err != nil {
			t.Errorf("handleMonitorSecurityPacketDrop: %v", err)
		}
	})
	if strings.Contains(out, "10.0.1.1") {
		t.Fatalf("permit screen alarm rendered as a packet drop (A43-05):\n%s", out)
	}
	if !strings.Contains(out, "10.0.1.2") || !strings.Contains(out, "Dropped by SCREEN:syn-flood") {
		t.Fatalf("deny screen line missing/changed:\n%s", out)
	}
}

func TestHandleRequestDHCPRenewResolves15227(t *testing.T) {
	st, err := configstore.New(filepath.Join(t.TempDir(), "cfg.db"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := st.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := st.LoadMerge(`
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
		t.Fatalf("LoadMerge: %v", err)
	}
	if _, err := st.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	mgr := dhcp.NewManagerForTesting(func(ctx context.Context, iface string, af dhcp.AddressFamily) {
		<-ctx.Done()
	})
	mgr.Reconcile([]dhcp.ClientSpec{
		{Iface: "ge-0-0-0", Family: dhcp.AFInet},
		{Iface: "ge-0-0-3.50", Family: dhcp.AFInet6},
	})
	deadline := time.Now().Add(5 * time.Second)
	for len(mgr.RunningClientHandlesForTesting()) != 2 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if len(mgr.RunningClientHandlesForTesting()) != 2 {
		t.Fatalf("premise: running clients = %v", mgr.RunningClientHandlesForTesting())
	}
	defer mgr.StopAll()

	c := &CLI{store: st, dhcp: mgr}
	for _, target := range []string{"ge-0/0/0", "ge-0/0/3.7", "ge-0-0-3.50"} {
		if err := c.handleRequestDHCP([]string{"renew", target}); err != nil {
			t.Errorf("renew %q: %v (pre-fix: false 'no DHCP client running')", target, err)
		}
	}
	if err := c.handleRequestDHCP([]string{"renew", "ge-0/0/9"}); err == nil {
		t.Error("renew of unknown interface succeeded, want refusal")
	}
}
