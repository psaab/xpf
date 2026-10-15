package daemon

import (
	"net"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #13542: dual-to-single fabric restart must clear the stale fab1 address.
func TestSyncPeerAddrsDualToSingleClearsSecondary_13542(t *testing.T) {
	cc := &config.ClusterConfig{Fabric1PeerAddress: "10.99.1.2"}
	d := newWiringTestDaemon()
	ss := newWiringTestSessionSync()
	d.fabricMu.Lock()
	d.fabricPeerIP1 = net.ParseIP("10.99.9.2")
	d.fabricMu.Unlock()
	d.wireSessionSyncTransportRefs(ss, cc, "fabric", "10.99.0.2", "10.99.1.1:4785")
	if got := d.fabricPeerAddrs(); len(got) != 2 {
		t.Fatalf("dual: fabricPeerAddrs = %v, want 2 addrs", got)
	}
	d.wireSessionSyncTransportRefs(ss, cc, "control-link", "10.99.0.2", "")
	got := d.fabricPeerAddrs()
	if len(got) != 1 || got[0] != "10.99.0.2" {
		t.Errorf("single after dual: fabricPeerAddrs = %v, want [10.99.0.2]", got)
	}
}

func TestSyncPeerAddrsConcurrentRebindSnapshot_13542(t *testing.T) {
	cc := &config.ClusterConfig{Fabric1PeerAddress: "10.99.1.2"}
	d := newWiringTestDaemon()
	ss := newWiringTestSessionSync()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 1000 {
			d.wireSessionSyncTransportRefs(ss, cc, "fabric", "10.99.0.2", "10.99.1.1:4785")
			d.wireSessionSyncTransportRefs(ss, cc, "control-link", "10.99.0.2", "")
		}
	}()
	go func() {
		defer wg.Done()
		for range 1000 {
			d.fabricPeerAddrs()
		}
	}()
	wg.Wait()
}
