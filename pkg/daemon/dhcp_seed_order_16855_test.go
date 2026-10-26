package daemon

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	"os"
	"path/filepath"

	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #16855: the post-start lease-add backstop must not seed the pre-restart Kea.
//
// Modelled active/active takeover: an old Kea is already listening on the
// control socket and rejects lease4-add with "Invalid subnet-id" (it has no
// subnet for the newly taken RG). The takeover apply (restart) only completes
// ~when the test flips the stub to the new Kea, which accepts. Pre-fix the
// seed dials at once, hits the old Kea exactly once, and never retries
// (oldAdds=1 newAdds=0). Post-fix the seed waits for the apply generation to
// be marked applied, then seeds the new Kea (oldAdds=0 newAdds=1).
//
// Control (pure backup): no old Kea, socket appears only after the restart —
// the seed must still land exactly once on the new Kea.
//
// The daemon side drives a real dhcpserver.Manager (not a fake applier): its
// runSystemctl seam blocks the restart until released, and the daemon's
// enqueue returns the authority generation the seed waits on. AppliedGeneration
// flips only when that apply body finishes the restart.

type flipKea16855 struct {
	mu            sync.Mutex
	isNew         bool
	oldAdds       int
	newAdds       int
	newValidLfts  []int
	newAddresses  []string
}

func (f *flipKea16855) flip() {
	f.mu.Lock()
	f.isNew = true
	f.mu.Unlock()
}
func (f *flipKea16855) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.oldAdds, f.newAdds
}

func (f *flipKea16855) validLifetimes() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.newValidLfts...)
}

func (f *flipKea16855) newLeaseAddresses() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.newAddresses...)
}

func startFlipKea16855(t *testing.T, path string, f *flipKea16855) func() {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var req struct {
					Command   string         `json:"command"`
					Arguments map[string]any `json:"arguments"`
				}
				if err := json.NewDecoder(c).Decode(&req); err != nil {
					return
				}
				f.mu.Lock()
				isNew := f.isNew
				if req.Command == "lease4-add" {
					if isNew {
						f.newAdds++
						if validLft, ok := req.Arguments["valid-lft"].(float64); ok {
							f.newValidLfts = append(f.newValidLfts, int(validLft))
						}
						if address, ok := req.Arguments["ip-address"].(string); ok {
							f.newAddresses = append(f.newAddresses, address)
						}
					} else {
						f.oldAdds++
					}
				}
				f.mu.Unlock()
				if req.Command == "lease4-add" && !isNew {
					_, _ = c.Write([]byte(`{"result":1,"text":"Invalid subnet-id"}`))
					return
				}
				_, _ = c.Write([]byte(`{"result":0,"text":"ok"}`))
			}(c)
		}
	}()
	return func() { _ = ln.Close() }
}

func TestSeedWaitsForTakeoverApply16855(t *testing.T) {
	sock4 := shortTmpSocket(t, "k4.sock")
	sock6 := shortTmpSocket(t, "k6.sock")
	flip := &flipKea16855{}
	defer startFlipKea16855(t, sock4, flip)()

	d := leaseSyncTestDaemon(t, sock4, sock6, true)
	// Real manager with temp conf paths + no-op systemctl: the enqueue below
	// runs the genuine async apply (restart) instead of failing on /etc/kea.
	restarting := make(chan struct{}, 1)
	release := make(chan struct{})
	confDir, _ := os.MkdirTemp("", "kea-conf")
	t.Cleanup(func() { os.RemoveAll(confDir) })
	mgr := dhcpserver.NewManagerForTesting(
		confDir+"/kea-dhcp4.conf", filepath.Join(t.TempDir(), "kea-dhcp6.conf"),
		func(args ...string) error {
			select {
			case restarting <- struct{}{}:
			default:
			}
			<-release
			return nil
		},
		func(string) bool { return true },
	)
	mgr.SetLeaseSyncSeamsForTesting(unixDialer(), sock4, sock6, "", "")
	d.dhcpServer = mgr
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	d.sessionSync.SetPeerDHCPLeasesForTesting(4, []dhcpserver.SyncLease{
		{Family: 4, Address: "10.0.61.150", HWAddress: "aa:bb:cc:dd:ee:96",
			SubnetID: 1, Remaining: 1800, PreferredRemaining: 1800, State: 0},
	})

	// Model the takeover apply: the restart is in flight (old Kea still
	// serving) and completes only when released; completion publishes the
	// authority generation as applied, which is what the seed waits on.
	gen := d.enqueueDHCPApplyWithAuthorityState(
		d.desiredClusterDHCPConfigWithMasters(d.store.ActiveConfig(), map[int]bool{1: true}), "vrrp MASTER rg-test", d.store.ActiveConfig(), nil)
	if gen == 0 {
		t.Fatal("enqueue returned generation 0")
	}
	// Simulate the async worker finishing the restart after a delay: flip to
	// the new Kea and publish the applied generation via a real apply.
	go func() {
		<-restarting // async worker is inside the (modelled) restart
		time.Sleep(200 * time.Millisecond)
		flip.flip() // new Kea, with the taken-over subnet, is now serving
		releaseOnce.Do(func() { close(release) })
	}()

	done := make(chan struct{})
	go func() {
		d.seedDHCPLeasesFromPeerGen(context.Background(), gen)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("seed did not complete")
	}
	oldAdds, newAdds := flip.counts()
	if oldAdds != 0 || newAdds != 1 {
		t.Fatalf("seed hit old/new Kea = %d/%d, want 0/1 (pre-fix: 1/0)", oldAdds, newAdds)
	}
	if got := d.sessionSync.Stats().DHCPLeasesSeeded; got != 1 {
		t.Fatalf("DHCPLeasesSeeded = %d, want 1", got)
	}
}

// TestSeedWaitDoesNotFailOpenOrReanchorOldSnapshot17884 pins restart ordering,
// lifetime aging, and expiry through the apply wait. The survivor's exact
// remainder varies with elapsed whole seconds; a two-second lease expires.
//
// FAIL-ON-REVERT: make the former 20s deadline short, then hold restart beyond
// it. Returning or seeding the old process before release fails; seeding the
// new process with the pre-wait remaining value or the expired lease also fails.
func TestSeedWaitDoesNotFailOpenOrReanchorOldSnapshot17884(t *testing.T) {
	oldWait := dhcpLeaseSeedApplyWaitWarn
	dhcpLeaseSeedApplyWaitWarn = 200 * time.Millisecond
	t.Cleanup(func() { dhcpLeaseSeedApplyWaitWarn = oldWait })

	sock4 := shortTmpSocket(t, "k4.sock")
	sock6 := shortTmpSocket(t, "k6.sock")
	flip := &flipKea16855{}
	defer startFlipKea16855(t, sock4, flip)()
	d := leaseSyncTestDaemon(t, sock4, sock6, true)

	restarting := make(chan struct{}, 1)
	release := make(chan struct{})
	confDir, err := os.MkdirTemp("", "kea-conf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(confDir) })
	mgr := dhcpserver.NewManagerForTesting(
		filepath.Join(confDir, "kea-dhcp4.conf"), filepath.Join(t.TempDir(), "kea-dhcp6.conf"),
		func(args ...string) error {
			select {
			case restarting <- struct{}{}:
			default:
			}
			<-release
			return nil
		},
		func(string) bool { return true },
	)
	mgr.SetLeaseSyncSeamsForTesting(unixDialer(), sock4, sock6, "", "")
	d.dhcpServer = mgr
	var releaseOnce sync.Once
	releaseRestart := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseRestart)
	d.sessionSync.SetPeerDHCPLeasesForTesting(4, []dhcpserver.SyncLease{
		{Family: 4, Address: "10.0.61.151", HWAddress: "aa:bb:cc:dd:ee:97",
			SubnetID: 1, Remaining: 100, PreferredRemaining: 100, State: 0},
		{Family: 4, Address: "10.0.61.152", HWAddress: "aa:bb:cc:dd:ee:98",
			SubnetID: 1, Remaining: 2, PreferredRemaining: 2, State: 0},
	})

	gen := d.enqueueDHCPApplyWithAuthorityState(
		d.desiredClusterDHCPConfigWithMasters(d.store.ActiveConfig(), map[int]bool{1: true}),
		"vrrp MASTER rg-test", d.store.ActiveConfig(), nil)
	if gen == 0 {
		t.Fatal("enqueue returned generation 0")
	}
	done := make(chan struct{})
	go func() {
		d.seedDHCPLeasesFromPeerGen(context.Background(), gen)
		close(done)
	}()
	select {
	case <-restarting:
	case <-time.After(5 * time.Second):
		releaseRestart()
		t.Fatal("takeover restart did not start")
	}

	time.Sleep(2200 * time.Millisecond)
	select {
	case <-done:
		oldAdds, newAdds := flip.counts()
		t.Fatalf("#17884: seed returned before restart completed (old/new adds %d/%d)", oldAdds, newAdds)
	default:
	}
	if oldAdds, newAdds := flip.counts(); oldAdds != 0 || newAdds != 0 {
		t.Fatalf("#17884: lease seed reached old/new Kea during restart = %d/%d, want 0/0", oldAdds, newAdds)
	}

	flip.flip()
	releaseRestart()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("seed did not complete after takeover restart")
	}
	oldAdds, newAdds := flip.counts()
	if oldAdds != 0 || newAdds != 1 {
		t.Fatalf("#17884: seed hit old/new Kea = %d/%d, want 0/1", oldAdds, newAdds)
	}
	if got := flip.validLifetimes(); len(got) != 1 || got[0] <= 0 || got[0] >= 100 {
		t.Fatalf("#17884: seeded valid-lft values = %v, want only the aged surviving lease (0 < valid-lft < 100)", got)
	}
	if got := flip.newLeaseAddresses(); len(got) != 1 || got[0] != "10.0.61.151" {
		t.Fatalf("#17884: seeded addresses = %v, want only 10.0.61.151 (the two-second lease expired)", got)
	}
}

func TestSeedApplyWaitStopsOnDaemonShutdown17884(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &Daemon{
		dhcpServer:        dhcpserver.New(),
		applyCancelContext: ctx,
	}
	done := make(chan bool, 1)
	go func() {
		done <- d.waitForDHCPApplyGen(d.applyCancelCtx(), 1, true, false)
	}()
	cancel()
	select {
	case ready := <-done:
		if ready {
			t.Fatal("wait reported an unapplied generation ready after shutdown cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("takeover apply wait did not stop after daemon shutdown cancellation")
	}
}


// IAID-0 must survive the seed wire form (#16855 alongside): keaLeaseJSON with
// omitempty dropped "iaid" for IAID 0; the pointer form must emit "iaid":0.
func TestSeedIAIDZeroEmitted16855(t *testing.T) {
	sock4 := shortTmpSocket(t, "k4.sock")
	sock6 := shortTmpSocket(t, "k6.sock")
	stub := &stubKeaServer{}
	defer stub.start(t, sock6)()
	_ = sock4
	d := leaseSyncTestDaemon(t, sock4, sock6, true)
	d.sessionSync.SetPeerDHCPLeasesForTesting(6, []dhcpserver.SyncLease{
		{Family: 6, Address: "2001:db8::100", DUID: "00:01:00:01", IAID: 0,
			LeaseType: "IA_NA", SubnetID: 1, Remaining: 2400, PreferredRemaining: 2400, State: 0},
	})
	d.seedDHCPLeasesFromPeer(context.Background())
	adds := stub.adds()
	if len(adds) != 1 {
		t.Fatalf("expected 1 lease6-add, got %d: %+v", len(adds), adds)
	}
	iaid, ok := adds[0]["iaid"]
	if !ok {
		t.Fatalf("lease6-add dropped iaid for IAID-0 binding: %+v", adds[0])
	}
	if v, _ := iaid.(float64); v != 0 {
		t.Fatalf("iaid = %v, want 0", iaid)
	}
}
