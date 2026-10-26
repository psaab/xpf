package daemon

import (
	"context"
	"encoding/json"
	"errors"
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
	mu           sync.Mutex
	isNew        bool
	oldAdds      int
	newAdds      int
	newValidLfts []int
	newAddresses []string
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

func startDHCPLeaseSeedForTesting(t *testing.T, d *Daemon, gen uint64, warnAfter time.Duration) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	d.dhcpLeaseSync.seedWG.Add(1)
	go func() {
		defer d.dhcpLeaseSync.seedWG.Done()
		d.seedDHCPLeasesFromPeerGenWithWait(d.applyCancelCtx(), gen, warnAfter)
		close(done)
	}()
	t.Cleanup(func() {
		if d.applyCancel != nil {
			d.applyCancel()
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("test-owned DHCP lease seed did not exit after fixture cancellation")
		}
	})
	return done
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

	done := startDHCPLeaseSeedForTesting(t, d, gen, dhcpLeaseSeedApplyWaitWarnAfter)
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
// lifetime aging, and expiry through the apply wait for both address families.
// The seed-wait channel proves each short lease was captured while still live;
// the survivor's exact remainder varies with elapsed whole seconds.
//
// FAIL-ON-REVERT: while both family applies are blocked, returning at the
// former 20s deadline reaches the old Kea. Seeding from the pre-wait snapshots
// also revives the two-second lease and gives each survivor its original
// valid-lft.
func TestSeedWaitDoesNotFailOpenOrReanchorOldSnapshot17884(t *testing.T) {
	sock4 := shortTmpSocket(t, "k4.sock")
	sock6 := shortTmpSocket(t, "k6.sock")
	flip := &flipKea16855{}
	defer startFlipKea16855(t, sock4, flip)()
	v6Kea := &stubKeaServer{}
	defer v6Kea.start(t, sock6)()
	d := leaseSyncTestDaemon(t, sock4, sock6, true)
	d.dhcpLeaseSync.seedWaitStarted = make(chan int, 2)

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

	gen := d.enqueueDHCPApplyWithAuthorityState(
		d.desiredClusterDHCPConfigWithMasters(d.store.ActiveConfig(), map[int]bool{1: true}),
		"vrrp MASTER rg-test", d.store.ActiveConfig(), nil)
	if gen == 0 {
		t.Fatal("enqueue returned generation 0")
	}
	select {
	case <-restarting:
	case <-time.After(5 * time.Second):
		releaseRestart()
		t.Fatal("takeover restart did not start")
	}

	// Store both rows only after the v4 restart is blocked, then require a
	// per-family wait witness within one second. This proves the seed captured
	// each two-second lease while it was still live, not after it had aged out.
	d.sessionSync.SetPeerDHCPLeasesForTesting(4, []dhcpserver.SyncLease{
		{Family: 4, Address: "10.0.61.151", HWAddress: "aa:bb:cc:dd:ee:97",
			SubnetID: 1, Remaining: 100, PreferredRemaining: 100, State: 0},
		{Family: 4, Address: "10.0.61.152", HWAddress: "aa:bb:cc:dd:ee:98",
			SubnetID: 1, Remaining: 2, PreferredRemaining: 2, State: 0},
	})
	d.sessionSync.SetPeerDHCPLeasesForTesting(6, []dhcpserver.SyncLease{
		{Family: 6, Address: "2001:db8:61::151", DUID: "00:01:00:01:aa:bb:cc:dd:ee:97",
			IAID: 97, LeaseType: "IA_NA", SubnetID: 1, Remaining: 100, PreferredRemaining: 100, State: 0},
		{Family: 6, Address: "2001:db8:61::152", DUID: "00:01:00:01:aa:bb:cc:dd:ee:98",
			IAID: 98, LeaseType: "IA_NA", SubnetID: 1, Remaining: 2, PreferredRemaining: 2, State: 0},
	})
	snapshotsAt := time.Now()
	done := startDHCPLeaseSeedForTesting(t, d, gen, 200*time.Millisecond)

	waiting := map[int]bool{}
	deadline := time.After(time.Second)
	for !waiting[4] || !waiting[6] {
		select {
		case family := <-d.dhcpLeaseSync.seedWaitStarted:
			waiting[family] = true
			if time.Since(snapshotsAt) >= 2*time.Second {
				t.Fatalf("#17884: family %d entered its wait only after the two-second lease expired", family)
			}
		case <-deadline:
			t.Fatalf("#17884: seed did not enter both family waits before lease expiry; observed=%v", waiting)
		}
	}

	time.Sleep(2200 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("#17884: seed returned while takeover restart was still blocked")
	default:
	}
	if oldAdds, newAdds := flip.counts(); oldAdds != 0 || newAdds != 0 {
		t.Fatalf("#17884: v4 seed reached old/new Kea during restart = %d/%d, want 0/0", oldAdds, newAdds)
	}
	if adds := v6Kea.adds(); len(adds) != 0 {
		t.Fatalf("#17884: v6 seed reached Kea during restart: %+v", adds)
	}

	flip.flip()
	releaseRestart()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("seed did not complete after both takeover applies")
	}
	oldAdds, newAdds := flip.counts()
	if oldAdds != 0 || newAdds != 1 {
		t.Fatalf("#17884: v4 seed hit old/new Kea = %d/%d, want 0/1", oldAdds, newAdds)
	}
	if got := flip.validLifetimes(); len(got) != 1 || got[0] <= 0 || got[0] >= 100 {
		t.Fatalf("#17884: v4 valid-lft values = %v, want only the aged surviving lease (0 < valid-lft < 100)", got)
	}
	if got := flip.newLeaseAddresses(); len(got) != 1 || got[0] != "10.0.61.151" {
		t.Fatalf("#17884: v4 addresses = %v, want only 10.0.61.151 (the two-second lease expired)", got)
	}
	v6Adds := v6Kea.adds()
	if len(v6Adds) != 1 || v6Adds[0]["ip-address"] != "2001:db8:61::151" {
		t.Fatalf("#17884: v6 lease-adds = %+v, want only the surviving address 2001:db8:61::151", v6Adds)
	}
	if validLft, ok := v6Adds[0]["valid-lft"].(float64); !ok || validLft <= 0 || validLft >= 100 {
		t.Fatalf("#17884: v6 valid-lft = %v, want an aged value between 1 and 99", v6Adds[0]["valid-lft"])
	}
	if got := d.sessionSync.Stats().DHCPLeasesSeeded; got != 2 {
		t.Fatalf("#17884: DHCPLeasesSeeded = %d, want 2 surviving leases", got)
	}
}

func TestSeedApplyWaitStopsOnDaemonShutdown17884(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &Daemon{
		dhcpServer:         dhcpserver.New(),
		applyCancelContext: ctx,
	}
	done := make(chan bool, 1)
	go func() {
		done <- d.waitForDHCPApplyGen(d.applyCancelCtx(), 1, 20*time.Millisecond, 4)
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

// A failed family must not hold the healthy family behind a shared wait.
// Cancellation still joins the seed worker while the failed family remains
// unapplied.
func TestSeedFamiliesApplyIndependently17884(t *testing.T) {
	tests := []struct {
		name         string
		failedFamily int
		failedUnit   string
	}{
		{name: "v4 blocked, v6 seeds", failedFamily: 4, failedUnit: "kea-dhcp4-server"},
		{name: "v6 blocked, v4 seeds", failedFamily: 6, failedUnit: "kea-dhcp6-server"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sock4 := shortTmpSocket(t, "k4.sock")
			sock6 := shortTmpSocket(t, "k6.sock")
			kea4 := &stubKeaServer{}
			kea6 := &stubKeaServer{}
			defer kea4.start(t, sock4)()
			defer kea6.start(t, sock6)()
			d := leaseSyncTestDaemon(t, sock4, sock6, true)
			d.dhcpLeaseSync.seedWaitStarted = make(chan int, 2)
			confDir := t.TempDir()
			mgr := dhcpserver.NewManagerForTesting(
				filepath.Join(confDir, "kea-dhcp4.conf"), filepath.Join(confDir, "kea-dhcp6.conf"),
				func(args ...string) error {
					if len(args) >= 2 && args[0] == "restart" && args[1] == tt.failedUnit {
						return errors.New("injected family restart failure")
					}
					return nil
				},
				func(string) bool { return true },
			)
			mgr.SetLeaseSyncSeamsForTesting(unixDialer(), sock4, sock6, "", "")
			d.dhcpServer = mgr
			d.sessionSync.SetPeerDHCPLeasesForTesting(4, []dhcpserver.SyncLease{
				{Family: 4, Address: "10.0.62.151", HWAddress: "aa:bb:cc:dd:ee:97",
					SubnetID: 1, Remaining: 3600, PreferredRemaining: 3600, State: 0},
			})
			d.sessionSync.SetPeerDHCPLeasesForTesting(6, []dhcpserver.SyncLease{
				{Family: 6, Address: "2001:db8:62::151", DUID: "00:01:00:01:aa:bb:cc:dd:ee:97",
					IAID: 97, LeaseType: "IA_NA", SubnetID: 1, Remaining: 3600, PreferredRemaining: 3600, State: 0},
			})
			gen := d.enqueueDHCPApplyWithAuthorityState(
				d.desiredClusterDHCPConfigWithMasters(d.store.ActiveConfig(), map[int]bool{1: true}),
				"vrrp MASTER rg-test", d.store.ActiveConfig(), nil)
			if gen == 0 {
				t.Fatal("enqueue returned generation 0")
			}
			d.spawnDHCPLeaseSeed(d.applyCancelCtx(), gen, 50*time.Millisecond)

			failedWaitStarted := false
			deadline := time.After(3 * time.Second)
			for !failedWaitStarted {
				select {
				case family := <-d.dhcpLeaseSync.seedWaitStarted:
					failedWaitStarted = family == tt.failedFamily
				case <-deadline:
					t.Fatalf("seed did not wait on failed family %d", tt.failedFamily)
				}
			}
			healthyFamily := 10 - tt.failedFamily
			waitFor(t, 3*time.Second, "healthy-family seed", func() bool {
				if healthyFamily == 4 {
					return len(kea4.adds()) == 1
				}
				return len(kea6.adds()) == 1
			})
			failedAdds := kea4.adds()
			if tt.failedFamily == 6 {
				failedAdds = kea6.adds()
			}
			if len(failedAdds) != 0 {
				t.Fatalf("failed family %d received lease-add commands: %+v", tt.failedFamily, failedAdds)
			}

			seedDone := make(chan struct{})
			go func() {
				d.dhcpLeaseSync.seedWG.Wait()
				close(seedDone)
			}()
			select {
			case <-seedDone:
				t.Fatal("seed worker returned while one family remained unapplied")
			case <-time.After(75 * time.Millisecond):
			}
			d.applyCancel()
			select {
			case <-seedDone:
			case <-time.After(time.Second):
				t.Fatal("seed worker did not join after apply-context cancellation")
			}
		})
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
