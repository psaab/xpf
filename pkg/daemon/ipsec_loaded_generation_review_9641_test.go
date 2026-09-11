package daemon

// #9641 Codex implementation review: the marker may OVERRIDE the promoted config only
// when no IPsec apply overlaps the pass (finding 1) and charon's connections are
// provably not the promoted config's (finding 2), and it must resolve a generation this
// process wrote even after the store dropped it (finding 3). Each cell is built so the
// unguarded code gives the other answer.

import (
	"errors"
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/ipsec"
)

// overlappingApply9641 wires a daemon whose charon double runs apply exactly once,
// DURING the pass: inside the first --list-conns, after the listing is taken. The listing
// the pass sees is therefore the one from before the apply.
func overlappingApply9641(t *testing.T, store *configstore.Store, ch *charon9641, apply func(d *Daemon)) *Daemon {
	t.Helper()
	ch.dir = t.TempDir()
	m := ipsec.NewWithConfigDir(ch.dir)
	d := &Daemon{cluster: clusterOwning9511(t, store, 1), store: store, ipsec: m}
	fired := false
	m.SetSwanctlForTesting(func(args ...string) ([]byte, error) {
		out, err := ch.swanctl(args...)
		if !fired && len(args) > 0 && args[0] == "--list-conns" {
			fired = true
			apply(d)
		}
		return out, err
	})
	return d
}

// FINDING 1, overlap. charon lists C0 with its marker, and during the pass a commit's
// apply of C1 succeeds. The pass must not answer with C0, which charon no longer runs; it
// re-reads the record, C1. Unguarded, C0 validates and blue-red is initiated.
func TestAttributionDropsTheMarkerWhenAnApplyOverlapsThePass9641(t *testing.T) {
	store, d0, _ := generations9641(t)
	if !initiates9641(daemonAskingCharon9641(t, store, &charon9641{marker: d0, conns: listBlue9641}, 1), "blue-red") {
		t.Fatal("FIXTURE: without an overlapping apply the C0 listing must be trusted")
	}
	c1 := store.ActiveConfig()
	d := overlappingApply9641(t, store, &charon9641{marker: d0, conns: listBlue9641}, func(d *Daemon) {
		if err := d.applyIPsecTracked(c1); err != nil {
			t.Errorf("FIXTURE: the overlapping apply must succeed: %v", err)
		}
	})
	if initiates9641(d, "blue-red") {
		t.Error("an apply of C1 completed during the pass, yet attribution used charon's pre-apply C0")
	}
	if d.ipsecLoadedCfg.Load() != c1 {
		t.Fatal("FIXTURE: the overlapping apply must have recorded C1")
	}
}

// FINDING 1, the fallback after an overlap is the RECORD the apply left, not merely the
// promoted config. The overlapping apply records a config whose answer differs from the
// promoted C1's, so skipping the re-read shows.
func TestAttributionAfterAnOverlapReReadsTheRecord9641(t *testing.T) {
	store, d0, _ := generations9641(t)
	applied := storeWith9511(t, blueOnRG1_9511...).ActiveConfig()
	d := overlappingApply9641(t, store, &charon9641{marker: d0, conns: listBlue9641}, func(d *Daemon) {
		if err := d.applyIPsecTracked(applied); err != nil {
			t.Errorf("FIXTURE: the overlapping apply must succeed: %v", err)
		}
	})
	if !initiates9641(d, "blue-red") {
		t.Error("after the overlap the record names a blue-only config, where blue-red is blue's RG1 " +
			"child; attribution answered with the promoted C1 instead of re-reading the record")
	}
}

// FINDING 1, in progress. An apply has written its file and is still reloading when the
// pass starts, and it is still reloading when the pass ends. charon must not be asked,
// and the promoted config stands. Unguarded, the sequence number has not moved by the end
// of the pass, so C0 validates.
func TestAttributionDoesNotAskCharonWhileAnApplyIsInProgress9641(t *testing.T) {
	store, d0, _ := generations9641(t)
	ch := &charon9641{marker: d0, conns: listBlue9641, dir: t.TempDir()}
	m := ipsec.NewWithConfigDir(ch.dir)
	d := &Daemon{cluster: clusterOwning9511(t, store, 1), store: store, ipsec: m}
	loading := make(chan struct{})
	release := make(chan struct{})
	m.SetSwanctlForTesting(func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--load-all" {
			close(loading)
			<-release
		}
		return ch.swanctl(args...)
	})
	done := make(chan error, 1)
	go func() { done <- d.applyIPsecTracked(store.ActiveConfig()) }()
	<-loading

	listsBefore := ch.lists
	initiated := initiates9641(d, "blue-red")
	asked := ch.lists - listsBefore
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("FIXTURE: the held apply must complete: %v", err)
	}
	if initiated {
		t.Error("an apply was reloading throughout the pass, yet attribution used charon's C0")
	}
	if asked != 0 {
		t.Errorf("charon was asked %d times while an apply was in progress", asked)
	}
}

// FINDING 2. C0 and C1 differ only in which redundancy group the gateway's interface
// belongs to, and an explicit local address makes them render identical connections.
// Those connections carry no generation, and RG ownership comes from the interface config
// the apply's earlier steps took from the promoted config. The marker naming C0 must not
// override it. Unguarded, C0 validates and the RG1 owner initiates.
func TestAttributionKeepsThePromotedConfigForIdenticalConnections9641(t *testing.T) {
	store := storeWith9511(t,
		"set security ike gateway gw-x address 198.51.100.9",
		"set security ike gateway gw-x external-interface reth1.0",
		"set security ike gateway gw-x local-address 10.0.9.9",
		"set security ipsec vpn same ike gateway gw-x",
	)
	c0, d0 := store.ActiveConfig(), store.ActiveDigest()
	if err := store.SetFromInput("security ike gateway gw-x external-interface reth2.0"); err != nil {
		t.Fatalf("FIXTURE: SetFromInput: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("FIXTURE: Commit: %v", err)
	}
	c1 := store.ActiveConfig()
	if ipsecVPNRedundancyGroup(c0, c0.Security.IPsec.VPNs["same"]) != 1 || ipsecVPNRedundancyGroup(c1, c1.Security.IPsec.VPNs["same"]) != 2 {
		t.Fatal("FIXTURE: the gateway must move from RG1 to RG2")
	}
	list := "list-conn event {same {local_addrs=[10.0.9.9] remote_addrs=[198.51.100.9] version=IKEv1/2 " +
		"local-1 {class=pre-shared key} remote-1 {class=pre-shared key} children {same {mode=TUNNEL}}}}\n"
	ch := &charon9641{marker: d0, conns: list}
	d := daemonAskingCharon9641(t, store, ch, 1)
	have, err := d.ipsec.ListLoadedConns()
	if err != nil {
		t.Fatalf("FIXTURE: list: %v", err)
	}
	w0, err0 := ipsec.ExpectedLoadedConns(c0)
	w1, err1 := ipsec.ExpectedLoadedConns(c1)
	if err0 != nil || err1 != nil || !have.Equal(w0) || !have.Equal(w1) {
		t.Fatalf("FIXTURE: C0 and C1 must both render exactly charon's listing (err0 %v, err1 %v)", err0, err1)
	}
	if initiates9641(d, "same") {
		t.Error("identical connections: the marker naming C0 overrode the promoted C1, and the RG1 owner " +
			"initiated a tunnel whose interface the applied config puts in RG2")
	}
}

// FINDING 2, uncomparable. The promoted C1 adds a VPN whose local address comes from a
// DHCP interface, so what charon would list for it cannot be computed. Not being able to
// rule the promoted config out means it stands. Unguarded, C0 validates and blue-red is
// initiated.
func TestAttributionKeepsThePromotedConfigWhenItCannotBeCompared9641(t *testing.T) {
	store, d0, _ := generations9641(t)
	for _, line := range []string{
		"interfaces ge-0/0/4 unit 0 family inet dhcp",
		"security ike gateway gw-dhcp address 198.51.100.7",
		"security ike gateway gw-dhcp external-interface ge-0/0/4.0",
		"security ipsec vpn dyn ike gateway gw-dhcp",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("FIXTURE: SetFromInput %q: %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("FIXTURE: Commit: %v", err)
	}
	if _, err := ipsec.ExpectedLoadedConns(store.ActiveConfig()); err == nil {
		t.Fatal("FIXTURE: the promoted config must be uncomparable (a DHCP-derived local address)")
	}
	if initiates9641(daemonAskingCharon9641(t, store, &charon9641{marker: d0, conns: listBlue9641}, 1), "blue-red") {
		t.Error("the promoted config could not be ruled out, yet the marker naming C0 overrode it")
	}
}

// FINDING 3. charon runs C1, which this process wrote and loaded; then a rollback promoted
// C0 into a store that no longer retains C1, and the rollback's reload failed. The
// generation charon names must still resolve, from what this process wrote. Unguarded,
// C1 is not retained, the pass falls back to the promoted C0, and blue-red is initiated.
func TestAttributionResolvesAGenerationTheStoreDropped9641(t *testing.T) {
	withC1, _, d1 := generations9641(t)
	ch := &charon9641{}
	d := daemonAskingCharon9641(t, withC1, ch, 1)
	if err := d.applyIPsecTracked(withC1.ActiveConfig()); err != nil {
		t.Fatalf("FIXTURE: applying C1 must succeed: %v", err)
	}
	ch.loadFile(t)
	ch.conns = listBlue9641 + listBlueRed9641
	if ch.marker != d1 {
		t.Fatalf("FIXTURE: charon must name C1, got %q", ch.marker)
	}

	rolledBack := storeWith9511(t, blueOnRG1_9511...)
	if _, ok := rolledBack.RetainedGeneration(d1); ok {
		t.Fatal("FIXTURE: the rolled-back store must not retain C1")
	}
	d.store = rolledBack
	d.cluster = clusterOwning9511(t, rolledBack, 1)
	ch.loadErr = errors.New("charon vici socket refused")
	if err := d.applyIPsecTracked(rolledBack.ActiveConfig()); err == nil {
		t.Fatal("FIXTURE: the rollback's reload must fail")
	}
	if initiates9641(d, "blue-red") {
		t.Error("charon still runs C1, which this process wrote; attribution could not resolve it and used the promoted C0")
	}
}

// CODEX RE-CHECK, finding 2. charon runs C1, which this process loaded. A rollback's
// reload then fails, and so do ipsecWrittenMax+1 more applies of distinct generations.
// Their writes push C1 out of the written list, yet charon still runs C1. Unguarded, C1
// no longer resolves and the pass falls back to the promoted config.
func TestAttributionResolvesTheLastLoadedGenerationAfterManyFailedWrites9641(t *testing.T) {
	withC1, _, d1 := generations9641(t)
	ch := &charon9641{}
	d := daemonAskingCharon9641(t, withC1, ch, 1)
	if err := d.applyIPsecTracked(withC1.ActiveConfig()); err != nil {
		t.Fatalf("FIXTURE: applying C1 must succeed: %v", err)
	}
	ch.loadFile(t)
	ch.conns = listBlue9641 + listBlueRed9641
	if ch.marker != d1 {
		t.Fatalf("FIXTURE: charon must name C1, got %q", ch.marker)
	}

	rolledBack := storeWith9511(t, blueOnRG1_9511...)
	d.store = rolledBack
	d.cluster = clusterOwning9511(t, rolledBack, 1)
	ch.loadErr = errors.New("charon vici socket refused")
	for i := 0; i <= ipsecWrittenMax; i++ {
		if err := rolledBack.SetFromInput(fmt.Sprintf("system host-name failed-%d", i)); err != nil {
			t.Fatalf("FIXTURE: SetFromInput: %v", err)
		}
		if _, err := rolledBack.Commit(); err != nil {
			t.Fatalf("FIXTURE: Commit: %v", err)
		}
		if err := d.applyIPsecTracked(rolledBack.ActiveConfig()); err == nil {
			t.Fatal("FIXTURE: every reload must fail")
		}
	}
	if list := d.ipsecWritten.Load(); list != nil {
		for _, c := range *list {
			if c.gen == d1 {
				t.Fatal("FIXTURE: the failed writes must have pushed C1 out of the written list")
			}
		}
	}
	if initiates9641(d, "blue-red") {
		t.Error("charon still runs C1, the generation this process last loaded; a run of failed " +
			"writes evicted it and attribution used the promoted config")
	}
}
