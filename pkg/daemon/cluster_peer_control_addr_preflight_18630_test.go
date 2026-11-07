package daemon

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"golang.org/x/sync/semaphore"
)

const (
	peerControlAddrOld18630     = "10.99.14.2/30"
	peerControlAddrNew18630     = "10.99.14.5/30"
	peerControlAddrForeign18630 = "192.0.2.77"
)

func peerControlAddrStore18630(t *testing.T, candidatePeerAddr string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	store.SetNodeID(0)
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"groups node0 chassis cluster node 0",
		"groups node0 chassis cluster peer-address 10.99.14.2",
		"groups node0 interfaces em0 unit 0 family inet address 10.99.14.1/30",
		"groups node1 chassis cluster node 1",
		"groups node1 chassis cluster peer-address 10.99.14.1",
		"groups node1 interfaces em0 unit 0 family inet address " + peerControlAddrOld18630,
		`apply-groups "${node}"`,
		"chassis cluster cluster-id 1",
		"chassis cluster authentication-key test-cluster-psk-18630",
		"chassis cluster control-interface em0",
		"system host-name baseline-18630",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit baseline: %v", err)
	}
	if candidatePeerAddr != peerControlAddrOld18630 {
		if err := store.DeleteFromInput("groups node1 interfaces em0 unit 0 family inet address " + peerControlAddrOld18630); err != nil {
			t.Fatalf("delete baseline peer control address: %v", err)
		}
		if err := store.SetFromInput("groups node1 interfaces em0 unit 0 family inet address " + candidatePeerAddr); err != nil {
			t.Fatalf("set candidate peer control address: %v", err)
		}
	}
	if err := store.SetFromInput("system host-name candidate-18630"); err != nil {
		t.Fatalf("stage candidate marker: %v", err)
	}
	return store
}

func peerControlAddrDHCPStore18630(t *testing.T) *configstore.Store {
	t.Helper()
	store := peerControlAddrStore18630(t, peerControlAddrOld18630)
	if err := store.SetFromInput("groups node1 interfaces em0 unit 0 family inet dhcp"); err != nil {
		t.Fatalf("set peer DHCP: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit peer DHCP running config: %v", err)
	}
	if err := store.SetFromInput("system host-name unrelated-dhcp-edit-18630"); err != nil {
		t.Fatalf("stage unrelated candidate: %v", err)
	}
	return store
}

func peerControlAddrForeignStore18630(t *testing.T) *configstore.Store {
	t.Helper()
	store := peerControlAddrStore18630(t, peerControlAddrOld18630)
	if err := store.SetFromInput("groups node0 chassis cluster peer-address " + peerControlAddrForeign18630); err != nil {
		t.Fatalf("set running peer endpoint: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit foreign running endpoint: %v", err)
	}
	if err := store.SetFromInput("system host-name unrelated-foreign-edit-18630"); err != nil {
		t.Fatalf("stage unrelated candidate: %v", err)
	}
	return store
}

func runningPeerControlDaemon18630(store *configstore.Store) *Daemon {
	return runningPeerControlDaemonWithPeerAddr18630(store, "10.99.14.2")
}

func runningPeerControlDaemonWithPeerAddr18630(store *configstore.Store, peerAddr string) *Daemon {
	running := cluster.NewManager(0, 1)
	running.SetHeartbeatEndpointForTesting("10.99.14.1", peerAddr, "em0")
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1), cluster: running}
	d.applyBodyForTest = func(*config.Config) {}
	return d
}

func requirePeerControlAddressRefusal18630(t *testing.T, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "peer's chassis cluster control-link address") {
		t.Fatalf("renumbering the peer's running control address must be refused, got %v", err)
	}
	for _, want := range []string{"10.99.14.2", "BOTH nodes", "restart xpfd on both", "offline", "Do NOT commit", "separately"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal must contain %q and the offline procedure:\n%s", want, err)
		}
	}
}

func TestPeerControlAddressRenumberRefusedAtCommit_18630(t *testing.T) {
	store := peerControlAddrStore18630(t, peerControlAddrNew18630)
	candidate, _, _ := store.CandidateGateSample()
	peerView, err := config.CompileConfigForNodeLenient(candidate, 1)
	if err != nil {
		t.Fatalf("precondition: compile candidate for peer node: %v", err)
	}
	if got := controlLinkState18606(peerView, "em0").addrs; len(got) != 1 || got[0] != peerControlAddrNew18630 {
		t.Fatalf("precondition: peer view renders em0 addresses %v, want [%s]", got, peerControlAddrNew18630)
	}

	activeBefore := store.ActiveTree().Format()
	candidateBefore := store.CandidateTree().Format()
	d := runningPeerControlDaemon18630(store)
	_, err = d.commitAndApply(context.Background(), configstore.InternalCommitter(), "renumber peer control link", peerSyncNever)
	requirePeerControlAddressRefusal18630(t, err)
	if got := store.ActiveTree().Format(); got != activeBefore {
		t.Fatalf("refused peer-address renumber changed active config:\n--- before\n%s\n--- after\n%s", activeBefore, got)
	}
	if got := store.CandidateTree().Format(); got != candidateBefore {
		t.Fatalf("refused peer-address renumber changed candidate config:\n--- before\n%s\n--- after\n%s", candidateBefore, got)
	}
}

func TestPeerControlAddressRenumberRefusedAtCommitConfirmed_18630(t *testing.T) {
	store := peerControlAddrStore18630(t, peerControlAddrNew18630)
	activeBefore := store.ActiveTree().Format()
	candidateBefore := store.CandidateTree().Format()
	d := runningPeerControlDaemon18630(store)
	_, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 5, peerSyncNever)
	requirePeerControlAddressRefusal18630(t, err)
	if got := store.ActiveTree().Format(); got != activeBefore {
		t.Fatalf("refused confirmed peer-address renumber changed active config:\n--- before\n%s\n--- after\n%s", activeBefore, got)
	}
	if got := store.CandidateTree().Format(); got != candidateBefore {
		t.Fatalf("refused confirmed peer-address renumber changed candidate config:\n--- before\n%s\n--- after\n%s", candidateBefore, got)
	}
}

func TestPeerControlAddressUnchangedCommitPasses_18630(t *testing.T) {
	store := peerControlAddrStore18630(t, peerControlAddrOld18630)
	d := runningPeerControlDaemon18630(store)
	compiled, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "unrelated candidate edit", peerSyncNever)
	if err != nil {
		t.Fatalf("unchanged peer control address must pass commit: %v", err)
	}
	if compiled == nil || compiled.System.HostName != "candidate-18630" {
		t.Fatalf("commit returned compiled config %+v, want candidate-18630", compiled)
	}
	activeTree := store.ActiveTree()
	peerView, err := config.CompileConfigForNodeLenient(activeTree, 1)
	if err != nil {
		t.Fatalf("compile committed peer view: %v", err)
	}
	if got := controlLinkState18606(peerView, "em0").addrs; len(got) != 1 || got[0] != peerControlAddrOld18630 {
		t.Fatalf("committed peer view renders em0 addresses %v, want unchanged [%s]", got, peerControlAddrOld18630)
	}
}

func TestPeerControlAddressDHCPAndForeignBindingsPassBothCommitPaths18630(t *testing.T) {
	for _, tc := range []struct {
		name     string
		peerAddr string
		newStore func(*testing.T) *configstore.Store
	}{
		{"DHCP-derived peer address", "10.99.14.2", peerControlAddrDHCPStore18630},
		{"foreign peer address", peerControlAddrForeign18630, peerControlAddrForeignStore18630},
	} {
		for _, entry := range []struct {
			name      string
			confirmed bool
		}{
			{"plain commit", false},
			{"confirmed commit", true},
		} {
			t.Run(tc.name+"/"+entry.name, func(t *testing.T) {
				store := tc.newStore(t)
				activePeerView, err := config.CompileConfigForNodeLenient(store.ActiveTree(), 1)
				if err != nil {
					t.Fatalf("compile running peer view: %v", err)
				}
				runningAddrs := controlLinkState18606(activePeerView, "em0").addrs
				peerIP := net.ParseIP(tc.peerAddr)
				if cidrListHasIP18606(runningAddrs, peerIP) {
					t.Fatalf("precondition: running peer address %s unexpectedly appears in static control addresses %v",
						tc.peerAddr, runningAddrs)
				}
				candidatePeerView, err := config.CompileConfigForNodeLenient(store.CandidateTree(), 1)
				if err != nil {
					t.Fatalf("compile candidate peer view: %v", err)
				}
				candidateAddrs := controlLinkState18606(candidatePeerView, "em0").addrs
				if cidrListHasIP18606(candidateAddrs, peerIP) {
					t.Fatalf("precondition: candidate unexpectedly renders running peer address %s in %v",
						tc.peerAddr, candidateAddrs)
				}
				if strings.Join(runningAddrs, ",") != strings.Join(candidateAddrs, ",") {
					t.Fatalf("precondition: unrelated candidate changed control addresses: running=%v candidate=%v",
						runningAddrs, candidateAddrs)
				}

				d := runningPeerControlDaemonWithPeerAddr18630(store, tc.peerAddr)
				if entry.confirmed {
					_, err = d.commitConfirmedAndApply(
						context.Background(), configstore.InternalCommitter(), 5, peerSyncNever)
				} else {
					_, err = d.commitAndApply(
						context.Background(), configstore.InternalCommitter(), "unrelated candidate edit", peerSyncNever)
				}
				if err != nil {
					t.Fatalf("%s must pass when the heartbeat address is not statically configured in the running peer view: %v",
						entry.name, err)
				}
			})
		}
	}
}

func TestPeerOnlyRetiredDataplaneTypePassesControlAddressPreflight18630(t *testing.T) {
	store := peerControlAddrStore18630(t, peerControlAddrOld18630)
	if err := store.SetFromInput("groups node1 system dataplane-type dpdk"); err != nil {
		t.Fatalf("set retired dataplane type only on peer: %v", err)
	}
	candidateBefore := store.CandidateTree().Format()
	if !strings.Contains(candidateBefore, "dataplane-type dpdk") {
		t.Fatalf("precondition: candidate does not contain peer-only dpdk leaf: %s", candidateBefore)
	}

	d := runningPeerControlDaemon18630(store)
	if _, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(),
		"peer-only retired dataplane leaf", peerSyncNever); err != nil {
		t.Fatalf("peer-only dpdk leaf is stripped by peer-sync ingress and must pass the control-address gate: %v", err)
	}
	if active := store.ActiveTree().Format(); !strings.Contains(active, "dataplane-type dpdk") {
		t.Fatalf("peer-ingest normalization mutated the operator's committed tree: %s", active)
	}
}
