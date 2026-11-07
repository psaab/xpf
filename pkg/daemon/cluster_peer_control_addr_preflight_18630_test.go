package daemon

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"golang.org/x/sync/semaphore"
)

const (
	peerControlAddrOld18630 = "10.99.14.2/30"
	peerControlAddrNew18630 = "10.99.14.5/30"
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

func runningPeerControlDaemon18630(store *configstore.Store) *Daemon {
	running := cluster.NewManager(0, 1)
	running.SetHeartbeatEndpointForTesting("10.99.14.1", "10.99.14.2", "em0")
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
	if got := controlLinkStaticAddrs18606(peerView, "em0"); len(got) != 1 || got[0] != peerControlAddrNew18630 {
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
	if got := controlLinkStaticAddrs18606(peerView, "em0"); len(got) != 1 || got[0] != peerControlAddrOld18630 {
		t.Fatalf("committed peer view renders em0 addresses %v, want unchanged [%s]", got, peerControlAddrOld18630)
	}
}
