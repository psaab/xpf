package daemon

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"golang.org/x/sync/semaphore"
)

// #18606: a live renumber of THIS node's control-link address (same interface,
// same peer) passed every #8965-family gate, applied, and partitioned the pair.
// FAIL-ON-REVERT: neuter clusterControlLocalAddressCommitPreflight to `return
// nil` and every refusal cell below reds; drop its call from any one of the
// three apply paths and both that path's behaviour cell and the wiring census
// red; make it refuse when nothing is running and the first-commit cell reds.

func TestControlLocalAddressDecision18606(t *testing.T) {
	for _, tc := range []struct {
		name      string
		have      string
		candidate []string
		refuse    bool
	}{
		{"renumber is refused", "10.99.14.1", []string{"10.99.14.5/30"}, true},
		{"unchanged passes", "10.99.14.1", []string{"10.99.14.1/30"}, false},
		{"a mask change alone passes", "10.99.14.1", []string{"10.99.14.1/29"}, false},
		{"still configured beside a new address passes", "10.99.14.1", []string{"192.0.2.9/24", "10.99.14.1/30"}, false},
		{"removing the bound address but keeping another is refused", "10.99.14.1", []string{"192.0.2.9/24"}, true},
		{"no running heartbeat abstains (boot, first commit)", "", []string{"10.99.14.5/30"}, false},
		{"no static address abstains (DHCP control link)", "10.99.14.1", nil, false},
		{"IPv6 renumber is refused", "2001:db8:14::1", []string{"2001:db8:14::5/64"}, true},
		{"IPv6 unchanged passes", "2001:db8:14::1", []string{"2001:db8:14::1/64"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := controlLocalAddressDecision18606(tc.have, tc.candidate, "10.99.14.2")
			if tc.refuse && err == nil {
				t.Errorf("have=%q candidate=%v must be REFUSED: the running heartbeat's address "+
					"would no longer exist on the control link", tc.have, tc.candidate)
			}
			if !tc.refuse && err != nil {
				t.Errorf("have=%q candidate=%v is not a live renumber and must pass: %v",
					tc.have, tc.candidate, err)
			}
		})
	}
}

func TestControlLocalAddressRefusalNamesTheProcedure18606(t *testing.T) {
	err := controlLocalAddressDecision18606("10.99.14.1", []string{"10.99.14.5/30"}, "10.99.14.2")
	if err == nil {
		t.Fatal("a live control-address renumber must be refused")
	}
	for _, want := range []string{"10.99.14.1", "10.99.14.5", "BOTH nodes", "restart", "Do NOT", "separately", "partitioned"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must contain %q (the #8965 procedure and its warning):\n%s", want, err)
		}
	}
}

// localAddrCfgLines18606 is a running clustered node 0 whose control link em0
// carries addr. The address sits at the top level here; the shipped configs put
// it in `groups node0`, which compiles to the same unit address.
func localAddrCfgLines18606(addr string) []string {
	return []string{
		"chassis cluster cluster-id 1",
		"chassis cluster node 0",
		"chassis cluster authentication-key test-cluster-psk-18606",
		"chassis cluster control-interface em0",
		"chassis cluster peer-address 10.99.14.2",
		"interfaces em0 unit 0 family inet address " + addr,
	}
}

func compiledCfg18606(t *testing.T, lines []string) *config.Config {
	t.Helper()
	sets := make([]string, len(lines))
	for i, l := range lines {
		sets[i] = "set " + l
	}
	return testStoreWithSetConfig(t, sets).ActiveConfig()
}

// The PREFLIGHT reads the running heartbeat's bound address and the candidate's
// configured one: drive it with a real Manager.
func TestControlLocalAddressPreflightReadsTheRunningBind18606(t *testing.T) {
	running := cluster.NewManager(0, 1)
	renumbered := compiledCfg18606(t, localAddrCfgLines18606("10.99.14.5/30"))
	unchanged := compiledCfg18606(t, localAddrCfgLines18606("10.99.14.1/30"))

	// First commit / boot: the manager exists, the heartbeat never started.
	if err := clusterControlLocalAddressCommitPreflight(running, renumbered); err != nil {
		t.Fatalf("with no running heartbeat (boot, first cluster commit) the gate must abstain: %v", err)
	}
	running.SetHeartbeatEndpointForTesting("10.99.14.1", "10.99.14.2", "em0")
	if err := clusterControlLocalAddressCommitPreflight(running, unchanged); err != nil {
		t.Fatalf("an unchanged control address must pass: %v", err)
	}
	if err := clusterControlLocalAddressCommitPreflight(running, renumbered); err == nil {
		t.Fatal("renumbering the control link under a heartbeat bound to 10.99.14.1 must be refused")
	}
	if err := clusterControlLocalAddressCommitPreflight(nil, renumbered); err != nil {
		t.Fatalf("no running cluster manager must abstain: %v", err)
	}
}

// committedLocalAddrStore18606 commits node 0 with em0 at 10.99.14.1/30 and
// stages a candidate that renumbers it to 10.99.14.5/30.
func committedLocalAddrStore18606(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for _, l := range localAddrCfgLines18606("10.99.14.1/30") {
		if err := store.SetFromInput(l); err != nil {
			t.Fatalf("set %q: %v", l, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit running config: %v", err)
	}
	if err := store.DeleteFromInput("interfaces em0 unit 0 family inet address 10.99.14.1/30"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFromInput("interfaces em0 unit 0 family inet address 10.99.14.5/30"); err != nil {
		t.Fatal(err)
	}
	return store
}

func activeEm0Addrs18606(store *configstore.Store) []string {
	return controlLinkStaticAddrs18606(store.ActiveConfig(), "em0")
}

func runningLocalAddrDaemon18606(store *configstore.Store) *Daemon {
	running := cluster.NewManager(0, 1)
	running.SetHeartbeatEndpointForTesting("10.99.14.1", "10.99.14.2", "em0")
	return &Daemon{store: store, applySem: semaphore.NewWeighted(1), cluster: running}
}

func requireLocalAddrRefusal18606(t *testing.T, path string, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "control-link address from 10.99.14.1 to 10.99.14.5") {
		t.Fatalf("%s of a live control-address renumber must be refused by the #18606 gate; got %v", path, err)
	}
}

func TestControlAddressRenumberRefusedByCommit18606(t *testing.T) {
	store := committedLocalAddrStore18606(t)
	d := runningLocalAddrDaemon18606(store)
	_, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "renumber em0", peerSyncNever)
	requireLocalAddrRefusal18606(t, "commitAndApply", err)
	if got := activeEm0Addrs18606(store); len(got) != 1 || got[0] != "10.99.14.1/30" {
		t.Fatalf("a refused renumber promoted the candidate: active em0 = %v", got)
	}
}

func TestControlAddressRenumberRefusedByCommitConfirmed18606(t *testing.T) {
	store := committedLocalAddrStore18606(t)
	d := runningLocalAddrDaemon18606(store)
	_, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 5, peerSyncNever)
	requireLocalAddrRefusal18606(t, "commitConfirmedAndApply", err)
	if got := activeEm0Addrs18606(store); len(got) != 1 || got[0] != "10.99.14.1/30" {
		t.Fatalf("a refused confirmed renumber promoted the candidate: active em0 = %v", got)
	}
}

// The peer-synced path: a synced text that renumbers THIS node is refused
// before the live apply. SyncApply has already promoted it (as on #8965's
// synced path); the refusal keeps the running comms on the address the peer
// targets, and a restart applies the promoted text.
func TestControlAddressRenumberRefusedBySyncedApply18606(t *testing.T) {
	store := committedLocalAddrStore18606(t)
	store.ExitConfigure()
	d := runningLocalAddrDaemon18606(store)
	text := `chassis { cluster { cluster-id 1; node 0; authentication-key test-cluster-psk-18606;
	control-interface em0; peer-address 10.99.14.2; } }
interfaces { em0 { unit 0 { family inet { address 10.99.14.5/30; } } } }
`
	_, err := d.syncAndApplyWithAncestry(context.Background(), text, nil, nil)
	requireLocalAddrRefusal18606(t, "syncAndApplyWithAncestry", err)
}

// The steady-state peer sync carries THIS node's unchanged address (the
// shipped configs keep it in the per-node group), so it must not trip.
func TestPeerSyncedSameAddressDoesNotTrip18606(t *testing.T) {
	running := cluster.NewManager(0, 1)
	running.SetHeartbeatEndpointForTesting("10.99.14.1", "10.99.14.2", "em0")
	synced := compiledCfg18606(t, []string{
		"groups node0 interfaces em0 unit 0 family inet address 10.99.14.1/30",
		"groups node1 interfaces em0 unit 0 family inet address 10.99.14.2/30",
		`apply-groups "${node}"`,
		"chassis cluster cluster-id 1",
		"chassis cluster node 0",
		"chassis cluster authentication-key test-cluster-psk-18606",
		"chassis cluster control-interface em0",
		"chassis cluster peer-address 10.99.14.2",
	})
	if got := controlLinkStaticAddrs18606(synced, "em0"); len(got) != 1 || got[0] != "10.99.14.1/30" {
		t.Fatalf("precondition: the per-node group compiled em0 to %v, want [10.99.14.1/30] for node 0", got)
	}
	if err := clusterControlLocalAddressCommitPreflight(running, synced); err != nil {
		t.Fatalf("a steady-state synced text (per-node address unchanged) was refused: %v", err)
	}
}

// ALL THREE APPLY PATHS, structurally, against the #8965 sibling as control —
// the shape #8987 uses for the same family.
func TestControlLocalAddressGateIsWiredAtEveryApplyPath18606(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "daemon_apply_commit.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, sibling := map[string]int{}, map[string]int{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok {
				switch id.Name {
				case "clusterControlLocalAddressCommitPreflight":
					got[fn.Name.Name]++
				case "clusterControlEndpointCommitPreflight":
					sibling[fn.Name.Name]++
				}
			}
			return true
		})
	}
	if len(sibling) != 3 {
		t.Fatalf("the #8965 sibling is wired at %d functions (%v), not 3: the apply paths moved", len(sibling), sibling)
	}
	for path := range sibling {
		if got[path] != 1 {
			t.Errorf("%s runs the #8965 peer-address gate but the #18606 local-address gate %d times, want 1",
				path, got[path])
		}
	}
	for path := range got {
		if sibling[path] == 0 {
			t.Errorf("%s runs the #18606 gate without its #8965 sibling", path)
		}
	}
}
