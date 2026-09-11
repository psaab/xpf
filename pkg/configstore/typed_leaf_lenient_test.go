package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #1319 PR 2 — boot safety for the typed-leaf gate.
//
// The SchemaValidate gate is strict ONLY on the operator-driven commit /
// commit-check path. A typed-leaf violation in an already-persisted config
// (written by an older binary, before the leaf was typed or its range
// tightened) must NOT fail Store.Load — a node with a bad stored value
// would otherwise boot with no active config (operational blackout).
// Same for Store.SyncApply (HA config sync from a possibly-un-upgraded
// primary must not alarm-loop). compileTreeLenient downgrades the gate to
// a warning on exactly those two paths.

// writeStoredConfig persists a flat-set-built tree directly through the
// DB, bypassing commit validation — simulating a config persisted by a
// pre-gate binary.
func writeStoredConfig(t *testing.T, cfgPath string, lines ...string) {
	t.Helper()
	writer := newTestStoreAt(t, cfgPath)
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	if err := writer.db.WriteActive(tree); err != nil {
		t.Fatalf("db.WriteActive: %v", err)
	}
}

// A stored typed-leaf GARBAGE value (the PR-1 schedulers leaves) must not
// fail boot. Before #1319 PR 2 this returned "compile config: ... invalid
// value \"asd\"" from Load, leaving the daemon with no active config.
func TestLoad_ToleratesStoredGarbageTypedLeaf(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config")
	writeStoredConfig(t, cfgPath,
		"set class-of-service schedulers be transmit-rate asd")

	s := newTestStoreAt(t, cfgPath)
	if err := s.Load(); err != nil {
		t.Fatalf("Load() must tolerate stored typed-leaf garbage, got: %v", err)
	}
	if s.ActiveConfig() == nil {
		t.Fatal("ActiveConfig() is nil after tolerated Load")
	}

	// The next STRICT operator commit must still reject the stale value.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("CommitCheck must stay strict after a tolerated Load, got nil")
	}
	if !strings.Contains(err.Error(), "transmit-rate") {
		t.Fatalf("CommitCheck error should reference transmit-rate: %v", err)
	}
}

// HA config sync from a primary carrying a typed-leaf violation must not
// alarm-loop the standby: SyncApply uses the same lenient path as Load.
func TestSyncApply_ToleratesTypedLeafViolation(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	cfg, err := s.SyncApply(`class-of-service {
    schedulers {
        be {
            transmit-rate asd;
        }
    }
}`, nil)
	if err != nil {
		t.Fatalf("SyncApply must tolerate a typed-leaf violation, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("SyncApply returned nil config on tolerated violation")
	}
}

// #1319 PR 2 — an OUT-OF-RANGE chassis-cluster value in a stored config
// (legal when persisted; the range was typed later) must not fail boot.
// The compiler keeps accepting it verbatim, so running behavior is
// preserved; the warning surfaces the condition and the next strict
// commit rejects it. cluster-id 999 is the probe value: it violates the
// runtime-derived 0..255 bound (one byte of the RETH virtual MAC) but
// strconv.Atoi in compileChassis accepts it.
func TestLoad_ToleratesStoredOutOfRangeChassisLeaf(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config")
	writeStoredConfig(t, cfgPath,
		"set chassis cluster cluster-id 999",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster heartbeat-interval 200")

	s := newTestStoreAt(t, cfgPath)
	if err := s.Load(); err != nil {
		t.Fatalf("Load() must tolerate stored out-of-range cluster-id, got: %v", err)
	}
	active := s.ActiveConfig()
	if active == nil {
		t.Fatal("ActiveConfig() is nil after tolerated Load")
	}
	// Verbatim compile — running behavior preserved, no silent rewrite.
	if active.Chassis.Cluster == nil || active.Chassis.Cluster.ClusterID != 999 {
		t.Fatalf("stored out-of-range value must compile verbatim, got %+v", active.Chassis.Cluster)
	}

	// The next STRICT operator commit rejects the stale value.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("CommitCheck must reject the out-of-range stored value, got nil")
	}
	if !strings.Contains(err.Error(), "cluster-id") {
		t.Fatalf("CommitCheck error should reference cluster-id: %v", err)
	}
}

// Strict-path e2e for a chassis typed leaf: CommitCheck and Commit reject
// an out-of-range value entered by the operator.
func TestCommitCheck_RejectsOutOfRangeChassisLeaf(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("chassis cluster redundancy-group 1 node 0 priority 255"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("expected CommitCheck to reject priority 255 (VRRP owner-reserved), got nil")
	}
	if !strings.Contains(err.Error(), "priority") {
		t.Fatalf("CommitCheck error should reference priority: %v", err)
	}
	if _, err := s.Commit(); err == nil {
		t.Fatal("expected Commit to reject priority 255, got nil")
	}
}

// #1319 PR 3 — boot safety for the system typed leaves. A stored
// unknown poll-mode was silently ignored before the enum was typed; it
// must keep booting (warn only) and be rejected by the next strict
// commit.
func TestLoad_ToleratesStoredUnknownPollMode(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config")
	writeStoredConfig(t, cfgPath,
		"set system dataplane poll-mode polling")

	s := newTestStoreAt(t, cfgPath)
	if err := s.Load(); err != nil {
		t.Fatalf("Load() must tolerate a stored unknown poll-mode, got: %v", err)
	}
	if s.ActiveConfig() == nil {
		t.Fatal("ActiveConfig() is nil after tolerated Load")
	}

	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("CommitCheck must reject the stored unknown poll-mode, got nil")
	}
	if !strings.Contains(err.Error(), "poll-mode") {
		t.Fatalf("CommitCheck error should reference poll-mode: %v", err)
	}
}

// #1387 stale-lease-cleanup slice (Path S) — boot/HA safety (invariant
// H7 / R4). A stored config that committed an expired-leases-processing
// timer of 0 BEFORE the Min(1) floor existed (or a peer-synced config from
// an un-upgraded primary) must still LOAD — the schema gate downgrades to a
// warning on the tolerant Load / SyncApply path. The compiler (the shared
// compileExpanded core) lands the block on both strict and lenient sites,
// so the block is present in the loaded active config, and the next strict
// operator commit rejects the bad value loudly.
func TestLoad_ToleratesStoredExpiredLeasesTimerZero(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config")
	writeStoredConfig(t, cfgPath,
		"set system services dhcp-local-server expired-leases-processing enable",
		"set system services dhcp-local-server expired-leases-processing reclaim-timer 0")

	s := newTestStoreAt(t, cfgPath)
	if err := s.Load(); err != nil {
		t.Fatalf("Load() must tolerate a stored expired-leases timer 0, got: %v", err)
	}
	active := s.ActiveConfig()
	if active == nil {
		t.Fatal("ActiveConfig() is nil after tolerated Load")
	}
	// The block must be present (compiled on the lenient path too — R4).
	ls := active.System.DHCPServer.DHCPLocalServer
	if ls == nil || ls.ExpiredLeases == nil || !ls.ExpiredLeases.Enabled {
		t.Fatalf("lenient Load dropped the expired-leases block: %+v", ls)
	}

	// The next STRICT operator commit must reject the bad timer.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("CommitCheck must reject the stored timer 0, got nil")
	}
	if !strings.Contains(err.Error(), "reclaim-timer") {
		t.Fatalf("CommitCheck error should reference reclaim-timer: %v", err)
	}
}

// HA config sync from a primary carrying a sub-floor timer must not
// alarm-loop the standby: SyncApply uses the same lenient path as Load.
func TestSyncApply_ToleratesExpiredLeasesTimerZero(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	cfg, err := s.SyncApply(`system {
    services {
        dhcp-local-server {
            expired-leases-processing {
                enable;
                reclaim-timer 0;
            }
        }
    }
}`, nil)
	if err != nil {
		t.Fatalf("SyncApply must tolerate a sub-floor expired-leases timer, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("SyncApply returned nil config on tolerated violation")
	}
}

// #1319 PR 3 — firewall forwarding-class cross-ref, end-to-end through
// the PRODUCTION gate path (Store commit-check / Load / SyncApply, the
// call sites that pass cfg=nil to SchemaValidate). These are the proving
// tests for the tree-based design: a dangling reference rejects at
// commit, a same-commit definition + reference passes (atomicity), and
// the same dangling reference WARN-boots through the tolerant paths.

func TestCommitCheck_RejectsDanglingForwardingClass(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("firewall family inet filter f1 term t1 then forwarding-class no-such-class"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("expected CommitCheck to reject the dangling forwarding-class, got nil")
	}
	if !strings.Contains(err.Error(), "no-such-class") {
		t.Fatalf("CommitCheck error should name the dangling class: %v", err)
	}
	if _, err := s.Commit(); err == nil {
		t.Fatal("expected Commit to reject the dangling forwarding-class, got nil")
	}
}

// Atomicity: the class definition and the reference land in the SAME
// commit and must validate against each other — the tree-based refs are
// collected from the candidate tree itself, never from compiled state.
func TestCommitCheck_AcceptsSameCommitForwardingClass(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"class-of-service forwarding-classes queue 5 iperf-video",
		"firewall family inet filter f1 term t1 then forwarding-class iperf-video",
	} {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
	if _, err := s.CommitCheck(); err != nil {
		t.Fatalf("same-commit definition + reference must pass CommitCheck, got: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("same-commit definition + reference must Commit, got: %v", err)
	}
}

// A node-variable cluster config keeps its forwarding-class definitions
// inside `groups node0 { ... }` selected via `apply-groups ${node}`.
// The strict gate validates the EXPANDED tree (and the refs collection
// also unions group bodies), so this must never false-reject.
func TestCommitCheck_AcceptsGroupDefinedForwardingClass(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config")
	writeStoredConfig(t, cfgPath,
		"set groups node0 class-of-service forwarding-classes queue 5 iperf-video",
		// #9619: node1's group too. A clustered commit is now strict-checked on
		// the peer's view as well, and with only node0 defined node1's
		// `${node}` names an undefined group, which node1 cannot load.
		"set groups node1 class-of-service forwarding-classes queue 5 iperf-video",
		`set apply-groups "${node}"`,
		"set firewall family inet filter f1 term t1 then forwarding-class iperf-video")

	s := newTestStoreAt(t, cfgPath)
	s.SetNodeID(0)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := s.CommitCheck(); err != nil {
		t.Fatalf("group-defined forwarding-class must pass the strict gate, got: %v", err)
	}
}

// AGY r1 HIGH on PR #1886: apply-groups expansion REMOVES the groups
// stanza, so a forwarding-class defined ONLY in the PEER node's group
// (un-applied locally) used to vanish from the refs union — a shared
// firewall section referencing it would commit on node1 but falsely
// reject on node0, wedging cluster config sync. The strict gate now
// collects definitions from the PRE-expansion candidate too
// (SchemaValidateWithDefinitions).
func TestCommitCheck_AcceptsPeerNodeGroupForwardingClass(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config")
	writeStoredConfig(t, cfgPath,
		"set groups node0 system host-name fw0",
		"set groups node1 class-of-service forwarding-classes queue 5 iperf-video",
		`set apply-groups "${node}"`,
		"set firewall family inet filter f1 term t1 then forwarding-class iperf-video")

	s := newTestStoreAt(t, cfgPath)
	s.SetNodeID(0) // node1's group is NOT applied here
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := s.CommitCheck(); err != nil {
		t.Fatalf("peer-node group definition must satisfy the shared reference, got: %v", err)
	}
}

// A stored dangling reference (legal before the leaf was typed) must
// warn-boot, compile verbatim, and be rejected by the next strict commit.
func TestLoad_ToleratesStoredDanglingForwardingClass(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config")
	writeStoredConfig(t, cfgPath,
		"set firewall family inet filter f1 term t1 then forwarding-class no-such-class")

	s := newTestStoreAt(t, cfgPath)
	if err := s.Load(); err != nil {
		t.Fatalf("Load() must tolerate a stored dangling forwarding-class, got: %v", err)
	}
	active := s.ActiveConfig()
	if active == nil {
		t.Fatal("ActiveConfig() is nil after tolerated Load")
	}
	filter := active.Firewall.FiltersInet["f1"]
	if filter == nil || len(filter.Terms) != 1 || filter.Terms[0].ForwardingClass != "no-such-class" {
		t.Fatalf("stored dangling reference must compile verbatim, got %+v", filter)
	}

	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("CommitCheck must reject the stored dangling forwarding-class, got nil")
	}
	if !strings.Contains(err.Error(), "no-such-class") {
		t.Fatalf("CommitCheck error should name the dangling class: %v", err)
	}
}

// HA config sync carrying the dangling reference must not alarm-loop.
func TestSyncApply_ToleratesDanglingForwardingClass(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	cfg, err := s.SyncApply(`firewall {
    family inet {
        filter f1 {
            term t1 {
                then {
                    forwarding-class no-such-class;
                }
            }
        }
    }
}`, nil)
	if err != nil {
		t.Fatalf("SyncApply must tolerate a dangling forwarding-class, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("SyncApply returned nil config on tolerated violation")
	}
}

// #1319 PR 3 — boot safety for the interfaces typed leaves. A stored
// bare (prefix-less) interface address was legal before the address key
// slot was typed; it must keep booting (warn only), compile verbatim,
// and be rejected by the next strict operator commit.
func TestLoad_ToleratesStoredBareInterfaceAddress(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config")
	writeStoredConfig(t, cfgPath,
		"set interfaces ge-0-0-0 unit 0 family inet address 10.0.1.10",
		"set interfaces ge-0-0-0 mtu 1500")

	s := newTestStoreAt(t, cfgPath)
	if err := s.Load(); err != nil {
		t.Fatalf("Load() must tolerate a stored bare interface address, got: %v", err)
	}
	active := s.ActiveConfig()
	if active == nil {
		t.Fatal("ActiveConfig() is nil after tolerated Load")
	}
	ifc := active.Interfaces.Interfaces["ge-0-0-0"]
	if ifc == nil || ifc.Units[0] == nil ||
		len(ifc.Units[0].Addresses) != 1 || ifc.Units[0].Addresses[0] != "10.0.1.10" {
		t.Fatalf("stored bare address must compile verbatim, got %+v", ifc)
	}

	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("CommitCheck must reject the stored bare address, got nil")
	}
	if !strings.Contains(err.Error(), "address") {
		t.Fatalf("CommitCheck error should reference address: %v", err)
	}
}

// #2105 — boot safety for the route-filter prefix CIDR validator. A
// stored MALFORMED route-filter prefix (legal when persisted by a
// pre-#2105 binary, before the keyValidator existed) must NOT fail
// Store.Load — it must WARN-boot (lenient path) so the standby/upgraded
// node keeps an active config, while the next STRICT operator commit
// rejects it. The FRR renderer's belt-and-suspenders skip keeps the
// stored garbage from reaching an FRR line meanwhile.
func TestLoad_ToleratesStoredMalformedRouteFilterPrefix(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config")
	writeStoredConfig(t, cfgPath,
		"set policy-options policy-statement P term T from route-filter 10.0.0.0 exact")

	s := newTestStoreAt(t, cfgPath)
	if err := s.Load(); err != nil {
		t.Fatalf("Load() must tolerate a stored malformed route-filter prefix, got: %v", err)
	}
	if s.ActiveConfig() == nil {
		t.Fatal("ActiveConfig() is nil after tolerated Load")
	}

	// The next STRICT operator commit must still reject the stale value.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("CommitCheck must stay strict after a tolerated Load, got nil")
	}
	if !strings.Contains(err.Error(), "route-filter") {
		t.Fatalf("CommitCheck error should reference route-filter: %v", err)
	}
}

// #2105 — HA config sync from a primary carrying a malformed
// route-filter prefix must not alarm-loop the standby: SyncApply uses
// the same lenient path as Load.
func TestSyncApply_ToleratesMalformedRouteFilterPrefix(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	cfg, err := s.SyncApply(`policy-options {
    policy-statement P {
        term T {
            from {
                route-filter 10.0.0.0 exact;
            }
            then accept;
        }
    }
}`, nil)
	if err != nil {
		t.Fatalf("SyncApply must tolerate a malformed route-filter prefix, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("SyncApply returned nil config on tolerated violation")
	}
}

// #2105 — strict-path e2e: an operator committing a malformed
// route-filter prefix is rejected at both CommitCheck and Commit.
func TestCommitCheck_RejectsMalformedRouteFilterPrefix(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("policy-options policy-statement P term T from route-filter 10.0.0.0/99 exact"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitCheck(); err == nil {
		t.Fatal("expected CommitCheck to reject an out-of-range route-filter mask, got nil")
	}
	if _, err := s.Commit(); err == nil {
		t.Fatal("expected Commit to reject an out-of-range route-filter mask, got nil")
	}
}
