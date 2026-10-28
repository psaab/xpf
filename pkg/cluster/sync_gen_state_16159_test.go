package cluster

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #16159 (W2.6) pins for the SessionSync sub-struct extraction.
//
// The structural claim of the PR is that generation-guard storage and
// peer-snapshot storage each live behind exactly one named sub-struct with
// a lock-local boundary, and that the #9915 genGuard* cap counters were NOT
// renamed into collision with it. These tests make that claim fail on
// revert: flattening a field back onto SessionSync, or renaming a cap
// counter onto the struct name, reds here even if every behavioral test
// still passes.

// sessionSyncFieldNames returns the direct field names of SessionSync.
func sessionSyncFieldNames(t *testing.T) map[string]reflect.StructField {
	t.Helper()
	typ := reflect.TypeOf(SessionSync{})
	out := make(map[string]reflect.StructField, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		out[f.Name] = f
	}
	return out
}

func TestSessionSyncSubStructs16159(t *testing.T) {
	fields := sessionSyncFieldNames(t)

	gen, ok := fields["genState"]
	if !ok {
		t.Fatal("SessionSync has no genState field: the generation-guard domain is not extracted (#16159)")
	}
	if gen.Type != reflect.TypeOf(sessionGenState{}) {
		t.Fatalf("genState type = %s, want sessionGenState (value field, not a pointer: zero SessionSync literals must stay usable)", gen.Type)
	}
	snaps, ok := fields["peerSnaps"]
	if !ok {
		t.Fatal("SessionSync has no peerSnaps field: the peer-snapshot domain is not extracted (#16159)")
	}
	if snaps.Type != reflect.TypeOf(peerSnapshotState{}) {
		t.Fatalf("peerSnaps type = %s, want peerSnapshotState (value field, not a pointer)", snaps.Type)
	}

	// Every generation/peer field must live on the sub-struct, and none may
	// remain directly on SessionSync (a flattened duplicate would split the
	// lock domain the extraction exists to create).
	genFields := []string{
		"genCounter", "genSentMu", "genSentV4", "genSentV6",
		"genSentScopedV4", "genSentScopedV6", "genSentScopedByTupleV4", "genSentScopedByTupleV6",
		"genSentOverflowV4", "genSentOverflowV6", "genSentOverflowScopedV4", "genSentOverflowScopedV6",
		"sentGenGuardCap", "recvGenGuardCap", "genGuardSessionCap", "genGuardMapCeilingOverride",
		"testGenCapAfterCeilingRead",
		"closeClassSentV4", "closeClassSentV6", "tcpHandshakeSentV4", "tcpHandshakeSentV6",
		"installTableSentV4", "installTableSentV6", "sourceNatICMPSentV4", "sourceNatICMPSentV6",
		"policyIdentitySentV4", "policyIdentitySentV6", "appTimeoutLogSentV4", "appTimeoutLogSentV6",
		"recvGenMu", "installTableRecvV4", "installTableRecvV6",
		"sourceNatICMPRecvV4", "sourceNatICMPRecvV6", "policyIdentityRecvV4", "policyIdentityRecvV6", "appTimeoutLogRecvV4", "appTimeoutLogRecvV6",
		"recvGenV4", "recvGenV6", "recvGenScopedV4", "recvGenScopedV6",
		"recvGenScopedByTupleV4", "recvGenScopedByTupleV6",
		"recvTombV4", "recvTombV6", "recvTombScopedV4", "recvTombScopedV6",
	}
	peerFields := []string{
		"peerIPsecSAs", "peerIPsecSAsMu",
		"peerDHCPLeases4", "peerDHCPLeases6", "peerDHCPLeaseSnapshot4", "peerDHCPLeaseSnapshot6",
		"peerDHCPLeases4RecvAt", "peerDHCPLeases6RecvAt", "peerDHCPLeasesMu",
		"peerSnapshotProtocol", "peerSnapshotProtocolWriteMu", "peerSnapshotProtocolGeneration",
	}
	genTyp := reflect.TypeOf(sessionGenState{})
	for _, name := range genFields {
		if _, flat := fields[name]; flat {
			t.Errorf("generation field %s is back directly on SessionSync; it belongs on sessionGenState", name)
		}
		if _, ok := genTyp.FieldByName(name); !ok {
			t.Errorf("sessionGenState is missing generation field %s", name)
		}
	}
	peerTyp := reflect.TypeOf(peerSnapshotState{})
	for _, name := range peerFields {
		if _, flat := fields[name]; flat {
			t.Errorf("peer-snapshot field %s is back directly on SessionSync; it belongs on peerSnapshotState", name)
		}
		if _, ok := peerTyp.FieldByName(name); !ok {
			t.Errorf("peerSnapshotState is missing peer field %s", name)
		}
	}
	// The lock-locality boundary in one check: each domain's mutexes live
	// with their data, not on the parent.
	if _, ok := genTyp.FieldByName("genSentMu"); !ok {
		t.Error("sessionGenState does not own genSentMu")
	}
	if _, ok := genTyp.FieldByName("recvGenMu"); !ok {
		t.Error("sessionGenState does not own recvGenMu")
	}
	for _, mu := range []string{"peerIPsecSAsMu", "peerDHCPLeasesMu", "peerSnapshotProtocolWriteMu"} {
		if _, ok := peerTyp.FieldByName(mu); !ok {
			t.Errorf("peerSnapshotState does not own %s", mu)
		}
	}
}

// TestNoGenGuardStructNameCollision16159 pins the naming decision the issue
// made mandatory: no cluster type may be named genGuard (or genGuard*
// as a TYPE), because genGuardMapCap / genGuardMapDefaultCap /
// genGuardSessionCap already name the #9915 cap counters. Verified against
// parsed type declarations, not a substring, so comments and the cap
// constants themselves cannot false-red it.
func TestNoGenGuardStructNameCollision16159(t *testing.T) {
	t.Parallel()
	if genGuardMapCap <= 0 || genGuardMapDefaultCap <= 0 {
		t.Fatalf("#9915 cap counters changed shape: genGuardMapCap=%d genGuardMapDefaultCap=%d", genGuardMapCap, genGuardMapDefaultCap)
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if strings.HasPrefix(ts.Name.Name, "genGuard") {
					t.Errorf("%s declares type %s, colliding with the #9915 genGuard* cap counters (#16159 naming rule)", name, ts.Name.Name)
				}
				if ts.Name.Name == "genGuard" {
					t.Errorf("%s declares the forbidden genGuard struct name (#16159)", name)
				}
			}
		}
	}
}

// TestZeroSessionSyncGenPeerDomainsUsable16159 proves the value-field
// invariant the extraction relies on: a SessionSync built by a bare literal
// (no constructor, as ~98 test literals do) has working generation and
// peer-snapshot domains. A pointer sub-struct would nil-panic here.
func TestZeroSessionSyncGenPeerDomainsUsable16159(t *testing.T) {
	ss := &SessionSync{}
	ss.initGenState()

	key := synthKeyV4(16159)
	if gen := ss.nextInstallGen(); gen == 0 {
		t.Fatal("nextInstallGen on a zero SessionSync returned 0")
	}
	val := dataplane.SessionValue{}
	ss.stampInstallGenV4(key, &val)
	gen := val.Generation
	if gen == 0 {
		t.Fatal("stampInstallGenV4 stamped generation 0 on a zero SessionSync")
	}
	if got := ss.SentInstallGenerationV4ForTesting(key); got != gen {
		t.Fatalf("sent stamp readback = %d, want %d", got, gen)
	}
	if _, apply := ss.installGenGuardV4(key, gen); !apply {
		t.Fatal("install guard refused the just-stamped generation on a zero SessionSync")
	}

	ss.SetPeerIPsecSAsForTesting([]string{"ike-peer-a"})
	if got := ss.PeerIPsecSAs(); len(got) != 1 || got[0] != "ike-peer-a" {
		t.Fatalf("PeerIPsecSAs = %v, want [ike-peer-a]", got)
	}
	ss.SetPeerSnapshotProtocolVersionForTesting(3)
	if got := ss.PeerSnapshotProtocolVersion(); got != 3 {
		t.Fatalf("PeerSnapshotProtocolVersion = %d, want 3", got)
	}
	ss.storePeerDHCPLeases(4, nil)
	if got := ss.PeerDHCPLeases4(); len(got) != 0 {
		t.Fatalf("PeerDHCPLeases4 = %v, want empty", got)
	}
	// A second bare literal must not share maps with the first (no
	// package-level storage snuck in behind the sub-struct).
	other := &SessionSync{}
	other.initGenState()
	if got := other.SentInstallGenerationV4ForTesting(key); got != 0 {
		t.Fatalf("fresh SessionSync sees another instance's stamp %d; generation storage is shared", got)
	}
}

// TestSessionSyncLockOrderGraphPinned16159 is the PR-0 pin: the lock-order
// graph on SessionSync must keep naming every SessionSync mutex and every
// documented nesting edge. Adding a mutex without documenting it, removing
// a documented edge, or renaming a sub-struct mutex reds here.
func TestSessionSyncLockOrderGraphPinned16159(t *testing.T) {
	t.Parallel()
	src := readClusterSource(t, "sync.go")

	// Every mutex field reachable from SessionSync (directly or via the two
	// sub-structs) must be named in the graph.
	mutexNames := []string{
		"mu", "writeMu", "preAuthMu", "queuedFrameMu",
		"peerSnaps.peerIPsecSAsMu", "peerSnaps.peerDHCPLeasesMu", "peerSnaps.peerSnapshotProtocolWriteMu",
		"fenceAckMu", "zoneRGMu", "deleteJournalMu", "bulkStartMu", "bulkSendMu",
		"bulkSnapshotGenMu", "bulkMu", "barrierWaitMu", "failoverWaitMu",
		"genState.genSentMu", "genState.recvGenMu", "applyMu",
		"configEpochRoleMu", "configGenMu", "configApplyMu", "recvSeqMu",
		"persistentNatLeaseApplyMu", "ipsecApplyMu", "dhcpApplyMu",
	}
	for _, name := range mutexNames {
		if !strings.Contains(src, name) {
			t.Errorf("lock-order graph / sync.go no longer names mutex %q; document it in the SessionSync lock-order graph (#16159 PR-0)", name)
		}
	}
	edges := []string{
		"mu -> peerSnapshotProtocolWriteMu",
		"peerSnapshotProtocolWriteMu -> writeMu",
		"mu -> fenceAckMu",
		"bulkSnapshotGenMu -> genSentMu",
		"bulkSnapshotGenMu -> recvGenMu",
		"genSentMu -> recvGenMu",
		"applyMu -> recvGenMu",
		"dhcpApplyMu -> recvSeqMu",
		"ipsecApplyMu -> recvSeqMu",
		"persistentNatLeaseApplyMu -> recvSeqMu",
		"recvSeqMu -> peerDHCPLeasesMu",
		"dhcpApplyMu -> peerDHCPLeasesMu",
	}
	for _, edge := range edges {
		if !strings.Contains(src, edge) {
			t.Errorf("lock-order graph is missing documented edge %q; if the nesting really changed, update the graph and this pin together (#16159 PR-0)", edge)
		}
	}
	if !strings.Contains(src, "sessionGenState") || !strings.Contains(src, "peerSnapshotState") {
		t.Error("lock-order graph no longer names the sessionGenState/peerSnapshotState boundaries")
	}
}
