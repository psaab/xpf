package userspace

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// session_ingress_fold_import_7095_test.go — #7095, the RECEIVING half.
//
// The sender ships a fold of a name both chassis agree on; this side turns it
// back into a LOCAL {ifindex, vlan} before the helper stores it. The cells below
// bind that translation and, more importantly, the three ways it must decline.
//
// Declining matters more than resolving here. #6928 imported 0 on purpose,
// because naming the wrong NIC is worse than naming none — so every path that
// cannot be sure must reach 0, not a guess.

func managerWithFoldResolver7095(fn func(uint32) (uint32, uint16, bool)) *Manager {
	m := &Manager{}
	m.SetIngressFoldResolver(fn)
	return m
}

func TestImportResolvesFoldToLocalIfindex_7095(t *testing.T) {
	const fold = 0x51DE51DE
	m := managerWithFoldResolver7095(func(got uint32) (uint32, uint16, bool) {
		if got != fold {
			t.Errorf("resolver called with fold %#x, want %#x", got, fold)
		}
		return 42, 50, true
	})
	val := &dataplane.SessionValue{IngressIfaceFold: fold}
	req := m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{}, val)
	if req.IngressIfindex != 42 || req.IngressVLANID != 50 {
		t.Fatalf("import resolved to {ifindex:%d vlan:%d}, want {42 50} — the peer's "+
			"fold must become THIS node's numbers, which is the whole reason an "+
			"ifindex is not what crosses the wire (#7095)",
			req.IngressIfindex, req.IngressVLANID)
	}
}

// TestImportDeclinesRatherThanGuesses_7095 covers every path to "no identity".
// Each is a case where naming a device would be a confident lie.
func TestImportDeclinesRatherThanGuesses_7095(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fold     uint32
		resolver func(uint32) (uint32, uint16, bool)
	}{
		{
			// A legacy peer sends no wire field; it decodes to 0.
			name: "legacy_peer_absent_field", fold: 0,
			resolver: func(uint32) (uint32, uint16, bool) { return 9, 9, true },
		},
		{
			// #7096: a fabric-redirected session records no ingress identity,
			// because the fabric stamp carries a u16 zone id and nothing else —
			// the peer's real ingress interface is not knowable here at all.
			name: "fabric_redirected_records_nothing", fold: 0,
			resolver: func(uint32) (uint32, uint16, bool) { return 9, 9, true },
		},
		{
			// This node does not have the interface the peer named (its config
			// is ahead of ours), or two stable names collided on one fold.
			name: "unknown_or_ambiguous_fold", fold: 0x1234,
			resolver: func(uint32) (uint32, uint16, bool) { return 0, 0, false },
		},
		{
			// No resolver wired yet: the pre-#7095 behaviour, not an error.
			name: "resolver_unset", fold: 0x1234, resolver: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := managerWithFoldResolver7095(tc.resolver)
			val := &dataplane.SessionValue{IngressIfaceFold: tc.fold}
			req := m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{}, val)
			if req.IngressIfindex != 0 || req.IngressVLANID != 0 {
				t.Fatalf("import produced {ifindex:%d vlan:%d} for %s; it must be {0 0}. "+
					"A non-zero value here names a device on evidence this node does not "+
					"have, which is the confidently-wrong rendering #6928 refused to ship",
					req.IngressIfindex, req.IngressVLANID, tc.name)
			}
		})
	}
}

// TestImportResolvesFoldV6_7095: v6 sessions travel through a SEPARATE request
// builder. Wiring only v4 leaves every IPv6 session degraded after a failover
// with the v4 cells still green.
func TestImportResolvesFoldV6_7095(t *testing.T) {
	m := managerWithFoldResolver7095(func(uint32) (uint32, uint16, bool) { return 7, 80, true })
	val := &dataplane.SessionValueV6{IngressIfaceFold: 0xFEED}
	req := m.buildSessionSyncRequestV6("upsert", dataplane.SessionKeyV6{}, val)
	if req.IngressIfindex != 7 || req.IngressVLANID != 80 {
		t.Fatalf("v6 import resolved to {ifindex:%d vlan:%d}, want {7 80}",
			req.IngressIfindex, req.IngressVLANID)
	}
}

// #18927 child 2's request-builder consumer shares the retained fixture with
// the cluster sender/receive consumer. The packages keep those private paths
// separate (cluster depends on userspace, not vice versa); the fixture is their
// stable byte-level bridge.
func TestSessionSyncScopeCohortRequestBuilder18927(t *testing.T) {
	reth080 := config.StableIfaceID("reth0.80")
	unknownIngress := config.StableIfaceID("reth1.80")
	unknownScope := config.StableIfaceID("unresolved-scope0.80")
	if reth080 == 0 || unknownIngress == 0 || unknownScope == 0 ||
		reth080 == unknownIngress || reth080 == unknownScope || unknownIngress == unknownScope {
		t.Fatal("controlled cohort interface folds are zero or collided")
	}
	rows := []struct {
		name        string
		ingressFold uint32
		scopeFold   uint32
		fabric      bool
	}{
		{"scope_present_identity_bearing", reth080, reth080, false},
		{"scopeless_identity_bearing_zero_scope_fold", reth080, 0, false},
		{"scopeless_identity_bearing_unknown_scope_fold", reth080, unknownScope, false},
		{"scopeless_identity_bearing_legacy_tail", reth080, 0, false},
		{"scopeless_unresolved_ingress_fold", unknownIngress, 0, false},
		{"scopeless_no_ingress_fold", 0, 0, false},
		{"scopeless_fabric_ingress", 0, 0, true},
		{"scope_present_unresolved_ingress_fold", unknownIngress, reth080, false},
		{"scope_present_no_ingress_fold", 0, reth080, false},
	}

	raw, err := os.ReadFile("testdata/session_sync_scope_cohort_18927.jsonl")
	if err != nil {
		t.Fatalf("read cohort fixture: %v", err)
	}
	var fixtureLines [][]byte
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		fixtureLines = append(fixtureLines, append([]byte(nil), line...))
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan cohort fixture: %v", err)
	}
	if len(rows) != 9 || len(fixtureLines) != len(rows) {
		t.Fatalf("cohort cases=%d, fixture records=%d; want exactly 9 aligned records", len(rows), len(fixtureLines))
	}

	m := &Manager{
		bpfShim: dataplane.New(),
		lastSnapshot: &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
			{Name: "reth0.80", Ifindex: 22, ParentIfindex: 20, VLANID: 80, RedundancyGroup: 1},
		}},
	}
	m.SetIngressFoldResolver(func(fold uint32) (uint32, uint16, bool) {
		if fold == reth080 {
			return 20, 80, true
		}
		return 0, 0, false
	})

	identityBearing, scopePresent := 0, 0
	var classCounts [2][2]int // [identity-less, identity-bearing][scope-less, scope-present]
	for i, row := range rows {
		key := dataplane.SessionKey{
			SrcIP: [4]byte{10, 0, 0, byte(i + 1)}, DstIP: [4]byte{172, 16, 0, 1},
			SrcPort: hostToNetwork16(12345), DstPort: hostToNetwork16(80), Protocol: 6,
		}
		val := &dataplane.SessionValue{
			State: dataplane.SessStateEstablished,
			Flags: dataplane.SessFlagSNAT | dataplane.WithSourceNatProvenance(0, dataplane.SourceNatProvenanceDynamic),
			NATSrcIP: natU32("10.0.0.100"), NATSrcPort: hostToNetwork16(40000),
			IngressZone: 1, EgressZone: 2,
			IngressIfaceFold: row.ingressFold, NatScopeFold: row.scopeFold,
			EgressIfaceFold: reth080, TCPHandshakeState: dataplane.TCPHandshakeStateEstablished,
			Generation: uint64(i + 3),
		}
		if row.fabric {
			val.LogFlags = dataplane.LogFlagUserspaceFabricIngress
		}
		req := m.buildSessionSyncRequestV4("upsert", key, val)
		encoded, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("row %d (%s): marshal request: %v", i, row.name, err)
		}
		if !bytes.Equal(encoded, fixtureLines[i]) {
			t.Fatalf("row %d (%s): request JSON differs from fixture:\n got: %s\nwant: %s",
				i, row.name, encoded, fixtureLines[i])
		}

		identity := req.IngressIfindex != 0
		scope := req.NatScopeIfindex != 0
		identityClass, scopeClass := 0, 0
		if identity {
			identityClass = 1
		}
		if scope {
			scopeClass = 1
		}
		classCounts[identityClass][scopeClass]++
		if identity {
			identityBearing++
			if req.IngressIfindex != 20 || req.IngressVLANID != 80 {
				t.Fatalf("row %s: ingress identity=(%d,%d), want receiver-local (20,80)",
					row.name, req.IngressIfindex, req.IngressVLANID)
			}
		}
		if scope {
			scopePresent++
			if req.NatScopeIfindex != 22 {
				t.Fatalf("row %s: NAT scope ifindex=%d, want logical unit 22", row.name, req.NatScopeIfindex)
			}
		}
		if identity != (row.ingressFold == reth080) {
			t.Fatalf("row %s: identity-bearing=%t, ingress fold=%#x", row.name, identity, row.ingressFold)
		}
		if scope != (row.scopeFold == reth080) {
			t.Fatalf("row %s: scope-present=%t, scope fold=%#x", row.name, scope, row.scopeFold)
		}
		if req.FabricIngress != row.fabric {
			t.Fatalf("row %s: fabric_ingress=%t, want %t", row.name, req.FabricIngress, row.fabric)
		}
		if strings.HasPrefix(row.name, "scopeless") && scope {
			t.Fatalf("row %s is plan-defined scope-less but emitted nat_scope_ifindex=%d", row.name, req.NatScopeIfindex)
		}
		if strings.HasPrefix(row.name, "scope_present") && !scope {
			t.Fatalf("row %s is plan-defined scope-present but emitted no NAT scope", row.name)
		}
	}
	wantClassCounts := [2][2]int{{3, 2}, {3, 1}}
	if identityBearing != 4 || scopePresent != 3 || classCounts != wantClassCounts {
		t.Fatalf("cohort identity-bearing=%d scope-present=%d class-counts=%v, want 4/3 and %v",
			identityBearing, scopePresent, classCounts, wantClassCounts)
	}
}
