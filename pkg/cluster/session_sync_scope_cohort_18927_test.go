package cluster

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// captureSyncedRows18927 observes the exact value delivered by handleMessage's
// production receive/install path without projecting away its sync-only folds.
type captureSyncedRows18927 struct {
	dataplane.SessionStore
	rows map[dataplane.SessionKey]dataplane.SessionValue
}

func (s *captureSyncedRows18927) PutClusterSyncedV4(key dataplane.SessionKey, val dataplane.SessionValue) error {
	s.rows[key] = val
	return nil
}

// The matching userspace test byte-compares request-builder output. These
// consumers are separate because the sender/receiver are private to cluster
// while the request builder is private to userspace (and cluster imports
// userspace); the shared fixture is the cross-package contract.

func TestSessionSyncScopeCohortSenderWireReceiver18927(t *testing.T) {
	foldReth080 := config.StableIfaceID("reth0.80")
	foldReth180 := config.StableIfaceID("reth1.80")
	foldUnknownScope := config.StableIfaceID("unresolved-scope0.80")
	if foldReth080 == 0 || foldReth180 == 0 || foldUnknownScope == 0 ||
		foldReth080 == foldReth180 || foldReth080 == foldUnknownScope || foldReth180 == foldUnknownScope {
		t.Fatal("controlled cohort interface folds are zero or collided")
	}
	rows := []struct {
		name          string
		ingressIfindex uint32
		scopeIfindex  int32
		fabric        bool
		legacyTail    bool
		wantIdentity  bool
		wantScope     bool
	}{
		{"scope_present_identity_bearing", 20, 22, false, false, true, true},
		{"scopeless_identity_bearing_zero_scope_fold", 20, 0, false, false, true, false},
		{"scopeless_identity_bearing_unknown_scope_fold", 20, 23, false, false, true, false},
		{"scopeless_identity_bearing_legacy_tail", 20, 22, false, true, true, false},
		{"scopeless_unresolved_ingress_fold", 30, 0, false, false, false, false},
		{"scopeless_no_ingress_fold", 0, 0, false, false, false, false},
		{"scopeless_fabric_ingress", 0, 0, true, false, false, false},
		{"scope_present_unresolved_ingress_fold", 30, 22, false, false, false, true},
		{"scope_present_no_ingress_fold", 0, 22, false, false, false, true},
	}

	fixture, err := os.ReadFile("../dataplane/userspace/testdata/session_sync_scope_cohort_18927.jsonl")
	if err != nil {
		t.Fatalf("read retained request fixture: %v", err)
	}
	var requests []userspace.SessionSyncRequest
	sc := bufio.NewScanner(bytes.NewReader(fixture))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var req userspace.SessionSyncRequest
		if err := json.Unmarshal(line, &req); err != nil {
			t.Fatalf("decode retained request fixture row %d: %v", len(requests), err)
		}
		requests = append(requests, req)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan retained request fixture: %v", err)
	}
	if len(requests) != len(rows) {
		t.Fatalf("retained requests=%d, sender/receiver cohort rows=%d; want 9 each", len(requests), len(rows))
	}

	sender := NewSessionSync(":0", ":0", nil)
	sender.SetIngressFoldFn(func(ifindex uint32, vlan uint16) uint32 {
		switch {
		case ifindex == 20 && vlan == 80:
			return foldReth080
		case ifindex == 30 && vlan == 80:
			return foldReth180
		default:
			return 0
		}
	})
	sender.SetNatScopeFoldFn(func(ifindex int32) uint32 {
		switch ifindex {
		case 22:
			return foldReth080
		case 23:
			return foldUnknownScope
		default:
			return 0
		}
	})
	// A fixed generator makes the real stampInstallGenV4 path reproducible in
	// this retained fixture lane: install stamps are 3..11 and the optional
	// config epoch remains unstamped.
	sender.genState.genCounter.Store(2)
	sender.configGenCounter.Store(0)
	sender.SetConnectedForTesting(true)

	capture := &captureSyncedRows18927{rows: make(map[dataplane.SessionKey]dataplane.SessionValue, len(rows))}
	receiver := NewSessionSync(":0", ":0", nil)
	receiver.SetRuntimeDomains(capture, nil)

	for i, row := range rows {
		key := dataplane.SessionKey{
			SrcIP: [4]byte{10, 0, 0, byte(i + 1)}, DstIP: [4]byte{172, 16, 0, 1},
			SrcPort: sessionSyncScopePort18927(12345), DstPort: sessionSyncScopePort18927(80), Protocol: 6,
		}
		val := dataplane.SessionValue{
			State: dataplane.SessStateEstablished,
			Flags: dataplane.SessFlagSNAT | dataplane.WithSourceNatProvenance(0, dataplane.SourceNatProvenanceDynamic),
			NATSrcIP: binary.NativeEndian.Uint32([]byte{10, 0, 0, 100}),
			NATSrcPort: sessionSyncScopePort18927(40000),
			IngressZone: 1, EgressZone: 2,
			IngressIfindex: row.ingressIfindex, IngressVlanID: 80,
			NatScopeIfindex: row.scopeIfindex,
			FibIfindex: 20, FibVlanID: 80,
			TCPHandshakeState: dataplane.TCPHandshakeStateEstablished,
			LogFlags: func() uint8 {
				if row.fabric {
					return dataplane.LogFlagUserspaceFabricIngress
				}
				return 0
			}(),
		}

		var frame []byte
		if row.legacyTail {
			// The old peer's tail carries the handshake/egress extension but no
			// NatScopeFold. Run the production install stamp, then represent the
			// omitted extension by clearing that final fold before production
			// framing; the metadata tail remains the five-byte handshake/egress
			// suffix understood by the current decoder.
			sender.stampInstallGenV4(key, &val)
			val.NatScopeFold = 0
			frame = encodeSessionV4(key, val)
		} else {
			sender.QueueSessionV4(key, val)
			if len(sender.sendCh) == 0 {
				t.Fatalf("row %s: actual sender did not queue a session frame", row.name)
			}
			frame = <-sender.sendCh
		}
		if len(frame) < syncHeaderSize || frame[4] != syncMsgSessionV4 {
			t.Fatalf("row %s: sender emitted malformed/non-v4 frame", row.name)
		}
		if ok := receiver.handleMessage(nil, syncMsgSessionV4, frame[syncHeaderSize:]); !ok {
			t.Fatalf("row %s: production receive handler rejected sender frame", row.name)
		}
		got, found := capture.rows[key]
		if !found {
			t.Fatalf("row %s: production receive/install path did not deliver the value", row.name)
		}
		wantIngressFold := uint32(0)
		if row.ingressIfindex == 20 {
			wantIngressFold = foldReth080
		} else if row.ingressIfindex == 30 {
			wantIngressFold = foldReth180
		}
		wantScopeFold := uint32(0)
		if row.scopeIfindex == 22 {
			wantScopeFold = foldReth080
		} else if row.scopeIfindex == 23 {
			wantScopeFold = foldUnknownScope
		}
		if row.legacyTail {
			wantScopeFold = 0
		}
		if got.IngressIfaceFold != wantIngressFold || got.NatScopeFold != wantScopeFold || got.EgressIfaceFold != foldReth080 {
			t.Fatalf("row %s: received folds ingress=%#x scope=%#x egress=%#x, want %#x/%#x/%#x",
				row.name, got.IngressIfaceFold, got.NatScopeFold, got.EgressIfaceFold,
				wantIngressFold, wantScopeFold, foldReth080)
		}
		if got.Generation != uint64(i+3) {
			t.Fatalf("row %s: received install generation=%d, want %d", row.name, got.Generation, i+3)
		}
		if got.State != dataplane.SessStateEstablished ||
			dataplane.SourceNatProvenanceFromFlags(got.Flags) != dataplane.SourceNatProvenanceDynamic ||
			got.NATSrcIP != binary.NativeEndian.Uint32([]byte{10, 0, 0, 100}) ||
			got.NATSrcPort != sessionSyncScopePort18927(40000) ||
			got.IngressZone != 1 || got.EgressZone != 2 {
			t.Fatalf("row %s: decoded state/NAT/zones=%d/%d/%d/%d/%d/%d, want established/dynamic/10.0.0.100/40000/1/2",
				row.name, got.State, dataplane.SourceNatProvenanceFromFlags(got.Flags), got.NATSrcIP,
				got.NATSrcPort, got.IngressZone, got.EgressZone)
		}
		wantIngressIfindex, wantIngressVLAN, wantScopeIfindex := 0, uint16(0), int32(0)
		if row.wantIdentity {
			wantIngressIfindex, wantIngressVLAN = 20, 80
		}
		if row.wantScope {
			wantScopeIfindex = 22
		}
		if requests[i].Operation != "upsert" || requests[i].AddrFamily != dataplane.AFInet ||
			requests[i].Protocol != key.Protocol ||
			requests[i].SrcIP != net.IP(key.SrcIP[:]).String() ||
			requests[i].DstIP != net.IP(key.DstIP[:]).String() ||
			requests[i].SrcPort != 12345 || requests[i].DstPort != 80 ||
			requests[i].IngressZoneID != 1 || requests[i].EgressZoneID != 2 ||
			requests[i].IngressIfindex != wantIngressIfindex ||
			requests[i].IngressVLANID != wantIngressVLAN ||
			requests[i].NatScopeIfindex != wantScopeIfindex ||
			requests[i].OwnerRGID != 1 || requests[i].EgressIfindex != 22 ||
			requests[i].TXIfindex != 20 || requests[i].TXVLANID != 80 ||
			requests[i].NATSrcIP != "10.0.0.100" || requests[i].NATSrcPort != 40000 ||
			requests[i].SourceNatProvenance != dataplane.SourceNatProvenanceDynamic ||
			requests[i].FabricIngress != row.fabric ||
			requests[i].Generation != got.Generation ||
			requests[i].TCPHandshakeState != dataplane.TCPHandshakeStateEstablished {
			t.Fatalf("row %s: fixture request does not describe decoded sender/receiver row: %+v", row.name, requests[i])
		}
	}
}
func sessionSyncScopePort18927(port uint16) uint16 {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], port)
	return binary.NativeEndian.Uint16(raw[:])
}

