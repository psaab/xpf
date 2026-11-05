package cluster

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"reflect"
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

// The matching userspace test byte-compares production request-builder output
// to the shared fixture. This cluster-side test projects every request-effective
// captured SessionValue field into the fixture comparison, including the
// SessFlagSNAT-controlled NAT fields and zero-valued request fields, while
// checking receiver-local fold resolution without a production seam.

func TestSessionSyncScopeCohortSenderWireReceiver18927(t *testing.T) {
	foldReth080 := config.StableIfaceID("reth0.80")
	foldReth180 := config.StableIfaceID("reth1.80")
	foldUnknownScope := config.StableIfaceID("unresolved-scope0.80")
	if foldReth080 == 0 || foldReth180 == 0 || foldUnknownScope == 0 ||
		foldReth080 == foldReth180 || foldReth080 == foldUnknownScope || foldReth180 == foldUnknownScope {
		t.Fatal("controlled cohort interface folds are zero or collided")
	}
	rows := []struct {
		name           string
		ingressIfindex uint32
		scopeIfindex   int32
		fabric         bool
		legacyTail     bool
		wantIdentity   bool
		wantScope      bool
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
			State:       dataplane.SessStateEstablished,
			Flags:       dataplane.SessFlagSNAT | dataplane.WithSourceNatProvenance(0, dataplane.SourceNatProvenanceDynamic),
			NATSrcIP:    binary.NativeEndian.Uint32([]byte{10, 0, 0, 100}),
			NATSrcPort:  sessionSyncScopePort18927(40000),
			IngressZone: 1, EgressZone: 2,
			IngressIfindex: row.ingressIfindex, IngressVlanID: 80,
			NatScopeIfindex: row.scopeIfindex,
			FibIfindex:      20, FibVlanID: 80,
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

		if row.wantIdentity != (got.IngressIfaceFold == foldReth080) ||
			row.wantScope != (got.NatScopeFold == foldReth080) {
			t.Fatalf("row %s: received folds do not match intended local identity/scope presence", row.name)
		}
		wantLogFlags := uint8(0)
		if row.fabric {
			wantLogFlags = dataplane.LogFlagUserspaceFabricIngress
		}
		if got.LogFlags != wantLogFlags {
			t.Fatalf("row %s: received LogFlags=%#x, want %#x", row.name, got.LogFlags, wantLogFlags)
		}
		if got.Generation != uint64(i+3) {
			t.Fatalf("row %s: received install generation=%d, want %d", row.name, got.Generation, i+3)
		}
		if got.State != dataplane.SessStateEstablished ||
			got.Flags&dataplane.SessFlagSNAT == 0 || got.Flags&dataplane.SessFlagDNAT != 0 ||
			dataplane.SourceNatProvenanceFromFlags(got.Flags) != dataplane.SourceNatProvenanceDynamic ||
			got.NATSrcIP != binary.NativeEndian.Uint32([]byte{10, 0, 0, 100}) ||
			got.NATSrcPort != sessionSyncScopePort18927(40000) ||
			got.NATDstIP != 0 || got.NATDstPort != 0 ||
			got.IngressZone != 1 || got.EgressZone != 2 ||
			got.FibIfindex != 20 || got.FibVlanID != 80 ||
			got.FibDmac != ([6]byte{}) || got.FibSmac != ([6]byte{}) {
			t.Fatalf("row %s: decoded state/flags/NAT/zones/FIB=%d/%#x/%#x/%d/%#x/%d/%d/%d/%d, want established/SNAT/dynamic/10.0.0.100:40000/no-DNAT/zones 1/2/FIB 20.80",
				row.name, got.State, got.Flags, dataplane.SourceNatProvenanceFromFlags(got.Flags),
				got.NATSrcIP, got.NATSrcPort, got.NATDstIP, got.IngressZone, got.EgressZone, got.FibIfindex)
		}
		wantIngressIfindex, wantIngressVLAN, wantScopeIfindex := 0, uint16(0), int32(0)
		if got.IngressIfaceFold == foldReth080 {
			wantIngressIfindex, wantIngressVLAN = 20, 80
		}
		if got.NatScopeFold == foldReth080 {
			wantScopeIfindex = 22
		}

		wantNATSrcIP, wantNATDstIP := "", ""
		var wantNATSrcPort, wantNATDstPort uint16
		if got.Flags&dataplane.SessFlagSNAT != 0 {
			if got.NATSrcIP != 0 {
				wantNATSrcIP = dataplane.SessionIPv4(got.NATSrcIP).String()
			}
			wantNATSrcPort = sessionSyncScopeHostPort18927(got.NATSrcPort)
		}
		if got.Flags&dataplane.SessFlagDNAT != 0 {
			if got.NATDstIP != 0 {
				wantNATDstIP = dataplane.SessionIPv4(got.NATDstIP).String()
			}
			wantNATDstPort = sessionSyncScopeHostPort18927(got.NATDstPort)
		}
		wantRTFlowSessionID := got.RTFlowSessionID
		if wantRTFlowSessionID == 0 {
			wantRTFlowSessionID = got.SessionID
		}
		wantTunnelEndpointID := uint16(0)
		if got.LogFlags&dataplane.LogFlagUserspaceTunnelEndpoint != 0 && got.FibGen != 0 {
			wantTunnelEndpointID = got.FibGen
		}
		wantRequest := userspace.SessionSyncRequest{
			Operation:           "upsert",
			AddrFamily:          dataplane.AFInet,
			Protocol:            key.Protocol,
			SrcIP:               net.IP(key.SrcIP[:]).String(),
			DstIP:               net.IP(key.DstIP[:]).String(),
			SrcPort:             sessionSyncScopeHostPort18927(key.SrcPort),
			DstPort:             sessionSyncScopeHostPort18927(key.DstPort),
			PrimaryLiveness:     got.PrimaryLiveness,
			IngressZoneID:       uint32(got.IngressZone),
			EgressZoneID:        uint32(got.EgressZone),
			IngressIfindex:      wantIngressIfindex,
			IngressVLANID:       wantIngressVLAN,
			NatScopeIfindex:     wantScopeIfindex,
			OwnerRGID:           1,
			EgressIfindex:       22,
			TXIfindex:           20,
			TunnelEndpointID:    wantTunnelEndpointID,
			TXVLANID:            80,
			NATSrcIP:            wantNATSrcIP,
			NATDstIP:            wantNATDstIP,
			NATSrcPort:          wantNATSrcPort,
			NATDstPort:          wantNATDstPort,
			SourceNatICMPValid:  got.SourceNatICMPValid,
			SourceNatICMPType:   got.SourceNatICMPType,
			SourceNatICMPCode:   got.SourceNatICMPCode,
			SourceNatProvenance: dataplane.SourceNatProvenanceFromFlags(got.Flags),
			FabricIngress:       got.LogFlags&dataplane.LogFlagUserspaceFabricIngress != 0,
			IsReverse:           got.IsReverse != 0,
			LogSessionInit:      got.LogFlags&dataplane.LogFlagSessionInit != 0,
			LogSessionClose:     got.LogFlags&dataplane.LogFlagSessionClose != 0,
			Generation:          got.Generation,
			PolicyID:            got.PolicyID,
			PolicyCounterIdx:    got.PolicyCounterIdx,
			PolicyRuleID:        got.PolicyRuleID,
			InactivityTimeout:   got.AppTimeout,
			RTFlowSessionID:     wantRTFlowSessionID,
			TunnelDiscriminator: got.TunnelDiscriminator,
			PptpCallIDs:         got.PptpCallIDs,
			RoutingDomain:       got.RoutingDomain,
			TCPCloseClass:       got.TCPCloseClass,
			TCPHandshakeState:   dataplane.NormalizeTCPHandshakeState(got.TCPHandshakeState),
			FwdPackets:          got.FwdPackets,
			RevPackets:          got.RevPackets,
			InstallTableDomain:  got.InstallTableDomain,
			InstallTableCheck:   got.InstallTableCheck,
		}
		if !reflect.DeepEqual(requests[i], wantRequest) {
			t.Fatalf("row %s: fixture request does not match every request-effective captured field:\n got: %+v\nwant: %+v",
				row.name, requests[i], wantRequest)
		}
	}
}
func sessionSyncScopePort18927(port uint16) uint16 {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], port)
	return binary.NativeEndian.Uint16(raw[:])
}
func sessionSyncScopeHostPort18927(port uint16) uint16 {
	var raw [2]byte
	binary.NativeEndian.PutUint16(raw[:], port)
	return binary.BigEndian.Uint16(raw[:])
}
