package cluster

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #16173: the decisive acceptance check for collapsing the V4/V6 twin
// guards + session tail. The property half drives IDENTICAL op sequences
// through both families' install/delete guards (bare and scoped) and
// requires identical verdicts and identical normalized recorded state,
// including at forced tiny caps (overflow / tombstone-eviction cells).
// The golden half pins the exact wire bytes the encoders emit today, so
// the tail extraction must reproduce them bit-for-bit. Written against
// the twins before their collapse; after the collapse the wrappers it
// drives are the 2-line methods over the generic cores, so any verdict
// drift inside a shared core that is not family-symmetric, any tail
// offset drift, or any cap-accounting drift turns it red.

type guardOp16173 struct {
	kind   string // "install" | "delete" | "sdel" | "installS"
	domain uint32
	keyIdx int
	gen    uint64
}

var guardOps16173 = []guardOp16173{
	{"install", 0, 1, 5},
	{"install", 0, 1, 3},
	{"install", 0, 1, 0},
	{"install", 0, 1, 9},
	{"delete", 0, 1, 4},
	{"delete", 0, 1, 9},
	{"install", 0, 1, 7},
	{"install", 0, 1, 12},
	{"sdel", 100007, 1, 10},
	{"sdel", 100007, 1, 13},
	{"installS", 100007, 1, 11},
	{"install", 0, 2, 1},
	{"delete", 0, 2, 1},
	{"install", 0, 2, 0},
	{"installS", 0, 1, 50},
	{"install", 0, 1, 1},
	{"delete", 0, 2, 50},
	{"delete", 0, 1, 13},
	{"installS", 0, 3, 100},
	{"install", 0, 3, 100},
	{"sdel", 100007, 2, 21},
	{"install", 0, 3, 0},
	{"installS", 100007, 1, 8},
	{"installS", 0, 1, 0},
	{"install", 0, 2, 21},
	{"sdel", 0, 2, 21},
	{"sdel", 100007, 2, 8},
	{"installS", 0, 3, 8},
	{"delete", 0, 1, 21},
	{"installS", 0, 2, 100},
	{"sdel", 100007, 2, 3},
	{"install", 0, 3, 2},
	{"install", 0, 3, 8},
	{"install", 0, 1, 0},
	{"delete", 0, 3, 50},
	{"installS", 100007, 2, 0},
	{"delete", 0, 3, 8},
	{"sdel", 100007, 3, 0},
	{"delete", 0, 3, 3},
	{"sdel", 100007, 2, 21},
	{"install", 0, 1, 0},
	{"install", 0, 1, 8},
	{"install", 0, 1, 100},
	{"install", 0, 1, 3},
	{"delete", 0, 2, 3},
	{"installS", 100007, 3, 13},
	{"install", 0, 3, 5},
	{"installS", 0, 3, 0},
	{"delete", 0, 1, 5},
	{"installS", 100007, 1, 100},
	{"sdel", 100007, 2, 1},
	{"sdel", 100007, 3, 3},
	{"installS", 0, 1, 1},
	{"delete", 0, 2, 0},
	{"install", 0, 2, 8},
	{"install", 0, 2, 0},
	{"sdel", 0, 3, 21},
	{"sdel", 100007, 2, 1},
	{"install", 0, 2, 2},
	{"sdel", 100007, 1, 5},
	{"delete", 0, 1, 2},
	{"installS", 0, 3, 21},
	{"delete", 0, 2, 8},
	{"sdel", 0, 1, 13},
	{"installS", 100007, 2, 13},
	{"sdel", 100007, 1, 100},
	{"installS", 0, 2, 50},
	{"install", 0, 1, 2},
	{"install", 0, 3, 8},
	{"installS", 100007, 1, 50},
	{"sdel", 100007, 3, 3},
	{"installS", 100007, 1, 0},
	{"installS", 0, 3, 13},
	{"sdel", 0, 2, 2},
	{"sdel", 100007, 2, 8},
	{"install", 0, 1, 5},
	{"sdel", 100007, 1, 100},
	{"sdel", 100007, 2, 13},
	{"delete", 0, 3, 5},
	{"delete", 0, 1, 50},
	{"sdel", 100007, 3, 5},
	{"installS", 0, 1, 13},
	{"sdel", 0, 2, 50},
	{"installS", 100007, 1, 13},
	{"install", 0, 1, 13},
	{"sdel", 100007, 1, 1},
	{"delete", 0, 1, 1},
	{"install", 0, 1, 8},
	{"sdel", 0, 3, 8},
	{"installS", 100007, 3, 13},
	{"sdel", 100007, 2, 100},
	{"sdel", 100007, 3, 13},
	{"sdel", 100007, 1, 3},
	{"sdel", 0, 2, 5},
	{"installS", 100007, 2, 21},
	{"install", 0, 1, 2},
	{"installS", 100007, 3, 5},
	{"sdel", 100007, 3, 3},
	{"installS", 100007, 2, 8},
	{"install", 0, 3, 8},
	{"delete", 0, 2, 5},
	{"installS", 100007, 1, 100},
	{"delete", 0, 1, 3},
	{"delete", 0, 1, 50},
	{"sdel", 100007, 2, 13},
	{"install", 0, 3, 8},
	{"sdel", 0, 3, 3},
	{"delete", 0, 1, 100},
	{"install", 0, 1, 2},
	{"install", 0, 2, 3},
	{"sdel", 100007, 1, 100},
	{"delete", 0, 1, 13},
	{"sdel", 0, 2, 0},
	{"delete", 0, 2, 3},
	{"delete", 0, 2, 5},
	{"delete", 0, 1, 13},
	{"delete", 0, 1, 13},
	{"sdel", 100007, 2, 3},
	{"delete", 0, 1, 100},
	{"installS", 100007, 1, 50},
	{"delete", 0, 1, 21},
	{"install", 0, 1, 8},
	{"sdel", 0, 1, 50},
	{"delete", 0, 2, 13},
	{"install", 0, 1, 21},
	{"install", 0, 3, 8},
	{"sdel", 0, 1, 8},
	{"install", 0, 1, 8},
	{"installS", 100007, 1, 2},
	{"delete", 0, 1, 100},
	{"sdel", 0, 1, 5},
	{"install", 0, 3, 5},
	{"install", 0, 1, 13},
	{"delete", 0, 1, 0},
}

func guardKeyV4_16173(idx int) dataplane.SessionKey {
	return dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{10, 0, 0, byte(idx)},
		DstIP:    [4]byte{172, 16, 0, 1},
		SrcPort:  uint16(4000 + idx),
		DstPort:  443,
	}
}

func guardKeyV6_16173(idx int) dataplane.SessionKeyV6 {
	k := dataplane.SessionKeyV6{Protocol: 6, SrcPort: uint16(4000 + idx), DstPort: 443}
	k.SrcIP[15] = byte(idx)
	k.DstIP[15] = 1
	return k
}

// runGuardOpsV4 replays the op sequence through the v4 guard surface,
// mirroring installClusterSynced/deleteClusterSynced verdict composition
// (apply only when BOTH the bare and scoped guards admit; an admitted
// delete tombstones through the guard itself), and returns a normalized
// transcript: one verdict per op plus the final recorded state.
func runGuardOpsV4_16173(ceiling int) []string {
	s := &SessionSync{}
	if ceiling != 0 {
		s.genGuardMapCeilingOverride = ceiling
	}
	out := []string{}
	for _, op := range guardOps16173 {
		key := guardKeyV4_16173(op.keyIdx)
		switch op.kind {
		case "install":
			_, applyBare := s.installGenGuardV4(key, op.gen)
			_, applyScoped := s.installGenGuardScopedV4(op.domain, key, op.gen)
			apply := applyBare && applyScoped
			out = append(out, fmt.Sprintf("install k%d g%d -> %v", op.keyIdx, op.gen, apply))
			if apply {
				rec, _ := s.installGenGuardV4(key, op.gen)
				srec, _ := s.installGenGuardScopedV4(op.domain, key, op.gen)
				s.recordInstalledGenV4(key, rec)
				s.recordInstalledGenScopedV4(op.domain, key, srec)
			}
		case "installS":
			_, applyBare := s.installGenGuardV4(key, op.gen)
			_, applyScoped := s.installGenGuardScopedV4(op.domain, key, op.gen)
			apply := applyBare && applyScoped
			out = append(out, fmt.Sprintf("installS d%d k%d g%d -> %v", op.domain, op.keyIdx, op.gen, apply))
			if apply {
				rec, _ := s.installGenGuardV4(key, op.gen)
				srec, _ := s.installGenGuardScopedV4(op.domain, key, op.gen)
				s.recordInstalledGenV4(key, rec)
				s.recordInstalledGenScopedV4(op.domain, key, srec)
			}
		case "delete":
			apply := s.deleteGenGuardV4(key, op.gen)
			out = append(out, fmt.Sprintf("delete k%d g%d -> %v", op.keyIdx, op.gen, apply))
		case "sdel":
			apply := s.deleteGenGuardScopedV4(op.domain, key, op.gen)
			out = append(out, fmt.Sprintf("sdel d%d k%d g%d -> %v", op.domain, op.keyIdx, op.gen, apply))
		}
	}
	// Sender side: take-delete draws must agree in shape too (fresh
	// strictly-increasing draws when stamped/overflowed, 0 otherwise).
	// Interleave a fixed sender script on a fresh instance per family.
	out = append(out, senderTranscriptV4_16173(ceiling)...)
	// Final recorded state, normalized (keyIdx/domain/gen only).
	var state []string
	for k, g := range s.recvGenV4 {
		state = append(state, fmt.Sprintf("bare %d=%d", keyIdxV4_16173(k), g))
	}
	for sk, g := range s.recvGenScopedV4 {
		state = append(state, fmt.Sprintf("scoped %d/%d=%d", sk.Domain, keyIdxV4_16173(sk.Key), g))
	}
	sort.Strings(state)
	return append(out, state...)
}

func runGuardOpsV6_16173(ceiling int) []string {
	s := &SessionSync{}
	if ceiling != 0 {
		s.genGuardMapCeilingOverride = ceiling
	}
	out := []string{}
	for _, op := range guardOps16173 {
		key := guardKeyV6_16173(op.keyIdx)
		switch op.kind {
		case "install":
			_, applyBare := s.installGenGuardV6(key, op.gen)
			_, applyScoped := s.installGenGuardScopedV6(op.domain, key, op.gen)
			apply := applyBare && applyScoped
			out = append(out, fmt.Sprintf("install k%d g%d -> %v", op.keyIdx, op.gen, apply))
			if apply {
				rec, _ := s.installGenGuardV6(key, op.gen)
				srec, _ := s.installGenGuardScopedV6(op.domain, key, op.gen)
				s.recordInstalledGenV6(key, rec)
				s.recordInstalledGenScopedV6(op.domain, key, srec)
			}
		case "installS":
			_, applyBare := s.installGenGuardV6(key, op.gen)
			_, applyScoped := s.installGenGuardScopedV6(op.domain, key, op.gen)
			apply := applyBare && applyScoped
			out = append(out, fmt.Sprintf("installS d%d k%d g%d -> %v", op.domain, op.keyIdx, op.gen, apply))
			if apply {
				rec, _ := s.installGenGuardV6(key, op.gen)
				srec, _ := s.installGenGuardScopedV6(op.domain, key, op.gen)
				s.recordInstalledGenV6(key, rec)
				s.recordInstalledGenScopedV6(op.domain, key, srec)
			}
		case "delete":
			apply := s.deleteGenGuardV6(key, op.gen)
			out = append(out, fmt.Sprintf("delete k%d g%d -> %v", op.keyIdx, op.gen, apply))
		case "sdel":
			apply := s.deleteGenGuardScopedV6(op.domain, key, op.gen)
			out = append(out, fmt.Sprintf("sdel d%d k%d g%d -> %v", op.domain, op.keyIdx, op.gen, apply))
		}
	}
	out = append(out, senderTranscriptV6_16173(ceiling)...)
	var state []string
	for k, g := range s.recvGenV6 {
		state = append(state, fmt.Sprintf("bare %d=%d", keyIdxV6_16173(k), g))
	}
	for sk, g := range s.recvGenScopedV6 {
		state = append(state, fmt.Sprintf("scoped %d/%d=%d", sk.Domain, keyIdxV6_16173(sk.Key), g))
	}
	sort.Strings(state)
	return append(out, state...)
}

func keyIdxV4_16173(k dataplane.SessionKey) int { return int(k.SrcIP[3]) }
func keyIdxV6_16173(k dataplane.SessionKeyV6) int {
	return int(k.SrcIP[15])
}

// senderTranscript exercises stamp/take (bare + scoped) on a fresh
// sender. Draws come from one monotonic counter seeded identically, so
// the two families must produce the same verdict shape: a stamped take
// returns a nonzero draw, the second take returns 0 (or a fresh draw
// once overflow latched), and recorded overflow stats match.
func senderTranscriptV4_16173(ceiling int) []string {
	s := &SessionSync{}
	if ceiling != 0 {
		s.genGuardMapCeilingOverride = ceiling
	}
	k1, k2 := guardKeyV4_16173(1), guardKeyV4_16173(2)
	v1 := dataplane.SessionValue{SessionID: 11, RoutingDomain: 1}
	v2 := dataplane.SessionValue{SessionID: 22, RoutingDomain: 100007}
	s.stampInstallGenV4(k1, &v1)
	s.stampInstallGenV4(k2, &v2)
	out := []string{
		fmt.Sprintf("stamp g1!=0:%v g2!=0:%v g2>g1:%v", v1.Generation != 0, v2.Generation != 0, v2.Generation > v1.Generation),
	}
	t1 := s.takeDeleteGenV4(k1)
	out = append(out, fmt.Sprintf("take1>t1stamp:%v", t1 > v1.Generation))
	out = append(out, fmt.Sprintf("take1-again==0:%v", s.takeDeleteGenV4(k1) == 0))
	ts := s.takeDeleteGenScopedV4(100007, k2)
	out = append(out, fmt.Sprintf("takeScoped>stamp:%v", ts > v2.Generation))
	out = append(out, fmt.Sprintf("takeScoped-again==0:%v", s.takeDeleteGenScopedV4(100007, k2) == 0))
	out = append(out, fmt.Sprintf("overflowStats:%d", s.stats.GenMapOverflow.Load()))
	return out
}

func senderTranscriptV6_16173(ceiling int) []string {
	s := &SessionSync{}
	if ceiling != 0 {
		s.genGuardMapCeilingOverride = ceiling
	}
	k1, k2 := guardKeyV6_16173(1), guardKeyV6_16173(2)
	v1 := dataplane.SessionValueV6{SessionID: 11, RoutingDomain: 1}
	v2 := dataplane.SessionValueV6{SessionID: 22, RoutingDomain: 100007}
	s.stampInstallGenV6(k1, &v1)
	s.stampInstallGenV6(k2, &v2)
	out := []string{
		fmt.Sprintf("stamp g1!=0:%v g2!=0:%v g2>g1:%v", v1.Generation != 0, v2.Generation != 0, v2.Generation > v1.Generation),
	}
	t1 := s.takeDeleteGenV6(k1)
	out = append(out, fmt.Sprintf("take1>t1stamp:%v", t1 > v1.Generation))
	out = append(out, fmt.Sprintf("take1-again==0:%v", s.takeDeleteGenV6(k1) == 0))
	ts := s.takeDeleteGenScopedV6(100007, k2)
	out = append(out, fmt.Sprintf("takeScoped>stamp:%v", ts > v2.Generation))
	out = append(out, fmt.Sprintf("takeScoped-again==0:%v", s.takeDeleteGenScopedV6(100007, k2) == 0))
	out = append(out, fmt.Sprintf("overflowStats:%d", s.stats.GenMapOverflow.Load()))
	return out
}

func TestGuardTwinsIdenticalVerdicts16173(t *testing.T) {
	// Ceiling 0 = production caps; 2 and 3 force the overflow /
	// tombstone-eviction cells (identity at the cap) on every map.
	for _, ceiling := range []int{0, 2, 3} {
		v4 := runGuardOpsV4_16173(ceiling)
		v6 := runGuardOpsV6_16173(ceiling)
		if len(v4) != len(v6) {
			t.Fatalf("ceiling %d: transcript lengths differ v4=%d v6=%d", ceiling, len(v4), len(v6))
		}
		for i := range v4 {
			if v4[i] != v6[i] {
				t.Fatalf("ceiling %d: verdict drift at step %d:\n v4: %s\n v6: %s", ceiling, i, v4[i], v6[i])
			}
		}
	}
}

// Golden wire vectors, captured from the pre-collapse encoders. Any tail
// offset/sizing drift in encode*Payload (or in a shared tail helper)
// changes these bytes.
var goldenV4_16173 = "0a010203ac100908419cbb010600000004ab0400000000000807060504030201e803000000000000d007000000000000100e00004d000000010002000100000a010010ac881370170b000000000000004c0400000000000009000000000000008403000000000000ac1009080a010203bb01419c06000000010300000c0000006400aabbccddeeff112233445566050018171615141312112d0000000900000028272625242322213837363534333231444342415857565554535251a7860100020700000008000000010103040a0072756c652d616c706861026463626174737271"
var goldenV6_16173 = "20010db800000000000000000000000120010db8000000000000000000000002419cbb010600000004ab0400000000000807060504030201e803000000000000d007000000000000100e00004d0000000100020020010db800000000000000000000000920010db800000000000000000000000a881370170b000000000000004c040000000000000900000000000000840300000000000020010db800000000000000000000000220010db8000000000000000000000001bb01419c06000000010300000c0000006400aabbccddeeff112233445566050018171615141312112d00000009000000cb00710728272625242322213837363534333231444342415857565554535251a7860100020700000008000000010103040a0072756c652d616c706861026463626174737271"

func goldenKeyValV4_16173() (dataplane.SessionKey, dataplane.SessionValue) {
	key := dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{10, 1, 2, 3},
		DstIP:    [4]byte{172, 16, 9, 8},
		SrcPort:  40001,
		DstPort:  443,
	}
	val := dataplane.SessionValue{
		State:               dataplane.SessStateEstablished,
		Flags:               0x1AB,
		TCPState:            4,
		SessionID:           0x0102030405060708,
		Created:             1000,
		LastSeen:            2000,
		Timeout:             3600,
		PolicyID:            77,
		IngressZone:         1,
		EgressZone:          2,
		NATSrcIP:            0x0A000001,
		NATDstIP:            0xAC100001,
		NATSrcPort:          5000,
		NATDstPort:          6000,
		FwdPackets:          11,
		FwdBytes:            1100,
		RevPackets:          9,
		RevBytes:            900,
		ALGType:             1,
		LogFlags:            3,
		FibIfindex:          12,
		FibVlanID:           100,
		FibGen:              5,
		Generation:          0x1112131415161718,
		AppTimeout:          45,
		PolicyCounterIdx:    9,
		ConfigEpoch:         0x2122232425262728,
		RTFlowSessionID:     0x3132333435363738,
		IngressIfaceFold:    0x41424344,
		TunnelDiscriminator: 0x5152535455565758,
		RoutingDomain:       100007,
		TCPCloseClass:       2,
		InstallTableDomain:  7,
		InstallTableCheck:   8,
		SourceNatICMPValid:  true,
		SourceNatICMPType:   3,
		SourceNatICMPCode:   4,
		PolicyRuleID:        "rule-alpha",
		TCPHandshakeState:   2,
		EgressIfaceFold:     0x61626364,
		NatScopeFold:        0x71727374,
	}
	val.ReverseKey = dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{172, 16, 9, 8},
		DstIP:    [4]byte{10, 1, 2, 3},
		SrcPort:  443,
		DstPort:  40001,
	}
	copy(val.FibDmac[:], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	copy(val.FibSmac[:], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	return key, val
}

func goldenKeyValV6_16173() (dataplane.SessionKeyV6, dataplane.SessionValueV6) {
	var key dataplane.SessionKeyV6
	key.Protocol = 6
	key.SrcPort, key.DstPort = 40001, 443
	copy(key.SrcIP[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(key.DstIP[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	_, v4 := goldenKeyValV4_16173()
	val := dataplane.SessionValueV6{
		State:               v4.State,
		Flags:               v4.Flags,
		TCPState:            v4.TCPState,
		SessionID:           v4.SessionID,
		Created:             v4.Created,
		LastSeen:            v4.LastSeen,
		Timeout:             v4.Timeout,
		PolicyID:            v4.PolicyID,
		IngressZone:         v4.IngressZone,
		EgressZone:          v4.EgressZone,
		NATSrcPort:          v4.NATSrcPort,
		NATDstPort:          v4.NATDstPort,
		FwdPackets:          v4.FwdPackets,
		FwdBytes:            v4.FwdBytes,
		RevPackets:          v4.RevPackets,
		RevBytes:            v4.RevBytes,
		ALGType:             v4.ALGType,
		LogFlags:            v4.LogFlags,
		FibIfindex:          v4.FibIfindex,
		FibVlanID:           v4.FibVlanID,
		FibGen:              v4.FibGen,
		Generation:          v4.Generation,
		AppTimeout:          v4.AppTimeout,
		PolicyCounterIdx:    v4.PolicyCounterIdx,
		ConfigEpoch:         v4.ConfigEpoch,
		RTFlowSessionID:     v4.RTFlowSessionID,
		IngressIfaceFold:    v4.IngressIfaceFold,
		TunnelDiscriminator: v4.TunnelDiscriminator,
		RoutingDomain:       v4.RoutingDomain,
		TCPCloseClass:       v4.TCPCloseClass,
		InstallTableDomain:  v4.InstallTableDomain,
		InstallTableCheck:   v4.InstallTableCheck,
		SourceNatICMPValid:  v4.SourceNatICMPValid,
		SourceNatICMPType:   v4.SourceNatICMPType,
		SourceNatICMPCode:   v4.SourceNatICMPCode,
		PolicyRuleID:        v4.PolicyRuleID,
		TCPHandshakeState:   v4.TCPHandshakeState,
		EgressIfaceFold:     v4.EgressIfaceFold,
		NatScopeFold:        v4.NatScopeFold,
	}
	copy(val.NATSrcIP[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9})
	copy(val.NATDstIP[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10})
	copy(val.Nat64SnatV4[:], []byte{203, 0, 113, 7})
	copy(val.FibDmac[:], v4.FibDmac[:])
	copy(val.FibSmac[:], v4.FibSmac[:])
	var rk dataplane.SessionKeyV6
	rk.Protocol = 6
	rk.SrcPort, rk.DstPort = 443, 40001
	copy(rk.SrcIP[:], key.DstIP[:])
	copy(rk.DstIP[:], key.SrcIP[:])
	val.ReverseKey = rk
	return key, val
}

func TestSessionTailGoldenBytes16173(t *testing.T) {
	k4, v4 := goldenKeyValV4_16173()
	got4 := encodeSessionV4Payload(k4, v4)
	want4, err := hex.DecodeString(goldenV4_16173)
	if err != nil {
		t.Fatalf("golden v4 hex: %v", err)
	}
	if !bytes.Equal(got4, want4) {
		t.Fatalf("v4 wire bytes drifted:\n got %x\nwant %x", got4, want4)
	}
	// Round-trip through both decoders: every tail field must survive.
	d4k, d4v, ok := decodeSessionV4Payload(got4)
	if !ok || d4k != k4 {
		t.Fatalf("v4 golden does not decode: ok=%v key=%v", ok, d4k)
	}
	if d4v.Generation != v4.Generation || d4v.AppTimeout != v4.AppTimeout ||
		d4v.PolicyCounterIdx != v4.PolicyCounterIdx || d4v.ConfigEpoch != v4.ConfigEpoch ||
		d4v.RTFlowSessionID != v4.RTFlowSessionID || d4v.RoutingDomain != v4.RoutingDomain ||
		d4v.PolicyRuleID != v4.PolicyRuleID || d4v.EgressIfaceFold != v4.EgressIfaceFold ||
		d4v.NatScopeFold != v4.NatScopeFold || d4v.Flags != v4.Flags {
		t.Fatalf("v4 tail round-trip drift: %+v", d4v)
	}

	k6, v6 := goldenKeyValV6_16173()
	got6 := encodeSessionV6Payload(k6, v6)
	want6, err := hex.DecodeString(goldenV6_16173)
	if err != nil {
		t.Fatalf("golden v6 hex: %v", err)
	}
	if !bytes.Equal(got6, want6) {
		t.Fatalf("v6 wire bytes drifted:\n got %x\nwant %x", got6, want6)
	}
	d6k, d6v, ok := decodeSessionV6Payload(got6)
	if !ok || d6k != k6 {
		t.Fatalf("v6 golden does not decode: ok=%v", ok)
	}
	if d6v.Generation != v6.Generation || d6v.ConfigEpoch != v6.ConfigEpoch ||
		d6v.Nat64SnatV4 != v6.Nat64SnatV4 || d6v.PolicyRuleID != v6.PolicyRuleID ||
		d6v.NatScopeFold != v6.NatScopeFold || d6v.Flags != v6.Flags {
		t.Fatalf("v6 tail round-trip drift: %+v", d6v)
	}
	// Differential prefix property: truncating at every length must
	// decode identically in shape (ok only past the mandatory blocks,
	// never a panic, never a tail field appearing from bytes that are
	// not there).
	for n := 0; n <= len(got4); n++ {
		_, _, _ = decodeSessionV4Payload(got4[:n])
	}
	for n := 0; n <= len(got6); n++ {
		_, _, _ = decodeSessionV6Payload(got6[:n])
	}
}

// BenchmarkEncodeSessionTail16173 guards the perf/alloc contract of the
// tail extraction: plain generic-free helpers over the preallocated
// buffer must stay allocation-free like the hand-written ladders.
func BenchmarkEncodeSessionTail16173(b *testing.B) {
	k4, v4 := goldenKeyValV4_16173()
	b.ReportAllocs()
	for range b.N {
		_ = encodeSessionV4Payload(k4, v4)
	}
}
