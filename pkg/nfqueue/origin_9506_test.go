package nfqueue

// #9506 S5: CaptureOrigin/provenance RED tests. These fail until origin.go
// (registry + validator) and the nfqueue.go parser extension land.

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestCaptureOriginRegistryImmutable9506(t *testing.T) {
	var reg OriginRegistry
	want := CaptureOrigin{Family: CaptureFamilyInet, Hook: CaptureHookForward, Owner: "SecureTunnel", STN: "st0", OwnedIfindex: 7}
	if err := reg.Register(1000, want); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, ok := reg.Lookup(1000)
	if !ok {
		t.Fatal("Lookup(1000) missed a registered queue")
	}
	if got != want {
		t.Fatalf("Lookup(1000)=%+v, want %+v", got, want)
	}
	if _, ok := reg.Lookup(1001); ok {
		t.Fatal("Lookup(1001) hit an unregistered queue")
	}
	// Immutable-once: re-registration is refused even with an identical origin.
	if err := reg.Register(1000, want); err == nil {
		t.Fatal("re-Register identical origin succeeded, want refusal")
	}
	other := want
	other.OwnedIfindex = 9
	if err := reg.Register(1000, other); err == nil {
		t.Fatal("re-Register mutated origin succeeded, want refusal")
	}
	got, _ = reg.Lookup(1000)
	if got != want {
		t.Fatalf("Lookup after refused re-Register=%+v, want %+v", got, want)
	}
}

func TestCaptureOriginKernelConstsPinned9506(t *testing.T) {
	if captureAFInet != int(unix.AF_INET) {
		t.Fatalf("captureAFInet=%d, want unix AF_INET=%d", captureAFInet, unix.AF_INET)
	}
	if captureAFInet != 2 {
		t.Fatalf("captureAFInet=%d, want AF_INET=2", captureAFInet)
	}
	if captureAFInet6 != int(unix.AF_INET6) {
		t.Fatalf("captureAFInet6=%d, want unix AF_INET6=%d", captureAFInet6, unix.AF_INET6)
	}
	if captureAFInet6 != 10 {
		t.Fatalf("captureAFInet6=%d, want AF_INET6=10", captureAFInet6)
	}
	if captureAFBridge != int(unix.AF_BRIDGE) {
		t.Fatalf("captureAFBridge=%d, want unix AF_BRIDGE=%d", captureAFBridge, unix.AF_BRIDGE)
	}
	if captureAFBridge != 7 {
		t.Fatalf("captureAFBridge=%d, want AF_BRIDGE=7", captureAFBridge)
	}
}

func originTestRegistry(t *testing.T) *OriginRegistry {
	t.Helper()
	var reg OriginRegistry
	if err := reg.Register(1000, CaptureOrigin{Family: CaptureFamilyInet, Hook: CaptureHookForward, Owner: "SecureTunnel", STN: "st0", OwnedIfindex: 7}); err != nil {
		t.Fatalf("Register inet/forward: %v", err)
	}
	if err := reg.Register(1001, CaptureOrigin{Family: CaptureFamilyInet, Hook: CaptureHookInput, Owner: "SecureTunnel", STN: "st0", OwnedIfindex: 7}); err != nil {
		t.Fatalf("Register inet/input: %v", err)
	}
	if err := reg.Register(1002, CaptureOrigin{Family: CaptureFamilyBridge, Hook: CaptureHookForward, Owner: "SecureTunnel", STN: "st0", OwnedIfindex: 7}); err != nil {
		t.Fatalf("Register bridge/forward: %v", err)
	}
	return &reg
}

func TestValidateProvenanceAccepts9506(t *testing.T) {
	reg := originTestRegistry(t)
	cases := []struct {
		name   string
		packet *Packet
	}{
		{"inet-forward-v4", &Packet{queueID: 1000, nfgenFamily: 2, hook: 2, indevIfindex: 7}},
		{"inet-forward-v6-normalized", &Packet{queueID: 1000, nfgenFamily: 10, hook: 2, indevIfindex: 7}},
		{"inet-input", &Packet{queueID: 1001, nfgenFamily: 2, hook: 1, indevIfindex: 7}},
		{"bridge-forward", &Packet{queueID: 1002, nfgenFamily: 7, hook: 2, indevIfindex: 7}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateProvenance(tc.packet, reg); err != nil {
				t.Fatalf("ValidateProvenance: %v", err)
			}
		})
	}
}

func TestValidateProvenanceMismatches9506(t *testing.T) {
	reg := originTestRegistry(t)
	cases := []struct {
		name   string
		packet *Packet
	}{
		{"family-bridge-on-inet-queue", &Packet{queueID: 1000, nfgenFamily: 7, hook: 2, indevIfindex: 7}},
		{"family-inet-on-bridge-queue", &Packet{queueID: 1002, nfgenFamily: 2, hook: 2, indevIfindex: 7}},
		{"hook-input-on-forward-queue", &Packet{queueID: 1000, nfgenFamily: 2, hook: 1, indevIfindex: 7}},
		{"hook-forward-on-input-queue", &Packet{queueID: 1001, nfgenFamily: 2, hook: 2, indevIfindex: 7}},
		{"ifindex-name-reuse", &Packet{queueID: 1000, nfgenFamily: 2, hook: 2, indevIfindex: 9}},
		{"ifindex-zero", &Packet{queueID: 1000, nfgenFamily: 2, hook: 2, indevIfindex: 0}},
		{"unregistered-queue", &Packet{queueID: 1999, nfgenFamily: 2, hook: 2, indevIfindex: 7}},
		{"unknown-family", &Packet{queueID: 1000, nfgenFamily: 1, hook: 2, indevIfindex: 7}},
		{"unknown-hook-output", &Packet{queueID: 1000, nfgenFamily: 2, hook: 3, indevIfindex: 7}},
		{"unknown-hook-postrouting", &Packet{queueID: 1000, nfgenFamily: 2, hook: 4, indevIfindex: 7}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateProvenance(tc.packet, reg)
			if err == nil {
				t.Fatal("ValidateProvenance accepted a mismatched packet, want typed refusal")
			}
			perr, ok := err.(*ProvenanceError)
			if !ok {
				t.Fatalf("error type %T, want *ProvenanceError", err)
			}
			if perr.Queue != tc.packet.queueID {
				t.Fatalf("ProvenanceError.Queue=%d, want %d", perr.Queue, tc.packet.queueID)
			}
		})
	}
	if err := ValidateProvenance(nil, reg); err == nil {
		t.Fatal("ValidateProvenance(nil) accepted, want refusal")
	}
	if err := ValidateProvenance(&Packet{queueID: 1000}, nil); err == nil {
		t.Fatal("ValidateProvenance(nil registry) accepted, want refusal")
	}
}

// buildProvenancePacketMsg synthesizes one NFQNL_MSG_PACKET netlink message:
// nlmsghdr + nfgenmsg(family, version, res_id) + PACKET_HDR + indev/outdev.
func buildProvenancePacketMsg(t *testing.T, queue uint16, family byte, hook byte, indev, outdev uint32) []byte {
	t.Helper()
	var attrs []byte
	hdr := make([]byte, 7)
	binary.BigEndian.PutUint32(hdr[:4], 4242)
	binary.BigEndian.PutUint16(hdr[4:6], 0x0800)
	hdr[6] = hook
	attrs = appendNlAttr(attrs, nlAttr{Type: nfqaPacketHdr, Data: hdr})
	indevBody := make([]byte, 4)
	binary.BigEndian.PutUint32(indevBody, indev)
	attrs = appendNlAttr(attrs, nlAttr{Type: nfqaIfindexIndev, Data: indevBody})
	outdevBody := make([]byte, 4)
	binary.BigEndian.PutUint32(outdevBody, outdev)
	attrs = appendNlAttr(attrs, nlAttr{Type: nfqaIfindexOutdev, Data: outdevBody})
	attrs = appendNlAttr(attrs, nlAttr{Type: nfqaPayload, Data: []byte{0x45, 0x00, 0x00, 0x14}})
	nfgen := buildNfgenmsg(family, queue)
	return buildNlmsg(uint16(nfqnlMsgPacketType), 0, 0, append(nfgen, attrs...))
}

func TestParsePreservesProvenance9506(t *testing.T) {
	q := &Queue{id: 1000, fd: -1}
	msg := buildProvenancePacketMsg(t, 1000, 2, 2, 7, 0)
	pkts, err := q.parsePackets(msg)
	if err != nil {
		t.Fatalf("parsePackets: %v", err)
	}
	if len(pkts) != 1 {
		t.Fatalf("parsePackets returned %d packets, want 1", len(pkts))
	}
	pkt := pkts[0]
	if pkt.NfgenFamily() != 2 {
		t.Fatalf("NfgenFamily=%d, want 2", pkt.NfgenFamily())
	}
	if pkt.Hook() != 2 {
		t.Fatalf("Hook=%d, want 2", pkt.Hook())
	}
	if pkt.IndevIfindex() != 7 {
		t.Fatalf("IndevIfindex=%d, want 7", pkt.IndevIfindex())
	}
	if pkt.OutdevIfindex() != 0 {
		t.Fatalf("OutdevIfindex=%d, want 0", pkt.OutdevIfindex())
	}
	if len(pkt.Payload()) != 4 {
		t.Fatalf("payload len=%d, want 4", len(pkt.Payload()))
	}
	// Missing provenance attributes must not break the pre-existing parse
	// contract: the packet still parses, with zero provenance.
	bareHdr := make([]byte, 7)
	binary.BigEndian.PutUint32(bareHdr[:4], 99)
	bareHdr[6] = 1
	bareAttrs := appendNlAttr(nil, nlAttr{Type: nfqaPacketHdr, Data: bareHdr})
	bare := buildNlmsg(uint16(nfqnlMsgPacketType), 0, 0,
		append(buildNfgenmsg(10, 1000), bareAttrs...))
	pkts, err = q.parsePackets(bare)
	if err != nil {
		t.Fatalf("parsePackets(bare): %v", err)
	}
	if len(pkts) != 1 {
		t.Fatalf("parsePackets(bare) returned %d packets, want 1", len(pkts))
	}
	if pkts[0].NfgenFamily() != 10 || pkts[0].Hook() != 1 {
		t.Fatalf("bare provenance family=%d hook=%d, want 10/1",
			pkts[0].NfgenFamily(), pkts[0].Hook())
	}
	if pkts[0].IndevIfindex() != 0 {
		t.Fatalf("bare IndevIfindex=%d, want 0", pkts[0].IndevIfindex())
	}
}

// TestProvenanceLiveNetns9506 proves indev/nfgen/hook arrive on a live queue:
// an INPUT-hook divert holds a loopback UDP datagram and the parsed packet
// carries nfgen=AF_INET, hook=LOCAL_IN(1), indev=lo.
func TestProvenanceLiveNetns9506(t *testing.T) {
	requireNetNS(t)

	q, err := Open(62)
	if err != nil {
		t.Fatalf("Open(queue 62) in netns: %v", err)
	}
	defer q.Close()
	release, err := divertTestTrafficInput(t, q.ID())
	if err != nil {
		t.Fatalf("divertTestTrafficInput: %v", err)
	}
	defer release()

	deadline := time.Now().Add(10 * time.Second)
	if err := sendTestDatagram(deadline); err != nil {
		t.Fatalf("sendTestDatagram: %v", err)
	}
	pkt, err := q.Recv(deadline)
	if err != nil {
		t.Fatalf("Recv held packet: %v", err)
	}
	if pkt.NfgenFamily() != 2 {
		t.Fatalf("live NfgenFamily=%d, want AF_INET(2)", pkt.NfgenFamily())
	}
	if pkt.Hook() != 1 {
		t.Fatalf("live Hook=%d, want LOCAL_IN(1)", pkt.Hook())
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("find loopback: %v", err)
	}
	if pkt.IndevIfindex() != uint32(lo.Attrs().Index) {
		t.Fatalf("live IndevIfindex=%d, want lo=%d", pkt.IndevIfindex(), lo.Attrs().Index)
	}
	if err := pkt.Verdict(VerdictAccept); err != nil {
		t.Fatalf("Verdict(ACCEPT): %v", err)
	}
	if err := awaitTestDatagram(deadline); err != nil {
		t.Fatalf("ACCEPTed datagram did not arrive: %v", err)
	}
}

// divertTestTrafficInput mirrors divertTestTraffic on the INPUT hook so a live
// packet arrives with indev populated (OUTPUT-hook packets carry none).
func divertTestTrafficInput(t *testing.T, queueID uint16) (func(), error) {
	t.Helper()
	bringLoopbackUp(t)
	conn, err := openHarnessReceiver()
	if err != nil {
		return nil, err
	}
	c, err := nftables.New()
	if err != nil {
		closeHarnessReceiver(conn)
		return nil, err
	}
	table := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: harnessTable + "_in"})
	priority := nftables.ChainPriority(0)
	policy := nftables.ChainPolicyAccept
	chain := c.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: &priority,
		Policy:   &policy,
	})
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(harnessUDPPort)},
			&expr.Queue{Num: queueID, Total: 1},
		},
	})
	if err := c.Flush(); err != nil {
		closeHarnessReceiver(conn)
		return nil, err
	}
	release := func() {
		c.DelTable(table)
		if err := c.Flush(); err != nil {
			t.Errorf("remove input queue rule/table: %v", err)
		}
		closeHarnessReceiver(conn)
	}
	return release, nil
}

func openHarnessReceiver() (*net.UDPConn, error) {
	activeTraffic.mu.Lock()
	defer activeTraffic.mu.Unlock()
	if activeTraffic.conn != nil {
		return nil, errors.New("nfqueue harness: receiver already active")
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: harnessUDPPort})
	if err != nil {
		return nil, err
	}
	activeTraffic.conn = conn
	return conn, nil
}

func closeHarnessReceiver(conn *net.UDPConn) {
	activeTraffic.mu.Lock()
	if activeTraffic.conn == conn {
		activeTraffic.conn = nil
	}
	activeTraffic.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}
func TestCapturePipelineRejectsCallerOriginConflict9506(t *testing.T) {
	sink := new(pipelineTestSink)
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry: originTestRegistry(t), Phase: PipelineShadow, Sink: sink, HandoffCap: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	frame := CaptureFrame{
		Packet:  pipelineTestPacket(77, 2, 2, 7, 1),
		FlowKey: "origin-conflict",
		origin: CaptureOrigin{
			Family: CaptureFamilyBridge, Hook: CaptureHookForward,
			Owner: "attacker", STN: "bad", OwnedIfindex: 9,
		},
		originSet: true,
	}
	if err := p.Enqueue(frame); err == nil {
		t.Fatal("caller origin conflict accepted")
	}
	if got := p.Stats(); got.ProvenanceMismatches != 1 {
		t.Fatalf("provenance mismatches=%d, want 1", got.ProvenanceMismatches)
	}
	if len(sink.verdicts) != 1 || sink.verdicts[0].v != VerdictDrop {
		t.Fatalf("sink verdicts=%+v, want one DROP", sink.verdicts)
	}
}
