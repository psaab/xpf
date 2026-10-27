package daemon

import (
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
	"github.com/psaab/xpf/pkg/flowexport"
)

// #16760: the production live counter feed built dataplane.SessionKey
// with host-order ports, but the session maps carry __be16 ports (the
// Rust helper writes src_port.to_be()). Every lookup missed, so flows
// longer than the 15s inactive timeout were exported as one 0/0 record
// and their real close was suppressed. These tests run the REAL
// liveFlowCounters (flowLiveCounters seam nil) against a store keyed
// exactly as the production encoder writes it — network-order ports —
// so a host-order lookup misses the byte-keyed map.
//
// FAIL-ON-REVERT: drop the userspaceHostToNetwork16 conversion in
// liveFlowCounters and the Rust-layout lookup below returns ok=false.

// byteKeyedSessionStore16760 models the BPF session map: keys are the
// raw SessionKey/SessionKeyV6 structs (ports in __be16, as
// bpf_session_key_v4/v6 write them) and lookup is exact struct equality,
// exactly as bpf_map_lookup_elem compares key bytes.
type byteKeyedSessionStore16760 struct {
	dataplane.SessionStore
	v4 map[dataplane.SessionKey]dataplane.SessionValue
	v6 map[dataplane.SessionKeyV6]dataplane.SessionValueV6
}

func (s *byteKeyedSessionStore16760) GetV4(key dataplane.SessionKey) (dataplane.SessionValue, error) {
	if v, ok := s.v4[key]; ok {
		return v, nil
	}
	return dataplane.SessionValue{}, errors.New("key not found")
}

func (s *byteKeyedSessionStore16760) GetV6(key dataplane.SessionKeyV6) (dataplane.SessionValueV6, error) {
	if v, ok := s.v6[key]; ok {
		return v, nil
	}
	return dataplane.SessionValueV6{}, errors.New("key not found")
}

func template16760(key flowexport.FlowKey) flowexport.FlowRecord {
	return flowexport.FlowRecord{SrcPort: key.SrcPort, DstPort: key.DstPort, Protocol: key.Protocol, IsIPv6: key.IsIPv6}
}

// liveFeedDP16760 is a RuntimeDataPlane whose Sessions() returns the
// byte-keyed store. The embedded nil interface supplies the rest; only
// Sessions() is called on this path.
type liveFeedDP16760 struct {
	dataplane.RuntimeDataPlane
	store dataplane.SessionStore
}

func (d *liveFeedDP16760) Sessions() dataplane.SessionStore { return d.store }
func (d *liveFeedDP16760) SessionDeltas() dpruntime.SessionDeltaSource {
	return nil
}

// productionSessionKeyV4 encodes a host-order tuple exactly as the Rust
// production encoder does (bpf_session_key_v4: ports .to_be()).
func productionSessionKeyV4(src, dst [4]byte, srcPort, dstPort uint16, proto uint8) dataplane.SessionKey {
	return dataplane.SessionKey{SrcIP: src, DstIP: dst, SrcPort: userspaceHostToNetwork16(srcPort), DstPort: userspaceHostToNetwork16(dstPort), Protocol: proto}
}

func productionSessionKeyV6(src, dst [16]byte, srcPort, dstPort uint16, proto uint8) dataplane.SessionKeyV6 {
	return dataplane.SessionKeyV6{SrcIP: src, DstIP: dst, SrcPort: userspaceHostToNetwork16(srcPort), DstPort: userspaceHostToNetwork16(dstPort), Protocol: proto}
}

func TestLiveFlowCountersRustLayout16760(t *testing.T) {
	src4, dst4 := [4]byte{10, 0, 0, 102}, [4]byte{192, 0, 2, 200}
	var src6, dst6 [16]byte
	copy(src6[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(dst6[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})

	store := &byteKeyedSessionStore16760{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			productionSessionKeyV4(src4, dst4, 34567, 443, 6): {FwdPackets: 100, FwdBytes: 10000, RevPackets: 40, RevBytes: 4000},
		},
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			productionSessionKeyV6(src6, dst6, 54321, 443, 6): {FwdPackets: 7, FwdBytes: 700, RevPackets: 3, RevBytes: 300},
		},
	}
	d := &Daemon{}
	d.setDataplane(&liveFeedDP16760{store: store})
	// flowLiveCounters seam must stay nil: this is the production path.
	if d.flowLiveCounters != nil {
		t.Fatal("test must exercise production liveFlowCounters, seam is set")
	}

	fp, fb, rp, rb, ok := d.liveFlowCounters(flowexport.FlowKey{SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 34567, DstPort: 443, Protocol: 6})
	if !ok || fp != 100 || fb != 10000 || rp != 40 || rb != 4000 {
		t.Fatalf("v4 Rust-layout lookup = %d/%d/%d/%d ok=%v, want 100/10000/40/4000 ok=true", fp, fb, rp, rb, ok)
	}
	fp, fb, rp, rb, ok = d.liveFlowCounters(flowexport.FlowKey{SrcIP: "2001:db8::1", DstIP: "2001:db8::2", SrcPort: 54321, DstPort: 443, Protocol: 6, IsIPv6: true})
	if !ok || fp != 7 || fb != 700 || rp != 3 || rb != 300 {
		t.Fatalf("v6 Rust-layout lookup = %d/%d/%d/%d ok=%v, want 7/700/3/300 ok=true", fp, fb, rp, rb, ok)
	}

	// Control: a tuple the store does not hold still misses.
	if _, _, _, _, ok := d.liveFlowCounters(flowexport.FlowKey{SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 1111, DstPort: 443, Protocol: 6}); ok {
		t.Fatal("absent v4 tuple must miss")
	}
	if _, _, _, _, ok := d.liveFlowCounters(flowexport.FlowKey{SrcIP: "2001:db8::1", DstIP: "2001:db8::2", SrcPort: 1111, DstPort: 443, Protocol: 6, IsIPv6: true}); ok {
		t.Fatal("absent v6 tuple must miss")
	}
}

// TestLiveFeedMissCounter16760: a tracked key the source no longer
// holds increments FlowLiveFeedMisses; a hit does not.
func TestLiveFeedMissCounter16760(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	d.flowLiveCounters = func(key flowexport.FlowKey) (uint64, uint64, uint64, uint64, bool) {
		if key.SrcPort == 34567 {
			return 10, 1000, 4, 400, true
		}
		return 0, 0, 0, 0, false
	}
	// Drive feedFlowLiveCounters with exporters from reconcile.
	v9Coll, v9Port := listenUDP(t)
	t.Cleanup(func() { v9Coll.Close() })
	ipfixColl, ipfixPort := listenUDP(t)
	t.Cleanup(func() { ipfixColl.Close() })
	cfg := openSamplingConfig16303(t, v9Port, ipfixPort, "1")
	if !d.reconcileFlowExporters(cfg) {
		t.Fatal("exporters must start")
	}
	// Register tracked flows on every group so TrackedKeys is non-empty.
	hit := flowexport.FlowKey{SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 34567, DstPort: 443, Protocol: 6}
	miss := flowexport.FlowKey{SrcIP: "10.0.0.103", DstIP: "192.0.2.201", SrcPort: 2222, DstPort: 443, Protocol: 6}
	groups := 0
	if b := d.v9Family().bundle.Load(); b != nil {
		for _, g := range b.groups {
			g.exp.TrackFlowOpenRecord(hit, time.Now(), template16760(hit))
			g.exp.TrackFlowOpenRecord(miss, time.Now(), template16760(miss))
			groups++
		}
	}
	if b := d.ipfixFamily().bundle.Load(); b != nil {
		for _, g := range b.groups {
			g.exp.TrackFlowOpenRecord(hit, time.Now(), template16760(hit))
			g.exp.TrackFlowOpenRecord(miss, time.Now(), template16760(miss))
			groups++
		}
	}
	if groups == 0 {
		t.Fatal("no exporter groups published")
	}
	before := d.FlowLiveFeedMisses()
	d.feedFlowLiveCounters(time.Now())
	// Exactly one miss per group (the miss key); the hit key must not count.
	if got := d.FlowLiveFeedMisses() - before; got != uint64(groups) {
		t.Fatalf("FlowLiveFeedMisses delta = %d, want %d (one per group)", got, groups)
	}
	// Nil daemon is safe.
	if got := (*Daemon)(nil).FlowLiveFeedMisses(); got != 0 {
		t.Fatalf("nil daemon FlowLiveFeedMisses = %d, want 0", got)
	}
}
