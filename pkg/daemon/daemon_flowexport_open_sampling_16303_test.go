package daemon

import (
	"encoding/binary"
	"strconv"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/flowexport"
)

// #16303: dual-format opens consume exactly one sampling slot per
// instance, and an output-only sampled flow is tracked from its
// production-shaped SESSION_OPEN (unsampled ingress name + sampled
// egress name from the frame's [148:152] egress slot).

func openSamplingConfig16303(t *testing.T, v9Port, ipfixPort int, rate string) *config.Config {
	t.Helper()
	text := `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet { address 10.0.0.1/24; }
            family inet6 { address 2001:db8::1/64; }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet { address 192.0.2.1/24; sampling { output; } }
            family inet6 { address 2001:db8:1::1/64; sampling { output; } }
        }
    }
}
security {
    zones {
        security-zone trust { interfaces { ge-0/0/0.0; } }
        security-zone untrust { interfaces { ge-0/0/2.0; } }
    }
}
forwarding-options {
    sampling {
        instance s {
            input { rate ` + rate + `; }
            family inet {
                output {
                    flow-server 127.0.0.1 { port ` + strconv.Itoa(v9Port) + `; version9; }
                    flow-server 127.0.0.1 { port ` + strconv.Itoa(ipfixPort) + `; version-ipfix; }
                }
            }
            family inet6 {
                output {
                    flow-server 127.0.0.1 { port ` + strconv.Itoa(v9Port) + `; version9; }
                    flow-server 127.0.0.1 { port ` + strconv.Itoa(ipfixPort) + `; version-ipfix; }
                }
            }
        }
    }
}
services {
    flow-monitoring {
        version9 { template t { flow-active-timeout 60; flow-inactive-timeout 15; } }
        version-ipfix { template t { flow-active-timeout 60; flow-inactive-timeout 15; } }
    }
}
`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func openRaw16303(srcPort uint16, ingressIfindex, egressIfindex uint32, ingressZone, egressZone uint16) []byte {
	buf := make([]byte, 168) // full SESSION_RT_FLOW payload incl. [148:152]
	copy(buf[8:12], []byte{10, 0, 0, 102})
	copy(buf[24:28], []byte{192, 0, 2, 200})
	binary.BigEndian.PutUint16(buf[40:42], srcPort)
	binary.BigEndian.PutUint16(buf[42:44], 443)
	binary.LittleEndian.PutUint16(buf[48:50], ingressZone)
	binary.LittleEndian.PutUint16(buf[50:52], egressZone)
	buf[52] = dataplane.EventTypeSessionOpen
	buf[53] = 6
	buf[55] = dataplane.AFInet
	buf[135] = 1
	binary.LittleEndian.PutUint32(buf[128:132], ingressIfindex)
	binary.LittleEndian.PutUint32(buf[148:152], egressIfindex)
	return buf
}

func TestDualFormatOpenConsumesOneSlotPerInstance16303(t *testing.T) {
	v9Coll, v9Port := listenUDP(t)
	t.Cleanup(func() { v9Coll.Close() })
	ipfixColl, ipfixPort := listenUDP(t)
	t.Cleanup(func() { ipfixColl.Close() })

	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	d.eventReader.SetIfNames(map[uint32]string{11: "ge-0/0/0.0", 12: "ge-0/0/2.0"})
	if !d.reconcileFlowExporters(openSamplingConfig16303(t, v9Port, ipfixPort, "2")) {
		t.Fatal("exporters must start")
	}
	if n := d.eventReader.CallbackCount(); n != 3 {
		t.Fatalf("callbacks = %d, want 3 (open fanout + v9 + ipfix)", n)
	}
	trust, untrust := config.StableZoneID("trust"), config.StableZoneID("untrust")

	// Rate 2, burst of three opens: exactly the second is selected in
	// each format (counter 1,2,3 -> selected={2}), not every flow as a
	// double-evaluation (1,2 / 3,4 / 5,6) would produce.
	for _, port := range []uint16{12345, 12346, 12347} {
		if !d.eventReader.ProcessRawEvent(openRaw16303(port, 11, 12, trust, untrust)) {
			t.Fatal("open rejected")
		}
	}
	for _, s := range d.FlowExportSamplingStats() {
		if s.Evaluated != 3 || s.Selected != 1 {
			t.Fatalf("dual-format open sampling = %+v, want evaluated=3 selected=1", s)
		}
	}
	key := flowexport.FlowKey{SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 12346, DstPort: 443, Protocol: 6}
	if b := d.flowBundle.Load(); b == nil || !b.firstExp().Tracked(key) {
		t.Fatal("selected v9 open (second flow) must be tracked")
	}
	if b := d.ipfixBundlePtr.Load(); b == nil || !b.firstExp().Tracked(key) {
		t.Fatal("selected ipfix open (second flow) must be tracked")
	}
	unsampled := flowexport.FlowKey{SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 12345, DstPort: 443, Protocol: 6}
	if d.flowBundle.Load().firstExp().Tracked(unsampled) {
		t.Fatal("first (sampled-out) open must not be tracked")
	}

	// Its close exports in both formats without another evaluation.
	closeBuf := buildSessionCloseRawEventV4(6, [4]byte{10, 0, 0, 102}, [4]byte{192, 0, 2, 200}, 12346, 443, [4]byte{}, 0, trust, untrust)
	binary.LittleEndian.PutUint32(closeBuf[128:132], 11)
	if !d.eventReader.ProcessRawEvent(closeBuf) {
		t.Fatal("close rejected")
	}
	for _, s := range d.FlowExportSamplingStats() {
		if s.Evaluated != 3 || s.Selected != 1 {
			t.Fatalf("close consumed another slot: %+v", s)
		}
	}
	if got := waitFlows(t, d.flowBundle.Load().firstExp().Stats); got < 1 {
		t.Fatal("v9 close of sampled open must export")
	}
	if got := waitFlows(t, d.ipfixBundlePtr.Load().firstExp().Stats); got < 1 {
		t.Fatal("ipfix close of sampled open must export")
	}
}

func TestOutputOnlySampledOpenIsTracked16303(t *testing.T) {
	v9Coll, v9Port := listenUDP(t)
	t.Cleanup(func() { v9Coll.Close() })
	ipfixColl, ipfixPort := listenUDP(t)
	t.Cleanup(func() { ipfixColl.Close() })

	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	// Ingress ge-0/0/0.0 is named but unsampled; egress ge-0/0/2.0 is
	// output-sampled. Before #16303 the open carried no egress identity
	// and was rejected, so timeout tracking never started.
	d.eventReader.SetIfNames(map[uint32]string{11: "ge-0/0/0.0", 12: "ge-0/0/2.0"})
	if !d.reconcileFlowExporters(openSamplingConfig16303(t, v9Port, ipfixPort, "1")) {
		t.Fatal("exporters must start")
	}
	trust, untrust := config.StableZoneID("trust"), config.StableZoneID("untrust")
	if !d.eventReader.ProcessRawEvent(openRaw16303(23456, 11, 12, trust, untrust)) {
		t.Fatal("open rejected")
	}
	key := flowexport.FlowKey{SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 23456, DstPort: 443, Protocol: 6}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if d.flowBundle.Load().firstExp().Tracked(key) && d.ipfixBundlePtr.Load().firstExp().Tracked(key) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("output-only sampled open must be tracked in both formats")
}
