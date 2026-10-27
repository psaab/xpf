package daemon

import (
	"encoding/binary"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/logging"
)

// #15230 A46-05 daemon leg: trust has ge-0/0/0.0 (sampled input) and
// ge-0/0/1.0 (unsampled). A SESSION_CLOSE ingressing on ge-0/0/1.0 must
// not be exported; the ge-0/0/0.0 control must. The ifindex->name table
// is installed exactly as applySyslogConfig does (buildIfNames needs
// real netdevs, so the test installs the same map shape directly).

func samplingInterfaceDaemonConfig15230(t *testing.T, v9Port, ipfixPort int) *config.Config {
	t.Helper()
	text := `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet { address 10.0.0.1/24; sampling { input; } }
        }
    }
    ge-0/0/1 {
        unit 0 {
            family inet { address 10.0.1.1/24; }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet { address 192.0.2.1/24; }
        }
    }
}
security {
    zones {
        security-zone trust { interfaces { ge-0/0/0.0; ge-0/0/1.0; } }
        security-zone untrust { interfaces { ge-0/0/2.0; } }
    }
}
forwarding-options {
    sampling {
        instance s {
            family inet {
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
        version9 { template t { } }
        version-ipfix { template t { } }
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

func rawWithIngress15230(eventType byte, ingressIfindex uint32, ingressZone, egressZone uint16) []byte {
	buf := buildSessionCloseRawEventV4(6,
		[4]byte{10, 0, 0, 102}, [4]byte{192, 0, 2, 200},
		12345, 443, [4]byte{}, 0, ingressZone, egressZone)
	buf[52] = eventType
	// Ensure the buffer is at least the extended size so [128:132] exists.
	if len(buf) < int(unsafe.Sizeof(dataplane.Event{})) {
		nb := make([]byte, int(unsafe.Sizeof(dataplane.Event{})))
		copy(nb, buf)
		buf = nb
	}
	binary.LittleEndian.PutUint32(buf[128:132], ingressIfindex)
	return buf
}

func closeRawWithIngress15230(ingressIfindex uint32, ingressZone, egressZone uint16) []byte {
	return rawWithIngress15230(dataplane.EventTypeSessionClose, ingressIfindex, ingressZone, egressZone)
}

func openRawWithIngress15230(ingressIfindex uint32, ingressZone, egressZone uint16) []byte {
	buf := rawWithIngress15230(dataplane.EventTypeSessionOpen, ingressIfindex, ingressZone, egressZone)
	buf[135] = 1 // syslog gate open; callbacks run regardless
	return buf
}

func TestSessionCloseSamplingPerInterface15230(t *testing.T) {
	v9Coll, v9Port := listenUDP(t)
	t.Cleanup(func() { v9Coll.Close() })
	ipfixColl, ipfixPort := listenUDP(t)
	t.Cleanup(func() { ipfixColl.Close() })

	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	// Synthetic ifindex table: 11 = sampled ge-0/0/0.0, 12 = unsampled ge-0/0/1.0.
	d.eventReader.SetIfNames(map[uint32]string{11: "ge-0/0/0.0", 12: "ge-0/0/1.0"})

	cfg := samplingInterfaceDaemonConfig15230(t, v9Port, ipfixPort)
	if !d.reconcileFlowExporters(cfg) {
		t.Fatal("exporters must start")
	}
	trust, untrust := config.StableZoneID("trust"), config.StableZoneID("untrust")

	// Probe decoding: records must carry the interface names.
	var probe logging.EventRecord
	d.eventReader.AddCallback(func(rec logging.EventRecord, _ []byte) {
		if rec.Type == "SESSION_CLOSE" {
			probe = rec
		}
	})

	// Unsampled ingress open: the single open decision must deny it
	// without consuming a slot, so its close exports nothing.
	if !d.eventReader.ProcessRawEvent(openRawWithIngress15230(12, uint16(trust), uint16(untrust))) {
		t.Fatal("ProcessRawEvent rejected unsampled open")
	}
	if !d.eventReader.ProcessRawEvent(closeRawWithIngress15230(12, uint16(trust), uint16(untrust))) {
		t.Fatal("ProcessRawEvent rejected unsampled close")
	}
	if probe.IngressIface != "ge-0/0/1.0" {
		t.Fatalf("probe IngressIface = %q, want ge-0/0/1.0 (fixture would be vacuous)", probe.IngressIface)
	}
	time.Sleep(400 * time.Millisecond)
	if b := d.flowBundle.Load(); b != nil && len(b.groups) > 0 {
		if flows, _ := b.firstExp().Stats(); flows != 0 {
			t.Fatalf("v9 exported %d flows from unsampled ge-0/0/1.0, want 0", flows)
		}
	}
	if b := d.ipfixBundlePtr.Load(); b != nil && len(b.groups) > 0 {
		if flows, _ := b.firstExp().Stats(); flows != 0 {
			t.Fatalf("ipfix exported %d flows from unsampled ge-0/0/1.0, want 0", flows)
		}
	}
	for _, s := range d.FlowExportSamplingStats() {
		if s.Evaluated != 0 || s.Selected != 0 {
			t.Fatalf("unsampled flow consumed slots: %+v", s)
		}
		if s.ZoneFiltered == 0 {
			t.Fatalf("unsampled flow must count zoneFiltered: %+v", s)
		}
	}

	// Nameless close (ifindex absent from the map, so no interface
	// name resolves) with no recorded open: #16742 makes ONE close-time
	// fallback decision. In daemon scope a record naming no interface
	// at all falls back to zone semantics (#15946 scoping): trust input
	// is sampled, rate 1 here, so the close exports and consumes
	// exactly one fallback slot. The strict unit-level fail-closed
	// contract itself stays pinned in pkg/flowexport (strictEligible).
	if !d.eventReader.ProcessRawEvent(closeRawWithIngress15230(99, uint16(trust), uint16(untrust))) {
		t.Fatal("ProcessRawEvent rejected nameless close")
	}
	if got := waitFlows(t, d.flowBundle.Load().firstExp().Stats); got < 1 {
		t.Fatalf("v9 nameless no-open close: exported %d, want 1 via #16742 close-time fallback (zone semantics, rate 1)", got)
	}
	for _, s := range d.FlowExportSamplingStats() {
		if s.Evaluated != 1 || s.Selected != 1 {
			t.Fatalf("nameless no-open close must consume exactly one fallback slot: %+v", s)
		}
	}

	// Sampled control: open makes the one decision; close exports
	// without consuming another slot (rate 1 in this config).
	if !d.eventReader.ProcessRawEvent(openRawWithIngress15230(11, uint16(trust), uint16(untrust))) {
		t.Fatal("ProcessRawEvent rejected sampled open")
	}
	if !d.eventReader.ProcessRawEvent(closeRawWithIngress15230(11, uint16(trust), uint16(untrust))) {
		t.Fatal("ProcessRawEvent rejected sampled close")
	}
	if probe.IngressIface != "ge-0/0/0.0" {
		t.Fatalf("probe IngressIface = %q, want ge-0/0/0.0", probe.IngressIface)
	}
	if got := waitFlows(t, d.flowBundle.Load().firstExp().Stats); got < 1 {
		t.Fatalf("v9 exported %d sampled flows, want >=1", got)
	}
	if got := waitFlows(t, d.ipfixBundlePtr.Load().firstExp().Stats); got < 1 {
		t.Fatalf("ipfix exported %d sampled flows, want >=1", got)
	}
	for _, s := range d.FlowExportSamplingStats() {
		// One #16742 fallback evaluation (nameless close above) plus
		// exactly one open evaluation for the sampled control; the
		// control's close consumed no second slot.
		if s.Evaluated != 2 || s.Selected != 2 {
			t.Fatalf("sampled open/close must consume exactly one slot per instance (plus the one #16742 fallback), got %+v", s)
		}
	}
}
