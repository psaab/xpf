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

func closeRawWithIngress15230(ingressIfindex uint32, ingressZone, egressZone uint16) []byte {
	buf := buildSessionCloseRawEventV4(6,
		[4]byte{10, 0, 0, 102}, [4]byte{192, 0, 2, 200},
		12345, 443, [4]byte{}, 0, ingressZone, egressZone)
	// Ensure the buffer is at least the extended size so [128:132] exists.
	if len(buf) < int(unsafe.Sizeof(dataplane.Event{})) {
		nb := make([]byte, int(unsafe.Sizeof(dataplane.Event{})))
		copy(nb, buf)
		buf = nb
	}
	binary.LittleEndian.PutUint32(buf[128:132], ingressIfindex)
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

	// Unsampled ingress: must not export.
	if !d.eventReader.ProcessRawEvent(closeRawWithIngress15230(12, trust, untrust)) {
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

	// Sampled control: must export (rate 1 in this config via default).
	if !d.eventReader.ProcessRawEvent(closeRawWithIngress15230(11, trust, untrust)) {
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
}
