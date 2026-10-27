package daemon

import (
	"encoding/binary"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/flowexport"
)

// #16754 daemon integration: a SESSION_OPEN sampled on the egress
// interface (ge-0/0/2.0 output-sampled, ge-0/0/0.0 unsampled) must
// produce an active-timeout interim carrying Direction=1 and the
// resolved route masks — the same fields its close record carries.
// Pre-fix the interim was a verbatim copy of the open template:
// Direction 0, SrcMask/DstMask 0/0.
//
// The exporters' MaskResolver is replaced with a deterministic FIB so
// the test needs no kernel route lookup; the direction path runs the
// production open → tracker → CollectDueExports chain.
func trackerFieldsConfig16754(t *testing.T, v9Port, ipfixPort int) *config.Config {
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
            input { rate 1; }
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
        version9 { template t { flow-active-timeout 60; flow-inactive-timeout 15; ipv4-template { export-extension flow-dir; } } }
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

func TestTrackerInterimEgressDirectionAndMasks16754(t *testing.T) {
	v9Coll, v9Port := listenUDP(t)
	t.Cleanup(func() { v9Coll.Close() })
	ipfixColl, ipfixPort := listenUDP(t)
	t.Cleanup(func() { ipfixColl.Close() })
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	d.eventReader.SetIfNames(map[uint32]string{11: "ge-0/0/0.0", 12: "ge-0/0/2.0"})

	live := struct{ fp, fb, rp, rb uint64 }{100, 10000, 40, 4000}
	d.flowLiveCounters = func(flowexport.FlowKey) (uint64, uint64, uint64, uint64, bool) {
		return live.fp, live.fb, live.rp, live.rb, true
	}
	if !d.reconcileFlowExporters(trackerFieldsConfig16754(t, v9Port, ipfixPort)) {
		t.Fatal("exporters must start")
	}

	// Deterministic FIB: src /24, dst /30 (mirrors the flowexport
	// maskResolverFor seam); VRF-scope assertions are in the unit test.
	maskFor := flowexport.MaskResolver(func(ip net.IP, _ int) (uint8, bool) {
		if ip.String() == "10.0.0.102" {
			return 24, true
		}
		if ip.String() == "192.0.2.200" {
			return 30, true
		}
		return 0, false
	})

	var v9exp flowExporter
	var ipexp flowExporter
	for _, g := range d.v9Family().bundle.Load().groups {
		if !g.ec.GroupIsV6 {
			v9exp = g.exp
		}
	}
	for _, g := range d.ipfixFamily().bundle.Load().groups {
		if !g.ec.GroupIsV6 {
			ipexp = g.exp
		}
	}
	if v9exp == nil || ipexp == nil {
		t.Fatal("v4 groups must exist")
	}
	v9exp.SetMaskResolver(maskFor)
	ipexp.SetMaskResolver(maskFor)

	trust, untrust := config.StableZoneID("trust"), config.StableZoneID("untrust")
	if !d.eventReader.ProcessRawEvent(openRaw16303(44567, 11, 12, uint16(trust), uint16(untrust))) {
		t.Fatal("open rejected")
	}
	key := flowexport.FlowKey{SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 44567, DstPort: 443, Protocol: 6}
	if !v9exp.Tracked(key) || !ipexp.Tracked(key) {
		t.Fatal("egress-sampled open must be tracked in both formats")
	}

	now := time.Now()
	// Feed with a fresh activity stamp so the 15s inactive timer does
	// not fire before the 60s active window (as in #16303 F5 tests).
	d.feedFlowLiveCounters(now.Add(50 * time.Second))
	d.feedFlowLiveCounters(now)
	due9 := v9exp.CollectDueExports(now.Add(61 * time.Second))
	if len(due9) != 1 {
		t.Fatalf("v9 interim = %+v, want 1", due9)
	}
	if due9[0].Direction != 1 {
		t.Fatalf("v9 interim Direction = %d, want 1 (egress-sampled)", due9[0].Direction)
	}
	if due9[0].SrcMask != 24 || due9[0].DstMask != 30 {
		t.Fatalf("v9 interim masks = %d/%d, want 24/30 (same as close)", due9[0].SrcMask, due9[0].DstMask)
	}
	dueIP := ipexp.CollectDueExports(now.Add(61 * time.Second))
	if len(dueIP) != 1 || dueIP[0].Direction != 1 || dueIP[0].SrcMask != 24 || dueIP[0].DstMask != 30 {
		t.Fatalf("ipfix interim = %+v, want Direction 1 masks 24/30", dueIP)
	}

	// Control: the close record for the same flow carries the same
	// Direction/masks (close remainder after the interim baseline).
	closeBuf := buildSessionCloseRawEventV4(6, [4]byte{10, 0, 0, 102}, [4]byte{192, 0, 2, 200}, 44567, 443, [4]byte{}, 0, uint16(trust), uint16(untrust))
	binary.LittleEndian.PutUint64(closeBuf[56:64], 280)
	binary.LittleEndian.PutUint64(closeBuf[64:72], 28000)
	if !d.eventReader.ProcessRawEvent(closeBuf) {
		t.Fatal("close rejected")
	}
	if v9exp.Tracked(key) {
		t.Fatal("close must forget the tracked flow")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if got, _ := v9exp.Stats(); got >= 2 {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("v9 exported = %d, want >=2 (interim + close remainder)", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
