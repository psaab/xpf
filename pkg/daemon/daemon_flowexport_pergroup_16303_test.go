package daemon

import (
	"encoding/binary"
	"strconv"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/flowexport"
)

// #16303 fold 3: same-instance template groups have independent trackers
// (staggered active timeouts). The close callbacks must apply EACH
// group's own baseline to that group's remainder — collapsing them into
// one tuple made the last group's baseline subtract from every group.

func twoTemplateConfig16303(t *testing.T, v9Port, ipfixPort int) *config.Config {
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
                    flow-server 127.0.0.1 { port ` + strconv.Itoa(v9Port) + `; version9 { template fast; } }
                    flow-server 127.0.0.1 { port ` + strconv.Itoa(v9Port) + `; version9 { template slow; } }
                    flow-server 127.0.0.1 { port ` + strconv.Itoa(ipfixPort) + `; version-ipfix { template fast; } }
                    flow-server 127.0.0.1 { port ` + strconv.Itoa(ipfixPort) + `; version-ipfix { template slow; } }
                }
            }
            family inet6 {
                output {
                    flow-server 127.0.0.1 { port ` + strconv.Itoa(v9Port) + `; version9 { template fast; } }
                    flow-server 127.0.0.1 { port ` + strconv.Itoa(v9Port) + `; version9 { template slow; } }
                    flow-server 127.0.0.1 { port ` + strconv.Itoa(ipfixPort) + `; version-ipfix { template fast; } }
                    flow-server 127.0.0.1 { port ` + strconv.Itoa(ipfixPort) + `; version-ipfix { template slow; } }
                }
            }
        }
    }
}
services {
    flow-monitoring {
        version9 {
            template fast { flow-active-timeout 30; flow-inactive-timeout 900; }
            template slow { flow-active-timeout 300; flow-inactive-timeout 900; }
        }
        version-ipfix {
            template fast { flow-active-timeout 30; flow-inactive-timeout 900; }
            template slow { flow-active-timeout 300; flow-inactive-timeout 900; }
        }
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

func TestPerGroupCloseBaselines16303(t *testing.T) {
	v9Coll, v9Port := listenUDP(t)
	t.Cleanup(func() { v9Coll.Close() })
	ipfixColl, ipfixPort := listenUDP(t)
	t.Cleanup(func() { ipfixColl.Close() })

	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	d.eventReader.SetIfNames(map[uint32]string{11: "ge-0/0/0.0", 12: "ge-0/0/2.0"})

	now := time.Now()
	live := struct{ fp, fb, rp, rb uint64 }{200, 20000, 90, 9000}
	d.flowLiveCounters = func(flowexport.FlowKey) (uint64, uint64, uint64, uint64, bool) {
		return live.fp, live.fb, live.rp, live.rb, true
	}
	if !d.reconcileFlowExporters(twoTemplateConfig16303(t, v9Port, ipfixPort)) {
		t.Fatal("exporters must start")
	}
	vb := d.flowBundle.Load()
	ib := d.ipfixBundlePtr.Load()
	if vb == nil || len(vb.groups) < 2 || ib == nil || len(ib.groups) < 2 {
		t.Fatalf("want >=2 groups per family, v9=%v ipfix=%v", vb, ib)
	}
	trust, untrust := config.StableZoneID("trust"), config.StableZoneID("untrust")
	if !d.eventReader.ProcessRawEvent(openRaw16303(45678, 11, 12, trust, untrust)) {
		t.Fatal("open rejected")
	}
	key := flowexport.FlowKey{SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 45678, DstPort: 443, Protocol: 6}

	byTemplateV9 := map[string]*flowexport.Exporter{}
	for _, g := range vb.groups {
		if !g.ec.GroupIsV6 {
			byTemplateV9[g.ec.TemplateName] = g.exp
		}
	}
	byTemplateIPFIX := map[string]*flowexport.IPFIXExporter{}
	for _, g := range ib.groups {
		if !g.ec.GroupIsV6 {
			byTemplateIPFIX[g.ec.TemplateName] = g.exp
		}
	}
	fastV9, slowV9 := byTemplateV9["fast"], byTemplateV9["slow"]
	fastIP, slowIP := byTemplateIPFIX["fast"], byTemplateIPFIX["slow"]
	if fastV9 == nil || slowV9 == nil || fastIP == nil || slowIP == nil {
		t.Fatalf("groups by template: v9 fast=%v slow=%v ipfix fast=%v slow=%v", fastV9 != nil, slowV9 != nil, fastIP != nil, slowIP != nil)
	}

	// Live feed at counters 200/90, then stagger: fast (30s) collects an
	// interim at +31s (baseline 200/90); slow (300s) collects nothing.
	d.feedFlowLiveCounters(now.Add(10 * time.Second))
	if due := fastV9.CollectDueExports(now.Add(31 * time.Second)); len(due) != 1 || due[0].Packets != 200 {
		t.Fatalf("fast v9 interim = %+v, want fwd=200", due)
	}
	if due := fastIP.CollectDueExports(now.Add(31 * time.Second)); len(due) != 1 || due[0].Packets != 200 || due[0].RevPackets != 90 {
		t.Fatalf("fast ipfix interim = %+v, want fwd=200 rev=90", due)
	}
	if due := slowV9.CollectDueExports(now.Add(31 * time.Second)); len(due) != 0 {
		t.Fatalf("slow v9 must not interim at 31s, got %+v", due)
	}
	if due := slowIP.CollectDueExports(now.Add(31 * time.Second)); len(due) != 0 {
		t.Fatalf("slow ipfix must not interim at 31s, got %+v", due)
	}

	// Real close at cumulative 280/130. fast groups must queue remainder
	// 80/40; slow groups the full 280/130 (decisive sum check is the
	// flowexport remainder test; here record counts + per-group
	// forgetting prove each group used its own baseline path).
	closeBuf := buildSessionCloseRawEventV4(6, [4]byte{10, 0, 0, 102}, [4]byte{192, 0, 2, 200}, 45678, 443, [4]byte{}, 0, trust, untrust)
	binary.LittleEndian.PutUint64(closeBuf[56:64], 280)
	binary.LittleEndian.PutUint64(closeBuf[64:72], 28000)
	binary.LittleEndian.PutUint64(closeBuf[112:120], 130)
	binary.LittleEndian.PutUint64(closeBuf[120:128], 13000)
	if !d.eventReader.ProcessRawEvent(closeBuf) {
		t.Fatal("close rejected")
	}
	if fastV9.Tracked(key) || slowV9.Tracked(key) || fastIP.Tracked(key) || slowIP.Tracked(key) {
		t.Fatal("every group's entry must be forgotten at close")
	}
	// Flush both families and require: fast groups exported 2 records
	// (interim + 80-remainder), slow groups 1 record (full close).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f1, _ := fastV9.Stats()
		s1, _ := slowV9.Stats()
		f2, _ := fastIP.Stats()
		s2, _ := slowIP.Stats()
		if f1 >= 2 && s1 >= 1 && f2 >= 2 && s2 >= 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	f1, _ := fastV9.Stats()
	s1, _ := slowV9.Stats()
	f2, _ := fastIP.Stats()
	s2, _ := slowIP.Stats()
	t.Fatalf("record counts fastV9=%d slowV9=%d fastIPFIX=%d slowIPFIX=%d, want 2/1/2/1 (per-group remainder)", f1, s1, f2, s2)
}
