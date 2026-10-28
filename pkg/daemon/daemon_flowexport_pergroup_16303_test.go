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

// decodedFlow is one data record decoded off a collector socket,
// attributed to its exporter group by SourceID/ObservationDomain.
type decodedFlow16303 struct {
	packets, bytes     uint64
	revPackets, revByt uint64
}

// drainGroup16303 reads datagrams from conn until the deadline and
// decodes every v4 data record, grouped by header SourceID (v9 at
// [16:20]) or Observation Domain ID (IPFIX at [12:16]).
func drainGroup16303(t *testing.T, conn interface {
	Read([]byte) (int, error)
	SetReadDeadline(time.Time) error
}, isIPFIX bool, want map[uint32]int) map[uint32][]decodedFlow16303 {
	t.Helper()
	out := map[uint32][]decodedFlow16303{}
	templates := map[uint16][][2]uint16{} // templateID -> (elementID,len), enterprise folded into elementID|0x8000
	buf := make([]byte, 65535)
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if doneGroupCounts16303(out, want) {
			break
		}
		_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil {
			continue
		}
		pkt := buf[:n]
		if isIPFIX {
			decodeIPFIX16303(pkt, templates, out)
		} else {
			decodeV916303(pkt, templates, out)
		}
	}
	return out
}

func doneGroupCounts16303(out map[uint32][]decodedFlow16303, want map[uint32]int) bool {
	for id, n := range want {
		if len(out[id]) < n {
			return false
		}
	}
	return len(want) > 0
}

func decodeV916303(pkt []byte, templates map[uint16][][2]uint16, out map[uint32][]decodedFlow16303) {
	if len(pkt) < 20 || binary.BigEndian.Uint16(pkt[0:2]) != 9 {
		return
	}
	srcID := binary.BigEndian.Uint32(pkt[16:20])
	off := 20
	for off+4 <= len(pkt) {
		setID := binary.BigEndian.Uint16(pkt[off : off+2])
		setLen := int(binary.BigEndian.Uint16(pkt[off+2 : off+4]))
		if setLen < 4 || off+setLen > len(pkt) {
			return
		}
		body := pkt[off+4 : off+setLen]
		if setID == 0 { // template set: one v4 + one v6 template
			for len(body) >= 4 {
				tid := binary.BigEndian.Uint16(body[0:2])
				cnt := int(binary.BigEndian.Uint16(body[2:4]))
				if len(body) < 4+cnt*4 {
					return
				}
				var fields [][2]uint16
				for i := range cnt {
					fields = append(fields, [2]uint16{binary.BigEndian.Uint16(body[4+i*4:]), binary.BigEndian.Uint16(body[6+i*4:])})
				}
				templates[tid] = fields
				body = body[4+cnt*4:]
			}
		} else if fields, ok := templates[setID]; ok {
			recSize := 0
			for _, f := range fields {
				recSize += int(f[1])
			}
			if recSize == 0 {
				return
			}
			for r := 0; r+recSize <= len(body); r += recSize {
				rec := body[r : r+recSize]
				var df decodedFlow16303
				pos := 0
				for _, f := range fields {
					l := int(f[1])
					if pos+l > len(rec) {
						return
					}
					switch f[0] {
					case 2: // IN_PKTS
						df.packets = binary.BigEndian.Uint64(rec[pos:])
					case 1: // IN_BYTES
						df.bytes = binary.BigEndian.Uint64(rec[pos:])
					}
					pos += l
				}
				out[srcID] = append(out[srcID], df)
			}
		}
		off += setLen
	}
}

func decodeIPFIX16303(pkt []byte, templates map[uint16][][2]uint16, out map[uint32][]decodedFlow16303) {
	if len(pkt) < 16 || binary.BigEndian.Uint16(pkt[0:2]) != 10 {
		return
	}
	odid := binary.BigEndian.Uint32(pkt[12:16])
	off := 16
	for off+4 <= len(pkt) {
		setID := binary.BigEndian.Uint16(pkt[off : off+2])
		setLen := int(binary.BigEndian.Uint16(pkt[off+2 : off+4]))
		if setLen < 4 || off+setLen > len(pkt) {
			return
		}
		body := pkt[off+4 : off+setLen]
		if setID == 2 { // template set
			for len(body) >= 4 {
				tid := binary.BigEndian.Uint16(body[0:2])
				cnt := int(binary.BigEndian.Uint16(body[2:4]))
				body = body[4:]
				var fields [][2]uint16
				ok := true
				for i := 0; i < cnt; i++ {
					if len(body) < 4 {
						ok = false
						break
					}
					id := binary.BigEndian.Uint16(body[0:2])
					l := binary.BigEndian.Uint16(body[2:4])
					body = body[4:]
					if id&0x8000 != 0 {
						if len(body) < 4 {
							ok = false
							break
						}
						body = body[4:]
						fields = append(fields, [2]uint16{id | 0x8000, l})
					} else {
						fields = append(fields, [2]uint16{id, l})
					}
					_ = i
				}
				if !ok {
					return
				}
				templates[tid] = fields
			}
		} else if setID == 3 {
			// options template: skip (6-byte record headers)
			continue
		} else if fields, ok := templates[setID]; ok {
			recSize := 0
			for _, f := range fields {
				recSize += int(f[1])
			}
			if recSize == 0 {
				return
			}
			for r := 0; r+recSize <= len(body); r += recSize {
				rec := body[r : r+recSize]
				var df decodedFlow16303
				pos := 0
				for _, f := range fields {
					l := int(f[1])
					switch f[0] {
					case 2:
						df.packets = binary.BigEndian.Uint64(rec[pos:])
					case 1:
						df.bytes = binary.BigEndian.Uint64(rec[pos:])
					case 0x8002: // reverse packetDeltaCount (IE2 + enterprise bit)
						df.revPackets = binary.BigEndian.Uint64(rec[pos:])
					case 0x8001: // reverse octetDeltaCount
						df.revByt = binary.BigEndian.Uint64(rec[pos:])
					}
					pos += l
				}
				out[odid] = append(out[odid], df)
			}
		}
		off += setLen
	}
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
	vb := d.v9Family().bundle.Load()
	ib := d.ipfixFamily().bundle.Load()
	if vb == nil || len(vb.groups) < 2 || ib == nil || len(ib.groups) < 2 {
		t.Fatalf("want >=2 groups per family, v9=%v ipfix=%v", vb, ib)
	}
	trust, untrust := config.StableZoneID("trust"), config.StableZoneID("untrust")
	if !d.eventReader.ProcessRawEvent(openRaw16303(45678, 11, 12, uint16(trust), uint16(untrust))) {
		t.Fatal("open rejected")
	}
	key := flowexport.FlowKey{SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 45678, DstPort: 443, Protocol: 6}

	byTemplateV9 := map[string]flowExporter{}
	for _, g := range vb.groups {
		if !g.ec.GroupIsV6 {
			byTemplateV9[g.ec.TemplateName] = g.exp
		}
	}
	byTemplateIPFIX := map[string]flowExporter{}
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
	closeBuf := buildSessionCloseRawEventV4(6, [4]byte{10, 0, 0, 102}, [4]byte{192, 0, 2, 200}, 45678, 443, [4]byte{}, 0, uint16(trust), uint16(untrust))
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
	// Flush, then DECODE each group's records off the collector sockets
	// (grouped by SourceID/Observation Domain — fast and slow share one
	// socket per protocol). The close record must carry ONLY that
	// group's remainder: fast 80/40 (280-200 / 130-90), slow the full
	// 280/130. Record counts alone cannot catch the shared-baseline bug.
	deadline := time.Now().Add(3 * time.Second)
	var f1, s1, f2, s2 uint64
	for time.Now().Before(deadline) {
		f1, _ = fastV9.Stats()
		s1, _ = slowV9.Stats()
		f2, _ = fastIP.Stats()
		s2, _ = slowIP.Stats()
		if f1 >= 2 && s1 >= 1 && f2 >= 2 && s2 >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !(f1 >= 2 && s1 >= 1 && f2 >= 2 && s2 >= 1) {
		t.Fatalf("record counts fastV9=%d slowV9=%d fastIPFIX=%d slowIPFIX=%d, want 2/1/2/1", f1, s1, f2, s2)
	}
	v9BySrc := drainGroup16303(t, v9Coll, false, map[uint32]int{})
	ipBySrc := drainGroup16303(t, ipfixColl, true, map[uint32]int{})
	assertGroupClose16303(t, "v9", v9BySrc, false)
	assertGroupClose16303(t, "ipfix", ipBySrc, true)
}

// assertGroupClose16303 finds the two SourceIDs (fast+slow) and checks
// close-record magnitudes: one totals via 200-interim + 80-close, the
// other via a single 280 close. Either assignment (fast/slow SourceID
// order unknown) is accepted, but the pair must be {80, 280} packets
// for close records — the shared-baseline mutation makes both 80
// (last-group baseline) or both 280.
func assertGroupClose16303(t *testing.T, proto string, bySrc map[uint32][]decodedFlow16303, isIPFIX bool) {
	t.Helper()
	if len(bySrc) != 2 {
		t.Fatalf("%s: decoded %d SourceIDs, want 2 (fast+slow): %v", proto, len(bySrc), bySrc)
	}
	var closes []decodedFlow16303
	for src, recs := range bySrc {
		var sum uint64
		for _, r := range recs {
			sum += r.packets
		}
		if sum != 280 {
			t.Fatalf("%s src=%d total packets=%d, want 280 (interim+close must sum to lifetime)", proto, src, sum)
		}
		closes = append(closes, recs[len(recs)-1])
	}
	var small, big *decodedFlow16303
	for i := range closes {
		if closes[i].packets == 80 {
			small = &closes[i]
		}
		if closes[i].packets == 280 {
			big = &closes[i]
		}
	}
	if small == nil || big == nil {
		t.Fatalf("%s close records = %+v, want one 80-packet remainder and one 280-packet full close (shared-baseline bug makes them equal)", proto, closes)
	}
	if small.bytes != 8000 {
		t.Fatalf("%s remainder close bytes=%d, want 8000 (28000-20000)", proto, small.bytes)
	}
	if big.bytes != 28000 {
		t.Fatalf("%s full close bytes=%d, want 28000", proto, big.bytes)
	}
	if isIPFIX {
		if small.revPackets != 40 || small.revByt != 4000 {
			t.Fatalf("ipfix remainder close rev=%d/%d, want 40/4000", small.revPackets, small.revByt)
		}
		if big.revPackets != 130 || big.revByt != 13000 {
			t.Fatalf("ipfix full close rev=%d/%d, want 130/13000", big.revPackets, big.revByt)
		}
	}
}
