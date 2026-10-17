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

// #14608: interface sampling is per-family at the daemon gate too. With
// only `family inet sampling input` on the trust unit and a DUAL-family
// sampling instance (one instance serving both inet and inet6 collectors,
// so the #6811/#2462 collector-side ServesFamily gate passes for IPv6),
// an IPv6 trust->untrust SESSION_CLOSE must NOT be exported and must not
// consume a 1-in-N slot; the twin with `family inet6 sampling input`
// MUST export it. Exercises the real parser -> compiler ->
// reconcileFlowExporters -> flowExportCallback/ipfixExportCallback path.
//
// FAIL-ON-REVERT: family-less SamplingInput made the IPv6 close eligible
// (exported, slot consumed); per-family flags + the family argument to
// ShouldExport deny it before the counter advances.

// buildSessionCloseRawEventV6 is the IPv6 twin of
// buildSessionCloseRawEventV4: full 16-byte addresses in the [8:24] /
// [24:40] slots and AFInet6 at [55].
func buildSessionCloseRawEventV6(
	proto uint8,
	srcIP, dstIP [16]byte,
	srcPort, dstPort uint16,
	ingressZone, egressZone uint16,
) []byte {
	buf := make([]byte, int(unsafe.Sizeof(dataplane.Event{})))
	copy(buf[8:24], srcIP[:])
	copy(buf[24:40], dstIP[:])
	binary.BigEndian.PutUint16(buf[40:42], srcPort)
	binary.BigEndian.PutUint16(buf[42:44], dstPort)
	binary.LittleEndian.PutUint16(buf[48:50], ingressZone)
	binary.LittleEndian.PutUint16(buf[50:52], egressZone)
	buf[52] = dataplane.EventTypeSessionClose
	buf[53] = proto
	buf[55] = dataplane.AFInet6
	return buf
}

// dualFamilySamplingConfig14608 builds, through the real parser/compiler,
// a config with one sampling instance serving BOTH families (v9 + IPFIX
// flow-servers for inet and inet6), zones trust/untrust on ge-0/0/0.0 /
// ge-0/0/1.0, and sampling input on the trust unit under exactly one
// family ("inet" or "inet6"). Rate 2 so slot consumption is observable.
func dualFamilySamplingConfig14608(t *testing.T, family string, v9Port, ipfixPort int) *config.Config {
	t.Helper()
	text := `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet { address 10.0.0.1/24; }
            family inet6 { address 2001:db8::1/64; }
            family ` + family + ` { sampling { input; } }
        }
    }
    ge-0/0/1 {
        unit 0 {
            family inet { address 192.0.2.1/24; }
            family inet6 { address 2001:db8:1::1/64; }
        }
    }
}
security {
    zones {
        security-zone trust { interfaces { ge-0/0/0.0; } }
        security-zone untrust { interfaces { ge-0/0/1.0; } }
    }
}
forwarding-options {
    sampling {
        instance s {
            input { rate 2; }
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
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func TestSessionCloseSamplingPerFamily14608(t *testing.T) {
	for _, tc := range []struct {
		name       string
		family     string // family carrying `sampling input` on trust
		wantExport bool   // whether the IPv6 trust->untrust close exports
	}{
		{"inet only denies IPv6", "inet", false},
		{"inet6 twin exports IPv6", "inet6", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v9Coll, v9Port := listenUDP(t)
			t.Cleanup(func() { v9Coll.Close() })
			ipfixColl, ipfixPort := listenUDP(t)
			t.Cleanup(func() { ipfixColl.Close() })

			d := newFlowTestDaemon()
			t.Cleanup(d.stopFlowExporter)
			t.Cleanup(d.stopIPFIXExporter)

			cfg := dualFamilySamplingConfig14608(t, tc.family, v9Port, ipfixPort)
			if !d.reconcileFlowExporters(cfg) {
				t.Fatal("dual-family exporters must start")
			}
			b := d.flowBundle.Load()
			if b == nil || len(b.groups) == 0 {
				t.Fatal("v9 bundle must be live")
			}
			ib := d.ipfixBundlePtr.Load()
			if ib == nil || len(ib.groups) == 0 {
				t.Fatal("ipfix bundle must be live")
			}
			// Dual-family instance: the collector-side gate passes for
			// IPv6 (the #6811 control) — only the interface sampling
			// family may deny the flow.
			lead := b.groups[0].ec
			if !lead.ServesFamily(true) || !lead.ServesFamily(false) {
				t.Fatalf("instance must serve both families: v4=%v v6=%v",
					lead.ServesFamily(false), lead.ServesFamily(true))
			}

			trust, untrust := config.StableZoneID("trust"), config.StableZoneID("untrust")
			var src, dst [16]byte
			copy(src[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x65})
			copy(dst[:], []byte{0x20, 0x01, 0x0d, 0xb8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc8})
			payload := buildSessionCloseRawEventV6(6, src, dst, 12345, 443, trust, untrust)

			// Sanity: the payload decodes as an IPv6 SESSION_CLOSE.
			var probe logging.EventRecord
			d.eventReader.AddCallback(func(rec logging.EventRecord, _ []byte) {
				if rec.Type == "SESSION_CLOSE" {
					probe = rec
				}
			})

			if !d.eventReader.ProcessRawEvent(payload) {
				t.Fatal("ProcessRawEvent rejected a valid IPv6 SESSION_CLOSE payload")
			}
			if probe.Type != "SESSION_CLOSE" {
				t.Fatalf("decoded record type = %q, want SESSION_CLOSE", probe.Type)
			}

			if tc.wantExport {
				// Rate 2: first close may be sampled out; feed a second
				// so one must land. The record fans out only to the
				// IPv6 group (GroupIsV6), which may not be groups[0] —
				// aggregate Stats across all groups of each bundle.
				if !d.eventReader.ProcessRawEvent(payload) {
					t.Fatal("ProcessRawEvent rejected second IPv6 SESSION_CLOSE")
				}
				sumV9 := func() (uint64, uint64) {
					var f, p uint64
					for _, g := range b.groups {
						gf, gp := g.exp.Stats()
						f, p = f+gf, p+gp
					}
					return f, p
				}
				sumIPFIX := func() (uint64, uint64) {
					var f, p uint64
					for _, g := range ib.groups {
						gf, gp := g.exp.Stats()
						f, p = f+gf, p+gp
					}
					return f, p
				}
				if got := waitFlows(t, sumV9); got < 1 {
					t.Fatalf("v9 exporter exported %d IPv6 flows, want >= 1 (inet6 sampling twin)", got)
				}
				if got := waitFlows(t, sumIPFIX); got < 1 {
					t.Fatalf("ipfix exporter exported %d IPv6 flows, want >= 1", got)
				}
			} else {
				// Give the 100ms flush ticker ample margin, then both
				// exporters must still be at zero and no sampling slot
				// may have been consumed (evaluated stays 0).
				time.Sleep(400 * time.Millisecond)
				if flows, _ := b.firstExp().Stats(); flows != 0 {
					t.Fatalf("v9 exporter exported %d IPv6 flows with only inet sampling, want 0", flows)
				}
				if flows, _ := ib.firstExp().Stats(); flows != 0 {
					t.Fatalf("ipfix exporter exported %d IPv6 flows with only inet sampling, want 0", flows)
				}
				stats := d.FlowExportSamplingStats()
				if len(stats) == 0 {
					t.Fatal("no sampling stats snapshots")
				}
				for _, s := range stats {
					if s.Evaluated != 0 || s.Selected != 0 {
						t.Fatalf("instance %s (%s) consumed sampling slots for a denied family: evaluated=%d selected=%d zoneFiltered=%d",
							s.Instance, s.Protocol, s.Evaluated, s.Selected, s.ZoneFiltered)
					}
					if s.ZoneFiltered == 0 {
						t.Fatalf("instance %s (%s): denied IPv6 close must count as zone-filtered, got %+v",
							s.Instance, s.Protocol, s)
					}
				}
				// Control: an IPv4 trust->untrust close at the same
				// zones IS eligible (rate 2: second call lands), proving
				// the deny above is family-scoped, not zone-scoped.
				v4 := buildSessionCloseRawEventV4(6,
					[4]byte{10, 0, 0, 102}, [4]byte{192, 0, 2, 200},
					12345, 443, [4]byte{}, 0, trust, untrust)
				if !d.eventReader.ProcessRawEvent(v4) || !d.eventReader.ProcessRawEvent(v4) {
					t.Fatal("ProcessRawEvent rejected IPv4 SESSION_CLOSE control")
				}
				if got := waitFlows(t, b.firstExp().Stats); got < 1 {
					t.Fatalf("v9 exporter exported %d IPv4 control flows, want >= 1", got)
				}
			}
		})
	}
}
