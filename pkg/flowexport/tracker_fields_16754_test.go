package flowexport

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// #16754: tracker-emitted records (active interims + inactive finals) are
// copies of the SESSION_OPEN template, which carried no SrcMask/DstMask
// and no Direction — only close records ran buildFlowRecord enrichment
// (#2866/#3744 masks, #3270 IE 61). An interim for an egress-sampled flow
// must carry Direction=1 and the same masks as its close record.
//
// RED pre-fix: CollectDueExports returned the template verbatim, so the
// interim carried Direction 0 / masks 0/0 while the close record for the
// same tuple carried Direction 1 / 24/30. GREEN post-fix: the shared
// drain enriches tracker records from the exporter's sampling config +
// MaskResolver (ingress VRF = InIf).

func trackerTestConfig() *ExportConfig {
	return &ExportConfig{
		FlowActiveTimeout:   60 * time.Second,
		FlowInactiveTimeout: 15 * time.Second,
		SamplingZones: FamilySamplingDirs{V4: map[uint16]SamplingDir{
			2: {Input: true},  // trust: ingress-sampled
			3: {Output: true}, // untrust: egress-sampled
		}},
	}
}

func trackerTestTemplate() (FlowKey, FlowRecord) {
	src := net.IPv4(10, 0, 1, 100)
	dst := net.IPv4(172, 16, 80, 200)
	key := FlowKey{SrcIP: src.String(), DstIP: dst.String(), SrcPort: 40000, DstPort: 80, Protocol: 6}
	tmpl := FlowRecord{
		SrcIP: src, DstIP: dst, SrcPort: 40000, DstPort: 80, Protocol: 6,
		InIf: 11, OutIf: 12,
		// Egress-sampled: ingress zone 1 is sampled nowhere, egress
		// zone 3 is output-only, so FlowDirectionIface(1,3) must
		// derive 1 (an input-sampled ingress would win the tie at 0).
		InZone: 1, OutZone: 3,
		NATSrcIP: src, NATDstIP: dst, NATSrcPort: 40000, NATDstPort: 80,
	}
	return key, tmpl
}

func TestTrackerInterimCarriesDirectionAndMasks16754(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	key, tmpl := trackerTestTemplate()

	for _, tc := range []struct {
		name string
		mk   func() *exporterCore
	}{
		{"netflow", func() *exporterCore {
			e, err := NewExporter(trackerTestConfig())
			if err != nil {
				t.Fatalf("NewExporter: %v", err)
			}
			e.MaskResolver = maskResolverFor(tmpl.SrcIP, tmpl.DstIP)
			return &e.exporterCore
		}},
		{"ipfix", func() *exporterCore {
			e, err := NewIPFIXExporter(trackerTestConfig())
			if err != nil {
				t.Fatalf("NewIPFIXExporter: %v", err)
			}
			e.MaskResolver = maskResolverFor(tmpl.SrcIP, tmpl.DstIP)
			return &e.exporterCore
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core := tc.mk()
			if core.tracker == nil {
				t.Fatal("tracker not wired")
			}
			// Daemon open path: TrackFlowOpenRecord with the open
			// template (no masks, Direction unset).
			core.TrackFlowOpenRecord(key, start, tmpl)
			core.TouchFlow(key, start.Add(30*time.Second), 100, 10000)
			due := core.collectDueExports(start.Add(61 * time.Second))
			if len(due) != 1 {
				t.Fatalf("want 1 interim, got %d (%v)", len(due), due)
			}
			if due[0].Direction != 1 {
				t.Fatalf("interim Direction = %d, want 1 (egress-sampled)", due[0].Direction)
			}
			if due[0].SrcMask != testSrcMask || due[0].DstMask != testDstMask {
				t.Fatalf("interim masks = %d/%d, want %d/%d (same as close record)",
					due[0].SrcMask, due[0].DstMask, testSrcMask, testDstMask)
			}
			// The batch copy carries the same enriched fields.
			v4, _ := core.batch.drain()
			if len(v4) != 1 || v4[0].Direction != 1 || v4[0].SrcMask != testSrcMask {
				t.Fatalf("batched interim = %+v, want enriched copy", v4)
			}

			// The same flow's close record (control) carries identical
			// fields — interim and close must agree.
			rec := logging.EventRecord{
				Type: "SESSION_CLOSE", Time: start.Add(120 * time.Second),
				Created: uint32(start.Unix()), ProtocolNum: 6,
				SessionPkts: 300, SessionBytes: 30000,
			}
			sd := SessionCloseData{
				SrcIP: tmpl.SrcIP, DstIP: tmpl.DstIP, SrcPort: 40000, DstPort: 80,
				Protocol: 6, InIf: 11, OutIf: 12, Direction: 1,
			}
			closeRec, _ := core.buildFlowRecord(rec, sd, false)
			if closeRec.Direction != due[0].Direction || closeRec.SrcMask != due[0].SrcMask || closeRec.DstMask != due[0].DstMask {
				t.Fatalf("interim %+v disagrees with close %+v", due[0], closeRec)
			}

			// (Inactive-final enrichment is pinned separately in
			// TestTrackerInactiveFinalCarriesDirectionAndMasks16754:
			// after this flow's interim its last Touch ages past
			// inactive before the next window only in isolation.)
		})
	}
}

// The inactive-timeout final (the tracker-emitted record that replaces
// a close for an idle flow) is enriched the same way.
func TestTrackerInactiveFinalCarriesDirectionAndMasks16754(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	key, tmpl := trackerTestTemplate()
	e, err := NewExporter(trackerTestConfig())
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	e.MaskResolver = maskResolverFor(tmpl.SrcIP, tmpl.DstIP)
	e.TrackFlowOpenRecord(key, start, tmpl)
	e.TouchFlow(key, start.Add(30*time.Second), 100, 10000)
	// lastActivity=start+30s, inactive=15s → final due at start+45s,
	// before the 60s active window.
	final := e.collectDueExports(start.Add(50 * time.Second))
	if len(final) != 1 {
		t.Fatalf("want 1 inactive final, got %v", final)
	}
	if final[0].Direction != 1 || final[0].SrcMask != testSrcMask || final[0].DstMask != testDstMask {
		t.Fatalf("inactive final = dir %d masks %d/%d, want 1 / %d/%d",
			final[0].Direction, final[0].SrcMask, final[0].DstMask, testSrcMask, testDstMask)
	}
}

// Control: an ingress-sampled flow keeps Direction 0, and a template
// whose Direction was already set at open is not overwritten.
func TestTrackerInterimIngressAndPresetDirection16754(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	key, tmpl := trackerTestTemplate()

	e, err := NewExporter(trackerTestConfig())
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	e.MaskResolver = maskResolverFor(tmpl.SrcIP, tmpl.DstIP)

	// Ingress control: zones swapped — ingress zone output-only,
	// egress zone input-sampled → derived direction stays 0, masks
	// still resolved. (FlowDirectionIface: input wins / default 0.)
	ing := tmpl
	ing.InZone, ing.OutZone = 3, 2
	e.TrackFlowOpenRecord(key, start, ing)
	e.TouchFlow(key, start.Add(61*time.Second), 10, 1000)
	due := e.collectDueExports(start.Add(61 * time.Second))
	if len(due) != 1 || due[0].Direction != 0 || due[0].SrcMask != testSrcMask {
		t.Fatalf("ingress interim = %+v, want Direction 0 with masks", due)
	}

	// Preset control: a caller that set Direction=1 at open (via
	// TrackFlowOpenWithMeta) keeps it even when the config would
	// derive 0 for the zones.
	e2, err := NewExporter(trackerTestConfig())
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	e2.MaskResolver = maskResolverFor(tmpl.SrcIP, tmpl.DstIP)
	pre := tmpl
	pre.InZone, pre.OutZone = 3, 2 // config derives 0
	pre.Direction = 1
	e2.TrackFlowOpenWithMeta(key, start, pre)
	e2.TouchFlow(key, start.Add(61*time.Second), 10, 1000)
	due = e2.collectDueExports(start.Add(61 * time.Second))
	if len(due) != 1 || due[0].Direction != 1 {
		t.Fatalf("preset interim = %+v, want Direction 1 preserved", due)
	}
}

// Masks resolve in the ingress VRF: the resolver must be scoped by
// InIf (OutIf only as fallback), matching buildFlowRecord.
func TestTrackerMasksScopedToIngressVRF16754(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	key, tmpl := trackerTestTemplate()

	var scopes []int
	resolver := MaskResolver(func(ip net.IP, scope int) (uint8, bool) {
		scopes = append(scopes, scope)
		if ip.Equal(tmpl.SrcIP) {
			return testSrcMask, true
		}
		return testDstMask, true
	})
	e, err := NewExporter(trackerTestConfig())
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	e.MaskResolver = resolver
	e.TrackFlowOpenRecord(key, start, tmpl)
	e.TouchFlow(key, start.Add(61*time.Second), 10, 1000)
	if due := e.collectDueExports(start.Add(61 * time.Second)); len(due) != 1 {
		t.Fatalf("want 1 interim, got %v", due)
	}
	if len(scopes) != 2 || scopes[0] != 11 || scopes[1] != 11 {
		t.Fatalf("resolver scopes = %v, want [11 11] (ingress VRF)", scopes)
	}
}
