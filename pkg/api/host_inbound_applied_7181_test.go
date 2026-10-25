package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #7181: the tri-state must not collapse.
//
// WHY A TABLE AND NOT TWO CELLS. `Established` is sticky-true: a failed render
// does NOT clear it, because the retained generation may still be protecting.
// So the two ends — never-established and established-and-healthy — are passed
// by a renderer that simply returns `Established`. Only the MIDDLE row
// (Established AND LastApplyFailed) separates a correct implementation from
// that one, and it is the row an operator most needs, because it is the box
// whose latest render failed while a stale table still stands.
func TestHostInboundAppliedIsTriState7181(t *testing.T) {
	cases := []struct {
		name string
		snap HostInboundAppliedSnapshot
		want string
	}{
		{
			name: "never established — a configured default-deny is NOT in force",
			snap: HostInboundAppliedSnapshot{Known: true},
			want: HostInboundAppliedNotEstablished,
		},
		{
			// THE MIDDLE ROW. Established is true and stays true; the latest
			// render failed. A renderer keyed on Established alone says
			// "current" here and is wrong in the direction that matters.
			name: "established but the latest render FAILED — stale, not current",
			snap: HostInboundAppliedSnapshot{Known: true, Established: true, LastApplyFailed: true, Generation: 3},
			want: HostInboundAppliedStale,
		},
		{
			name: "established and current",
			snap: HostInboundAppliedSnapshot{Known: true, Established: true, Generation: 4},
			want: HostInboundAppliedCurrent,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hostInboundAppliedInfo(tc.snap)
			if got.State != tc.want {
				t.Errorf("state = %q, want %q.\nA sticky Established rendered as a health verdict is the "+
					"exact conflation #7181 exists to remove: it reports a box whose latest render failed "+
					"as enforcing, and the operator has no other surface that would tell them otherwise.",
					got.State, tc.want)
			}
		})
	}
}

// The evidence fields must survive into the projection, not just the verdict.
// A verdict with no generation is unfalsifiable from the operator's side —
// they cannot tell a box that re-rendered a second ago from one that has been
// standing on the same generation since boot.
func TestHostInboundAppliedCarriesItsEvidence7181(t *testing.T) {
	got := hostInboundAppliedInfo(HostInboundAppliedSnapshot{
		Known: true, Established: true, LastApplyFailed: true,
		Generation: 7, LastFailureUnixSec: 1690000000, GapFenceActive: true,
		BarrierRetained: true, BarrierPendingDetail: "untrust/ge-0-0-1.0 inet6",
	})
	if got.Generation != 7 {
		t.Errorf("Generation = %d, want 7", got.Generation)
	}
	if got.LastFailureUnixSec != 1690000000 {
		t.Errorf("LastFailureUnixSec = %d, want 1690000000", got.LastFailureUnixSec)
	}
	if !got.GapFenceActive {
		t.Error("GapFenceActive lost. A box enforcing through the additive gap fence " +
			"is in a different state from one whose main table covers everything, and an " +
			"operator diagnosing reachability needs to know which table is answering")
	}
	if !got.BarrierRetained || got.BarrierPendingDetail != "untrust/ge-0-0-1.0 inet6" {
		t.Errorf("barrier fields lost: %+v, want retained with pending detail (#16785)", got)
	}
}

// #7181 WIRING: zonesHandler must actually CALL the mapper.
//
// This cell exists because a mutation escaped without it. The tri-state tests
// above drive `hostInboundAppliedInfo` directly, so deleting the call from
// zonesHandler left every one of them green while the feature was completely
// disconnected — a REST consumer would have seen no `host_inbound_applied` key
// at all and had no way to tell that from "the daemon was not asked".
//
// Testing the mapper proves the mapping. Only reaching it THROUGH the handler
// proves the projection renders it.
func TestZonesHandlerRendersTheAppliedState7181(t *testing.T) {
	s := &Server{
		store: nilZoneValueAPIStore(t),
		dp: &schedulerCounterAPIDP{
			Manager:  dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{},
		},
		// The STALE state deliberately: it is the row a renderer keyed on the
		// sticky bool gets wrong, so if the handler ever renders from
		// Established alone this fixture catches it here too.
		hostInboundAppliedFn: func() HostInboundAppliedSnapshot {
			return HostInboundAppliedSnapshot{
				Known: true, Established: true, LastApplyFailed: true, Generation: 9,
			}
		},
	}
	rr := httptest.NewRecorder()
	s.zonesHandler(rr, httptest.NewRequest("GET", "/api/v1/security/zones", nil))
	if rr.Code != 200 {
		t.Fatalf("zonesHandler status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"host_inbound_applied"`) {
		t.Fatalf("zonesHandler rendered NO host_inbound_applied key. The mapper is "+
			"correct in isolation but nothing calls it, so the applied state never "+
			"reaches a REST consumer (#7181).\n--- body ---\n%s", body)
	}
	if !strings.Contains(body, `"stale"`) {
		t.Errorf("the rendered state is not %q. A handler that renders from the sticky "+
			"Established bool alone reports this box as enforcing while its latest "+
			"render failed.\n--- body ---\n%s", "stale", body)
	}
}

// The unwired case must render NOTHING rather than a false verdict. An absent
// key claims nothing; a `"state":"not-established"` from a daemon that was
// never asked is a claim, and a wrong one.
func TestZonesHandlerOmitsAppliedStateWhenUnwired7181(t *testing.T) {
	s := &Server{
		store: nilZoneValueAPIStore(t),
		dp: &schedulerCounterAPIDP{
			Manager:  dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{},
		},
	}
	rr := httptest.NewRecorder()
	s.zonesHandler(rr, httptest.NewRequest("GET", "/api/v1/security/zones", nil))
	if strings.Contains(rr.Body.String(), "host_inbound_applied") {
		t.Errorf("an unwired callback still rendered an applied state. Absence must "+
			"claim nothing.\n--- body ---\n%s", rr.Body.String())
	}
}
