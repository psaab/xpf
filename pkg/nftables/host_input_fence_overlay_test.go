package nftables

import "testing"

func TestHostInputFenceOverlayMarkerCanonical9506(t *testing.T) {
	base := HostInputFenceOverlay{
		MasterSet:       []string{"st1", "st0", "st1"},
		Generation:      7,
		PermitEpoch:     9,
		CloseRequestSeq: 11,
		CloseRequestKey: "UNSAFE/7",
		WatchGeneration: 7,
		State:           "CLOSING",
	}
	permuted := base
	permuted.MasterSet = []string{"st0", "st1"}
	if got, want := HostInputFenceOverlayCounterName(base), HostInputFenceOverlayCounterName(permuted); got != want {
		t.Fatalf("marker depends on master order/duplicates: got %q want %q", got, want)
	}
	for name, mutate := range map[string]func(*HostInputFenceOverlay){
		"generation":       func(o *HostInputFenceOverlay) { o.Generation++ },
		"permit epoch":     func(o *HostInputFenceOverlay) { o.PermitEpoch++ },
		"close sequence":   func(o *HostInputFenceOverlay) { o.CloseRequestSeq++ },
		"close key":        func(o *HostInputFenceOverlay) { o.CloseRequestKey = "UNKNOWN/7" },
		"watch generation": func(o *HostInputFenceOverlay) { o.WatchGeneration++ },
		"state":            func(o *HostInputFenceOverlay) { o.State = "RETIRING" },
		"master":           func(o *HostInputFenceOverlay) { o.MasterSet = []string{"st2"} },
	} {
		candidate := base
		mutate(&candidate)
		if got := HostInputFenceOverlayCounterName(candidate); got == HostInputFenceOverlayCounterName(base) {
			t.Errorf("marker did not change for %s", name)
		}
	}
}
