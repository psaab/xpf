// #3343 key-pin: the per-screen-reason counter table is the single source of
// truth for the ordinal->GlobalCtrScreen* counter mapping AND the API-visible
// reason key/label names used by the gRPC GetGlobalStats screen_drop_details
// map, the Prometheus xpf_screen_drops_by_reason_total{reason=...} label, and
// the CLI/text display rows. Routing those surfaces through this table (#3343)
// is what fixed the always-0 per-reason counters, but it also made the reason
// KEYS API-visible and content-load-bearing (the SSOT keys are the canonical
// Rust ScreenVerdict::Drop strings, which renamed the old gRPC detail keys
// `tear-drop`->`teardrop` and `syn-fragment`->`syn-frag`). This test pins the
// exact ordinal->(index, reason, label) contract so a future accidental
// rename/reorder/index-remap of any entry is caught here, not in production.
package dataplane

import "testing"

func TestScreenReasonCountersCanonicalContract(t *testing.T) {
	if ScreenReasonDropCount != 19 {
		t.Fatalf("ScreenReasonDropCount = %d, want 19 (must match Rust screen::SCREEN_REASON_DROP_COUNT and the protocol_wire_v1.json array length)", ScreenReasonDropCount)
	}
	if len(ScreenReasonCounters) != ScreenReasonDropCount {
		t.Fatalf("len(ScreenReasonCounters) = %d, want %d", len(ScreenReasonCounters), ScreenReasonDropCount)
	}

	// Ordinal i MUST stay in lockstep with the Rust BindingStatus.screen_reason_drops
	// wire array ordinal (screen::screen_reason_drop_index). The Index column is
	// the GlobalCtrScreen* counter each reason feeds; the Reason column is the
	// canonical machine key (gRPC detail-map key + Prometheus reason label).
	want := []struct {
		index  uint32
		reason string
		label  string
	}{
		{GlobalCtrScreenSynFlood, "syn-flood", "SYN flood"},
		{GlobalCtrScreenICMPFlood, "icmp-flood", "ICMP flood"},
		{GlobalCtrScreenUDPFlood, "udp-flood", "UDP flood"},
		{GlobalCtrScreenPortScan, "port-scan", "port scan"},
		{GlobalCtrScreenIPSweep, "ip-sweep", "IP sweep"},
		{GlobalCtrScreenLandAttack, "land-attack", "LAND attack"},
		{GlobalCtrScreenPingOfDeath, "ping-of-death", "ping of death"},
		{GlobalCtrScreenTearDrop, "teardrop", "teardrop"},
		{GlobalCtrScreenTCPSynFin, "tcp-syn-fin", "TCP SYN+FIN"},
		{GlobalCtrScreenTCPNoFlag, "tcp-no-flag", "TCP no-flag"},
		{GlobalCtrScreenTCPFinNoAck, "tcp-fin-no-ack", "TCP FIN-no-ACK"},
		{GlobalCtrScreenWinNuke, "winnuke", "WinNuke"},
		{GlobalCtrScreenIPSrcRoute, "ip-source-route", "IP source-route"},
		{GlobalCtrScreenSynFrag, "syn-frag", "SYN fragment"},
		{GlobalCtrScreenSessionLimit, "session-limit", "session limit"},
		{GlobalCtrScreenICMPFragment, "icmp-fragment", "ICMP fragment"},
		{GlobalCtrScreenIPMalformed, "ip-malformed", "IP malformed"},
		{GlobalCtrScreenSynCookieUnavail, "syn-cookie-unavailable", "SYN-cookie unavailable"},
		{GlobalCtrScreenSynCookieInvalid, "syn-cookie-invalid", "SYN-cookie invalid"},
	}
	if len(want) != len(ScreenReasonCounters) {
		t.Fatalf("test want table length %d != ScreenReasonCounters length %d", len(want), len(ScreenReasonCounters))
	}

	seenReason := map[string]bool{}
	seenIndex := map[uint32]bool{}
	for i, w := range want {
		got := ScreenReasonCounters[i]
		if got.Index != w.index {
			t.Errorf("ScreenReasonCounters[%d].Index = %d, want %d (ordinal->counter remap?)", i, got.Index, w.index)
		}
		if got.Reason != w.reason {
			t.Errorf("ScreenReasonCounters[%d].Reason = %q, want %q (API key rename?)", i, got.Reason, w.reason)
		}
		if got.Label != w.label {
			t.Errorf("ScreenReasonCounters[%d].Label = %q, want %q", i, got.Label, w.label)
		}
		if seenReason[got.Reason] {
			t.Errorf("duplicate reason key %q at ordinal %d", got.Reason, i)
		}
		if seenIndex[got.Index] {
			t.Errorf("duplicate counter index %d at ordinal %d", got.Index, i)
		}
		seenReason[got.Reason] = true
		seenIndex[got.Index] = true
	}

	// The two keys renamed by #3343 must never silently revert.
	for _, legacy := range []string{"tear-drop", "syn-fragment"} {
		if seenReason[legacy] {
			t.Errorf("ScreenReasonCounters reintroduced legacy reason key %q (must stay %q-family canonical)", legacy, "Rust ScreenVerdict::Drop")
		}
	}
}
