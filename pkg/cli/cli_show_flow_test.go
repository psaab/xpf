package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestFormatSessionBriefEndpoint(t *testing.T) {
	if got, want := formatSessionBriefEndpoint("192.0.2.10", 443), "192.0.2.10:443"; got != want {
		t.Fatalf("formatSessionBriefEndpoint() = %q, want %q", got, want)
	}
	if got, want := formatSessionBriefEndpoint("2001:db8::10", 443), "[2001:db8::10]:443"; got != want {
		t.Fatalf("formatSessionBriefEndpoint() = %q, want %q", got, want)
	}
	if got, want := formatSessionBriefEndpoint("", 443), "-"; got != want {
		t.Fatalf("formatSessionBriefEndpoint() = %q, want %q", got, want)
	}
}

func TestSessionBriefWriterPreservesLongValues(t *testing.T) {
	var buf bytes.Buffer
	w := newSessionBriefWriter(&buf)
	printSessionBriefHeader(w)
	printSessionBriefRow(w, sessionBriefRow{
		ID:          42,
		Source:      formatSessionBriefEndpoint("2001:db8:100::1234", 65535),
		Destination: formatSessionBriefEndpoint("2001:db8:200::5678", 443),
		Proto:       "tcp",
		Zone:        "very-long-trust-zone-name->another-very-long-untrust-zone-name",
		NAT:         "-",
		State:       "ESTAB",
		Age:         123,
		FwdPackets:  456789,
		RevPackets:  987654,
	})
	flushSessionBriefWriter(w)

	out := buf.String()
	for _, needle := range []string{
		"ID",
		"[2001:db8:100::1234]:65535",
		"[2001:db8:200::5678]:443",
		"very-long-trust-zone-name->another-very-long-untrust-zone-name",
		"456789/987654",
	} {
		if !strings.Contains(out, needle) {
			t.Fatalf("brief output missing %q:\n%s", needle, out)
		}
	}
	if strings.Contains(out, "\t") {
		t.Fatalf("brief output still contains tabs after flush:\n%s", out)
	}
}

// TestPeerSessionBriefNATFlag13247 guards peer brief parity with local sessions:
// simultaneous SNAT and DNAT must render "B", not the DNAT-only "D".
func TestPeerSessionBriefNATFlag13247(t *testing.T) {
	for nat, want := range map[string]string{
		"":                                "-",
		"SNAT 203.0.113.1:1234":           "S",
		"DNAT 10.0.0.1:443":               "D",
		"SNAT 203.0.113.1:1234; DNAT x:1": "B",
	} {
		if got := peerSessionNATFlag(nat); got != want {
			t.Errorf("peerSessionNATFlag(%q) = %q, want %q", nat, got, want)
		}
	}
}

// TestFlowSessionDisplayIDMatchesDataplaneID is the #5213 correlation invariant:
// the id shown by `show security flow session` must equal the STABLE dataplane
// session id (dataplane.SessionValue.SessionID) that the userspace-dp conntrack
// mirror stamps from SessionEntry.session_id (#4915) — the SAME u64 RT_FLOW
// emits on SESSION_CREATE/CLOSE for that session. Only an absent (0) id may fall
// back to the per-row ordinal. Reverting flowSessionDisplayID to always return
// the ordinal turns the first assertion RED.
func TestFlowSessionDisplayIDMatchesDataplaneID(t *testing.T) {
	// A real, RT_FLOW-correlated dataplane id (worker 7 in the high 16 bits,
	// per-worker counter 42). show-flow MUST render this exact value, NOT the
	// per-row ordinal — that equality IS the cross-surface correlation.
	const rtFlowSessionID uint64 = (7 << 48) | 42
	const ordinal = 3
	if got := flowSessionDisplayID(rtFlowSessionID, ordinal); got != rtFlowSessionID {
		t.Fatalf("show-flow id = %d, want dataplane/RT_FLOW id %d (not ordinal %d)",
			got, rtFlowSessionID, ordinal)
	}
	// Defensive fallback: an absent (0) dataplane id renders the ordinal, never
	// a bare 0 — the pre-#5213 legacy display for a row with no stamped id.
	if got := flowSessionDisplayID(0, ordinal); got != uint64(ordinal) {
		t.Fatalf("absent dataplane id must fall back to ordinal %d, got %d", ordinal, got)
	}
}
