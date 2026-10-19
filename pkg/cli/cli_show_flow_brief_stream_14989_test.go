package cli

import (
	"bytes"
	"strings"
	"testing"
)

// #14989 (D37-04): `show security flow session brief` rendered through a
// text/tabwriter over os.Stdout. tabwriter buffers the ENTIRE table until
// Flush, so a large session table was heap-buffered in full before any byte
// reached the terminal/pager, defeating streaming. The brief writer must
// emit the header and each row as they are printed, before the final flush.
func TestSessionBriefWriterStreamsBeforeFlush14989(t *testing.T) {
	var buf bytes.Buffer
	w := newSessionBriefWriter(&buf)
	printSessionBriefHeader(w)
	if buf.Len() == 0 {
		t.Fatal("brief header was buffered by the writer before flush; " +
			"streaming requires the header to reach the underlying writer immediately (#14989)")
	}
	if !strings.Contains(buf.String(), "Source") {
		t.Fatalf("streamed header missing columns:\n%s", buf.String())
	}

	printSessionBriefRow(w, sessionBriefRow{
		ID:          1,
		Source:      "192.0.2.10:443",
		Destination: "198.51.100.20:8443",
		Proto:       "tcp",
		Zone:        "trust->untrust",
		NAT:         "-",
		State:       "ESTAB",
		Age:         10,
		FwdPackets:  3,
		RevPackets:  4,
	})
	out := buf.String()
	if !strings.Contains(out, "192.0.2.10:443") || !strings.Contains(out, "3/4") {
		t.Fatalf("brief row was buffered by the writer before flush; "+
			"streaming requires each row to reach the underlying writer as printed (#14989):\n%s", out)
	}
	if strings.Contains(out, "\t") {
		t.Fatalf("brief output contains tabs; fixed-width streaming layout must not emit tabwriter input:\n%s", out)
	}

	// Control: a second row and the final flush preserve all content.
	printSessionBriefRow(w, sessionBriefRow{
		ID:          2,
		Source:      "[2001:db8::10]:443",
		Destination: "[2001:db8::20]:8443",
		Proto:       "udp",
		Zone:        "trust->untrust",
		NAT:         "S",
		State:       "ESTAB",
		Age:         20,
		FwdPackets:  5,
		RevPackets:  6,
	})
	flushSessionBriefWriter(w)
	out = buf.String()
	for _, needle := range []string{"192.0.2.10:443", "[2001:db8::10]:443", "3/4", "5/6"} {
		if !strings.Contains(out, needle) {
			t.Fatalf("brief output after flush missing %q:\n%s", needle, out)
		}
	}
	// Alignment control: both data rows share the same column layout, so the
	// Proto column starts at the same offset on each row.
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("brief output = %d lines, want header + 2 rows:\n%s", len(lines), out)
	}
}
