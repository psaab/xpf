package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/lldp"
)

func TestShowLLDPNeighborsQuotesAndBoundsPeerFields10899(t *testing.T) {
	seen := time.Now()
	neighbors := []*lldp.Neighbor{
		{
			Interface:  "eth0",
			ChassisID:  "chassis id",
			PortID:     "port id",
			SystemName: "system name " + strings.Repeat("long ", 10),
			TTL:        120,
			LastSeen:   seen,
		},
		{
			Interface:  "eth1",
			ChassisID:  "host\u202epeer",
			PortID:     "p \u2028世",
			SystemName: "123456789\u2029coreverylong",
			TTL:        240,
			LastSeen:   seen,
		},
	}
	c := &CLI{lldpNeighborsFn: func() []*lldp.Neighbor { return neighbors }}
	var showErr error
	out := captureStdout(t, func() { showErr = c.showLLDPNeighbors() })
	if showErr != nil {
		t.Fatalf("showLLDPNeighbors() error = %v", showErr)
	}

	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want header and two neighbor rows, got %d lines: %q", len(lines), out)
	}
	if !strings.Contains(lines[1], `"chassis id"`) || !strings.Contains(lines[1], `"port id"`) {
		t.Fatalf("space-bearing LLDP cells were not quoted: %q", lines[1])
	}
	if cell := lines[1][51:71]; !strings.HasSuffix(cell, `..."`) {
		t.Errorf("long system-name cell is not visibly truncated to its column: %q", cell)
	}
	ttlColumn := strings.Index(lines[0], "TTL")
	for row, ttl := range []string{"120", "240"} {
		if got := strings.Index(lines[row+1], ttl); got != ttlColumn {
			t.Errorf("row %d TTL starts at column %d, header TTL starts at %d: %q", row+1, got, ttlColumn, lines[row+1])
		}
	}
	if !strings.Contains(lines[2], `\u2029..."`) {
		t.Errorf("truncated system-name cell split or omitted its complete escape: %q", lines[2])
	}
	if !strings.Contains(out, `"p \u2028\u4e16"`) {
		t.Errorf("Unicode was not represented within the quoted cell: %q", out)
	}
	for _, escaped := range []string{`\u202e`, `\u2028`, `\u2029`} {
		if !strings.Contains(out, escaped) {
			t.Errorf("LLDP renderer did not visibly escape %s: %q", escaped, out)
		}
	}
	for _, unsafe := range []rune{'\u202e', '\u2028', '\u2029'} {
		if strings.ContainsRune(out, unsafe) {
			t.Errorf("LLDP renderer emitted raw U+%04X: %q", unsafe, out)
		}
	}
}
