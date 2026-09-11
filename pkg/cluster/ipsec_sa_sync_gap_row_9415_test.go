package cluster

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #9415 member 4: docs/feature-gaps.md marked "IPsec SA Synchronization" Done.
// The row's Description is the Junos feature (SAs synchronized, no tunnel
// re-establishment on failover), but the implementation syncs only connection
// names and re-initiates each tunnel on the new primary
// (sync_protocol.go, pkg/ipsec/ike.go `swanctl --initiate`). That is Partial,
// and the row must say what an operator sees on every failover.
func TestFeatureGapsIPsecSASyncRowIsPartial_9415(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "feature-gaps.md"))
	if err != nil {
		t.Fatalf("read feature-gaps.md: %v", err)
	}
	var row string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "| **IPsec SA Synchronization** |") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatal("precondition: the IPsec SA Synchronization row must exist")
	}
	cells := strings.Split(row, "|")
	status := strings.TrimSpace(cells[len(cells)-2])
	if !strings.HasPrefix(status, "Partial") {
		t.Errorf("status cell must read Partial, got %q", status)
	}
	for _, want := range []string{"renegotiation", "planned or not", "remote peer"} {
		if !strings.Contains(status, want) {
			t.Errorf("status cell must name the failover consequence (%q): %q", want, status)
		}
	}
}
