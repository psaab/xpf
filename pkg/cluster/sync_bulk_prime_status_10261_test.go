package cluster

import (
	"strings"
	"testing"
)

func TestSyncBulkPrimedStatusIsStrictAndRendered10261(t *testing.T) {
	m := NewManager(0, 1)
	if m.IsSyncBulkPrimed() {
		t.Fatal("a new manager must start with inbound bulk state unprimed")
	}
	if got := m.FormatInformation(); !strings.Contains(got, "Bulk sync primed: no") {
		t.Fatalf("information must fail closed before inbound bulk completion:\n%s", got)
	}

	m.SetSyncBulkPrimed(true)
	if !m.IsSyncBulkPrimed() {
		t.Fatal("SetSyncBulkPrimed(true) must publish the strict state")
	}
	if got := m.FormatInformation(); !strings.Contains(got, "Bulk sync primed: yes") {
		t.Fatalf("information must expose completed inbound bulk state:\n%s", got)
	}

	// The ordinary readiness bit may be timeout-released, but strict bulk prime
	// remains independently controlled and can be cleared for a new epoch.
	m.SetSyncReady(true)
	m.SetSyncBulkPrimed(false)
	if m.IsSyncBulkPrimed() {
		t.Fatal("strict bulk prime must not follow timeout-released sync readiness")
	}
}
