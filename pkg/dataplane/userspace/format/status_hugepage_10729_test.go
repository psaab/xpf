package format

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// TestFormatStatusSummaryHugepageFallback10729 pins the X1-09 visibility: a
// binding whose UMEM fell back to standard pages shows in the backed count,
// and the process fallback total renders exactly once (max, not sum).
func TestFormatStatusSummaryHugepageFallback10729(t *testing.T) {
	backed := userspace.BindingStatus{Slot: 0, Bound: true, HugepageBacked: true}
	unbacked := userspace.BindingStatus{
		Slot: 1, Bound: true, HugepageBacked: false,
		UMEMFallbackBytesTotal: 134217728,
	}
	out := FormatStatusSummary(userspace.ProcessStatus{Bindings: []userspace.BindingStatus{backed, unbacked}})
	if !strings.Contains(out, "Hugepage-backed bindings:  1/2") {
		t.Fatalf("summary must show 1/2 backed bindings, got:\n%s", out)
	}
	if !strings.Contains(out, "UMEM fallback bytes:       134217728") {
		t.Fatalf("summary must show the fallback total once, got:\n%s", out)
	}
	if n := strings.Count(out, "UMEM fallback bytes:"); n != 1 {
		t.Fatalf("fallback total rendered %d times, want once (max, not sum)", n)
	}

	// All backed: the bytes line stays hidden (nothing to report).
	clean := FormatStatusSummary(userspace.ProcessStatus{Bindings: []userspace.BindingStatus{backed}})
	if strings.Contains(clean, "UMEM fallback bytes:") {
		t.Fatalf("bytes line must hide when the total is 0, got:\n%s", clean)
	}
	if !strings.Contains(clean, "Hugepage-backed bindings:  1/1") {
		t.Fatalf("summary must show 1/1 backed bindings, got:\n%s", clean)
	}
}
