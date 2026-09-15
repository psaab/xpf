package format

// #9642: the shared helper-status overview (local CLI + gRPC) renders retry
// debt health beside the backend classification. Indebted output names the
// unpublished generation; recovered output omits the row entirely; mode and
// Enabled lines are byte-identical either way (classification untouched).

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestFormatStatusSummaryShowsRetryDebt9642(t *testing.T) {
	t.Parallel()
	indebted := userspace.ProcessStatus{
		Enabled:                     true,
		Workers:                     1,
		LastSnapshotGeneration:      8,
		SnapshotRetryDebt:           true,
		SnapshotRetryDebtGeneration: 9,
	}
	out := FormatStatusSummary(indebted)
	if !strings.Contains(out, "Snapshot retry debt:") || !strings.Contains(out, "generation 9 unpublished") {
		t.Fatalf("indebted overview missing the debt row with generation:\n%s", out)
	}
	if !strings.Contains(out, "Enabled:") {
		t.Fatalf("debt row displaced the backend classification lines:\n%s", out)
	}

	recovered := indebted
	recovered.SnapshotRetryDebt = false
	recovered.SnapshotRetryDebtGeneration = 0
	out = FormatStatusSummary(recovered)
	if strings.Contains(out, "Snapshot retry debt:") {
		t.Fatalf("recovered overview still shows the debt row:\n%s", out)
	}
}
