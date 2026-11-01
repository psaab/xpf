package format

import (
	"fmt"
	"strings"
	"testing"

	userspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #18656: every Rust FlowCacheEvictionArm ordinal is rendered under its own
// label, including the two PostHitSessionDead sub-arms (20/21) and arm 19,
// which the CLI line did not print before. Distinct per-arm values (ordinal
// + 1, summed over two bindings) catch an off-by-one or a dropped slot that
// the all-zero golden cannot.
func TestFlowCacheEvictionsByArmLabels18656(t *testing.T) {
	arms := make([]uint64, 22)
	for i := range arms {
		arms[i] = uint64(i + 1)
	}
	status := userspace.ProcessStatus{
		Bindings: []userspace.BindingStatus{
			{FlowCacheEvictionsByArm: arms},
			{FlowCacheEvictionsByArm: arms},
		},
	}
	out := FormatStatusSummary(status)
	want := map[string]int{
		"session_dead":                      10,
		"forward_candidate_egress_departed": 18,
		"destination_now_local":             19,
		"session_dead_no_record":            20,
		"session_dead_idle_crossed":         21,
	}
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "Flow cache evictions by arm:") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("no eviction-arm line in:\n%s", out)
	}
	for label, ordinal := range want {
		needle := fmt.Sprintf(" %s=%d", label, 2*(ordinal+1))
		if !strings.Contains(line, needle) {
			t.Errorf("arm %d: want %q in %q", ordinal, needle, line)
		}
	}
}
