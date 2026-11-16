package format

import (
	"strings"
	"testing"

	userspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #19173: the Rust FlowCacheEvictionArm ordinal 22 (PostHitSessionReplaced,
// a cache hit refused because its backing row was replaced since the seed)
// renders under its own label, after the two #18656 sub-arms. Distinct
// per-arm values catch an off-by-one into arm 21 or a dropped slot.
func TestFlowCacheEvictionsByArmSessionReplaced19173(t *testing.T) {
	arms := make([]uint64, 23)
	for i := range arms {
		arms[i] = uint64(i + 1)
	}
	out := FormatStatusSummary(userspace.ProcessStatus{
		Bindings: []userspace.BindingStatus{{FlowCacheEvictionsByArm: arms}},
	})
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "Flow cache evictions by arm:") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("no eviction-arm line in:\n%s", out)
	}
	for _, needle := range []string{" session_dead_idle_crossed=22", " session_replaced=23"} {
		if !strings.Contains(line, needle) {
			t.Errorf("want %q in %q", needle, line)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(line), "session_replaced=23") {
		t.Errorf("session_replaced must be the last arm rendered: %q", line)
	}
}
