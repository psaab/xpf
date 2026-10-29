package eventengine

import (
	"log/slog"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestClassifyPlanLogsRedactedQuotedComment18379(t *testing.T) {
	const secret = "LOGSECRET-18379-QUOTED-COMMENT"
	cmd := strconv.Quote("# set security ike policy p1 pre-shared-key ascii-text " + secret)
	h := &cmdCapturingHandler16726{}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	defer slog.SetDefault(prev)

	e := &Engine{}
	ops, ok := e.classifyPlan(&config.EventPolicy{Name: "p1", ThenCommands: []string{cmd}})
	if ok || len(ops) != 0 {
		t.Fatalf("classifyPlan(%q) = (%d ops, ok=%v), want batch rejected", cmd, len(ops), ok)
	}
	if len(h.cmds) != 1 {
		t.Fatalf("captured %d cmd log fields, want 1: %v", len(h.cmds), h.cmds)
	}
	if strings.Contains(h.cmds[0], secret) {
		t.Errorf("classifyPlan logged raw secret: cmd=%q", h.cmds[0])
	}
	if !strings.Contains(h.cmds[0], config.SecretDataPlaceholder) {
		t.Errorf("classifyPlan logged cmd=%q, want redacted placeholder", h.cmds[0])
	}
}
