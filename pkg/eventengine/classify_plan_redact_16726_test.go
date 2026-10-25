package eventengine

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16726 (R3-A20-02): classifyPlan logged the raw embedded command into the
// xpfd journal (`show log` serves it at PermView). Every warning that carries
// a command must carry RedactEmbeddedChangeConfigCommand's output instead.

type cmdCapturingHandler16726 struct {
	cmds []string
}

func (h *cmdCapturingHandler16726) Enabled(_ context.Context, lvl slog.Level) bool {
	return lvl >= slog.LevelWarn
}

func (h *cmdCapturingHandler16726) Handle(_ context.Context, r slog.Record) error {
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "cmd" {
			h.cmds = append(h.cmds, a.Value.String())
		}
		return true
	})
	return nil
}

func (h *cmdCapturingHandler16726) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *cmdCapturingHandler16726) WithGroup(_ string) slog.Handler      { return h }

func TestClassifyPlanLogsRedactedCmd16726(t *testing.T) {
	const secret = "LOGSECRET-16726"
	cases := []struct {
		name string
		cmd  string
	}{
		// ParseSetCommand rejects a path containing a structural token? Use
		// an unbalanced quote: TrimSpace keeps it, HasPrefix "set " holds,
		// and ParseSetCommand fails on the unterminated string.
		{"set parse failure", `set security ike policy p1 pre-shared-key ascii-text "` + secret},
		{"delete parse failure", `delete security ike policy p1 pre-shared-key ascii-text "` + secret},
		{"unsupported verb", "frobnicate security ike policy p1 pre-shared-key ascii-text " + secret},
		{"mis-cased Set", "Set security ike policy p1 pre-shared-key ascii-text " + secret},
		{"delete-shaped secret via unsupported case", "DELETE security ike policy p1 pre-shared-key ascii-text " + secret},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &cmdCapturingHandler16726{}
			prev := slog.Default()
			slog.SetDefault(slog.New(h))
			defer slog.SetDefault(prev)

			e := &Engine{}
			ops, ok := e.classifyPlan(&config.EventPolicy{Name: "p1", ThenCommands: []string{tc.cmd}})
			if ok || len(ops) != 0 {
				t.Fatalf("classifyPlan(%q) = (%d ops, ok=%v), want batch rejected", tc.cmd, len(ops), ok)
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
		})
	}
}
