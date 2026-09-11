package grpcapi

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9340 on the REAL registered surface: the issue's combined pattern fires
// here as a whole (`request system reboot` is a mapped command), so the #7172
// whole-pattern answer stays empty. The per-alternative answer names the
// argument-text alternative, and only that one.
func TestCombinedDenyAlternativeOnTheRealSurface9340(t *testing.T) {
	rules, ok, err := config.OperationalLoginRegexesFor(
		gateCfg7172(t, "^(show route table secret-vrf|request system reboot)$", true), "ops")
	if err != nil || !ok {
		t.Fatalf("precondition failed (ok=%v err=%v)", ok, err)
	}
	if got := unenforceableDenyPatterns(rules); len(got) != 0 {
		t.Fatalf("premise broken: the combined pattern must fire here as a whole; got %v", got)
	}
	got := unenforceableDenyAlternatives(rules)
	if len(got) != 1 || got[0] != "^show route table secret-vrf$" {
		t.Fatalf("want exactly the argument-text alternative reported, got %q", got)
	}

	// The single-restriction control keeps the whole-pattern answer and no
	// alternative answer; a wholly enforceable pattern has neither.
	single, _, _ := config.OperationalLoginRegexesFor(gateCfg7172(t, "^show route table secret-vrf$", true), "ops")
	if len(unenforceableDenyPatterns(single)) != 1 || len(unenforceableDenyAlternatives(single)) != 0 {
		t.Errorf("single restriction: want the whole-pattern answer only; patterns=%v alternatives=%v",
			unenforceableDenyPatterns(single), unenforceableDenyAlternatives(single))
	}
	whole, _, _ := config.OperationalLoginRegexesFor(gateCfg7172(t, "^(request system reboot)$", true), "ops")
	if len(unenforceableDenyPatterns(whole)) != 0 || len(unenforceableDenyAlternatives(whole)) != 0 {
		t.Errorf("enforceable pattern: want nothing; patterns=%v alternatives=%v",
			unenforceableDenyPatterns(whole), unenforceableDenyAlternatives(whole))
	}
}

// The runtime log: exactly one partial-enforcement record per class and
// pattern, however many requests arrive, naming the alternative.
func TestPartialDenyLogsOncePerClassAndPattern9340(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	rules, ok, err := config.OperationalLoginRegexesFor(
		gateCfg7172(t, "^(show route table secret-vrf|request system reboot)$", true), "ops")
	if err != nil || !ok {
		t.Fatalf("precondition failed (ok=%v err=%v)", ok, err)
	}
	s := &Server{}
	for i := 0; i < 5; i++ {
		s.warnUnenforceableDenyPatternsOnce("ops", rules)
	}
	out := buf.String()
	if n := strings.Count(out, "only partly enforceable"); n != 1 {
		t.Fatalf("want one partial-enforcement record for five requests, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, "show route table secret-vrf$") {
		t.Errorf("the record does not name the alternative:\n%s", out)
	}
	if strings.Contains(out, "cannot be enforced on the gRPC surface") {
		t.Errorf("a pattern that fires as a whole got the whole-pattern record:\n%s", out)
	}
}
