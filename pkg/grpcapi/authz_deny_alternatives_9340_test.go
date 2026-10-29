package grpcapi

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9340 on the REAL registered surface, updated for #16067: the gate
// now reconstructs argument-bearing commands (ShowText
// route-table:secret-vrf charges "show route table secret-vrf"), so
// the issue's argument-text alternative DOES fire here and is no
// longer unenforceable. A truly unenforceable alternative is one
// naming no producible command in any spelling (^show qqq-zzz$).
func TestCombinedDenyAlternativeOnTheRealSurface9340(t *testing.T) {
	rules, ok, err := config.OperationalLoginRegexesFor(
		gateCfg7172(t, "^(show qqq-zzz|request system reboot)$", true), "ops")
	if err != nil || !ok {
		t.Fatalf("precondition failed (ok=%v err=%v)", ok, err)
	}
	if got := unenforceableDenyPatterns(rules); len(got) != 0 {
		t.Fatalf("premise broken: the combined pattern must fire here as a whole; got %v", got)
	}
	got := unenforceableDenyAlternatives(rules)
	if len(got) != 1 || got[0] != "^show qqq-zzz$" {
		t.Fatalf("want exactly the unenforceable alternative reported, got %q", got)
	}

	// #16067 control: the route-table argument alternative now fires
	// on this surface, so the combined pattern reports nothing.
	rt, _, _ := config.OperationalLoginRegexesFor(gateCfg7172(t, "^(show route table secret-vrf|request system reboot)$", true), "ops")
	if len(unenforceableDenyPatterns(rt)) != 0 || len(unenforceableDenyAlternatives(rt)) != 0 {
		t.Errorf("route-table pattern: want nothing after #16067; patterns=%v alternatives=%v",
			unenforceableDenyPatterns(rt), unenforceableDenyAlternatives(rt))
	}
	// The single-restriction control: an argument-scoped restriction
	// that fires remotely has neither answer; one naming no command
	// keeps the whole-pattern answer only.
	single, _, _ := config.OperationalLoginRegexesFor(gateCfg7172(t, "^show route table secret-vrf$", true), "ops")
	if len(unenforceableDenyPatterns(single)) != 0 || len(unenforceableDenyAlternatives(single)) != 0 {
		t.Errorf("single route-table restriction: want nothing after #16067; patterns=%v alternatives=%v",
			unenforceableDenyPatterns(single), unenforceableDenyAlternatives(single))
	}
	dead, _, _ := config.OperationalLoginRegexesFor(gateCfg7172(t, "^show qqq-zzz$", true), "ops")
	if len(unenforceableDenyPatterns(dead)) != 1 || len(unenforceableDenyAlternatives(dead)) != 0 {
		t.Errorf("single dead restriction: want the whole-pattern answer only; patterns=%v alternatives=%v",
			unenforceableDenyPatterns(dead), unenforceableDenyAlternatives(dead))
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
		gateCfg7172(t, "^(show qqq-zzz|request system reboot)$", true), "ops")
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
	if !strings.Contains(out, "show qqq-zzz$") {
		t.Errorf("the record does not name the alternative:\n%s", out)
	}
	if strings.Contains(out, "cannot be enforced on the gRPC surface") {
		t.Errorf("a pattern that fires as a whole got the whole-pattern record:\n%s", out)
	}
}
