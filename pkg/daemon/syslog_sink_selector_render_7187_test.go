package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7187 render half: a file/user destination carrying several authored
// selectors must render ONE drop-in whose selector field names all of them.
//
// A destination is one target — a log path, or an omusrmsg account — so it gets
// one xpf-managed drop-in named after it. rsyslog's selector field already
// expresses a set: semicolon-separated `facility.priority` pairs are OR'd,
// which is Junos' meaning for several statements under one stanza. Rendering
// one pair and dropping the rest would move #7187's discard from the compiler
// into the renderer rather than fixing it.
func TestMultiSelectorFileRendersEverySelector7187(t *testing.T) {
	cfg := syslogCfg([]*config.SyslogFileConfig{{
		Name: "messages",
		Selectors: []config.SyslogFacility{
			{Facility: "daemon", Severity: "info"},
			{Facility: "authorization", Severity: "warning"},
			{Facility: "change-log", Severity: "any"},
		},
	}}, nil)

	body, ok := renderedFor(cfg, renderPrefix+"messages.conf")
	if !ok {
		t.Fatal("a multi-selector file destination rendered no drop-in at all")
	}
	// change-log has no rsyslog name and maps to local6; `any` maps to `*`.
	const want = "daemon.info;authorization.warning;local6.*"
	if !strings.Contains(body, want) {
		t.Errorf("rendered selector field does not contain %q:\n%s\n"+
			"Every authored selector must reach the one drop-in this destination owns "+
			"(#7187). Rendering only one reproduces the discard in the renderer.",
			want, body)
	}
	if strings.Count(body, "/var/log/messages") != 1 {
		t.Errorf("the destination rendered %d target lines, want exactly 1 — several "+
			"lines racing for one path is not the fix:\n%s",
			strings.Count(body, "/var/log/messages"), body)
	}
}

func TestMultiSelectorUserRendersEverySelector7187(t *testing.T) {
	cfg := syslogCfg(nil, []*config.SyslogUserConfig{{
		User: "root",
		Selectors: []config.SyslogFacility{
			{Facility: "daemon", Severity: "info"},
			{Facility: "authorization", Severity: "warning"},
		},
	}})
	body, ok := renderedFor(cfg, renderPrefix+"user-root.conf")
	if !ok {
		t.Fatal("a multi-selector user destination rendered no drop-in at all")
	}
	if !strings.Contains(body, "daemon.info;authorization.warning") {
		t.Errorf("rendered user selector field lost a selector (#7187):\n%s", body)
	}
}

// THE MIDDLE ROW. One unsafe selector among safe ones must drop only ITSELF.
//
// Before #7187 a sink held one pair and the #5797 belt skipped the whole
// destination when that pair was unsafe. With a list, keeping that rule would
// let one poisoned selector delete the operator's safe ones — a strictly worse
// outcome than the injection it defends against, since the destination then
// silently stops logging. Dropping just the offending pair is closer to what
// was authored and, for a one-selector destination, bit-identical to the old
// behaviour: nothing safe survives and the destination is skipped, which the
// all-unsafe cell below pins.
func TestOneUnsafeSelectorDropsOnlyItself7187(t *testing.T) {
	cfg := syslogCfg([]*config.SyslogFileConfig{{
		Name: "audit",
		Selectors: []config.SyslogFacility{
			{Facility: "daemon", Severity: "info"},
			{Facility: "daemon;*.* @@collector.example:514", Severity: "info"},
			{Facility: "authorization", Severity: "warning"},
		},
	}}, nil)

	body, ok := renderedFor(cfg, renderPrefix+"audit.conf")
	if !ok {
		t.Fatal("one unsafe selector deleted the whole destination; the operator's safe " +
			"selectors must still render (#7187)")
	}
	if strings.Contains(body, "@@collector.example") {
		t.Errorf("the injecting selector reached the drop-in (#5797 belt defeated):\n%s", body)
	}
	for _, want := range []string{"daemon.info", "authorization.warning"} {
		if !strings.Contains(body, want) {
			t.Errorf("safe selector %q was dropped along with the unsafe one:\n%s", want, body)
		}
	}
}

// The all-unsafe case is what keeps the cell above from being satisfied by a
// belt that stopped rejecting anything: with nothing safe left, the destination
// must not render — exactly what a single unsafe selector did before #7187.
func TestAllUnsafeSelectorsSkipTheDestination7187(t *testing.T) {
	cfg := syslogCfg([]*config.SyslogFileConfig{
		{Name: "evil", Selectors: []config.SyslogFacility{
			{Facility: "daemon;*.* @@collector.example:514", Severity: "info"},
		}},
		{Name: "ops", Selectors: []config.SyslogFacility{
			{Facility: "daemon", Severity: "info"},
		}},
	}, nil)
	if body, ok := renderedFor(cfg, renderPrefix+"evil.conf"); ok {
		t.Errorf("a destination whose only selector is unsafe still rendered:\n%s", body)
	}
	if _, ok := renderedFor(cfg, renderPrefix+"ops.conf"); !ok {
		t.Error("the safe sibling did not render; a reject-everything belt fails here just " +
			"as loudly as a reject-nothing one")
	}
}

// #15708 supersedes the #7187 empty-wildcard rule: an empty selector list
// must NOT render `*.*` — a modifier-only stanza would otherwise log
// everything. The destination is omitted.
func TestEmptySelectorListStillRendersWildcard7187(t *testing.T) {
	cfg := syslogCfg([]*config.SyslogFileConfig{{Name: "catchall"}}, nil)
	if body, ok := renderedFor(cfg, renderPrefix+"catchall.conf"); ok {
		t.Fatalf("a file destination with no authored selector rendered %q; #15708 requires omission, not *.*", body)
	}
}

// A PARTIALLY dropped destination must still warn. This is a silent-loss risk
// #7187 INTRODUCES: before it, an unsafe selector took the whole destination
// down, and TestSyslogRenderWarnsOnSkippedDestination_5797 pinned the warning
// for that. Now the destination survives with fewer selectors, so the operator
// is still logging — just not everything they authored — which is the quieter
// and more misleading of the two outcomes. It owes its own signal, naming both
// the destination and the selector that was dropped.
func TestPartiallyDroppedDestinationStillWarns7187(t *testing.T) {
	buf := captureRenderedWarnings(t)
	syslogDropinContents(syslogCfg([]*config.SyslogFileConfig{{
		Name: "audit",
		Selectors: []config.SyslogFacility{
			{Facility: "daemon", Severity: "info"},
			{Facility: "daemon;*.* @@collector.example:514", Severity: "info"},
		},
	}}, nil), renderPrefix)

	got := buf.String()
	if !strings.Contains(got, "unsafe selector token") {
		t.Errorf("dropping ONE selector from a surviving destination emitted no warning. "+
			"The destination still logs, so nothing else signals that part of the "+
			"operator's config was discarded (#7187). captured:\n%s", got)
	}
	if !strings.Contains(got, "audit") {
		t.Errorf("the warning must name the destination whose selector was dropped. "+
			"captured:\n%s", got)
	}
	// Negative control: the surviving selector must not be reported as dropped,
	// or the warning says the destination lost more than it did.
	if strings.Count(got, "unsafe selector token") != 1 {
		t.Errorf("expected exactly one dropped-selector warning, got %d:\n%s",
			strings.Count(got, "unsafe selector token"), got)
	}
}
