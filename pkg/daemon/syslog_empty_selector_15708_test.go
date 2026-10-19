package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15708: empty selectors must not fabricate *.* (modifier-only stanza).
func TestEmptySelectorListNoWildcard15708(t *testing.T) {
	cfg := syslogCfg([]*config.SyslogFileConfig{{Name: "messages", ArchiveConfigured: true}}, []*config.SyslogUserConfig{{User: "bob"}})
	if body, ok := renderedFor(cfg, renderPrefix+"messages.conf"); ok {
		t.Fatalf("modifier-only file rendered %q, want omitted (no *.*)", body)
	}
	if body, ok := renderedFor(cfg, renderPrefix+"user-bob.conf"); ok {
		t.Fatalf("selector-less user rendered %q, want omitted (no *.*)", body)
	}
	// Merged coalesced destination from acceptance: two file messages blocks -> one selector field.
	cfg2 := syslogCfg([]*config.SyslogFileConfig{{Name: "messages", Selectors: []config.SyslogFacility{{Facility: "any", Severity: "notice"}, {Facility: "auth", Severity: "info"}}}}, nil)
	body, ok := renderedFor(cfg2, renderPrefix+"messages.conf")
	if !ok {
		t.Fatal("merged file did not render")
	}
	want := "*.notice;auth.info\t/var/log/messages"
	if !strings.Contains(body, want) {
		t.Fatalf("rendered %q want selector %q", body, want)
	}
}
