package config

import (
	"strings"
	"testing"
)

// #16581 (residual of Y39-05/#15256, R3-N08-07): Junos spells
// `[edit security flow tcp-session] tcp-initial-timeout`,
// `fin-invalidate-session`, and
// `time-wait-state apply-to-half-close-state`. Those rows were
// rejected by the closed-world schema while the xpf spellings
// (`initial-timeout`, `apply-to-half-closed-state`) committed.
// The Junos spellings are now canonical; the xpf spellings remain
// as deprecated aliases committing to the SAME fields.
//
// FAIL-ON-REVERT: removing any Junos schema leaf makes its strict
// case below reject again; removing the fin compiler arm leaves
// FinInvalidateSession false; removing the fin wire/runtime leg is
// pinned in pkg/dataplane/userspace and userspace-dp.

func strict16581(t *testing.T, cmds []string) (*Config, error) {
	t.Helper()
	tree := buildTree(t, cmds)
	if err := SchemaValidate(tree); err != nil {
		return nil, err
	}
	return CompileConfig(tree)
}

func TestTCPSessionJunosSpellings16581(t *testing.T) {
	// Junos canonical rows commit to the same fields as the xpf aliases.
	junos, err := strict16581(t, []string{
		"set security flow tcp-session tcp-initial-timeout 20",
		"set security flow tcp-session fin-invalidate-session",
		"set security flow tcp-session time-wait-state apply-to-half-close-state",
	})
	if err != nil {
		t.Fatalf("Junos spellings rejected at strict commit: %v", err)
	}
	ts := junos.Security.Flow.TCPSession
	if ts == nil || ts.InitialTimeout != 20 || !ts.FinInvalidateSession || !ts.TimeWaitStateApplyToHalfClosed {
		t.Fatalf("Junos rows did not commit to the same fields: %+v", ts)
	}

	xpf, err := strict16581(t, []string{
		"set security flow tcp-session initial-timeout 20",
		"set security flow tcp-session time-wait-state apply-to-half-closed-state",
	})
	if err != nil {
		t.Fatalf("deprecated xpf aliases rejected: %v", err)
	}
	xts := xpf.Security.Flow.TCPSession
	if xts == nil || xts.InitialTimeout != ts.InitialTimeout ||
		xts.TimeWaitStateApplyToHalfClosed != ts.TimeWaitStateApplyToHalfClosed {
		t.Fatalf("xpf aliases diverged from Junos rows: junos=%+v xpf=%+v", ts, xts)
	}

	// Unknown keywords still fail closed under the closed world.
	if _, err := strict16581(t, []string{
		"set security flow tcp-session tcp-initial-timeoutx 20",
	}); err == nil {
		t.Fatal("near-miss tcp-initial-timeoutx accepted under closed-world tcp-session")
	}
	if _, err := strict16581(t, []string{
		"set security flow tcp-session time-wait-state apply-to-half-closest-state",
	}); err == nil {
		t.Fatal("near-miss apply-to-half-closest-state accepted under closed-world time-wait-state")
	}

	// Range gate applies to the Junos spelling exactly as to the alias.
	if _, err := strict16581(t, []string{
		"set security flow tcp-session tcp-initial-timeout -1",
	}); err == nil {
		t.Fatal("tcp-initial-timeout -1 accepted; want range rejection")
	}
	if _, err := strict16581(t, []string{
		"set security flow tcp-session tcp-initial-timeout 9223372037",
	}); err == nil {
		t.Fatal("tcp-initial-timeout overflow accepted; want range rejection")
	}

	// Hierarchical spelling commits identically.
	tree, perrs := NewParser("security { flow { tcp-session { tcp-initial-timeout 33; fin-invalidate-session; time-wait-state { apply-to-half-close-state; } } } }").Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse hier: %v", perrs)
	}
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("hier Junos spellings rejected: %v", err)
	}
	hcfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("hier compile: %v", err)
	}
	hts := hcfg.Security.Flow.TCPSession
	if hts == nil || hts.InitialTimeout != 33 || !hts.FinInvalidateSession || !hts.TimeWaitStateApplyToHalfClosed {
		t.Fatalf("hier Junos rows not compiled: %+v", hts)
	}

	// Show renders the fin-invalidate knob (SSOT for CLI/gRPC/REST).
	var sb strings.Builder
	RenderFlowTimeouts(&sb, junos)
	if !strings.Contains(sb.String(), "fin-invalidate-session") {
		t.Fatalf("show must render fin-invalidate-session:\n%s", sb.String())
	}
}
