package daemon

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestPackedTailGate18771BootstrapWarnsThenOperatorCommitRefuses(t *testing.T) {
	const packedDrop = `interfaces { ge-0/0/0 { unit 0 { family inet6 dad-disable; } } }`
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(old) })

	d, hasActive := bootstrapDaemon(t, packedDrop, -1)
	if err := d.bootstrapFromFile(); err != nil {
		t.Fatalf("bootstrapFromFile must install a DROP config warn-only: %v", err)
	}
	if !hasActive() {
		t.Fatal("bootstrapFromFile did not install the active config")
	}
	active := d.store.ActiveConfig()
	if active == nil || !strings.Contains(strings.Join(active.Warnings, "\n"), "packedTailGate18771 DROP") {
		t.Fatalf("bootstrap did not retain the DROP diagnostic: %v", active)
	}

	if err := d.store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	defer d.store.ExitConfigure()
	if err := d.store.SetFromInput("system host-name after-bootstrap18771"); err != nil {
		t.Fatal(err)
	}
	_, activeText, activeGen := d.store.ActiveConfigAndText()
	if _, err := d.store.Commit(); err == nil || !strings.Contains(err.Error(), "packed-tail statement(s) would be silently dropped") {
		t.Fatalf("first operator commit after bootstrap = %v, want packed-tail refusal", err)
	}
	_, afterText, afterGen := d.store.ActiveConfigAndText()
	if afterText != activeText || afterGen != activeGen {
		t.Fatal("refused first operator commit changed the bootstrapped active config")
	}
	if got := strings.Count(logs.String(), "packedTailGate18771 DROP"); got != 2 {
		t.Fatalf("bootstrap + first operator commit emitted %d DROP diagnostics, want 2", got)
	}
}
