package daemon

import (
	"errors"
	"log/slog"
	"strings"
	"testing"

	xnft "github.com/psaab/xpf/pkg/nftables"
)

// TestHostInboundGapFenceLog18836 pins the #18836 operator-log contract for
// installHostInboundGapFence. The same function installs two different
// fences: the pre-activation fence (PreActivation=true, installed before
// networkd brings new addresses up, when no real install has failed) and
// the coverage-gap fence (PreActivation=false, installed only after a real
// install failed). Before the fix both successes logged the Warn
// "host-inbound real install failed; ...", so every successful
// pre-activation install produced a false failure warning. Successful
// pre-activation installs must log an Info instead; coverage-gap success
// keeps the Warn, and genuine install failures keep the Error.
func TestHostInboundGapFenceLog18836(t *testing.T) {
	injected := errors.New("nftables: gap fence install failed")

	run := func(t *testing.T, spec xnft.GapFenceSpec, installErr error) (*Daemon, []captureRecord, error) {
		t.Helper()

		sink := newCaptureSink()
		prevLog := slog.Default()
		slog.SetDefault(slog.New(capturingHandler{sink: sink}))
		t.Cleanup(func() { slog.SetDefault(prevLog) })

		origInstaller := nftInstaller
		origProbe := nftProbeAvailable
		// Keep tagNftInstallErr from probing a real netlink socket: the
		// subsystem reads available, so an injected failure stays untagged.
		nftProbeAvailable = func() error { return nil }
		t.Cleanup(func() { nftInstaller = origInstaller; nftProbeAvailable = origProbe })

		var gotSpec xnft.GapFenceSpec
		var calls int
		nftInstaller = &fakeNftInstaller{
			gapFence: func(s xnft.GapFenceSpec) error {
				calls++
				gotSpec = s
				return installErr
			},
		}

		d := &Daemon{}
		err := d.installHostInboundGapFence(spec)
		if calls != 1 {
			t.Fatalf("InstallGapFence calls = %d, want 1", calls)
		}
		if gotSpec.PreActivation != spec.PreActivation {
			t.Fatalf("installer saw PreActivation=%v, want %v", gotSpec.PreActivation, spec.PreActivation)
		}
		return d, sink.records(), err
	}

	has := func(recs []captureRecord, level slog.Level, substr string) bool {
		for _, r := range recs {
			if r.level == level && strings.Contains(r.msg, substr) {
				return true
			}
		}
		return false
	}
	anyHas := func(recs []captureRecord, substr string) bool {
		for _, r := range recs {
			if strings.Contains(r.msg, substr) {
				return true
			}
		}
		return false
	}

	preSpec := xnft.GapFenceSpec{
		PreActivation: true,
		UncoveredV4:   []string{"192.0.2.10"},
		UncoveredV6:   []string{"2001:db8::10"},
	}
	gapSpec := xnft.GapFenceSpec{
		UncoveredV4: []string{"192.0.2.11"},
		UncoveredV6: []string{"2001:db8::11"},
	}

	t.Run("pre_activation_success_logs_info_not_false_failure", func(t *testing.T) {
		d, recs, err := run(t, preSpec, nil)
		if err != nil {
			t.Fatalf("installHostInboundGapFence = %v, want nil", err)
		}
		if anyHas(recs, "real install failed") {
			t.Errorf("successful pre-activation install must not log 'real install failed': %+v", recs)
		}
		if has(recs, slog.LevelWarn, "") || has(recs, slog.LevelError, "") {
			t.Errorf("successful pre-activation install must not Warn/Error: %+v", recs)
		}
		if !has(recs, slog.LevelInfo, "host-inbound pre-activation gap fence installed") {
			t.Errorf("successful pre-activation install must log its Info: %+v", recs)
		}
		if d.hostInboundGapFenceSpec != nil {
			t.Errorf("pre-activation install must not retain a coverage-gap spec: %+v", d.hostInboundGapFenceSpec)
		}
	})

	t.Run("coverage_gap_success_keeps_warn", func(t *testing.T) {
		d, recs, err := run(t, gapSpec, nil)
		if err != nil {
			t.Fatalf("installHostInboundGapFence = %v, want nil", err)
		}
		if !has(recs, slog.LevelWarn, "host-inbound real install failed; retained generation does not cover newly-appeared") {
			t.Errorf("coverage-gap success must retain the Warn wording: %+v", recs)
		}
		if has(recs, slog.LevelInfo, "pre-activation gap fence installed") {
			t.Errorf("coverage-gap success must not log the pre-activation Info: %+v", recs)
		}
		if d.hostInboundGapFenceSpec == nil {
			t.Error("coverage-gap install must retain its spec for later merges")
		}
	})

	t.Run("pre_activation_failure_keeps_error", func(t *testing.T) {
		_, recs, err := run(t, preSpec, injected)
		if err == nil || !errors.Is(err, injected) {
			t.Fatalf("installHostInboundGapFence = %v, want wrapped injected error", err)
		}
		if !has(recs, slog.LevelError, "COVERAGE-GAP FAIL-OPEN GUARD: host-inbound real install failed") {
			t.Errorf("failed pre-activation install must retain the Error log: %+v", recs)
		}
		if has(recs, slog.LevelInfo, "pre-activation gap fence installed") {
			t.Errorf("failed pre-activation install must not log the success Info: %+v", recs)
		}
	})

	t.Run("coverage_gap_failure_keeps_error", func(t *testing.T) {
		_, recs, err := run(t, gapSpec, injected)
		if err == nil || !errors.Is(err, injected) {
			t.Fatalf("installHostInboundGapFence = %v, want wrapped injected error", err)
		}
		if !has(recs, slog.LevelError, "COVERAGE-GAP FAIL-OPEN GUARD: host-inbound real install failed") {
			t.Errorf("failed coverage-gap install must retain the Error log: %+v", recs)
		}
		if has(recs, slog.LevelWarn, "installed an additive gap fence") {
			t.Errorf("failed coverage-gap install must not log the success Warn: %+v", recs)
		}
	})
}
