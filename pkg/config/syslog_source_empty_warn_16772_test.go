package config

import (
	"context"
	"log/slog"
	"strings"
	"testing"
)

// #16772 (R3-A47-03): resolveSyslogSource warned whenever no address of
// the collector's family was found — including when NO source-interface
// was configured at all. The daemon fingerprints
// (syslogClientFingerprint / syslogStreamFingerprint15231) call
// ResolveSyslogSourceAddrForCollector unconditionally, so every
// default-shaped stream (empty per-stream and global source-interface)
// logged a false "leaving the syslog source unbound (#15078)" WARN on
// every apply, indistinguishable from the genuine #15078 audit-loss
// warning for a configured interface with no address of the collector's
// family.
//
// FAIL-ON-REVERT: remove the empty-srcIface early return in
// resolveSyslogSource and the empty/whitespace cells below capture the
// #15078 WARN again.

type syslogWarnCapture16772 struct{ msgs *[]string }

func (h syslogWarnCapture16772) Enabled(context.Context, slog.Level) bool { return true }
func (h syslogWarnCapture16772) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		*h.msgs = append(*h.msgs, r.Message)
	}
	return nil
}
func (h syslogWarnCapture16772) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h syslogWarnCapture16772) WithGroup(string) slog.Handler      { return h }

func captureSyslogWarns16772(t *testing.T) *[]string {
	t.Helper()
	msgs := &[]string{}
	old := slog.Default()
	slog.SetDefault(slog.New(syslogWarnCapture16772{msgs: msgs}))
	t.Cleanup(func() { slog.SetDefault(old) })
	return msgs
}

func countUnboundWarns16772(msgs []string) int {
	n := 0
	for _, m := range msgs {
		if strings.Contains(m, "leaving the syslog source unbound") {
			n++
		}
	}
	return n
}

// Defect cell: empty (or whitespace-only) source-interface with an
// IP-literal collector must resolve to "" silently — 0 WARNs.
func TestResolveSyslogSource_EmptyIfaceNoWarn16772(t *testing.T) {
	cfg := syslogFamilyFixture15078()
	for _, tc := range []struct {
		name      string
		srcIface  string
		collector string
	}{
		{"empty v6 collector", "", "2001:db8:9::1"},
		{"empty v4 collector", "", "192.0.2.1"},
		{"whitespace v6 collector", "   ", "2001:db8:9::1"},
		{"empty hostname collector", "", "collector.example.net"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msgs := captureSyslogWarns16772(t)
			if got := ResolveSyslogSourceAddrForCollector(cfg, tc.srcIface, tc.collector); got != "" {
				t.Errorf("ResolveSyslogSourceAddrForCollector(%q, %q) = %q, want \"\" (unbound)",
					tc.srcIface, tc.collector, got)
			}
			if n := countUnboundWarns16772(*msgs); n != 0 {
				t.Errorf("captured %d #15078 unbound WARN(s) for unconfigured source-interface %q, want 0 (#16772): %v",
					n, tc.srcIface, *msgs)
			}
		})
	}
	// The family-blind entry point shares the resolver: also silent.
	msgs := captureSyslogWarns16772(t)
	if got := ResolveSyslogSourceAddr(cfg, ""); got != "" {
		t.Errorf("ResolveSyslogSourceAddr(\"\") = %q, want \"\"", got)
	}
	if n := countUnboundWarns16772(*msgs); n != 0 {
		t.Errorf("family-blind empty resolve captured %d WARN(s), want 0 (#16772)", n)
	}
}

// Positive control: a CONFIGURED source-interface with no address of the
// collector's family must still warn (#15078) — the genuine audit-loss
// signal the false warning was drowning out. Acceptance: an IPv6
// collector with a v4-only configured source-interface still warns.
func TestResolveSyslogSource_ConfiguredWrongFamilyStillWarns16772(t *testing.T) {
	cfg := syslogFamilyFixture15078()
	// reth2.0 is IPv6-only; reth1.100 is dual-stack, so use a v4-only
	// configured interface for the IPv6-collector cell: construct one.
	cfg.Interfaces.Interfaces["reth3"] = &InterfaceConfig{
		Name: "reth3",
		Units: map[int]*InterfaceUnit{
			0: {
				Number:         0,
				Addresses:      []string{"10.0.3.20/24"},
				PrimaryAddress: "10.0.3.20/24",
			},
		},
	}
	for _, tc := range []struct {
		name      string
		srcIface  string
		collector string
	}{
		{"ipv6 collector v4-only iface", "reth3.0", "2001:db8:9::1"},
		{"ipv4 collector v6-only iface", "reth2.0", "192.0.2.1"},
		{"ipv6 collector nonexistent iface", "reth9.0", "2001:db8:9::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msgs := captureSyslogWarns16772(t)
			if got := ResolveSyslogSourceAddrForCollector(cfg, tc.srcIface, tc.collector); got != "" {
				t.Errorf("ResolveSyslogSourceAddrForCollector(%q, %q) = %q, want \"\" (unbound)",
					tc.srcIface, tc.collector, got)
			}
			if n := countUnboundWarns16772(*msgs); n != 1 {
				t.Errorf("captured %d #15078 unbound WARN(s) for configured %q, want exactly 1 (positive control must stay loud): %v",
					n, tc.srcIface, *msgs)
			}
		})
	}
}
