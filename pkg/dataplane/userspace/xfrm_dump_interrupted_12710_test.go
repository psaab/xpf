package userspace

import (
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// TestAllowlistDegradesToNilOnInterruptedXfrmDump12710 records the #12710
// decision: an interrupted dump is incomplete evidence and must not grant RSS
// reshape permission based on the absence of a device from its partial result.
//
// The policy is intentionally consumer-specific. Snapshot/ingress classification
// retains known xfrmi links from the partial result so known tunnels stay
// excluded; the reshape allowlist grants permission from absence, so it must
// degrade to nil. The stale, zoned st10 in this fixture was measured as the
// ordinary-looking entry in [ge-0-0-0 st10] before this policy. Failing closed
// costs NIC tuning until the next apply; using the partial list can reshape a
// live IPsec tunnel's RSS table. The adjacent #12580 hard-failure policy already
// accepts the same operator-visible defer-until-next-apply cost.
//
// FAIL-ON-REVERT: swallowing ErrDumpInterrupted in xfrmDumpNames makes the
// interrupted allowlist equal [ge-0-0-0 st10], and the policy assertion rejects
// the missing error. Degrading on every dump fails the healthy control because
// the LAN must remain present. The WARN assertion pins the successful-commit
// skip and retry point for operators.
func TestAllowlistDegradesToNilOnInterruptedXfrmDump12710(t *testing.T) {
	defer stubLinkSnapshot5619(t, map[string]int{"ge-0-0-0": 10, "st10": 11})()
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces st10 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust interfaces st10.0",
	}

	t.Run("interrupted partial list cannot grant permission", func(t *testing.T) {
		defer stubInterruptedXfrmNetdevs12710(t, "ge-0-0-0")()
		cfg := compileForTest5619(t, lines...)
		logs := captureInterruptedWarns12710(t)
		if got := UserspaceBoundLinuxInterfaces(cfg); got != nil {
			t.Errorf("allowlist on an interrupted xfrm dump = %v, want nil: st10's "+
				"absence from the partial list is not evidence that it is an ordinary NIC", got)
		}
		warns := interruptedAllowlistWarns12710(logs.String())
		if len(warns) != 1 {
			t.Fatalf("allowlist WARN count = %d, want exactly 1: the commit succeeds, "+
				"so this is the only operator signal that NIC tuning was skipped.\n%s",
				len(warns), logs.String())
		}
		for _, want := range []string{
			"RSS indirection", "kill-switch", "coalescence", "hand-back", "next config apply",
		} {
			if !strings.Contains(warns[0], want) {
				t.Errorf("allowlist WARN lacks %q: %s", want, warns[0])
			}
		}
		snap, err := buildSnapshot(cfg, deriveUserspaceConfig(cfg), 0, 0)
		if err != nil {
			t.Fatalf("buildSnapshot on interrupted dump: %v", err)
		}
		if !snap.xfrmDumpFailed {
			t.Fatal("snapshot lost the interrupted-dump failure status")
		}
	})

	t.Run("policy reports interruption and preserves known xfrmi", func(t *testing.T) {
		partial := []netlink.Link{
			&netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-0"}},
			&netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: "st10"}, Ifid: 0x50001},
		}
		got, err := xfrmDumpNames(partial, netlink.ErrDumpInterrupted)
		if !errors.Is(err, netlink.ErrDumpInterrupted) {
			t.Fatalf("xfrmDumpNames error = %v, want ErrDumpInterrupted", err)
		}
		if !got["st10"] {
			t.Fatalf("xfrmDumpNames = %v, lost known xfrmi from partial dump", got)
		}
		if got["ge-0-0-0"] {
			t.Fatalf("xfrmDumpNames = %v, ordinary Device classified as xfrm", got)
		}
	})

	t.Run("healthy control retains LAN", func(t *testing.T) {
		defer stubXfrmNetdevs(t, "st10")()
		cfg := compileForTest5619(t, lines...)
		logs := captureInterruptedWarns12710(t)
		got := UserspaceBoundLinuxInterfaces(cfg)
		if !slices.Contains(got, "ge-0-0-0") {
			t.Errorf("healthy allowlist = %v, want ge-0-0-0", got)
		}
		if slices.Contains(got, "st10") {
			t.Errorf("healthy allowlist = %v includes live xfrmi st10", got)
		}
		if warns := interruptedAllowlistWarns12710(logs.String()); len(warns) != 0 {
			t.Errorf("healthy dump logged allowlist-degrade WARN: %q", warns)
		}
	})
}

func stubInterruptedXfrmNetdevs12710(t *testing.T, names ...string) func() {
	t.Helper()
	prev := liveXfrmNetdevs
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	liveXfrmNetdevs = func() (map[string]bool, error) { return set, netlink.ErrDumpInterrupted }
	return func() { liveXfrmNetdevs = prev }
}

func captureInterruptedWarns12710(t *testing.T) *strings.Builder {
	t.Helper()
	var buf strings.Builder
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return &buf
}

func interruptedAllowlistWarns12710(logs string) []string {
	var out []string
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, "level=WARN") && strings.Contains(line, "allowlist") {
			out = append(out, line)
		}
	}
	return out
}
