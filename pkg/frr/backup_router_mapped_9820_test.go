package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9820: the backup-router render belt skips a mapped next-hop (the commit
// gate refuses it), and the family check uses the shared predicate —
// which flips both mapped-destination rows toward gate agreement
// (Codex-B3). Belt attribution is behavioral, not log-based:
//
//   - mapped NH + mapped dst: skipped ONLY by the mapped belt (neither
//     the old nor the new family belt skips it) — proves the mapped arm.
//   - plain-v4 NH + mapped dst: skipped ONLY by the new family belt (the
//     NH is not mapped) — proves the predicate swap.
//   - v6 NH + mapped dst: EMITS (the old belt vetoed it) — proves the
//     omit→emit flip.
//
// FAIL-ON-REVERT: restore frrOperandIsV6 in the belt (or drop the mapped
// skip) and the discriminating cells below flip back.

func TestBackupRouterMappedNextHopOmitted_9820(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
	}{
		{"empty-dst", []string{"set system backup-router ::ffff:192.0.2.1"}},
		{"v6-dst", []string{"set system backup-router ::ffff:192.0.2.1 destination ::/0"}},
		{"v4-dst", []string{"set system backup-router ::ffff:192.0.2.1 destination 0.0.0.0/0"}},
		{"hex", []string{"set system backup-router ::ffff:c000:201"}},
		// Mapped NH + mapped dst: the family belts (old and new) both
		// pass this row, so emptiness here proves the MAPPED belt.
		{"mapped-dst", []string{"set system backup-router ::ffff:192.0.2.1 destination ::ffff:10.0.0.0/104"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := renderBackupRouterFromLenientConfig(t, tc.cmds...)
			if strings.TrimSpace(got) != "" {
				t.Fatalf("mapped backup-router must render nothing, got:\n%s", got)
			}
		})
	}
}

func TestBackupRouterMappedDestinationFlips_9820(t *testing.T) {
	// B3 row 1: v6 NH + mapped dst EMITS (grammatically valid, matching
	// families) — the old belt vetoed it under a false reason.
	got, _ := renderBackupRouterFromLenientConfig(t,
		"set system backup-router 2001:db8::1 destination ::ffff:10.0.0.0/104")
	if want := "ipv6 route ::ffff:10.0.0.0/104 2001:db8::1 250\n!\n"; got != want {
		t.Fatalf("B3 row 1 render = %q, want %q", got, want)
	}
	// B3 row 2: plain-v4 NH + mapped dst SKIPS (family mismatch under the
	// shared predicate) — the old belt emitted an interface-fill line.
	// The NH is not mapped, so only the family belt can skip this row.
	got, _ = renderBackupRouterFromLenientConfig(t,
		"set system backup-router 192.168.50.1 destination ::ffff:10.0.0.0/104")
	if strings.TrimSpace(got) != "" {
		t.Fatalf("B3 row 2 must render nothing, got:\n%s", got)
	}
}

func TestBackupRouterMatchedFamiliesUnchanged_9820(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
		want string
	}{
		{"v4-empty", []string{"set system backup-router 192.168.50.1"},
			"ip route 0.0.0.0/0 192.168.50.1 250\n!\n"},
		{"v6-empty", []string{"set system backup-router 2001:db8::1"},
			"ipv6 route ::/0 2001:db8::1 250\n!\n"},
		{"v4-matched", []string{"set system backup-router 192.168.50.1 destination 0.0.0.0/0"},
			"ip route 0.0.0.0/0 192.168.50.1 250\n!\n"},
		{"v6-matched", []string{"set system backup-router 2001:db8::1 destination 2001:db8:1::/48"},
			"ipv6 route 2001:db8:1::/48 2001:db8::1 250\n!\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := renderBackupRouterFromLenientConfig(t, tc.cmds...)
			if got != tc.want {
				t.Fatalf("render = %q, want %q", got, tc.want)
			}
		})
	}
}

// Non-vacuity: the lenient compile retains the mapped value (so the
// belt, not the compiler, deserves the credit) and strict still refuses
// it with the mapped reason.
func TestBackupRouterMappedFixturesReachRenderer_9820(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{"set system backup-router ::ffff:192.0.2.1"} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.System.BackupRouter != "::ffff:192.0.2.1" {
		t.Fatalf("lenient compile dropped the mapped next-hop: %q", cfg.System.BackupRouter)
	}
	if _, err := config.CompileConfig(tree); err == nil ||
		!strings.Contains(err.Error(), "IPv4-mapped") {
		t.Fatalf("strict must refuse with the mapped reason, got: %v", err)
	}
}

// GLM-F2: the belt omits zoned literals (the gate refuses them), for the
// backup-router and, via the shared shape helper, for statics.
func TestZonedLiteralsOmitted_9820(t *testing.T) {
	if validFRRNextHopAddress("fe80::1%eth0") {
		t.Fatal("validFRRNextHopAddress accepted a zoned literal")
	}
	if !validFRRNextHopAddress("fe80::1") {
		t.Fatal("validFRRNextHopAddress rejected a plain v6 address")
	}
	got, _ := renderBackupRouterFromLenientConfig(t,
		"set system backup-router fe80::1%eth0")
	if strings.TrimSpace(got) != "" {
		t.Fatalf("zoned backup-router must render nothing, got:\n%s", got)
	}
	m := &Manager{}
	out := m.generateStaticRoute(&config.StaticRoute{
		Destination: "2001:db8::/32",
		Preference:  5,
		NextHops:    []config.NextHopEntry{{Address: "fe80::1%eth0"}},
	}, "", nil, nil, nil)
	if strings.TrimSpace(out) != "" {
		t.Fatalf("zoned static next-hop must render nothing, got:\n%s", out)
	}
}
