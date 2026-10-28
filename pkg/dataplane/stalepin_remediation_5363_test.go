package dataplane

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// TestLivePinABIMismatchUsesStalePinRemediation is the #5363 core: when the
// embedded shim's map ABI differs from the RUNNING daemon's LIVE pinned map,
// the live pin is ALWAYS the stale side — it is the OLD daemon's map, while the
// embedded shim is the intended (and un-broken) deploy target. So the
// remediation must be the stale-pin guidance
// (`userspaceShimStalePinRemediation`), NEVER `make generate` (which would tell
// the operator to rebuild a shim that is not broken).
//
// "full-dataplane-reload" was this comment's original NAME for that constant
// and is retired (#6928 review): the constant now instructs a TARGETED
// single-pin unlink, and no reload releases a bpffs pin at all — so the old
// label described an action nothing performs.
//
// This is direction-INDEPENDENT: it holds both when the embedded shape is the
// larger side AND when it is the smaller side. Both cases exercise the SAME
// live-pin mismatch branch, so a single stale-pin remediation is correct for
// the whole branch — no MaxEntries >-vs-< heuristic.
//
// #5364 CORRECTION: the userspace_cpumap "16 vs 256 MaxEntries" gap that #5363
// originally used as its example is NOT a genuine ABI break — a CPUMAP's
// MaxEntries is clamped to nr_possible_cpus at load, so the map is pinned at
// nr_possible_cpus and MapSpec.Compatible accepts it. That case is now handled
// by livePinRefABI and is no longer rejected (see TestCPUMapLivePinPossibleCPU*).
// The cases below therefore use a genuine cpumap ABI break (a ValueSize change)
// and a genuine non-cpumap MaxEntries drift, both of which are still stale-pin
// mismatches that must carry the stale-pin remediation.
//
// RED-on-revert: with the pre-#5363 code the live-pin error appended
// userspaceShimGenerateRemediation ("Re-run `make generate-userspace-xdp`."),
// so this test's "must NOT contain make generate-userspace-xdp" and "must
// contain the stale-pin phrase" assertions both flip red.
func TestLivePinABIMismatchUsesStalePinRemediation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		mapName      string
		embedded     *ebpf.MapSpec   // added to the shim spec (nil => already present)
		pinnedShape  userspaceMapABI // live pin the fake reader reports
		wantDiffFrag string          // substring naming the offending field
	}{
		{
			// #5364: a GENUINE cpumap ABI break. The MaxEntries axis is
			// CPU-count-clamped and no longer diffs (the map is pinned at
			// nr_possible_cpus), so this uses a ValueSize change — a real
			// cross-version ABI break that is still a stale-pin mismatch.
			// The live pin's MaxEntries is nr_possible_cpus (what a fresh
			// daemon actually pins) so only ValueSize drives the diff.
			name:         "cpumap-genuine-valuesize-break",
			mapName:      "userspace_cpumap",
			embedded:     &ebpf.MapSpec{Type: ebpf.CPUMap, KeySize: 4, ValueSize: 8, MaxEntries: 256},
			pinnedShape:  userspaceMapABI{Type: ebpf.CPUMap, KeySize: 4, ValueSize: 4, MaxEntries: uint32(ebpf.MustPossibleCPU())},
			wantDiffFrag: "ValueSize embedded=8 pinned=4",
		},
		{
			// A shim-declared map (userspace_sessions): embedded shape is the
			// correct one; only the LIVE pin drifts, so the mismatch is caught
			// by the live-pin arm.
			name:         "sessions-live-pin-drift",
			mapName:      "userspace_sessions",
			embedded:     nil,
			pinnedShape:  userspaceMapABI{Type: ebpf.Hash, KeySize: 40, ValueSize: 1, MaxEntries: 16, Flags: unix.BPF_F_NO_PREALLOC},
			wantDiffFrag: "MaxEntries",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			base := validABIBaseSpec()
			if tt.embedded != nil {
				base.Maps[tt.mapName] = tt.embedded
			}

			// RED-on-revert guard: the base spec passes the legacy
			// presence+MaxEntries validator, so the ONLY reject signal is the
			// live-pin ABI comparison whose remediation we are asserting.
			if err := legacyPresenceMaxEntriesValidate(base); err != nil {
				t.Fatalf("legacy validator rejected base (%v); cannot prove RED-on-revert", err)
			}

			reader := pinReaderWithOverride(base, map[string]userspaceMapABI{tt.mapName: tt.pinnedShape})
			err := validateUserspaceShimSpecWith(base, reader)
			if err == nil {
				t.Fatalf("want live-pin ABI mismatch on %s, got nil", tt.mapName)
			}

			msg := err.Error()
			// The mismatch is still reported, naming the map and the field.
			for _, want := range []string{tt.mapName, "ABI-incompatible", tt.wantDiffFrag} {
				if !strings.Contains(msg, want) {
					t.Fatalf("err = %v, want substring %q", err, want)
				}
			}
			// The remediation is the stale-pin guidance...
			if !strings.Contains(msg, userspaceShimStalePinRemediation) {
				t.Fatalf("err = %v, want stale-pin remediation constant", err)
			}
			// ...and it must be ACTIONABLE, not merely distinctive.
			//
			// This block has now pinned the WORDING of two DIFFERENT wrong
			// instructions (#6928). It first required "FULL dataplane reload" /
			// "stale pin" / "released", which was satisfied by text telling the
			// operator to "stop xpfd so the old pin is released" — a bpffs pin
			// outlives the process, so following it reproduced the refusal. r5
			// replaced those with "restarting xpfd does NOT release" and
			// "OUTLIVES the process", which locked in the OPPOSITE categorical
			// claim, equally false: Cleanup() also runs from Manager.Teardown,
			// which non-hitless HA shutdown calls, so on that path a restart IS
			// enough.
			//
			// A phrase-presence assertion is satisfied identically by a correct
			// and an incorrect instruction — that is how both wrong messages
			// acquired a passing test. So the only assertion kept here is the
			// NEGATIVE on the specific claims the code disproves.
			//
			// WHAT THIS IS: a VOCABULARY check, not a property check (#6928).
			// It stops those two disproven phrasings returning VERBATIM. It
			// cannot tell a correct remediation from an incorrect one that
			// avoids those words, and this was measured, not assumed: rewriting
			// the constant to say "A plain restart ALWAYS releases this pin, on
			// every shutdown path" — categorically false, and false in the
			// opposite direction from the claims banned below — leaves every
			// test in ./pkg/dataplane/... green.
			//
			// Adding a third banned literal would repeat the mistake a third
			// time, so the escape is not narrowed, it is stated. What IS bound
			// is the pair of facts the message describes:
			// TestCleanupProductionCallersMatchRemediation_6928 pins Cleanup()'s
			// production caller set, and TestShutdownModeChoosesCloseOrTeardown6928
			// (pkg/daemon) pins which shutdown arm calls Teardown versus Close.
			// Whether this English sentence reports those two facts correctly is
			// not decidable by a test; it is decided by reading it against them.
			for _, disproven := range []string{
				"restarting xpfd does NOT release",
				"reachable only from",
			} {
				if strings.Contains(msg, disproven) {
					t.Fatalf("err = %v, remediation restored the categorical claim %q. "+
						"Cleanup() also runs from Manager.Teardown, which "+
						"daemon_run_shutdown.go calls on every NON-hitless shutdown, so "+
						"whether a restart clears the pin is mode-dependent (#6928)",
						err, disproven)
				}
			}
			// ...and NEVER the "rebuild the shim" remediation.
			if strings.Contains(msg, "make generate-userspace-xdp") {
				t.Fatalf("err = %v, live-pin mismatch must NOT tell the operator to rebuild the shim", err)
			}
		})
	}
}
