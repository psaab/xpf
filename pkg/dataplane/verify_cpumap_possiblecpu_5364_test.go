package dataplane

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// TestCPUMapLivePinPossibleCPUAccepted is the #5364 core: the live-pin ABI
// pre-flight must NOT treat a CPU-count-sized userspace_cpumap live pin as an
// ABI break. userspace_cpumap is a BPF_MAP_TYPE_CPUMAP; the shim declares it as
// `CpuMap::with_max_entries(256, 0)` (a template MAX), but cilium/ebpf's
// MapSpec.fixupMagicFields clamps a CPUMAP's MaxEntries to nr_possible_cpus
// before it creates OR ABI-compares the map, so a fresh daemon ALWAYS pins it at
// nr_possible_cpus (16 on the loss VMs), never 256. MapSpec.Compatible — the
// exact ErrMapIncompatible check this pre-flight predicts — runs the identical
// clamp, so the real PinByName load compares nr_possible_cpus==nr_possible_cpus
// and succeeds. The pre-flight must resolve the reference MaxEntries the same way
// (livePinRefABI) or it false-rejects EVERY rolling cluster-deploy.
//
// RED-on-revert: before #5364 the reference used the embedded .o MaxEntries (256)
// verbatim, so 256-vs-nr_possible_cpus produced a phantom MaxEntries diff and this
// "must be accepted" assertion flips red (the false-reject returns).
func TestCPUMapLivePinPossibleCPUAccepted(t *testing.T) {
	t.Parallel()

	ncpu := uint32(ebpf.MustPossibleCPU())
	if ncpu >= 256 {
		t.Skipf("machine reports %d possible CPUs; the shim's 256-entry cpumap template is not clamped below 256 here", ncpu)
	}

	base := validABIBaseSpec()
	// Embedded shim declares the cpumap at the 256 template max.
	base.Maps["userspace_cpumap"] = &ebpf.MapSpec{Type: ebpf.CPUMap, KeySize: 4, ValueSize: 4, MaxEntries: 256}

	// RED-on-revert guard: the base spec passes the legacy presence+MaxEntries
	// validator, so the ONLY reject signal is the live-pin ABI comparison.
	if err := legacyPresenceMaxEntriesValidate(base); err != nil {
		t.Fatalf("legacy validator rejected base (%v); cannot prove RED-on-revert", err)
	}

	// Live pin is what a fresh daemon actually pinned: nr_possible_cpus.
	reader := pinReaderWithOverride(base, map[string]userspaceMapABI{
		"userspace_cpumap": {Type: ebpf.CPUMap, KeySize: 4, ValueSize: 4, MaxEntries: ncpu},
	})

	if err := validateUserspaceShimSpecWith(base, reader); err != nil {
		t.Fatalf("cpumap 256-template embedded vs nr_possible_cpus(%d) live pin must be ACCEPTED "+
			"(loader clamps CPUMAP MaxEntries to possible-CPU); got: %v", ncpu, err)
	}
}

// TestCPUMapLivePinGenuineBreakStillRejected proves the #5364 relaxation is
// scoped to the MaxEntries axis of a CPUMAP only: a genuine cpumap ABI break —
// here a ValueSize change — is STILL rejected at the pre-flight and STILL carries
// the stale-pin remediation. userspaceMapABIDiff checks ValueSize before
// MaxEntries, so the ValueSize break dominates regardless of the CPU count.
func TestCPUMapLivePinGenuineBreakStillRejected(t *testing.T) {
	t.Parallel()

	ncpu := uint32(ebpf.MustPossibleCPU())

	base := validABIBaseSpec()
	base.Maps["userspace_cpumap"] = &ebpf.MapSpec{Type: ebpf.CPUMap, KeySize: 4, ValueSize: 8, MaxEntries: 256}
	// MaxEntries matches (clamped 256 == live nr_possible_cpus); ValueSize differs.
	reader := pinReaderWithOverride(base, map[string]userspaceMapABI{
		"userspace_cpumap": {Type: ebpf.CPUMap, KeySize: 4, ValueSize: 4, MaxEntries: ncpu},
	})

	err := validateUserspaceShimSpecWith(base, reader)
	if err == nil {
		t.Fatal("genuine cpumap ValueSize break must still be rejected (relaxation is MaxEntries-only)")
	}
	for _, want := range []string{"userspace_cpumap", "ValueSize", "ABI-incompatible", userspaceShimStalePinRemediation} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("err = %v, want substring %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "make generate-userspace-xdp") {
		t.Fatalf("err = %v, live-pin mismatch must NOT tell the operator to rebuild the shim", err)
	}
}

// TestNonCPUMapMaxEntriesStillStrict proves the #5364 fix does NOT weaken the
// MaxEntries check for any non-cpumap ABI-checked map: a real MaxEntries drift on
// a HASH map (here the shim-declared userspace_sessions) is STILL rejected. Only
// userspace_cpumap is CPU-count-sized; every other map keeps a strict MaxEntries
// comparison.
func TestNonCPUMapMaxEntriesStillStrict(t *testing.T) {
	t.Parallel()

	base := validABIBaseSpec()
	// A shim-declared HASH map; embedded shape is the reference for the diff.
	base.Maps["userspace_sessions"] = &ebpf.MapSpec{Type: ebpf.Hash, KeySize: 40, ValueSize: 1, MaxEntries: UserspaceSessionsMaxEntries, Flags: unix.BPF_F_NO_PREALLOC}
	// Live pin drifted to a smaller MaxEntries — a genuine ABI break for a
	// non-cpumap map, which must NOT be clamped away.
	reader := pinReaderWithOverride(base, map[string]userspaceMapABI{
		"userspace_sessions": {Type: ebpf.Hash, KeySize: 40, ValueSize: 1, MaxEntries: UserspaceSessionsMaxEntries / 2, Flags: unix.BPF_F_NO_PREALLOC},
	})

	err := validateUserspaceShimSpecWith(base, reader)
	if err == nil {
		t.Fatal("non-cpumap MaxEntries drift must still be rejected (strict check preserved)")
	}
	for _, want := range []string{
		"userspace_sessions",
		fmt.Sprintf("MaxEntries embedded=%d pinned=%d", UserspaceSessionsMaxEntries, UserspaceSessionsMaxEntries/2),
		"ABI-incompatible",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("err = %v, want substring %q", err, want)
		}
	}
}
