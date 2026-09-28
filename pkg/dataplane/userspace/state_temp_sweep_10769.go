package userspace

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// tempWriterInstance identifies the helper process instance that staged a
// state-writer temp file: pid plus process start time. Both are required:
// Linux recycles pids, so a pid alone cannot tell a live writer from a
// dead one's orphan (#2957).
type tempWriterInstance struct {
	pid       uint32
	startTime uint64
}

// parseStateTempInstance parses the "<pid>_<starttime>.<seq>" middle of a
// "<dest>.<pid>_<starttime>.<seq>.tmp" temp name. It mirrors
// instance_from_temp_name in userspace-dp/src/state_writer.rs: the seq must
// be all digits, and the instance component exactly "<pid>_<starttime>"
// with both parts numeric and non-empty.
func parseStateTempInstance(middle string) (tempWriterInstance, bool) {
	dot := strings.LastIndex(middle, ".")
	if dot < 0 {
		return tempWriterInstance{}, false
	}
	seq, inst := middle[dot+1:], middle[:dot]
	if seq == "" || !isAllDigits(seq) {
		return tempWriterInstance{}, false
	}
	pidStr, startStr, ok := strings.Cut(inst, "_")
	if !ok || pidStr == "" || startStr == "" || !isAllDigits(pidStr) || !isAllDigits(startStr) {
		return tempWriterInstance{}, false
	}
	pid, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		return tempWriterInstance{}, false
	}
	start, err := strconv.ParseUint(startStr, 10, 64)
	if err != nil {
		return tempWriterInstance{}, false
	}
	return tempWriterInstance{pid: uint32(pid), startTime: start}, true
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isLegacyStateTempMiddle reports whether middle is the exact pre-#2957 temp
// shape "<pid>.<seq>" with both components all digits and non-empty. The
// steady-state sweeps (Rust and Go) deliberately reject this form — without
// a start time a bare pid cannot be PID-reuse disambiguated against a live
// writer — so only the reset/boot repair paths below, which run with no
// live writer by construction, treat it as a verified orphan.
func isLegacyStateTempMiddle(middle string) bool {
	pidStr, seq, ok := strings.Cut(middle, ".")
	if !ok || pidStr == "" || seq == "" || strings.Contains(seq, ".") {
		return false
	}
	return isAllDigits(pidStr) && isAllDigits(seq)
}

// procStartTime reads a process's start time (field 22 of /proc/<pid>/stat),
// mirroring real_proc_start_time. ok is false when the process is gone or
// /proc cannot be read.
func procStartTime(pid uint32) (start uint64, ok bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	// comm may itself contain ')'; the kernel guarantees the FINAL one ends it.
	idx := strings.LastIndex(string(data), ")")
	if idx < 0 {
		return 0, false
	}
	after := string(data)[idx+1:]
	fields := strings.Fields(after)
	// Fields after comm, 0-indexed: 0=state(3) ... 19=starttime(22).
	if len(fields) < 20 {
		return 0, false
	}
	start, err = strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, false
	}
	return start, true
}

// tempInstanceAlive reports whether a temp's writer instance is still live,
// mirroring instance_is_alive: our own full instance is always alive; any
// other pid must exist with a matching non-zero start time. Lookup failure
// means dead (same fail-open direction as the Rust sweep).
func tempInstanceAlive(inst tempWriterInstance) bool {
	self := uint32(os.Getpid())
	if selfStart, ok := procStartTime(self); ok && inst.pid == self && inst.startTime == selfStart {
		return true
	}
	now, ok := procStartTime(inst.pid)
	if !ok {
		return false
	}
	return now == inst.startTime && inst.startTime != 0
}

// ListStaleStateTemps censuses the state-writer temps for dest without
// removing anything, splitting them into dead-writer orphans and live
// writers' in-flight files. Backs both the sweep and post-sweep
// verification so the match rule has one definition.
func ListStaleStateTemps(dest string) (dead, live []string, err error) {
	return listStaleStateTemps(dest, false)
}

// ListStaleStateTempsIncludingLegacy censuses like ListStaleStateTemps but
// additionally classifies exact pre-#2957 "<dest>.<pid>.<seq>.tmp" siblings
// as dead. RESET/BOOT CONTEXTS ONLY: the steady-state Rust sweep rejects
// this shape because a bare pid cannot be disambiguated against a live
// writer, but the reset sweep runs after the helper is synchronously
// stopped and the boot repair runs before any helper starts, so no live
// writer exists and every exact-legacy sibling is a verified orphan from
// an upgrade-carried crash. An upgrade-carried crash orphan left under a
// custom persistent StateFile would otherwise survive the reset.
func ListStaleStateTempsIncludingLegacy(dest string) (dead, live []string, err error) {
	return listStaleStateTemps(dest, true)
}

func listStaleStateTemps(dest string, legacy bool) (dead, live []string, err error) {
	dir := filepath.Dir(dest)
	base := filepath.Base(dest)
	if base == "" || base == "." || base == string(filepath.Separator) {
		return nil, nil, fmt.Errorf("list state temps: invalid destination %q", dest)
	}
	prefix := base + "."
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		if os.IsNotExist(rerr) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("list state temps in %s: %w", dir, rerr)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".tmp") {
			continue
		}
		middle := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".tmp")
		full := filepath.Join(dir, name)
		if inst, ok := parseStateTempInstance(middle); ok {
			if tempInstanceAlive(inst) {
				live = append(live, full)
			} else {
				dead = append(dead, full)
			}
			continue
		}
		if legacy && isLegacyStateTempMiddle(middle) {
			dead = append(dead, full)
		}
	}
	return dead, live, nil
}

// SweepStaleStateTemps removes crash-orphaned state-writer temps for dest,
// mirroring sweep_stale_temps in userspace-dp/src/state_writer.rs: only
// dead-writer orphans are removed; live writers' in-flight temps are
// returned (never removed) so the caller can fail closed on genuine
// ambiguity.
func SweepStaleStateTemps(dest string) (live []string, err error) {
	dead, live, err := ListStaleStateTemps(dest)
	if err != nil {
		return nil, err
	}
	return live, removeStateTempDead(dead)
}

// SweepStaleStateTempsIncludingLegacy sweeps like SweepStaleStateTemps but
// also removes exact pre-#2957 legacy siblings. RESET/BOOT CONTEXTS ONLY
// (see ListStaleStateTempsIncludingLegacy): the reset and boot-repair
// sweeps run with no live writer, so legacy siblings are verified orphans.
func SweepStaleStateTempsIncludingLegacy(dest string) (live []string, err error) {
	dead, live, err := ListStaleStateTempsIncludingLegacy(dest)
	if err != nil {
		return nil, err
	}
	return live, removeStateTempDead(dead)
}

func removeStateTempDead(dead []string) error {
	var errs []error
	for _, full := range dead {
		if rerr := os.Remove(full); rerr != nil && !os.IsNotExist(rerr) {
			errs = append(errs, fmt.Errorf("sweep stale state temp %s: %w", full, rerr))
			continue
		}
		slog.Info("swept stale orphan helper state temp (dead writer instance)", "temp", full)
	}
	return errors.Join(errs...)
}
