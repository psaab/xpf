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

// SweepStaleStateTemps removes crash-orphaned state-writer temps for dest,
// mirroring sweep_stale_temps in userspace-dp/src/state_writer.rs: only
// siblings named "<dest>.<pid>_<starttime>.<seq>.tmp" whose writer instance
// is dead are removed; live writers' in-flight temps are returned (never
// removed) so the caller can fail closed on genuine ambiguity.
func SweepStaleStateTemps(dest string) (live []string, err error) {
	dir := filepath.Dir(dest)
	base := filepath.Base(dest)
	if base == "" || base == "." || base == string(filepath.Separator) {
		return nil, fmt.Errorf("sweep state temps: invalid destination %q", dest)
	}
	prefix := base + "."
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		if os.IsNotExist(rerr) {
			return nil, nil
		}
		return nil, fmt.Errorf("sweep state temps in %s: %w", dir, rerr)
	}
	var errs []error
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".tmp") {
			continue
		}
		inst, ok := parseStateTempInstance(strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".tmp"))
		if !ok {
			continue
		}
		full := filepath.Join(dir, name)
		if tempInstanceAlive(inst) {
			live = append(live, full)
			continue
		}
		if rerr := os.Remove(full); rerr != nil && !os.IsNotExist(rerr) {
			errs = append(errs, fmt.Errorf("sweep stale state temp %s: %w", full, rerr))
			continue
		}
		slog.Info("swept stale orphan helper state temp (dead writer instance)",
			"temp", full, "pid", inst.pid, "start_time", inst.startTime)
	}
	return live, errors.Join(errs...)
}
