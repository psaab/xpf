package userspace

import (
	"log/slog"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9698: the helper-status binding-index bounds. They live in their own file
// so maps_sync.go stays under the 2000-LOC [REFACTOR] floor
// (docs/engineering-style.md, "Modularity discipline").

// bindingIfindexInRange reports whether a helper-reported ifindex can be used
// as the ifindex dimension of the composed userspace_bindings index (#9698).
//
// The index is uint32(ifindex)*bindingQueuesPerIface + queue. The ifindex is
// helper-supplied and unbounded above. With a stride of 16, an ifindex of 2^28
// or more wraps the uint32 product, and an ifindex of 2^32 or more truncates
// in the uint32 conversion. Either way the wrapped index lands INSIDE the
// dense cap, so the #814 cap check after the multiply passes, and the row
// written (or repaired) belongs to a different (ifindex, queue).
//
// The queue (#4894) and slot (#7497) dimensions have explicit bounds because
// helper numbers are not trusted; this is the ifindex dimension's bound. The
// comparison is done in int64, so neither the wrap nor the truncation can
// defeat it.
func bindingIfindexInRange(ifindex int) bool {
	return ifindex > 0 && int64(ifindex) < int64(dataplane.MaxInterfaces)
}

// watchdogBindingIndex is the bindings watchdog's per-binding decision: the
// composed index to check and repair, or ok=false to skip. It is repair-only
// and logs and skips, never unwinds. It is split out of verifyBindingsMapLocked
// so the decision is testable without BPF maps, which the watchdog's own cell
// needs and an unprivileged `make test` cannot create.
func watchdogBindingIndex(binding BindingStatus, deadWorkers map[uint32]bool) (uint32, bool) {
	if binding.Ifindex <= 0 {
		return 0, false
	}
	// #1666: only repair (re-assert READY for) slots whose worker is
	// actually forwarding-live. Repairing on (Registered && Armed)
	// would let the watchdog fight the crash-clear by rewriting
	// READY=1 for a dead worker.
	if !bindingForwardingLive(binding, deadWorkers) {
		return 0, false
	}
	// Queue-dimension bound guard (#4894): repair-only, log-and-skip
	// (never unwind). A queue-id at/above the stride would alias the
	// adjacent ifindex queue-0 slot; the dense-cap guard below cannot
	// catch that, so skip the binding instead of repairing a wrong slot.
	if binding.QueueID >= bindingQueuesPerIface {
		slog.Warn("userspace: bindings watchdog: queue-id at/above stride would alias adjacent ifindex queue-0 slot, skipping (#4894)",
			"ifindex", binding.Ifindex, "queue", binding.QueueID,
			"stride", uint32(bindingQueuesPerIface))
		return 0, false
	}
	// Ifindex-dimension bound (#9698), BEFORE the multiply it protects.
	if !bindingIfindexInRange(binding.Ifindex) {
		slog.Warn("userspace: bindings watchdog: ifindex exceeds cap MaxInterfaces and would wrap the composed index onto another row, skipping (#9698)",
			"ifindex", binding.Ifindex, "queue", binding.QueueID,
			"max_interfaces", dataplane.MaxInterfaces)
		return 0, false
	}
	idx := uint32(binding.Ifindex)*bindingQueuesPerIface + binding.QueueID
	// Call-site cap guard (#814): the watchdog is repair-only and
	// must not unwind. Log and skip if the ifindex would overflow
	// the BindingArrayMaxEntries dense cap.
	if idx >= dataplane.BindingArrayMaxEntries {
		slog.Warn("userspace: bindings watchdog: ifindex exceeds BindingArrayMaxEntries cap, skipping",
			"ifindex", binding.Ifindex, "queue", binding.QueueID,
			"idx", idx, "cap", dataplane.BindingArrayMaxEntries)
		return 0, false
	}
	return idx, true
}
