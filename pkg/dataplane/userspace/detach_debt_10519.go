package userspace

import (
	"log/slog"

	"github.com/psaab/xpf/pkg/dataplane"
)

// noteDetachDebtLocked is the userspace-side observability latch for #10519.
// Caller holds m.mu, just as noteLocalAddressCapacityLocked does. A failed
// post-acceptance reconciliation is not returned as a second apply failure:
// the new snapshot is already the retained authority, and the next compile is
// the existing retry path. The latch and ApplyResult field make the partial
// host outcome visible while dataplane.Manager's debt set keeps the fence
// fail-closed.
func (m *Manager) noteDetachDebtLocked(result *dataplane.CompileResult, err error) {
	if err != nil {
		if msg := err.Error(); msg != m.detachDebtAlarm {
			slog.Error("userspace: obsolete attachment reconciliation failed; transit fence omits detach-debt interfaces",
				"err", err, "ifindexes", resultDetachErrors(result), "issue", "#10519")
			m.detachDebtAlarm = msg
		}
		return
	}
	if m.bpfShim != nil && len(m.bpfShim.ReconcileDetachDebt(nil)) != 0 {
		// A pass with no new error does not prove prior debt recovered. Keep the
		// alarm latched until both the reconciliation result and debt census are
		// clean.
		return
	}
	if m.detachDebtAlarm != "" {
		slog.Info("userspace: obsolete attachment reconciliation recovered; transit fence may restore recovered interfaces",
			"issue", "#10519")
		m.detachDebtAlarm = ""
	}
}

func resultDetachErrors(result *dataplane.CompileResult) []int {
	if result == nil {
		return nil
	}
	return result.DetachedWithErrors
}
