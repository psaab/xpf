package configstore

import (
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #9615: a commit-confirmed window re-armed at boot (recoverPendingConfirmLocked)
// never passed the #6707/#9588 rollback-target pre-flight, which runs in the
// daemon only when a window is armed in-process. These accessors let the daemon
// check the target before the timer's rollback promotes anything, and tell the
// operator when a recovered target is one this build's dataplane refuses.

// PendingRollbackTarget returns the compiled rollback target of the pending
// window armed with gen WITHOUT promoting it. ok is false when gen is stale or
// no window is pending. first reports the never-committed first-commit target,
// whose compiled config is nil by design.
func (s *Store) PendingRollbackTarget(gen uint64) (target *config.Config, first bool, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if gen != s.confirmGen || s.confirmPrevTree == nil {
		return nil, false, false
	}
	return s.confirmPrevCfg, s.confirmPrevFirst, true
}

// DeferConfirmTimer re-arms the pending window armed with gen to fire again
// after delay, keeping gen, so the rollback can wait for a transient condition
// (a dynamic-address feed that is not ready yet) without promoting anything.
// It returns false, and changes nothing, when gen is stale or no window is
// pending.
func (s *Store) DeferConfirmTimer(gen uint64, delay time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if gen != s.confirmGen || s.confirmPrevTree == nil || s.confirmTimer == nil {
		return false
	}
	s.confirmTimer.Stop()
	s.confirmTimer = time.AfterFunc(delay, func() {
		s.fireConfirmTimer(gen)
	})
	return true
}

// RecoveredConfirmWindow reports a pending window that Load re-armed from
// confirm.json, with its rollback target and deadline. ok is false for a window
// armed in this process (the daemon pre-flighted that one before arming) and
// when nothing is pending.
func (s *Store) RecoveredConfirmWindow() (target *config.Config, first bool, deadline time.Time, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.confirmRecovered || s.confirmTimer == nil || s.confirmPrevTree == nil {
		return nil, false, time.Time{}, false
	}
	return s.confirmPrevCfg, s.confirmPrevFirst, s.confirmDeadline, true
}

// NoteConfirmTargetAlarm records an operator-visible alarm about the pending
// window's rollback target: a journal entry, and the text ConfirmAlarm returns
// for the CLI's pending-window line. It is cleared with the window.
func (s *Store) NoteConfirmTargetAlarm(detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.confirmTimer == nil {
		return
	}
	s.confirmAlarm = detail
	s.journalLog(&JournalEntry{
		Action:     "confirm_rollback_target_refused",
		Detail:     detail,
		ConfigHash: journalConfigHash(s.active),
	})
}

// ConfirmAlarm returns the pending window's rollback-target alarm, or "".
func (s *Store) ConfirmAlarm() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.confirmTimer == nil {
		return ""
	}
	return s.confirmAlarm
}
