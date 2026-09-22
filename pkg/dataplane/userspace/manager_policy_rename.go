package userspace

// SetPolicyRenameAncestry stages the provenance and pre-publication verdicts
// for the next full snapshot build. The daemon calls this while holding its
// apply semaphore; Manager copies both slices so a failed apply can safely
// leave its input available for a retry.
func (m *Manager) SetPolicyRenameAncestry(
	ancestry []PolicyRenameAncestry,
	rebinds []PolicySessionRebind,
) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.policyRenameAncestry = append([]PolicyRenameAncestry(nil), ancestry...)
	m.policySessionRebinds = append([]PolicySessionRebind(nil), rebinds...)
	m.mu.Unlock()
}
