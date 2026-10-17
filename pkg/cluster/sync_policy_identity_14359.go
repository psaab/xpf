package cluster

// policyIdentityMemo preserves one session incarnation's admitting-policy
// identity (#14359): PolicyRuleID (#11070, the stable "<from>-><to>/<name>"
// string) and PolicyCounterIdx (#3301, the 1-based per-rule hit-counter
// handle). Both are sync-only — the BPF conntrack mirror has no slot for
// either (bpfSessionValue drops them exactly as it drops InstallTableDomain)
// — so a mirror-sourced sweep/bulk resend arrives with ""/0. Without this
// memo the standby's copy loses its per-policy hit-counter binding within
// one sweep cycle: the Rust import deliberately binds policy_counter None
// when policy_rule_id is empty (no fallback to the positional index), and
// purge_sessions_bound_to_deleted_first_policy identifies sessions admitted
// by the first compiled policy (policy_id == 0, indistinguishable from
// unattributed) exclusively via that counter's rule_id — a wiped session
// therefore also escapes the deleted-first-policy purge after failover.
type policyIdentityMemo struct {
	sessionID uint64
	ruleID    string
	counter   uint32
}

// stampPolicyIdentityLocked records a stated policy identity or restores it
// when a mirror-sourced resend has lost the sync-only fields. The caller
// holds the corresponding sender/receiver generation mutex. Returns false
// when a new identity cannot be recorded at the current cap.
//
// Discipline (mirrors stampSourceNatICMPLocked / stampInstallTableLocked):
//   - Records are keyed per tuple and matched on SessionID, the helper's
//     stable per-incarnation id. A reused tuple carries a new id and never
//     inherits the old incarnation's binding, in any arrival order.
//   - SessionID 0 means "no identity": nothing is recorded or applied, which
//     fails toward ""/0 (the pre-#14359 window), never toward a wrong rule.
//   - Either field stating a value records BOTH as stated: a frame that
//     names a different rule than the memo (policy re-compilation between
//     sends, or a corrected binding) wins over the record. Only a frame
//     stating neither field (""/0 — the mirror loss signature, or a legacy
//     peer that predates both fields) is restored from the record, and only
//     when the record actually holds an identity.
func stampPolicyIdentityLocked[K comparable](m map[K]policyIdentityMemo, key K, sessionID uint64, ruleID *string, counter *uint32, maxEntries int) bool {
	if sessionID == 0 {
		return true
	}
	rec, ok := m[key]
	if ok && rec.sessionID != sessionID {
		delete(m, key)
		ok = false
	}
	if *ruleID == "" && *counter == 0 {
		if ok && (rec.ruleID != "" || rec.counter != 0) {
			*ruleID, *counter = rec.ruleID, rec.counter
		}
		if *ruleID == "" && *counter == 0 {
			return true
		}
		// Restored from the record: it is already the memo content.
		return true
	}
	if !ok && len(m) >= maxEntries {
		return false
	}
	m[key] = policyIdentityMemo{sessionID: sessionID, ruleID: *ruleID, counter: *counter}
	return true
}

func lookupPolicyIdentityLocked[K comparable](m map[K]policyIdentityMemo, key K, sessionID uint64) (string, uint32, bool) {
	if sessionID == 0 {
		return "", 0, false
	}
	rec, ok := m[key]
	if !ok || rec.sessionID != sessionID || (rec.ruleID == "" && rec.counter == 0) {
		return "", 0, false
	}
	return rec.ruleID, rec.counter, true
}
