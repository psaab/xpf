package userspace

import (
	"errors"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func buildPolicyRuleCounterIndex(status *ProcessStatus) map[string]PolicyRuleCounterStatus {
	index := make(map[string]PolicyRuleCounterStatus)
	if status == nil {
		return index
	}
	for _, counter := range status.PolicyRuleCounters {
		if counter.RuleID == "" {
			continue
		}
		index[counter.RuleID] = counter
	}
	return index
}

func policyRuleIDForCounter(cfg *config.Config, policyID uint32) string {
	if cfg == nil {
		return ""
	}
	policySetID := policyID / dataplane.MaxRulesPerPolicy
	ruleIndex := policyID % dataplane.MaxRulesPerPolicy

	var currentSet uint32
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		if currentSet == policySetID {
			if int(ruleIndex) >= len(zpp.Policies) || zpp.Policies[ruleIndex] == nil {
				return ""
			}
			return stablePolicyRuleID(zpp.FromZone, zpp.ToZone, zpp.Policies[ruleIndex].Name)
		}
		currentSet++
	}
	if currentSet == policySetID {
		if int(ruleIndex) >= len(cfg.Security.GlobalPolicies) || cfg.Security.GlobalPolicies[ruleIndex] == nil {
			return ""
		}
		return stablePolicyRuleID("junos-global", "junos-global", cfg.Security.GlobalPolicies[ruleIndex].Name)
	}
	return ""
}

func (m *Manager) ReadPolicyCounters(policyID uint32) (dataplane.CounterValue, error) {
	// The public DataPlane API is still indexed by legacy policy ID, while the
	// userspace helper reports counters by stable policy identity. Keep the
	// translation config-derived so scheduled-rule counters survive delete/re-add
	// and app-term slot expansion without callers recomputing Rust map slots.
	var total dataplane.CounterValue
	var innerErr error
	if m.inner != nil {
		total, innerErr = m.inner.ReadPolicyCounters(policyID)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	cfg := (*config.Config)(nil)
	if m.lastSnapshot != nil {
		cfg = m.lastSnapshot.Config
	}
	ruleID := policyRuleIDForCounter(cfg, policyID)
	if ruleID == "" {
		if innerErr != nil {
			return dataplane.CounterValue{}, innerErr
		}
		return total, nil
	}
	counter, ok := buildPolicyRuleCounterIndex(&m.lastStatus)[ruleID]
	if !ok {
		if innerErr != nil {
			return dataplane.CounterValue{}, innerErr
		}
		return total, nil
	}
	total.Packets += counter.Packets
	total.Bytes += counter.Bytes
	return total, nil
}

func (m *Manager) ClearPolicyCounters() error {
	var errs []error
	if m.inner != nil {
		if err := m.inner.ClearPolicyCounters(); err != nil {
			errs = append(errs, err)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.clearHelperPolicyCountersLocked(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (m *Manager) ClearAllCounters() error {
	var errs []error
	if m.inner != nil {
		if err := m.inner.ClearAllCounters(); err != nil {
			errs = append(errs, err)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.clearHelperPolicyCountersLocked(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (m *Manager) clearHelperPolicyCountersLocked() error {
	if m.proc == nil || m.proc.Process == nil {
		for i := range m.lastStatus.PolicyRuleCounters {
			m.lastStatus.PolicyRuleCounters[i].Packets = 0
			m.lastStatus.PolicyRuleCounters[i].Bytes = 0
		}
		return nil
	}

	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "clear_policy_counters"}, &status); err != nil {
		return err
	}
	m.recordHelperStatusLocked(&status)
	return nil
}
