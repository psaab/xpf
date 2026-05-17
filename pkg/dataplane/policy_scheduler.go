package dataplane

import (
	"fmt"

	"github.com/psaab/xpf/pkg/config"
)

type ScheduledPolicyRuleSlot struct {
	PolicyName      string
	SchedulerName   string
	AbsoluteRuleIdx uint32
}

func BuildScheduledPolicyRuleSlots(cfg *config.Config) ([]ScheduledPolicyRuleSlot, error) {
	if cfg == nil {
		return nil, nil
	}

	var slots []ScheduledPolicyRuleSlot
	policySetID := uint32(0)

	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			policySetID++
			continue
		}
		setSlots, err := scheduledPolicyRuleSlotsForPolicies(policySetID, zpp.Policies, cfg)
		if err != nil {
			return nil, err
		}
		slots = append(slots, setSlots...)
		policySetID++
	}

	if len(cfg.Security.GlobalPolicies) > 0 {
		setSlots, err := scheduledPolicyRuleSlotsForPolicies(policySetID, cfg.Security.GlobalPolicies, cfg)
		if err != nil {
			return nil, err
		}
		slots = append(slots, setSlots...)
	}

	return slots, nil
}

func scheduledPolicyRuleSlotsForPolicies(policySetID uint32, policies []*config.Policy, cfg *config.Config) ([]ScheduledPolicyRuleSlot, error) {
	var (
		slots []ScheduledPolicyRuleSlot
		seq   uint32
	)

	for _, pol := range policies {
		if pol == nil {
			continue
		}
		ruleCount, err := expandedPolicyRuleCount(cfg, pol)
		if err != nil {
			return nil, err
		}
		if pol.SchedulerName == "" {
			seq += ruleCount
			continue
		}
		for i := uint32(0); i < ruleCount; i++ {
			slots = append(slots, ScheduledPolicyRuleSlot{
				PolicyName:      pol.Name,
				SchedulerName:   pol.SchedulerName,
				AbsoluteRuleIdx: policySetID*MaxRulesPerPolicy + seq + i,
			})
		}
		seq += ruleCount
	}

	return slots, nil
}

func expandedPolicyRuleCount(cfg *config.Config, pol *config.Policy) (uint32, error) {
	hasAny := false
	for _, appName := range pol.Match.Applications {
		if appName == "any" {
			hasAny = true
			break
		}
	}
	if hasAny || len(pol.Match.Applications) == 0 {
		return 1, nil
	}

	seen := make(map[string]struct{})
	count := uint32(0)
	for _, appName := range pol.Match.Applications {
		if appName == "" {
			continue
		}
		if _, isSet := cfg.Applications.ApplicationSets[appName]; isSet {
			expanded, err := config.ExpandApplicationSet(appName, &cfg.Applications)
			if err != nil {
				return 0, fmt.Errorf("policy %q expand app-set %q: %w", pol.Name, appName, err)
			}
			for _, expandedApp := range expanded {
				if expandedApp == "" {
					continue
				}
				if _, ok := seen[expandedApp]; ok {
					continue
				}
				seen[expandedApp] = struct{}{}
				count++
			}
			continue
		}
		if _, ok := seen[appName]; ok {
			continue
		}
		seen[appName] = struct{}{}
		count++
	}
	if count == 0 {
		return 1, nil
	}
	return count, nil
}
