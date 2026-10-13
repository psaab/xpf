package config

import (
	"errors"
	"fmt"
	"strings"
)

type unknownSecurityPoliciesChildSchemaError12217 struct {
	path    string
	keyword string
	content string
}

func (e *unknownSecurityPoliciesChildSchemaError12217) Error() string {
	return fmt.Sprintf("%s: child %q content %q does not match the known non-enforcement grammar under the closed-world subtree",
		e.path, e.keyword, e.content)
}

// IsUnknownSecurityPoliciesChildSchemaError12217 reports a strict closed-world
// rejection for a direct child of `security policies`, so tolerant Store
// ingestion can identify the diagnostic instead of logging it as a typed leaf.
func IsUnknownSecurityPoliciesChildSchemaError12217(err error) bool {
	var target *unknownSecurityPoliciesChildSchemaError12217
	return errors.As(err, &target)
}

func securityPoliciesSchema12217() *schemaNode {
	if schemaSecurity == nil {
		return nil
	}
	return schemaSecurity.children["policies"]
}

// Known non-enforcement statements are exempted by content, not keyword. Leaf
// values may be written packed, bracketed, or in blocks; enforcement-bearing
// content is never exempted.
func validPolicyTraceFileTail12819(keys []string, from int) bool {
	for i := from; i < len(keys); {
		if i+1 >= len(keys) || keys[i+1] == "" {
			return false
		}
		switch keys[i] {
		case "size", "files":
			i += 2
		default:
			return false
		}
	}
	return true
}

func validPolicyTraceFlags12819(values []string) bool {
	for _, flag := range values {
		if flag != "" && flag != "all" && !flowTraceImplementedFlags[flag] {
			return false
		}
	}
	return true
}

func validPolicyTraceFlagNode12819(node *Node) bool {
	if node == nil || node.Name() != "flag" || !validPolicyTraceFlags12819(node.Keys[1:]) {
		return false
	}
	for _, flag := range node.Children {
		if flag == nil || len(flag.Children) != 0 || !validPolicyTraceFlags12819(flag.Keys) {
			return false
		}
	}
	return len(node.Keys) > 1 || len(node.Children) > 0
}

func validPolicyTraceFileNode12819(node *Node) bool {
	if node == nil || node.Name() != "file" || len(node.Keys) < 2 || node.Keys[1] == "" ||
		!validPolicyTraceFileTail12819(node.Keys, 2) {
		return false
	}
	for _, option := range node.Children {
		if option == nil || len(option.Children) != 0 || !validPolicyTraceFileTail12819(option.Keys, 0) {
			return false
		}
	}
	return true
}

func validPolicyTraceOptions12819(keys []string, children []*Node) bool {
	if len(keys) > 1 {
		packed := &Node{Keys: keys[1:]}
		switch packed.Name() {
		case "flag":
			return validPolicyTraceFlagNode12819(packed) && len(children) == 0
		case "file":
			return validPolicyTraceFileNode12819(packed) && len(children) == 0
		case "packet-filter":
			return validPolicyTracePacketFilterNode12819(packed) && len(children) == 0
		case "no-remote-trace":
			return len(packed.Keys) == 1 && len(children) == 0
		default:
			return false
		}
	}
	for _, option := range children {
		if option == nil {
			return false
		}
		switch option.Name() {
		case "file":
			if !validPolicyTraceFileNode12819(option) {
				return false
			}
		case "flag":
			if !validPolicyTraceFlagNode12819(option) {
				return false
			}
		case "packet-filter":
			if !validPolicyTracePacketFilterNode12819(option) {
				return false
			}
		case "no-remote-trace":
			if len(option.Keys) != 1 || len(option.Children) != 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validPolicyTracePacketFilterNode12819(node *Node) bool {
	if node == nil || node.Name() != "packet-filter" || len(node.Keys) < 2 || node.Keys[1] == "" {
		return false
	}
	validLeaf := func(name string) bool {
		switch name {
		case "source-prefix", "destination-prefix", "protocol":
			return true
		default:
			return false
		}
	}
	if len(node.Keys) > 2 {
		if (len(node.Keys)-2)%2 != 0 {
			return false
		}
		for i := 2; i < len(node.Keys); i += 2 {
			if !validLeaf(node.Keys[i]) || node.Keys[i+1] == "" {
				return false
			}
		}
	}
	for _, leaf := range node.Children {
		if leaf == nil || len(leaf.Keys) != 2 || leaf.Keys[1] == "" ||
			len(leaf.Children) != 0 || !validLeaf(leaf.Name()) {
			return false
		}
	}
	return len(node.Keys) > 2 || len(node.Children) > 0
}

func validPolicyLogModes12819(keys []string, children []*Node) bool {
	valid := func(mode string) bool { return mode == "session-init" || mode == "session-close" }
	for _, mode := range keys {
		if !valid(mode) {
			return false
		}
	}
	for _, mode := range children {
		if mode == nil || len(mode.Children) != 0 {
			return false
		}
		for _, value := range mode.Keys {
			if !valid(value) {
				return false
			}
		}
	}
	return len(keys) > 0 || len(children) > 0
}

func nonEnforcementSecurityPoliciesChild12628(child *Node) bool {
	if child == nil || len(child.Keys) == 0 {
		return false
	}
	switch child.Name() {
	case "traceoptions":
		return validPolicyTraceOptions12819(child.Keys, child.Children)
	case "policy-stats":
		if len(child.Keys) > 1 {
			return len(child.Keys) == 3 && child.Keys[1] == "system-wide" &&
				child.Keys[2] == "enable" && len(child.Children) == 0
		}
		for _, option := range child.Children {
			if option == nil || option.Name() != "system-wide" || len(option.Keys) != 2 ||
				option.Keys[1] != "enable" || len(option.Children) != 0 {
				return false
			}
		}
		return true
	case "pre-id-default-policy":
		if len(child.Keys) > 1 {
			return len(child.Keys) >= 4 && child.Keys[1] == "then" && child.Keys[2] == "log" &&
				validPolicyLogModes12819(child.Keys[3:], nil) && len(child.Children) == 0
		}
		for _, action := range child.Children {
			if action == nil || action.Name() != "then" {
				return false
			}
			if len(action.Keys) > 1 {
				if len(action.Keys) < 3 || action.Keys[1] != "log" ||
					!validPolicyLogModes12819(action.Keys[2:], nil) || len(action.Children) != 0 {
					return false
				}
				continue
			}
			for _, option := range action.Children {
				if option == nil || option.Name() != "log" ||
					!validPolicyLogModes12819(option.Keys[1:], option.Children) {
					return false
				}
			}
		}
		return true
	default:
		return false
	}
}

func enforcementSecurityPoliciesChildren12217(sec *SecurityConfig) []string {
	if sec == nil || len(sec.EnforcementPoliciesChildren) == 0 {
		return nil
	}
	return sec.EnforcementPoliciesChildren
}

func securityPoliciesChildContentShape12819(node *Node) string {
	if node == nil || node.Name() == "" {
		return "empty subtree"
	}
	parts := []string{node.Name()}
	for _, key := range node.Keys[1:] {
		switch key {
		case "policy", "from-zone", "to-zone", "global", "default-policy", "then",
			"deny", "permit", "reject", "accept", "log", "match", "flag", "file",
			"packet-filter", "source-prefix", "destination-prefix", "protocol",
			"system-wide", "frobnicate":
			parts = append(parts, key)
		}
	}
	for _, child := range node.Children {
		parts = append(parts, securityPoliciesChildContentShape12819(child))
	}
	return strings.Join(parts, "/")
}

func recordEnforcementSecurityPoliciesChild12819(sec *SecurityConfig, keyword, content string) {
	if sec == nil || keyword == "" {
		return
	}
	for _, existing := range sec.EnforcementPoliciesChildren {
		if existing == keyword {
			return
		}
	}
	sec.EnforcementPoliciesChildren = append(sec.EnforcementPoliciesChildren, keyword)
	sec.EnforcementPoliciesContent = append(sec.EnforcementPoliciesContent, content)
}

func recordUnknownSecurityPoliciesChild12217(sec *SecurityConfig, keyword string) {
	if sec == nil || keyword == "" || isApplyStatementKeyword(keyword) {
		return
	}
	for _, existing := range sec.UnknownPoliciesChildren {
		if existing == keyword {
			return
		}
	}
	sec.UnknownPoliciesChildren = append(sec.UnknownPoliciesChildren, keyword)
}

func enforcementSecurityPoliciesContent12819(sec *SecurityConfig, keyword string) string {
	if sec != nil {
		for i, child := range sec.EnforcementPoliciesChildren {
			if child == keyword && i < len(sec.EnforcementPoliciesContent) {
				return sec.EnforcementPoliciesContent[i]
			}
		}
	}
	return keyword + " subtree"
}

func validateUnknownSecurityPoliciesChild12217(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	children := enforcementSecurityPoliciesChildren12217(&cfg.Security)
	if len(children) == 0 {
		return nil
	}
	return fmt.Errorf("security policies: child %q has rejected content shape %q (outside the known non-enforcement grammar) and would be silently dropped",
		children[0], enforcementSecurityPoliciesContent12819(&cfg.Security, children[0]))
}

func hasSecurityPoliciesChild12819(children []string, keyword string) bool {
	for _, child := range children {
		if child == keyword {
			return true
		}
	}
	return false
}

func toleratedUnknownSecurityPoliciesChildWarnings12217(cfg *Config) []string {
	if cfg == nil || len(cfg.Security.UnknownPoliciesChildren) == 0 {
		return nil
	}
	warnings := make([]string, 0, len(cfg.Security.UnknownPoliciesChildren))
	for _, keyword := range cfg.Security.UnknownPoliciesChildren {
		if !hasSecurityPoliciesChild12819(cfg.Security.EnforcementPoliciesChildren, keyword) {
			warnings = append(warnings, fmt.Sprintf(
				"security policies: Junos-valid non-enforcement child %q is accepted but not consumed by the policy compiler (issue #12628)", keyword))
			continue
		}
		warnings = append(warnings, fmt.Sprintf(
			"security policies: child %q has rejected content shape %q; the incomplete rulebase is quarantined and the userspace policy snapshot is refused (tolerant path; strict commit rejects this; issue #12217)",
			keyword, enforcementSecurityPoliciesContent12819(&cfg.Security, keyword)))
	}
	return warnings
}
