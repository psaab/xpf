package config

import (
	"reflect"
	"strconv"
	"strings"
)

// EventPlantClassSuperuser is the reserved persisted attribution for a
// mutation made by a trusted root/system surface that has no login-class
// principal (uid 0, the daemon, or an in-process test). It is deliberately a
// concrete value rather than the empty string: empty means legacy metadata is
// absent and the event engine must quarantine the payload.
const EventPlantClassSuperuser = "super-user"

// EventPlantClassForMutation turns the authenticated surface answer into the
// value persisted beside a changed event-options payload. Empty class means
// the caller is the explicitly trusted superuser path; it is not legacy
// metadata and must never be confused with an omitted PlantClass field.
func EventPlantClassForMutation(class string) string {
	if strings.TrimSpace(class) == "" {
		return EventPlantClassSuperuser
	}
	return strings.TrimSpace(class)
}

// LoginClassExists reports whether class is present in the active login model.
// Built-in classes are resolved separately by ResolveClassPermissions.
func LoginClassExists(cfg *Config, class string) bool {
	if strings.TrimSpace(class) == "" {
		return false
	}
	if _, ok := ResolveClassPermissions(cfg, class); ok {
		return true
	}
	return false
}

// StampChangedEventPlantClasses binds the authenticated planting class to the
// effective event policy whose execution semantics changed in the candidate
// mutation. It compares compiled policies with PlantClass excluded, so edits
// to triggers, matchers, windows, and commands all rebind attribution. The
// raw-shape fallback covers apply-groups and otherwise uncompileable portions.
//
// before may be nil for a first mutation. The caller holds the config-store
// mutation lock, so the command and metadata update are one atomic candidate
// mutation. Legacy policies with unchanged execution semantics remain empty
// and are handled by the eventengine migration guard.
func StampChangedEventPlantClasses(before, after *ConfigTree, class string) {
	if after == nil {
		return
	}
	class = EventPlantClassForMutation(class)
	beforeCompiled := compiledEventPolicies9984(before)
	afterCompiled := compiledEventPolicies9984(after)
	changed := make(map[string]bool)
	if afterCompiled != nil {
		for name, afterPolicy := range afterCompiled {
			if afterPolicy == nil || len(afterPolicy.ThenCommands) == 0 {
				continue
			}
			beforePolicy := beforeCompiled[name]
			if beforePolicy == nil ||
				!eventPolicyExecutionEqual9984(beforePolicy, afterPolicy) {
				changed[name] = true
			}
		}
	}
	// Always union the raw-shape census. Group-specific or otherwise
	// uncompileable portions must not retain a stale marker merely because a
	// different policy already changed in the effective compiled view.
	beforeRaw := eventPolicyNodes9984(before)
	afterRaw := eventPolicyNodes9984(after)
	for name, afterNodes := range afterRaw {
		if !eventPolicyHasCommands9984(afterNodes) {
			continue
		}
		commandsChanged := eventPolicyCommandsSignature9984(beforeRaw[name]) !=
			eventPolicyCommandsSignature9984(afterNodes)
		beforeClass := eventPolicyPlantClass9984(beforeRaw[name])
		afterClass := eventPolicyPlantClass9984(afterNodes)
		executionChanged := changed[name] || commandsChanged
		if executionChanged {
			changed[name] = true
			continue
		}
		if beforeClass == afterClass {
			continue
		}
		if afterClass == "" || strings.Trim(beforeClass, "\x00") == "" {
			// Removing the marker or trying to add one to a legacy policy
			// must leave the payload unbound and quarantined at fire time.
			clearEventPlantClass9984(after, name)
			delete(changed, name)
			continue
		}
		// An already-attributed policy may be re-bound by an explicit
		// metadata edit, but it can never choose the value it writes: the
		// authenticated caller remains authoritative.
		changed[name] = true
	}
	for name := range changed {
		setEventPlantClass9984(after, name, class)
	}
}

func eventPolicyExecutionEqual9984(before, after *EventPolicy) bool {
	if before == nil || after == nil {
		return before == after
	}
	left := *before
	right := *after
	left.PlantClass = ""
	right.PlantClass = ""
	return reflect.DeepEqual(left, right)
}

func compiledEventPolicies9984(tree *ConfigTree) map[string]*EventPolicy {
	if tree == nil {
		return map[string]*EventPolicy{}
	}
	compiled, err := CompileConfigLenient(tree)
	if err != nil || compiled == nil {
		return nil
	}
	out := make(map[string]*EventPolicy, len(compiled.EventOptions))
	for _, policy := range compiled.EventOptions {
		if policy != nil {
			out[policy.Name] = policy
		}
	}
	return out
}

func eventPolicyNodes9984(tree *ConfigTree) map[string][]*Node {
	out := make(map[string][]*Node)
	if tree == nil {
		return out
	}
	var walk func([]*Node, bool)
	walk = func(nodes []*Node, inEventOptions bool) {
		for _, node := range nodes {
			if node == nil {
				continue
			}
			inSection := inEventOptions || node.Name() == "event-options"
			if inSection && node.Name() == "policy" && len(node.Keys) >= 2 {
				out[node.Keys[1]] = append(out[node.Keys[1]], node)
			}
			walk(node.Children, inSection)
		}
	}
	walk(tree.Children, false)
	return out
}

func eventPolicyHasCommands9984(policies []*Node) bool {
	for _, policy := range policies {
		if policy == nil {
			continue
		}
		if policy.Name() == "commands" && (len(policy.Keys) > 1 || len(policy.Children) > 0) {
			return true
		}
		if eventPolicyHasCommands9984(policy.Children) {
			return true
		}
	}
	return false
}

func eventPolicyCommandsSignature9984(policies []*Node) string {
	if len(policies) == 0 {
		return ""
	}
	var b strings.Builder
	for _, policy := range policies {
		if policy == nil {
			continue
		}
		writeNodeSignature9984(&b, policy)
	}
	return b.String()
}

func eventPolicyPlantClass9984(policies []*Node) string {
	var b strings.Builder
	for _, policy := range policies {
		if policy == nil {
			continue
		}
		for _, child := range policy.Children {
			if child != nil && child.Name() == "plant-class" {
				// Keep this reader byte-for-byte aligned with compileEventOptions:
				// nodeVal reads Keys[1] first, then the first child name.
				b.WriteString(nodeVal(child))
				b.WriteByte('\x00')
			}
		}
	}
	return b.String()
}

func writeBoolMaskSignature9984(b *strings.Builder, label string, mask []bool) {
	b.WriteString(label)
	if mask == nil {
		b.WriteString("nil;")
		return
	}
	b.WriteString(strconv.Itoa(len(mask)))
	b.WriteByte(':')
	for _, bit := range mask {
		if bit {
			b.WriteByte('1')
		} else {
			b.WriteByte('0')
		}
	}
	b.WriteByte(';')
}

func writeNodeSignature9984(b *strings.Builder, n *Node) {
	if n == nil || n.Name() == "plant-class" {
		return
	}
	b.WriteString(strings.Join(n.Keys, "\x00"))
	b.WriteByte('\x01')
	b.WriteString(strconv.FormatBool(n.Inactive))
	b.WriteByte('\x01')
	writeBoolMaskSignature9984(b, "quoted:", n.KeysQuoted)
	writeBoolMaskSignature9984(b, "bracketed:", n.KeysBracketed)
	for _, child := range n.Children {
		writeNodeSignature9984(b, child)
	}
	b.WriteByte('\x02')
}

func clearEventPlantClass9984(tree *ConfigTree, name string) {
	if tree == nil || name == "" {
		return
	}
	clearEventPlantClassNodes9984(eventPolicyNodes9984(tree)[name])
}

func clearEventPlantClassNodes9984(policies []*Node) {
	for _, policy := range policies {
		if policy == nil {
			continue
		}
		filtered := policy.Children[:0]
		for _, child := range policy.Children {
			if child == nil || child.Name() != "plant-class" {
				filtered = append(filtered, child)
			}
		}
		policy.Children = filtered
	}
}

func setEventPlantClass9984(tree *ConfigTree, name, class string) {
	if tree == nil || name == "" {
		return
	}
	policies := eventPolicyNodes9984(tree)[name]
	for _, policy := range policies {
		if policy == nil {
			continue
		}
		filtered := policy.Children[:0]
		for _, child := range policy.Children {
			if child == nil || child.Name() != "plant-class" {
				filtered = append(filtered, child)
			}
		}
		policy.Children = append(filtered, &Node{Keys: []string{"plant-class", class}, IsLeaf: true})
	}
	if len(policies) > 0 {
		return
	}
	var eventOptions *Node
	for _, node := range tree.Children {
		if node != nil && node.Name() == "event-options" {
			eventOptions = node
			break
		}
	}
	if eventOptions == nil {
		eventOptions = &Node{Keys: []string{"event-options"}}
		tree.Children = append(tree.Children, eventOptions)
	}
	var policy *Node
	for _, node := range eventOptions.Children {
		if node != nil && node.Name() == "policy" && len(node.Keys) > 1 && node.Keys[1] == name {
			policy = node
			break
		}
	}
	if policy == nil {
		policy = &Node{Keys: []string{"policy", name}}
		eventOptions.Children = append(eventOptions.Children, policy)
	}
	policy.Children = append(policy.Children, &Node{Keys: []string{"plant-class", class}, IsLeaf: true})
}

// QuarantineUntrustedEventPlantClasses clears super-user attribution from
// untrusted synchronized event policies. It leaves commands intact but removes
// their fire-time authority; the engine then quarantines the empty marker.
func QuarantineUntrustedEventPlantClasses(tree *ConfigTree) {
	for _, policies := range eventPolicyNodes9984(tree) {
		if !eventPolicyHasCommands9984(policies) {
			continue
		}
		hasSuperuserMarker := false
		for _, policy := range policies {
			if policy == nil {
				continue
			}
			for _, child := range policy.Children {
				if child != nil && child.Name() == "plant-class" &&
					nodeVal(child) == EventPlantClassSuperuser {
					hasSuperuserMarker = true
					break
				}
			}
			if hasSuperuserMarker {
				break
			}
		}
		if hasSuperuserMarker {
			clearEventPlantClassNodes9984(policies)
		}
	}
}
