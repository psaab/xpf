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
	// #16722: cheap raw gate. When neither tree carries a change-configuration
	// commands payload, no policy can gain, lose, or rebind commands, so the
	// two full lenient compiles below would compare empty policies and the
	// raw census would find no commands — a provable no-op. The gate scans
	// only the event-policy subtrees (including `groups { ... event-options
	// ... }` bodies, where apply-groups can materialise an effective policy)
	// and requires a real commands payload (tail values or children), never
	// a bare keyword mention. A policy-local `apply-groups` can also
	// materialise commands from an arbitrary group body, so its presence
	// forces the full path as well.
	if !treeMayHaveEventCommands9984(before) && !treeMayHaveEventCommands9984(after) {
		return
	}
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

// treeMayHaveEventCommands9984 reports whether tree carries, anywhere an
// event policy can live, a `then change-configuration commands` payload
// with at least one value (the same payload test eventPolicyHasCommands9984
// applies inside a policy), or a policy-local `apply-groups` /
// `apply-groups-except` that could materialise / suppress such a payload
// from a group body. It descends only into event-options subtrees, group
// definition bodies (`groups { <name> { ... } }` — the group name is one
// level below `groups`), and group-body subtrees, so an unrelated stanza
// (a firewall `then`, a description mentioning "commands") never trips
// it; a stanza outside those scopes cannot compile into an EventPolicy.
// #16722 gate helper.
func treeMayHaveEventCommands9984(tree *ConfigTree) bool {
	if tree == nil {
		return false
	}
	return nodesMayHaveEventCommands9984(tree.Children, 0)
}

// scopedNodesMayHaveEventCommands9984 walks top-level / group-body nodes
// that may contain a scoping stanza.
func nodesMayHaveEventCommands9984(nodes []*Node, depth int) bool {
	for _, node := range nodes {
		if node == nil {
			continue
		}
		switch node.Name() {
		case "event-options":
			if eventOptionsMayHaveEventCommands9984(node) {
				return true
			}
		case "groups":
			for _, body := range node.Children {
				if body != nil && nodesMayHaveEventCommands9984(body.Children, depth+1) {
					return true
				}
			}
		default:
			if depth > 0 && nodesMayHaveEventCommands9984(node.Children, depth) {
				return true
			}
		}
	}
	return false
}

func eventOptionsMayHaveEventCommands9984(node *Node) bool {
	if inst, ok := compactEventOptionsPolicyInstance9984(node, nil); ok &&
		policyMayHaveEventCommands9984(inst.node) {
		return true
	}
	if len(node.Keys) == 2 && node.Keys[1] == "policy" {
		for _, child := range node.Children {
			if inst, ok := compactEventOptionsPolicyInstance9984(node, child); ok &&
				policyMayHaveEventCommands9984(inst.node) {
				return true
			}
		}
	}
	for _, child := range node.Children {
		if child == nil || child.Name() != "policy" {
			continue
		}
		for _, inst := range namedInstances([]*Node{child}) {
			if inst.node != nil && policyMayHaveEventCommands9984(inst.node) {
				return true
			}
		}
	}
	return false
}

type eventPolicyInstance9984 struct {
	name string
	node *Node
}

// compactEventOptionsPolicyInstance9984 resolves the packed raw spellings
// `event-options policy p ...` and `event-options policy { p { ... } }`.
// For the one-key container, a named instance may itself be named after a
// policy keyword, so its body structure—not its name—distinguishes it from
// an elided-name policy body.
func compactEventOptionsPolicyInstance9984(container, child *Node) (eventPolicyInstance9984, bool) {
	if container == nil || container.Name() != "event-options" ||
		len(container.Keys) < 2 || container.Keys[1] != "policy" {
		return eventPolicyInstance9984{}, false
	}
	if len(container.Keys) >= 3 {
		if container.Keys[2] == "" {
			return eventPolicyInstance9984{}, false
		}
		return eventPolicyInstance9984{name: container.Keys[2], node: container}, true
	}
	if len(container.Keys) != 2 || child == nil || child.Name() == "" ||
		!eventPolicyInstanceHasPropertyChildren9984(child) {
		return eventPolicyInstance9984{}, false
	}
	return eventPolicyInstance9984{name: child.Name(), node: child}, true
}

func eventPolicyInstanceHasPropertyChildren9984(instance *Node) bool {
	if instance == nil {
		return false
	}
	policySchema := schemaEventOptions.children["policy"]
	for _, child := range instance.Children {
		if child == nil {
			continue
		}
		if child.Name() == "apply-groups" || child.Name() == "apply-groups-except" {
			return true
		}
		if policySchema != nil && policySchema.children[child.Name()] != nil {
			return true
		}
	}
	return false
}

func policyMayHaveEventCommands9984(policy *Node) bool {
	// Policy-local inheritance can materialise (or, via -except, suppress)
	// commands authored in a group body this subtree does not contain.
	for _, child := range policy.Children {
		if child == nil {
			continue
		}
		if child.Name() == "apply-groups" || child.Name() == "apply-groups-except" {
			return true
		}
	}
	if eventPolicyHasCommands9984([]*Node{policy}) {
		return true
	}
	// Packed flat-set spelling: the policy and its commands ride on one
	// leaf's Keys (`policy p then change-configuration commands ...`).
	return eventOptionsKeysMayHaveCommands9984(policy.Keys)
}

// eventOptionsKeysMayHaveCommands9984 scans a packed key run for the
// adjacent `change-configuration commands` pair followed by at least one
// value token — the packed spelling of the payload. A bare trailing
// `commands` keyword carries no value and compiles to zero commands.
func eventOptionsKeysMayHaveCommands9984(keys []string) bool {
	for i := range len(keys) - 2 {
		if keys[i] == "change-configuration" && keys[i+1] == "commands" {
			return true
		}
	}
	return false
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
			if inSection && node.Name() == "event-options" {
				if inst, ok := compactEventOptionsPolicyInstance9984(node, nil); ok {
					out[inst.name] = append(out[inst.name], inst.node)
				}
				if len(node.Keys) == 2 && node.Keys[1] == "policy" {
					for _, child := range node.Children {
						if inst, ok := compactEventOptionsPolicyInstance9984(node, child); ok {
							out[inst.name] = append(out[inst.name], inst.node)
						}
					}
				}
			}
			if inSection && node.Name() == "policy" {
				// Mirror namedInstances, used by compileEventOptions: a
				// direct policy carries its name in Keys[1]; the
				// one-key-container shape `policy { p { ... } }` files
				// each named instance as a child of the policy node.
				// Indexing only Keys>=2 made a solely nested plant-class
				// invisible to stamping/quarantine while the compiler
				// still honoured it (#14142).
				for _, inst := range namedInstances([]*Node{node}) {
					out[inst.name] = append(out[inst.name], inst.node)
				}
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
