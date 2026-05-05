package config

import (
	"fmt"
	"strings"
)

// Node represents a node in the Junos configuration tree.
// It is either a leaf (terminated by ;) or a block (containing children in {}).
type Node struct {
	// Keys is the sequence of identifiers forming this node's identity.
	// Examples:
	//   "security" -> ["security"]
	//   "security-zone trust" -> ["security-zone", "trust"]
	//   "from-zone trust to-zone untrust" -> ["from-zone", "trust", "to-zone", "untrust"]
	//   "address 10.0.1.0/24" -> ["address", "10.0.1.0/24"]
	Keys []string

	// Children are the nodes within this block's braces.
	// nil for leaf nodes.
	Children []*Node

	// IsLeaf is true when the node is terminated by ; (no block body).
	IsLeaf bool

	// Annotation is a user comment set via the "annotate" command.
	Annotation string

	// InheritedFrom is the group name this node was inherited from.
	// Set during ExpandGroups when tagInherited is true.
	InheritedFrom string

	// Line/Column where this node starts (for error reporting).
	Line   int
	Column int
}

// Name returns the first key of the node.
func (n *Node) Name() string {
	if len(n.Keys) == 0 {
		return ""
	}
	return n.Keys[0]
}

// KeyPath returns the full key path as a single string (unquoted).
// Used for map lookups and comparison. For display/format output, use QuotedKeyPath.
func (n *Node) KeyPath() string {
	return strings.Join(n.Keys, " ")
}

// QuotedKeyPath returns the key path with keys quoted if they contain
// characters that aren't valid bare identifiers (e.g. ${node}).
func (n *Node) QuotedKeyPath() string {
	parts := make([]string, len(n.Keys))
	for i, k := range n.Keys {
		parts[i] = quoteKey(k)
	}
	return strings.Join(parts, " ")
}

// quoteKey wraps a key in double quotes if it contains characters that
// are not valid in bare Junos identifiers.
func quoteKey(s string) string {
	if s == "" {
		return `""`
	}
	for i := 0; i < len(s); i++ {
		if !isIdentChar(s[i]) {
			// Escape any internal quotes.
			return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
		}
	}
	return s
}

// FindChild returns the first child whose first key matches name.
func (n *Node) FindChild(name string) *Node {
	for _, child := range n.Children {
		if len(child.Keys) > 0 && child.Keys[0] == name {
			return child
		}
	}
	return nil
}

// FindChildren returns all children whose first key matches name.
func (n *Node) FindChildren(name string) []*Node {
	var result []*Node
	for _, child := range n.Children {
		if len(child.Keys) > 0 && child.Keys[0] == name {
			result = append(result, child)
		}
	}
	return result
}

// ConfigTree is the root of a parsed configuration.
type ConfigTree struct {
	Children []*Node
}

// FindChild returns the first top-level child matching name.
func (t *ConfigTree) FindChild(name string) *Node {
	for _, child := range t.Children {
		if len(child.Keys) > 0 && child.Keys[0] == name {
			return child
		}
	}
	return nil
}

// Clone creates a deep copy of the config tree.
func (t *ConfigTree) Clone() *ConfigTree {
	if t == nil {
		return nil
	}
	return &ConfigTree{
		Children: cloneNodes(t.Children),
	}
}

func cloneNodes(nodes []*Node) []*Node {
	if nodes == nil {
		return nil
	}
	result := make([]*Node, len(nodes))
	for i, n := range nodes {
		result[i] = &Node{
			Keys:          append([]string(nil), n.Keys...),
			Children:      cloneNodes(n.Children),
			IsLeaf:        n.IsLeaf,
			Annotation:    n.Annotation,
			InheritedFrom: n.InheritedFrom,
			Line:          n.Line,
			Column:        n.Column,
		}
	}
	return result
}

// navigatePath walks the tree following path components and returns matching nodes.
// When multiple sibling nodes share the same key prefix (e.g., path ["from-zone","untrust"]
// matching both ["from-zone","untrust","to-zone","trust"] and
// ["from-zone","untrust","to-zone","dmz"]), all matches are returned.
func navigatePath(nodes []*Node, path []string) []*Node {
	current := nodes
	i := 0
	for i < len(path) {
		keyword := path[i]
		// Try multi-key match (keyword + argument pairs).
		if i+1 < len(path) {
			var matched []*Node
			for _, n := range current {
				if len(n.Keys) >= 2 && n.Keys[0] == keyword && n.Keys[1] == path[i+1] {
					matched = append(matched, n)
				}
			}
			if len(matched) > 0 {
				consumed := 2
				// Continue consuming additional key-value pairs from the path
				// that match the node's remaining keys. E.g., path
				// ["from-zone","untrust","to-zone","trust"] consumes all 4 keys
				// of node Keys=["from-zone","untrust","to-zone","trust"].
				for consumed < len(matched[0].Keys) && i+consumed+1 < len(path) {
					nextKey := path[i+consumed]
					nextVal := path[i+consumed+1]
					var filtered []*Node
					for _, n := range matched {
						if len(n.Keys) > consumed+1 && n.Keys[consumed] == nextKey && n.Keys[consumed+1] == nextVal {
							filtered = append(filtered, n)
						}
					}
					if len(filtered) == 0 {
						break
					}
					matched = filtered
					consumed += 2
				}
				i += consumed
				if i >= len(path) {
					return matched
				}
				current = matched[0].Children
				continue
			}
		}
		// Single-key match.
		found := false
		for _, n := range current {
			if len(n.Keys) > 0 && n.Keys[0] == keyword {
				i++
				if i >= len(path) {
					return []*Node{n}
				}
				current = n.Children
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}
	return nil
}

// matchNodeKeys checks if a node's Keys match path elements starting at pos.
// Returns the number of path elements consumed (len(node.Keys)) on match, 0 otherwise.
func matchNodeKeys(n *Node, path []string, pos int) int {
	if len(n.Keys) == 0 || pos >= len(path) {
		return 0
	}
	if n.Keys[0] != path[pos] {
		return 0
	}
	// First key matches; check remaining keys fit within path
	nk := len(n.Keys)
	if pos+nk > len(path) {
		// Partial match: node has more keys than remaining path.
		// Accept if we're at the last path segment (allows matching by first key only).
		return 1
	}
	for j := 1; j < nk; j++ {
		if n.Keys[j] != path[pos+j] {
			return 1 // first key matched but subsequent didn't; still a 1-key match
		}
	}
	return nk
}

// navigateToNode walks the tree following path, returning the target node.
// Multi-key nodes consume multiple path elements at once.
func navigateToNode(children []*Node, path []string) (*Node, error) {
	var current *Node
	pos := 0
	for pos < len(path) {
		found := false
		for _, child := range children {
			consumed := matchNodeKeys(child, path, pos)
			if consumed > 0 {
				current = child
				children = child.Children
				pos += consumed
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("path element %q not found", path[pos])
		}
	}
	return current, nil
}

// findNode navigates the tree to find a node at the given path.
// Handles multi-key nodes by consuming multiple path elements per node.
func (t *ConfigTree) findNode(path []string) (*Node, error) {
	return navigateToNode(t.Children, path)
}

// removeNode removes and returns a node at the given path.
func (t *ConfigTree) removeNode(path []string) (*Node, error) {
	if len(path) == 0 {
		return nil, fmt.Errorf("empty path")
	}
	// Navigate to the parent, then find and remove the target child.
	parentChildren := &t.Children
	pos := 0
	// We need to find where the last node starts.
	// Walk until we can identify the target node at the end.
	for pos < len(path) {
		// Try to match a child and see if it's the final node.
		var bestChild *Node
		bestConsumed := 0
		bestIdx := -1
		for i, child := range *parentChildren {
			consumed := matchNodeKeys(child, path, pos)
			if consumed > 0 {
				bestChild = child
				bestConsumed = consumed
				bestIdx = i
				break
			}
		}
		if bestChild == nil {
			return nil, fmt.Errorf("path element %q not found", path[pos])
		}
		if pos+bestConsumed >= len(path) {
			// This is the target node — remove it.
			*parentChildren = append((*parentChildren)[:bestIdx], (*parentChildren)[bestIdx+1:]...)
			return bestChild, nil
		}
		// Descend into this child's children.
		parentChildren = &bestChild.Children
		pos += bestConsumed
	}
	return nil, fmt.Errorf("path not found")
}

// insertNode inserts a node as a child at the given parent path.
func (t *ConfigTree) insertNode(parentPath []string, node *Node) error {
	children := &t.Children
	pos := 0
	for pos < len(parentPath) {
		found := false
		for _, child := range *children {
			consumed := matchNodeKeys(child, parentPath, pos)
			if consumed > 0 {
				children = &child.Children
				pos += consumed
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("destination parent path element %q not found", parentPath[pos])
		}
	}
	*children = append(*children, node)
	return nil
}

// findNodeWithParent navigates the tree and returns the target node
// plus the parent's children slice (for insertion/removal at the correct level).
func (t *ConfigTree) findNodeWithParent(path []string) (*Node, *[]*Node, error) {
	parentChildren := &t.Children
	pos := 0
	for pos < len(path) {
		// Try all children; prefer full-key matches over partial ones.
		// This handles siblings like [policy first], [policy second], [policy third]
		// where the first key "policy" matches all but we need the full key match.
		var bestChild *Node
		bestConsumed := 0
		for _, child := range *parentChildren {
			consumed := matchNodeKeys(child, path, pos)
			if consumed > bestConsumed {
				bestChild = child
				bestConsumed = consumed
			}
		}
		if bestChild == nil {
			return nil, nil, fmt.Errorf("path element %q not found", path[pos])
		}
		if pos+bestConsumed >= len(path) {
			return bestChild, parentChildren, nil
		}
		parentChildren = &bestChild.Children
		pos += bestConsumed
	}
	return nil, nil, fmt.Errorf("path not found")
}

// ValueHint identifies what kind of dynamic value is expected at a schema position.
type ValueHint int

const (
	ValueHintNone          ValueHint = iota
	ValueHintZoneName                // security-zone <name>
	ValueHintAddressName             // address-set <name>
	ValueHintAppName                 // application <name>
	ValueHintPoolName                // pool <name>
	ValueHintInterfaceName           // interfaces <name>
	ValueHintScreenProfile           // ids-option <name>
	ValueHintStreamName              // stream <name>
	ValueHintAppSetName              // application-set <name>
	ValueHintUnitNumber              // unit <number>
	ValueHintPolicyAddress           // policy match source/destination-address
	ValueHintPolicyApp               // policy match application (any + apps)
	ValueHintPolicyName              // policy <name> (from path context)
)

// SchemaCompletion is a completion candidate from the config schema.
type SchemaCompletion struct {
	Name string
	Desc string
}

// ValueProvider returns possible values for a given hint.
// The path parameter provides consumed tokens for context (e.g., interface name for unit completion).
type ValueProvider func(hint ValueHint, path []string) []SchemaCompletion

// schemaNode defines a container keyword in the Junos config hierarchy.
// It tells SetPath how to group flat path tokens into the correct tree structure.
type schemaNode struct {
	args         int                    // extra tokens consumed as part of this node's key
	children     map[string]*schemaNode // known container children
	wildcard     *schemaNode            // matches any keyword not in children (for dynamic names)
	multi        bool                   // true = multiple leaf values allowed (e.g. source-address); false = replace on set
	valueHint    ValueHint              // hint for dynamic value completion (when args > 0)
	desc         string                 // description shown in completion help
	placeholder  string                 // Junos-style placeholder (e.g., "<interface-name>")
	midKeyword   string                 // fixed keyword in the middle of args (e.g., "to-zone")
	midKeywordAt int                    // 1-based arg position where midKeyword appears (e.g., 2 for "from-zone X to-zone Y")
	compoundKey  bool                   // children form compound key (e.g., "family inet6" → Keys=["family","inet6"])
}

// setSchema defines the Junos configuration tree structure.
// Keywords present in the schema at a given depth are treated as containers.
// Keywords NOT in the schema become leaf nodes (all remaining tokens form the leaf's Keys).
var setSchema = &schemaNode{children: map[string]*schemaNode{
	"groups":       {wildcard: &schemaNode{}}, // children set in init()
	"apply-groups": {args: 1, multi: true, children: nil},
	"security": {children: map[string]*schemaNode{
		"zones": {children: map[string]*schemaNode{
			"security-zone": {args: 1, valueHint: ValueHintZoneName, children: map[string]*schemaNode{
				"description": {args: 1, children: nil},
				"interfaces":  {children: nil},
				"tcp-rst":     {children: nil},
				"screen":      {args: 1, children: nil},
				"host-inbound-traffic": {children: map[string]*schemaNode{
					"system-services": {children: nil},
					"protocols":       {children: nil},
				}},
			}},
		}},
		"policies": {children: map[string]*schemaNode{
			"from-zone": {args: 3, valueHint: ValueHintZoneName, midKeyword: "to-zone", midKeywordAt: 2, children: map[string]*schemaNode{
				"policy": {args: 1, valueHint: ValueHintPolicyName, children: map[string]*schemaNode{
					"description": {args: 1, children: nil},
					"match": {children: map[string]*schemaNode{
						"source-address":      {args: 1, multi: true, valueHint: ValueHintPolicyAddress, children: nil},
						"destination-address": {args: 1, multi: true, valueHint: ValueHintPolicyAddress, children: nil},
						"application":         {args: 1, multi: true, valueHint: ValueHintPolicyApp, children: nil},
					}},
					"then": {children: map[string]*schemaNode{
						"log": {children: nil},
						// permit, deny, reject, count → leaf
					}},
				}},
			}},
			"global": {children: map[string]*schemaNode{
				"policy": {args: 1, valueHint: ValueHintPolicyName, children: map[string]*schemaNode{
					"description": {args: 1, children: nil},
					"match": {children: map[string]*schemaNode{
						"source-address":      {args: 1, multi: true, valueHint: ValueHintPolicyAddress, children: nil},
						"destination-address": {args: 1, multi: true, valueHint: ValueHintPolicyAddress, children: nil},
						"application":         {args: 1, multi: true, valueHint: ValueHintPolicyApp, children: nil},
					}},
					"then": {children: map[string]*schemaNode{
						"log": {children: nil},
					}},
				}},
			}},
		}},
		"screen": {children: map[string]*schemaNode{
			"ids-option": {args: 1, valueHint: ValueHintScreenProfile, children: map[string]*schemaNode{
				"icmp": {children: nil},
				"tcp": {children: map[string]*schemaNode{
					"syn-flood": {children: nil},
					"port-scan": {children: nil},
					// land, winnuke, syn-frag -> leaf
				}},
				"ip": {children: map[string]*schemaNode{
					"ip-sweep": {children: nil},
					// source-route-option, tear-drop -> leaf
				}},
				"udp": {children: nil},
				"limit-session": {children: map[string]*schemaNode{
					"source-ip-based":      {args: 1, children: nil},
					"destination-ip-based": {args: 1, children: nil},
				}},
			}},
		}},
		"nat": {children: map[string]*schemaNode{
			"source": {children: map[string]*schemaNode{
				"pool":               {args: 1, valueHint: ValueHintPoolName, children: nil},
				"address-persistent": {children: nil},
				"rule-set": {args: 1, children: map[string]*schemaNode{
					"from": {children: map[string]*schemaNode{
						"zone": {args: 1, valueHint: ValueHintZoneName, children: nil},
					}},
					"to": {children: map[string]*schemaNode{
						"zone": {args: 1, valueHint: ValueHintZoneName, children: nil},
					}},
					"rule": {args: 1, children: map[string]*schemaNode{
						"match": {children: map[string]*schemaNode{
							"source-address":      {args: 1, multi: true, children: nil},
							"destination-address": {args: 1, multi: true, children: nil},
							"destination-port":    {args: 1, multi: true, children: nil},
							"application":         {args: 1, multi: true, children: nil},
						}},
						"then": {children: map[string]*schemaNode{
							"source-nat": {children: map[string]*schemaNode{
								"interface": {children: nil},
								"off":       {children: nil},
								"pool":      {args: 1, valueHint: ValueHintPoolName, children: nil},
							}},
						}},
					}},
				}},
			}},
			"destination": {children: map[string]*schemaNode{
				"pool": {args: 1, valueHint: ValueHintPoolName, children: nil},
				"rule-set": {args: 1, children: map[string]*schemaNode{
					"from": {children: map[string]*schemaNode{
						"zone": {args: 1, valueHint: ValueHintZoneName, children: nil},
					}},
					"to": {children: map[string]*schemaNode{
						"zone": {args: 1, valueHint: ValueHintZoneName, children: nil},
					}},
					"rule": {args: 1, children: map[string]*schemaNode{
						"match": {children: map[string]*schemaNode{
							"source-address":      {args: 1, multi: true, children: nil},
							"source-address-name": {args: 1, multi: true, children: nil},
							"destination-address": {args: 1, multi: true, children: nil},
							"destination-port":    {args: 1, multi: true, children: nil},
							"protocol":            {args: 1, multi: true, children: nil},
							"application":         {args: 1, multi: true, children: nil},
						}},
						"then": {children: map[string]*schemaNode{
							"destination-nat": {children: map[string]*schemaNode{
								"pool": {args: 1, valueHint: ValueHintPoolName, children: nil},
							}},
						}},
					}},
				}},
			}},
			"static": {children: map[string]*schemaNode{
				"rule-set": {args: 1, children: map[string]*schemaNode{
					"rule": {args: 1, children: map[string]*schemaNode{
						"match": {children: nil},
						"then": {children: map[string]*schemaNode{
							"static-nat": {children: nil},
						}},
					}},
				}},
			}},
			"nat64": {children: map[string]*schemaNode{
				"rule-set": {args: 1, children: map[string]*schemaNode{
					"prefix":      {args: 1, children: nil},
					"source-pool": {args: 1, children: nil},
				}},
			}},
			"natv6v4": {children: map[string]*schemaNode{
				"no-v6-frag-header": {children: nil},
			}},
			"proxy-arp": {children: map[string]*schemaNode{
				"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
					"address": {args: 1, multi: true, children: nil},
				}},
			}},
		}},
		"address-book": {children: map[string]*schemaNode{
			"global": {children: map[string]*schemaNode{
				"address": {args: 2, multi: true, children: nil},
				"address-set": {args: 1, valueHint: ValueHintAddressName, children: map[string]*schemaNode{
					"address":     {args: 1, multi: true, children: nil},
					"address-set": {args: 1, multi: true, valueHint: ValueHintAddressName, children: nil},
					"description": {args: 1, children: nil},
				}},
			}},
		}},
		"log": {children: map[string]*schemaNode{
			"mode":             {args: 1, children: nil},
			"format":           {args: 1, children: nil},
			"source-interface": {args: 1, valueHint: ValueHintInterfaceName, children: nil},
			"stream": {args: 1, valueHint: ValueHintStreamName, children: map[string]*schemaNode{
				"host":           {args: 1, children: nil},
				"port":           {args: 1, children: nil},
				"severity":       {args: 1, children: nil},
				"facility":       {args: 1, children: nil},
				"format":         {args: 1, children: nil},
				"category":       {args: 1, children: nil},
				"source-address": {args: 1, children: nil},
			}},
		}},
		"flow": {children: map[string]*schemaNode{
			"aging":                        {children: nil},
			"tcp-session":                  {children: nil},
			"udp-session":                  {children: nil},
			"icmp-session":                 {children: nil},
			"tcp-mss":                      {children: nil},
			"allow-dns-reply":              {children: nil},
			"allow-embedded-icmp":          {children: nil},
			"gre-performance-acceleration": {children: nil},
			"power-mode-disable":           {children: nil},
			"traceoptions": {children: map[string]*schemaNode{
				"file": {args: 1, children: nil},
				"flag": {args: 1, children: nil},
				"packet-filter": {args: 1, children: map[string]*schemaNode{
					"source-prefix":      {args: 1, children: nil},
					"destination-prefix": {args: 1, children: nil},
				}},
			}},
		}},
		"alg": {children: map[string]*schemaNode{
			"dns":  {children: nil},
			"ftp":  {children: nil},
			"sip":  {children: nil},
			"tftp": {children: nil},
		}},
		"ike": {children: map[string]*schemaNode{
			"proposal": {args: 1, children: nil},
			"policy": {args: 1, children: map[string]*schemaNode{
				"mode":           {args: 1, children: nil},
				"proposals":      {args: 1, children: nil},
				"pre-shared-key": {children: nil},
			}},
			"gateway": {args: 1, children: map[string]*schemaNode{
				"address":            {args: 1, children: nil},
				"local-address":      {args: 1, children: nil},
				"ike-policy":         {args: 1, children: nil},
				"external-interface": {args: 1, children: nil},
				"local-certificate":  {args: 1, children: nil},
				"version":            {args: 1, children: nil},
				"no-nat-traversal":   {children: nil},
				"nat-traversal":      {args: 1, children: nil},
				"dead-peer-detection": {children: map[string]*schemaNode{
					"always-send":       {children: nil},
					"optimized":         {children: nil},
					"probe-idle-tunnel": {children: nil},
					"interval":          {args: 1, children: nil},
					"threshold":         {args: 1, children: nil},
				}},
				"local-identity":  {children: nil},
				"remote-identity": {children: nil},
				"dynamic":         {children: nil},
			}},
		}},
		"ipsec": {children: map[string]*schemaNode{
			"proposal": {args: 1, children: nil},
			"policy": {args: 1, children: map[string]*schemaNode{
				"perfect-forward-secrecy": {children: nil},
				"proposals":               {args: 1, children: nil},
			}},
			"gateway": {args: 1, children: map[string]*schemaNode{
				"address":            {args: 1, children: nil},
				"local-address":      {args: 1, children: nil},
				"ike-policy":         {args: 1, children: nil},
				"external-interface": {args: 1, children: nil},
				"local-certificate":  {args: 1, children: nil},
				"version":            {args: 1, children: nil},
				"no-nat-traversal":   {children: nil},
				"nat-traversal":      {args: 1, children: nil},
				"dead-peer-detection": {children: map[string]*schemaNode{
					"always-send":       {children: nil},
					"optimized":         {children: nil},
					"probe-idle-tunnel": {children: nil},
					"interval":          {args: 1, children: nil},
					"threshold":         {args: 1, children: nil},
				}},
				"local-identity":  {children: nil},
				"remote-identity": {children: nil},
				"dynamic":         {children: nil},
			}},
			"vpn": {args: 1, children: map[string]*schemaNode{
				"bind-interface":    {args: 1, children: nil},
				"df-bit":            {args: 1, children: nil},
				"establish-tunnels": {args: 1, children: nil},
				"local-identity":    {args: 1, children: nil},
				"remote-identity":   {args: 1, children: nil},
				"pre-shared-key":    {args: 1, children: nil},
				"local-address":     {args: 1, children: nil},
				"traffic-selector": {args: 1, children: map[string]*schemaNode{
					"local-ip":  {args: 1, children: nil},
					"remote-ip": {args: 1, children: nil},
				}},
				"ike": {children: map[string]*schemaNode{
					"gateway":      {args: 1, children: nil},
					"ipsec-policy": {args: 1, children: nil},
				}},
			}},
		}},
		"dynamic-address": {children: map[string]*schemaNode{
			"feed-server": {args: 1, children: map[string]*schemaNode{
				"url":             {args: 1, children: nil},
				"hostname":        {args: 1, children: nil},
				"update-interval": {args: 1, children: nil},
				"hold-interval":   {args: 1, children: nil},
				"feed-name": {args: 1, children: map[string]*schemaNode{
					"path": {args: 1, children: nil},
				}},
			}},
			"address-name": {args: 1, children: map[string]*schemaNode{
				"profile": {children: map[string]*schemaNode{
					"feed-name": {args: 1, children: nil},
				}},
			}},
		}},
		"ssh-known-hosts": {children: map[string]*schemaNode{
			"host": {args: 1, children: nil},
		}},
		"policy-stats": {children: map[string]*schemaNode{
			"system-wide": {args: 1, children: nil},
		}},
		"pre-id-default-policy": {children: map[string]*schemaNode{
			"then": {children: map[string]*schemaNode{
				"log": {children: map[string]*schemaNode{
					"session-init":  {children: nil},
					"session-close": {children: nil},
				}},
			}},
		}},
	}},
	"interfaces": {desc: "Interface configuration", wildcard: &schemaNode{valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
		"description":           {desc: "Text description of interface", args: 1, children: nil},
		"mtu":                   {desc: "Maximum transmit packet size", args: 1, children: nil},
		"speed":                 {desc: "Link speed", args: 1, children: nil},
		"duplex":                {desc: "Link duplex mode", args: 1, children: nil},
		"bandwidth":             {desc: "Interface bandwidth", args: 1, children: nil},
		"disable":               {desc: "Disable this interface", children: nil},
		"vlan-tagging":          {desc: "Enable 802.1Q VLAN tagging", children: nil},
		"flexible-vlan-tagging": {desc: "Enable flexible 802.1Q VLAN tagging (QinQ)", children: nil},
		"encapsulation":         {desc: "Physical link-layer encapsulation", args: 1, children: nil},
		"gigether-options": {desc: "Gigabit Ethernet interface options", children: map[string]*schemaNode{
			"redundant-parent": {desc: "Parent of this redundant interface", args: 1, children: nil},
			"802.3ad":          {desc: "Link aggregation group", args: 1, children: nil},
		}},
		"aggregated-ether-options": {desc: "Aggregated Ethernet interface options", children: map[string]*schemaNode{
			"lacp": {desc: "LACP parameters", children: map[string]*schemaNode{
				"active":   {desc: "Active LACP mode", children: nil},
				"passive":  {desc: "Passive LACP mode", children: nil},
				"periodic": {desc: "LACP timer period", args: 1, children: nil},
			}},
			"link-speed":    {desc: "Member link speed", args: 1, children: nil},
			"minimum-links": {desc: "Minimum active member links", args: 1, children: nil},
		}},
		"redundant-ether-options": {desc: "Redundant Ethernet interface options", children: map[string]*schemaNode{
			"redundancy-group": {desc: "Redundancy group for this RETH", args: 1, children: nil},
		}},
		"fabric-options": {desc: "Fabric interface options", children: map[string]*schemaNode{
			"member-interfaces": {desc: "Member interfaces", children: nil},
		}},
		"tunnel": {desc: "Tunnel parameters", children: map[string]*schemaNode{
			"source":          {desc: "Tunnel source address", args: 1, children: nil},
			"destination":     {desc: "Tunnel destination address", args: 1, children: nil},
			"mode":            {desc: "Tunnel mode", args: 1, children: nil},
			"key":             {desc: "Tunnel key", args: 1, children: nil},
			"ttl":             {desc: "Time to live", args: 1, children: nil},
			"keepalive":       {desc: "Keepalive interval", args: 1, children: nil},
			"keepalive-retry": {desc: "Keepalive retry count", args: 1, children: nil},
			"routing-instance": {desc: "Routing instance", children: map[string]*schemaNode{
				"destination": {desc: "Destination routing instance", args: 1, children: nil},
			}},
		}},
		"unit": {desc: "Logical unit number", args: 1, valueHint: ValueHintUnitNumber, placeholder: "<unit-number>", children: map[string]*schemaNode{
			"description":    {args: 1, children: nil},
			"point-to-point": {children: nil},
			"vlan-id":        {args: 1, children: nil},
			"inner-vlan-id":  {args: 1, children: nil},
			"tunnel": {desc: "Tunnel parameters", children: map[string]*schemaNode{
				"source":          {desc: "Tunnel source address", args: 1, children: nil},
				"destination":     {desc: "Tunnel destination address", args: 1, children: nil},
				"mode":            {desc: "Tunnel mode", args: 1, children: nil},
				"key":             {desc: "Tunnel key", args: 1, children: nil},
				"ttl":             {desc: "Time to live", args: 1, children: nil},
				"keepalive":       {desc: "Keepalive interval", args: 1, children: nil},
				"keepalive-retry": {desc: "Keepalive retry count", args: 1, children: nil},
				"routing-instance": {desc: "Routing instance", children: map[string]*schemaNode{
					"destination": {desc: "Destination routing instance", args: 1, children: nil},
				}},
			}},
			"family": {compoundKey: true, children: map[string]*schemaNode{
				"inet": {children: map[string]*schemaNode{
					"mtu": {args: 1, children: nil},
					"address": {args: 1, children: map[string]*schemaNode{
						"primary":   {children: nil},
						"preferred": {children: nil},
					}},
					"dhcp": {children: map[string]*schemaNode{
						"lease-time":              {args: 1, children: nil},
						"retransmission-attempt":  {args: 1, children: nil},
						"retransmission-interval": {args: 1, children: nil},
						"force-discover":          {children: nil},
					}},
					"sampling": {children: map[string]*schemaNode{
						"input":  {children: nil},
						"output": {children: nil},
					}},
					"filter": {children: map[string]*schemaNode{
						"input":  {args: 1, children: nil},
						"output": {args: 1, children: nil},
					}},
				}},
				"inet6": {children: map[string]*schemaNode{
					"mtu":         {args: 1, children: nil},
					"dad-disable": {children: nil},
					"address": {args: 1, children: map[string]*schemaNode{
						"primary":   {children: nil},
						"preferred": {children: nil},
					}},
					"sampling": {children: map[string]*schemaNode{
						"input":  {children: nil},
						"output": {children: nil},
					}},
					"filter": {children: map[string]*schemaNode{
						"input":  {args: 1, children: nil},
						"output": {args: 1, children: nil},
					}},
					"dhcpv6-client": {children: map[string]*schemaNode{
						"client-type":    {args: 1, children: nil},
						"client-ia-type": {args: 1, children: nil},
						"prefix-delegating": {children: map[string]*schemaNode{
							"preferred-prefix-length": {args: 1, children: nil},
							"sub-prefix-length":       {args: 1, children: nil},
						}},
						"client-identifier": {children: map[string]*schemaNode{
							"duid-type": {args: 1, children: nil},
						}},
						"req-option": {args: 1, children: nil},
						"update-router-advertisement": {children: map[string]*schemaNode{
							"interface": {args: 1, children: nil},
						}},
					}},
				}},
			}},
		}},
	}}},
	"applications": {children: map[string]*schemaNode{
		"application": {args: 1, valueHint: ValueHintAppName, children: map[string]*schemaNode{
			"protocol":           {args: 1, children: nil},
			"destination-port":   {args: 1, children: nil},
			"source-port":        {args: 1, children: nil},
			"inactivity-timeout": {args: 1, children: nil},
			"timeout":            {args: 1, children: nil},
			"alg":                {args: 1, children: nil},
			"description":        {args: 1, children: nil},
			"term":               {args: 1, children: nil},
		}},
		"application-set": {args: 1, valueHint: ValueHintAppSetName, children: nil},
	}},
	"routing-options": {children: map[string]*schemaNode{
		"static": {children: map[string]*schemaNode{
			"route": {args: 1, children: nil},
		}},
		"rib": {args: 1, children: map[string]*schemaNode{
			"static": {children: map[string]*schemaNode{
				"route": {args: 1, children: nil},
			}},
		}},
		"autonomous-system": {args: 1, children: nil},
		"forwarding-table": {children: map[string]*schemaNode{
			"export": {args: 1, multi: true, children: nil},
		}},
		"rib-groups": {wildcard: &schemaNode{children: map[string]*schemaNode{
			"import-rib": {children: nil},
		}}},
		"interface-routes": {children: map[string]*schemaNode{
			"rib-group": {children: map[string]*schemaNode{
				"inet":  {args: 1, children: nil},
				"inet6": {args: 1, children: nil},
			}},
		}},
		"generate": {children: map[string]*schemaNode{
			"route": {args: 1, children: map[string]*schemaNode{
				"policy":  {args: 1, children: nil},
				"discard": {children: nil},
			}},
		}},
	}},
	"snmp": {children: map[string]*schemaNode{
		"community": {args: 1, children: map[string]*schemaNode{
			"authorization": {args: 1, children: nil},
		}},
		"trap-group": {args: 1, children: nil},
		"v3": {children: map[string]*schemaNode{
			"usm": {children: map[string]*schemaNode{
				"local-engine": {children: map[string]*schemaNode{
					"user": {args: 1, children: map[string]*schemaNode{
						"authentication-md5":    {children: map[string]*schemaNode{"authentication-password": {args: 1, children: nil}}},
						"authentication-sha":    {children: map[string]*schemaNode{"authentication-password": {args: 1, children: nil}}},
						"authentication-sha256": {children: map[string]*schemaNode{"authentication-password": {args: 1, children: nil}}},
						"privacy-des":           {children: map[string]*schemaNode{"privacy-password": {args: 1, children: nil}}},
						"privacy-aes128":        {children: map[string]*schemaNode{"privacy-password": {args: 1, children: nil}}},
					}},
				}},
			}},
		}},
	}},
	"policy-options": {children: map[string]*schemaNode{
		"prefix-list": {args: 1, children: nil},
		"community": {args: 1, children: map[string]*schemaNode{
			"members": {args: 1, multi: true, children: nil},
		}},
		"as-path": {args: 2, multi: true, children: nil},
		"policy-statement": {args: 1, children: map[string]*schemaNode{
			"term": {args: 1, children: map[string]*schemaNode{
				"from": {children: map[string]*schemaNode{
					"protocol":     {args: 1, children: nil},
					"prefix-list":  {args: 1, children: nil},
					"route-filter": {args: 2, children: nil},
					"community":    {args: 1, children: nil},
					"as-path":      {args: 1, children: nil},
				}},
				"then": {children: map[string]*schemaNode{
					"accept":           {children: nil},
					"reject":           {children: nil},
					"next-hop":         {args: 1, children: nil},
					"load-balance":     {args: 1, children: nil},
					"local-preference": {args: 1, children: nil},
					"metric":           {args: 1, children: nil},
					"metric-type":      {args: 1, children: nil},
					"community":        {args: 1, children: nil},
					"origin":           {args: 1, children: nil},
				}},
			}},
			"then": {children: nil},
		}},
	}},
	"protocols": {children: map[string]*schemaNode{
		"ospf": {children: map[string]*schemaNode{
			"router-id":           {args: 1, children: nil},
			"reference-bandwidth": {args: 1, children: nil},
			"passive":             {children: nil},
			"export":              {args: 1, multi: true, children: nil},
			"area": {args: 1, children: map[string]*schemaNode{
				"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
					"passive":        {children: nil},
					"no-passive":     {children: nil},
					"interface-type": {args: 1, children: nil},
					"cost":           {args: 1, children: nil},
					"authentication": {children: map[string]*schemaNode{
						"md5": {args: 1, children: map[string]*schemaNode{
							"key": {args: 1, children: nil},
						}},
						"simple-password": {args: 1, children: nil},
					}},
					"bfd-liveness-detection": {children: map[string]*schemaNode{
						"minimum-interval": {args: 1, children: nil},
						"multiplier":       {args: 1, children: nil},
					}},
				}},
				"area-type": {children: map[string]*schemaNode{
					"stub": {children: map[string]*schemaNode{
						"no-summaries": {children: nil},
					}},
					"nssa": {children: map[string]*schemaNode{
						"no-summaries": {children: nil},
					}},
				}},
				"virtual-link": {args: 1, children: map[string]*schemaNode{
					"transit-area": {args: 1, children: nil},
				}},
			}},
		}},
		"ospf3": {children: map[string]*schemaNode{
			"router-id": {args: 1, children: nil},
			"export":    {args: 1, multi: true, children: nil},
			"area": {args: 1, children: map[string]*schemaNode{
				"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
					"passive": {children: nil},
					"cost":    {args: 1, children: nil},
				}},
			}},
		}},
		"bgp": {children: map[string]*schemaNode{
			"local-as":         {args: 1, children: nil},
			"router-id":        {args: 1, children: nil},
			"cluster-id":       {args: 1, children: nil},
			"graceful-restart": {children: nil},
			"log-updown":       {children: nil},
			"multipath": {children: map[string]*schemaNode{
				"multiple-as": {children: nil},
			}},
			"damping": {children: map[string]*schemaNode{
				"half-life":    {args: 1, children: nil},
				"reuse":        {args: 1, children: nil},
				"suppress":     {args: 1, children: nil},
				"max-suppress": {args: 1, children: nil},
			}},
			"export": {args: 1, multi: true, children: nil},
			"group": {args: 1, children: map[string]*schemaNode{
				"peer-as":            {args: 1, children: nil},
				"description":        {args: 1, children: nil},
				"multihop":           {args: 1, children: nil},
				"export":             {args: 1, multi: true, children: nil},
				"authentication-key": {args: 1, children: nil},
				"default-originate":  {children: nil},
				"loops":              {args: 1, children: nil},
				"remove-private":     {children: nil},
				"family": {compoundKey: true, children: map[string]*schemaNode{
					"inet": {children: map[string]*schemaNode{
						"unicast": {children: map[string]*schemaNode{
							"prefix-limit": {children: map[string]*schemaNode{
								"maximum": {args: 1, children: nil},
							}},
						}},
					}},
					"inet6": {children: map[string]*schemaNode{
						"unicast": {children: map[string]*schemaNode{
							"prefix-limit": {children: map[string]*schemaNode{
								"maximum": {args: 1, children: nil},
							}},
						}},
					}},
				}},
				"bfd-liveness-detection": {children: map[string]*schemaNode{
					"minimum-interval": {args: 1, children: nil},
					"multiplier":       {args: 1, children: nil},
				}},
				"neighbor": {args: 1, children: map[string]*schemaNode{
					"description":            {args: 1, children: nil},
					"peer-as":                {args: 1, children: nil},
					"multihop":               {args: 1, children: nil},
					"authentication-key":     {args: 1, children: nil},
					"route-reflector-client": {children: nil},
					"default-originate":      {children: nil},
					"loops":                  {args: 1, children: nil},
					"remove-private":         {children: nil},
					"family": {compoundKey: true, children: map[string]*schemaNode{
						"inet": {children: map[string]*schemaNode{
							"unicast": {children: map[string]*schemaNode{
								"prefix-limit": {children: map[string]*schemaNode{
									"maximum": {args: 1, children: nil},
								}},
							}},
						}},
						"inet6": {children: map[string]*schemaNode{
							"unicast": {children: map[string]*schemaNode{
								"prefix-limit": {children: map[string]*schemaNode{
									"maximum": {args: 1, children: nil},
								}},
							}},
						}},
					}},
					"bfd-liveness-detection": {children: map[string]*schemaNode{
						"minimum-interval": {args: 1, children: nil},
						"multiplier":       {args: 1, children: nil},
					}},
				}},
			}},
		}},
		"rip": {children: map[string]*schemaNode{
			"group":               {args: 1, children: nil},
			"neighbor":            {args: 1, valueHint: ValueHintInterfaceName, children: nil},
			"passive-interface":   {args: 1, valueHint: ValueHintInterfaceName, children: nil},
			"redistribute":        {args: 1, children: nil},
			"authentication-key":  {args: 1, children: nil},
			"authentication-type": {args: 1, children: nil},
		}},
		"isis": {children: map[string]*schemaNode{
			"net":     {args: 1, children: nil},
			"level":   {args: 1, children: nil},
			"is-type": {args: 1, children: nil},
			"export":  {args: 1, multi: true, children: nil},
			"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
				"level":               {args: 1, children: nil},
				"passive":             {children: nil},
				"metric":              {args: 1, children: nil},
				"authentication-key":  {args: 1, children: nil},
				"authentication-type": {args: 1, children: nil},
				"bfd-liveness-detection": {children: map[string]*schemaNode{
					"minimum-interval": {args: 1, children: nil},
					"multiplier":       {args: 1, children: nil},
				}},
			}},
			"authentication-key":  {args: 1, children: nil},
			"authentication-type": {args: 1, children: nil},
			"wide-metrics-only":   {children: nil},
			"overload":            {children: nil},
		}},
		"router-advertisement": {children: map[string]*schemaNode{
			"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
				"prefix":     {args: 1, children: nil}, // prefix <prefix/len>
				"preference": {args: 1, children: nil},
				"nat-prefix": {args: 1, children: map[string]*schemaNode{
					"lifetime": {args: 1, children: nil},
				}},
				"nat64prefix": {args: 1, children: map[string]*schemaNode{
					"lifetime": {args: 1, children: nil},
				}},
			}},
		}},
		"lldp": {children: map[string]*schemaNode{
			"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
				"disable": {children: nil},
			}},
			"transmit-interval": {args: 1, children: nil},
			"hold-multiplier":   {args: 1, children: nil},
			"disable":           {children: nil},
		}},
	}},
	"event-options": {children: map[string]*schemaNode{
		"policy": {args: 1, children: map[string]*schemaNode{
			"events": {children: nil},
			"within": {args: 1, children: map[string]*schemaNode{
				"trigger": {children: nil},
			}},
			"attributes-match": {children: nil},
			"then": {children: map[string]*schemaNode{
				"change-configuration": {children: map[string]*schemaNode{
					"commands": {children: nil},
				}},
			}},
		}},
	}},
	"chassis": {children: map[string]*schemaNode{
		"cluster": {children: map[string]*schemaNode{
			"cluster-id":            {args: 1, children: nil},
			"node":                  {args: 1, children: nil},
			"reth-count":            {args: 1, children: nil},
			"heartbeat-interval":    {args: 1, children: nil},
			"heartbeat-threshold":   {args: 1, children: nil},
			"control-link-recovery": {children: nil},
			"control-ports": {children: map[string]*schemaNode{
				"fpc": {args: 1, children: map[string]*schemaNode{
					"port": {args: 1, children: nil},
				}},
			}},
			"control-interface":             {args: 1, children: nil},
			"peer-address":                  {args: 1, children: nil},
			"fabric-interface":              {args: 1, children: nil},
			"fabric-peer-address":           {args: 1, children: nil},
			"configuration-synchronize":     {children: nil},
			"nat-state-synchronization":     {children: nil},
			"ipsec-session-synchronization": {children: nil},
			"reth-advertise-interval":       {args: 1, children: nil},
			"hitless-restart":               {children: nil},
			"peer-fencing":                  {args: 1, children: nil},
			"takeover-hold-time":            {args: 1, children: nil},
			"no-reth-vrrp":                  {children: nil},
			"private-rg-election":           {children: nil},
			"no-private-rg-election":        {children: nil},
			"redundancy-group": {args: 1, children: map[string]*schemaNode{
				"node": {args: 1, children: map[string]*schemaNode{
					"priority": {args: 1, children: nil},
				}},
				"gratuitous-arp-count": {args: 1, children: nil},
				"preempt":              {children: nil},
				"interface-monitor":    {children: nil},
				"ip-monitoring": {children: map[string]*schemaNode{
					"global-weight":    {args: 1, children: nil},
					"global-threshold": {args: 1, children: nil},
					"family": {compoundKey: true, children: map[string]*schemaNode{
						"inet": {wildcard: &schemaNode{children: map[string]*schemaNode{
							"weight": {args: 1, children: nil},
						}}},
					}},
				}},
			}},
		}},
	}},
	"class-of-service": {children: map[string]*schemaNode{
		"forwarding-classes": {children: map[string]*schemaNode{
			"queue": {args: 2, multi: true, children: nil},
		}},
		"classifiers": {children: map[string]*schemaNode{
			"dscp": {args: 1, multi: true, children: map[string]*schemaNode{
				"forwarding-class": {args: 1, multi: true, children: map[string]*schemaNode{
					"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
						"code-points": {args: 1, multi: true, children: nil},
					}},
				}},
			}},
			"ieee-802.1": {args: 1, multi: true, children: map[string]*schemaNode{
				"forwarding-class": {args: 1, multi: true, children: map[string]*schemaNode{
					"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
						"code-points": {args: 1, multi: true, children: nil},
					}},
				}},
			}},
		}},
		"rewrite-rules": {children: map[string]*schemaNode{
			"dscp": {args: 1, multi: true, children: map[string]*schemaNode{
				"forwarding-class": {args: 1, multi: true, children: map[string]*schemaNode{
					"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
						"code-point":  {args: 1, children: nil},
						"code-points": {args: 1, multi: true, children: nil},
					}},
				}},
			}},
		}},
		"schedulers": {args: 1, multi: true, children: map[string]*schemaNode{
			"transmit-rate": {args: 1, children: map[string]*schemaNode{
				"exact": {children: nil},
			}},
			"priority":        {args: 1, children: nil},
			"buffer-size":     {args: 1, children: nil},
			"surplus-sharing": {children: nil}, // #915
		}},
		"scheduler-maps": {args: 1, multi: true, children: map[string]*schemaNode{
			"forwarding-class": {args: 1, multi: true, children: map[string]*schemaNode{
				"scheduler": {args: 1, children: nil},
			}},
		}},
		"interfaces": {args: 1, multi: true, children: map[string]*schemaNode{
			"unit": {args: 1, multi: true, children: map[string]*schemaNode{
				"classifiers": {children: map[string]*schemaNode{
					"dscp":       {args: 1, children: nil},
					"ieee-802.1": {args: 1, children: nil},
				}},
				"rewrite-rules": {children: map[string]*schemaNode{
					"dscp": {args: 1, children: nil},
				}},
				"shaping-rate": {args: 1, children: map[string]*schemaNode{
					"burst-size": {args: 1, children: nil},
				}},
				"scheduler-map": {args: 1, children: nil},
			}},
		}},
	}},
	"firewall": {children: map[string]*schemaNode{
		"policer": {args: 1, multi: true, children: map[string]*schemaNode{
			"if-exceeding": {children: map[string]*schemaNode{
				"bandwidth-limit":  {args: 1, children: nil},
				"burst-size-limit": {args: 1, children: nil},
			}},
			"logical-interface-policer": {children: nil},
			"then": {children: map[string]*schemaNode{
				"discard":       {children: nil},
				"loss-priority": {args: 1, children: nil},
			}},
		}},
		"three-color-policer": {args: 1, multi: true, children: map[string]*schemaNode{
			"single-rate": {children: map[string]*schemaNode{
				"color-blind":                {children: nil},
				"color-aware":                {children: nil},
				"committed-information-rate": {args: 1, children: nil},
				"committed-burst-size":       {args: 1, children: nil},
				"excess-burst-size":          {args: 1, children: nil},
			}},
			"two-rate": {children: map[string]*schemaNode{
				"color-blind":                {children: nil},
				"color-aware":                {children: nil},
				"committed-information-rate": {args: 1, children: nil},
				"committed-burst-size":       {args: 1, children: nil},
				"peak-information-rate":      {args: 1, children: nil},
				"peak-burst-size":            {args: 1, children: nil},
			}},
			"then": {children: map[string]*schemaNode{
				"discard":       {children: nil},
				"loss-priority": {args: 1, children: nil},
			}},
		}},
		"family": {compoundKey: true, children: map[string]*schemaNode{
			"inet": {children: map[string]*schemaNode{
				"filter": {args: 1, children: map[string]*schemaNode{
					"term": {args: 1, children: map[string]*schemaNode{
						"from": {children: map[string]*schemaNode{
							"source-address":          {args: 1, multi: true, children: nil},
							"destination-address":     {args: 1, multi: true, children: nil},
							"source-prefix-list":      {children: nil},
							"destination-prefix-list": {children: nil},
							"protocol":                {args: 1, multi: true, children: nil},
							"dscp":                    {args: 1, multi: true, children: nil},
							"destination-port":        {args: 1, multi: true, children: nil},
							"source-port":             {args: 1, multi: true, children: nil},
							"icmp-type":               {args: 1, multi: true, children: nil},
							"icmp-code":               {args: 1, multi: true, children: nil},
							"tcp-flags":               {args: 1, multi: true, children: nil},
							"is-fragment":             {children: nil},
							"flexible-match-range": {children: map[string]*schemaNode{
								"range": {args: 1, children: map[string]*schemaNode{
									"match-start": {args: 1, children: nil},
									"byte-offset": {args: 1, children: nil},
									"bit-length":  {args: 1, children: nil},
									"range":       {args: 1, children: nil},
									"match-value": {args: 1, children: nil},
									"match-mask":  {args: 1, children: nil},
								}},
							}},
						}},
						"then": {children: map[string]*schemaNode{
							"accept":           {children: nil},
							"reject":           {children: nil},
							"discard":          {children: nil},
							"log":              {children: nil},
							"syslog":           {children: nil},
							"routing-instance": {args: 1, children: nil},
							"count":            {args: 1, children: nil},
							"forwarding-class": {args: 1, children: nil},
							"loss-priority":    {args: 1, children: nil},
							"dscp":             {args: 1, children: nil},
							"traffic-class":    {args: 1, children: nil},
							"policer":          {args: 1, children: nil},
						}},
					}},
				}},
			}},
			"inet6": {children: map[string]*schemaNode{
				"filter": {args: 1, children: map[string]*schemaNode{
					"term": {args: 1, children: map[string]*schemaNode{
						"from": {children: map[string]*schemaNode{
							"source-address":          {args: 1, multi: true, children: nil},
							"destination-address":     {args: 1, multi: true, children: nil},
							"source-prefix-list":      {children: nil},
							"destination-prefix-list": {children: nil},
							"protocol":                {args: 1, multi: true, children: nil},
							"traffic-class":           {args: 1, multi: true, children: nil},
							"destination-port":        {args: 1, multi: true, children: nil},
							"source-port":             {args: 1, multi: true, children: nil},
							"icmp-type":               {args: 1, multi: true, children: nil},
							"icmp-code":               {args: 1, multi: true, children: nil},
							"tcp-flags":               {args: 1, multi: true, children: nil},
							"is-fragment":             {children: nil},
							"flexible-match-range": {children: map[string]*schemaNode{
								"range": {args: 1, children: map[string]*schemaNode{
									"match-start": {args: 1, children: nil},
									"byte-offset": {args: 1, children: nil},
									"bit-length":  {args: 1, children: nil},
									"range":       {args: 1, children: nil},
									"match-value": {args: 1, children: nil},
									"match-mask":  {args: 1, children: nil},
								}},
							}},
						}},
						"then": {children: map[string]*schemaNode{
							"accept":           {children: nil},
							"reject":           {children: nil},
							"discard":          {children: nil},
							"log":              {children: nil},
							"syslog":           {children: nil},
							"routing-instance": {args: 1, children: nil},
							"count":            {args: 1, children: nil},
							"forwarding-class": {args: 1, children: nil},
							"loss-priority":    {args: 1, children: nil},
							"dscp":             {args: 1, children: nil},
							"traffic-class":    {args: 1, children: nil},
							"policer":          {args: 1, children: nil},
						}},
					}},
				}},
			}},
		}},
	}},
	"system": {children: map[string]*schemaNode{
		"host-name":     {args: 1, children: nil},
		"domain-name":   {args: 1, children: nil},
		"domain-search": {args: 1, multi: true, children: nil},
		"time-zone":     {args: 1, children: nil},
		"no-redirects":  {children: nil},
		"name-server":   {children: nil},
		"backup-router": {args: 1, children: map[string]*schemaNode{
			"destination": {args: 1, children: nil},
		}},
		"root-authentication": {children: map[string]*schemaNode{
			"encrypted-password": {args: 1, children: nil},
			"ssh-ed25519":        {args: 1, children: nil},
			"ssh-rsa":            {args: 1, children: nil},
			"ssh-dsa":            {args: 1, children: nil},
		}},
		"archival": {children: map[string]*schemaNode{
			"configuration": {children: map[string]*schemaNode{
				"transfer-on-commit": {children: nil},
				"archive-sites":      {args: 1, children: nil},
			}},
		}},
		"master-password": {children: map[string]*schemaNode{
			"pseudorandom-function": {args: 1, children: nil},
		}},
		"license": {children: map[string]*schemaNode{
			"autoupdate": {children: map[string]*schemaNode{
				"url": {args: 1, children: nil},
			}},
		}},
		"processes": {children: nil},
		"internet-options": {children: map[string]*schemaNode{
			"no-ipv6-reject-zero-hop-limit": {children: nil},
		}},
		"ntp": {children: map[string]*schemaNode{
			"server": {args: 1, children: nil},
			"threshold": {args: 1, children: map[string]*schemaNode{
				"action": {args: 1, children: nil},
			}},
		}},
		"syslog": {children: map[string]*schemaNode{
			"user": {args: 1, children: nil},
			"host": {args: 1, children: nil},
			"file": {args: 1, children: nil},
		}},
		"login": {children: map[string]*schemaNode{
			"user": {args: 1, children: map[string]*schemaNode{
				"uid":            {args: 1, children: nil},
				"class":          {args: 1, children: nil},
				"authentication": {children: nil},
			}},
		}},
		"dataplane-type": {args: 1, children: nil},
		"dataplane": {desc: "Dataplane configuration", children: map[string]*schemaNode{
			"cores":          {args: 1, desc: "Number of dataplane cores", children: nil},
			"memory":         {args: 1, desc: "Dataplane memory allocation", children: nil},
			"socket-mem":     {args: 1, desc: "DPDK socket memory", children: nil},
			"binary":         {args: 1, desc: "Userspace dataplane helper binary path", children: nil},
			"control-socket": {args: 1, desc: "Unix control socket path", children: nil},
			"state-file":     {args: 1, desc: "Helper state file path", children: nil},
			"workers":        {args: 1, desc: "Worker thread count", children: nil},
			"ring-entries":   {args: 1, desc: "AF_XDP ring entries per queue", children: nil},
			"poll-mode":      {args: 1, desc: "Worker poll mode (busy-poll or interrupt)", children: nil},
			"rss-indirection":     {args: 1, desc: "mlx5 RSS indirection reshaping (enable|disable)", children: nil},
			"claim-host-tunables": {args: 1, desc: "Allow xpfd to write host-scope tunables (true|false, default false)", children: nil},
			"cpu-governor":        {args: 1, desc: "Host cpufreq governor (performance|schedutil|default)", children: nil},
			"netdev-budget":       {args: 1, desc: "net.core.netdev_budget value", children: nil},
			"coalescence": {desc: "NIC interrupt-coalescence tuning (mlx5)", children: map[string]*schemaNode{
				"adaptive": {args: 1, desc: "Adaptive coalescing (enable|disable)", children: nil},
				"rx-usecs": {args: 1, desc: "RX coalescing µs", children: nil},
				"tx-usecs": {args: 1, desc: "TX coalescing µs", children: nil},
			}},
			"rx-mode": {children: map[string]*schemaNode{
				"idle-threshold":   {args: 1, children: nil},
				"resume-threshold": {args: 1, children: nil},
				"sleep-timeout":    {args: 1, children: nil},
			}},
			"ports": {wildcard: &schemaNode{children: map[string]*schemaNode{
				"interface": {args: 1, children: nil},
				"rx-mode":   {args: 1, children: nil},
				"cores":     {args: 1, children: nil},
			}}},
		}},
		"services": {children: map[string]*schemaNode{
			"ssh": {children: map[string]*schemaNode{
				"root-login": {args: 1, children: nil},
			}},
			"web-management": {children: map[string]*schemaNode{
				"http": {children: map[string]*schemaNode{
					"interface": {args: 1, children: nil},
				}},
				"https": {children: map[string]*schemaNode{
					"system-generated-certificate": {children: nil},
					"interface":                    {args: 1, children: nil},
				}},
				"api-auth": {children: map[string]*schemaNode{
					"user": {wildcard: &schemaNode{children: map[string]*schemaNode{
						"password": {args: 1, children: nil},
					}}},
					"api-key": {args: 1, children: nil},
				}},
			}},
			"dns": {children: nil},
			"dhcp-local-server": {children: map[string]*schemaNode{
				"group": {args: 1, children: map[string]*schemaNode{
					"pool": {args: 1, children: nil},
				}},
			}},
			"dhcpv6-local-server": {children: map[string]*schemaNode{
				"group": {args: 1, children: map[string]*schemaNode{
					"pool": {args: 1, children: nil},
				}},
			}},
		}},
	}},
	"services": {children: map[string]*schemaNode{
		"rpm": {desc: "Real-time Performance Monitoring probes", children: map[string]*schemaNode{
			"probe-limit": {args: 1, desc: "Default maximum consecutive failed probes before stopping a test cycle", children: nil},
			"probe": {args: 1, desc: "RPM probe name", children: map[string]*schemaNode{
				"test": {args: 1, desc: "RPM test name", children: map[string]*schemaNode{
					"probe-type":       {args: 1, desc: "Probe type: icmp-ping, tcp-ping, or http-get", children: nil},
					"target":           {desc: "Target IP, hostname, or URL", wildcard: &schemaNode{placeholder: "<target>", desc: "Target IP, hostname, or URL"}, children: map[string]*schemaNode{"url": {args: 1, desc: "HTTP target URL", children: nil}}},
					"source-address":   {args: 1, desc: "Source address for the probe", children: nil},
					"routing-instance": {args: 1, desc: "Routing instance / VRF for the probe", children: nil},
					"probe-interval":   {args: 1, desc: "Seconds between probes within a test", children: nil},
					"probe-count":      {args: 1, desc: "Number of probes per test cycle", children: nil},
					"test-interval":    {args: 1, desc: "Seconds between test cycles", children: nil},
					"thresholds": {desc: "Failure thresholds for the test", children: map[string]*schemaNode{
						"successive-loss": {args: 1, desc: "Consecutive losses before marking the test failed", children: nil},
					}},
					"probe-limit":      {args: 1, desc: "Maximum consecutive failed probes before stopping the current test cycle", children: nil},
					"destination-port": {args: 1, desc: "Destination TCP port for tcp-ping probes", children: nil},
				}},
			}},
		}},
		"flow-monitoring": {children: map[string]*schemaNode{
			"version9": {children: map[string]*schemaNode{
				"template": {args: 1, children: map[string]*schemaNode{
					"flow-active-timeout":   {args: 1, children: nil},
					"flow-inactive-timeout": {args: 1, children: nil},
					"template-refresh-rate": {children: map[string]*schemaNode{
						"seconds": {args: 1, children: nil},
					}},
				}},
			}},
			"version-ipfix": {children: map[string]*schemaNode{
				"template": {args: 1, children: map[string]*schemaNode{
					"flow-active-timeout":   {args: 1, children: nil},
					"flow-inactive-timeout": {args: 1, children: nil},
					"template-refresh-rate": {children: map[string]*schemaNode{
						"seconds": {args: 1, children: nil},
					}},
					"ipv4-template": {children: map[string]*schemaNode{
						"export-extension": {args: 1, children: nil},
					}},
					"ipv6-template": {children: map[string]*schemaNode{
						"export-extension": {args: 1, children: nil},
					}},
				}},
			}},
		}},
		"application-identification": {children: nil},
	}},
	"forwarding-options": {children: map[string]*schemaNode{
		"family": {compoundKey: true, children: map[string]*schemaNode{
			"inet6": {children: map[string]*schemaNode{
				"mode": {args: 1, children: nil},
			}},
		}},
		"sampling": {children: map[string]*schemaNode{
			"instance": {args: 1, children: map[string]*schemaNode{
				"input": {children: nil},
				"family": {compoundKey: true, children: map[string]*schemaNode{
					"inet": {children: map[string]*schemaNode{
						"output": {children: map[string]*schemaNode{
							"flow-server":  {args: 1, children: nil},
							"inline-jflow": {children: nil},
						}},
					}},
					"inet6": {children: map[string]*schemaNode{
						"output": {children: map[string]*schemaNode{
							"flow-server":  {args: 1, children: nil},
							"inline-jflow": {children: nil},
						}},
					}},
				}},
			}},
		}},
		"port-mirroring": {children: map[string]*schemaNode{
			"instance": {args: 1, children: map[string]*schemaNode{
				"input": {children: map[string]*schemaNode{
					"ingress": {children: nil},
				}},
				"output": {children: nil},
			}},
		}},
	}},
	"bridge-domains": {wildcard: &schemaNode{desc: "Bridge domain name", children: map[string]*schemaNode{
		"vlan-id-list":      {args: 1, multi: true, desc: "VLAN IDs in this bridge domain", children: nil},
		"routing-interface": {args: 1, desc: "IRB routing interface (e.g. irb.0)", children: nil},
		"domain-type":       {args: 1, desc: "Bridge domain type", children: nil},
	}}},
	"routing-instances": {wildcard: &schemaNode{children: map[string]*schemaNode{
		// instance-type and interface are NOT listed here → they become leaf nodes
		// e.g. "instance-type virtual-router;" and "interface enp7s0;"
		"routing-options": {children: map[string]*schemaNode{
			"static": {children: map[string]*schemaNode{
				"route": {args: 1, children: nil},
			}},
			"rib": {args: 1, children: map[string]*schemaNode{
				"static": {children: map[string]*schemaNode{
					"route": {args: 1, children: nil},
				}},
			}},
			"interface-routes": {children: map[string]*schemaNode{
				"rib-group": {children: map[string]*schemaNode{
					"inet":  {args: 1, children: nil},
					"inet6": {args: 1, children: nil},
				}},
			}},
		}},
		"protocols": {children: map[string]*schemaNode{
			"ospf": {children: map[string]*schemaNode{
				"reference-bandwidth": {args: 1, children: nil},
				"passive":             {children: nil},
				"area": {args: 1, children: map[string]*schemaNode{
					"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
						"passive":        {children: nil},
						"no-passive":     {children: nil},
						"interface-type": {args: 1, children: nil},
						"cost":           {args: 1, children: nil},
						"authentication": {children: map[string]*schemaNode{
							"md5": {args: 1, children: map[string]*schemaNode{
								"key": {args: 1, children: nil},
							}},
							"simple-password": {args: 1, children: nil},
						}},
						"bfd-liveness-detection": {children: map[string]*schemaNode{
							"minimum-interval": {args: 1, children: nil},
							"multiplier":       {args: 1, children: nil},
						}},
					}},
					"area-type": {children: map[string]*schemaNode{
						"stub": {children: map[string]*schemaNode{
							"no-summaries": {children: nil},
						}},
						"nssa": {children: map[string]*schemaNode{
							"no-summaries": {children: nil},
						}},
					}},
					"virtual-link": {args: 1, children: map[string]*schemaNode{
						"transit-area": {args: 1, children: nil},
					}},
				}},
			}},
			"ospf3": {children: map[string]*schemaNode{
				"router-id": {args: 1, children: nil},
				"export":    {args: 1, multi: true, children: nil},
				"area": {args: 1, children: map[string]*schemaNode{
					"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
						"passive": {children: nil},
						"cost":    {args: 1, children: nil},
					}},
				}},
			}},
			"bgp": {children: map[string]*schemaNode{
				"graceful-restart": {children: nil},
				"damping": {children: map[string]*schemaNode{
					"half-life":    {args: 1, children: nil},
					"reuse":        {args: 1, children: nil},
					"suppress":     {args: 1, children: nil},
					"max-suppress": {args: 1, children: nil},
				}},
				"group": {args: 1, children: nil},
			}},
			"isis": {children: map[string]*schemaNode{
				"net":     {args: 1, children: nil},
				"level":   {args: 1, children: nil},
				"is-type": {args: 1, children: nil},
				"export":  {args: 1, multi: true, children: nil},
				"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
					"level":               {args: 1, children: nil},
					"passive":             {children: nil},
					"metric":              {args: 1, children: nil},
					"authentication-key":  {args: 1, children: nil},
					"authentication-type": {args: 1, children: nil},
					"bfd-liveness-detection": {children: map[string]*schemaNode{
						"minimum-interval": {args: 1, children: nil},
						"multiplier":       {args: 1, children: nil},
					}},
				}},
				"authentication-key":  {args: 1, children: nil},
				"authentication-type": {args: 1, children: nil},
				"wide-metrics-only":   {children: nil},
				"overload":            {children: nil},
			}},
		}},
	}}},
}}

func init() {
	// Wire groups wildcard to mirror top-level schema children.
	// This allows "set groups <name> security ..." etc. to parse correctly.
	groupWild := setSchema.children["groups"].wildcard
	groupWild.children = make(map[string]*schemaNode)
	for k, v := range setSchema.children {
		if k == "groups" || k == "apply-groups" {
			continue
		}
		groupWild.children[k] = v
	}
}

// keysEqual returns true if two key slices are identical.
func keysEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// CompleteSetPath returns possible completions for a partial set/delete path.
// It walks setSchema consuming tokens; at the current position it returns
// child keyword names. If the current position expects a dynamic argument
// (wildcard or args > 0), it returns nil (user must type a name).
func CompleteSetPath(tokens []string) []string {
	results := CompleteSetPathWithValues(tokens, nil)
	if results == nil {
		return nil
	}
	names := make([]string, len(results))
	for i, r := range results {
		names[i] = r.Name
	}
	return names
}

// CompleteSetPathWithValues is like CompleteSetPath but uses a ValueProvider
// to suggest dynamic values at positions where schema expects a name argument.
// Returns SchemaCompletion pairs with names and descriptions.
func CompleteSetPathWithValues(tokens []string, provider ValueProvider) []SchemaCompletion {
	schema := setSchema
	i := 0
	var path []string // consumed tokens for context

	for i < len(tokens) {
		if schema == nil {
			return nil
		}
		if schema.children == nil && schema.wildcard == nil {
			return nil // at a leaf with no further options
		}

		keyword := tokens[i]

		// Look up keyword in current schema level.
		var childSchema *schemaNode
		resolvedKeyword := keyword
		if schema.children != nil {
			if s, ok := schema.children[keyword]; ok {
				childSchema = s
			} else {
				var matches []string
				for name := range schema.children {
					if strings.HasPrefix(name, keyword) {
						matches = append(matches, name)
					}
				}
				if len(matches) == 1 && i < len(tokens)-1 {
					resolvedKeyword = matches[0]
					childSchema = schema.children[resolvedKeyword]
				} else if len(matches) > 0 && i == len(tokens)-1 {
					var completions []SchemaCompletion
					for _, name := range matches {
						completions = append(completions, SchemaCompletion{Name: name, Desc: schema.children[name].desc})
					}
					return completions
				}
			}
		}
		if childSchema == nil && schema.wildcard != nil {
			childSchema = schema.wildcard
		}
		if childSchema == nil {
			// Last token might be a partial prefix — return matching keywords.
			if i == len(tokens)-1 && schema.children != nil {
				var matches []SchemaCompletion
				for name, node := range schema.children {
					if strings.HasPrefix(name, keyword) {
						matches = append(matches, SchemaCompletion{Name: name, Desc: node.desc})
					}
				}
				if len(matches) > 0 {
					return matches
				}
			}
			return nil // unknown keyword, no completions
		}

		// Consume keyword + extra args.
		nodeKeyCount := 1 + childSchema.args
		end := i + nodeKeyCount
		if end > len(tokens) {
			end = len(tokens)
		}
		path = append(path, resolvedKeyword)
		if end-i > 1 {
			path = append(path, tokens[i+1:end]...)
		}
		i += nodeKeyCount

		// Compound key: consume child token as part of key.
		if childSchema.compoundKey && i < len(tokens) {
			if sub, ok := childSchema.children[tokens[i]]; ok {
				path = append(path, tokens[i])
				i++
				childSchema = sub
			}
		}

		if i > len(tokens) {
			// Still consuming args for this node — user needs to type a value.
			startIdx := i - nodeKeyCount
			consumed := end - startIdx // tokens consumed for this node (including keyword)

			// Check for fixed keyword in the middle of args (e.g., "to-zone" in "from-zone X to-zone Y").
			if childSchema.midKeyword != "" && childSchema.midKeywordAt > 0 {
				nextPos := consumed // 0-indexed position to complete next (0=keyword, 1=arg1, ...)
				// If the last consumed token is a partial match for the midKeyword, suggest it.
				if nextPos == childSchema.midKeywordAt+1 && consumed > 1 {
					lastToken := tokens[end-1]
					if lastToken != childSchema.midKeyword && strings.HasPrefix(childSchema.midKeyword, lastToken) {
						return []SchemaCompletion{{Name: childSchema.midKeyword, Desc: "Destination zone"}}
					}
				}
				// If we need to complete the midKeyword position, suggest it.
				if nextPos == childSchema.midKeywordAt {
					return []SchemaCompletion{{Name: childSchema.midKeyword, Desc: "Destination zone"}}
				}
			}

			// Try to provide dynamic values via the provider.
			if provider != nil && childSchema.valueHint != ValueHintNone {
				results := provider(childSchema.valueHint, path)
				// Add placeholder if available.
				if childSchema.placeholder != "" {
					results = append([]SchemaCompletion{{Name: childSchema.placeholder, Desc: childSchema.desc}}, results...)
				}
				return results
			}
			// No provider but have a placeholder — show it.
			if childSchema.placeholder != "" {
				return []SchemaCompletion{{Name: childSchema.placeholder, Desc: childSchema.desc}}
			}
			return nil
		}

		if childSchema.multi && childSchema.children == nil {
			// Stay at current schema level so sibling keywords are offered.
		} else {
			schema = childSchema
		}
	}

	// We've consumed all tokens. Return child keywords at this schema level.
	if schema == nil {
		return nil
	}

	// If we're at a leaf with no children/wildcard, hint that Enter completes.
	if schema.children == nil && schema.wildcard == nil {
		return []SchemaCompletion{{Name: "<[Enter]>", Desc: "Execute this command"}}
	}

	var completions []SchemaCompletion
	if schema.children != nil {
		for name, node := range schema.children {
			completions = append(completions, SchemaCompletion{Name: name, Desc: node.desc})
		}
	}
	// If this level accepts a wildcard name, provide dynamic values too.
	if schema.wildcard != nil {
		if provider != nil && schema.wildcard.valueHint != ValueHintNone {
			completions = append(completions, provider(schema.wildcard.valueHint, path)...)
		}
		// Add placeholder.
		if schema.wildcard.placeholder != "" {
			completions = append(completions, SchemaCompletion{Name: schema.wildcard.placeholder, Desc: schema.wildcard.desc})
		}
	}
	if len(completions) == 0 {
		return nil
	}
	return completions
}

// ResolveConsumedSetPathTokens expands uniquely matching keyword prefixes in a
// token list that is already known to contain only consumed words, not the
// current partial token being completed.
func ResolveConsumedSetPathTokens(tokens []string) ([]string, bool) {
	schema := setSchema
	i := 0
	var resolved []string

	for i < len(tokens) {
		if schema == nil {
			return nil, false
		}

		keyword := tokens[i]
		resolvedKeyword := keyword
		var childSchema *schemaNode
		if schema.children != nil {
			if s, ok := schema.children[keyword]; ok {
				childSchema = s
			} else {
				var matches []string
				for name := range schema.children {
					if strings.HasPrefix(name, keyword) {
						matches = append(matches, name)
					}
				}
				if len(matches) != 1 {
					return nil, false
				}
				resolvedKeyword = matches[0]
				childSchema = schema.children[resolvedKeyword]
			}
		}
		if childSchema == nil && schema.wildcard != nil {
			childSchema = schema.wildcard
		}
		if childSchema == nil {
			return nil, false
		}

		resolved = append(resolved, resolvedKeyword)
		nodeKeyCount := 1 + childSchema.args
		end := i + nodeKeyCount
		if end > len(tokens) {
			return resolved, true
		}
		if end-i > 1 {
			resolved = append(resolved, tokens[i+1:end]...)
		}
		i += nodeKeyCount

		if childSchema.compoundKey && i < len(tokens) {
			subKeyword := tokens[i]
			if sub, ok := childSchema.children[subKeyword]; ok {
				resolved = append(resolved, subKeyword)
				i++
				childSchema = sub
			} else {
				var matches []string
				for name := range childSchema.children {
					if strings.HasPrefix(name, subKeyword) {
						matches = append(matches, name)
					}
				}
				if len(matches) != 1 {
					return nil, false
				}
				resolved = append(resolved, matches[0])
				i++
				childSchema = childSchema.children[matches[0]]
			}
		}

		if childSchema.multi && childSchema.children == nil {
			continue
		}
		schema = childSchema
	}

	return resolved, true
}
