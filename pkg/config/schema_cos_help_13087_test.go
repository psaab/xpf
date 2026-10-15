package config

import (
	"strings"
	"testing"
)

// #13087 (D7-06): CoS help strings must not claim resolved forms are
// inert. transmit-rate percent/remainder, buffer-size temporal, and
// shaping-rate percent all resolve at commit
// (compiler_cos_rate_resolve.go).
func TestCoSHelpStringsDoNotClaimUnresolved13087(t *testing.T) {
	var walk func(n *schemaNode, path string)
	walk = func(n *schemaNode, path string) {
		if n == nil {
			return
		}
		// Only the four D7-06 forms (transmit-rate percent/remainder,
		// buffer-size temporal, shaping-rate percent) — the 802.1
		// rewrite note is a separate, accurate statement.
		if strings.Contains(n.desc, "NOT yet resolved") {
			t.Errorf("%s: help still claims unresolved: %q", path, n.desc)
		}
		if strings.Contains(n.desc, "percent accepted-but-inert") {
			t.Errorf("%s: help still claims inert percent: %q", path, n.desc)
		}
		for name, child := range n.children {
			walk(child, path+" "+name)
		}
	}
	walk(schemaClassOfService, "class-of-service")
}
