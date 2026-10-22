// #9326: `security log stream <s> host` was an UNTYPED schema leaf — `args: 1`,
// no valueType, no validator — so any string an operator typed was carried
// straight to `net.Dial`'s resolver on the commit path, including one that is
// not a hostname at all.
//
// The dial is now deferred for TCP/TLS and bounded for UDP, so this leaf is no
// longer the only thing between a typo and a stalled commit. It is the half
// that returns the error where the operator can act on it — at commit, naming
// the leaf — rather than as a resolver failure logged later from a background
// warm.

package config

import "testing"

func TestSyslogHostLeafIsTyped9326(t *testing.T) {
	for _, tc := range []struct {
		name, host string
		wantErr    bool
	}{
		{"ipv4 literal", "192.0.2.10", false},
		{"ipv6 literal", "2001:db8::1", false},
		{"hostname", "logs.example.net", false},
		{"single label", "collector", false},
		// The shapes that used to reach the resolver.
		{"embedded space", "logs.example.net evil", true},
		{"not a name at all", "http://logs.example.net/", true},
		{"embedded newline", "logs.example.net\nmore", true},
		{"empty", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSyslogHost(tc.host)
			if tc.wantErr && err == nil {
				t.Errorf("#9326: host %q must be REFUSED at commit; it was accepted and "+
					"would be handed to the dialer's resolver", tc.host)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("host %q is a legitimate syslog target and must be accepted; "+
					"got %v", tc.host, err)
			}
		})
	}
}

// The validator has to be WIRED to the leaf, not merely exist. A validator
// nothing calls is the shape this issue is about: the leaf stayed untyped for
// as long as it did because everything around it looked configured.
func TestSyslogHostLeafWiring9326(t *testing.T) {
	node := setSchema
	for _, k := range []string{"security", "log", "stream", "host"} {
		if node == nil || node.children == nil {
			t.Fatalf("schema path security log stream host does not resolve (stopped at %q)", k)
		}
		node = node.children[k]
	}
	if node == nil {
		t.Fatal("no `security log stream host` leaf in setSchema")
	}
	if node.validator == nil {
		t.Fatal("#9326: the `security log stream <s> host` leaf has NO validator, so any " +
			"string reaches the dialer's resolver on the commit path")
	}
	if node.valueType == ValueAny {
		t.Error("#9326: the leaf carries no valueType, so `?` completion and the " +
			"commit-check typed-leaf walk both treat it as free-form")
	}
	// The validator wired must be the one that admits addresses AND names: a
	// stricter one (IP-only) would refuse `logs.example.net`, which is the
	// common configuration.
	if err := node.validator("logs.example.net"); err != nil {
		t.Errorf("the wired validator refuses a plain hostname (%v) — a syslog target "+
			"is routinely a name, and refusing it would be a worse defect than the "+
			"untyped leaf", err)
	}
}
