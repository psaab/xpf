package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #11770: both rule-set dispatchers read only args[1]. Extra arguments must
// fail rather than silently running the command named by that first value.
func TestShowNATRuleSetDispatchRejectsExtraArguments11770(t *testing.T) {
	c := &CLI{dp: dataplane.New()}
	cfg := sharedNATFixture()
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"source", func() error { return c.showNATSource(cfg, []string{"rule-set", "rs-src", "junk"}) }},
		{"destination", func() error { return c.showNATDestination(cfg, []string{"rule-set", "rs-dst", "junk"}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); err == nil {
				t.Fatal("extra rule-set argument was silently ignored")
			}
		})
	}
}
