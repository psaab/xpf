package ra

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15058 (A26-04), second leg: Manager.Apply built its desired map with
// `desired[cfg.Interface] = cfg` — last-wins with no signal. Two configs
// naming the same interface (as buildRAConfigs could produce before its
// merge key was resolved) silently dropped the first config's options.
// Apply must refuse duplicates so no caller can silently lose an RA config.

func TestApply15058RejectsDuplicateInterface(t *testing.T) {
	fl := newFakeListen(t)
	m := New()
	t.Cleanup(func() { _ = m.Clear() })

	staticCfg := &config.RAInterfaceConfig{
		Interface:     "lo",
		ManagedConfig: true,
		DNSServers:    []string{"2001:db8::53"},
		Prefixes: []*config.RAPrefix{
			{Prefix: "2001:db8:1::/64", OnLink: true, Autonomous: true},
		},
	}
	pdCfg := &config.RAInterfaceConfig{
		Interface: "lo",
		Prefixes: []*config.RAPrefix{
			{Prefix: "2001:db8:aaaa::/64", OnLink: true, Autonomous: true},
		},
	}
	err := m.Apply([]*config.RAInterfaceConfig{staticCfg, pdCfg})
	if err == nil {
		t.Fatalf("Apply accepted two configs for interface %q; the first would be silently dropped (last-wins)", "lo")
	}
	// Nothing must have been started for the ambiguous interface.
	if got := fl.liveCount(); got != 0 {
		t.Fatalf("Apply started %d conns despite rejecting duplicates, want 0", got)
	}
	m.mu.Lock()
	started := len(m.senders)
	m.mu.Unlock()
	if started != 0 {
		t.Fatalf("Apply left %d senders despite rejecting duplicates, want 0", started)
	}

	// Control: a single config for the interface still applies.
	if err := m.Apply([]*config.RAInterfaceConfig{staticCfg}); err != nil {
		t.Fatalf("Apply(single config) = %v, want nil", err)
	}
	_ = waitConn(t, fl.getConn, "lo")
}
