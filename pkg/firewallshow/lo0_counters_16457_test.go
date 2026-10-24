package firewallshow

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #16457 acceptance fixture: an injected Lo0Count{ssh-deny: 42} for a
// lo0-referenced filter renders 42, labelled by count name; a non-lo0
// filter never invokes the lookup and renders nothing.
func TestLo0CountersForFilter16457(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.Lo0FilterInputV4 = "protect-re"
	cfg.System.Lo0FilterInputV6 = "protect-re6"
	filter := &config.FirewallFilter{Name: "protect-re", Terms: []*config.FirewallFilterTerm{
		{Name: "ssh", Count: "ssh-deny", Action: config.FilterActionDiscard},
		{Name: "other", Count: "other-count", Action: config.FilterActionAccept},
	}}

	calls := 0
	lookup := func() ([]xnft.Lo0Count, error) {
		calls++
		return []xnft.Lo0Count{
			{Counter: "ssh-deny", Packets: 42, Bytes: 4200},
			{Counter: "unrelated", Packets: 9, Bytes: 900},
		}, nil
	}

	counts, err := Lo0CountersForFilter(cfg, "inet", "protect-re", lookup)
	if err != nil {
		t.Fatalf("Lo0CountersForFilter: %v", err)
	}
	if calls != 1 {
		t.Fatalf("lookup calls = %d, want 1", calls)
	}
	var buf strings.Builder
	WriteLo0KernelCounters(&buf, filter, counts)
	out := buf.String()
	if !strings.Contains(out, "Kernel lo0 counter ssh-deny: 42 packets, 4200 bytes") {
		t.Fatalf("output = %q, want injected ssh-deny 42 rendered", out)
	}
	if strings.Contains(out, "unrelated") {
		t.Fatalf("output = %q, unreferenced count name must not render", out)
	}
	if strings.Contains(out, "other-count") {
		t.Fatalf("output = %q, count with no kernel object must not render", out)
	}

	// Non-lo0 filter: lookup untouched, nothing rendered (unchanged view).
	counts, err = Lo0CountersForFilter(cfg, "inet", "edge-filter", lookup)
	if err != nil || counts != nil {
		t.Fatalf("non-lo0 = (%v, %v), want (nil, nil)", counts, err)
	}
	if calls != 1 {
		t.Fatalf("lookup calls = %d after non-lo0, want 1 (no netlink read)", calls)
	}

	// Wrong family binding: protect-re is v4-only here.
	counts, err = Lo0CountersForFilter(cfg, "inet6", "protect-re", lookup)
	if err != nil || counts != nil || calls != 1 {
		t.Fatalf("wrong-family = (%v, %v, calls %d), want (nil, nil, 1)", counts, err, calls)
	}

	// Read error propagates (no misleading absence, #3345).
	boom := errors.New("netlink: permission denied")
	if _, err := Lo0CountersForFilter(cfg, "inet", "protect-re", func() ([]xnft.Lo0Count, error) {
		return nil, boom
	}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}

	// Nil cfg / nil lookup are no-ops.
	if counts, err := Lo0CountersForFilter(nil, "inet", "protect-re", lookup); counts != nil || err != nil {
		t.Fatalf("nil cfg = (%v, %v), want (nil, nil)", counts, err)
	}
}
