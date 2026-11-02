package firewallshow

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// The show surfaces look the synthetic term's counter up by the name the
// snapshot builder gives it; the two constants must not drift.
func TestImplicitDiscardTermNameMatchesDataplane18728(t *testing.T) {
	if ImplicitDiscardTermName != dpuserspace.ImplicitDiscardTermName {
		t.Fatalf("firewallshow %q != dataplane %q", ImplicitDiscardTermName, dpuserspace.ImplicitDiscardTermName)
	}
}

func allowlist18728() *config.FirewallFilter {
	return &config.FirewallFilter{Name: "allow", Terms: []*config.FirewallFilterTerm{
		{Name: "ssh", Protocols: []string{"tcp"}, DestinationPorts: []string{"22"}, Action: config.FilterActionAccept},
	}}
}

func permitDefault18728() *config.FirewallFilter {
	f := allowlist18728()
	f.Terms = append(f.Terms, &config.FirewallFilterTerm{Name: "default", Action: config.FilterActionAccept})
	return f
}

func TestWriteImplicitDiscard18728(t *testing.T) {
	const head = "  Term: implicit-discard (Junos implicit final discard: no term above matched)\n    then discard\n"
	for _, tc := range []struct {
		name    string
		filter  *config.FirewallFilter
		counter ImplicitDiscardCounter
		blank   bool
		want    string
	}{
		{"catch-all renders nothing", permitDefault18728(), ImplicitDiscardCounter{Packets: 9, Have: true}, false, ""},
		{"nil filter renders nothing", nil, ImplicitDiscardCounter{}, false, ""},
		{"no reading omits hit count", allowlist18728(), ImplicitDiscardCounter{}, false, head},
		{"reading prints hit count", allowlist18728(), ImplicitDiscardCounter{Packets: 3, Bytes: 180, Have: true}, false,
			head + "    Hit count: 3 packets, 180 bytes\n"},
		{"zero reading still prints", allowlist18728(), ImplicitDiscardCounter{Have: true}, true,
			"\n" + head + "    Hit count: 0 packets, 0 bytes\n"},
		{"empty filter discards everything", &config.FirewallFilter{Name: "empty"}, ImplicitDiscardCounter{}, false, head},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			WriteImplicitDiscard(&b, tc.filter, tc.counter, tc.blank)
			if b.String() != tc.want {
				t.Fatalf("got %q, want %q", b.String(), tc.want)
			}
		})
	}
}

// The config-only all-filters view (REST) lists the synthetic term after the
// authored ones, and only for the filter without a catch-all.
func TestWriteAllFiltersListsImplicitDiscard18728(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"allow":  allowlist18728(),
		"permit": permitDefault18728(),
	}
	var b strings.Builder
	WriteAllFilters(&b, cfg)
	out := b.String()
	allow := out[strings.Index(out, "Filter: allow"):strings.Index(out, "Filter: permit")]
	permit := out[strings.Index(out, "Filter: permit"):]
	if !strings.Contains(allow, "Term: implicit-discard") {
		t.Errorf("allowlist view lacks the implicit-discard term:\n%s", allow)
	}
	if strings.Contains(permit, "implicit-discard") {
		t.Errorf("catch-all filter view must not show an implicit-discard term:\n%s", permit)
	}
}

func TestWriteLo0ImplicitDiscardCounter18728(t *testing.T) {
	counts := []xnft.Lo0Count{
		{Counter: "ssh", Packets: 1, Bytes: 60},
		{ImplicitDiscardFamily: "inet", Packets: 4, Bytes: 240},
		{ImplicitDiscardFamily: "inet6", Packets: 5, Bytes: 400},
	}
	var b strings.Builder
	WriteLo0ImplicitDiscardCounter(&b, allowlist18728(), "inet6", counts)
	want := "    Kernel lo0 implicit-discard: 5 packets, 400 bytes (inet xpf_lo0 chain; unmatched host-bound inet6 traffic, except loopback and the cluster control/fabric links)\n"
	if b.String() != want {
		t.Fatalf("got %q, want %q", b.String(), want)
	}
	b.Reset()
	WriteLo0ImplicitDiscardCounter(&b, permitDefault18728(), "inet", counts)
	if b.String() != "" {
		t.Fatalf("catch-all lo0 filter has no implicit drop rule; got %q", b.String())
	}
	// The implicit row is not a `then count` counter: the named-counter
	// renderer must not print it under an empty name.
	b.Reset()
	f := allowlist18728()
	f.Terms[0].Count = "ssh"
	WriteLo0KernelCounters(&b, f, counts)
	if strings.Contains(b.String(), "implicit") || strings.Count(b.String(), "Kernel lo0 counter") != 1 {
		t.Fatalf("named-counter view must show only the ssh counter; got %q", b.String())
	}
}
