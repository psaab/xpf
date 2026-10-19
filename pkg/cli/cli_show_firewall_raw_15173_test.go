package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #15173 (B18-02): the local CLI raw `show firewall` views dropped
// except-ports, tcp-flags, is-fragment, flexible-match, reject type,
// policer and syslog, and printed empty-action terms as accepts.

func rawFirewallCLIStore15173(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, cmd := range []string{
		"firewall family inet filter edge term ssh-only from protocol tcp",
		"firewall family inet filter edge term ssh-only from destination-port-except 22",
		"firewall family inet filter edge term ssh-only then discard",
		"firewall family inet filter edge term pass-on from protocol tcp",
		"firewall family inet filter edge term pass-on then count hits",
		"firewall family inet filter edge term pass-on then next term",
		"firewall family inet filter edge term count-only from protocol udp",
		"firewall family inet filter edge term count-only then count hits",
		"firewall family inet filter edge term frag from is-fragment",
		"firewall family inet filter edge term frag then reject tcp-reset",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func cliTermBlock15173(t *testing.T, out, name string) string {
	t.Helper()
	marker := "  Term: " + name + "\n"
	start := strings.Index(out, marker)
	if start < 0 {
		t.Fatalf("term %q missing:\n%s", name, out)
	}
	rest := out[start+len(marker):]
	if idx := strings.Index(rest, "\n  Term: "); idx >= 0 {
		rest = rest[:idx+1]
	}
	return rest
}

func TestCLIShowFirewallRawFields15173(t *testing.T) {
	c := &CLI{store: rawFirewallCLIStore15173(t)}
	surfaces := map[string]func() error{
		"show_firewall":        c.showFirewallFilters,
		"show_firewall_filter": func() error { return c.showFirewallFilter("edge", "") },
	}
	for name, fn := range surfaces {
		t.Run(name, func(t *testing.T) {
			out := captureStdout(t, func() {
				if err := fn(); err != nil {
					t.Fatalf("render error = %v", err)
				}
			})
			ssh := cliTermBlock15173(t, out, "ssh-only")
			if !strings.Contains(ssh, "    from destination-port-except 22\n") || !strings.Contains(ssh, "    then discard\n") {
				t.Errorf("ssh-only misrendered (narrow discard must stay narrow):\n%s", ssh)
			}
			pass := cliTermBlock15173(t, out, "pass-on")
			if !strings.Contains(pass, "    then next term\n") || strings.Contains(pass, "then accept") {
				t.Errorf("pass-on must fall through, not accept:\n%s", pass)
			}
			countOnly := cliTermBlock15173(t, out, "count-only")
			if !strings.Contains(countOnly, "    then accept\n") || strings.Contains(countOnly, "next term") {
				t.Errorf("count-only must terminate as implicit accept:\n%s", countOnly)
			}
			frag := cliTermBlock15173(t, out, "frag")
			if !strings.Contains(frag, "    from is-fragment\n") || !strings.Contains(frag, "    then reject tcp-reset\n") {
				t.Errorf("frag term fields dropped:\n%s", frag)
			}
		})
	}
}
