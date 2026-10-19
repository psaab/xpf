package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #15173 (B18-02): the gRPC raw `show firewall` / `show firewall filter`
// views dropped except-ports, tcp-flags, is-fragment, flexible-match,
// reject type and syslog, and printed empty-action terms as terminating
// accepts. These cells drive the live ShowText topics.

func rawShowStore15173(t *testing.T) *configstore.Store {
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

func termBlock15173(t *testing.T, out, name string) string {
	t.Helper()
	marker := "  Term: " + name + "\n"
	start := strings.Index(out, marker)
	if start < 0 {
		t.Fatalf("term %q missing from output:\n%s", name, out)
	}
	rest := out[start+len(marker):]
	end := len(rest)
	if idx := strings.Index(rest, "\n  Term: "); idx >= 0 && idx < end {
		end = idx + 1
	}
	return rest[:end]
}

func TestShowFirewallRawFields15173(t *testing.T) {
	s := &Server{store: rawShowStore15173(t)}
	for _, topic := range []string{"firewall", "firewall-filter:edge", "firewall-filter:edge:inet"} {
		resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: topic})
		if err != nil {
			t.Fatalf("ShowText(%q) error = %v", topic, err)
		}
		out := resp.GetOutput()
		ssh := termBlock15173(t, out, "ssh-only")
		if !strings.Contains(ssh, "    from destination-port-except 22\n") {
			t.Errorf("topic %s: ssh-only lost its except-port (reads as broad discard):\n%s", topic, ssh)
		}
		if !strings.Contains(ssh, "    then discard\n") {
			t.Errorf("topic %s: ssh-only lost discard:\n%s", topic, ssh)
		}
		pass := termBlock15173(t, out, "pass-on")
		if !strings.Contains(pass, "    then next term\n") {
			t.Errorf("topic %s: pass-on must render `then next term`:\n%s", topic, pass)
		}
		if strings.Contains(pass, "then accept") {
			t.Errorf("topic %s: fall-through term rendered as accept:\n%s", topic, pass)
		}
		countOnly := termBlock15173(t, out, "count-only")
		if !strings.Contains(countOnly, "    then count hits\n") || !strings.Contains(countOnly, "    then accept\n") {
			t.Errorf("topic %s: modifier-only term must terminate as implicit accept:\n%s", topic, countOnly)
		}
		if strings.Contains(countOnly, "next term") {
			t.Errorf("topic %s: modifier-only term rendered as fall-through:\n%s", topic, countOnly)
		}
		frag := termBlock15173(t, out, "frag")
		if !strings.Contains(frag, "    from is-fragment\n") {
			t.Errorf("topic %s: is-fragment dropped:\n%s", topic, frag)
		}
		if !strings.Contains(frag, "    then reject tcp-reset\n") {
			t.Errorf("topic %s: reject message type dropped:\n%s", topic, frag)
		}
	}
}

// Control: an explicit accept term keeps its exact pre-fix rendering.
func TestShowFirewallRawExplicitAcceptControl15173(t *testing.T) {
	store := newFirewallFilterShowStore(t)
	s := &Server{store: store}
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "firewall"})
	if err != nil {
		t.Fatalf("ShowText error = %v", err)
	}
	out := resp.GetOutput()
	if !strings.Contains(out, "    from destination-port 80\n    then accept\n") {
		t.Errorf("explicit accept rendering changed:\n%s", out)
	}
}
