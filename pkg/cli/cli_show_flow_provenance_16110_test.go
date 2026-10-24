package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16110: provenance is the stored SessFlagClusterSynced bit, not a
// counter heuristic. Promotion clears the bit, so a promoted row reads
// "local"; FwdPackets only drives Forwarding-ready.
func TestSessionOriginLabel16110(t *testing.T) {
	if got := sessionOriginLabel(0); got != "local" {
		t.Fatalf("local flags: got %q", got)
	}
	if got := sessionOriginLabel(dataplane.SessFlagClusterSynced | dataplane.SessFlagSNAT); got != "cluster-synced" {
		t.Fatalf("synced flags: got %q", got)
	}
	if got := sessionForwardingReady(0); got != "no" {
		t.Fatalf("forwarding-ready 0: got %q", got)
	}
	if got := sessionForwardingReady(7); got != "yes" {
		t.Fatalf("forwarding-ready 7: got %q", got)
	}
}

// #16110: address-only NAT preserves the original port; explicit PAT port
// renders as-is; no NAT flag never invents a port. FAIL-ON-REVERT:
// returning natPort unconditionally renders /0 for address-only rows.
func TestTranslatedPorts16110(t *testing.T) {
	if got := translatedSrcPort(dataplane.SessFlagSNAT, 0, 57566); got != 57566 {
		t.Fatalf("address-only SNAT: got %d want 57566", got)
	}
	if got := translatedSrcPort(dataplane.SessFlagSNAT, 40000, 57566); got != 40000 {
		t.Fatalf("PAT SNAT: got %d want 40000", got)
	}
	if got := translatedSrcPort(0, 0, 57566); got != 0 {
		t.Fatalf("no SNAT: got %d want 0", got)
	}
	if got := translatedDstPort(dataplane.SessFlagDNAT, 0, 5211); got != 5211 {
		t.Fatalf("address-only DNAT: got %d want 5211", got)
	}
	if got := translatedDstPort(dataplane.SessFlagDNAT, 8443, 5211); got != 8443 {
		t.Fatalf("mapped DNAT: got %d want 8443", got)
	}
}

func TestNATDivergenceWarning16110(t *testing.T) {
	if w := natDivergenceWarning("10.0.61.102/57566 -> 172.16.80.200/5211", 0, 57566, true); w == "" {
		t.Fatal("divergent ports must warn (owner /0 vs standby 57566)")
	} else if want := "NAT divergence: local translated port 0 != peer translated port 57566"; !strings.Contains(w, want) {
		t.Fatalf("warning %q missing %q", w, want)
	}
	if w := natDivergenceWarning("t", 57566, 57566, true); w != "" {
		t.Fatalf("agreeing ports must not warn, got %q", w)
	}
	if w := natDivergenceWarning("t", 0, 0, false); w != "" {
		t.Fatalf("absent peer NAT must not warn, got %q", w)
	}
}

func TestPeerSessionOriginLabel16110(t *testing.T) {
	if got := peerSessionOriginLabel(nil); got != "unknown" {
		t.Fatalf("nil peer: got %q", got)
	}
	if got := peerSessionOriginLabel(&pb.SessionEntry{}); got != "unknown" {
		t.Fatalf("pre-16110 peer: got %q", got)
	}
	if got := peerSessionOriginLabel(&pb.SessionEntry{Origin: "cluster-synced"}); got != "cluster-synced" {
		t.Fatalf("synced peer: got %q", got)
	}
	if got := protoNumFromName("tcp"); got != 6 {
		t.Fatalf("tcp: got %d", got)
	}
	if got := protoNumFromName("47"); got != 47 {
		t.Fatalf("numeric proto: got %d", got)
	}
}

