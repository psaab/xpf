package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16728: gRPC ShowText{snmp} must mask the trap-group name (the v1/v2c
// trap community since #15052) unconditionally, like the query community.
// RED-on-revert: printing the raw map key re-leaks the canary on a
// fabric-reachable RPC.
func TestShowTextSNMPTrapGroupRedacted16728(t *testing.T) {
	const canary = "GRPC-TRAPSECRET-16728"
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	if _, err := store.LoadSet(strings.Join([]string{
		"set snmp community " + snmpCommunitySentinel + " authorization read-only",
		"set snmp trap-group " + canary + " targets 192.0.2.10",
	}, "\n")); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	out := showTextOutput(t, &Server{store: store}, "snmp")
	if strings.Contains(out, canary) {
		t.Errorf("trap-group community leaked over gRPC ShowText:\n%s", out)
	}
	if strings.Contains(out, snmpCommunitySentinel) {
		t.Errorf("community control leaked over gRPC ShowText:\n%s", out)
	}
	if !strings.Contains(out, config.SecretDataPlaceholder+": 192.0.2.10") {
		t.Errorf("missing masked trap-group line:\n%s", out)
	}
}
