package main

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16697: remote CLI must render "unknown" for unresolvable HA ownership
// on all rows, not Backup from ha_active=false.
func TestSessionHAStateLabel16697(t *testing.T) {
	if got := sessionHAStateLabel(nil); got != "unknown" {
		t.Errorf("nil: %q", got)
	}
	if got := sessionHAStateLabel(&pb.SessionEntry{}); got != "unknown" {
		t.Errorf("pre-16697 (empty): %q want unknown", got)
	}
	if got := sessionHAStateLabel(&pb.SessionEntry{HaState: "unknown"}); got != "unknown" {
		t.Errorf("unknown: %q", got)
	}
	if got := sessionHAStateLabel(&pb.SessionEntry{HaState: "Active", HaActive: true}); got != "Active" {
		t.Errorf("active: %q", got)
	}
	if got := sessionHAStateLabel(&pb.SessionEntry{HaState: "Backup"}); got != "Backup" {
		t.Errorf("backup control: %q", got)
	}
}

func TestPrintSessionEntriesHAUnknown16697(t *testing.T) {
	out := captureStdout(t, func() {
		printSessionEntries(&pb.GetSessionsResponse{Sessions: []*pb.SessionEntry{
			{SrcAddr: "192.0.2.1", DstAddr: "198.51.100.1", Protocol: "tcp", State: "ESTABLISHED", HaState: "unknown"},
			{SrcAddr: "192.0.2.2", DstAddr: "198.51.100.2", Protocol: "tcp", State: "ESTABLISHED", HaState: "Backup"},
			{SrcAddr: "192.0.2.3", DstAddr: "198.51.100.3", Protocol: "tcp", State: "ESTABLISHED", HaState: "Active", HaActive: true},
		}}, false)
	})
	if !strings.Contains(out, "HA State: unknown") {
		t.Errorf("unknown row not rendered:\n%s", out)
	}
	if !strings.Contains(out, "HA State: Backup") || !strings.Contains(out, "HA State: Active") {
		t.Errorf("known rows changed:\n%s", out)
	}
}
