package cli

import (
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16697: console peer block must render "unknown" for unresolvable HA
// ownership, not guess Backup from ha_active=false. Pre-#16697 peers
// (empty ha_state) also render unknown.
func TestPeerSessionHAState16697(t *testing.T) {
	if got := peerSessionHAState(nil); got != "unknown" {
		t.Errorf("nil: %q want unknown", got)
	}
	if got := peerSessionHAState(&pb.SessionEntry{}); got != "unknown" {
		t.Errorf("pre-16697 peer (empty ha_state, ha_active=false): %q want unknown, not Backup", got)
	}
	if got := peerSessionHAState(&pb.SessionEntry{HaState: "unknown", HaActive: false}); got != "unknown" {
		t.Errorf("unknown: %q", got)
	}
	if got := peerSessionHAState(&pb.SessionEntry{HaState: "Active", HaActive: true}); got != "Active" {
		t.Errorf("active: %q", got)
	}
	if got := peerSessionHAState(&pb.SessionEntry{HaState: "Backup", HaActive: false}); got != "Backup" {
		t.Errorf("backup control: %q want Backup (known secondary unchanged)", got)
	}
}
