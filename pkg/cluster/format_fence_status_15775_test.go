package cluster

import (
	"strings"
	"testing"
)

// #15775: dedicated peer-fencing view backing `show chassis cluster
// fence-status` on both CLI surfaces. Unlike the conditional block inside
// FormatInformation, the dedicated view always renders (action `disabled`
// when unconfigured) so an advertised command never silently renders RG
// status.
func TestFormatFenceStatus15775(t *testing.T) {
	m := fenceInfoManager(t, "disable-rg")
	m.SetPeerFenceFunc(func() error { return nil })
	m.handlePeerTimeout()

	out := m.FormatFenceStatus()
	if !strings.Contains(out, "Peer fencing:") {
		t.Fatalf("FormatFenceStatus lacks header:\n%s", out)
	}
	if !strings.Contains(out, "Action: disable-rg") {
		t.Errorf("lacks configured action:\n%s", out)
	}
	if !strings.Contains(out, "Fence disable-rg sent to peer") {
		t.Errorf("lacks fence attempt history:\n%s", out)
	}
	if strings.Contains(out, "Redundancy group:") {
		t.Errorf("fence view must not be RG status:\n%s", out)
	}
}

func TestFormatFenceStatusUnconfigured15775(t *testing.T) {
	m := fenceInfoManager(t, "")
	out := m.FormatFenceStatus()
	if !strings.Contains(out, "Action: disabled") {
		t.Errorf("unconfigured fence view must state disabled:\n%s", out)
	}
	if !strings.Contains(out, "Attempts: none") {
		t.Errorf("unconfigured fence view must state no attempts:\n%s", out)
	}
}
