package main

import "testing"

// #15775 remote: `fence-status` must resolve to its own topic, unknown
// cluster subsystems / trailing tokens must error (not fall through to
// `show chassis cluster`), and extra tokens after leaf views must error.

func TestClusterSubsystemViewFenceStatus15775(t *testing.T) {
	topic, filter, err := clusterSubsystemView("fence-status", nil)
	if err != nil {
		t.Fatalf("fence-status: %v", err)
	}
	if topic != "chassis-cluster-fence-status" || filter != "" {
		t.Errorf("fence-status = (%q,%q), want (chassis-cluster-fence-status,\"\")", topic, filter)
	}
	if _, _, err := clusterSubsystemView("fence-status", []string{"extra"}); err == nil {
		t.Error("fence-status with trailing token: expected error")
	}
	if _, _, err := clusterSubsystemView("bogus", nil); err == nil {
		t.Error("unknown subsystem: expected error")
	}
}
