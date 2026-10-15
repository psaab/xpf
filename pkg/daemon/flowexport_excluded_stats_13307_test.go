package daemon

import "testing"

func TestBuildStateReportsExcludedFlowServers13307(t *testing.T) {
	d := &Daemon{}
	d.flowExcludedFlowServers.Store(2)
	for _, st := range d.FlowExportBuildStates() {
		if st.Family == "netflow-v9" {
			if st.ExcludedFlowServers != 2 {
				t.Fatalf("excluded flow-server gauge = %d, want 2", st.ExcludedFlowServers)
			}
			return
		}
	}
	t.Fatal("netflow-v9 build state absent")
}
