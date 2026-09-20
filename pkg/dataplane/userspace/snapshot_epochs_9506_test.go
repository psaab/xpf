package userspace

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestSnapshotEpochFeedSerde9506(t *testing.T) {
	provider := func(uint64, uint32) (uint64, []QueueEpochSnapshot, uint64, []IpsecTunnelRowSnapshot) {
		return 41,
			[]QueueEpochSnapshot{{Queue: 1000, Epoch: 9}, {Queue: 1001, Epoch: 10}},
			17,
			[]IpsecTunnelRowSnapshot{{STN: "st0", IfID: 9, LogicalIfindex: 10}}
	}
	snap, err := buildSnapshotWithEpochProvider(nil, configUserspaceForEpochTest(), 7, 3, provider)
	if err != nil {
		t.Fatalf("buildSnapshotWithEpochProvider: %v", err)
	}
	if snap.PermitEpoch != 41 {
		t.Fatalf("PermitEpoch=%d, want 41", snap.PermitEpoch)
	}
	if len(snap.QueueEpochs) != 2 || snap.QueueEpochs[0].Queue != 1000 || snap.QueueEpochs[1].Epoch != 10 {
		t.Fatalf("QueueEpochs=%+v, want ordered list", snap.QueueEpochs)
	}
	if snap.IpsecTunnelSnapshotGeneration != 17 || len(snap.IpsecTunnelRows) != 1 ||
		snap.IpsecTunnelRows[0].STN != "st0" {
		t.Fatalf("IpsecTunnelRows=%d/%+v, want capture generation 17 and st0 row",
			snap.IpsecTunnelSnapshotGeneration, snap.IpsecTunnelRows)
	}
	wire, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		PermitEpoch uint64 `json:"permit_epoch"`
		QueueEpochs []struct {
			Queue uint16 `json:"queue"`
			Epoch uint64 `json:"epoch"`
		} `json:"queue_epochs"`
		TunnelGeneration uint64 `json:"ipsec_tunnel_snapshot_generation"`
		TunnelRows []struct {
			STN string `json:"stn"`
			IfID uint32 `json:"if_id"`
			LogicalIfindex int32 `json:"logical_ifindex"`
		} `json:"ipsec_tunnel_rows"`
	}
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.PermitEpoch != 41 || len(decoded.QueueEpochs) != 2 || decoded.QueueEpochs[0].Queue != 1000 ||
		decoded.TunnelGeneration != 17 || len(decoded.TunnelRows) != 1 ||
		decoded.TunnelRows[0].STN != "st0" || decoded.TunnelRows[0].IfID != 9 ||
		decoded.TunnelRows[0].LogicalIfindex != 10 {
		t.Fatalf("wire authority=%+v, want additive snake_case epoch and row fields", decoded)
	}
}

// configUserspaceForEpochTest keeps the nil-config builder path explicit; the
// epoch feed must be available even before a compiled policy exists.
func configUserspaceForEpochTest() config.UserspaceConfig { return config.UserspaceConfig{} }
