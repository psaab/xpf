package userspace

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestSnapshotEpochFeedSerde9506(t *testing.T) {
	provider := func() (uint64, []QueueEpochSnapshot) {
		return 41, []QueueEpochSnapshot{{Queue: 1000, Epoch: 9}, {Queue: 1001, Epoch: 10}}
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
	}
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.PermitEpoch != 41 || len(decoded.QueueEpochs) != 2 || decoded.QueueEpochs[0].Queue != 1000 {
		t.Fatalf("wire epochs=%+v, want additive snake_case fields", decoded)
	}
}

// configUserspaceForEpochTest keeps the nil-config builder path explicit; the
// epoch feed must be available even before a compiled policy exists.
func configUserspaceForEpochTest() config.UserspaceConfig { return config.UserspaceConfig{} }
