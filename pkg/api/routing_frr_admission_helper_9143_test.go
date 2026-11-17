package api

import (
	"context"
	"errors"

	"github.com/psaab/xpf/pkg/frr"
)

// failingFRRExec9143 returns an ordinary (non-admission) FRR error so the
// stay-500 control has something to measure.
type failingFRRExec9143 struct{ frr.RecordingExecutor }

func (*failingFRRExec9143) Vtysh(context.Context, string) (string, error) {
	return "", errors.New("vtysh \"show ip ospf database\": exit status 1: zebra unreachable")
}
