package grpcapi

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestCompletionValuesSeam16160 pins the exported seam to the real
// provider so the cross-package parity test cannot silently drift
// onto a stub.
func TestCompletionValuesSeam16160(t *testing.T) {
	s := &Server{}
	if got := CompletionValuesForTest16160(s, config.ValueHintZoneName, nil); got != nil {
		t.Errorf("nil-store seam = %v, want nil", got)
	}
	if got := CompletionValuesForTest16160(nil, config.ValueHintZoneName, nil); got != nil {
		t.Errorf("nil-server seam = %v, want nil", got)
	}
}
