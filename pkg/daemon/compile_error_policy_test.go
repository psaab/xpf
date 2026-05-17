package daemon

import (
	"errors"
	"fmt"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestCompileErrorMustAbortApply(t *testing.T) {
	if !compileErrorMustAbortApply(dpuserspace.ErrPolicySchedulerProtocolIncompatible) {
		t.Fatal("protocol incompatibility must abort apply")
	}
	if !compileErrorMustAbortApply(fmt.Errorf("wrapped: %w", dpuserspace.ErrPolicySchedulerProtocolIncompatible)) {
		t.Fatal("wrapped protocol incompatibility must abort apply")
	}
	if compileErrorMustAbortApply(errors.New("compile failed for unrelated dataplane reason")) {
		t.Fatal("non-protocol compile failures must not abort apply")
	}
}
