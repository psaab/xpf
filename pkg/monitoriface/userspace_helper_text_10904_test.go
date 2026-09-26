package monitoriface

import (
	"bytes"
	"strings"
	"testing"
	"time"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestRenderSingleInterfaceSanitizesUserspaceHelperText10904(t *testing.T) {
	const kernelName = "xpf10904-test"
	const helperError = "endpoint 198.51.100.1:4789: helper failed \x1b]52;c;clipboard\x07\nforged"
	const exceptionReason = "inject failed \x1b[2J\nforged"

	userspace := AggregateUserspaceSnapshot(kernelName, dpuserspace.ProcessStatus{
		Bindings: []dpuserspace.BindingStatus{{
			Interface: kernelName,
			LastError: helperError,
		}},
		RecentExceptions: []dpuserspace.ExceptionStatus{{
			Interface: kernelName,
			Reason:    exceptionReason,
		}},
	})
	snap := &Snapshot{Timestamp: time.Now(), Userspace: userspace}

	var rendered bytes.Buffer
	RenderSingleInterface(&rendered, "host", "eth0", kernelName, snap, nil, nil, time.Now(), "")
	out := rendered.String()

	for _, raw := range []string{helperError, exceptionReason} {
		if strings.Contains(out, raw) {
			t.Errorf("rendered raw helper control bytes %q:\n%s", raw, out)
		}
	}
	for _, escaped := range []string{
		`endpoint 198.51.100.1:4789: helper failed \x1b]52;c;clipboard\x07\x0aforged`,
		`inject failed \x1b[2J\x0aforged`,
	} {
		if !strings.Contains(out, escaped) {
			t.Errorf("rendered output missing escaped helper text %q:\n%s", escaped, out)
		}
	}
	if strings.ContainsAny(out, "\x1b\x07") {
		t.Errorf("rendered output contains terminal control bytes:\n%s", out)
	}
}
