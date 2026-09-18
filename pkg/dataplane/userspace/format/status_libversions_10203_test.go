package format

import (
	"encoding/json"
	"strings"
	"testing"

	userspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #10203: Rust records the #9931 linked versions in its ProcessStatus
// document; the Go status summary must display them. The payload is decoded
// through the Go ProcessStatus exactly as the control-socket poll delivers it.
func TestFormatStatusSummaryShowsLinkedLibVersions10203(t *testing.T) {
	const rustJSON = `{"pid":4242,` +
		`"linked_libelf_version":"0.195",` +
		`"linked_zlib_version":"1.3.2",` +
		`"linked_zstd_version":"1.5.7"}`
	var st userspace.ProcessStatus
	if err := json.Unmarshal([]byte(rustJSON), &st); err != nil {
		t.Fatalf("decode Rust-shaped status: %v", err)
	}
	out := FormatStatusSummary(st)
	for _, want := range []string{
		"Linked libelf version:     0.195",
		"Linked zlib version:       1.3.2",
		"Linked zstd version:       1.5.7",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status summary hides linked version row %q:\n%s", want, out)
		}
	}
}
