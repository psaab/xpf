package cli

import (
	"strings"
	"testing"
)

// #13552: the local `pkg/cli` `show security zones` dispatcher inspected only
// args[1] (`detail` dumps every zone; selector after that position dropped).
// The #9065 SplitModifiers fix was applied to cmd/cli's twin but never here,
// so `show security zones detail trust` returned all zones in detail instead
// of only trust, and extra zone arguments were silently ignored. These cells
// drive the local dispatcher end-to-end (handleShow -> handleShowSecurity)
// against a two-zone fixture and assert the selector is honored
// position-independently, extra words error, and bare/detail/terse modifier
// behavior remains intact. RED on pristine master because `detail trust`
// ignores `trust`; reintroducing the args[1] ladder (or dropping selector
// handling) fails the string assertions.
func TestShowSecurityZonesDetailSelector13552(t *testing.T) {
	c := logicalUnitCLIStore(t)
	out := captureStdout(t, func() {
		if err := c.handleShow([]string{"security", "zones", "detail", "trust"}); err != nil {
			t.Fatalf("handleShow(security zones detail trust): %v", err)
		}
	})
	if !strings.Contains(out, "Interface details:") {
		t.Fatalf("`detail trust` must keep detail rendering:\n%s", out)
	}
	if !strings.Contains(out, "Security zone: trust") ||
		strings.Contains(out, "Security zone: dmz") {
		t.Fatalf("`detail trust` must render only trust (pre-fix dumps all zones):\n%s", out)
	}
	if !strings.Contains(out, "Address: 10.0.9.1/24") {
		t.Fatalf("`detail trust` must render trust interface address detail:\n%s", out)
	}
}

func TestShowSecurityZonesSelectorPositions13552(t *testing.T) {
	c := logicalUnitCLIStore(t)
	cases := []struct {
		args []string
		want string
		not  string
	}{
		{[]string{"security", "zones", "trust"}, "Security zone: trust", "Security zone: dmz"},
		{[]string{"security", "zones", "detail", "trust"}, "Security zone: trust", "Security zone: dmz"},
		{[]string{"security", "zones", "trust", "terse"}, "Security zone: trust", "Security zone: dmz"},
		{[]string{"security", "zones", "terse", "dmz"}, "Security zone: dmz", "Security zone: trust"},
		{[]string{"security", "zones", "det", "trust"}, "Security zone: trust", "Security zone: dmz"},
		{[]string{"security", "zones"}, "Security zone: trust", ""},
		{[]string{"security", "zones", "detail"}, "Security zone: dmz", ""},
	}
	for _, tc := range cases {
		out := captureStdout(t, func() {
			if err := c.handleShow(tc.args); err != nil {
				t.Fatalf("handleShow(%v): %v", tc.args, err)
			}
		})
		if tc.want != "" && !strings.Contains(out, tc.want) {
			t.Errorf("handleShow(%v): output missing %q:\n%s", tc.args, tc.want, out)
		}
		if tc.not != "" && strings.Contains(out, tc.not) {
			t.Errorf("handleShow(%v): output unexpectedly contains %q:\n%s", tc.args, tc.not, out)
		}
	}
}

func TestShowSecurityZonesRejectsInvalid13552(t *testing.T) {
	c := logicalUnitCLIStore(t)
	bad := [][]string{
		{"security", "zones", "trust", "dmz"},
		{"security", "zones", "trust", "dmz", "detail"},
		{"security", "zones", "detail", "trust", "dmz"},
	}
	for _, args := range bad {
		if err := c.handleShow(args); err == nil {
			t.Fatalf("handleShow(%v) must error, got nil", args)
		}
	}
}
