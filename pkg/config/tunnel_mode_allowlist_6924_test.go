package config

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// #6924 — `tunnel mode <value>` used to accept ANY token. The leaf carried no
// validator, so `tunnel mode banana` committed green, built a kernel GRE device
// (routing/tunnel.go's buildKernelTunnelLink default arm) and carried no
// traffic: an interface an operator can see with nothing going through it.
//
// The allowlist that closes it is a CLAIM about what the dataplane carries, so
// it owes three separate things, and they are three separate tests below:
//
//  1. the claim agrees with the dataplane's own predicate (drift guard);
//  2. an unrecognised value is REJECTED — with a positive control, because a
//     negative cell passes if ANYTHING rejects;
//  3. rejecting at commit does not brick a box that already persisted one
//     (#1960).

// rustTunnelModeKindPath is the dataplane predicate that decides, for real,
// whether a mode carries traffic.
const rustTunnelModeKindPath = "../../userspace-dp/src/afxdp/forwarding_build/tunnels.rs"

// carriedModesFromRust extracts the modes tunnel_mode_kind maps to a CARRYING
// kind. It parses the match arms rather than a hand-copied list: a literal on
// this side would encode which copy is trusted, and the whole point is that
// neither is — the AGREEMENT is the property.
func carriedModesFromRust(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(rustTunnelModeKindPath)
	if err != nil {
		t.Fatalf("read the dataplane SSOT %s: %v", rustTunnelModeKindPath, err)
	}
	src := string(raw)
	start := strings.Index(src, "fn tunnel_mode_kind(")
	if start < 0 {
		t.Fatalf("tunnel_mode_kind not found in %s — the dataplane predicate was renamed or "+
			"moved, so this guard is no longer reading the SSOT it claims to read",
			rustTunnelModeKindPath)
	}
	body := src[start:]
	if end := strings.Index(body, "\n}"); end > 0 {
		body = body[:end]
	}

	// Arms look like `"gre" | "ip6gre" => TunnelKind::Gre,`. The catch-all
	// `_ => TunnelKind::Unknown` carries no literals, so it contributes none.
	arm := regexp.MustCompile(`((?:\s*"[a-z0-9_]+"\s*\|)*\s*"[a-z0-9_]+")\s*=>\s*TunnelKind::(\w+)`)
	lit := regexp.MustCompile(`"([a-z0-9_]+)"`)

	var carried []string
	kinds := 0
	for _, m := range arm.FindAllStringSubmatch(body, -1) {
		kinds++
		if m[2] == "Unknown" {
			continue
		}
		for _, l := range lit.FindAllStringSubmatch(m[1], -1) {
			carried = append(carried, l[1])
		}
	}
	// NON-VACUITY. A regex that stopped matching would hand back an empty set,
	// and "the Go list equals the empty set" is a comparison that proves
	// nothing while looking like a clean pass.
	if kinds == 0 || len(carried) == 0 {
		t.Fatalf("parsed %d match arms and %d carried modes out of tunnel_mode_kind — the "+
			"scan is not reaching the arms, so this guard cannot bind the agreement.\n"+
			"body:\n%s", kinds, len(carried), body)
	}
	sort.Strings(carried)
	return carried
}

// TestTunnelModeAllowlistMatchesTheDataplane_6924 asserts the AGREEMENT, not
// either side's literal. Pinning the Go list to a hardcoded expectation would
// encode which copy is trusted; the defect class here is precisely the two
// drifting apart, so the assertion has to be equality between them.
func TestTunnelModeAllowlistMatchesTheDataplane_6924(t *testing.T) {
	want := carriedModesFromRust(t)

	got := append([]string(nil), TunnelModeNames...)
	sort.Strings(got)

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("config.TunnelModeNames = %v, but the dataplane carries %v (from %s).\n\n"+
			"These two must be one list. A mode the dataplane gained but config rejects is "+
			"silently unconfigurable; a mode config accepts but the dataplane drops builds a "+
			"kernel device that carries nothing — which is the #6924 defect and the same "+
			"symptom #4785 exists to reject.",
			got, want, rustTunnelModeKindPath)
	}
}

// TestTunnelModeRejectsUnknownValues_6924 is the negative cell, and its POSITIVE
// CONTROL is what makes it worth anything.
//
// A negative cell passes if ANYTHING rejects — a typo in the stanza, a missing
// required sibling, an unrelated validator. So every row here is the SAME config
// differing ONLY in the mode token, and the accepted rows must COMMIT-CHECK
// CLEAN. Without them, a validator that refused every value would satisfy the
// rejection rows and break every tunnel on the box.
func TestTunnelModeRejectsUnknownValues_6924(t *testing.T) {
	// The SAME config every time, differing only in the mode token. Source and
	// destination are present so a missing-sibling complaint cannot be what
	// rejects a row.
	build := func(t *testing.T, mode string) *ConfigTree {
		t.Helper()
		tree := &ConfigTree{}
		for _, cmd := range []string{
			"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
			"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
			"set interfaces gr-0/0/0 tunnel mode " + mode,
		} {
			path, err := ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v — a parse failure would satisfy the "+
					"rejection rows for a reason unrelated to the mode value", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		return tree
	}

	for _, tc := range []struct {
		mode       string
		wantReject bool
	}{
		// Positive controls: everything the dataplane carries must pass, or a
		// reject-everything validator would satisfy the rows below.
		{mode: "gre", wantReject: false},
		{mode: "ip6gre", wantReject: false},
		{mode: "wireguard", wantReject: false},
		// The reported defect.
		{mode: "banana", wantReject: true},
		// A mode the system RECOGNISES but the dataplane does not carry. It is
		// rejected here rather than left to #4785's endpoint-naming gate, so
		// the leaf refuses every mode that carries nothing — the general rule
		// #4785's ipip case is one instance of.
		{mode: "ipip", wantReject: true},
		// Near-misses: casing and whitespace are not accepted spellings.
		{mode: "GRE", wantReject: true},
		{mode: "gre6", wantReject: true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			err := SchemaValidate(build(t, tc.mode))
			if tc.wantReject {
				if err == nil {
					t.Fatalf("`tunnel mode %s` was ACCEPTED. It builds a kernel GRE device "+
						"that carries no traffic — an interface the operator can see with "+
						"nothing going through it (#6924)", tc.mode)
				}
				// The rejection must be ABOUT the mode. Any other complaint
				// would pass this row while leaving the defect open.
				if !strings.Contains(err.Error(), tc.mode) {
					t.Errorf("rejected, but not for the mode value: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("`tunnel mode %s` was REJECTED (%v). This is a mode the dataplane "+
					"carries; refusing it makes a working configuration uncommittable.",
					tc.mode, err)
			}
		})
	}
}
