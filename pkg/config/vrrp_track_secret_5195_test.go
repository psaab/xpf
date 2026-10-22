package config

import (
	"strings"
	"testing"
)

// #5195 (codex-177 A3-b2-F10): validateVRRPTrackInterfaceAST built the
// diagnostic node path from the FULL vrrp-group node Keys before feeding it to
// checkVRRPGroupTrackShape's duplicate-track error/warning. In the Keys-packed
// spelling `vrrp-group 1 authentication-key <secret> track-interface X
// track-interface Y` the authentication-key VALUE rides on the vrrp-group node's
// Keys run, so the duplicate-track message echoed the secret into the commit
// error / lenient warning (logs + CLI). The fix builds the path from
// vrrpGroupIDKeys(n) (the value-free `vrrp-group <id>` identity), mirroring the
// #4288 auth validator.

const vrrpTrackSecret = "SUPERSECRETTRACKKEY"

// trackDupWithSecretKeysPacked packs the authentication-key value AND two
// track-interface statements onto the vrrp-group node's Keys (single-statement
// hierarchical leaf form), which is exactly what makes a message built from
// n.Keys leak the secret.
const trackDupWithSecretKeysPacked = `interfaces {
    reth0 {
        unit 0 {
            family inet {
                address 10.0.61.10/24 {
                    vrrp-group 1 authentication-key ` + vrrpTrackSecret + ` track-interface ge-0/0/1 track-interface ge-0/0/2;
                }
            }
        }
    }
}`

// STRICT commit: the duplicate track-interface reject fires (it runs before the
// #4288 auth reject) and must NOT echo the authentication-key secret.
// RED-on-revert: building the path from n.Keys puts the secret in the error.
func TestVRRPTrackDuplicateRejectDoesNotLeakSecret_5195(t *testing.T) {
	_, err := CompileConfig(parseHierText(t, trackDupWithSecretKeysPacked))
	if err == nil {
		t.Fatal("expected strict rejection for duplicate track-interface, got nil")
	}
	if strings.Contains(err.Error(), vrrpTrackSecret) {
		t.Fatalf("track-interface reject error LEAKED the authentication-key secret: %v", err)
	}
	// It must still identify the offending group + the finding, value-free.
	if !strings.Contains(err.Error(), "vrrp-group 1") || !strings.Contains(err.Error(), "track-interface") {
		t.Fatalf("reject error must name the group identity + track-interface, got: %v", err)
	}
}

// LENIENT (load / peer-sync): the duplicate track-interface downgrades to a
// first-wins warning; that warning must also be value-free. RED-on-revert: the
// warning built from n.Keys leaks the secret.
func TestVRRPTrackDuplicateWarnDoesNotLeakSecret_5195(t *testing.T) {
	cfg, err := CompileConfigLenient(parseHierText(t, trackDupWithSecretKeysPacked))
	if err != nil {
		t.Fatalf("CompileConfigLenient: duplicate track-interface must downgrade to a warning, got: %v", err)
	}
	// No warning may contain the secret.
	for _, w := range cfg.Warnings {
		if strings.Contains(w, vrrpTrackSecret) {
			t.Fatalf("lenient warning LEAKED the authentication-key secret: %q", w)
		}
	}
	// The track-interface first-wins warning must be present and value-free.
	sawTrackWarn := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "track-interface") && strings.Contains(w, "vrrp-group 1") {
			sawTrackWarn = true
			break
		}
	}
	if !sawTrackWarn {
		t.Fatalf("expected a value-free duplicate track-interface warning, got: %v", cfg.Warnings)
	}
}
