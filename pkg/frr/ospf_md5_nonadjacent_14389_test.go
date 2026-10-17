package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14389 (DR6-H5) liveness: the hierarchical spelling
// `md5 1 2 { key SECRET; }` is not dormant text — the compiler installs
// key-id 1 with the secret and FRR renders it on the wire. This is what
// makes the AST-display leak a live-credential leak rather than a
// display-only artifact.
func TestOSPFMD5NonAdjacentKeyRendersLive14389(t *testing.T) {
	const secret = "LIVE-OSPF-MD5-SECRET-14389"
	tree, errs := config.NewParser(`protocols {
    ospf {
        area 0.0.0.0 {
            interface ge-0/0/0 {
                authentication {
                    md5 1 2 {
                        key "` + secret + `";
                    }
                }
            }
        }
    }
}`).Parse()
	if len(errs) != 0 {
		t.Fatalf("NewParser: %v", errs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg == nil || cfg.Protocols.OSPF == nil {
		t.Fatalf("compiled config has no OSPF: %+v", cfg)
	}
	got := New().generateProtocols(cfg.Protocols.OSPF, nil, nil, nil, nil, "", 0, nil, nil)
	want := "ip ospf message-digest-key 1 md5 " + secret
	if !strings.Contains(got, want) {
		t.Fatalf("non-adjacent MD5 key did not render live (want %q):\n%s", want, got)
	}
}
