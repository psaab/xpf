package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9820 GPT-P2: store-ingress split for padded statics. Strict ingress
// refuses (schema padding arm); tolerant ingress compiles, logs the
// schema warning, and retains the raw padded value for the render belt
// (which omits it — see the frr padding cells).

func TestStaticPaddingStrictIngressRefuses_9820(t *testing.T) {
	tree, perrs := config.NewParser(`
routing-options {
    static {
        route " 2001:db8::/32 " {
            next-hop 2001:db8::1;
        }
    }
}`).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	if _, err := compileTreeStrict(tree, -1); err == nil ||
		!strings.Contains(err.Error(), "whitespace is not allowed") {
		t.Fatalf("strict ingress must refuse the padded destination, got: %v", err)
	}
}

func TestStaticPaddingTolerantIngressWarns_9820(t *testing.T) {
	buf := captureWarnLogs(t)
	s := newTestStore(t)
	tree, perrs := config.NewParser(`
routing-options {
    static {
        route 2001:db8::/32 {
            next-hop " 2001:db8::1 ";
        }
    }
}`).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	cfg, err := s.compileTreeLenient(tree)
	if err != nil {
		t.Fatalf("tolerant ingress must NOT fail, got: %v", err)
	}
	if len(cfg.RoutingOptions.StaticRoutes) != 1 ||
		len(cfg.RoutingOptions.StaticRoutes[0].NextHops) != 1 ||
		cfg.RoutingOptions.StaticRoutes[0].NextHops[0].Address != " 2001:db8::1 " {
		t.Fatalf("tolerant compile must retain the raw padded next-hop: %+v",
			cfg.RoutingOptions.StaticRoutes)
	}
	if logged := buf.String(); !strings.Contains(logged, "typed-leaf schema violation") {
		t.Fatalf("tolerant ingress must log the schema warning, got:\n%s", logged)
	}
}
