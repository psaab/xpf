package ra

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

// Router Lifetime is the source for inherited RDNSS/PREF64 lifetimes. Keep the
// header clamp ahead of that derivation, then saturate the narrower PREF64 wire
// field instead of silently pruning the option. The large value also verifies
// tolerant-ingress configs cannot wrap RDNSS's uint32 lifetime.
func TestBuildRA_12134_InheritedLifetimesAreBounded(t *testing.T) {
	oldLogger := slog.Default()
	var log bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&log, nil)))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	for _, lifetime := range []int{0, 65532, 65533, 65534, 65535, 1 << 32} {
		name := fmt.Sprintf("lifetime_%d", lifetime)
		t.Run(name, func(t *testing.T) {
			s := newTestSender3895(&config.RAInterfaceConfig{
				Interface:          "trust0",
				DefaultLifetime:    lifetime,
				DefaultLifetimeSet: true,
				DNSServers:         []string{"2001:db8::53"},
				NAT64Prefix:        "64:ff9b::/96",
			})
			ra := s.buildRA()
			wire, err := ndp.MarshalMessage(ra)
			if err != nil {
				t.Fatalf("MarshalMessage: %v", err)
			}
			message, err := ndp.ParseMessage(wire)
			if err != nil {
				t.Fatalf("ParseMessage: %v", err)
			}
			decoded, ok := message.(*ndp.RouterAdvertisement)
			if !ok {
				t.Fatalf("ParseMessage returned %T, want *ndp.RouterAdvertisement", message)
			}

			wantRouterLifetime := lifetime
			if wantRouterLifetime > config.RARouterMaxLifetimeSeconds {
				wantRouterLifetime = config.RARouterMaxLifetimeSeconds
			}
			wantOptionLifetime := wantRouterLifetime
			if wantOptionLifetime <= 0 {
				wantOptionLifetime = defaultRouterLifetime
			}
			wantPREF64Lifetime := wantOptionLifetime
			if wantPREF64Lifetime > config.RAPREF64MaxLifetimeSeconds {
				wantPREF64Lifetime = config.RAPREF64MaxLifetimeSeconds
			}
			if got := int(decoded.RouterLifetime / time.Second); got != wantRouterLifetime {
				t.Errorf("wire Router Lifetime = %d, want clamped value %d", got, wantRouterLifetime)
			}

			var dns *ndp.RecursiveDNSServer
			var pref64 *ndp.PREF64
			for _, option := range decoded.Options {
				switch option := option.(type) {
				case *ndp.RecursiveDNSServer:
					dns = option
				case *ndp.PREF64:
					pref64 = option
				}
			}
			if dns == nil {
				t.Fatal("inherited RDNSS option is missing")
			}
			if got := int(dns.Lifetime / time.Second); got != wantOptionLifetime {
				t.Errorf("wire RDNSS Lifetime = %d, want inherited option lifetime %d", got, wantOptionLifetime)
			}
			if pref64 == nil {
				t.Fatal("inherited PREF64 was silently pruned")
			}
			if got := int(pref64.Lifetime / time.Second); got != wantPREF64Lifetime {
				t.Errorf("wire PREF64 Lifetime = %d, want saturated/fallback value %d", got, wantPREF64Lifetime)
			}
			// A repeat build must not repeat the saturation warning for this sender.
			s.buildRA()
		})
	}

	if got := strings.Count(log.String(), "clamped inherited PREF64 lifetime"); got != 5 {
		t.Errorf("inherited PREF64 saturation warnings = %d, want one per sender (5)", got)
	}
}
