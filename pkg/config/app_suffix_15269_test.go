package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestApplicationSuffix15269(t *testing.T) {
	typ, cod := uint8(8), uint8(0)
	app := &Application{Name: "ping", Protocol: "icmp", SourcePort: "1024-65535", ICMPType: &typ, ICMPCode: &cod, InactivityTimeout: 60}
	got := ApplicationTermSuffix(app)
	for _, want := range []string{"src-port=1024-65535", "icmp-type=8", "icmp-code=0", "timeout=60s"} {
		if !strings.Contains(got, want) {
			t.Errorf("suffix %q missing %q", got, want)
		}
	}
	if ApplicationTermSuffix(nil) != "" {
		t.Error("nil must be empty")
	}
	never := &Application{Protocol: "tcp", InactivityTimeoutNever: true}
	if !strings.Contains(ApplicationTermSuffix(never), "timeout=never") {
		t.Errorf("never: %q", ApplicationTermSuffix(never))
	}
	plain := fmt.Sprint(ApplicationTermSuffix(&Application{Protocol: "tcp", DestinationPort: "80"}))
	if plain != "" {
		t.Errorf("plain suffix=%q, want empty", plain)
	}
}
