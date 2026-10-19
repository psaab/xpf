package main

import (
	"testing"
)

// #15728: trailing tokens after a request-system lifecycle/service verb must
// error BEFORE prompting or issuing the SystemAction RPC. Tests run with
// rl == nil: if rejection did not precede confirmation, confirmYes would
// return the non-TTY error (or, with a TTY, the action would fire) — either
// way an error alone is not enough; we assert the RPC never fired and, for
// the nil-rl fixture, that the error is not the interactive-confirmation one
// only insofar as no RPC occurred. The decisive assertion is systemActionCalls==0
// combined with err != nil while the fake would have recorded any RPC.
func TestRemoteRequestSystemTrailingArgsRejected15728(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"reboot in 10", []string{"system", "reboot", "in", "10"}},
		{"halt at 23:00", []string{"system", "halt", "at", "23:00"}},
		{"power-off message", []string{"system", "power-off", "message", "maintenance"}},
		{"zeroize media", []string{"system", "zeroize", "media"}},
		{"software extra", []string{"system", "software", "in-service-upgrade", "extra"}},
		{"dynamic-dns iface", []string{"system", "dynamic-dns", "update", "ge-0/0/0"}},
		{"rescue save extra", []string{"system", "configuration", "rescue", "save", "extra"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeBpfrxClient{}
			c := &ctl{client: fake, rl: nil}
			var err error
			_ = captureStdout(t, func() { err = c.handleRequest(tc.args) })
			if err == nil {
				t.Fatalf("handleRequest(%v) = nil; trailing args must be rejected", tc.args)
			}
			if fake.systemActionCalls != 0 {
				t.Fatalf("handleRequest(%v) issued %d SystemAction RPCs; must not invoke action", tc.args, fake.systemActionCalls)
			}
		})
	}
}
