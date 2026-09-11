package policymatch

import "testing"

// #9603 in the simulator: tcp/135 beside a lost `uuid` is reported refused,
// not permitted as every MS-RPC interface on tcp/135.
func TestUnimplementedJunosStatementIsReportedAsRefused9603(t *testing.T) {
	cfg := lenientPolicyText9595(t, `application a { protocol tcp; destination-port 135; uuid 1be617c0-31a5-11cf-a7d8-00805f48a135; }`, "permit", "deny-all")
	if res := Match(cfg, tcpQuery9595(135)); !res.ContentRejected {
		t.Fatalf("tcp/135 must be refused, not permitted past a dropped uuid; got %+v", res)
	}
}
