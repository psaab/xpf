package frr

import (
	"context"
	"testing"
)

// bgpSummaryJSONFixture is a captured-shape "show bgp summary json" output
// with two ESTABLISHED IPv4 peers (pfxRcd 3 and 1) plus the sibling
// footer fields FRR emits alongside the peers map (totalPeers,
// displayedPeers, failedPeers, bestPath). It mirrors FRR 8/9/10's schema:
// the top level is keyed by AFI/SAFI ("ipv4Unicast"), each peer carries a
// real "pfxRcd" and a "state" string, and Established peers report their
// prefix count.
const bgpSummaryJSONFixture = `{
  "ipv4Unicast": {
    "routerId": "10.0.0.1",
    "as": 65001,
    "vrfId": 0,
    "vrfName": "default",
    "tableVersion": 6,
    "ribCount": 7,
    "ribMemory": 1344,
    "peerCount": 2,
    "peerMemory": 39936,
    "peers": {
      "10.0.0.2": {
        "hostname": "r2",
        "remoteAs": 65002,
        "localAs": 65001,
        "version": 4,
        "msgRcvd": 124,
        "msgSent": 130,
        "tableVersion": 0,
        "outq": 0,
        "inq": 0,
        "peerUptime": "01:05:12",
        "peerUptimeMsec": 3912000,
        "pfxRcd": 3,
        "pfxSnt": 4,
        "state": "Established",
        "peerState": "OK",
        "idType": "ipv4"
      },
      "10.0.0.6": {
        "hostname": "r3",
        "remoteAs": 65003,
        "localAs": 65001,
        "version": 4,
        "msgRcvd": 98,
        "msgSent": 101,
        "tableVersion": 0,
        "outq": 0,
        "inq": 0,
        "peerUptime": "00:42:37",
        "peerUptimeMsec": 2557000,
        "pfxRcd": 1,
        "pfxSnt": 4,
        "state": "Established",
        "peerState": "OK",
        "idType": "ipv4"
      }
    },
    "failedPeers": 0,
    "displayedPeers": 2,
    "totalPeers": 2,
    "dynamicPeers": 0,
    "bestPath": {
      "multiPathRelax": "false"
    }
  }
}`

// bgpSummaryTextFixture is the equivalent legacy "show bgp summary" text
// table the OLD scraper consumed. It has the same two Established peers
// (the "State/PfxRcd" column shows the prefix count for an Established
// peer) plus the "Total number of neighbors 2" footer. The old
// field-count scraper misparsed the footer as a third phantom peer
// (Neighbor="Total") and stored the pfxRcd digit in State while leaving
// PfxRcd empty. Supplying BOTH command responses makes the assertions in
// TestGetBGPSummaryJSON go RED when GetBGPSummary is reverted to scrape
// this text (3 peers, phantom "Total", empty PfxRcd).
const bgpSummaryTextFixture = `IPv4 Unicast Summary (VRF default):
BGP router identifier 10.0.0.1, local AS number 65001 vrf-id 0
BGP table version 6
RIB entries 7, using 1344 bytes of memory
Peers 2, using 39 KiB of memory

Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
10.0.0.2        4      65002       124       130        0    0    0 01:05:12            3        4 N/A
10.0.0.6        4      65003        98       101        0    0    0 00:42:37            1        4 N/A

Total number of neighbors 2
`

// TestGetBGPSummaryJSON pins GetBGPSummary against a real-shape FRR
// summary: exactly two peers, correct per-peer PfxRcd read from the JSON
// "pfxRcd" field, and no phantom footer peer. On revert (text scraping)
// this goes RED: the "Total number of neighbors 2" footer becomes a
// third phantom peer and PfxRcd is never populated. #3942.
func TestGetBGPSummaryJSON(t *testing.T) {
	fake := &fakeExecutor{
		vtyshResp: map[string]string{
			"show bgp vrf all summary json": bgpSummaryJSONFixture,
			// Legacy command the reverted implementation would call.
			"show bgp summary": bgpSummaryTextFixture,
		},
	}
	m := &Manager{exec: fake}

	peers, err := m.GetBGPSummary(context.Background())
	if err != nil {
		t.Fatalf("GetBGPSummary: %v", err)
	}
	// Exactly two peers — no phantom footer/trailer peer.
	if len(peers) != 2 {
		t.Fatalf("GetBGPSummary returned %d peers, want 2: %+v", len(peers), peers)
	}
	for _, p := range peers {
		if p.Neighbor == "Total" {
			t.Fatalf("phantom footer parsed as a peer: %+v", p)
		}
	}
	// Sorted by neighbor address: 10.0.0.2 then 10.0.0.6.
	if peers[0].Neighbor != "10.0.0.2" {
		t.Errorf("peers[0].Neighbor = %q, want 10.0.0.2", peers[0].Neighbor)
	}
	if peers[0].PfxRcd != "3" {
		t.Errorf("peers[0].PfxRcd = %q, want 3", peers[0].PfxRcd)
	}
	if peers[0].AS != "65002" {
		t.Errorf("peers[0].AS = %q, want 65002", peers[0].AS)
	}
	if peers[0].State != "Established" {
		t.Errorf("peers[0].State = %q, want Established", peers[0].State)
	}
	if peers[0].UpDown != "01:05:12" {
		t.Errorf("peers[0].UpDown = %q, want 01:05:12", peers[0].UpDown)
	}
	if peers[0].MsgRcvd != "124" || peers[0].MsgSent != "130" {
		t.Errorf("peers[0] Msg counts = %q/%q, want 124/130", peers[0].MsgRcvd, peers[0].MsgSent)
	}
	if peers[0].AddressFamily != "ipv4-unicast" {
		t.Errorf("peers[0].AddressFamily = %q, want ipv4-unicast", peers[0].AddressFamily)
	}
	if peers[1].Neighbor != "10.0.0.6" {
		t.Errorf("peers[1].Neighbor = %q, want 10.0.0.6", peers[1].Neighbor)
	}
	if peers[1].PfxRcd != "1" {
		t.Errorf("peers[1].PfxRcd = %q, want 1", peers[1].PfxRcd)
	}
	// The JSON command must be the one issued.
	if fake.lastVtyshCmd != "show bgp vrf all summary json" {
		t.Errorf("Vtysh called with %q, want %q", fake.lastVtyshCmd, "show bgp vrf all summary json")
	}
}

// bgpSummaryDualFamilyFixture covers an IPv4 + IPv6 summary: one
// Established IPv4 peer and one Established IPv6 peer, exercising the
// per-family split and the AFI/SAFI label mapping.
const bgpSummaryDualFamilyFixture = `{
  "ipv4Unicast": {
    "routerId": "10.0.0.1",
    "as": 65001,
    "vrfName": "default",
    "peers": {
      "10.0.0.2": {
        "remoteAs": 65002,
        "msgRcvd": 10,
        "msgSent": 11,
        "peerUptime": "00:10:00",
        "pfxRcd": 4,
        "pfxSnt": 2,
        "state": "Established"
      }
    }
  },
  "ipv6Unicast": {
    "routerId": "10.0.0.1",
    "as": 65001,
    "vrfName": "default",
    "peers": {
      "2001:db8::2": {
        "remoteAs": 65002,
        "msgRcvd": 8,
        "msgSent": 9,
        "peerUptime": "00:05:00",
        "pfxRcd": 2,
        "pfxSnt": 1,
        "state": "Established"
      }
    }
  }
}`

// TestGetBGPSummaryDualFamily verifies IPv4 and IPv6 peers are both
// returned with the correct family label and per-family PfxRcd. #3942.
func TestGetBGPSummaryDualFamily(t *testing.T) {
	fake := &fakeExecutor{
		vtyshResp: map[string]string{"show bgp vrf all summary json": bgpSummaryDualFamilyFixture},
	}
	m := &Manager{exec: fake}

	peers, err := m.GetBGPSummary(context.Background())
	if err != nil {
		t.Fatalf("GetBGPSummary: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("GetBGPSummary returned %d peers, want 2: %+v", len(peers), peers)
	}
	// Families are sorted: ipv4Unicast < ipv6Unicast.
	if peers[0].AddressFamily != "ipv4-unicast" || peers[0].Neighbor != "10.0.0.2" || peers[0].PfxRcd != "4" {
		t.Errorf("peers[0] = %+v, want ipv4-unicast 10.0.0.2 PfxRcd 4", peers[0])
	}
	if peers[1].AddressFamily != "ipv6-unicast" || peers[1].Neighbor != "2001:db8::2" || peers[1].PfxRcd != "2" {
		t.Errorf("peers[1] = %+v, want ipv6-unicast 2001:db8::2 PfxRcd 2", peers[1])
	}
}

// TestGetBGPSummaryNotEstablished verifies a peer that has not reached
// Established reports its state string and PfxRcd 0 (never a state string
// stuffed into PfxRcd or vice versa). #3942.
func TestGetBGPSummaryNotEstablished(t *testing.T) {
	const fixture = `{
  "ipv4Unicast": {
    "as": 65001,
    "peers": {
      "10.0.0.9": {
        "remoteAs": 65009,
        "msgRcvd": 0,
        "msgSent": 0,
        "peerUptime": "never",
        "pfxRcd": 0,
        "state": "Active"
      }
    }
  }
}`
	fake := &fakeExecutor{
		vtyshResp: map[string]string{"show bgp vrf all summary json": fixture},
	}
	m := &Manager{exec: fake}

	peers, err := m.GetBGPSummary(context.Background())
	if err != nil {
		t.Fatalf("GetBGPSummary: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("GetBGPSummary returned %d peers, want 1", len(peers))
	}
	if peers[0].State != "Active" {
		t.Errorf("peers[0].State = %q, want Active", peers[0].State)
	}
	if peers[0].PfxRcd != "0" {
		t.Errorf("peers[0].PfxRcd = %q, want 0", peers[0].PfxRcd)
	}
	if peers[0].UpDown != "never" {
		t.Errorf("peers[0].UpDown = %q, want never", peers[0].UpDown)
	}
}

// TestGetBGPSummaryNoPeers verifies the empty / peerless / non-JSON
// responses all yield no peers and no error (not a phantom peer, not a
// hard error on the show path). #3942.
func TestGetBGPSummaryNoPeers(t *testing.T) {
	cases := map[string]string{
		"empty object":    `{}`,
		"family no peers": `{"ipv4Unicast":{"as":65001,"peers":{},"totalPeers":0}}`,
		"warning sibling": `{"warning":"No BGP process is configured"}`,
		"non-json banner": `% BGP instance not found`,
		"whitespace":      "  \n\t ",
	}
	for name, out := range cases {
		fake := &fakeExecutor{
			vtyshResp: map[string]string{"show bgp vrf all summary json": out},
		}
		m := &Manager{exec: fake}
		peers, err := m.GetBGPSummary(context.Background())
		if err != nil {
			t.Errorf("%s: GetBGPSummary error = %v, want nil", name, err)
		}
		if len(peers) != 0 {
			t.Errorf("%s: GetBGPSummary returned %d peers, want 0: %+v", name, len(peers), peers)
		}
	}
}
