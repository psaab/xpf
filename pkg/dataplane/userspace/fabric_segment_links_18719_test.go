package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/fabricsegment"
)

// #18719: the watcher is fed the RESOLVED fabric identity, and a link whose
// peer MAC has not resolved yet is projected but not armable (every peer
// frame would otherwise read as foreign).
func TestFabricSegmentLinksProjectResolvedIdentity18719(t *testing.T) {
	links := fabricSegmentLinks([]FabricSnapshot{
		{Name: "fab0", ParentLinuxName: "ge-0-0-0", ParentIfindex: 4, LocalMAC: "10:66:6a:00:00:01", PeerMAC: "10:66:6a:00:00:02"},
		{Name: "fab1", ParentLinuxName: "ge-0-0-3", ParentIfindex: 7, LocalMAC: "10:66:6a:00:00:03", PeerMAC: ""},
	})
	if len(links) != 2 {
		t.Fatalf("links = %v, want 2", links)
	}
	got := links[0]
	if got.Name != "fab0" || got.Parent != "ge-0-0-0" || got.ParentIfindex != 4 ||
		got.LocalMAC.String() != "10:66:6a:00:00:01" || got.PeerMAC.String() != "10:66:6a:00:00:02" {
		t.Fatalf("fab0 projected as %+v", got)
	}
	if !fabricsegment.Armable(links[0]) {
		t.Fatal("a resolved fabric link must be armable")
	}
	if fabricsegment.Armable(links[1]) {
		t.Fatal("a fabric link with no resolved peer MAC must not be armable")
	}
}
