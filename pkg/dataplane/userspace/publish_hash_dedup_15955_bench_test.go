package userspace

import (
	"fmt"
	"testing"
	"time"
)

// Benchmarks for #15955. They drive the publish-path hash sequence of a
// PreparedLocked publisher at the two snapshot sizes the issue measured
// (202 KB and 1.5 MB JSON). The triple variant reproduces the pre-fix
// overlay sequence — hash(next) for the dedup compare,
// stampSnapshotContentDigest(publishSnap) at the send site, and
// hash(publishSnap) for lastSnapshotHash. The dedup variant reproduces
// the post-fix sequence through the production entry points: one
// snapshotContentHash over the final publish snapshot, the
// stampSnapshotContentDigestPrehashed stamp (no recompute), and
// postPublishHash for the post-publish bookkeeping (reuses the same
// hash unless the ClearPolicies marker was in force).
//
// Measured on the campaign host (Xeon D-2146NT, schedutil governor;
// ratios are the stable quantity) BEFORE the fix, benchtime 20x:
//
//	BenchmarkPublishHash15955_202KB_triple-16   20   20235395 ns/op    991710 B/op   2022 allocs/op
//	BenchmarkPublishHash15955_202KB_dedup-16    20   13615604 ns/op    392441 B/op   1010 allocs/op
//	BenchmarkPublishHash15955_1p5MB_triple-16   20  149235188 ns/op  10415602 B/op   8047 allocs/op
//	BenchmarkPublishHash15955_1p5MB_dedup-16    20   68856510 ns/op   3404140 B/op   4016 allocs/op
//
// (dedup-modeled, calling the same production hash/stamp helpers the
// deduped publishers call; the after numbers from the landed code are
// reproduced in the PR body.)

func benchSnapshot15955(routes, neigh, pols int) *ConfigSnapshot {
	s := &ConfigSnapshot{Version: ProtocolVersion, Generation: 42, FIBGeneration: 3,
		GeneratedAt: time.Unix(100, 0).UTC(), DefaultPolicy: "permit"}
	for i := range routes {
		s.Routes = append(s.Routes, RouteSnapshot{Table: "inet.0", Family: "inet",
			Destination: fmt.Sprintf("10.%d.%d.0/24", i>>8, i&255),
			NextHops:    []string{fmt.Sprintf("172.16.%d.1", i&255)}})
	}
	for i := range neigh {
		s.Neighbors = append(s.Neighbors, NeighborSnapshot{Interface: "reth0.80", Ifindex: 5,
			Family: "inet", IP: fmt.Sprintf("172.16.%d.%d", i>>8, i&255),
			MAC: "aa:bb:cc:dd:ee:ff", State: "reachable"})
	}
	for i := range pols {
		s.Policies = append(s.Policies, PolicyRuleSnapshot{Name: fmt.Sprintf("p%d", i),
			FromZone: "trust", ToZone: "untrust",
			SourceLiterals: []string{"10.0.0.0/8"}, DestinationLiterals: []string{"0.0.0.0/0"},
			Applications: []string{"any"}, Action: "permit"})
	}
	return s
}

// benchPublishTriple15955 is the pre-#15955 overlay sequence, kept as the
// regression baseline: three full marshal+SHA-256 passes per publish.
func benchPublishTriple15955(b *testing.B, routes, neigh, pols int) {
	next := benchSnapshot15955(routes, neigh, pols)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, ok := snapshotContentHash(next); !ok {
			b.Fatal("dedup hash failed")
		}
		publishSnap := *next
		publishSnap.Neighbors = filterPublishableNeighbors(next.Neighbors)
		if err := stampSnapshotContentDigest(&publishSnap); err != nil {
			b.Fatalf("stamp: %v", err)
		}
		if _, ok := snapshotContentHash(&publishSnap); !ok {
			b.Fatal("post hash failed")
		}
	}
}

// benchPublishDedup15955 is the post-#15955 overlay sequence through the
// production helpers the deduped publishers call.
func benchPublishDedup15955(b *testing.B, routes, neigh, pols int) {
	next := benchSnapshot15955(routes, neigh, pols)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		publishSnap := *next
		publishSnap.Neighbors = filterPublishableNeighbors(next.Neighbors)
		publishHash, publishHashOK := snapshotContentHash(&publishSnap)
		preSendClear := publishSnap.ClearPolicies
		if err := stampSnapshotContentDigestPrehashed(&publishSnap, publishHash, publishHashOK); err != nil {
			b.Fatalf("prehashed stamp: %v", err)
		}
		if _, ok := postPublishHash(&publishSnap, publishHash, publishHashOK, preSendClear); !ok {
			b.Fatal("post hash failed")
		}
	}
}

func BenchmarkPublishHash15955_202KB_triple(b *testing.B) { benchPublishTriple15955(b, 1000, 500, 200) }
func BenchmarkPublishHash15955_202KB_dedup(b *testing.B)  { benchPublishDedup15955(b, 1000, 500, 200) }
func BenchmarkPublishHash15955_1p5MB_triple(b *testing.B) {
	benchPublishTriple15955(b, 10000, 2000, 1000)
}
func BenchmarkPublishHash15955_1p5MB_dedup(b *testing.B) {
	benchPublishDedup15955(b, 10000, 2000, 1000)
}
