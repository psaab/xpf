package dhcpserver

// Kea Lease File Cleanup (LFC) file-set naming + read order (#5796).
//
// Kea's memfile backend never rewrites the lease file in place between LFC
// compactions — every renewal / release / decline / expiry-reclaim is APPENDED
// — and it periodically runs kea-lfc to compact the log. During AND after a
// cleanup the live lease set is NOT the current file alone; it spans Kea's LFC
// file set. Reading only the current file loses every lease that currently
// lives in the previous or input file: right after LFC rotates the current
// file, that file is a fresh (often header-only) append log while the active
// leases sit in the compacted previous file. A header-only current file must
// therefore never by itself authorize the destructive DDNS trusted-empty diff.
//
// File naming is authoritative from Kea source
// (src/lib/dhcpsrv/memfile_lease_mgr.cc, appendSuffix / LFCFileType) for a
// current lease file <f>:
//
//	<f>            CURRENT  — the live append log the server writes now.
//	<f>.1          INPUT    — the current file the server MOVES ASIDE at the
//	                          START of a cleanup; kea-lfc reads it. Present only
//	                          while a cleanup is in progress (or left behind by a
//	                          crashed cleanup).
//	<f>.2          PREVIOUS — the COMPACTED result of the last COMPLETED cleanup
//	                          (one row per active lease). Present once any LFC
//	                          has run.
//	<f>.output     kea-lfc's temporary compaction output.
//	<f>.completed  kea-lfc's finished, lease-bearing compacted output.
//	<f>.pid        kea-lfc's pid file.
//
// Kea's startup loader gives .completed precedence over .2/.1 when it exists
// (memfile_lease_mgr.cc loadLeasesFromFiles); a stale orphan can therefore
// resurrect rows even though the generation files were replaced. The display
// and DDNS reader below intentionally ignores .output and .completed, because
// its candidate-path contract reads only .2, .1, and the current file.
//
// #5938 Invariant 3 — crash-interrupted-cleanup handling for the display/DDNS
// reader. A cleanup can leave `.output` and/or `.completed` behind, so this
// reader intentionally skips both. `.output` is safe to skip because it is
// built by merging INPUT (.1) and PREVIOUS (.2); every lease key it could
// contain is already in the .1/.2 union.
//
// `.completed` is different: it is lease-bearing and Kea startup gives it
// precedence over `.2`/.1. Kea's rotation removes old `.2`, removes `.1`, then
// renames `.completed` to `.2`; a crash between those removals and the rename
// can leave leases only in `.completed`. The display/DDNS reader would then
// miss those leases. This is a known reader gap, not a proof that ignoring
// `.completed` is safe; destructive pre-seed replacement removes the orphan
// before promoted Kea starts, and the reader gap remains a follow-up.
//
// TestKeaLFCIntermediatesIgnored pins only the current reader contract when
// `.2` and `.1` remain present: `.output`/`.completed` do not change its
// resolved lease set, and a lease living in `.output` is already covered by
// `.2`/`.1`.
//
// NOTE the suffix mapping: .1 is INPUT and .2 is PREVIOUS — so the
// CHRONOLOGICAL read order (oldest → newest) is .2 → .1 → current, i.e. the
// previous-compacted snapshot first, then the input file, then the current
// append log.
//
// keaLFCLeaseFilePaths returns the candidate paths in that chronological order.
// A reader that OPENS each in turn (treating a missing file as simply absent —
// skip, not an error) and replays the rows through the SAME append-only,
// last-row-wins dedup the single-file parsers already use gets Kea's own final
// disposition per lease key: a newer row in INPUT or CURRENT supersedes an older
// row in PREVIOUS, and a release/expiry row still tombstones a lease that a
// later re-allocation can reclaim. On a steady-state box with no LFC in progress
// (.1/.2 absent) the set collapses to exactly the current file, so behavior is
// byte-identical to the pre-#5796 single-file read.
func keaLFCLeaseFilePaths(current string) []string {
	return []string{current + ".2", current + ".1", current}
}
