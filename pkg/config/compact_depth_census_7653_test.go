package config

// compact_depth_census_7653_test.go — #7653.
//
// The #2419 census measures ONE packing depth. For a site with container path
// `[... authentication]` and leaf `simple-password` it compares
//
//	authentication { simple-password "x"; }     the block spelling
//	authentication simple-password "x";         the compact spelling
//
// which packs exactly ONE container onto the leaf line. Junos compaction is
// recursive, and operators write it that way:
//
//	authentication simple-password "x"    <- 2 tokens of packing  (measured)
//	authentication md5 7 key "x"          <- 3 tokens             (NOT measured)
//
// Every depth beyond the first is unmeasured, and a compiler that reads
// `prop.Children` correctly at one level can still drop the body at two. So the
// existing 354-divergent figure is a floor in a second, previously unstated
// dimension: not only "204 unruled sites", but "one packing depth of an
// arbitrarily deep spelling".
//
// This file extends the SAME walker rather than re-deriving it — same
// collectCompactSites, compactCensusPair, contextFor, nest, compileText,
// cfgEqual — so the two censuses cannot drift into disagreeing about what a site is.

import (
	"sort"
	"strings"
	"testing"
)

// compactAtDepth packs the last j container levels onto the leaf line.
//
// j=1 reproduces the existing census's spelling exactly, which is what makes
// this an extension rather than a parallel instrument: depth 1 must agree with
// the #2419 census cell for cell, and TestCompactDepth1AgreesWithTheBaseCensus7653
// asserts it.
func compactAtDepth(container []string, leaf, val string, j int) (string, bool) {
	if j < 1 || j > len(container) {
		return "", false
	}
	parent := container[:len(container)-j]
	tail := container[len(container)-j:]
	// #8690: the SAME scaffolding the base census uses. "Depth 1 IS the base
	// census's spelling" is this file's premise, and the agreement cell below
	// is what enforces it — it went red the moment the base census learned a
	// scaffold this walker did not have, which is the cross-check working.
	//
	// The stanza a scaffold keys on is the FIRST token of the packed tail: at
	// depth 1 that is the stanza the base census names, and at deeper j it is
	// the outermost container being packed, which is the one whose siblings the
	// compiler checks.
	stanza := ""
	if len(tail) > 0 {
		stanza = tail[0]
	}
	// #8690: the same instance-name rendering the base census uses, or "depth 1
	// IS the base census's spelling" stops being true. The scaffolds are keyed
	// on the canonical path and their TEXT is rendered to match.
	rendered := renderInstanceNames(container)
	ctx := renderScaffold(contextForStanza(parent, stanza), container, rendered)
	pre := renderScaffold(preambleFor(parent, stanza), container, rendered)
	rparent := rendered[:len(rendered)-j]
	rtail := rendered[len(rendered)-j:]
	// #9056: a VALUELESS FLAG site carries no value, so the tail ends at the
	// leaf. Appending an empty `val` would spell `... allow-dns-reply ;`, which
	// is not the operator's line and would measure the fixture rather than the
	// fold.
	rinner := strings.Join(rtail, " ") + " " + leaf + " " + val + ";"
	if val == "" {
		rinner = strings.Join(rtail, " ") + " " + leaf + ";"
	}
	return pre + nest(rparent, ctx+rinner), true
}

type depthOutcome struct {
	divergent  int
	equivalent int
	rejected   int // did not parse or compile — EXCLUDED, not counted as divergent
	unruled    int // value not observable, or no two synthesizable values
}

func (o *depthOutcome) population() int { return o.divergent + o.equivalent + o.rejected }

func runDepthCensus7653(t *testing.T) (map[int]*depthOutcome, int, map[string]bool) {
	t.Helper()
	byDepth := map[int]*depthOutcome{}
	divergentSites := map[string]bool{}
	maxJ := 0
	for _, s := range collectCompactSites() {
		if len(s.container) > 0 && strings.HasPrefix(s.container[0], "groups") {
			continue // same exclusion as the base census: schema re-host, duplicate coverage
		}
		// #9056: a flag site has no value to vary; its discriminator is
		// PRESENCE, exactly as in runCompactBlockCensus. Without this branch
		// synthPair refuses the shape, the site is skipped, and depth 1 stops
		// agreeing with the base census -- which the cell below asserts, so the
		// disagreement is what pointed here.
		var v1, v2 string
		if s.flag {
			v1, v2 = "", ""
		} else {
			var ok bool
			v1, v2, ok = compactCensusPair(s)
			if !ok {
				continue
			}
		}
		parent := s.container[:len(s.container)-1]
		stanza := s.container[len(s.container)-1]
		rendered := renderInstanceNames(s.container)
		pre := renderScaffold(preambleFor(parent, stanza), s.container, rendered)
		ctx := renderScaffold(contextForStanza(parent, stanza), s.container, rendered)
		rparent := rendered[:len(rendered)-1]
		rstanza := rendered[len(rendered)-1]
		blockV1 := pre + nest(rparent, ctx+rstanza+" { "+s.leaf+" "+v1+"; }")
		blockV2 := pre + nest(rparent, ctx+rstanza+" { "+s.leaf+" "+v2+"; }")
		if s.flag {
			blockV1 = pre + nest(rparent, ctx+rstanza+" { "+s.leaf+"; }")
			blockV2 = pre + nest(rparent, ctx+rstanza+" { }")
		}
		cb1, cb2 := compileText(t, blockV1), compileText(t, blockV2)
		if cb1 == nil || cb2 == nil {
			continue
		}
		// Same vacuity guard as the base census: if the VALUE is not observable
		// in the typed config, no depth of packing can prove anything here.
		if cfgEqual(cb1, cb2) {
			for j := 1; j <= len(s.container); j++ {
				o := outcomeFor7653(byDepth, j)
				o.unruled++
			}
			continue
		}
		for j := 1; j <= len(s.container); j++ {
			text, ok := compactAtDepth(s.container, s.leaf, v1, j)
			if !ok {
				continue
			}
			if j > maxJ {
				maxJ = j
			}
			o := outcomeFor7653(byDepth, j)
			cc := compileText(t, text)
			if cc == nil {
				// EXCLUDED per the #7653 policy call: a spelling the config
				// system already REJECTS is not a silent divergence. The defect
				// class is "accepted and dropped", not "refused".
				o.rejected++
				continue
			}
			if cfgEqual(cb1, cc) {
				o.equivalent++
			} else {
				o.divergent++
				divergentSites[strings.Join(s.container, " ")+" "+s.leaf] = true
			}
		}
	}
	return byDepth, maxJ, divergentSites
}

func outcomeFor7653(m map[int]*depthOutcome, j int) *depthOutcome {
	if m[j] == nil {
		m[j] = &depthOutcome{}
	}
	return m[j]
}

// TestCompactDepthCensus7653 reports the census across packing DEPTHS and
// ratchets the depth actually reached, so the second dimension cannot silently
// collapse back to one.
func TestCompactDepthCensus7653(t *testing.T) {
	byDepth, maxJ, divSites := runDepthCensus7653(t)

	depths := make([]int, 0, len(byDepth))
	for j := range byDepth {
		depths = append(depths, j)
	}
	sort.Ints(depths)

	t.Log("#7653 compact/block equivalence across PACKING DEPTH")
	t.Log("  depth = tokens packed onto one line: `authentication simple-password \"x\"` is 2,")
	t.Log("  `authentication md5 7 key \"x\"` is 3. The #2419 census measures depth 2 only.")
	totalDiv := 0
	for _, j := range depths {
		o := byDepth[j]
		totalDiv += o.divergent
		t.Logf("  depth %d (packs %d level(s)): population=%-4d divergent=%-4d equivalent=%-4d "+
			"rejected(excluded)=%-3d unruled=%d",
			j+1, j, o.population(), o.divergent, o.equivalent, o.rejected, o.unruled)
	}
	// CELLS are (site x depth) pairs; SITES are distinct schema paths. The
	// populations differ per depth because a shallow site has no deep spelling,
	// so the per-depth rows are NOT the same population and must not be read as
	// one shrinking cohort.
	t.Logf("  >= %d divergent CELLS (site x depth pairs) over >= %d DISTINCT SITES, "+
		"depths 2..%d.", totalDiv, len(divSites), maxJ+1)
	t.Log("  A FLOOR three times over: the base census's 204 'not observable' skips are")
	t.Log("  unruled at every depth; no depth beyond the deepest schema path is reachable;")
	t.Log("  and each row has its own population, so a site too shallow for depth 5 is")
	t.Log("  absent from that row rather than passing it.")
	t.Log("  REJECTED cells are excluded deliberately: a spelling the config system already")
	t.Log("  refuses is not a silent divergence. This class is 'accepted and dropped'.")

	// RATCHET. The point of this file is that depth > 1 is measured at all.
	if maxJ < 2 {
		t.Errorf("#7653: the depth census reached only depth %d (packing %d level). It exists "+
			"to measure RECURSIVE packing; at depth 1 it is the #2419 census with extra "+
			"steps and the second dimension has silently collapsed.", maxJ+1, maxJ)
	}
	if _, ok := byDepth[2]; !ok {
		t.Error("#7653: no depth-3 cells were produced at all — the walk stopped finding " +
			"containers two levels deep, so `authentication md5 7 key \"x\"` shaped " +
			"spellings are no longer covered.")
	}

	// ANTI-VACUITY. Existence of depth-3 cells is not evidence they PACK: a
	// generator that emitted the block spelling at every depth would produce a
	// full population, report every cell equivalent, and pass everything above.
	// Requiring a non-zero divergent count at depth 3 is what distinguishes
	// "measured and clean" from "not actually measured".
	//
	// If this ever reds, read it before changing it. Zero has two very different
	// causes: the recursive-packing class was genuinely FIXED — in which case
	// this is good news and the floor below should be raised deliberately — or
	// the generator stopped packing and the census is reporting on the block
	// spelling compared with itself.
	if d3 := byDepth[2]; d3 != nil && d3.divergent == 0 {
		t.Errorf("#7653: depth-3 reports %d cells and ZERO divergent. Either the recursive "+
			"packing class was fixed (raise this floor deliberately and say so) or the "+
			"generator is no longer packing and is comparing the block spelling with "+
			"itself.", d3.population())
	}

	// The rate is the finding, so it is asserted rather than merely printed:
	// divergence must not be LOWER at depth 3 than at depth 2. A compiler that
	// handles one level of packing can drop the body at two, and every
	// measurement so far says deeper is worse, never better. If that inverts,
	// something structural changed and the report's headline is wrong.
	if d2, d3 := byDepth[1], byDepth[2]; d2 != nil && d3 != nil &&
		d2.population() > 0 && d3.population() > 0 {
		r2 := float64(d2.divergent) / float64(d2.population())
		r3 := float64(d3.divergent) / float64(d3.population())
		if r3 < r2 {
			t.Errorf("#7653: divergence RATE fell with depth (depth2 %.1f%% -> depth3 %.1f%%). "+
				"Every measurement of this class says deeper packing is dropped more "+
				"often, not less; an inversion means the generator or the population "+
				"changed shape and the report's headline needs re-deriving.",
				r2*100, r3*100)
		}
	}
}

// TestCompactDepth1AgreesWithTheBaseCensus7653 is what makes this an EXTENSION
// of the #2419 walker rather than a second opinion about it.
//
// Depth 1 is, by construction, the base census's spelling. If the two ever
// disagree about how many cells diverge there, one of them has drifted — and
// without this cell the drift would be invisible, because each reports its own
// number and neither is checked against the other.
func TestCompactDepth1AgreesWithTheBaseCensus7653(t *testing.T) {
	base := runCompactBlockCensus(t)
	byDepth, _, _ := runDepthCensus7653(t)
	d1 := byDepth[1]
	if d1 == nil {
		t.Fatal("#7653: the depth census produced no depth-1 cells, so it cannot be " +
			"cross-checked against the #2419 census at all")
	}
	if d1.divergent != len(base.divergent) {
		t.Errorf("#7653: depth-1 divergent count %d != #2419 census divergent count %d.\n"+
			"    Depth 1 IS the base census's spelling, so these must agree. One of the "+
			"two walkers has drifted (fixture context, skip buckets, or the compact "+
			"rendering itself).", d1.divergent, len(base.divergent))
	}
}
