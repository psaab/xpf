package main

import (
	"fmt"

	"github.com/psaab/xpf/pkg/cmdtree"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// interfaceModifierTopic maps each declared `show interfaces` modifier to the
// ShowText topic that renders it. `terse` is absent deliberately: it is served
// by the typed ShowInterfacesDetail RPC below, not by a topic.
//
// A modifier missing from this map is a modifier the remote CLI cannot render
// WITH a selector. It must refuse rather than issue a request that silently
// drops the selector — see showInterfaces.
var interfaceModifierTopic = map[string]string{
	"detail":     "interfaces-detail",
	"extensive":  "interfaces-extensive",
	"statistics": "interfaces-statistics",
	"queue":      "interfaces-queue",
}

// showInterfaces dispatches `show interfaces [<name>] [<modifier>]`.
//
// #9065: this was a positional ladder that branched on args[0] and then, in a
// trailing loop, assigned `req.Filter = a` for every non-`terse` word — so the
// MODIFIER overwrote the interface name. `show interfaces ge-0/0/1 extensive`
// sent Filter="extensive", nothing matched, and the operator got EMPTY output
// for an interface that exists. The ladder happened to enumerate `<name>
// detail` one line above, which is why the defect looked like a one-off rather
// than the ordering it is.
//
// The split is now position-independent and derived from the command tree
// (cmdtree.SplitModifiersAt), so a modifier child added to the tree later
// cannot become the next member by being unenumerated here.
func (c *ctl) showInterfaces(args []string) error {
	split, ok := cmdtree.SplitModifiersAt([]string{"show", "interfaces"}, args)
	if !ok {
		return fmt.Errorf("internal: no command tree node for `show interfaces`")
	}
	if len(split.Ambiguous) > 0 {
		return fmt.Errorf("ambiguous keyword %q after `show interfaces`", split.Ambiguous[0])
	}
	if len(split.Extra) > 0 {
		return fmt.Errorf("unexpected argument %q: `show interfaces` takes at most one "+
			"interface name", split.Extra[0])
	}
	if len(split.Modifiers) > 1 {
		return fmt.Errorf("`show interfaces` takes one modifier, got %v", split.Modifiers)
	}

	if len(split.Modifiers) == 0 {
		// No modifier: the typed RPC, with the selector bound as the filter.
		return c.showInterfacesDetailRPC(split.Selector, false)
	}
	mod := split.Modifiers[0]

	if mod == "terse" {
		if split.Selector != "" {
			return fmt.Errorf("`show interfaces terse` does not take an interface name (got %q)", split.Selector)
		}
		return c.showInterfacesDetailRPC(split.Selector, true)
	}
	if (mod == "statistics") && split.Selector != "" {
		return fmt.Errorf("`show interfaces statistics` does not take an interface name (got %q)", split.Selector)
	}
	if mod == "tunnel" {
		// `show interfaces tunnel` is an inventory of tunnel interfaces, not a
		// per-interface view: the `tunnels` topic renders the whole set and the
		// daemon has no selector for it. REFUSING is the point of #9065 — the
		// old code accepted the pair and silently answered a different
		// question. If a selector is ever wanted here it needs a server-side
		// filter first, exactly as extensive/statistics got one.
		if split.Selector != "" {
			return fmt.Errorf("`show interfaces tunnel` does not take an interface "+
				"name (got %q); it lists all tunnel interfaces", split.Selector)
		}
		return c.showCommand("show interfaces tunnel")
	}
	topic, known := interfaceModifierTopic[mod]
	if !known {
		return fmt.Errorf("internal: `show interfaces %s` has no renderer; it must not "+
			"silently drop the interface name", mod)
	}
	return c.showTextFiltered(topic, split.Selector)
}

func (c *ctl) showInterfacesDetailRPC(filter string, terse bool) error {
	resp, err := c.client.ShowInterfacesDetail(c.ctx(),
		&pb.ShowInterfacesDetailRequest{Filter: filter, Terse: terse})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Print(resp.Output)
	return nil
}
