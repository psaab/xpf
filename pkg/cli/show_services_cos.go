package cli

import (
	"fmt"

	"github.com/psaab/xpf/pkg/cmdtree"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
)

// handleShowClassOfService dispatches `show class-of-service ...`
// to the appropriate presenter.
func (c *CLI) handleShowClassOfService(args []string) error {
	if len(args) == 0 {
		cmdtree.PrintTreeHelp("show class-of-service:", operationalTree, "show", "class-of-service")
		return nil
	}
	switch args[0] {
	case "interface":
		selector := ""
		if len(args) > 1 {
			selector = args[1]
		}
		return c.showClassOfServiceInterface(selector)
	case "classifier":
		nameFilter, typeFilter, err := cmdtree.ParseCoSNameTypeArgs(args[1:])
		if err != nil {
			return err
		}
		fmt.Print(dpformat.FormatCoSClassifiers(c.store.ActiveConfig(), nameFilter, typeFilter))
		return nil
	case "rewrite-rule":
		// #6848: same `name`/`type` filter grammar as `classifier`, so the two
		// sibling commands parse identically; the parser is shared rather than
		// duplicated. #6858: it is shared with the REMOTE binary too — see
		// cmdtree.ParseCoSNameTypeArgs.
		nameFilter, typeFilter, err := cmdtree.ParseCoSNameTypeArgs(args[1:])
		if err != nil {
			return err
		}
		fmt.Print(dpformat.FormatCoSRewriteRules(c.store.ActiveConfig(), nameFilter, typeFilter))
		return nil
	case "scheduler-map":
		name := ""
		if len(args) > 1 {
			name = args[1]
		}
		fmt.Print(dpformat.FormatCoSSchedulerMaps(c.store.ActiveConfig(), name))
		return nil
	case "forwarding-class":
		fmt.Print(dpformat.FormatCoSForwardingClasses(c.store.ActiveConfig()))
		return nil
	default:
		cmdtree.PrintTreeHelp("show class-of-service:", operationalTree, "show", "class-of-service")
		return nil
	}
}

func (c *CLI) showClassOfServiceInterface(selector string) error {
	cfg := c.store.ActiveConfig()
	var status *dpuserspace.ProcessStatus
	if userspaceStatus, err := c.userspaceDataplaneStatus(); err == nil {
		status = &userspaceStatus
	}
	fmt.Print(dpformat.FormatCoSInterfaceSummary(cfg, status, selector))
	return nil
}

// showInterfacesQueue renders `show interfaces queue [<interface>]` (#4228
// Gap 7) from the live userspace CoS runtime snapshot.
func (c *CLI) showInterfacesQueue(selector string) error {
	var status *dpuserspace.ProcessStatus
	userspaceStatus, statusErr := c.userspaceDataplaneStatus()
	if statusErr == nil {
		status = &userspaceStatus
	}
	// Pass the fetch error through so a failed status retrieval renders as an
	// explicit error, not "No class-of-service queues active" (#5326): a nil
	// status must not conflate "unreachable" with "empty".
	fmt.Print(dpformat.FormatInterfacesQueue(status, statusErr, selector))
	return nil
}
