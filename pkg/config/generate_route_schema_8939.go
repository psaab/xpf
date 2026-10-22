package config

// #8939 at `routing-options generate route`: A PACKED RUN LOST THE POLICY.
//
//	set routing-options generate route 10.0.0.0/8 discard policy P
//	  -> Discard=true  Policy=""
//
// SetPath nests as `[route <p>] > [discard policy P]`, so FindChild("discard")
// matched while `policy P` sat on that same node's Keys and was never read.
//
// The consequence is the wrong direction: a generate route's POLICY is what
// selects its contributing routes, so losing it leaves the aggregate's
// contributor set unconstrained rather than empty — it generates on
// contributions the operator meant to exclude.
func generateRouteSchema8939() *schemaNode {
	return refGenerateRoute.resolve()
}
