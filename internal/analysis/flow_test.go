package analysis

import (
	"testing"
)

// TestBuildFlowGraph_Basic verifies that a single ALLOW policy with one SCIM
// group, connector group, segment group, and segment produces all five
// expected column nodes and the four edges that wire them together
// (SCIM->Policy->ConnectorGroup->SegmentGroup->Segment).
func TestBuildFlowGraph_Basic(t *testing.T) {
	idx := newIndex()
	idx.Segments["seg1"] = seg("seg1", "Seg1", "grp1")
	idx.SegmentGroups["grp1"] = segGroup("grp1", "Grp1", "seg1")
	idx.ScimGroups[100] = scim(100, "Admins")

	registerPolicy(idx, withConnectorGroup(policy("pol1", "P1", "ALLOW", "1",
		cond("AND", op("APP", "seg1"), op("SCIM_GROUP", "100"))), "cg1", "CG1"))

	graph := BuildFlowGraph(idx, GraphQueryBody{})

	wantNodes := map[string]bool{
		"g:100": false, "p:pol1": false, "cg:cg1": false, "sg:grp1": false, "s:seg1": false,
	}
	for _, n := range graph.Nodes {
		if _, ok := wantNodes[n.ID]; ok {
			wantNodes[n.ID] = true
		}
	}
	for id, present := range wantNodes {
		if !present {
			t.Errorf("missing node %q", id)
		}
	}

	wantEdges := map[string]bool{
		"g:100->p:pol1":    false,
		"p:pol1->cg:cg1":   false,
		"cg:cg1->sg:grp1":  false,
		"sg:grp1->s:seg1":  false,
	}
	for _, e := range graph.Edges {
		if _, ok := wantEdges[e.ID]; ok {
			wantEdges[e.ID] = true
		}
	}
	for id, present := range wantEdges {
		if !present {
			t.Errorf("missing edge %q", id)
		}
	}
}

// TestBuildFlowGraph_SkipDisabledAndDeny verifies that policies with
// Disabled="1" and policies with Action="DENY" are excluded from the flow
// graph. Flow visualizes effective allow paths only.
func TestBuildFlowGraph_SkipDisabledAndDeny(t *testing.T) {
	idx := newIndex()
	idx.Segments["seg1"] = seg("seg1", "Seg1", "grp1")

	disabled := policy("polD", "D", "ALLOW", "1",
		cond("AND", op("APP", "seg1"), op("SCIM_GROUP", "100")))
	disabled.Disabled = "1"
	registerPolicy(idx, disabled)

	deny := policy("polX", "X", "DENY", "2",
		cond("AND", op("APP", "seg1"), op("SCIM_GROUP", "100")))
	registerPolicy(idx, deny)

	graph := BuildFlowGraph(idx, GraphQueryBody{})
	for _, n := range graph.Nodes {
		if n.ID == "p:polD" || n.ID == "p:polX" {
			t.Errorf("disabled/deny policy node present: %q", n.ID)
		}
	}
}

// TestBuildFlowGraph_DeterministicAcrossRuns verifies that repeated calls
// against the same index produce graphs with stable node and edge counts.
// Guards against Go map-iteration nondeterminism leaking into the frontend
// layout, which would cause visual jitter between page loads.
func TestBuildFlowGraph_DeterministicAcrossRuns(t *testing.T) {
	idx := newIndex()
	for i := 1; i <= 5; i++ {
		id := "seg" + string(rune('0'+i))
		idx.Segments[id] = seg(id, "S"+id, "grp1")
	}
	idx.SegmentGroups["grp1"] = segGroup("grp1", "G", "seg1", "seg2", "seg3", "seg4", "seg5")
	registerPolicy(idx, withConnectorGroup(policy("pol1", "P1", "ALLOW", "1",
		cond("AND", op("APP_GROUP", "grp1"), op("SCIM_GROUP", "100"))), "cg1", "CG1"))

	first := BuildFlowGraph(idx, GraphQueryBody{})
	for range 10 {
		got := BuildFlowGraph(idx, GraphQueryBody{})
		if len(got.Nodes) != len(first.Nodes) || len(got.Edges) != len(first.Edges) {
			t.Fatalf("nondeterministic node/edge count: first=%d/%d got=%d/%d",
				len(first.Nodes), len(first.Edges), len(got.Nodes), len(got.Edges))
		}
	}
}

// TestBuildFlowGraph_PolicyFilter verifies that supplying PolicyIDs in the
// FlowFilters narrows the graph to only matching policies and their related
// entities; unrelated policy and segment nodes must not appear.
func TestBuildFlowGraph_PolicyFilter(t *testing.T) {
	idx := newIndex()
	idx.Segments["seg1"] = seg("seg1", "Seg1", "grp1")
	idx.Segments["seg2"] = seg("seg2", "Seg2", "grp1")
	registerPolicy(idx, policy("pol1", "P1", "ALLOW", "1",
		cond("AND", op("APP", "seg1"), op("SCIM_GROUP", "100"))))
	registerPolicy(idx, policy("pol2", "P2", "ALLOW", "2",
		cond("AND", op("APP", "seg2"), op("SCIM_GROUP", "100"))))

	graph := BuildFlowGraph(idx, GraphQueryBody{
		Filters: FlowFilters{PolicyIDs: map[string]bool{"pol1": true}},
	})
	for _, n := range graph.Nodes {
		if n.ID == "p:pol2" || n.ID == "s:seg2" {
			t.Errorf("policy filter not applied, saw %q", n.ID)
		}
	}
}

// TestBuildRoutes_CrossProduct verifies that BuildRoutes emits the full
// cartesian product of (SCIM group x connector group x segment) for a
// policy that targets a segment group. Two segments x one CG x one SCIM
// group must yield exactly two route rows.
func TestBuildRoutes_CrossProduct(t *testing.T) {
	idx := newIndex()
	idx.Segments["seg1"] = seg("seg1", "Seg1", "grp1")
	idx.Segments["seg2"] = seg("seg2", "Seg2", "grp1")
	idx.SegmentGroups["grp1"] = segGroup("grp1", "Grp1", "seg1", "seg2")
	idx.ScimGroups[100] = scim(100, "Admins")

	registerPolicy(idx, withConnectorGroup(policy("pol1", "P1", "ALLOW", "1",
		cond("AND", op("APP_GROUP", "grp1"), op("SCIM_GROUP", "100"))), "cg1", "CG1"))

	m := BuildRoutes(idx)
	// 2 segments x 1 cg x 1 scim = 2 routes
	if len(m.Routes) != 2 {
		t.Errorf("route count = %d, want 2", len(m.Routes))
	}
	for _, r := range m.Routes {
		if r.Policy.ID != "pol1" || r.ScimGroup.ID != "100" || r.ConnectorGroup.ID != "cg1" {
			t.Errorf("bad route: %+v", r)
		}
	}
}

// TestBuildRoutes_NoScimGroup verifies that policies without any SCIM_GROUP
// operand still produce route rows (with an empty ScimGroup entry) rather
// than being dropped. Ensures routes remain visible for policies that grant
// access to all users.
func TestBuildRoutes_NoScimGroup(t *testing.T) {
	idx := newIndex()
	idx.Segments["seg1"] = seg("seg1", "Seg1", "grp1")

	registerPolicy(idx, withConnectorGroup(policy("pol1", "P1", "ALLOW", "1",
		cond("AND", op("APP", "seg1"))), "cg1", "CG1"))

	m := BuildRoutes(idx)
	if len(m.Routes) != 1 {
		t.Fatalf("want 1 route, got %d", len(m.Routes))
	}
	if m.Routes[0].ScimGroup.ID != "" {
		t.Errorf("ScimGroup should be empty, got %q", m.Routes[0].ScimGroup.ID)
	}
}
