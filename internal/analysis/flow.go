package analysis

import (
	"slices"
	"strconv"

	"github.com/painscaler/painscaler/internal/index"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/policysetcontrollerv2"
)

type RFPosition struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// --- Column-layout flow graph (ported from buildGraph.ts) ---

type FlowColumn int

type GraphQueryBody struct {
	Filters        FlowFilters         `json:"filters,omitempty"`
	VisibleCols    map[FlowColumn]bool `json:"visible_cols,omitempty"`
	ExpandedGroups map[string]bool     `json:"expanded_groups,omitempty"`
}

const (
	ColScimGroups      FlowColumn = 1
	ColPolicies        FlowColumn = 2
	ColConnectorGroups FlowColumn = 3
	ColSegmentGroups   FlowColumn = 4
	ColSegments        FlowColumn = 5
)

type FlowNodeData struct {
	Column   FlowColumn `json:"column"`
	Label    string     `json:"label"`
	Subtitle string     `json:"subtitle,omitempty"`
}

type FlowNode struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Position RFPosition   `json:"position"`
	Data     FlowNodeData `json:"data"`
	Width    float64      `json:"width"`
}

type FlowEdge struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"`
}

type FlowFilters struct {
	ScimGroupIDs      map[string]bool `json:"scimGroupIds"`
	PolicyIDs         map[string]bool `json:"policyIds"`
	ConnectorGroupIDs map[string]bool `json:"connectorGroupIds"`
	SegmentGroupIDs   map[string]bool `json:"segmentGroupIds"`
}

type FlowGraph struct {
	Nodes []FlowNode `json:"nodes"`
	Edges []FlowEdge `json:"edges"`
}

type FlowReachability struct {
	ReachableNodes map[string]bool `json:"reachableNodes"`
	ReachableEdges map[string]bool `json:"reachableEdges"`
}

// Route is one concrete access path through the 5-column model.
// Each field holds the human-readable name; the ID variant is used for lookups.
type RouteEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Route struct {
	ScimGroup      RouteEntry `json:"scimGroup"`
	Policy         RouteEntry `json:"policy"`
	ConnectorGroup RouteEntry `json:"connectorGroup"`
	SegmentGroup   RouteEntry `json:"segmentGroup"`
	Segment        RouteEntry `json:"segment"`
}

type RouteMatrix struct {
	Routes []Route `json:"routes"`
}

const (
	flowNodeWidth = 220.0
)

func hasFlowFilter(f FlowFilters) bool {
	return len(f.ScimGroupIDs) > 0 || len(f.PolicyIDs) > 0 ||
		len(f.ConnectorGroupIDs) > 0 || len(f.SegmentGroupIDs) > 0
}

func BuildFlowGraph(idx *index.Index, data GraphQueryBody) FlowGraph {
	var nodes []FlowNode
	var edges []FlowEdge

	filters := data.Filters
	visibleCols := data.VisibleCols
	expandedGroups := data.ExpandedGroups
	// Sort policies by ruleOrder, exclude disabled
	type polEntry struct {
		id  string
		pol *policysetcontrollerv2.PolicyRuleResource
	}
	var policies []polEntry
	for id, p := range idx.Policies {
		if p.Disabled == "true" || p.Disabled == "1" || p.Action == "DENY" {
			continue
		}
		policies = append(policies, polEntry{id, p})
	}
	slices.SortFunc(policies, func(a, b polEntry) int {
		ao, _ := strconv.Atoi(a.pol.RuleOrder)
		bo, _ := strconv.Atoi(b.pol.RuleOrder)
		if ao == 0 {
			ao = 999
		}
		if bo == 0 {
			bo = 999
		}
		return ao - bo
	})

	// Pre-build segment -> connector groups via standalone server groups
	segToConnectorGroups := make(map[string][]string)
	for _, sg := range idx.ServerGroups {
		for _, app := range sg.Applications {
			for _, acg := range sg.AppConnectorGroups {
				if acg.ID != "" {
					segToConnectorGroups[app.ID] = index.AppendUnique(segToConnectorGroups[app.ID], acg.ID)
				}
			}
		}
	}

	colRowCount := map[FlowColumn]int{1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
	placed := make(map[string]bool)
	edgeSet := make(map[string]bool)

	addEdge := func(id, source, target string) {
		if edgeSet[id] {
			return
		}
		edgeSet[id] = true
		edges = append(edges, FlowEdge{ID: id, Source: source, Target: target, Type: "smoothstep"})
	}

	for _, pe := range policies {
		pol := pe.pol
		polId := pe.id
		if polId == "" {
			continue
		}

		if len(filters.PolicyIDs) > 0 && !filters.PolicyIDs[polId] {
			continue
		}

		// Collect related entities
		var relScimGroupIDs []string
		var relConnectorGroupIDs []string
		var relSegmentGroupIDs []string
		var relSegmentIDs []string

		// Walk conditions
		for _, cond := range pol.Conditions {
			for _, op := range cond.Operands {
				switch op.ObjectType {
				case "SCIM_GROUP":
					if op.RHS != "" {
						relScimGroupIDs = append(relScimGroupIDs, op.RHS)
					}
				case "APP_GROUP":
					if op.RHS != "" {
						relSegmentGroupIDs = append(relSegmentGroupIDs, op.RHS)
					}
				case "APP":
					if op.RHS != "" {
						relSegmentIDs = append(relSegmentIDs, op.RHS)
					}
				}
			}
		}

		// Connector groups from policy
		for _, cg := range pol.AppConnectorGroups {
			if cg.ID != "" {
				relConnectorGroupIDs = append(relConnectorGroupIDs, cg.ID)
			}
		}

		// Connector groups from server groups
		for _, sg := range pol.AppServerGroups {
			for _, acg := range sg.AppConnectorGroups {
				if acg.ID != "" && !slices.Contains(relConnectorGroupIDs, acg.ID) {
					relConnectorGroupIDs = append(relConnectorGroupIDs, acg.ID)
				}
			}
		}

		// Expand segment groups -> segments
		for _, sgId := range relSegmentGroupIDs {
			if sg, ok := idx.SegmentGroups[sgId]; ok {
				for _, app := range sg.Applications {
					if app.ID != "" && !slices.Contains(relSegmentIDs, app.ID) {
						relSegmentIDs = append(relSegmentIDs, app.ID)
					}
				}
			}
		}

		// Expand segments -> segment groups (reverse)
		for _, segId := range relSegmentIDs {
			if seg, ok := idx.Segments[segId]; ok {
				if seg.SegmentGroupID != "" && !slices.Contains(relSegmentGroupIDs, seg.SegmentGroupID) {
					relSegmentGroupIDs = append(relSegmentGroupIDs, seg.SegmentGroupID)
				}
			}
		}

		// Derive connector groups via standalone server groups when policy
		// doesn't list them explicitly.
		if len(relConnectorGroupIDs) == 0 {
			for _, segId := range relSegmentIDs {
				for _, cgId := range segToConnectorGroups[segId] {
					if !slices.Contains(relConnectorGroupIDs, cgId) {
						relConnectorGroupIDs = append(relConnectorGroupIDs, cgId)
					}
				}
			}
		}

		// Apply filters
		if hasFlowFilter(filters) {
			if len(filters.ScimGroupIDs) > 0 {
				match := false
				for _, id := range relScimGroupIDs {
					if filters.ScimGroupIDs[id] {
						match = true
						break
					}
				}
				if !match {
					continue
				}
			}
			if len(filters.ConnectorGroupIDs) > 0 {
				match := false
				for _, id := range relConnectorGroupIDs {
					if filters.ConnectorGroupIDs[id] {
						match = true
						break
					}
				}
				if !match {
					continue
				}
			}
			if len(filters.SegmentGroupIDs) > 0 {
				match := false
				for _, id := range relSegmentGroupIDs {
					if filters.SegmentGroupIDs[id] {
						match = true
						break
					}
				}
				if !match {
					continue
				}
			}
		}

		// Column 1: SCIM Groups
		if visibleCols == nil || visibleCols[ColScimGroups] {
			for _, gId := range relScimGroupIDs {
				nid := "g:" + gId
				if !placed[nid] {
					label := gId
					gIdInt, err := strconv.ParseInt(gId, 10, 64)
					if err == nil {
						if g, ok := idx.ScimGroups[gIdInt]; ok {
							label = g.Name
						}
					}
					nodes = append(nodes, FlowNode{
						ID:    nid,
						Type:  "flow",
						Data:  FlowNodeData{Column: ColScimGroups, Label: label},
						Width: flowNodeWidth,
					})
					colRowCount[ColScimGroups]++
					placed[nid] = true
				}
			}
		}

		// Column 2: Policy
		if visibleCols == nil || visibleCols[ColPolicies] {
			pNodeId := "p:" + polId
			if !placed[pNodeId] {
				label := polId
				if pol.Name != "" {
					label = pol.Name
				}
				subtitle := ""
				if pol.Action != "" {
					subtitle = pol.Action
				}
				nodes = append(nodes, FlowNode{
					ID:    pNodeId,
					Type:  "flow",
					Data:  FlowNodeData{Column: ColPolicies, Label: label, Subtitle: subtitle},
					Width: flowNodeWidth,
				})
				colRowCount[ColPolicies]++
				placed[pNodeId] = true
			}

			// Edges: SCIM Group -> Policy
			if visibleCols == nil || visibleCols[ColScimGroups] {
				for _, gId := range relScimGroupIDs {
					addEdge("g:"+gId+"->p:"+polId, "g:"+gId, "p:"+polId)
				}
			}
		}

		// Column 3: Connector Groups
		if visibleCols == nil || visibleCols[ColConnectorGroups] {
			for _, cgId := range relConnectorGroupIDs {
				nid := "cg:" + cgId
				if !placed[nid] {
					label := cgId
					for _, cg := range pol.AppConnectorGroups {
						if cg.ID == cgId {
							label = cg.Name
							break
						}
					}
					if label == cgId {
						if name, ok := idx.ConnectorGroupNames[cgId]; ok {
							label = name
						}
					}
					nodes = append(nodes, FlowNode{
						ID:    nid,
						Type:  "flow",
						Data:  FlowNodeData{Column: ColConnectorGroups, Label: label},
						Width: flowNodeWidth,
					})
					colRowCount[ColConnectorGroups]++
					placed[nid] = true
				}

				// Edge: Policy -> Connector Group
				if visibleCols == nil || visibleCols[ColPolicies] {
					addEdge("p:"+polId+"->cg:"+cgId, "p:"+polId, "cg:"+cgId)
				}
			}
		}

		// Column 4: Segment Groups
		if visibleCols == nil || visibleCols[ColSegmentGroups] {
			for _, sgId := range relSegmentGroupIDs {
				nid := "sg:" + sgId
				if !placed[nid] {
					label := sgId
					if sg, ok := idx.SegmentGroups[sgId]; ok {
						label = sg.Name
					}
					nodes = append(nodes, FlowNode{
						ID:    nid,
						Type:  "flow",
						Data:  FlowNodeData{Column: ColSegmentGroups, Label: label},
						Width: flowNodeWidth,
					})
					colRowCount[ColSegmentGroups]++
					placed[nid] = true
				}

				// Edge: ConnectorGroup(3) -> SegmentGroup(4)
				if visibleCols == nil || visibleCols[ColConnectorGroups] {
					for _, cgId := range relConnectorGroupIDs {
						addEdge("cg:"+cgId+"->sg:"+sgId, "cg:"+cgId, "sg:"+sgId)
					}
				}
			}
		}

		// Column 5: Segments
		if visibleCols == nil || visibleCols[ColSegments] {
			for _, sId := range relSegmentIDs {
				seg := idx.Segments[sId]

				// If expandedGroups is provided, only show segments whose parent group is expanded
				if expandedGroups != nil && seg != nil && seg.SegmentGroupID != "" {
					if !expandedGroups["sg:"+seg.SegmentGroupID] {
						continue
					}
				}

				nid := "s:" + sId
				if !placed[nid] {
					label := sId
					if seg != nil && seg.Name != "" {
						label = seg.Name
					}
					nodes = append(nodes, FlowNode{
						ID:    nid,
						Type:  "flow",
						Data:  FlowNodeData{Column: ColSegments, Label: label},
						Width: flowNodeWidth,
					})
					colRowCount[ColSegments]++
					placed[nid] = true
				}

				// Edge: Segment Group -> Segment
				if (visibleCols == nil || visibleCols[ColSegmentGroups]) && seg != nil && seg.SegmentGroupID != "" {
					addEdge("sg:"+seg.SegmentGroupID+"->s:"+sId, "sg:"+seg.SegmentGroupID, "s:"+sId)
				}
			}
		}
	}

	// Filter out edges whose source or target node doesn't exist
	nodeIds := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		nodeIds[n.ID] = true
	}
	validEdges := make([]FlowEdge, 0, len(edges))
	for _, e := range edges {
		if nodeIds[e.Source] && nodeIds[e.Target] {
			validEdges = append(validEdges, e)
		}
	}

	return FlowGraph{Nodes: nodes, Edges: validEdges}
}

// BuildRoutes generates the route matrix: every concrete access path as a 5-tuple.
func BuildRoutes(idx *index.Index) RouteMatrix {
	// Pre-build segment -> connector groups via standalone server groups
	segToConnectorGroups := make(map[string][]string)
	segToCGNames := make(map[string]map[string]string)
	for _, sg := range idx.ServerGroups {
		for _, app := range sg.Applications {
			for _, acg := range sg.AppConnectorGroups {
				if acg.ID != "" {
					segToConnectorGroups[app.ID] = index.AppendUnique(segToConnectorGroups[app.ID], acg.ID)
					if segToCGNames[app.ID] == nil {
						segToCGNames[app.ID] = make(map[string]string)
					}
					if acg.Name != "" {
						segToCGNames[app.ID][acg.ID] = acg.Name
					}
				}
			}
		}
	}

	type polEntry struct {
		id  string
		pol *policysetcontrollerv2.PolicyRuleResource
	}
	var policies []polEntry
	for id, p := range idx.Policies {
		if p.Disabled == "true" || p.Disabled == "1" || p.Action == "DENY" {
			continue
		}
		policies = append(policies, polEntry{id, p})
	}
	slices.SortFunc(policies, func(a, b polEntry) int {
		ao, _ := strconv.Atoi(a.pol.RuleOrder)
		bo, _ := strconv.Atoi(b.pol.RuleOrder)
		if ao == 0 {
			ao = 999
		}
		if bo == 0 {
			bo = 999
		}
		return ao - bo
	})

	var routes []Route

	for _, pe := range policies {
		pol := pe.pol
		polId := pe.id
		if polId == "" {
			continue
		}

		polEntry := RouteEntry{ID: polId, Name: pol.Name}

		// Collect related entities
		var scimGroupIDs []string
		var connectorGroupIDs []string
		var segmentGroupIDs []string
		var segmentIDs []string

		for _, cond := range pol.Conditions {
			for _, op := range cond.Operands {
				switch op.ObjectType {
				case "SCIM_GROUP":
					if op.RHS != "" {
						scimGroupIDs = index.AppendUnique(scimGroupIDs, op.RHS)
					}
				case "APP_GROUP":
					if op.RHS != "" {
						segmentGroupIDs = index.AppendUnique(segmentGroupIDs, op.RHS)
					}
				case "APP":
					if op.RHS != "" {
						segmentIDs = index.AppendUnique(segmentIDs, op.RHS)
					}
				}
			}
		}

		// Connector groups from policy
		for _, cg := range pol.AppConnectorGroups {
			if cg.ID != "" {
				connectorGroupIDs = index.AppendUnique(connectorGroupIDs, cg.ID)
			}
		}
		for _, sg := range pol.AppServerGroups {
			for _, acg := range sg.AppConnectorGroups {
				if acg.ID != "" {
					connectorGroupIDs = index.AppendUnique(connectorGroupIDs, acg.ID)
				}
			}
		}

		// Expand segment groups -> segments
		for _, sgId := range segmentGroupIDs {
			if sg, ok := idx.SegmentGroups[sgId]; ok {
				for _, app := range sg.Applications {
					if app.ID != "" {
						segmentIDs = index.AppendUnique(segmentIDs, app.ID)
					}
				}
			}
		}

		// Expand segments -> segment groups (reverse)
		for _, segId := range segmentIDs {
			if seg, ok := idx.Segments[segId]; ok {
				if seg.SegmentGroupID != "" {
					segmentGroupIDs = index.AppendUnique(segmentGroupIDs, seg.SegmentGroupID)
				}
			}
		}

		// Derive connector groups from segments if not on policy
		if len(connectorGroupIDs) == 0 {
			for _, segId := range segmentIDs {
				for _, cgId := range segToConnectorGroups[segId] {
					connectorGroupIDs = index.AppendUnique(connectorGroupIDs, cgId)
				}
			}
		}

		// Build connector group name lookup
		cgNames := make(map[string]string)
		for _, cg := range pol.AppConnectorGroups {
			if cg.ID != "" && cg.Name != "" {
				cgNames[cg.ID] = cg.Name
			}
		}
		for _, sg := range pol.AppServerGroups {
			for _, acg := range sg.AppConnectorGroups {
				if acg.ID != "" && acg.Name != "" {
					cgNames[acg.ID] = acg.Name
				}
			}
		}
		// Fallback to idx and server group names
		for _, cgId := range connectorGroupIDs {
			if _, ok := cgNames[cgId]; !ok {
				if name, ok := idx.ConnectorGroupNames[cgId]; ok {
					cgNames[cgId] = name
				}
			}
		}

		// Emit routes: cross product of (scimGroup x connectorGroup x segmentGroup x segment)
		// Each combo through this policy = one route row
		for _, segId := range segmentIDs {
			seg := idx.Segments[segId]
			segName := segId
			segGroupID := ""
			if seg != nil {
				if seg.Name != "" {
					segName = seg.Name
				}
				segGroupID = seg.SegmentGroupID
			}

			sgEntry := RouteEntry{}
			if segGroupID != "" {
				sgName := segGroupID
				if sg, ok := idx.SegmentGroups[segGroupID]; ok {
					sgName = sg.Name
				}
				sgEntry = RouteEntry{ID: segGroupID, Name: sgName}
			}

			for _, cgId := range connectorGroupIDs {
				cgName := cgId
				if n, ok := cgNames[cgId]; ok {
					cgName = n
				}
				cgEntry := RouteEntry{ID: cgId, Name: cgName}

				if len(scimGroupIDs) == 0 {
					// Route without SCIM group
					routes = append(routes, Route{
						Policy:         polEntry,
						ConnectorGroup: cgEntry,
						SegmentGroup:   sgEntry,
						Segment:        RouteEntry{ID: segId, Name: segName},
					})
				} else {
					for _, gId := range scimGroupIDs {
						gName := gId
						gIdInt, err := strconv.ParseInt(gId, 10, 64)
						if err == nil {
							if g, ok := idx.ScimGroups[gIdInt]; ok {
								gName = g.Name
							}
						}
						routes = append(routes, Route{
							ScimGroup:      RouteEntry{ID: gId, Name: gName},
							Policy:         polEntry,
							ConnectorGroup: cgEntry,
							SegmentGroup:   sgEntry,
							Segment:        RouteEntry{ID: segId, Name: segName},
						})
					}
				}
			}

			// If no connector groups at all, still emit route
			if len(connectorGroupIDs) == 0 {
				if len(scimGroupIDs) == 0 {
					routes = append(routes, Route{
						Policy:       polEntry,
						SegmentGroup: sgEntry,
						Segment:      RouteEntry{ID: segId, Name: segName},
					})
				} else {
					for _, gId := range scimGroupIDs {
						gName := gId
						gIdInt, err := strconv.ParseInt(gId, 10, 64)
						if err == nil {
							if g, ok := idx.ScimGroups[gIdInt]; ok {
								gName = g.Name
							}
						}
						routes = append(routes, Route{
							ScimGroup:    RouteEntry{ID: gId, Name: gName},
							Policy:       polEntry,
							SegmentGroup: sgEntry,
							Segment:      RouteEntry{ID: segId, Name: segName},
						})
					}
				}
			}
		}
	}

	return RouteMatrix{Routes: routes}
}
