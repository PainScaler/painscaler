package analysis

import (
	"sort"
	"strconv"

	"github.com/painscaler/painscaler/internal/index"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/policysetcontrollerv2"
)

// NamedRef is a minimal ID+Name pair used across all analytics reports.
type NamedRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// --- 1. Blast Radius ---

type BlastRadiusReport struct {
	TargetID   string     `json:"targetId"`
	TargetName string     `json:"targetName"`
	TargetType string     `json:"targetType"`
	Policies   []NamedRef `json:"policies"`
	ScimGroups []NamedRef `json:"scimGroups"`
	Segments   []NamedRef `json:"segments"`
}

// BlastRadius computes everything affected if a connector group or server
// group goes down: which policies, SCIM groups, and segments are impacted.
func BlastRadius(idx *index.Index, targetID, targetType string) BlastRadiusReport {
	report := BlastRadiusReport{
		TargetID:   targetID,
		TargetType: targetType,
	}

	// Resolve to connector group IDs
	var cgIDs []string
	switch targetType {
	case "connector_group":
		cgIDs = []string{targetID}
		report.TargetName = idx.ConnectorGroupNames[targetID]
	case "server_group":
		if sg, ok := idx.ServerGroups[targetID]; ok {
			report.TargetName = sg.Name
			for _, cg := range sg.AppConnectorGroups {
				cgIDs = index.AppendUnique(cgIDs, cg.ID)
			}
		}
	}

	polSet := make(map[string]bool)
	scimSet := make(map[string]bool)
	segSet := make(map[string]bool)

	for _, cgID := range cgIDs {
		for _, polID := range idx.ConnectorGroupToPolicies[cgID] {
			polSet[polID] = true
		}
	}

	for polID := range polSet {
		// Backward: SCIM groups
		for _, sgID := range idx.PolicyToScimGroups[polID] {
			scimSet[sgID] = true
		}
		// Forward: segments via policy conditions
		pol := idx.Policies[polID]
		if pol == nil {
			continue
		}
		for _, segID := range policySegmentIDs(idx, pol) {
			segSet[segID] = true
		}
	}

	for polID := range polSet {
		pol := idx.Policies[polID]
		name := polID
		if pol != nil {
			name = pol.Name
		}
		report.Policies = append(report.Policies, NamedRef{ID: polID, Name: name})
	}
	for sgID := range scimSet {
		report.ScimGroups = append(report.ScimGroups, NamedRef{ID: sgID, Name: resolveScimName(idx, sgID)})
	}
	for segID := range segSet {
		name := segID
		if s := idx.Segments[segID]; s != nil {
			name = s.Name
		}
		report.Segments = append(report.Segments, NamedRef{ID: segID, Name: name})
	}

	sortNamedRefs(report.Policies)
	sortNamedRefs(report.ScimGroups)
	sortNamedRefs(report.Segments)

	return report
}

// --- 2. Policy Shadows ---

type PolicyShadowReport struct {
	PolicyA          PolicySummary `json:"policyA"`
	PolicyB          PolicySummary `json:"policyB"`
	SharedScimGroups []NamedRef    `json:"sharedScimGroups"`
	SharedSegments   []NamedRef    `json:"sharedSegments"`
	Verdict          string        `json:"verdict"` // "shadow" or "conflict"
}

type PolicySummary struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Action    string `json:"action"`
	RuleOrder int    `json:"ruleOrder"`
}

func PolicyShadows(idx *index.Index) []PolicyShadowReport {
	// Build per-policy reach: set of (scimGroupID, segmentID) pairs
	type reach struct {
		scimGroups map[string]bool
		segments   map[string]bool
	}
	policyReach := make(map[string]*reach)

	for polID, pol := range idx.Policies {
		scimIDs := idx.PolicyToScimGroups[polID]
		if len(scimIDs) == 0 {
			continue
		}
		segIDs := policySegmentIDs(idx, pol)
		if len(segIDs) == 0 {
			continue
		}
		r := &reach{
			scimGroups: make(map[string]bool, len(scimIDs)),
			segments:   make(map[string]bool, len(segIDs)),
		}
		for _, id := range scimIDs {
			r.scimGroups[id] = true
		}
		for _, id := range segIDs {
			r.segments[id] = true
		}
		policyReach[polID] = r
	}

	// Build inverted index: (scimGroup, segment) -> []policyID
	type pair struct{ scim, seg string }
	pairToPolicies := make(map[pair][]string)
	for polID, r := range policyReach {
		for scim := range r.scimGroups {
			for seg := range r.segments {
				key := pair{scim, seg}
				pairToPolicies[key] = index.AppendUnique(pairToPolicies[key], polID)
			}
		}
	}

	// Find overlapping pairs and group by policy pair
	type policyPairKey struct{ a, b string }
	type overlap struct {
		scimGroups map[string]bool
		segments   map[string]bool
	}
	pairOverlaps := make(map[policyPairKey]*overlap)

	for p, polIDs := range pairToPolicies {
		if len(polIDs) < 2 {
			continue
		}
		for i := 0; i < len(polIDs); i++ {
			for j := i + 1; j < len(polIDs); j++ {
				a, b := polIDs[i], polIDs[j]
				if a > b {
					a, b = b, a
				}
				key := policyPairKey{a, b}
				ov, ok := pairOverlaps[key]
				if !ok {
					ov = &overlap{
						scimGroups: make(map[string]bool),
						segments:   make(map[string]bool),
					}
					pairOverlaps[key] = ov
				}
				ov.scimGroups[p.scim] = true
				ov.segments[p.seg] = true
			}
		}
	}

	var reports []PolicyShadowReport
	for key, ov := range pairOverlaps {
		polA := idx.Policies[key.a]
		polB := idx.Policies[key.b]
		if polA == nil || polB == nil {
			continue
		}

		verdict := "shadow"
		if polA.Action != polB.Action {
			verdict = "conflict"
		}

		var sharedScim []NamedRef
		for id := range ov.scimGroups {
			sharedScim = append(sharedScim, NamedRef{ID: id, Name: resolveScimName(idx, id)})
		}
		var sharedSegs []NamedRef
		for id := range ov.segments {
			name := id
			if s := idx.Segments[id]; s != nil {
				name = s.Name
			}
			sharedSegs = append(sharedSegs, NamedRef{ID: id, Name: name})
		}
		sortNamedRefs(sharedScim)
		sortNamedRefs(sharedSegs)

		reports = append(reports, PolicyShadowReport{
			PolicyA:          makePolicySummary(polA),
			PolicyB:          makePolicySummary(polB),
			SharedScimGroups: sharedScim,
			SharedSegments:   sharedSegs,
			Verdict:          verdict,
		})
	}

	// Sort by lower rule order first
	sort.Slice(reports, func(i, j int) bool {
		return reports[i].PolicyA.RuleOrder < reports[j].PolicyA.RuleOrder
	})

	return reports
}

// --- 3. Orphan Clusters ---

type OrphanCluster struct {
	SegmentGroupID   string     `json:"segmentGroupId"`
	SegmentGroupName string     `json:"segmentGroupName"`
	FullyOrphaned    bool       `json:"fullyOrphaned"`
	OrphanSegments   []NamedRef `json:"orphanSegments"`
	ConnectorGroups  []NamedRef `json:"connectorGroups"`
}

func OrphanClusters(idx *index.Index) []OrphanCluster {
	orphanSet := make(map[string]bool, len(idx.OrphanSegments))
	for _, id := range idx.OrphanSegments {
		orphanSet[id] = true
	}

	// Group orphans by segment group
	groupOrphans := make(map[string][]string) // segGroupID -> []orphanSegIDs
	for _, segID := range idx.OrphanSegments {
		seg := idx.Segments[segID]
		if seg == nil || seg.SegmentGroupID == "" {
			continue
		}
		groupOrphans[seg.SegmentGroupID] = append(groupOrphans[seg.SegmentGroupID], segID)
	}

	var clusters []OrphanCluster
	for gid, orphanIDs := range groupOrphans {
		grp := idx.SegmentGroups[gid]
		name := gid
		totalApps := 0
		if grp != nil {
			name = grp.Name
			totalApps = len(grp.Applications)
		}

		var segs []NamedRef
		for _, sid := range orphanIDs {
			sname := sid
			if s := idx.Segments[sid]; s != nil {
				sname = s.Name
			}
			segs = append(segs, NamedRef{ID: sid, Name: sname})
		}
		sortNamedRefs(segs)

		// Find connector groups serving this segment group via server groups
		cgSet := make(map[string]bool)
		for _, sg := range idx.ServerGroups {
			serves := false
			for _, app := range sg.Applications {
				if _, ok := groupOrphans[app.ID]; ok {
					serves = true
					break
				}
				// Check if any app belongs to this segment group
				if seg := idx.Segments[app.ID]; seg != nil && seg.SegmentGroupID == gid {
					serves = true
					break
				}
			}
			if serves {
				for _, cg := range sg.AppConnectorGroups {
					cgSet[cg.ID] = true
				}
			}
		}
		var cgs []NamedRef
		for cgID := range cgSet {
			cgs = append(cgs, NamedRef{ID: cgID, Name: idx.ConnectorGroupNames[cgID]})
		}
		sortNamedRefs(cgs)

		clusters = append(clusters, OrphanCluster{
			SegmentGroupID:   gid,
			SegmentGroupName: name,
			FullyOrphaned:    totalApps > 0 && len(orphanIDs) == totalApps,
			OrphanSegments:   segs,
			ConnectorGroups:  cgs,
		})
	}

	sort.Slice(clusters, func(i, j int) bool {
		return len(clusters[i].OrphanSegments) > len(clusters[j].OrphanSegments)
	})

	return clusters
}

// --- 4. Domain Overlap Details ---

type DomainOverlapDetail struct {
	Domain      string                `json:"domain"`
	Segments    []DomainSegmentDetail `json:"segments"`
	HasConflict bool                  `json:"hasConflict"`
}

type DomainSegmentDetail struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Policies []NamedRef `json:"policies"`
}

func DomainOverlapDetails(idx *index.Index) []DomainOverlapDetail {
	var details []DomainOverlapDetail

	for domain, segIDs := range idx.OverlappingDomains {
		var segs []DomainSegmentDetail
		actionSet := make(map[string]bool)

		for _, segID := range segIDs {
			name := segID
			if s := idx.Segments[segID]; s != nil {
				name = s.Name
			}
			var pols []NamedRef
			for _, polID := range idx.SegmentToPolicies[segID] {
				pol := idx.Policies[polID]
				pname := polID
				if pol != nil {
					pname = pol.Name
					actionSet[pol.Action] = true
				}
				pols = append(pols, NamedRef{ID: polID, Name: pname})
			}
			sortNamedRefs(pols)
			segs = append(segs, DomainSegmentDetail{ID: segID, Name: name, Policies: pols})
		}

		details = append(details, DomainOverlapDetail{
			Domain:      domain,
			Segments:    segs,
			HasConflict: len(actionSet) > 1,
		})
	}

	sort.Slice(details, func(i, j int) bool {
		if details[i].HasConflict != details[j].HasConflict {
			return details[i].HasConflict // conflicts first
		}
		return details[i].Domain < details[j].Domain
	})

	return details
}

// --- 5. Connector Load ---

type ConnectorLoadEntry struct {
	ConnectorGroupID   string `json:"connectorGroupId"`
	ConnectorGroupName string `json:"connectorGroupName"`
	PolicyCount        int    `json:"policyCount"`
	SegmentGroupCount  int    `json:"segmentGroupCount"`
	SegmentCount       int    `json:"segmentCount"`
	ScimGroupCount     int    `json:"scimGroupCount"`
}

func ConnectorLoad(idx *index.Index) []ConnectorLoadEntry {
	var entries []ConnectorLoadEntry

	for cgID, polIDs := range idx.ConnectorGroupToPolicies {
		segGroupSet := make(map[string]bool)
		segSet := make(map[string]bool)
		scimSet := make(map[string]bool)

		for _, polID := range polIDs {
			pol := idx.Policies[polID]
			if pol == nil {
				continue
			}
			for _, scimID := range idx.PolicyToScimGroups[polID] {
				scimSet[scimID] = true
			}
			for _, segID := range policySegmentIDs(idx, pol) {
				segSet[segID] = true
				if s := idx.Segments[segID]; s != nil && s.SegmentGroupID != "" {
					segGroupSet[s.SegmentGroupID] = true
				}
			}
		}

		entries = append(entries, ConnectorLoadEntry{
			ConnectorGroupID:   cgID,
			ConnectorGroupName: idx.ConnectorGroupNames[cgID],
			PolicyCount:        len(polIDs),
			SegmentGroupCount:  len(segGroupSet),
			SegmentCount:       len(segSet),
			ScimGroupCount:     len(scimSet),
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].SegmentCount > entries[j].SegmentCount
	})

	return entries
}

// --- 6. SCIM Reach ---

type ScimReachEntry struct {
	ScimGroupID       string `json:"scimGroupId"`
	ScimGroupName     string `json:"scimGroupName"`
	PolicyCount       int    `json:"policyCount"`
	SegmentGroupCount int    `json:"segmentGroupCount"`
	SegmentCount      int    `json:"segmentCount"`
}

func ScimReach(idx *index.Index) []ScimReachEntry {
	// Invert PolicyToScimGroups -> scimGroupID -> []policyID
	scimToPolicies := make(map[string][]string)
	for polID, scimIDs := range idx.PolicyToScimGroups {
		for _, scimID := range scimIDs {
			scimToPolicies[scimID] = index.AppendUnique(scimToPolicies[scimID], polID)
		}
	}

	var entries []ScimReachEntry
	for scimID, polIDs := range scimToPolicies {
		segGroupSet := make(map[string]bool)
		segSet := make(map[string]bool)

		for _, polID := range polIDs {
			pol := idx.Policies[polID]
			if pol == nil {
				continue
			}
			for _, segID := range policySegmentIDs(idx, pol) {
				segSet[segID] = true
				if s := idx.Segments[segID]; s != nil && s.SegmentGroupID != "" {
					segGroupSet[s.SegmentGroupID] = true
				}
			}
		}

		entries = append(entries, ScimReachEntry{
			ScimGroupID:       scimID,
			ScimGroupName:     resolveScimName(idx, scimID),
			PolicyCount:       len(polIDs),
			SegmentGroupCount: len(segGroupSet),
			SegmentCount:      len(segSet),
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].SegmentCount > entries[j].SegmentCount
	})

	return entries
}

// --- helpers ---

// policySegmentIDs returns all segment IDs reachable from a policy's
// APP and APP_GROUP conditions.
func policySegmentIDs(idx *index.Index, pol *policysetcontrollerv2.PolicyRuleResource) []string {
	var ids []string
	for _, cond := range pol.Conditions {
		for _, op := range cond.Operands {
			switch op.ObjectType {
			case "APP":
				if op.RHS != "" {
					ids = index.AppendUnique(ids, op.RHS)
				}
			case "APP_GROUP":
				if op.RHS != "" {
					if grp, ok := idx.SegmentGroups[op.RHS]; ok {
						for _, app := range grp.Applications {
							ids = index.AppendUnique(ids, app.ID)
						}
					}
				}
			}
		}
	}
	return ids
}

func resolveScimName(idx *index.Index, id string) string {
	intID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return id
	}
	if g, ok := idx.ScimGroups[intID]; ok {
		return g.Name
	}
	return id
}

func makePolicySummary(pol *policysetcontrollerv2.PolicyRuleResource) PolicySummary {
	order, _ := strconv.Atoi(pol.RuleOrder)
	return PolicySummary{
		ID:        pol.ID,
		Name:      pol.Name,
		Action:    pol.Action,
		RuleOrder: order,
	}
}

func sortNamedRefs(refs []NamedRef) {
	sort.Slice(refs, func(i, j int) bool {
		return refs[i].Name < refs[j].Name
	})
}
