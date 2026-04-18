package analysis

import (
	"github.com/painscaler/painscaler/internal/index"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/appconnectorgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/applicationsegment"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/policysetcontrollerv2"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/scimgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/segmentgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/servergroup"
)

func newIndex() *index.Index {
	return &index.Index{
		Segments:                 map[string]*applicationsegment.ApplicationSegmentResource{},
		SegmentGroups:            map[string]*segmentgroup.SegmentGroup{},
		Policies:                 map[string]*policysetcontrollerv2.PolicyRuleResource{},
		ScimGroups:               map[int64]*scimgroup.ScimGroup{},
		ServerGroups:             map[string]*servergroup.ServerGroup{},
		SegmentToPolicies:        map[string][]string{},
		GroupToPolicies:          map[string][]string{},
		DomainToSegments:         map[string][]string{},
		OverlappingDomains:       map[string][]string{},
		PolicyToScimGroups:       map[string][]string{},
		ConnectorGroupToPolicies: map[string][]string{},
		PolicyToConnectorGroups:  map[string][]string{},
		ConnectorGroupNames:      map[string]string{},
	}
}

func seg(id, name, groupID string, domains ...string) *applicationsegment.ApplicationSegmentResource {
	return &applicationsegment.ApplicationSegmentResource{
		ID: id, Name: name, SegmentGroupID: groupID, DomainNames: domains, Enabled: true,
	}
}

func segGroup(id, name string, appIDs ...string) *segmentgroup.SegmentGroup {
	g := &segmentgroup.SegmentGroup{ID: id, Name: name}
	for _, aid := range appIDs {
		g.Applications = append(g.Applications, segmentgroup.Application{ID: aid})
	}
	return g
}

func scim(id int64, name string) *scimgroup.ScimGroup {
	return &scimgroup.ScimGroup{ID: id, Name: name}
}

func cond(operator string, ops ...policysetcontrollerv2.PolicyRuleResourceOperands) policysetcontrollerv2.PolicyRuleResourceConditions {
	return policysetcontrollerv2.PolicyRuleResourceConditions{Operator: operator, Operands: ops}
}

func op(objectType, rhs string) policysetcontrollerv2.PolicyRuleResourceOperands {
	return policysetcontrollerv2.PolicyRuleResourceOperands{ObjectType: objectType, RHS: rhs}
}

func policy(id, name, action, priority string, conds ...policysetcontrollerv2.PolicyRuleResourceConditions) *policysetcontrollerv2.PolicyRuleResource {
	return &policysetcontrollerv2.PolicyRuleResource{
		ID: id, Name: name, Action: action, Priority: priority, Conditions: conds,
	}
}

func withConnectorGroup(p *policysetcontrollerv2.PolicyRuleResource, cgID, cgName string) *policysetcontrollerv2.PolicyRuleResource {
	p.AppConnectorGroups = append(p.AppConnectorGroups, appconnectorgroup.AppConnectorGroup{ID: cgID, Name: cgName})
	return p
}

func serverGroup(id, name string, cgIDs []string, appIDs []string) *servergroup.ServerGroup {
	sg := &servergroup.ServerGroup{ID: id, Name: name}
	for _, cg := range cgIDs {
		sg.AppConnectorGroups = append(sg.AppConnectorGroups, appconnectorgroup.AppConnectorGroup{ID: cg, Name: cg + "-name"})
	}
	for _, a := range appIDs {
		sg.Applications = append(sg.Applications, servergroup.Applications{ID: a})
	}
	return sg
}

// registerPolicy adds policy to idx and populates the inverted maps
// the same way BuildIndex does. Keeps fixtures concise.
func registerPolicy(idx *index.Index, p *policysetcontrollerv2.PolicyRuleResource) {
	idx.Policies[p.ID] = p
	for _, c := range p.Conditions {
		for _, o := range c.Operands {
			switch o.ObjectType {
			case "APP":
				if o.RHS != "" {
					idx.SegmentToPolicies[o.RHS] = index.AppendUnique(idx.SegmentToPolicies[o.RHS], p.ID)
				}
			case "APP_GROUP":
				if o.RHS != "" {
					idx.GroupToPolicies[o.RHS] = index.AppendUnique(idx.GroupToPolicies[o.RHS], p.ID)
					if g, ok := idx.SegmentGroups[o.RHS]; ok {
						for _, app := range g.Applications {
							idx.SegmentToPolicies[app.ID] = index.AppendUnique(idx.SegmentToPolicies[app.ID], p.ID)
						}
					}
				}
			case "SCIM_GROUP":
				if o.RHS != "" {
					idx.PolicyToScimGroups[p.ID] = index.AppendUnique(idx.PolicyToScimGroups[p.ID], o.RHS)
				}
			}
		}
	}
	for _, cg := range p.AppConnectorGroups {
		if cg.ID != "" {
			idx.PolicyToConnectorGroups[p.ID] = index.AppendUnique(idx.PolicyToConnectorGroups[p.ID], cg.ID)
			idx.ConnectorGroupToPolicies[cg.ID] = index.AppendUnique(idx.ConnectorGroupToPolicies[cg.ID], p.ID)
			if cg.Name != "" {
				idx.ConnectorGroupNames[cg.ID] = cg.Name
			}
		}
	}
}

func registerOrphans(idx *index.Index) {
	for segID := range idx.Segments {
		if len(idx.SegmentToPolicies[segID]) == 0 {
			idx.OrphanSegments = append(idx.OrphanSegments, segID)
		}
	}
}
