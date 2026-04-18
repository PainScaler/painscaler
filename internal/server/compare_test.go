package server

import (
	"testing"

	"github.com/painscaler/painscaler/internal/index"
	"github.com/painscaler/painscaler/internal/simulator"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/applicationsegment"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/policysetcontrollerv2"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/scimattributeheader"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/scimgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/segmentgroup"
)

func newIdx() *index.Index {
	return &index.Index{
		Segments:         map[string]*applicationsegment.ApplicationSegmentResource{},
		SegmentGroups:    map[string]*segmentgroup.SegmentGroup{},
		Policies:         map[string]*policysetcontrollerv2.PolicyRuleResource{},
		ScimGroups:       map[int64]*scimgroup.ScimGroup{},
		ScimAttrByID:     map[string]*scimattributeheader.ScimAttributeHeader{},
		ScimAttrNameToID: map[string]string{},
		DomainToSegments: map[string][]string{},
	}
}

// TestCloneIndex_InjectsVirtualAndIsolatesOriginal verifies that the clone
// helper adds the virtual rule to the overlay without leaking it back into
// the source index, so concurrent baseline/overlay runs cannot cross-pollute.
func TestCloneIndex_InjectsVirtualAndIsolatesOriginal(t *testing.T) {
	idx := newIdx()
	idx.Policies["p1"] = &policysetcontrollerv2.PolicyRuleResource{ID: "p1", Action: "DENY"}

	virtual := &policysetcontrollerv2.PolicyRuleResource{ID: "virtual:x", Action: "ALLOW"}
	overlay := cloneIndexWithVirtual(idx, virtual)

	if _, ok := overlay.Policies["virtual:x"]; !ok {
		t.Fatal("overlay missing virtual rule")
	}
	if _, ok := idx.Policies["virtual:x"]; ok {
		t.Fatal("virtual rule leaked back into source index")
	}
}

// TestBuildVirtualRule_ShapesOperands verifies that SCIM_GROUP / APP /
// APP_GROUP IDs in VirtualPolicyInput become properly typed operands in a
// single OR condition block, matching the RHS convention the simulator reads.
func TestBuildVirtualRule_ShapesOperands(t *testing.T) {
	r := buildVirtualRule(VirtualPolicyInput{
		Name:         "v",
		Action:       "ALLOW",
		Priority:     "0",
		ScimGroupIDs: []string{"g1"},
		SegmentIDs:   []string{"s1", "s2"},
	})
	if len(r.Conditions) != 1 || r.Conditions[0].Operator != "OR" {
		t.Fatalf("want 1 OR block, got %+v", r.Conditions)
	}
	ops := r.Conditions[0].Operands
	if len(ops) != 3 {
		t.Fatalf("want 3 operands, got %d", len(ops))
	}
	gotTypes := map[string]int{}
	for _, op := range ops {
		gotTypes[op.ObjectType]++
	}
	if gotTypes["SCIM_GROUP"] != 1 || gotTypes["APP"] != 2 {
		t.Errorf("operand types mismatch: %+v", gotTypes)
	}
}

// TestCompare_BaselineVsOverlayFlipsDecision runs the simulator twice through
// the same code path the handler uses: once against the real index (DENY via
// an existing rule) and once against a clone with a virtual ALLOW at a higher
// Priority. It asserts the virtual rule changes the decision end-to-end.
func TestCompare_BaselineVsOverlayFlipsDecision(t *testing.T) {
	idx := newIdx()
	idx.Segments["seg1"] = &applicationsegment.ApplicationSegmentResource{ID: "seg1"}
	idx.Policies["deny-all"] = &policysetcontrollerv2.PolicyRuleResource{
		ID: "deny-all", Name: "deny-all", Action: "DENY", Priority: "1",
		Operator: "AND",
		Conditions: []policysetcontrollerv2.PolicyRuleResourceConditions{
			{Operator: "OR", Operands: []policysetcontrollerv2.PolicyRuleResourceOperands{
				{ObjectType: "APP", RHS: "seg1"},
			}},
		},
	}

	ctx := simulator.SimContext{
		ClientType: "zpa_client_connector",
		Platform:   "linux",
		SegmentID:  "seg1",
	}

	base, err := simulator.NewSimulator(idx).Run(t.Context(), ctx)
	if err != nil {
		t.Fatal(err)
	}
	if base.Action != "DENY" {
		t.Fatalf("baseline Action = %q, want DENY", base.Action)
	}

	virtual := buildVirtualRule(VirtualPolicyInput{
		Name: "allow-seg1", Action: "ALLOW", Priority: "10",
		SegmentIDs: []string{"seg1"},
	})
	overlay := cloneIndexWithVirtual(idx, virtual)

	withV, err := simulator.NewSimulator(overlay).Run(t.Context(), ctx)
	if err != nil {
		t.Fatal(err)
	}
	if withV.Action != "ALLOW" {
		t.Fatalf("overlay Action = %q, want ALLOW", withV.Action)
	}
}
