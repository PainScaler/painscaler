package simulator

import (
	"context"
	"testing"

	"github.com/painscaler/painscaler/internal/index"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/applicationsegment"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/policysetcontrollerv2"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/scimattributeheader"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/scimgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/segmentgroup"
)

// --- fixtures ---

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

func cond(operator string, negated bool, ops ...policysetcontrollerv2.PolicyRuleResourceOperands) policysetcontrollerv2.PolicyRuleResourceConditions {
	return policysetcontrollerv2.PolicyRuleResourceConditions{Operator: operator, Operands: ops, Negated: negated}
}

func op(objectType, rhs string) policysetcontrollerv2.PolicyRuleResourceOperands {
	return policysetcontrollerv2.PolicyRuleResourceOperands{ObjectType: objectType, RHS: rhs}
}

func opLHS(objectType, lhs, rhs string) policysetcontrollerv2.PolicyRuleResourceOperands {
	return policysetcontrollerv2.PolicyRuleResourceOperands{ObjectType: objectType, LHS: lhs, RHS: rhs}
}

func policy(id, action, priority string, operator string, conds ...policysetcontrollerv2.PolicyRuleResourceConditions) *policysetcontrollerv2.PolicyRuleResource {
	return &policysetcontrollerv2.PolicyRuleResource{
		ID: id, Name: id, Action: action, Priority: priority, Operator: operator, Conditions: conds,
	}
}

func baseCtx() SimContext {
	return SimContext{
		ClientType: "zpa_client_connector",
		Platform:   "linux",
		SegmentID:  "seg1",
	}
}

// --- Context validation ---

// TestValidateContext_MissingClientType verifies that a SimContext without
// ClientType short-circuits to Action="INVALID_CONTEXT" before any rule
// evaluation. Guards the first-stage validation in onValidateSimContext.
func TestValidateContext_MissingClientType(t *testing.T) {
	idx := newIdx()
	idx.Segments["seg1"] = &applicationsegment.ApplicationSegmentResource{ID: "seg1"}
	s := NewSimulator(idx)

	ctx := baseCtx()
	ctx.ClientType = ""
	r, err := s.Run(context.Background(), ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r.Action != "INVALID_CONTEXT" {
		t.Errorf("Action = %q, want INVALID_CONTEXT", r.Action)
	}
}

// TestValidateContext_BothSegmentAndFQDN verifies that supplying both
// SegmentID and FQDN is rejected as INVALID_CONTEXT. The two fields are
// mutually exclusive input modes; allowing both would make segment
// resolution ambiguous.
func TestValidateContext_BothSegmentAndFQDN(t *testing.T) {
	idx := newIdx()
	s := NewSimulator(idx)
	ctx := baseCtx()
	ctx.FQDN = "app.foo.com"
	r, _ := s.Run(context.Background(), ctx)
	if r.Action != "INVALID_CONTEXT" {
		t.Errorf("Action = %q, want INVALID_CONTEXT", r.Action)
	}
}

// TestValidateContext_NeitherSegmentNorFQDN verifies that omitting both
// SegmentID and FQDN is rejected as INVALID_CONTEXT. At least one is
// required to locate the target segment.
func TestValidateContext_NeitherSegmentNorFQDN(t *testing.T) {
	idx := newIdx()
	s := NewSimulator(idx)
	ctx := baseCtx()
	ctx.SegmentID = ""
	r, _ := s.Run(context.Background(), ctx)
	if r.Action != "INVALID_CONTEXT" {
		t.Errorf("Action = %q, want INVALID_CONTEXT", r.Action)
	}
}

// --- Segment resolution ---

// TestResolveSegment_Missing verifies that a context referencing a
// SegmentID absent from the index produces Action="NO_SEGMENT" and
// terminates before rule evaluation.
func TestResolveSegment_Missing(t *testing.T) {
	idx := newIdx()
	s := NewSimulator(idx)
	r, _ := s.Run(context.Background(), baseCtx())
	if r.Action != "NO_SEGMENT" {
		t.Errorf("Action = %q, want NO_SEGMENT", r.Action)
	}
}

// TestResolveSegment_FQDNExactMatch verifies that an FQDN exactly matching
// a DomainToSegments entry resolves to the correct segment, and that the
// lookup is case-insensitive via NormalizeDomain. With no policies the
// run then falls through to DEFAULT_DENY, proving resolution succeeded.
func TestResolveSegment_FQDNExactMatch(t *testing.T) {
	idx := newIdx()
	idx.Segments["seg1"] = &applicationsegment.ApplicationSegmentResource{ID: "seg1", SegmentGroupID: "grp1"}
	idx.DomainToSegments["app.foo.com"] = []string{"seg1"}

	s := NewSimulator(idx)
	ctx := baseCtx()
	ctx.SegmentID = ""
	ctx.FQDN = "APP.foo.com" // NormalizeDomain lowercases

	r, _ := s.Run(context.Background(), ctx)
	if r.Action != "DEFAULT_DENY" {
		t.Errorf("Action = %q (segment should resolve, rules empty -> DEFAULT_DENY)", r.Action)
	}
}

// TestResolveSegment_WildcardParent verifies that an FQDN like
// "app.foo.com" resolves to a segment registered under "*.foo.com" via
// the wildcard parent walk. Guards the WildcardParents generation logic,
// which is a frequent source of silent mis-routing.
func TestResolveSegment_WildcardParent(t *testing.T) {
	idx := newIdx()
	idx.Segments["seg1"] = &applicationsegment.ApplicationSegmentResource{ID: "seg1"}
	idx.DomainToSegments["*.foo.com"] = []string{"seg1"}

	s := NewSimulator(idx)
	ctx := baseCtx()
	ctx.SegmentID = ""
	ctx.FQDN = "app.foo.com"

	r, _ := s.Run(context.Background(), ctx)
	if r.Action != "DEFAULT_DENY" {
		t.Errorf("wildcard parent match failed: Action=%q warnings=%+v", r.Action, r.Warnings)
	}
}

// --- Rule ordering + disabled ---

// TestSortRules_OrderAndDisabled verifies two invariants at once:
// (1) rules with Disabled="1" are skipped entirely and must not appear in
// the trace, and (2) remaining rules are evaluated in descending Priority,
// so the highest-Priority matching rule wins. Critical for deterministic
// policy outcomes.
func TestSortRules_OrderAndDisabled(t *testing.T) {
	idx := newIdx()
	idx.Segments["seg1"] = &applicationsegment.ApplicationSegmentResource{ID: "seg1"}

	// Priority 2 is ALLOW allow-all; Priority 1 is DENY allow-all. The
	// disabled rule is inserted with the highest Priority (99) to prove it
	// would win if evaluated, and must be skipped.
	disabled := policy("dis", "ALLOW", "99", "AND")
	disabled.Disabled = "1"
	idx.Policies["dis"] = disabled
	idx.Policies["allow"] = policy("allow", "ALLOW", "2", "AND")
	idx.Policies["deny"] = policy("deny", "DENY", "1", "AND")

	s := NewSimulator(idx)
	r, _ := s.Run(context.Background(), baseCtx())
	if r.Action != "ALLOW" {
		t.Errorf("Action = %q, want ALLOW (highest-Priority non-disabled rule wins)", r.Action)
	}
	if r.MatchedRule == nil || r.MatchedRule.ID != "allow" {
		t.Errorf("matched rule = %+v", r.MatchedRule)
	}
	// Trace should contain only "allow", not "dis".
	for _, trace := range r.Trace {
		if trace.RuleID == "dis" {
			t.Errorf("disabled rule was evaluated")
		}
	}
}

// TestNextRule_EmptyRulesDefaultDeny verifies that an index with a valid
// segment but zero policies terminates at Action="DEFAULT_DENY". Encodes
// the fail-closed default when no rule is configured.
func TestNextRule_EmptyRulesDefaultDeny(t *testing.T) {
	idx := newIdx()
	idx.Segments["seg1"] = &applicationsegment.ApplicationSegmentResource{ID: "seg1"}
	s := NewSimulator(idx)
	r, _ := s.Run(context.Background(), baseCtx())
	if r.Action != "DEFAULT_DENY" {
		t.Errorf("Action = %q, want DEFAULT_DENY", r.Action)
	}
}

// TestNextRule_AllSkippedDefaultDeny verifies that when every rule exists
// but none matches (e.g., SCIM group the user lacks), the run exhausts
// the rule list and returns DEFAULT_DENY. Guards the rules-exhausted
// path in onNextRule.
func TestNextRule_AllSkippedDefaultDeny(t *testing.T) {
	idx := newIdx()
	idx.Segments["seg1"] = &applicationsegment.ApplicationSegmentResource{ID: "seg1"}
	// Policy requires SCIM_GROUP 999 which the context doesn't have.
	idx.Policies["p1"] = policy("p1", "ALLOW", "1", "AND",
		cond("AND", false, op("SCIM_GROUP", "999")))

	s := NewSimulator(idx)
	r, _ := s.Run(context.Background(), baseCtx())
	if r.Action != "DEFAULT_DENY" {
		t.Errorf("Action = %q, want DEFAULT_DENY", r.Action)
	}
}

// --- Condition evaluation ---

// TestEvalConditions_NoConditionsMatchesAll verifies the edge case where
// a policy has zero Conditions: it must match unconditionally and apply
// its Action. Mirrors the ZPA semantic "no conditions = applies to
// everyone".
func TestEvalConditions_NoConditionsMatchesAll(t *testing.T) {
	idx := newIdx()
	idx.Segments["seg1"] = &applicationsegment.ApplicationSegmentResource{ID: "seg1"}
	idx.Policies["p1"] = policy("p1", "ALLOW", "1", "AND")
	s := NewSimulator(idx)
	r, _ := s.Run(context.Background(), baseCtx())
	if r.Action != "ALLOW" {
		t.Errorf("Action = %q, want ALLOW", r.Action)
	}
}

// TestEvalConditions_SCIMGroupMatch verifies the SCIM_GROUP operand path:
// when the user's ScimGroupIDs contains the operand RHS, the condition
// evaluates true and the ALLOW action is applied.
func TestEvalConditions_SCIMGroupMatch(t *testing.T) {
	idx := newIdx()
	idx.Segments["seg1"] = &applicationsegment.ApplicationSegmentResource{ID: "seg1"}
	idx.Policies["p1"] = policy("p1", "ALLOW", "1", "AND",
		cond("AND", false, op("SCIM_GROUP", "100")))

	s := NewSimulator(idx)
	ctx := baseCtx()
	ctx.ScimGroupIDs = []string{"100"}
	r, _ := s.Run(context.Background(), ctx)
	if r.Action != "ALLOW" {
		t.Errorf("Action = %q, want ALLOW", r.Action)
	}
}

// TestEvalConditions_ORCombinator verifies that when a condition's
// Operator="OR" and the user matches any one of several SCIM_GROUP
// operands, the condition evaluates true. Guards the OR branch of
// combineResults.
func TestEvalConditions_ORCombinator(t *testing.T) {
	idx := newIdx()
	idx.Segments["seg1"] = &applicationsegment.ApplicationSegmentResource{ID: "seg1"}
	// OR across two SCIM groups -- user has only one.
	idx.Policies["p1"] = policy("p1", "ALLOW", "1", "AND",
		cond("OR", false, op("SCIM_GROUP", "100"), op("SCIM_GROUP", "200")))

	s := NewSimulator(idx)
	ctx := baseCtx()
	ctx.ScimGroupIDs = []string{"200"}
	r, _ := s.Run(context.Background(), ctx)
	if r.Action != "ALLOW" {
		t.Errorf("Action = %q, want ALLOW via OR", r.Action)
	}
}

// TestEvalConditions_NegatedCondition verifies that Negated=true flips the
// condition result: a matching SCIM_GROUP with Negated produces a failed
// condition, so the rule is skipped and the run reaches DEFAULT_DENY.
func TestEvalConditions_NegatedCondition(t *testing.T) {
	idx := newIdx()
	idx.Segments["seg1"] = &applicationsegment.ApplicationSegmentResource{ID: "seg1"}
	idx.Policies["p1"] = policy("p1", "ALLOW", "1", "AND",
		cond("AND", true, op("SCIM_GROUP", "100"))) // negated

	s := NewSimulator(idx)
	ctx := baseCtx()
	ctx.ScimGroupIDs = []string{"100"} // matches -> negated -> false
	r, _ := s.Run(context.Background(), ctx)
	if r.Action != "DEFAULT_DENY" {
		t.Errorf("Action = %q, negated match should prevent rule", r.Action)
	}
}

// TestEvalConditions_SCIMAttributeCaseInsensitive verifies the SCIM
// attribute path: the user's attribute value is compared against the
// operand RHS using strings.EqualFold, so "engineering" matches
// "Engineering". Prevents false negatives from IdP casing differences.
func TestEvalConditions_SCIMAttributeCaseInsensitive(t *testing.T) {
	idx := newIdx()
	idx.Segments["seg1"] = &applicationsegment.ApplicationSegmentResource{ID: "seg1"}
	idx.ScimAttrByID["attr1"] = &scimattributeheader.ScimAttributeHeader{ID: "attr1", Name: "department"}
	idx.Policies["p1"] = policy("p1", "ALLOW", "1", "AND",
		cond("AND", false, opLHS("SCIM", "attr1", "Engineering")))

	s := NewSimulator(idx)
	ctx := baseCtx()
	ctx.ScimAttrs = map[string]string{"attr1": "engineering"} // different case
	r, _ := s.Run(context.Background(), ctx)
	if r.Action != "ALLOW" {
		t.Errorf("SCIM attr case-insensitive match failed: %q", r.Action)
	}
}

// TestEvalConditions_UnknownObjectTypeSkippedFailsAND documents the
// current behavior for unsupported ObjectTypes (e.g., POSTURE): the
// operand is flagged Skipped=true in the trace but contributes false to
// the AND combination, so the rule does not match. This fail-closed
// behavior contradicts the inline code comment; if the intent changes,
// update this test alongside evaluateCondition.
func TestEvalConditions_UnknownObjectTypeSkippedFailsAND(t *testing.T) {
	idx := newIdx()
	idx.Segments["seg1"] = &applicationsegment.ApplicationSegmentResource{ID: "seg1"}
	// POSTURE not in known types -> operand result treated as false ->
	// AND block fails -> rule skipped -> DEFAULT_DENY.
	idx.Policies["p1"] = policy("p1", "ALLOW", "1", "AND",
		cond("AND", false, op("POSTURE", "some-rule")))

	s := NewSimulator(idx)
	r, _ := s.Run(context.Background(), baseCtx())
	if r.Action != "DEFAULT_DENY" {
		t.Errorf("skipped operand in AND should fail rule, got %q", r.Action)
	}
	// But the trace should flag it as skipped for diagnostics.
	if len(r.Trace) != 1 || len(r.Trace[0].Conditions) != 1 || len(r.Trace[0].Conditions[0].Operands) != 1 {
		t.Fatalf("unexpected trace: %+v", r.Trace)
	}
	if !r.Trace[0].Conditions[0].Operands[0].Skipped {
		t.Errorf("operand should be flagged Skipped=true")
	}
}

// --- Pure helper tests ---

// TestCombineResults_OR verifies combineResults across both combinators
// and edge cases: OR returns true iff any element is true, AND returns
// true only if all are true, an empty slice is vacuously true, and
// unrecognised operators default to AND.
func TestCombineResults_OR(t *testing.T) {
	cases := []struct {
		in   []bool
		op   string
		want bool
	}{
		{[]bool{false, true}, "OR", true},
		{[]bool{false, false}, "OR", false},
		{[]bool{true, false}, "AND", false},
		{[]bool{true, true}, "AND", true},
		{[]bool{}, "AND", true}, // vacuous truth
		{[]bool{true}, "weird", true},
	}
	for _, c := range cases {
		if got := combineResults(c.in, c.op); got != c.want {
			t.Errorf("combineResults(%v, %q) = %v, want %v", c.in, c.op, got, c.want)
		}
	}
}

// TestEvaluateOperand_SkippedFlag verifies that evaluateOperand sets
// Skipped=true for ObjectTypes outside the known set (APP, APP_GROUP,
// SCIM_GROUP, SCIM) and false for known types. The flag is surfaced in
// the trace so users can see why a condition did not contribute.
func TestEvaluateOperand_SkippedFlag(t *testing.T) {
	idx := newIdx()
	resolver := buildResolver(SimContext{}, idx)

	r := evaluateOperand(op("POSTURE", "x"), resolver)
	if !r.Skipped {
		t.Errorf("POSTURE should be skipped")
	}
	r = evaluateOperand(op("APP", "x"), resolver)
	if r.Skipped {
		t.Errorf("APP should not be skipped")
	}
}
