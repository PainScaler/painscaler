package simulator

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/painscaler/painscaler/internal/index"
	"github.com/looplab/fsm"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/policysetcontrollerv2"
)

// --- Simulator ---

type Simulator struct {
	fsm *fsm.FSM
	idx *index.Index
}

func NewSimulator(idx *index.Index) *Simulator {
	s := &Simulator{idx: idx}

	s.fsm = fsm.NewFSM(
		StateIdle,

		fsm.Events{
			{Name: EventStart, Src: []string{StateIdle}, Dst: StateValidateContext},
			{Name: EventContextValidationFailed, Src: []string{StateValidateContext}, Dst: StateDecided},
			{Name: EventContextValidated, Src: []string{StateValidateContext}, Dst: StateResolveSegment},
			{Name: EventSegmentFound, Src: []string{StateResolveSegment}, Dst: StateSortRules},
			{Name: EventSegmentMissing, Src: []string{StateResolveSegment}, Dst: StateDecided},
			{Name: EventRulesReady, Src: []string{StateSortRules}, Dst: StateNextRule},
			{Name: EventRulesExhausted, Src: []string{StateNextRule}, Dst: StateDecided},
			{Name: EventEvaluate, Src: []string{StateNextRule}, Dst: StateEvalConditions},
			{Name: EventRuleMatched, Src: []string{StateEvalConditions}, Dst: StateDecided},
			{Name: EventRuleSkipped, Src: []string{StateEvalConditions}, Dst: StateNextRule},
			{Name: EventInternalError, Src: []string{
				StateValidateContext, StateResolveSegment, StateSortRules,
				StateNextRule, StateEvalConditions,
			}, Dst: StateDecided},
		},

		fsm.Callbacks{
			"enter_" + StateValidateContext: s.onValidateSimContext,
			"enter_" + StateResolveSegment:  s.onResolveSegment,
			"enter_" + StateSortRules:       s.onSortRules,
			"enter_" + StateNextRule:        s.onNextRule,
			"enter_" + StateEvalConditions:  s.onEvalConditions,
			"enter_" + StateDecided:         s.onDecided,
		},
	)

	return s
}

// Run executes a full simulation synchronously and returns the result.
func (s *Simulator) Run(ctx context.Context, simCtx SimContext) (*DecisionResult, error) {
	// Reset to idle between runs.
	s.fsm.SetState(StateIdle)

	result := &DecisionResult{}
	s.fsm.SetMetadata(metaCtx, simCtx)
	s.fsm.SetMetadata(metaIdx, s.idx)
	s.fsm.SetMetadata(metaResult, result)
	s.fsm.SetMetadata(metaCursor, 0)

	resolver := buildResolver(simCtx, s.idx)
	s.fsm.SetMetadata(metaResolver, resolver)

	if err := s.fsm.Event(ctx, EventStart); err != nil {
		return nil, fmt.Errorf("fsm start: %w", err)
	}

	// The FSM drives itself from callbacks, by the time Event() returns
	// for terminal transitions (decided), the result is fully populated.
	return result, nil
}

// --- Callbacks ---

// bail marks the run as internally failed and drives the FSM into its
// terminal state. Used when metadata cannot be read, which should only
// happen if the FSM is misused; surfaced via Warnings rather than panic.
func (s *Simulator) bail(ctx context.Context, result *DecisionResult, err error) {
	if result != nil {
		result.Action = "INTERNAL_ERROR"
		result.Warnings = append(result.Warnings, err.Error())
	}
	_ = s.fsm.Event(ctx, EventInternalError)
}

func (s *Simulator) onValidateSimContext(ctx context.Context, e *fsm.Event) {
	result, err := getMeta[*DecisionResult](s.fsm, metaResult)
	if err != nil {
		s.bail(ctx, nil, err)
		return
	}
	simCtx, err := getMeta[SimContext](s.fsm, metaCtx)
	if err != nil {
		s.bail(ctx, result, err)
		return
	}

	var errs = []string{}

	hasSegmentId := simCtx.SegmentID != ""
	hasClientType := simCtx.ClientType != ""
	hasPlatform := simCtx.Platform != ""
	hasFQDN := simCtx.FQDN != ""

	if !hasClientType {
		errs = append(errs, "ctx.ClientType cannot be empty")
	}

	if !hasPlatform {
		errs = append(errs, "ctx.Platform cannot be empty")
	}

	if !hasFQDN && !hasSegmentId {
		errs = append(errs, "ctx.SegmentID cannot be empty when ctx.FQDN is empty")
	}

	if hasFQDN && hasSegmentId {
		errs = append(errs, "ctx.SegmentID must be empty when ctx.FQDN is set")
	}

	if len(errs) > 0 {
		result.Action = "INVALID_CONTEXT"
		result.Warnings = append(result.Warnings, errs...)
		_ = s.fsm.Event(ctx, EventContextValidationFailed)
		return
	}

	_ = s.fsm.Event(ctx, EventContextValidated)
}

func (s *Simulator) onResolveSegment(ctx context.Context, e *fsm.Event) {
	result, err := getMeta[*DecisionResult](s.fsm, metaResult)
	if err != nil {
		s.bail(ctx, nil, err)
		return
	}
	simCtx, err := getMeta[SimContext](s.fsm, metaCtx)
	if err != nil {
		s.bail(ctx, result, err)
		return
	}
	idx, err := getMeta[*index.Index](s.fsm, metaIdx)
	if err != nil {
		s.bail(ctx, result, err)
		return
	}

	// Resolve segment from FQDN: exact match first, then wildcard parents.
	if simCtx.FQDN != "" {
		fqdn := index.NormalizeDomain(simCtx.FQDN)
		var segIDs []string
		if ids, ok := idx.DomainToSegments[fqdn]; ok {
			segIDs = append(segIDs, ids...)
		}
		for _, wc := range index.WildcardParents(fqdn) {
			if ids, ok := idx.DomainToSegments[wc]; ok {
				segIDs = append(segIDs, ids...)
			}
		}
		if len(segIDs) > 0 {
			simCtx.SegmentID = segIDs[0]
			if len(segIDs) > 1 {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("FQDN %q matches %d segments, using most specific: %s", simCtx.FQDN, len(segIDs), segIDs[0]))
			}
		}
	}
	// Check the segment exists and build SegmentGroupIDs.
	seg, ok := idx.Segments[simCtx.SegmentID]

	if !ok {
		result.Action = "NO_SEGMENT"
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("segment %s not found in index", simCtx.SegmentID))
		// Fire terminal event from within the callback.
		_ = s.fsm.Event(ctx, EventSegmentMissing)
		return
	}

	// Resolve which segment group this segment belongs to.
	simCtx.SegmentGroupID = seg.SegmentGroupID
	s.fsm.SetMetadata(metaCtx, simCtx)

	_ = s.fsm.Event(ctx, EventSegmentFound)
}

func (s *Simulator) onSortRules(ctx context.Context, e *fsm.Event) {
	result, err := getMeta[*DecisionResult](s.fsm, metaResult)
	if err != nil {
		s.bail(ctx, nil, err)
		return
	}
	idx, err := getMeta[*index.Index](s.fsm, metaIdx)
	if err != nil {
		s.bail(ctx, result, err)
		return
	}

	// Collect and sort by RuleOrder (string -> int). Skip disabled rules.
	var rules []*policysetcontrollerv2.PolicyRuleResource
	for id := range idx.Policies {
		r := idx.Policies[id]
		if r.Disabled == "1" {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("rule %q disabled, skipped", r.Name))
			continue
		}
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool {
		oi, _ := strconv.Atoi(rules[i].RuleOrder)
		oj, _ := strconv.Atoi(rules[j].RuleOrder)
		return oi < oj
	})

	s.fsm.SetMetadata(metaRules, rules)
	s.fsm.SetMetadata(metaCursor, 0)

	_ = s.fsm.Event(ctx, EventRulesReady)
}

func (s *Simulator) onNextRule(ctx context.Context, e *fsm.Event) {
	result, err := getMeta[*DecisionResult](s.fsm, metaResult)
	if err != nil {
		s.bail(ctx, nil, err)
		return
	}
	rules, err := getMeta[[]*policysetcontrollerv2.PolicyRuleResource](s.fsm, metaRules)
	if err != nil {
		s.bail(ctx, result, err)
		return
	}
	cursor, err := getMeta[int](s.fsm, metaCursor)
	if err != nil {
		s.bail(ctx, result, err)
		return
	}

	if cursor >= len(rules) {
		result.Action = "DEFAULT_DENY"
		_ = s.fsm.Event(ctx, EventRulesExhausted)
		return
	}

	_ = s.fsm.Event(ctx, EventEvaluate)
}

func (s *Simulator) onEvalConditions(ctx context.Context, e *fsm.Event) {
	result, err := getMeta[*DecisionResult](s.fsm, metaResult)
	if err != nil {
		s.bail(ctx, nil, err)
		return
	}
	rules, err := getMeta[[]*policysetcontrollerv2.PolicyRuleResource](s.fsm, metaRules)
	if err != nil {
		s.bail(ctx, result, err)
		return
	}
	cursor, err := getMeta[int](s.fsm, metaCursor)
	if err != nil {
		s.bail(ctx, result, err)
		return
	}
	resolver, err := getMeta[Resolver](s.fsm, metaResolver)
	if err != nil {
		s.bail(ctx, result, err)
		return
	}

	rule := rules[cursor]
	order, _ := strconv.Atoi(rule.RuleOrder)

	trace := RuleTrace{
		RuleID:    rule.ID,
		RuleName:  rule.Name,
		RuleOrder: order,
		Action:    rule.Action,
	}

	// Evaluate all condition blocks, then combine with rule.Operator.
	blockResults := make([]bool, len(rule.Conditions))
	for i, cond := range rule.Conditions {
		cr, result := evaluateCondition(cond, resolver)
		trace.Conditions = append(trace.Conditions, cr)
		blockResults[i] = result
	}

	ruleMatched := combineResults(blockResults, rule.Operator)
	trace.Matched = ruleMatched

	// Handle the edge case: no conditions means the rule applies to everyone.
	if len(rule.Conditions) == 0 {
		ruleMatched = true
		trace.Matched = true
		trace.SkipReason = ""
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("rule %q has no conditions -- matches all", rule.Name))
	}

	if !ruleMatched {
		trace.SkipReason = "conditions not satisfied"
	}
	result.Trace = append(result.Trace, trace)

	if ruleMatched {
		result.Action = rule.Action
		result.MatchedRule = rule
		_ = s.fsm.Event(ctx, EventRuleMatched)
	} else {
		s.fsm.SetMetadata(metaCursor, cursor+1)
		_ = s.fsm.Event(ctx, EventRuleSkipped)
	}
}

func (s *Simulator) onDecided(_ context.Context, _ *fsm.Event) {
	// Terminal state, nothing to drive further.
	// Result is already fully populated in metadata.
}

// --- Condition & operand evaluation ---

func evaluateCondition(
	cond policysetcontrollerv2.PolicyRuleResourceConditions,
	resolve Resolver,
) (ConditionResult, bool) {
	cr := ConditionResult{
		ConditionID: cond.ID,
		Operator:    cond.Operator,
		Negated:     cond.Negated,
	}

	operandResults := make([]bool, len(cond.Operands))
	for i, op := range cond.Operands {
		or_ := evaluateOperand(op, resolve)
		cr.Operands = append(cr.Operands, or_)
		if or_.Skipped {
			// Skipped operands are treated as non-matching but don't poison
			// an OR block, only absent from the AND combination.
			operandResults[i] = false
		} else {
			operandResults[i] = or_.Matched
		}
	}

	result := combineResults(operandResults, cond.Operator)
	if cond.Negated {
		result = !result
	}
	cr.Result = result
	return cr, result
}

func evaluateOperand(
	op policysetcontrollerv2.PolicyRuleResourceOperands,
	resolve Resolver,
) OperandResult {
	matched, reason := resolve(op.ObjectType, op.LHS, op.RHS, op.IDPID)

	knownTypes := map[string]bool{
		"APP": true, "APP_GROUP": true, "SCIM_GROUP": true, "SCIM": true,
	}
	skipped := !knownTypes[op.ObjectType]

	return OperandResult{
		ObjectType:  op.ObjectType,
		Matched:     matched,
		Skipped:     skipped,
		MatchReason: reason,
	}
}

// combineResults applies AND or OR across a slice of bool results.
// Defaults to AND for any unrecognised operator.
func combineResults(results []bool, operator string) bool {
	if len(results) == 0 {
		return true
	}
	if strings.ToUpper(operator) == "OR" {
		return slices.Contains(results, true)
	}
	// AND
	for _, r := range results {
		if !r {
			return false
		}
	}
	return true
}

// --- Generic resolver ---

func buildResolver(ctx SimContext, idx *index.Index) Resolver {
	return func(objectType, lhs, rhs, idpID string) (bool, string) {
		switch objectType {

		case "APP":
			matched := rhs == ctx.SegmentID
			name := segmentDisplayName(idx, rhs)
			return matched, fmt.Sprintf("segment %s", name)

		case "APP_GROUP":
			matched := rhs == ctx.SegmentGroupID
			name := groupDisplayName(idx, rhs)
			return matched, fmt.Sprintf("group %s", name)

		case "SCIM_GROUP":
			matched := slices.Contains(ctx.ScimGroupIDs, rhs)
			name := scimGroupDisplayName(idx, rhs)
			return matched, fmt.Sprintf("SCIM group %s", name)

		case "SCIM":
			// lhs is the attribute definition ID.
			userVal, ok := ctx.ScimAttrs[lhs]
			attrName := scimAttrDisplayName(idx, lhs)
			if !ok {
				return false, fmt.Sprintf("%s not present on user", attrName)
			}
			matched := strings.EqualFold(userVal, rhs)
			return matched, fmt.Sprintf("%s: user=%q policy=%q", attrName, userVal, rhs)

		default:
			return false, fmt.Sprintf("ObjectType %q not evaluable", objectType)
		}
	}
}
