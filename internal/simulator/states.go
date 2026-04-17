package simulator

const (
	StateIdle            = "idle"
	StateValidateContext = "validate_context"
	StateResolveSegment  = "resolve_segment"
	StateSortRules       = "sort_rules"
	StateNextRule        = "next_rule"
	StateEvalConditions  = "eval_conditions"
	StateDecided         = "decided"
)
