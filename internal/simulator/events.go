package simulator

const (
	EventStart                   = "start"
	EventContextValidationFailed = "context_invalid"
	EventContextValidated        = "context_valid"
	EventSegmentFound            = "segment_found"
	EventSegmentMissing          = "segment_missing"
	EventRulesReady              = "rules_ready"
	EventRulesExhausted          = "rules_exhausted"
	EventEvaluate                = "evaluate"
	EventRuleMatched             = "rule_matched"
	EventRuleSkipped             = "rule_skipped"
	EventInternalError           = "internal_error"
)
