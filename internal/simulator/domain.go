package simulator

import "github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/policysetcontrollerv2"

type SimContext struct {
	ScimGroupIDs   []string          `json:"scim_group_ids,omitempty"`
	ScimAttrs      map[string]string `json:"scim_attrs,omitempty"` // attrDefID -> value
	SegmentID      string            `json:"segment_id,omitempty"`
	SegmentGroupID string            `json:"segment_group_id,omitempty"`
	ClientType     string            `json:"client_type,omitempty"`
	TrustedNetwork string            `json:"trusted_network,omitempty"`
	Platform       string            `json:"platform,omitempty"`
	FQDN           string            `json:"fqdn,omitempty"`
}

type OperandResult struct {
	ObjectType  string `json:"object_type,omitempty"`
	Matched     bool   `json:"matched,omitempty"`
	Skipped     bool   `json:"skipped,omitempty"`
	MatchReason string `json:"match_reason,omitempty"`
}

type ConditionResult struct {
	ConditionID string          `json:"condition_id,omitempty"`
	Operator    string          `json:"operator,omitempty"`
	Negated     bool            `json:"negated,omitempty"`
	Operands    []OperandResult `json:"operands,omitempty"`
	Result      bool            `json:"result,omitempty"`
}

type RuleTrace struct {
	RuleID     string            `json:"rule_id,omitempty"`
	RuleName   string            `json:"rule_name,omitempty"`
	RuleOrder  int               `json:"rule_order,omitempty"`
	Action     string            `json:"action,omitempty"`
	Matched    bool              `json:"matched,omitempty"`
	SkipReason string            `json:"skip_reason,omitempty"`
	Conditions []ConditionResult `json:"conditions,omitempty"`
}

type DecisionResult struct {
	Action      string                                    `json:"action,omitempty"` // "ALLOW", "DENY", "DEFAULT_DENY"
	MatchedRule *policysetcontrollerv2.PolicyRuleResource `json:"matched_rule,omitempty"`
	Trace       []RuleTrace                               `json:"trace,omitempty"`
	Warnings    []string                                  `json:"warnings,omitempty"`
}

// Resolver: given (objectType, lhs, rhs, idpID) returns (matched, displayReason).
type Resolver func(objectType, lhs, rhs, idpID string) (bool, string)
