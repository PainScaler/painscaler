package index

import (
	"testing"

	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/policysetcontrollerv2"
)

func TestValidatePolicy(t *testing.T) {
	cases := []struct {
		name    string
		in      policysetcontrollerv2.PolicyRuleResource
		wantOK  bool
		wantHas string
	}{
		{"good", policysetcontrollerv2.PolicyRuleResource{ID: "p1", RuleOrder: "1"}, true, ""},
		{"empty ID", policysetcontrollerv2.PolicyRuleResource{ID: "", RuleOrder: "1"}, false, "empty ID"},
		{"non-numeric order", policysetcontrollerv2.PolicyRuleResource{ID: "p1", RuleOrder: "abc"}, false, "non-numeric RuleOrder"},
		{"empty order", policysetcontrollerv2.PolicyRuleResource{ID: "p1", RuleOrder: ""}, false, "non-numeric RuleOrder"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reason, ok := validatePolicy(&c.in)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v (reason=%q)", ok, c.wantOK, reason)
			}
			if reason != c.wantHas {
				t.Fatalf("reason = %q, want %q", reason, c.wantHas)
			}
		})
	}
}
