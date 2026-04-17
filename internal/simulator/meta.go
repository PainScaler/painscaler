package simulator

import (
	"fmt"

	"github.com/looplab/fsm"
)

const (
	metaCtx      = "sim_ctx"
	metaIdx      = "sim_idx"
	metaRules    = "sim_rules"
	metaCursor   = "sim_cursor"
	metaResult   = "sim_result"
	metaResolver = "sim_resolver"
)

// getMeta returns metadata of the requested type. Returns an error instead of
// panicking when the key is missing or the stored value has an unexpected
// type so callers can surface the failure via DecisionResult.Warnings.
func getMeta[T any](f *fsm.FSM, key string) (T, error) {
	var zero T
	v, ok := f.Metadata(key)
	if !ok {
		return zero, fmt.Errorf("fsm metadata %q missing", key)
	}
	typed, ok := v.(T)
	if !ok {
		return zero, fmt.Errorf("fsm metadata %q has unexpected type %T", key, v)
	}
	return typed, nil
}
