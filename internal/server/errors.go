package server

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Handler-layer sentinel errors. Handlers wrap these (fmt.Errorf("...: %w",
// ErrX)) so writeError can map them to HTTP status codes without each
// handler needing to know about gin.
var (
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrForbidden       = errors.New("forbidden")
	ErrNotFound        = errors.New("not found")
	ErrRateLimited     = errors.New("rate limited")
	ErrInvalidInput    = errors.New("invalid input")
	ErrUnavailable     = errors.New("service unavailable")
)

// statusForError maps a handler error to an HTTP status code. Unknown errors
// fall back to 500 so the caller still sees a failure.
func statusForError(err error) int {
	switch {
	case errors.Is(err, ErrUnauthenticated):
		return http.StatusUnauthorized
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrRateLimited):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrInvalidInput):
		return http.StatusBadRequest
	case errors.Is(err, ErrUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// writeError is invoked by generated route handlers when an app method
// returns a non-nil error. Keeping it in a handwritten file lets us evolve
// the mapping without regenerating routes.gen.go.
func writeError(c *gin.Context, err error) {
	c.JSON(statusForError(err), gin.H{"error": err.Error()})
}
