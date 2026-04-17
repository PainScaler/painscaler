package server

import (
	"testing"
	"time"
)

func TestRefresh_RejectsMissingUser(t *testing.T) {
	s := &Server{}
	err := s.Refresh("")
	if err == nil {
		t.Fatal("expected error for empty user")
	}
	if err.Error() != "unauthenticated" {
		t.Fatalf("err = %q, want \"unauthenticated\"", err.Error())
	}
}

func TestRefreshThrottle_Throttles(t *testing.T) {
	var rt refreshThrottle
	t0 := time.Unix(0, 0)

	if !rt.allow(t0) {
		t.Fatal("first call should be allowed")
	}
	if rt.allow(t0.Add(refreshMinInterval - time.Second)) {
		t.Fatal("second call within interval should be rejected")
	}
	if !rt.allow(t0.Add(refreshMinInterval + time.Second)) {
		t.Fatal("call after interval should be allowed")
	}
}
