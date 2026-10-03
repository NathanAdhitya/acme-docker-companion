package scheduler

import (
	"testing"
	"time"
)

func cfg() Config {
	return Config{
		CheckInterval: 12 * time.Hour,
		Backoff:       []time.Duration{time.Minute, 10 * time.Minute, 100 * time.Minute, 24 * time.Hour},
	}
}

func TestMissingCertRenewsImmediately(t *testing.T) {
	if !ShouldRenew(time.Now(), State{}, cfg()) {
		t.Fatal("a certificate with no NotAfter must renew immediately")
	}
}

func TestMissingCertRespectsBackoff(t *testing.T) {
	now := time.Now().UTC()
	st := State{NextAttempt: now.Add(30 * time.Second)}
	if ShouldRenew(now, st, cfg()) {
		t.Fatal("a missing certificate must not retry before NextAttempt")
	}
	if !ShouldRenew(now.Add(time.Minute), st, cfg()) {
		t.Fatal("a missing certificate must retry once NextAttempt has passed")
	}
}

func TestForceRenewRespectsBackoff(t *testing.T) {
	now := time.Now().UTC()
	notAfter := now.Add(90 * 24 * time.Hour)
	if !ShouldRenew(now, State{NotAfter: notAfter, ForceRenew: true}, cfg()) {
		t.Fatal("ForceRenew must renew even inside the lifetime window")
	}
	if ShouldRenew(now, State{NotAfter: notAfter, ForceRenew: true, NextAttempt: now.Add(time.Minute)}, cfg()) {
		t.Fatal("ForceRenew must still honor the failure backoff")
	}
}

func TestNinetyDayLifetime(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(90 * 24 * time.Hour)

	// At 50% through the lifetime: not due.
	if ShouldRenew(notBefore.Add(45*24*time.Hour), State{NotBefore: notBefore, NotAfter: notAfter}, cfg()) {
		t.Fatal("should not renew at 50% of a 90-day lifetime")
	}

	// At 70% through: due (threshold is two thirds).
	if !ShouldRenew(notBefore.Add(70*24*time.Hour), State{NotBefore: notBefore, NotAfter: notAfter}, cfg()) {
		t.Fatal("should renew at 70% of a 90-day lifetime")
	}
}

func TestShortLifetimeUsesHalfway(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(6 * 24 * time.Hour)

	if ShouldRenew(notBefore.Add(2*24*time.Hour), State{NotBefore: notBefore, NotAfter: notAfter}, cfg()) {
		t.Fatal("should not renew at 1/3 of a 6-day lifetime")
	}
	if !ShouldRenew(notBefore.Add(4*24*time.Hour), State{NotBefore: notBefore, NotAfter: notAfter}, cfg()) {
		t.Fatal("should renew past halfway of a 6-day lifetime")
	}
}

func TestARIDrawnInstantIsHonored(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	at := now.Add(30 * 24 * time.Hour)
	st := State{
		NotBefore: now.Add(-10 * 24 * time.Hour),
		NotAfter:  now.Add(80 * 24 * time.Hour),
		ARI:       true,
		RenewAt:   at,
	}
	if ShouldRenew(now, st, cfg()) {
		t.Fatal("an ARI instant in the future must not renew now")
	}
	if !ShouldRenew(at, st, cfg()) {
		t.Fatal("an ARI instant already reached must renew")
	}
}

func TestARITakenButNotDrawnWaits(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	// The lifetime threshold would be due, but ARI is authoritative and the
	// window has not produced an actionable instant yet.
	st := State{
		NotBefore: now.Add(-100 * 24 * time.Hour),
		NotAfter:  now.Add(time.Hour),
		ARI:       true,
	}
	if ShouldRenew(now, st, cfg()) {
		t.Fatal("an ARI window awaiting its next refresh must suppress the lifetime rule")
	}
}

func TestBackoffGatesRetry(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	st := State{
		NotBefore:   now.Add(-100 * 24 * time.Hour),
		NotAfter:    now.Add(1 * time.Hour), // long overdue
		NextAttempt: now.Add(30 * time.Second),
	}
	if ShouldRenew(now, st, cfg()) {
		t.Fatal("must not retry before NextAttempt")
	}
	if !ShouldRenew(now.Add(time.Minute), st, cfg()) {
		t.Fatal("must retry once NextAttempt has passed")
	}
}

func TestBackoffDuration(t *testing.T) {
	c := cfg()
	cases := []struct {
		n    int
		want time.Duration
	}{
		{0, 0},
		{1, time.Minute},
		{2, 10 * time.Minute},
		{3, 100 * time.Minute},
		{4, 24 * time.Hour},
		{99, 24 * time.Hour},
	}
	for _, tc := range cases {
		if got := BackoffDuration(tc.n, c); got != tc.want {
			t.Errorf("BackoffDuration(%d) = %v, want %v", tc.n, got, tc.want)
		}
	}
}
