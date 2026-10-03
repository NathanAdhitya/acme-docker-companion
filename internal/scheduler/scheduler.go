// Package scheduler contains the pure renewal-decision logic: the
// lifetime-based fallback threshold and the Let's Encrypt failure backoff.
// The RFC 9773 ARI window algorithm is lego's; the reconciler draws the
// renewal instant once per window and passes it here as RenewAt.
package scheduler

import "time"

// Config holds scheduling policy.
type Config struct {
	// CheckInterval is how often ARI is consulted and due checks run. It also
	// bounds how far ahead an ARI renewal may be scheduled.
	CheckInterval time.Duration
	// RenewBefore, when non-zero, overrides the lifetime-relative threshold.
	RenewBefore time.Duration
	// Backoff is the retry schedule indexed by consecutive failure count.
	Backoff []time.Duration
}

// State is the scheduling-relevant snapshot of a certificate.
type State struct {
	NotBefore time.Time
	NotAfter  time.Time

	// ForceRenew skips the ARI/lifetime checks, e.g. because no usable
	// certificate is cached.
	ForceRenew bool

	// ARI reports that the CA supplied a renewal window. While true the
	// lifetime threshold is not used; renewal waits for RenewAt.
	ARI bool
	// RenewAt is the instant drawn from the ARI window (RFC 9773). The zero
	// value means the window is not actionable yet; the next ARI refresh
	// draws again.
	RenewAt time.Time

	// NextAttempt is the earliest time a retry may run after a failure.
	NextAttempt time.Time
}

// ShouldRenew decides whether an issuance or renewal attempt is due now.
//
// A failed attempt gates the next one through the backoff schedule. The gate
// applies to every reason to renew, including a missing certificate and a
// forced reissue, so failures cannot multiply ACME attempts.
func ShouldRenew(now time.Time, st State, cfg Config) bool {
	now = now.UTC()

	var renew bool
	switch {
	case st.ForceRenew || st.NotAfter.IsZero():
		renew = true
	case st.ARI:
		renew = !st.RenewAt.IsZero() && !st.RenewAt.After(now)
	default:
		renew = !renewalThreshold(st, cfg).After(now)
	}

	if renew && !st.NextAttempt.IsZero() && now.Before(st.NextAttempt) {
		return false
	}
	return renew
}

// renewalThreshold is the fallback renewal time when ARI is unavailable:
// two thirds through the lifetime, or halfway for certificates shorter than
// ten days.
func renewalThreshold(st State, cfg Config) time.Time {
	if cfg.RenewBefore > 0 {
		return st.NotAfter.Add(-cfg.RenewBefore)
	}
	lifetime := st.NotAfter.Sub(st.NotBefore)
	if lifetime < 10*24*time.Hour {
		return st.NotBefore.Add(lifetime / 2)
	}
	return st.NotBefore.Add(lifetime * 2 / 3)
}

// BackoffDuration returns the delay to apply after n consecutive failures.
func BackoffDuration(n int, cfg Config) time.Duration {
	if n <= 0 || len(cfg.Backoff) == 0 {
		return 0
	}
	return cfg.Backoff[min(n-1, len(cfg.Backoff)-1)]
}
