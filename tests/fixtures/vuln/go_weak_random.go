package main

import (
	"fmt"
	"math/rand"
)

// generateSessionToken derives a session token from math/rand, a
// deterministic, predictable PRNG - true positive for
// SAST-GO-WEAK_RANDOM-01.
func generateSessionToken() string {
	return fmt.Sprintf("session-%d", rand.Intn(1000000000))
}
