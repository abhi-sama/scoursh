package main

import (
	"crypto/rand"
	"encoding/hex"
)

// generateSessionToken derives a session token from crypto/rand, a
// cryptographically secure random source - safe equivalent for
// SAST-GO-WEAK_RANDOM-01.
func generateSessionToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
