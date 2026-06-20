package main

import (
	"crypto/rand"
	"encoding/hex"
)

// Config is the relay's runtime configuration. There is no device or contact
// file anymore: devices self-enroll by proving account control, and API keys are
// minted by their owners. The only persistent state lives in the Store.
type Config struct {
	Listen                string
	RequestTimeoutSeconds int
	SQLitePath            string // SQLite file path; empty = in-memory (dev only)
}

func randomSecret(nbytes int) string {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		panic("relay: out of randomness: " + err.Error())
	}
	return hex.EncodeToString(b)
}
