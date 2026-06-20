package main

import (
	"bufio"
	"log"
	"os"
	"strings"
)

// loadDotEnv loads environment variables from .env.local then .env in the
// working directory, without overriding variables already set in the real
// environment. Precedence (highest first): real environment, .env.local, .env.
// Missing files are ignored. Parsing is intentionally minimal: KEY=VALUE per
// line, '#' comments, an optional leading `export`, and optional surrounding
// quotes around the value.
func loadDotEnv() {
	for _, name := range []string{".env.local", ".env"} {
		if applyEnvFile(name) {
			log.Printf("loaded environment from %s", name)
		}
	}
}

func applyEnvFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		// The real environment and earlier files take precedence.
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		_ = os.Setenv(key, dotenvValue(val))
	}
	return true
}

// dotenvValue trims surrounding whitespace and matching quotes from a value.
func dotenvValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}
