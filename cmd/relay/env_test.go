package main

import (
	"os"
	"testing"
)

func TestLoadDotEnvParsingAndPrecedence(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	must(t, os.WriteFile(".env", []byte(
		"# comment\nDOTENV_A=from_env\nDOTENV_LISTEN=\":9000\"\nexport DOTENV_EXP=bar\n"), 0o600))
	must(t, os.WriteFile(".env.local", []byte("DOTENV_A='from_local'\n"), 0o600))

	for _, k := range []string{"DOTENV_A", "DOTENV_LISTEN", "DOTENV_EXP"} {
		os.Unsetenv(k)
		t.Cleanup(func() { os.Unsetenv(k) })
	}

	loadDotEnv()

	if got := os.Getenv("DOTENV_A"); got != "from_local" {
		t.Errorf(".env.local should win over .env: got %q", got)
	}
	if got := os.Getenv("DOTENV_LISTEN"); got != ":9000" {
		t.Errorf("surrounding quotes not stripped: got %q", got)
	}
	if got := os.Getenv("DOTENV_EXP"); got != "bar" {
		t.Errorf("leading export not handled: got %q", got)
	}
}

func TestRealEnvWinsOverDotEnv(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	must(t, os.WriteFile(".env.local", []byte("DOTENV_REAL=from_file\n"), 0o600))
	t.Setenv("DOTENV_REAL", "from_real_env")

	loadDotEnv()

	if got := os.Getenv("DOTENV_REAL"); got != "from_real_env" {
		t.Errorf("real environment must win over dotenv files: got %q", got)
	}
}
