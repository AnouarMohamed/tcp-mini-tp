package main

import "testing"

func TestParseAllowlistDefaultIncludesCoreCommands(t *testing.T) {
	allowed := parseAllowlist("")

	for _, cmd := range []string{"pwd", "ls", "whoami", "cd"} {
		if _, ok := allowed[cmd]; !ok {
			t.Fatalf("expected %q to be allowed", cmd)
		}
	}
}

func TestExecuteBlocksNonWhitelistedCommand(t *testing.T) {
	allowed := map[string]struct{}{"pwd": {}}
	got := execute("command whoami", allowed)

	want := "blocked command: whoami (not in whitelist)"
	if got != want {
		t.Fatalf("execute returned %q, want %q", got, want)
	}
}

func TestExecuteInfoCWD(t *testing.T) {
	allowed := map[string]struct{}{}
	got := execute("info cwd", allowed)
	if got == "" {
		t.Fatal("expected cwd output")
	}
}
