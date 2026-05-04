package main

import (
	"os"
	"strings"
	"testing"
)

func TestHandleInfo(t *testing.T) {
	currentDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}

	t.Setenv("TCP_TEST_SECRET", "super-secret")
	t.Setenv("TCP_TEST_VISIBLE", "visible-value")

	tests := []struct {
		name       string
		fields     []string
		want       string
		wantPrefix string
		check      func(t *testing.T, got string)
	}{
		{name: "cwd", fields: []string{"info", "cwd"}, want: currentDir},
		{name: "os", fields: []string{"info", "os"}, wantPrefix: "goos="},
		{name: "env", fields: []string{"info", "env"}, check: func(t *testing.T, got string) {
			if !strings.Contains(got, "TCP_TEST_VISIBLE=visible-value") {
				t.Fatalf("env output missing visible variable: %q", got)
			}
			if !strings.Contains(got, "TCP_TEST_SECRET=[redacted]") {
				t.Fatalf("env output missing redaction: %q", got)
			}
		}},
		{name: "uptime", fields: []string{"info", "uptime"}, wantPrefix: "uptime="},
		{name: "memory", fields: []string{"info", "memory"}, wantPrefix: "memory total="},
		{name: "unknown", fields: []string{"info", "whatever"}, want: "unknown info instruction"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			got := handleInfo(test.fields)
			if test.check != nil {
				test.check(t, got)
				return
			}
			if test.wantPrefix != "" {
				if !strings.HasPrefix(got, test.wantPrefix) {
					t.Fatalf("handleInfo returned %q, want prefix %q", got, test.wantPrefix)
				}
				return
			}
			if got != test.want {
				t.Fatalf("handleInfo returned %q, want %q", got, test.want)
			}
		})
	}
}
