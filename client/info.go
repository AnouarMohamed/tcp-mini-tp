package main

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

func handleInfo(fields []string) string {
	if len(fields) < 2 {
		return "unknown info instruction"
	}

	switch fields[1] {
	case "cwd":
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Sprintf("cwd error: %v", err)
		}
		return cwd
	case "os":
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
		}
		return fmt.Sprintf("goos=%s goarch=%s hostname=%s", runtime.GOOS, runtime.GOARCH, hostname)
	case "env":
		return renderEnvInfo()
	case "uptime":
		return renderUptimeInfo()
	case "memory":
		return renderMemoryInfo()
	default:
		return "unknown info instruction"
	}
}

func renderEnvInfo() string {
	environ := os.Environ()
	sort.Strings(environ)

	lines := make([]string, 0, len(environ))
	for _, entry := range environ {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if looksSensitiveEnvKey(key) {
			value = "[redacted]"
		}
		lines = append(lines, fmt.Sprintf("%s=%s", key, value))
	}

	if len(lines) == 0 {
		return "no environment variables"
	}
	return strings.Join(lines, "\n")
}

func looksSensitiveEnvKey(key string) bool {
	upper := strings.ToUpper(key)
	for _, token := range []string{"SECRET", "TOKEN", "PASSWORD", "PASS", "KEY", "PRIVATE", "COOKIE"} {
		if strings.Contains(upper, token) {
			return true
		}
	}
	return false
}

func renderUptimeInfo() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return fmt.Sprintf("uptime error: %v", err)
	}

	parts := strings.Fields(string(data))
	if len(parts) == 0 {
		return "uptime unavailable"
	}

	seconds, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return fmt.Sprintf("uptime parse error: %v", err)
	}

	return fmt.Sprintf("uptime=%s", formatSeconds(seconds))
}

func renderMemoryInfo() string {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return fmt.Sprintf("memory error: %v", err)
	}

	var totalKB, availableKB int64
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			totalKB = parseMeminfoValue(line)
		}
		if strings.HasPrefix(line, "MemAvailable:") {
			availableKB = parseMeminfoValue(line)
		}
	}

	if totalKB == 0 {
		return "memory unavailable"
	}

	usedKB := totalKB - availableKB
	return fmt.Sprintf("memory total=%s available=%s used=%s", formatKB(totalKB), formatKB(availableKB), formatKB(usedKB))
}

func parseMeminfoValue(line string) int64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	value, _ := strconv.ParseInt(fields[1], 10, 64)
	return value
}

func formatKB(value int64) string {
	if value <= 0 {
		return "0B"
	}
	bytes := value * 1024
	units := []struct {
		label string
		value int64
	}{
		{label: "GiB", value: 1024 * 1024 * 1024},
		{label: "MiB", value: 1024 * 1024},
		{label: "KiB", value: 1024},
	}
	for _, unit := range units {
		if bytes >= unit.value {
			return fmt.Sprintf("%.1f%s", float64(bytes)/float64(unit.value), unit.label)
		}
	}
	return fmt.Sprintf("%dB", bytes)
}

func formatSeconds(seconds float64) string {
	if seconds < 0 {
		return "0s"
	}
	whole := int64(seconds)
	hours := whole / 3600
	minutes := (whole % 3600) / 60
	remaining := whole % 60
	if hours > 0 {
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, remaining)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, remaining)
	}
	return fmt.Sprintf("%ds", remaining)
}
