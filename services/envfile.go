package services

import (
	"fmt"
	"strings"
)

func parseEnvFile(content string) map[string]string {
	result := make(map[string]string)
	normalizedContent := strings.ReplaceAll(content, "\r\n", "\n")
	normalizedContent = strings.ReplaceAll(normalizedContent, "\r", "\n")
	lines := strings.Split(normalizedContent, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		if key != "" && isValidEnvKey(key) {
			result[key] = value
		}
	}

	return result
}

func isValidEnvKey(key string) bool {
	for _, c := range key {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

func buildEnvContent(envConfig map[string]string, preferredKeys []string) string {
	var lines []string
	written := make(map[string]bool, len(preferredKeys))
	for _, key := range preferredKeys {
		if value, ok := envConfig[key]; ok && value != "" {
			lines = append(lines, fmt.Sprintf("%s=%s", key, value))
			written[key] = true
		}
	}
	for key, value := range envConfig {
		if written[key] || value == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s=%s", key, value))
	}

	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	return content
}
