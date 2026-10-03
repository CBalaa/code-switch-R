package services

import (
	"testing"
)

func TestResolveGeminiEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		model    string
		expected string
	}{
		{
			name:     "空端点默认/v1beta",
			endpoint: "",
			model:    "gemini-2.5-flash",
			expected: "/v1beta/models/gemini-2.5-flash:generateContent",
		},
		{
			name:     "用户输入/v1beta",
			endpoint: "/v1beta",
			model:    "Gemini-3.8-Flash",
			expected: "/v1beta/models/Gemini-3.8-Flash:generateContent",
		},
		{
			name:     "用户输入v1beta不带斜杠",
			endpoint: "v1beta",
			model:    "Gemini-3.8-Flash",
			expected: "/v1beta/models/Gemini-3.8-Flash:generateContent",
		},
		{
			name:     "用户输入/v1",
			endpoint: "/v1",
			model:    "gemini-2.5-pro",
			expected: "/v1/models/gemini-2.5-pro:generateContent",
		},
		{
			name:     "用户输入完整端点不改变",
			endpoint: "/v1beta/models/gemini-2.5-flash:generateContent",
			model:    "other-model",
			expected: "/v1beta/models/gemini-2.5-flash:generateContent",
		},
		{
			name:     "用户输入流式端点不改变",
			endpoint: "/v1beta/models/gemini-2.5-flash:streamGenerateContent",
			model:    "other-model",
			expected: "/v1beta/models/gemini-2.5-flash:streamGenerateContent",
		},
		{
			name:     "用户输入包含/models/但缺:generateContent",
			endpoint: "/v1beta/models/custom-model",
			model:    "fallback",
			expected: "/v1beta/models/custom-model:generateContent",
		},
		{
			name:     "用户输入包含/models结尾",
			endpoint: "/v1beta/models",
			model:    "custom-model",
			expected: "/v1beta/models/custom-model:generateContent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveGeminiEndpoint(tt.endpoint, tt.model)
			if got != tt.expected {
				t.Errorf("resolveGeminiEndpoint(%q, %q) = %q; 期望 %q", tt.endpoint, tt.model, got, tt.expected)
			}
		})
	}
}
