package services

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestExtractGeminiModelFromEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		expected string
	}{
		{"标准 generateContent", "/v1beta/models/gemini-2.5-pro:generateContent", "gemini-2.5-pro"},
		{"带查询参数的 stream", "/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse", "gemini-2.5-flash"},
		{"无前导斜杠", "models/gemini-1.5-flash:generateContent", "gemini-1.5-flash"},
		{"带斜杠的映射目标完整提取", "/v1beta/models/vendor/gemini-x:generateContent", "vendor/gemini-x"},
		{"notmodels 不得误匹配", "/v1beta/notmodels/foo:bar", ""},
		{"查询串里的 models 不算路径", "/v1beta/other?next=/models/x", ""},
		{"空模型段", "/v1beta/models/:generateContent", ""},
		{"无 models 段", "/v1beta/cachedContents", ""},
		{"空串", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractGeminiModelFromEndpoint(tt.endpoint); got != tt.expected {
				t.Errorf("extractGeminiModelFromEndpoint(%q) = %q, 期望 %q", tt.endpoint, got, tt.expected)
			}
		})
	}
}

func TestRewriteGeminiModelInEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		from     string
		to       string
		expected string
	}{
		{
			"重写保留动作与查询参数",
			"/v1beta/models/gemini-3.8-flash:streamGenerateContent?alt=sse",
			"gemini-3.8-flash", "Gemini-3.8-Flash",
			"/v1beta/models/Gemini-3.8-Flash:streamGenerateContent?alt=sse",
		},
		{
			"from 与路径段不一致时原样返回",
			"/v1beta/models/gemini-2.5-flash:generateContent",
			"gemini-2.5-pro", "vendor-x",
			"/v1beta/models/gemini-2.5-flash:generateContent",
		},
		{
			"from 为空原样返回",
			"/v1beta/models/gemini-2.5-pro:generateContent",
			"", "vendor-x",
			"/v1beta/models/gemini-2.5-pro:generateContent",
		},
		{
			"to 为空原样返回",
			"/v1beta/models/gemini-2.5-pro:generateContent",
			"gemini-2.5-pro", "",
			"/v1beta/models/gemini-2.5-pro:generateContent",
		},
		{
			"无 models 段原样返回",
			"/v1beta/cachedContents",
			"gemini-2.5-pro", "vendor-x",
			"/v1beta/cachedContents",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rewriteGeminiModelInEndpoint(tt.endpoint, tt.from, tt.to); got != tt.expected {
				t.Errorf("rewriteGeminiModelInEndpoint(%q, %q, %q) = %q, 期望 %q",
					tt.endpoint, tt.from, tt.to, got, tt.expected)
			}
		})
	}
}

func TestGeminiParseTokenUsageFromResponse(t *testing.T) {
	usageJSON := `{"candidates":[],"usageMetadata":{"promptTokenCount":120,"candidatesTokenCount":45,"thoughtsTokenCount":30,"totalTokenCount":195}}`
	log := &ReqeustLog{}
	GeminiParseTokenUsageFromResponse(usageJSON, log)
	if log.InputTokens != 120 {
		t.Errorf("InputTokens = %d, 期望 120", log.InputTokens)
	}
	if log.OutputTokens != 45 {
		t.Errorf("OutputTokens = %d, 期望 45", log.OutputTokens)
	}
	if log.ReasoningTokens != 30 {
		t.Errorf("ReasoningTokens = %d, 期望 30", log.ReasoningTokens)
	}
}

func TestGeminiRelayWithModelMapping(t *testing.T) {
	var receivedPath string
	var receivedAuthHeader string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedAuthHeader = r.Header.Get("x-goog-api-key")
		_, _ = io.ReadAll(r.Body)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"candidates": [
				{
					"content": {
						"parts": [
							{"text": "Hello from Gemini upstream!"}
						]
					}
				}
			],
			"usageMetadata": {
				"promptTokenCount": 10,
				"candidatesTokenCount": 20,
				"totalTokenCount": 30
			}
		}`))
	}))
	defer upstream.Close()

	providers := []Provider{
		{
			ID:      101,
			Name:    "isrc-gemini",
			APIURL:  upstream.URL,
			APIKey:  "test-upstream-key",
			Enabled: true,
			ModelMapping: map[string]string{
				"gemini-3.8-flash": "Gemini-3.8-Flash",
			},
		},
	}
	pool := &ProviderPool{
		Name:     "gemini-pool",
		Platform: "gemini",
		Mode:     "managed",
		Members: []ProviderPoolMember{
			{ProviderID: 101, Enabled: true, Level: 1},
		},
	}

	_, router, keySecret, _ := setupProviderPoolHTTPTest(t, "gemini", providers, pool)

	// 发起客户端请求：小写模型名 /v1beta/models/gemini-3.8-flash:generateContent
	req := httptest.NewRequest(http.MethodPost, "/v1beta/models/gemini-3.8-flash:generateContent", strings.NewReader(`{"contents":[{"parts":[{"text":"hi"}]}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+keySecret)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("HTTP code = %d, body = %s", w.Code, w.Body.String())
	}

	// 验证上游收到的路径被重写为大小写正确的 Gemini-3.8-Flash
	expectedPath := "/v1beta/models/Gemini-3.8-Flash:generateContent"
	if receivedPath != expectedPath {
		t.Errorf("上游接收路径 = %q, 期望 = %q", receivedPath, expectedPath)
	}

	// 验证上游通过 x-goog-api-key 获取到了 provider APIKey
	if receivedAuthHeader != "test-upstream-key" {
		t.Errorf("上游 x-goog-api-key = %q, 期望 = test-upstream-key", receivedAuthHeader)
	}

	if !strings.Contains(w.Body.String(), "Hello from Gemini upstream!") {
		t.Errorf("客户端未收到预期响应: %s", w.Body.String())
	}
}

func TestLiveISRCIntegration(t *testing.T) {
	apiKey := os.Getenv("ISRC_GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("跳过真实上游测试: 未设置 ISRC_GEMINI_API_KEY")
	}
	providers := []Provider{
		{
			ID:      201,
			Name:    "isrc-live",
			APIURL:  "https://llmapi.isrc.ac.cn/v1beta",
			APIKey:               apiKey,
			ConnectivityAuthType: "x-goog-api-key",
			Enabled:              true,
			ModelMapping: map[string]string{
				"gemini-3.8-flash": "Gemini-3.8-Flash",
			},
		},
	}
	pool := &ProviderPool{
		Name:     "gemini-live-pool",
		Platform: "gemini",
		Mode:     "managed",
		Members: []ProviderPoolMember{
			{ProviderID: 201, Enabled: true, Level: 1},
		},
	}

	_, router, keySecret, _ := setupProviderPoolHTTPTest(t, "gemini", providers, pool)

	// 发起客户端请求：小写模型名 /v1beta/models/gemini-3.8-flash:generateContent
	req := httptest.NewRequest(http.MethodPost, "/v1beta/models/gemini-3.8-flash:generateContent", strings.NewReader(`{"contents":[{"parts":[{"text":"Say ping in one word"}]}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+keySecret)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Live ISRC HTTP code = %d, body = %s", w.Code, w.Body.String())
	}

	t.Logf("Live ISRC Response: %s", w.Body.String())
	if !strings.Contains(w.Body.String(), "candidates") {
		t.Errorf("预期返回包含 candidates，实际响应: %s", w.Body.String())
	}
}

