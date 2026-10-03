package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTestProviderManualWithMessage_GeminiEndpointCompletion(t *testing.T) {
	var receivedPath string
	var receivedAuthHeader string
	var receivedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedAuthHeader = r.Header.Get("x-goog-api-key")
		_ = json.NewDecoder(r.Body).Decode(&receivedBody)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"candidates": [
				{
					"content": {
						"parts": [{"text": "Hello from Gemini"}]
					}
				}
			]
		}`))
	}))
	defer server.Close()

	cts := NewConnectivityTestService(nil, nil)
	cts.client = &http.Client{Timeout: 5 * time.Second}

	// 测试 1: endpoint 为 "/v1beta"，model 为 "Gemini-3.8-Flash"，authType 为 "bearer" (默认)
	res := cts.TestProviderManualWithMessage(
		"gemini",
		server.URL,
		"test-key-123",
		"Gemini-3.8-Flash",
		"/v1beta",
		"bearer",
		"hello test",
	)

	if !res.Success {
		t.Fatalf("预期测试成功，实际失败: %s", res.Message)
	}

	expectedPath := "/v1beta/models/Gemini-3.8-Flash:generateContent"
	if receivedPath != expectedPath {
		t.Errorf("receivedPath = %q; 期望 = %q", receivedPath, expectedPath)
	}

	if receivedAuthHeader != "test-key-123" {
		t.Errorf("receivedAuthHeader = %q; 期望 = %q", receivedAuthHeader, "test-key-123")
	}

	// 测试 2: server.URL 本身带 /v1beta，endpoint 用户写 /v1beta (防止出现 /v1beta/v1beta)
	receivedPath = ""
	res2 := cts.TestProviderManualWithMessage(
		"gemini",
		server.URL+"/v1beta",
		"test-key-456",
		"Gemini-3.8-Flash",
		"/v1beta",
		"x-goog-api-key",
		"hello test 2",
	)

	if !res2.Success {
		t.Fatalf("预期测试成功，实际失败: %s", res2.Message)
	}
	if receivedPath != expectedPath {
		t.Errorf("防重复前缀测试: receivedPath = %q; 期望 = %q", receivedPath, expectedPath)
	}
}
