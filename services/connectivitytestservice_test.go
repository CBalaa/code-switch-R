package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestTestProviderManualWithMessage_OpenAIImagesPromptBody(t *testing.T) {
	var receivedPath, receivedAuth string
	var receivedBody map[string]interface{}
	// 1MB 量级的 base64：验证生图响应不再被旧的 1MB 上限截断，
	// 否则前端拿不到完整 data[0].b64_json，无法做图片预览。
	bigB64 := strings.Repeat("A", 1<<20)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&receivedBody)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w,
			`{"created":1700000000,"data":[{"b64_json":%q}],"usage":{"input_tokens":12,"output_tokens":343}}`,
			bigB64)
	}))
	defer server.Close()

	cts := NewConnectivityTestService(nil, nil)
	cts.client = &http.Client{Timeout: 5 * time.Second}

	res := cts.TestProviderManualWithMessage(
		"openai-images",
		server.URL,
		"sk-images-test",
		"gpt-image-2",
		"/v1/images/generations",
		"bearer",
		"a red apple on a white background",
	)

	if !res.Success {
		t.Fatalf("预期 images 手动测试成功，实际失败: %s", res.Message)
	}
	if receivedPath != "/v1/images/generations" {
		t.Errorf("receivedPath = %q, 期望 /v1/images/generations", receivedPath)
	}
	if receivedAuth != "Bearer sk-images-test" {
		t.Errorf("receivedAuth = %q, 期望 Bearer sk-images-test", receivedAuth)
	}
	if got, _ := receivedBody["model"].(string); got != "gpt-image-2" {
		t.Errorf("请求 model = %q, 期望 gpt-image-2", got)
	}
	if got, _ := receivedBody["prompt"].(string); got != "a red apple on a white background" {
		t.Errorf("请求 prompt = %q, 期望测试消息作为 prompt", got)
	}
	if _, ok := receivedBody["messages"]; ok {
		t.Error("images 探测请求不应携带 chat messages 字段")
	}
	if len(res.RawResult) <= 1<<20 {
		t.Errorf("rawResult 长度 = %d, 期望大于 1MB（生图响应不应被旧上限截断）", len(res.RawResult))
	}
	if !strings.Contains(res.RawResult, bigB64[:64]) {
		t.Error("rawResult 缺少 b64_json 载荷")
	}
}
