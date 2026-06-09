package services

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daodao97/xgo/xrequest"
	"github.com/tidwall/gjson"
)

func TestResolveRelayEndpointUsesProtocolSpecificEndpoint(t *testing.T) {
	relay := &ProviderRelayService{}
	provider := Provider{
		APIEndpoint:       "/legacy",
		ResponsesEndpoint: "/v1/responses",
		ChatEndpoint:      "/v1/chat/completions",
	}

	if got := relay.resolveRelayEndpoint("codex", provider, "/responses"); got != "/v1/responses" {
		t.Fatalf("codex responses endpoint = %q, want /v1/responses", got)
	}
	if got := relay.resolveRelayEndpoint("codex", provider, "/v1/chat/completions"); got != "/v1/chat/completions" {
		t.Fatalf("codex chat endpoint = %q, want /v1/chat/completions", got)
	}
}

func TestResolveRelayEndpointUsesResponsesEndpointForClaudeOpenAICompatible(t *testing.T) {
	relay := &ProviderRelayService{}
	provider := Provider{
		APIEndpoint:       "/legacy",
		ResponsesEndpoint: "/v1/responses",
		UpstreamProtocol:  string(UpstreamProtocolOpenAIChat),
	}

	if got := relay.resolveRelayEndpoint("claude", provider, "/v1/messages"); got != "/v1/responses" {
		t.Fatalf("claude openai-compatible endpoint = %q, want /v1/responses", got)
	}
}

// ==================== ReplaceModelInRequestBody 测试 ====================

func TestReplaceModelInRequestBody(t *testing.T) {
	tests := []struct {
		name          string
		inputJSON     string
		newModel      string
		expectError   bool
		expectedModel string
	}{
		// 成功场景
		{
			name: "简单替换",
			inputJSON: `{
				"model": "claude-sonnet-4",
				"messages": [{"role": "user", "content": "Hello"}]
			}`,
			newModel:      "anthropic/claude-sonnet-4",
			expectError:   false,
			expectedModel: "anthropic/claude-sonnet-4",
		},
		{
			name: "复杂嵌套JSON",
			inputJSON: `{
				"model": "claude-opus-4",
				"messages": [
					{
						"role": "user",
						"content": "Test"
					}
				],
				"temperature": 0.7,
				"max_tokens": 1000,
				"metadata": {
					"user_id": "12345"
				}
			}`,
			newModel:      "gpt-4",
			expectError:   false,
			expectedModel: "gpt-4",
		},
		{
			name: "模型名包含特殊字符",
			inputJSON: `{
				"model": "claude-sonnet-4",
				"messages": []
			}`,
			newModel:      "anthropic/claude-3.5-sonnet@20241022",
			expectError:   false,
			expectedModel: "anthropic/claude-3.5-sonnet@20241022",
		},

		// 错误场景
		{
			name: "缺少model字段",
			inputJSON: `{
				"messages": [{"role": "user", "content": "Hello"}]
			}`,
			newModel:    "any-model",
			expectError: true,
		},
		{
			name: "空JSON",
			inputJSON: `{
			}`,
			newModel:    "any-model",
			expectError: true,
		},
		{
			name:        "无效JSON",
			inputJSON:   `{invalid json}`,
			newModel:    "any-model",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes := []byte(tt.inputJSON)
			result, err := ReplaceModelInRequestBody(bodyBytes, tt.newModel)

			// 检查错误预期
			if tt.expectError && err == nil {
				t.Errorf("期望返回错误，但没有错误")
			}
			if !tt.expectError && err != nil {
				t.Errorf("不期望错误，但返回了: %v", err)
			}

			// 如果不期望错误，验证结果
			if !tt.expectError {
				// 验证返回的JSON是否有效
				if !json.Valid(result) {
					t.Errorf("返回的JSON无效")
				}

				// 验证模型名是否正确替换
				actualModel := gjson.GetBytes(result, "model").String()
				if actualModel != tt.expectedModel {
					t.Errorf("替换后的模型名 = %q, 期望 %q", actualModel, tt.expectedModel)
				}

				// 验证其他字段未被修改
				if gjson.GetBytes(bodyBytes, "messages").Exists() {
					originalMessages := gjson.GetBytes(bodyBytes, "messages").Raw
					resultMessages := gjson.GetBytes(result, "messages").Raw
					if originalMessages != resultMessages {
						t.Errorf("messages 字段被意外修改")
					}
				}
			}
		})
	}
}

type streamingRecorder struct {
	header  http.Header
	mu      sync.Mutex
	body    strings.Builder
	status  int
	wroteCh chan struct{}
	flushCh chan struct{}
}

func newStreamingRecorder() *streamingRecorder {
	return &streamingRecorder{
		header:  make(http.Header),
		wroteCh: make(chan struct{}, 1),
		flushCh: make(chan struct{}, 1),
	}
}

func (r *streamingRecorder) Header() http.Header {
	return r.header
}

func (r *streamingRecorder) Write(data []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, err := r.body.Write(data)
	select {
	case r.wroteCh <- struct{}{}:
	default:
	}
	return n, err
}

func (r *streamingRecorder) WriteHeader(statusCode int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = statusCode
}

func (r *streamingRecorder) Flush() {
	select {
	case r.flushCh <- struct{}{}:
	default:
	}
}

func (r *streamingRecorder) BodyString() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body.String()
}

func TestWriteStreamingResponseFlushesFirstLineImmediately(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()

	resp := xrequest.NewResponse(&http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"text/event-stream"},
		},
		Body: pr,
	})

	recorder := newStreamingRecorder()
	requestLog := &ReqeustLog{startedAt: time.Now()}
	done := make(chan error, 1)
	go func() {
		_, err := writeStreamingResponse(recorder, resp, requestLog)
		done <- err
	}()

	if _, err := pw.Write([]byte("data: {\"type\":\"message_start\"}\n")); err != nil {
		t.Fatalf("write first SSE line: %v", err)
	}

	select {
	case <-recorder.wroteCh:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("first SSE line was not written promptly")
	}

	if got := recorder.BodyString(); !strings.Contains(got, "message_start") {
		t.Fatalf("expected first line in response body, got %q", got)
	}

	if recorder.header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("expected X-Accel-Buffering=no, got %q", recorder.header.Get("X-Accel-Buffering"))
	}
	if requestLog.FirstEventSec <= 0 {
		t.Fatalf("expected FirstEventSec to be recorded")
	}

	if err := pw.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("writeStreamingResponse returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("writeStreamingResponse did not return after upstream EOF")
	}
}

func TestWriteCodexGuardedStreamingResponseRejectsEmptyStreamAfterKeepAlive(t *testing.T) {
	resp := xrequest.NewResponse(&http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"text/event-stream"},
		},
		Body: io.NopCloser(strings.NewReader("data: {\"type\":\"response.created\"}\n\n")),
	})

	recorder := newStreamingRecorder()
	requestLog := &ReqeustLog{startedAt: time.Now()}
	written, responseWritten, err := writeCodexGuardedStreamingResponse(recorder, resp, requestLog)
	if !errors.Is(err, errCodexEmptyStream) {
		t.Fatalf("err = %v, want errCodexEmptyStream", err)
	}
	if !responseWritten {
		t.Fatalf("responseWritten = false, want true for keepalive")
	}
	if written != 0 {
		t.Fatalf("written = %d, want 0", written)
	}
	if body := recorder.BodyString(); body != codexStreamGuardKeepAliveComment {
		t.Fatalf("body = %q, want keepalive only", body)
	}
	if recorder.status != http.StatusOK {
		t.Fatalf("status = %d, want 200 for keepalive", recorder.status)
	}
}

func TestWriteCodexGuardedStreamingResponseReleasesOnUsefulContent(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()

	resp := xrequest.NewResponse(&http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"text/event-stream"},
		},
		Body: pr,
	})

	recorder := newStreamingRecorder()
	requestLog := &ReqeustLog{startedAt: time.Now()}
	done := make(chan error, 1)
	go func() {
		_, responseWritten, err := writeCodexGuardedStreamingResponse(recorder, resp, requestLog)
		if err == nil && !responseWritten {
			err = errors.New("guard returned without writing response")
		}
		done <- err
	}()

	select {
	case <-recorder.wroteCh:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("guard did not write initial keepalive")
	}
	if body := recorder.BodyString(); body != codexStreamGuardKeepAliveComment {
		t.Fatalf("body = %q, want initial keepalive only", body)
	}

	if _, err := pw.Write([]byte("data: {\"type\":\"response.created\"}\n\n")); err != nil {
		t.Fatalf("write created event: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	if body := recorder.BodyString(); strings.Contains(body, "response.created") {
		t.Fatalf("guard leaked buffered event before useful content, body=%q", body)
	}

	if _, err := pw.Write([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hello\"}\n\n")); err != nil {
		t.Fatalf("write text delta: %v", err)
	}

	select {
	case <-recorder.wroteCh:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("guard did not release on useful content")
	}

	if err := pw.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("writeCodexGuardedStreamingResponse returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("writeCodexGuardedStreamingResponse did not return after EOF")
	}

	body := recorder.BodyString()
	if !strings.Contains(body, "response.created") || !strings.Contains(body, "Hello") {
		t.Fatalf("guard did not replay buffered events, body=%q", body)
	}
	if requestLog.FirstEventSec <= 0 {
		t.Fatalf("expected FirstEventSec to be recorded")
	}
}

func TestCodexProviderEnabledRequiredOnlyInManagedProxyMode(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	relay := NewProviderRelayService(NewProviderService(), nil, nil, nil, nil, nil, DefaultRelayBindAddr)
	if relay.shouldRequireProviderEnabled("claude") != true {
		t.Fatalf("claude should always require provider enabled")
	}
	if relay.shouldRequireProviderEnabled("codex") != false {
		t.Fatalf("codex should ignore provider enabled when managed proxy is disabled")
	}

	codexDir := filepath.Join(testHome, codexSettingsDir)
	if err := os.MkdirAll(codexDir, 0o700); err != nil {
		t.Fatalf("create codex dir: %v", err)
	}
	config := `model_provider = "code-switch-r"

[model_providers.code-switch-r]
name = "code-switch-r"
base_url = "http://127.0.0.1:18100"
wire_api = "responses"
`
	if err := os.WriteFile(filepath.Join(codexDir, codexConfigFileName), []byte(config), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}
	if relay.shouldRequireProviderEnabled("codex") != true {
		t.Fatalf("codex should require provider enabled when managed proxy is enabled")
	}
}

func TestSelectCodexEmptyStreamRetryProviderDoesNotFallbackToOtherProvider(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	configDir := filepath.Join(testHome, ".code-switch")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	payload, err := json.Marshal(providerEnvelope{Providers: []Provider{
		{
			ID:      1,
			Name:    "other-provider",
			APIURL:  "https://other.example.com",
			APIKey:  "other-key",
			Enabled: true,
		},
	}})
	if err != nil {
		t.Fatalf("marshal providers: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "codex.json"), payload, 0o600); err != nil {
		t.Fatalf("write providers: %v", err)
	}

	relay := NewProviderRelayService(NewProviderService(), nil, nil, nil, nil, nil, DefaultRelayBindAddr)
	provider, ok, err := relay.selectCodexEmptyStreamRetryProvider("codex", "current-provider", "gpt-5.5")
	if err != nil {
		t.Fatalf("select retry provider returned error: %v", err)
	}
	if ok {
		t.Fatalf("expected no fallback provider, got %#v", provider)
	}
}

func TestCodexDirectAppliedProviderIDDetectedInManualMode(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	configDir := filepath.Join(testHome, ".code-switch")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	payload, err := json.Marshal(providerEnvelope{Providers: []Provider{
		{
			ID:      1,
			Name:    "superapi",
			APIURL:  "https://superapi.example.com",
			APIKey:  "super-key",
			Enabled: false,
		},
		{
			ID:      2,
			Name:    "wecoding",
			APIURL:  "https://yuzapi.fun",
			APIKey:  "wecoding-key",
			Enabled: true,
		},
	}})
	if err != nil {
		t.Fatalf("marshal providers: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "codex.json"), payload, 0o600); err != nil {
		t.Fatalf("write providers: %v", err)
	}

	codexDir := filepath.Join(testHome, codexSettingsDir)
	if err := os.MkdirAll(codexDir, 0o700); err != nil {
		t.Fatalf("create codex dir: %v", err)
	}
	config := `model_provider = "wecoding"
preferred_auth_method = "apikey"

[model_providers.wecoding]
name = "wecoding"
base_url = "https://yuzapi.fun"
wire_api = "responses"
`
	if err := os.WriteFile(filepath.Join(codexDir, codexConfigFileName), []byte(config), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}
	auth := []byte(`{"OPENAI_API_KEY":"wecoding-key"}`)
	if err := os.WriteFile(filepath.Join(codexDir, codexAuthFileName), auth, 0o600); err != nil {
		t.Fatalf("write codex auth: %v", err)
	}

	relay := NewProviderRelayService(NewProviderService(), nil, nil, nil, nil, nil, DefaultRelayBindAddr)
	id, required := relay.codexDirectAppliedProviderFilter("codex", false)
	if !required {
		t.Fatalf("manual mode should require direct applied provider")
	}
	if id == nil || *id != 2 {
		t.Fatalf("direct applied provider id = %v, want 2", id)
	}

	id, required = relay.codexDirectAppliedProviderFilter("codex", true)
	if required {
		t.Fatalf("managed mode should not require direct applied provider")
	}
	if id != nil {
		t.Fatalf("managed mode should not use direct applied provider id, got %v", *id)
	}
}

func TestCodexDirectAppliedProviderRequiredInManualMode(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	relay := NewProviderRelayService(NewProviderService(), nil, nil, nil, nil, nil, DefaultRelayBindAddr)
	id, required := relay.codexDirectAppliedProviderFilter("codex", false)
	if !required {
		t.Fatalf("manual mode should require direct applied provider")
	}
	if id != nil {
		t.Fatalf("manual mode without direct apply should not select a provider, got %v", *id)
	}
}

func TestMarkFirstTextFromSSEPayload(t *testing.T) {
	requestLog := &ReqeustLog{startedAt: time.Now()}
	payload := `event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"你"}}`

	markFirstTextFromSSEPayload(payload, requestLog)

	if requestLog.FirstTextSec <= 0 {
		t.Fatalf("expected FirstTextSec to be recorded")
	}
}

// ==================== 端到端场景测试 ====================

func TestModelMappingEndToEnd(t *testing.T) {
	// 模拟真实场景：用户请求 claude-sonnet-4，需要映射到 OpenRouter 的格式
	provider := Provider{
		Name: "OpenRouter",
		SupportedModels: map[string]bool{
			"anthropic/claude-sonnet-4":   true,
			"anthropic/claude-opus-4":     true,
			"openai/gpt-4":                true,
			"google/gemini-pro":           true,
			"meta-llama/llama-3.1-405b":   true,
			"anthropic/claude-3.5-sonnet": true,
			"anthropic/claude-3.5-haiku":  true,
		},
		ModelMapping: map[string]string{
			"claude-*": "anthropic/claude-*",
			"gpt-*":    "openai/gpt-*",
			"gemini-*": "google/gemini-*",
			"llama-*":  "meta-llama/llama-*",
		},
	}

	scenarios := []struct {
		requestedModel string
		shouldSupport  bool
		effectiveModel string
	}{
		// 通配符映射场景
		{"claude-sonnet-4", true, "anthropic/claude-sonnet-4"},
		{"claude-opus-4", true, "anthropic/claude-opus-4"},
		{"claude-3.5-sonnet", true, "anthropic/claude-3.5-sonnet"},
		{"gpt-4", true, "openai/gpt-4"},
		{"gpt-4-turbo", true, "openai/gpt-4-turbo"},
		{"gemini-pro", true, "google/gemini-pro"},
		{"llama-3.1-405b", true, "meta-llama/llama-3.1-405b"},

		// 不支持的模型
		{"deepseek-v3", false, "deepseek-v3"},
		{"qwen-max", false, "qwen-max"},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.requestedModel, func(t *testing.T) {
			// 1. 检查是否支持
			supported := provider.IsModelSupported(scenario.requestedModel)
			if supported != scenario.shouldSupport {
				t.Errorf("IsModelSupported(%q) = %v, 期望 %v",
					scenario.requestedModel, supported, scenario.shouldSupport)
			}

			// 2. 获取有效模型名
			effectiveModel := provider.GetEffectiveModel(scenario.requestedModel)
			if effectiveModel != scenario.effectiveModel {
				t.Errorf("GetEffectiveModel(%q) = %q, 期望 %q",
					scenario.requestedModel, effectiveModel, scenario.effectiveModel)
			}

			// 3. 如果支持，测试请求体替换
			if scenario.shouldSupport {
				requestBody := `{"model": "` + scenario.requestedModel + `", "messages": []}`
				result, err := ReplaceModelInRequestBody([]byte(requestBody), effectiveModel)
				if err != nil {
					t.Fatalf("ReplaceModelInRequestBody 失败: %v", err)
				}

				actualModel := gjson.GetBytes(result, "model").String()
				if actualModel != scenario.effectiveModel {
					t.Errorf("请求体中的模型 = %q, 期望 %q", actualModel, scenario.effectiveModel)
				}
			}
		})
	}
}

// ==================== 配置验证集成测试 ====================

func TestProviderConfigValidation(t *testing.T) {
	// 场景 1：完美配置
	validProvider := Provider{
		Name: "ValidProvider",
		SupportedModels: map[string]bool{
			"anthropic/claude-sonnet-4": true,
			"anthropic/claude-opus-4":   true,
		},
		ModelMapping: map[string]string{
			"claude-sonnet-4": "anthropic/claude-sonnet-4",
			"claude-opus-4":   "anthropic/claude-opus-4",
		},
	}

	errors := validProvider.ValidateConfiguration()
	if len(errors) != 0 {
		t.Errorf("完美配置不应有错误，但返回了: %v", errors)
	}

	// 场景 2：错误配置 - 映射目标不存在
	invalidProvider := Provider{
		Name: "InvalidProvider",
		SupportedModels: map[string]bool{
			"model-a": true,
		},
		ModelMapping: map[string]string{
			"external": "non-existent-model",
		},
	}

	errors = invalidProvider.ValidateConfiguration()
	if len(errors) == 0 {
		t.Errorf("错误配置应该返回验证错误")
	}

	// 场景 3：通配符配置
	wildcardProvider := Provider{
		Name: "WildcardProvider",
		SupportedModels: map[string]bool{
			"anthropic/claude-*": true,
			"openai/gpt-*":       true,
		},
		ModelMapping: map[string]string{
			"claude-*": "anthropic/claude-*",
			"gpt-*":    "openai/gpt-*",
		},
	}

	errors = wildcardProvider.ValidateConfiguration()
	if len(errors) != 0 {
		t.Errorf("通配符配置不应有错误，但返回了: %v", errors)
	}
}

func TestClaudeCodeParseTokenUsageFromResponse(t *testing.T) {
	var usage ReqeustLog

	ClaudeCodeParseTokenUsageFromResponse(`{
		"usage": {
			"input_tokens": 10,
			"output_tokens": 6,
			"cache_creation_input_tokens": 2,
			"input_tokens_details": {"cached_tokens": 3},
			"output_tokens_details": {"reasoning_tokens": 4}
		}
	}`, &usage)

	if usage.InputTokens != 10 {
		t.Fatalf("InputTokens = %d, want 10", usage.InputTokens)
	}
	if usage.OutputTokens != 6 {
		t.Fatalf("OutputTokens = %d, want 6", usage.OutputTokens)
	}
	if usage.CacheCreateTokens != 2 {
		t.Fatalf("CacheCreateTokens = %d, want 2", usage.CacheCreateTokens)
	}
	if usage.CacheReadTokens != 3 {
		t.Fatalf("CacheReadTokens = %d, want 3", usage.CacheReadTokens)
	}
	if usage.ReasoningTokens != 4 {
		t.Fatalf("ReasoningTokens = %d, want 4", usage.ReasoningTokens)
	}
}

func TestDeleteHeaderCaseInsensitive(t *testing.T) {
	headers := map[string]string{
		"Authorization":     "Bearer upstream-key",
		"X-Api-Key":         "code-switch-r",
		"Anthropic-Version": "2023-06-01",
		"anthropic-beta":    "tools-2024-04-04",
		"Content-Type":      "application/json",
	}

	deleteHeaderCaseInsensitive(headers, "x-api-key")
	deleteHeaderCaseInsensitive(headers, "anthropic-version")
	deleteHeaderCaseInsensitive(headers, "anthropic-beta")

	if _, ok := headers["X-Api-Key"]; ok {
		t.Fatalf("expected X-Api-Key to be removed")
	}
	if _, ok := headers["Anthropic-Version"]; ok {
		t.Fatalf("expected Anthropic-Version to be removed")
	}
	if _, ok := headers["anthropic-beta"]; ok {
		t.Fatalf("expected anthropic-beta to be removed")
	}
	if headers["Authorization"] != "Bearer upstream-key" {
		t.Fatalf("expected Authorization to be preserved")
	}
	if headers["Content-Type"] != "application/json" {
		t.Fatalf("expected Content-Type to be preserved")
	}
}

func TestRemoveInboundAuthHeaders(t *testing.T) {
	headers := map[string]string{
		"Authorization":        "Bearer relay-key",
		"X-Api-Key":            "relay-key",
		"X-Code-Switch-Key":    "relay-key",
		"Anthropic-Version":    "2023-06-01",
		"Content-Type":         "application/json",
		"X-Provider-Trace-Tag": "keep",
	}

	removeInboundAuthHeaders(headers)

	for _, key := range []string{"Authorization", "X-Api-Key", "X-Code-Switch-Key"} {
		if _, ok := headers[key]; ok {
			t.Fatalf("expected %s to be removed", key)
		}
	}
	if headers["Anthropic-Version"] != "2023-06-01" {
		t.Fatalf("expected Anthropic-Version to be preserved")
	}
	if headers["Content-Type"] != "application/json" {
		t.Fatalf("expected Content-Type to be preserved")
	}
	if headers["X-Provider-Trace-Tag"] != "keep" {
		t.Fatalf("expected unrelated headers to be preserved")
	}
}

// ==================== 性能测试 ====================

func BenchmarkIsModelSupported(b *testing.B) {
	provider := Provider{
		SupportedModels: map[string]bool{
			"claude-sonnet-4": true,
			"claude-opus-4":   true,
			"gpt-4":           true,
			"gpt-4-turbo":     true,
		},
		ModelMapping: map[string]string{
			"claude-*": "anthropic/claude-*",
			"gpt-*":    "openai/gpt-*",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = provider.IsModelSupported("claude-sonnet-4")
	}
}

func BenchmarkGetEffectiveModel(b *testing.B) {
	provider := Provider{
		ModelMapping: map[string]string{
			"claude-*": "anthropic/claude-*",
			"gpt-*":    "openai/gpt-*",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = provider.GetEffectiveModel("claude-sonnet-4")
	}
}

func BenchmarkReplaceModelInRequestBody(b *testing.B) {
	bodyBytes := []byte(`{
		"model": "claude-sonnet-4",
		"messages": [{"role": "user", "content": "Hello"}],
		"temperature": 0.7,
		"max_tokens": 1000
	}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ReplaceModelInRequestBody(bodyBytes, "anthropic/claude-sonnet-4")
	}
}
