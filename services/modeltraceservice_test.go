package services

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"codeswitch/services/modeltrace"
)

func TestExtractCompletionTextAnthropic(t *testing.T) {
	body, _ := json.Marshal(map[string]interface{}{
		"content": []map[string]string{
			{"type": "text", "text": "12 34 56"},
		},
		"stop_reason": "end_turn",
	})
	text, err := extractCompletionText(body, true)
	if err != nil || text != "12 34 56" {
		t.Fatalf("text=%q err=%v", text, err)
	}

	// max_tokens 截断 -> 丢弃
	body, _ = json.Marshal(map[string]interface{}{
		"content":     []map[string]string{{"type": "text", "text": "12"}},
		"stop_reason": "max_tokens",
	})
	if _, err := extractCompletionText(body, true); err == nil {
		t.Fatal("max_tokens 截断未被拒绝")
	}

	// 拒答 -> 丢弃
	body, _ = json.Marshal(map[string]interface{}{
		"content":     []map[string]string{{"type": "text", "text": "no"}},
		"stop_reason": "refusal",
	})
	if _, err := extractCompletionText(body, true); err == nil {
		t.Fatal("refusal 未被拒绝")
	}
}

func TestExtractCompletionTextOpenAI(t *testing.T) {
	body, _ := json.Marshal(map[string]interface{}{
		"choices": []map[string]interface{}{
			{
				"message":       map[string]interface{}{"content": "78 90"},
				"finish_reason": "stop",
			},
		},
	})
	text, err := extractCompletionText(body, false)
	if err != nil || text != "78 90" {
		t.Fatalf("text=%q err=%v", text, err)
	}

	// content 为分段数组
	body, _ = json.Marshal(map[string]interface{}{
		"choices": []map[string]interface{}{
			{
				"message": map[string]interface{}{
					"content": []map[string]string{{"type": "text", "text": "11 22"}, {"type": "text", "text": " 33"}},
				},
				"finish_reason": "stop",
			},
		},
	})
	text, err = extractCompletionText(body, false)
	if err != nil || text != "11 22 33" {
		t.Fatalf("segmented text=%q err=%v", text, err)
	}

	// length 截断 -> 丢弃
	body, _ = json.Marshal(map[string]interface{}{
		"choices": []map[string]interface{}{
			{
				"message":       map[string]interface{}{"content": "x"},
				"finish_reason": "length",
			},
		},
	})
	if _, err := extractCompletionText(body, false); err == nil {
		t.Fatal("length 截断未被拒绝")
	}
}

func TestExtractResponsesText(t *testing.T) {
	// 正常 Responses 形态
	body, _ := json.Marshal(map[string]interface{}{
		"status": "completed",
		"output": []map[string]interface{}{
			{
				"content": []map[string]string{
					{"type": "output_text", "text": "5 8 13"},
				},
			},
		},
	})
	text, err := extractResponsesText(body)
	if err != nil || text != "5 8 13" {
		t.Fatalf("text=%q err=%v", text, err)
	}

	// 截断（max_output_tokens）-> 丢弃
	body, _ = json.Marshal(map[string]interface{}{
		"status":             "incomplete",
		"incomplete_details": map[string]string{"reason": "max_output_tokens"},
		"output": []map[string]interface{}{
			{"content": []map[string]string{{"type": "output_text", "text": "5 8"}}},
		},
	})
	if _, err := extractResponsesText(body); err == nil {
		t.Fatal("incomplete 响应未被拒绝")
	}
}

func TestVerifyProviderModelMappingOutOfBank(t *testing.T) {
	// 模型映射目标不在指纹库内 -> 应报 error 而非 mismatch
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	ps := NewProviderService()
	if err := ps.SaveProviders("claude", []Provider{
		{
			ID:             7,
			Name:           "mapper",
			APIURL:         "https://example.com",
			MaxConcurrency: 1,
			ModelMapping:   map[string]string{"gpt-5.4": "gpt-4o-mini"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	svc := NewModelTraceService(ps)
	result := svc.VerifyProviderModel("", "claude", 7, "gpt-5.4")
	if result.Verdict != "error" {
		t.Errorf("映射目标不在库内应报 error, got %v (msg=%s)", result.Verdict, result.Message)
	}
}

func TestVerifyProviderModelRejectsModelOutsideProviderWhitelist(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ps := NewProviderService()
	if err := ps.SaveProviders("openai-chat", []Provider{
		{
			ID: 21, Name: "whitelist-only", APIURL: "http://127.0.0.1:1", APIKey: "test-key",
			MaxConcurrency:  1,
			SupportedModels: map[string]bool{"gpt-6-sol": true},
		},
	}); err != nil {
		t.Fatal(err)
	}

	result := NewModelTraceService(ps).VerifyProviderModel("", "openai-chat", 21, "gpt-6-astra")
	if result.Verdict != "error" {
		t.Fatalf("白名单外模型应在发起请求前报错，got verdict=%s message=%s", result.Verdict, result.Message)
	}
	if result.ExpectedModel != "gpt-6-astra" {
		t.Fatalf("错误结果应保留待检测模型，got %q", result.ExpectedModel)
	}
	if !strings.Contains(result.Message, "不在模型白名单") {
		t.Fatalf("错误信息应说明模型未配置，got %q", result.Message)
	}
}

func TestVerifyProviderModelSendsMappedUpstreamModel(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ps := NewProviderService()
	if err := ps.SaveProviders("openai-chat", []Provider{
		{
			ID: 22, Name: "mapped-provider", APIURL: "https://upstream.example", APIKey: "test-key",
			MaxConcurrency:  1,
			SupportedModels: map[string]bool{"gpt-6-astra": true},
			ModelMapping:    map[string]string{"gpt-6-sol": "gpt-6-astra"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	var requestedModels []string
	svc := NewModelTraceService(ps)
	svc.client = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		var payload struct {
			Model string `json:"model"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, err
		}
		requestedModels = append(requestedModels, payload.Model)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"choices":[{"message":{"content":"1 2"},"finish_reason":"stop"}]}`)),
			Request:    req,
		}, nil
	})}

	result := svc.VerifyProviderModel("", "openai-chat", 22, "gpt-6-sol")
	if result.ExpectedModel != "gpt-6-sol" {
		t.Fatalf("结果应保留外部模型名，got %q", result.ExpectedModel)
	}
	if len(requestedModels) == 0 {
		t.Fatal("模型映射测试没有发起上游请求")
	}
	for _, model := range requestedModels {
		if model != "gpt-6-astra" {
			t.Fatalf("上游请求模型应为映射目标 gpt-6-astra，got %q", model)
		}
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestResolveChallengeEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		provider Provider
		platform string
		expected string
	}{
		{
			name:     "claude默认anthropic",
			provider: Provider{},
			platform: "claude",
			expected: "/v1/messages",
		},
		{
			name:     "openai-responses默认",
			provider: Provider{},
			platform: "openai-responses",
			expected: "/responses",
		},
		{
			name:     "openai-chat默认",
			provider: Provider{},
			platform: "openai-chat",
			expected: "/chat/completions",
		},
		{
			name:     "claude自定义端点优先",
			provider: Provider{APIEndpoint: "/v1/chat/completions"},
			platform: "claude",
			expected: "/v1/chat/completions",
		},
		{
			name:     "连通性测试端点最优先",
			provider: Provider{ConnectivityTestEndpoint: "/v1/chat/completions"},
			platform: "claude",
			expected: "/v1/chat/completions",
		},
		{
			// 回归：配了 responsesEndpoint 时必须用它，否则会打到平台默认的
			// /responses（不少网关该路径返回门户 HTML 且状态码 200）
			name:     "openai-responses 尊重 responsesEndpoint",
			provider: Provider{ResponsesEndpoint: "/v1/responses"},
			platform: "openai-responses",
			expected: "/v1/responses",
		},
		{
			name:     "openai-chat 尊重 chatEndpoint",
			provider: Provider{ChatEndpoint: "/v1/chat/completions"},
			platform: "openai-chat",
			expected: "/v1/chat/completions",
		},
		{
			name:     "responsesEndpoint 优先于 apiEndpoint",
			provider: Provider{APIEndpoint: "/v1/chat/completions", ResponsesEndpoint: "/v1/responses"},
			platform: "openai-responses",
			expected: "/v1/responses",
		},
		{
			name:     "未配协议端点时回落到 apiEndpoint",
			provider: Provider{APIEndpoint: "/custom/openai"},
			platform: "openai-responses",
			expected: "/custom/openai",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := resolveConnectivityEndpoint(&c.provider, c.platform)
			if got != c.expected {
				t.Errorf("endpoint = %s, 期望 %s", got, c.expected)
			}
		})
	}
}

// TestChallengeProtocolSelection 挑战报文形态：平台即协议，平台未知时按端点兜底
func TestChallengeProtocolSelection(t *testing.T) {
	cases := []struct {
		platform string
		endpoint string
		protocol string
	}{
		{"claude", "/v1/messages", "anthropic"},
		{"openai-responses", "/responses", "responses"},
		{"openai-chat", "/chat/completions", "chat"},
		{"custom:mytool", "/v1/messages", "anthropic"},
		{"custom:mytool", "/v1/responses", "responses"},
		{"custom:mytool", "/v1/chat/completions", "chat"},
		{"", "/v1/messages", "anthropic"},
	}
	for _, c := range cases {
		if got := challengeProtocol(c.platform, c.endpoint); got != c.protocol {
			t.Errorf("challengeProtocol(%q, %q) = %q, 期望 %q", c.platform, c.endpoint, got, c.protocol)
		}
	}
}

func TestCompletionAuthHeader(t *testing.T) {
	cases := []struct {
		authType string
		name     string
		value    string
	}{
		{"bearer", "Authorization", "Bearer sk-1"},
		{"", "Authorization", "Bearer sk-1"},
		{"x-api-key", "x-api-key", "sk-1"},
		{"custom", "Authorization", "sk-1"}, // custom 语义与连通性测试一致：无 Bearer 前缀
		{"X-Custom-Key", "X-Custom-Key", "sk-1"},
	}
	for _, c := range cases {
		name, value := completionAuthHeader(c.authType, "sk-1")
		if name != c.name || value != c.value {
			t.Errorf("authType=%q -> (%q, %q), 期望 (%q, %q)", c.authType, name, value, c.name, c.value)
		}
	}
}

func TestModelTraceVerifyValidation(t *testing.T) {
	svc := NewModelTraceService(NewProviderService())

	// 空模型
	if r := svc.VerifyProviderModel("", "claude", 1, ""); r.Verdict != "error" {
		t.Errorf("空模型应报错, got %v", r.Verdict)
	}
	// 指纹库外模型
	if r := svc.VerifyProviderModel("", "claude", 1, "gpt-4o"); r.Verdict != "error" {
		t.Errorf("库外模型应报错, got %v", r.Verdict)
	}
	// 指纹库内模型 + 不存在的 provider
	if r := svc.VerifyProviderModel("", "claude", 99999, "gpt-5.4"); r.Verdict != "error" {
		t.Errorf("不存在的 provider 应报错, got %v", r.Verdict)
	}
	// 归一化：vendor 前缀与日期后缀都应被接受，最终走到"未找到供应商"而不是"不在覆盖范围"
	for _, model := range []string{"openai/gpt-5.4", "gpt-5.4-2026-01-31", "GPT-5.4", "openai/gpt-6-sol", "claude-haiku-4-5"} {
		r := svc.VerifyProviderModel("", "claude", 99999, model)
		if strings.Contains(r.Message, "不在指纹库覆盖范围内") {
			t.Errorf("%s 应能归一化到指纹库模型, got %v (%s)", model, r.Verdict, r.Message)
		}
	}
	// 不同型号不能被糊到同一个模型上：gpt-5.4-mini 不是 gpt-5.4
	r := svc.VerifyProviderModel("", "claude", 99999, "gpt-5.4-mini")
	if !strings.Contains(r.Message, "不在指纹库覆盖范围内") {
		t.Errorf("gpt-5.4-mini 不应被当成 gpt-5.4, got %v (%s)", r.Verdict, r.Message)
	}
	r = svc.VerifyProviderModel("", "claude", 99999, "gpt-6-terra")
	if !strings.Contains(r.Message, "不在指纹库覆盖范围内") {
		t.Errorf("gpt-6-terra 尚无上游指纹，不应被当成其他 gpt-6 型号, got %v (%s)", r.Verdict, r.Message)
	}
}

// TestModelTraceCrossTenantIsolation provider 必须按 userID 隔离：
// 别的租户的 providerID 一律"未找到"，不会拿别人的 key 发挑战。
func TestModelTraceCrossTenantIsolation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ps := NewProviderService()
	if err := ps.SaveProvidersForUser("user-a", "claude", []Provider{
		{ID: 11, Name: "owner-a", APIURL: "https://example.com", MaxConcurrency: 1},
	}); err != nil {
		t.Fatal(err)
	}
	svc := NewModelTraceService(ps)

	own, err := svc.loadProviders("user-a", "claude")
	if err != nil {
		t.Fatalf("读取 user-a provider 失败: %v", err)
	}
	if len(own) != 1 || own[0].ID != 11 {
		t.Fatalf("user-a 应看到自己的 1 个 provider, got %+v", own)
	}
	other, err := svc.loadProviders("user-b", "claude")
	if err != nil {
		t.Fatalf("读取 user-b provider 失败: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("user-b 不应看到 user-a 的 provider, got %+v", other)
	}

	// 跨租户调用必须在发起任何网络请求之前就失败
	result := svc.VerifyProviderModel("user-b", "claude", 11, "gpt-5.4")
	if result.Verdict != "error" || !strings.Contains(result.Message, "未找到指定供应商") {
		t.Fatalf("跨租户应报未找到供应商, got verdict=%s msg=%s", result.Verdict, result.Message)
	}
}

func TestModelTraceSupportedModels(t *testing.T) {
	svc := NewModelTraceService(NewProviderService())
	models, err := svc.GetSupportedModels()
	if err != nil {
		t.Fatalf("GetSupportedModels 失败: %v", err)
	}
	if len(models) != 16 {
		t.Fatalf("模型数 = %d, 期望 16", len(models))
	}
	ids := make(map[string]bool, len(models))
	for _, model := range models {
		ids[model.ID] = true
	}
	for _, id := range []string{"gpt-6-sol", "gpt-6-luna", "claude-opus-5-5"} {
		if !ids[id] {
			t.Errorf("模型列表缺少 %s", id)
		}
	}
	if ids["gpt-6-terra"] {
		t.Error("上游指纹库没有 gpt-6-terra，模型列表不应展示")
	}
}

// 确认 modeltrace 包的 challenge 生成满足解析阈值
func TestChallengeOutputSelfConsistency(t *testing.T) {
	challenge := modeltrace.GenerateChallenges(1)[0]
	if challenge.ExpectedCount < 292 {
		t.Fatalf("expected_count = %d", challenge.ExpectedCount)
	}
	minimum := challenge.ExpectedCount * 55 / 100
	if minimum < modeltrace.MinimumValidNumbers {
		minimum = modeltrace.MinimumValidNumbers
	}
	if minimum < 80 {
		t.Errorf("minimum = %d", minimum)
	}
}

func TestExtractStreamDelta(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		wantText string
		wantStop string
		wantErr  bool
	}{
		{
			name:     "OpenAI Responses output_text.delta (string delta)",
			payload:  `{"type":"response.output_text.delta","item_id":"msg_1","delta":"42, 108, "}`,
			wantText: "42, 108, ",
		},
		{
			name:     "OpenAI Responses reasoning_summary_text.delta",
			payload:  `{"type":"response.reasoning_summary_text.delta","delta":"thinking about numbers"}`,
			wantText: "thinking about numbers",
		},
		{
			name:     "OpenAI Responses completed",
			payload:  `{"type":"response.completed","response":{"id":"resp_1"}}`,
			wantStop: "stop",
		},
		{
			name:     "OpenAI Responses incomplete",
			payload:  `{"type":"response.incomplete","response":{"incomplete_details":{"reason":"max_tokens"}}}`,
			wantStop: "max_tokens",
		},
		{
			name:     "Anthropic content_block_delta text_delta",
			payload:  `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"123, 456"}}`,
			wantText: "123, 456",
		},
		{
			name:     "Anthropic content_block_delta thinking_delta",
			payload:  `{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"generating..."}}`,
			wantText: "generating...",
		},
		{
			name:     "Anthropic message_delta with delta.stop_reason",
			payload:  `{"type":"message_delta","delta":{"stop_reason":"end_turn"}}`,
			wantStop: "end_turn",
		},
		{
			name:     "OpenAI Chat content chunk",
			payload:  `{"choices":[{"index":0,"delta":{"content":"789, "}}]}`,
			wantText: "789, ",
		},
		{
			name:     "OpenAI Chat reasoning_content chunk",
			payload:  `{"choices":[{"index":0,"delta":{"reasoning_content":"reasoning step"}}]}`,
			wantText: "reasoning step",
		},
		{
			name:     "OpenAI Chat finish_reason",
			payload:  `{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
			wantStop: "stop",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, stop, err := extractStreamDelta(tt.payload)
			if (err != nil) != tt.wantErr {
				t.Fatalf("extractStreamDelta() error = %v, wantErr %v", err, tt.wantErr)
			}
			if text != tt.wantText {
				t.Errorf("extractStreamDelta() text = %q, want %q", text, tt.wantText)
			}
			if stop != tt.wantStop {
				t.Errorf("extractStreamDelta() stop = %q, want %q", stop, tt.wantStop)
			}
		})
	}
}
