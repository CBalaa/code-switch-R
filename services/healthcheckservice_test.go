package services

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHealthCheckEndpointFollowsProviderProtocolEndpoint 回归：
// 界面在 testEndpoint 为空时会自动写入平台默认值（/responses），
// 不能让这个"没配"的替身盖掉供应商真正配置的 responsesEndpoint——
// 否则探活打到的是平台默认路径，跟真实转发完全不是一个地址。
func TestHealthCheckEndpointFollowsProviderProtocolEndpoint(t *testing.T) {
	var hcs HealthCheckService
	cases := []struct {
		name     string
		provider Provider
		platform string
		expected string
	}{
		{
			name: "界面自动填的平台默认值不覆盖 responsesEndpoint",
			provider: Provider{
				ResponsesEndpoint:  "/v1/responses",
				AvailabilityConfig: &AvailabilityConfig{TestEndpoint: "/responses"},
			},
			platform: "openai-responses",
			expected: "/v1/responses",
		},
		{
			name: "界面自动填的平台默认值不覆盖 chatEndpoint",
			provider: Provider{
				ChatEndpoint:       "/v1/chat/completions",
				AvailabilityConfig: &AvailabilityConfig{TestEndpoint: "/chat/completions"},
			},
			platform: "openai-chat",
			expected: "/v1/chat/completions",
		},
		{
			name: "用户显式配置的测试端点仍然优先",
			provider: Provider{
				ResponsesEndpoint:  "/v1/responses",
				AvailabilityConfig: &AvailabilityConfig{TestEndpoint: "/custom/probe"},
			},
			platform: "openai-responses",
			expected: "/custom/probe",
		},
		{
			name: "没有协议端点时维持平台默认值",
			provider: Provider{
				AvailabilityConfig: &AvailabilityConfig{TestEndpoint: "/responses"},
			},
			platform: "openai-responses",
			expected: "/responses",
		},
		{
			name:     "两个字段都为空时回落到平台默认值",
			provider: Provider{},
			platform: "openai-responses",
			expected: "/responses",
		},
		{
			name: "apiEndpoint 同样生效",
			provider: Provider{
				APIEndpoint:        "/custom/openai",
				AvailabilityConfig: &AvailabilityConfig{TestEndpoint: "/responses"},
			},
			platform: "openai-responses",
			expected: "/custom/openai",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hcs.getEffectiveEndpoint(&c.provider, c.platform); got != c.expected {
				t.Errorf("endpoint = %q, 期望 %q", got, c.expected)
			}
		})
	}
}

// TestUpstreamRejectedForBodyTooSmall 只把"长度不足"类 4xx 识别为可重试，其余放行
func TestUpstreamRejectedForBodyTooSmall(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{
			name:   "ISRC 的中文提示",
			status: 400,
			body:   `{"error":{"message":"该令牌不接受输入少于 2000 token 的请求(按请求体大小判定)。This key does not accept requests with fewer than 2000 input tokens (judged by request body size)."}}`,
			want:   true,
		},
		{
			name:   "英文 fewer than",
			status: 400,
			body:   `{"error":{"message":"prompt must contain fewer than check: at least 1000 tokens required"}}`,
			want:   true,
		},
		{
			name:   "request body too small",
			status: 413,
			body:   `{"error":"request body too small"}`,
			want:   true,
		},
		{
			name:   "模型不存在不应该被当成长度问题",
			status: 400,
			body:   `{"error":{"code":"model_not_found","message":"No available channel for model gpt-5.6-sol"}}`,
			want:   false,
		},
		{
			name:   "鉴权失败不算",
			status: 401,
			body:   `{"error":{"message":"Invalid token"}}`,
			want:   false,
		},
		{
			name:   "只有阈值词没有长度概念不算",
			status: 400,
			body:   `{"error":{"message":"minimum concurrency is 1"}}`,
			want:   false,
		},
		{
			name:   "5xx 不算（属于上游抖动，走重试而不是换形态）",
			status: 503,
			body:   `{"error":{"message":"upstream failed, fewer than expected"}}`,
			want:   false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := upstreamRejectedForBodyTooSmall(c.status, c.body); got != c.want {
				t.Errorf("upstreamRejectedForBodyTooSmall(%d, %q) = %v, 期望 %v", c.status, c.body, got, c.want)
			}
		})
	}
}

// TestResponsesChallengeBodyInstructions 参考形态默认不带 instructions；
// 上游嫌请求体太小时才带上 Codex 默认提示词，并且长度足以越过 2000 token 门槛。
func TestResponsesChallengeBodyInstructions(t *testing.T) {
	plain, err := buildResponsesChallengeBody("gpt-5.6-sol", "生成 300 个整数", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "instructions") {
		t.Fatalf("参考形态不应该带 instructions: %s", plain)
	}

	withInstructions, err := buildResponsesChallengeBody("gpt-5.6-sol", "生成 300 个整数", false, true)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(withInstructions, &payload); err != nil {
		t.Fatal(err)
	}
	instructions, _ := payload["instructions"].(string)
	if strings.TrimSpace(instructions) == "" {
		t.Fatal("withInstructions=true 时必须带上 instructions")
	}
	// 按"请求体大小"判定 token 的上游（如 ISRC）要求 2000 token 量级
	if len(withInstructions) < 8000 {
		t.Fatalf("带 instructions 的请求体只有 %d 字节，不足以越过 2000 token 门槛", len(withInstructions))
	}
	if !strings.Contains(instructions, "You are Codex") {
		t.Fatalf("instructions 不是 Codex 默认提示词: %.80s", instructions)
	}

	// 挑战内容本身不受影响
	input, _ := payload["input"].([]interface{})
	if len(input) != 1 {
		t.Fatalf("input 段数 = %d, 期望 1", len(input))
	}
}

// TestChallengeRetriesWithCodexInstructionsWhenBodyTooSmall 端到端回归：
// 上游以"请求体太小"拒绝时，自动带上 Codex 默认 instructions 重发一次。
func TestChallengeRetriesWithCodexInstructionsWhenBodyTooSmall(t *testing.T) {
	var bodies []map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var payload map[string]interface{}
		_ = json.Unmarshal(raw, &payload)
		bodies = append(bodies, payload)

		if instructions, _ := payload["instructions"].(string); strings.TrimSpace(instructions) == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"该令牌不接受输入少于 2000 token 的请求(按请求体大小判定)。This key does not accept requests with fewer than 2000 input tokens (judged by request body size)."}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"completed","output":[{"content":[{"type":"output_text","text":"7 13 42"}]}]}`))
	}))
	defer server.Close()

	mts := NewModelTraceService(nil)
	provider := Provider{APIURL: server.URL, APIKey: "sk-test"}

	text, err := mts.requestChallenge(context.Background(), &provider, "openai-responses", "gpt-5.6-sol", "生成 300 个整数", nil)
	if err != nil {
		t.Fatalf("带上 instructions 重试后应当成功: %v", err)
	}
	if text != "7 13 42" {
		t.Fatalf("回答文本 = %q", text)
	}
	if len(bodies) != 2 {
		t.Fatalf("期望先失败再重试共 2 次请求，实际 %d 次", len(bodies))
	}
	if _, ok := bodies[0]["instructions"]; ok {
		t.Error("首次请求应保持参考实现形态，不应带 instructions")
	}
	if s, _ := bodies[1]["instructions"].(string); !strings.Contains(s, "You are Codex") {
		t.Errorf("重试请求应带 Codex 默认 instructions，实际: %.60s", s)
	}
}

// TestChallengeDoesNotRetryOnUnrelatedBadRequest 与长度无关的 400 不应触发重发
func TestChallengeDoesNotRetryOnUnrelatedBadRequest(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"model_not_found","message":"No available channel for model gpt-5.6-sol"}}`))
	}))
	defer server.Close()

	mts := NewModelTraceService(nil)
	provider := Provider{APIURL: server.URL, APIKey: "sk-test"}

	if _, err := mts.requestChallenge(context.Background(), &provider, "openai-responses", "gpt-5.6-sol", "生成 300 个整数", nil); err == nil {
		t.Fatal("应当返回错误")
	}
	if calls != 1 {
		t.Fatalf("与长度无关的 400 不应重发，实际请求 %d 次", calls)
	}
}
