package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daodao97/xgo/xdb"
	"github.com/daodao97/xgo/xrequest"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

func TestStreamingLineDoesNotWriteAfterUserRetryWins(t *testing.T) {
	oldTracker := defaultActiveRequestTracker
	defaultActiveRequestTracker = newActiveRequestTracker()
	t.Cleanup(func() {
		defaultActiveRequestTracker = oldTracker
	})

	requestLog := &ReqeustLog{Platform: "openai-responses", Provider: "provider-a"}
	requestLog.startedAt = time.Now()
	requestLog.ActiveRequestID = defaultActiveRequestTracker.Start(requestLog, requestLog.startedAt)
	defaultActiveRequestTracker.RegisterCancel(requestLog.ActiveRequestID, func() {})
	if result := defaultActiveRequestTracker.Retry(-requestLog.ActiveRequestID, ""); result.Status != activeRequestRetryTriggered {
		t.Fatalf("retry status = %q, want %q", result.Status, activeRequestRetryTriggered)
	}

	w := httptest.NewRecorder()
	line := []byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"old attempt\"}\n")
	_, err := writeStreamingLine(w, line, requestLog, ReqeustLogHook(nil, "openai-responses", requestLog))
	if !errors.Is(err, errActiveRequestRetryRequested) {
		t.Fatalf("stream write error = %v, want %v", err, errActiveRequestRetryRequested)
	}
	if w.Body.Len() != 0 {
		t.Fatalf("old attempt wrote data after retry: %q", w.Body.String())
	}
}

func TestStartActiveRequestLogSnapshotsAccountPoolTrafficExclusion(t *testing.T) {
	oldTracker := defaultActiveRequestTracker
	defaultActiveRequestTracker = newActiveRequestTracker()
	t.Cleanup(func() {
		defaultActiveRequestTracker = oldTracker
	})

	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	context.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	pool := &ProviderPool{
		PoolType:                ProviderPoolTypeAccount,
		ExcludeFromTotalTraffic: true,
	}
	context.Request = context.Request.WithContext(withProviderPoolContext(context.Request.Context(), pool, "user-a"))

	requestLog := (&ProviderRelayService{}).startActiveRequestLog(context, "openai-responses", "gpt-5", false)
	if !requestLog.ExcludeFromTotalTraffic {
		t.Fatal("account pool request log should snapshot exclude-from-total setting")
	}

	pool.ExcludeFromTotalTraffic = false
	if !requestLog.ExcludeFromTotalTraffic {
		t.Fatal("request log exclusion should not change after pool configuration changes")
	}
}

func TestResolveRelayEndpointUsesProtocolSpecificEndpoint(t *testing.T) {
	relay := &ProviderRelayService{}
	provider := Provider{
		APIEndpoint:       "/legacy",
		ResponsesEndpoint: "/v1/responses",
		ChatEndpoint:      "/chat/completions",
	}

	if got := relay.resolveRelayEndpoint("codex", provider, "/responses"); got != "/v1/responses" {
		t.Fatalf("codex responses endpoint = %q, want /v1/responses", got)
	}
	if got := relay.resolveRelayEndpoint("codex", provider, "/chat/completions"); got != "/chat/completions" {
		t.Fatalf("codex chat endpoint = %q, want /chat/completions", got)
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

type cancelAfterFirstTextRecorder struct {
	header http.Header
	cancel context.CancelFunc
	writes int
}

type errorAfterReader struct {
	data []byte
	err  error
}

func (r *errorAfterReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func (r *cancelAfterFirstTextRecorder) Header() http.Header {
	return r.header
}

func (r *cancelAfterFirstTextRecorder) WriteHeader(int) {}

func (r *cancelAfterFirstTextRecorder) Flush() {}

func (r *cancelAfterFirstTextRecorder) Write(data []byte) (int, error) {
	r.writes++
	// The first write is the guard keepalive and the second contains actual
	// text. Simulate the downstream closing only after that text was accepted.
	if r.writes >= 3 {
		r.cancel()
		return 0, context.Canceled
	}
	return len(data), nil
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

func TestWriteStreamingResponseNormalizesSSEHeaders(t *testing.T) {
	resp := xrequest.NewResponse(&http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":     []string{"text/html; charset=utf-8"},
			"Content-Encoding": []string{"gzip"},
			"Content-Length":   []string{"999"},
			"Cache-Control":    []string{"private"},
		},
		Body: io.NopCloser(strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"你\"}}]}\n\ndata: [DONE]\n\n")),
	})

	recorder := newStreamingRecorder()
	requestLog := &ReqeustLog{startedAt: time.Now()}
	if _, err := writeStreamingResponse(recorder, resp, requestLog); err != nil {
		t.Fatalf("writeStreamingResponse returned error: %v", err)
	}

	if got := recorder.header.Get("Content-Type"); got != "text/event-stream; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/event-stream; charset=utf-8", got)
	}
	if got := recorder.header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	if got := recorder.header.Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length = %q, want empty", got)
	}
	if got := recorder.header.Get("Cache-Control"); !strings.Contains(got, "private") || !strings.Contains(got, "no-cache") || !strings.Contains(got, "no-transform") {
		t.Fatalf("Cache-Control = %q, want private, no-cache, and no-transform", got)
	}
	if got := recorder.BodyString(); !strings.Contains(got, "data: [DONE]") {
		t.Fatalf("expected streamed body, got %q", got)
	}
}

func TestUpstreamHTMLStreamErrorRejectsHTML(t *testing.T) {
	resp := xrequest.NewResponse(&http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"text/html; charset=utf-8"},
		},
		Body: io.NopCloser(strings.NewReader("<!doctype html><html><head><title>WeCoding - AI API Gateway</title></head></html>")),
	})

	err := upstreamHTMLStreamError(resp)
	if err == nil {
		t.Fatalf("expected HTML stream response to be rejected")
	}
	if !strings.Contains(err.Error(), "upstream returned HTML instead of SSE") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "WeCoding") {
		t.Fatalf("expected upstream HTML title in error, got %v", err)
	}
}

func TestUpstreamHTMLStreamErrorAllowsSSE(t *testing.T) {
	resp := xrequest.NewResponse(&http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"text/event-stream"},
		},
		Body: io.NopCloser(strings.NewReader("data: {}\n\n")),
	})

	if err := upstreamHTMLStreamError(resp); err != nil {
		t.Fatalf("expected SSE to pass, got %v", err)
	}
}

func TestWriteCodexGuardedStreamingResponseRejectsEmptyStreamWithoutCommittingResponse(t *testing.T) {
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
	if responseWritten {
		t.Fatal("empty stream committed an HTTP response before the relay could return 502")
	}
	if written != 0 {
		t.Fatalf("written = %d, want 0", written)
	}
	if body := recorder.BodyString(); body != "" {
		t.Fatalf("body = %q, want no committed body", body)
	}
	if recorder.status != 0 {
		t.Fatalf("status = %d, want no committed status", recorder.status)
	}
}

func TestWriteCodexGuardedStreamingResponseRejectsCompletedWithoutUsefulContent(t *testing.T) {
	resp := xrequest.NewResponse(&http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body: io.NopCloser(strings.NewReader(
			"data: {\"type\":\"response.created\"}\n\n" +
				"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_empty\",\"output\":[],\"usage\":{\"input_tokens\":12,\"output_tokens\":0}}}\n\n" +
				"data: [DONE]\n\n",
		)),
	})

	recorder := newStreamingRecorder()
	written, responseWritten, err := writeCodexGuardedStreamingResponse(recorder, resp, &ReqeustLog{startedAt: time.Now()})
	if !errors.Is(err, errCodexEmptyStream) {
		t.Fatalf("err = %v, want errCodexEmptyStream", err)
	}
	if written != 0 || responseWritten || recorder.status != 0 || recorder.BodyString() != "" {
		t.Fatalf("completed empty response was committed: written=%d responseWritten=%v status=%d body=%q", written, responseWritten, recorder.status, recorder.BodyString())
	}
}

func TestWriteCodexGuardedStreamingResponseAcceptsCompletedWithEmbeddedOutput(t *testing.T) {
	resp := xrequest.NewResponse(&http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body: io.NopCloser(strings.NewReader(
			"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_full\",\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"embedded output\"}]}]}}\n\n" +
				"data: [DONE]\n\n",
		)),
	})

	recorder := newStreamingRecorder()
	requestLog := &ReqeustLog{startedAt: time.Now()}
	_, responseWritten, err := writeCodexGuardedStreamingResponse(recorder, resp, requestLog, ReqeustLogHook(nil, "openai-responses", requestLog))
	if err != nil {
		t.Fatalf("guard returned error: %v", err)
	}
	if !responseWritten || recorder.status != http.StatusOK || !strings.Contains(recorder.BodyString(), "embedded output") {
		t.Fatalf("completed response with embedded output was not forwarded: written=%v status=%d body=%q", responseWritten, recorder.status, recorder.BodyString())
	}
	if requestLog.FirstTextSec <= 0 {
		t.Fatal("embedded completed output did not mark first useful content")
	}
}

func TestWriteCodexGuardedStreamingResponseAcceptsCompletedCodexOutputItems(t *testing.T) {
	tests := []struct {
		name string
		item string
	}{
		{
			name: "image generation",
			item: `{"type":"image_generation_call","id":"ig_1","status":"completed","revised_prompt":"a blue square","result":"Zm9v"}`,
		},
		{
			name: "compaction",
			item: `{"type":"compaction","encrypted_content":"encrypted-summary"}`,
		},
		{
			name: "compaction summary alias",
			item: `{"type":"compaction_summary","encrypted_content":"encrypted-summary"}`,
		},
		{
			name: "reasoning with encrypted content",
			item: `{"type":"reasoning","id":"reasoning_1","summary":[],"encrypted_content":"encrypted-reasoning"}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := fmt.Sprintf(
				"data: {\"type\":\"response.output_item.done\",\"item\":%s}\n\n"+
					"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_item\"}}\n\n",
				test.item,
			)
			resp := xrequest.NewResponse(&http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:       io.NopCloser(strings.NewReader(payload)),
			})
			recorder := newStreamingRecorder()
			requestLog := &ReqeustLog{startedAt: time.Now()}
			_, responseWritten, err := writeCodexGuardedStreamingResponse(recorder, resp, requestLog, ReqeustLogHook(nil, "openai-responses", requestLog))
			if err != nil {
				t.Fatalf("guard returned error: %v", err)
			}
			if !responseWritten || recorder.status != http.StatusOK || !strings.Contains(recorder.BodyString(), "response.output_item.done") {
				t.Fatalf("valid Codex output item was not forwarded: written=%v status=%d body=%q", responseWritten, recorder.status, recorder.BodyString())
			}
			if requestLog.FirstTextSec <= 0 {
				t.Fatal("valid Codex output item did not mark first useful content")
			}
		})
	}
}

func TestWriteCodexGuardedStreamingResponseDoesNotReleaseEmptyReasoningPlaceholder(t *testing.T) {
	tests := []struct {
		name    string
		trailer string
		wantErr error
	}{
		{
			name:    "followed by terminal failure",
			trailer: "data: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp_failed\"}}\n\n",
			wantErr: errCodexTerminalStreamFailure,
		},
		{
			name:    "followed by EOF",
			wantErr: errCodexEmptyStream,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := "data: {\"type\":\"response.output_item.added\",\"item\":{\"type\":\"reasoning\",\"id\":\"reasoning_empty\",\"summary\":[]}}\n\n" + test.trailer
			resp := xrequest.NewResponse(&http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:       io.NopCloser(strings.NewReader(payload)),
			})
			recorder := newStreamingRecorder()
			requestLog := &ReqeustLog{startedAt: time.Now()}
			written, responseWritten, err := writeCodexGuardedStreamingResponse(recorder, resp, requestLog, ReqeustLogHook(nil, "openai-responses", requestLog))
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("err = %v, want %v", err, test.wantErr)
			}
			if written != 0 || responseWritten || recorder.status != 0 || recorder.BodyString() != "" || requestLog.FirstTextSec != 0 {
				t.Fatalf("empty reasoning placeholder was released: written=%d responseWritten=%v status=%d firstText=%f body=%q", written, responseWritten, recorder.status, requestLog.FirstTextSec, recorder.BodyString())
			}
		})
	}
}

func TestWriteCodexGuardedStreamingResponseReleasesOnToolCallAdded(t *testing.T) {
	tests := []struct {
		name string
		item string
	}{
		{
			name: "web search",
			item: `{"type":"web_search_call","id":"web_1","status":"in_progress"}`,
		},
		{
			name: "function call",
			item: `{"type":"function_call","call_id":"call_1","name":"get_weather","arguments":""}`,
		},
		{
			name: "local shell",
			item: `{"type":"local_shell_call","call_id":"shell_1","status":"in_progress","action":{"type":"exec","command":["pwd"]}}`,
		},
		{
			name: "custom tool",
			item: `{"type":"custom_tool_call","call_id":"custom_1","name":"apply_patch","input":""}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := fmt.Sprintf(
				"data: {\"type\":\"response.output_item.added\",\"item\":%s}\n\n"+
					"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_tool\"}}\n\n",
				test.item,
			)
			resp := xrequest.NewResponse(&http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:       io.NopCloser(strings.NewReader(payload)),
			})
			recorder := newStreamingRecorder()
			requestLog := &ReqeustLog{startedAt: time.Now()}
			_, responseWritten, err := writeCodexGuardedStreamingResponseWithOptions(
				recorder,
				resp,
				requestLog,
				codexStreamGuardOptions{
					deferInitialKeepAlive:        true,
					disableKeepAliveUntilRelease: true,
					firstUsefulContentTimeout:    25 * time.Millisecond,
				},
				ReqeustLogHook(nil, "openai-responses", requestLog),
			)
			if err != nil {
				t.Fatalf("guard returned error: %v", err)
			}
			if !responseWritten || recorder.status != http.StatusOK || !strings.Contains(recorder.BodyString(), "response.output_item.added") {
				t.Fatalf("tool call added event was not forwarded: written=%v status=%d body=%q", responseWritten, recorder.status, recorder.BodyString())
			}
			if requestLog.FirstTextSec <= 0 {
				t.Fatal("tool call added event did not mark first useful content")
			}
		})
	}
}

func TestWriteCodexGuardedStreamingResponseRejectsTerminalBeforeUsefulContent(t *testing.T) {
	for _, eventType := range []string{"response.failed", "response.incomplete"} {
		t.Run(eventType, func(t *testing.T) {
			resp := xrequest.NewResponse(&http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("data: {\"type\":%q,\"response\":{\"id\":\"resp_terminal\"}}\n\n", eventType))),
			})
			recorder := newStreamingRecorder()
			written, responseWritten, err := writeCodexGuardedStreamingResponse(recorder, resp, &ReqeustLog{startedAt: time.Now()})
			if !errors.Is(err, errCodexTerminalStreamFailure) {
				t.Fatalf("err = %v, want errCodexTerminalStreamFailure", err)
			}
			if written != 0 || responseWritten || recorder.status != 0 || recorder.BodyString() != "" {
				t.Fatalf("terminal response was committed: written=%d responseWritten=%v status=%d body=%q", written, responseWritten, recorder.status, recorder.BodyString())
			}
		})
	}
}

func TestWriteCodexGuardedStreamingResponseCommitsOnlyCompletedResponseID(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		wantCommit string
		wantErr    error
	}{
		{
			name: "completed",
			payload: "data: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\"}\n\n" +
				"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_complete\"}}\n\n" +
				"data: [DONE]\n\n",
			wantCommit: "resp_complete",
		},
		{
			name: "failed",
			payload: "data: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp_failed\"}}\n\n" +
				"data: [DONE]\n\n",
			wantErr: errCodexTerminalStreamFailure,
		},
		{
			name: "incomplete",
			payload: "data: {\"type\":\"response.incomplete\",\"response\":{\"id\":\"resp_incomplete\"}}\n\n" +
				"data: [DONE]\n\n",
			wantErr: errCodexTerminalStreamFailure,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resp := xrequest.NewResponse(&http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:       io.NopCloser(strings.NewReader(test.payload)),
			})
			var committed string
			_, _, err := writeCodexGuardedStreamingResponseWithOptions(
				newStreamingRecorder(),
				resp,
				&ReqeustLog{startedAt: time.Now()},
				codexStreamGuardOptions{
					deferInitialKeepAlive: true,
					onSuccessfulCompleted: func(responseID string) {
						committed = responseID
					},
				},
			)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("guard error = %v, want %v", err, test.wantErr)
			}
			if committed != test.wantCommit {
				t.Fatalf("committed response id = %q, want %q", committed, test.wantCommit)
			}
		})
	}
}

func TestShouldUseCodexStreamGuardOnlyForResponses(t *testing.T) {
	relay := &ProviderRelayService{}

	if !relay.shouldUseCodexStreamGuard("codex", "/responses") {
		t.Fatalf("expected Codex Responses stream guard to be enabled by default")
	}
	if relay.shouldUseCodexStreamGuard("codex", "/chat/completions") {
		t.Fatalf("expected Codex Chat Completions to bypass stream guard")
	}
	if !relay.shouldUseCodexStreamGuard("openai-responses", "/custom/codex") {
		t.Fatalf("expected OpenAI Responses custom endpoints to use the stream guard")
	}
	if relay.shouldUseCodexStreamGuard("claude", "/v1/responses") {
		t.Fatalf("expected non-Codex streams to bypass Codex stream guard")
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
		t.Fatal("guard committed a response before useful content")
	case <-time.After(50 * time.Millisecond):
	}

	if _, err := pw.Write([]byte("data: {\"type\":\"response.created\"}\n\n")); err != nil {
		t.Fatalf("write created event: %v", err)
	}

	select {
	case <-recorder.wroteCh:
		t.Fatalf("guard released metadata before useful content: %q", recorder.BodyString())
	case <-time.After(50 * time.Millisecond):
	}

	if _, err := pw.Write([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hello\"}\n\n")); err != nil {
		t.Fatalf("write text delta: %v", err)
	}

	select {
	case <-recorder.wroteCh:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("guard did not release on useful content")
	}

	if _, err := pw.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_complete\"}}\n\n")); err != nil {
		t.Fatalf("write completed event: %v", err)
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

func TestWriteCodexGuardedStreamingResponseRejectsMissingCompletionAfterUsefulContent(t *testing.T) {
	resp := xrequest.NewResponse(&http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body: io.NopCloser(strings.NewReader(
			"data: {\"type\":\"response.created\"}\n\n" +
				"data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n",
		)),
	})

	recorder := newStreamingRecorder()
	written, responseWritten, err := writeCodexGuardedStreamingResponse(recorder, resp, &ReqeustLog{startedAt: time.Now()})
	if !errors.Is(err, errCodexMissingCompletion) {
		t.Fatalf("err = %v, want %v", err, errCodexMissingCompletion)
	}
	if !responseWritten || written == 0 {
		t.Fatalf("partial stream was not forwarded before terminal check: written=%d responseWritten=%v", written, responseWritten)
	}
	if body := recorder.BodyString(); !strings.Contains(body, "partial") {
		t.Fatalf("forwarded stream missing partial event: %q", body)
	}
}

func TestWriteCodexGuardedStreamingResponseRejectsTruncatedReadWithoutCompletion(t *testing.T) {
	resp := xrequest.NewResponse(&http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body: io.NopCloser(&errorAfterReader{
			data: []byte(
				"data: {\"type\":\"response.created\"}\n\n" +
					"data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n",
			),
			err: io.ErrUnexpectedEOF,
		}),
	})

	recorder := newStreamingRecorder()
	_, responseWritten, err := writeCodexGuardedStreamingResponse(recorder, resp, &ReqeustLog{startedAt: time.Now()})
	if !errors.Is(err, errCodexMissingCompletion) {
		t.Fatalf("err = %v, want %v", err, errCodexMissingCompletion)
	}
	if !responseWritten || !strings.Contains(recorder.BodyString(), "partial") {
		t.Fatalf("truncated stream was not forwarded before terminal check: written=%v body=%q", responseWritten, recorder.BodyString())
	}
}

func TestWriteCodexGuardedStreamingResponseForwardsTerminalFailureAfterUsefulContent(t *testing.T) {
	for _, eventType := range []string{"response.failed", "response.incomplete"} {
		t.Run(eventType, func(t *testing.T) {
			resp := xrequest.NewResponse(&http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body: io.NopCloser(strings.NewReader(
					"data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n" +
						fmt.Sprintf("data: {\"type\":%q,\"response\":{\"id\":\"resp_terminal\"}}\n\n", eventType),
				)),
			})

			recorder := newStreamingRecorder()
			_, responseWritten, err := writeCodexGuardedStreamingResponse(recorder, resp, &ReqeustLog{startedAt: time.Now()})
			if !errors.Is(err, errCodexTerminalStreamFailure) {
				t.Fatalf("err = %v, want %v", err, errCodexTerminalStreamFailure)
			}
			if !responseWritten || !strings.Contains(recorder.BodyString(), eventType) {
				t.Fatalf("terminal event was not forwarded: written=%v body=%q", responseWritten, recorder.BodyString())
			}
		})
	}
}

func TestWriteCodexGuardedStreamingResponseSendsKeepAliveAfterRelease(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	resp := xrequest.NewResponse(&http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       pr,
	})
	recorder := newStreamingRecorder()
	done := make(chan error, 1)
	go func() {
		_, _, err := writeCodexGuardedStreamingResponseWithOptions(
			recorder,
			resp,
			&ReqeustLog{startedAt: time.Now()},
			codexStreamGuardOptions{
				deferInitialKeepAlive:        true,
				disableKeepAliveUntilRelease: true,
				keepAliveInterval:            10 * time.Millisecond,
			},
		)
		done <- err
	}()

	if _, err := pw.Write([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"ready\"}\n\n")); err != nil {
		t.Fatalf("write useful event: %v", err)
	}

	deadline := time.After(500 * time.Millisecond)
	for !strings.Contains(recorder.BodyString(), codexStreamGuardKeepAliveComment) {
		select {
		case <-deadline:
			t.Fatalf("expected a post-release keepalive, body=%q", recorder.BodyString())
		case <-time.After(5 * time.Millisecond):
		}
	}

	if _, err := pw.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_keepalive\"}}\n\n")); err != nil {
		t.Fatalf("write completed event: %v", err)
	}
	if err := pw.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("guard returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("guard did not return after completed stream EOF")
	}
}

func TestWriteCodexGuardedStreamingResponseKeepsEventsIntactAcrossKeepAlive(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	resp := xrequest.NewResponse(&http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       pr,
	})
	recorder := newStreamingRecorder()
	done := make(chan error, 1)
	go func() {
		_, _, err := writeCodexGuardedStreamingResponseWithOptions(
			recorder,
			resp,
			&ReqeustLog{startedAt: time.Now()},
			codexStreamGuardOptions{
				deferInitialKeepAlive:        true,
				disableKeepAliveUntilRelease: true,
				keepAliveInterval:            10 * time.Millisecond,
			},
		)
		done <- err
	}()

	if _, err := pw.Write([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"ready\"}\n\n")); err != nil {
		t.Fatalf("write useful event: %v", err)
	}
	if _, err := pw.Write([]byte("event: response.completed\n")); err != nil {
		t.Fatalf("write completed event name: %v", err)
	}

	deadline := time.After(500 * time.Millisecond)
	for !strings.Contains(recorder.BodyString(), "event: response.completed\n") {
		select {
		case <-deadline:
			t.Fatalf("event name was not forwarded: %q", recorder.BodyString())
		case <-time.After(5 * time.Millisecond):
		}
	}
	time.Sleep(50 * time.Millisecond)
	body := recorder.BodyString()
	eventOffset := strings.LastIndex(body, "event: response.completed\n")
	if strings.Contains(body[eventOffset:], codexStreamGuardKeepAliveComment) {
		t.Fatalf("keepalive split an SSE event: %q", body[eventOffset:])
	}

	if _, err := pw.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_boundary\"}}\n\n")); err != nil {
		t.Fatalf("write completed data: %v", err)
	}
	if err := pw.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("guard returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("guard did not return after a completed stream")
	}
}

func TestWriteCodexGuardedStreamingResponseTimesOutBeforeUsefulContent(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()

	resp := xrequest.NewResponse(&http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       pr,
	})

	start := time.Now()
	_, responseWritten, err := writeCodexGuardedStreamingResponseWithOptions(
		newStreamingRecorder(),
		resp,
		&ReqeustLog{startedAt: start},
		codexStreamGuardOptions{
			deferInitialKeepAlive:        true,
			disableKeepAliveUntilRelease: true,
			firstUsefulContentTimeout:    25 * time.Millisecond,
		},
	)
	if !errors.Is(err, errCodexFirstTextTimeout) {
		t.Fatalf("err = %v, want errCodexFirstTextTimeout", err)
	}
	if responseWritten {
		t.Fatal("response was committed before first useful content")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("first-content timeout took %s, want prompt timeout", elapsed)
	}
}

func TestWriteCodexGuardedStreamingResponseDoesNotTreatUsageAsFirstText(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	resp := xrequest.NewResponse(&http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       pr,
	})

	done := make(chan error, 1)
	go func() {
		_, _, err := writeCodexGuardedStreamingResponseWithOptions(
			newStreamingRecorder(),
			resp,
			&ReqeustLog{startedAt: time.Now()},
			codexStreamGuardOptions{
				deferInitialKeepAlive:        true,
				disableKeepAliveUntilRelease: true,
				firstUsefulContentTimeout:    25 * time.Millisecond,
			},
		)
		done <- err
	}()

	if _, err := pw.Write([]byte("data: {\"type\":\"response.in_progress\",\"response\":{\"usage\":{\"input_tokens\":12}}}\n\n")); err != nil {
		t.Fatalf("write usage event: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, errCodexFirstTextTimeout) {
			t.Fatalf("err = %v, want errCodexFirstTextTimeout after usage-only event", err)
		}
	case <-time.After(time.Second):
		t.Fatal("usage-only stream did not observe first-text timeout")
	}
}

func TestReadResponseBodyWithFirstTextTimeout(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	resp := xrequest.NewResponse(&http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       reader,
	})

	startedAt := time.Now()
	_, err := readResponseBodyWithFirstTextTimeout(resp, 25*time.Millisecond)
	if !errors.Is(err, errCodexFirstTextTimeout) {
		t.Fatalf("err = %v, want errCodexFirstTextTimeout", err)
	}
	if elapsed := time.Since(startedAt); elapsed > 500*time.Millisecond {
		t.Fatalf("first-text timeout took %s, want prompt timeout", elapsed)
	}
}

func TestLateClientCloseAfterFirstTextKeepsSuccessfulResponseLog(t *testing.T) {
	oldTracker := defaultActiveRequestTracker
	defaultActiveRequestTracker = newActiveRequestTracker()
	t.Cleanup(func() {
		defaultActiveRequestTracker = oldTracker
	})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"ready\"}\n\n")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\"}}\n\n")
	}))
	defer upstream.Close()

	requestContext, cancel := context.WithCancel(context.Background())
	recorder := &cancelAfterFirstTextRecorder{
		header: make(http.Header),
		cancel: cancel,
	}
	context, _ := gin.CreateTestContext(recorder)
	request := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5","stream":true}`))
	context.Request = request.WithContext(requestContext)

	relay := NewProviderRelayService(NewProviderService(), NewProviderPoolService(), nil, nil, nil, DefaultRelayBindAddr)
	requestLog := &ReqeustLog{startedAt: time.Now()}
	ok, err := relay.forwardRequestWithLog(
		context,
		"openai-responses",
		Provider{ID: 1, Name: "provider-a", APIURL: upstream.URL, APIKey: "test-key"},
		"/responses",
		nil,
		http.Header{},
		[]byte(`{"model":"gpt-5","stream":true}`),
		true,
		"gpt-5",
		requestLog,
	)
	if !ok || err != nil {
		t.Fatalf("late close after first text = (%v, %v), want successful response", ok, err)
	}
	if requestLog.HttpCode != http.StatusOK {
		t.Fatalf("http code = %d, want 200", requestLog.HttpCode)
	}
	if requestLog.FirstTextSec <= 0 {
		t.Fatalf("first text = %.3fs, want positive", requestLog.FirstTextSec)
	}
	if requestLog.ErrorMessage != "" {
		t.Fatalf("error message = %q, want empty successful log", requestLog.ErrorMessage)
	}
}

func TestForwardRequestWithLogReportsMissingCompletionAfterResponseStarted(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n")
	}))
	defer upstream.Close()

	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5","stream":true}`))

	relay := NewProviderRelayService(NewProviderService(), NewProviderPoolService(), nil, nil, nil, DefaultRelayBindAddr)
	requestLog := &ReqeustLog{startedAt: time.Now()}
	ok, err := relay.forwardRequestWithLog(
		context,
		"openai-responses",
		Provider{ID: 1, Name: "truncated-provider", APIURL: upstream.URL, APIKey: "test-key"},
		"/responses",
		nil,
		http.Header{},
		[]byte(`{"model":"gpt-5","stream":true}`),
		true,
		"gpt-5",
		requestLog,
	)
	if ok {
		t.Fatal("truncated stream was reported as a successful provider response")
	}
	if !errors.Is(err, errCodexMissingCompletion) {
		t.Fatalf("err = %v, want %v", err, errCodexMissingCompletion)
	}
	if requestLog.HttpCode != http.StatusBadGateway {
		t.Fatalf("request log HTTP status = %d, want %d", requestLog.HttpCode, http.StatusBadGateway)
	}
	if !strings.Contains(requestLog.ErrorMessage, `"code":"missing_completion"`) {
		t.Fatalf("request log error = %q, want missing_completion protocol error", requestLog.ErrorMessage)
	}
	if body := recorder.Body.String(); !strings.Contains(body, "partial") {
		t.Fatalf("client did not receive the partial stream before it closed: %q", body)
	}
}

func TestLocalRelayDoesNotForwardPublicClientAddressHeaders(t *testing.T) {
	receivedHeaders := make(chan http.Header, 1)
	localRelay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders <- r.Header.Clone()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"ready\"}\n\n")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\"}}\n\n")
	}))
	defer localRelay.Close()

	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5","stream":true}`))

	clientHeaders := http.Header{
		"Forwarded":          []string{"for=203.0.113.25"},
		"X-Forwarded-For":    []string{"203.0.113.25"},
		"X-Real-IP":          []string{"203.0.113.25"},
		"CF-Connecting-IP":   []string{"203.0.113.25"},
		"True-Client-IP":     []string{"203.0.113.25"},
		"X-Forwarded-Proto":  []string{"https"},
		"X-Unrelated-Header": []string{"keep-me"},
	}
	relay := NewProviderRelayService(NewProviderService(), NewProviderPoolService(), nil, nil, nil, DefaultRelayBindAddr)
	requestLog := &ReqeustLog{startedAt: time.Now()}
	ok, err := relay.forwardRequestWithLog(
		context,
		"openai-responses",
		Provider{ID: 1, Name: "local-relay", APIURL: localRelay.URL, APIKey: "test-key"},
		"/responses",
		nil,
		clientHeaders,
		[]byte(`{"model":"gpt-5","stream":true}`),
		true,
		"gpt-5",
		requestLog,
	)
	if !ok || err != nil {
		t.Fatalf("local relay result = (%v, %v), want success", ok, err)
	}

	select {
	case headers := <-receivedHeaders:
		for _, key := range []string{"Forwarded", "X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", "True-Client-IP"} {
			if value := headers.Get(key); value != "" {
				t.Fatalf("local relay forwarded %s = %q, want empty", key, value)
			}
		}
		if got := headers.Get("X-Forwarded-Proto"); got != "https" {
			t.Fatalf("X-Forwarded-Proto = %q, want preserved", got)
		}
		if got := headers.Get("X-Unrelated-Header"); got != "keep-me" {
			t.Fatalf("X-Unrelated-Header = %q, want preserved", got)
		}
	case <-time.After(time.Second):
		t.Fatal("local relay did not receive request")
	}
}

func TestPublicUpstreamKeepsClientAddressHeaders(t *testing.T) {
	headers := make(http.Header)
	headers.Set("X-Forwarded-For", "203.0.113.25")
	headers.Set("X-Real-IP", "203.0.113.25")
	stripClientAddressHeadersForLocalRelay(headers, "https://203.0.113.10/responses")
	if got := headers.Get("X-Forwarded-For"); got != "203.0.113.25" {
		t.Fatalf("public X-Forwarded-For = %q, want preserved", got)
	}
	if got := headers.Get("X-Real-IP"); got != "203.0.113.25" {
		t.Fatalf("public X-Real-IP = %q, want preserved", got)
	}
}

func TestPoolFirstTextTimeoutCancelsBeforeDelayedHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		select {
		case <-r.Context().Done():
			return
		case <-time.After(6 * time.Second):
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"late\"}\n\n"))
		}
	}))
	defer upstream.Close()

	relay := NewProviderRelayService(NewProviderService(), NewProviderPoolService(), nil, nil, nil, DefaultRelayBindAddr)
	pool := &ProviderPool{FirstTextRetryEnabled: true, FirstTextRetryTimeoutSeconds: 5}
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	request := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5","stream":true}`))
	request = request.WithContext(withProviderPoolContext(request.Context(), pool, "user-a"))
	context.Request = request

	startedAt := time.Now()
	ok, err := relay.forwardRequestWithLog(
		context,
		"openai-responses",
		Provider{ID: 1, Name: "slow", APIURL: upstream.URL, APIKey: "test-key"},
		"/responses",
		nil,
		http.Header{},
		[]byte(`{"model":"gpt-5","stream":true}`),
		true,
		"gpt-5",
		nil,
	)
	if ok || !errors.Is(err, errCodexFirstTextTimeout) {
		t.Fatalf("forward result = (%v, %v), want first-text timeout", ok, err)
	}
	if elapsed := time.Since(startedAt); elapsed > 5500*time.Millisecond {
		t.Fatalf("delayed headers timed out after %s, want close to 5 seconds", elapsed)
	}
}

func TestPoolFirstTextTimeoutResetsForEachProviderAttempt(t *testing.T) {
	requestReachedUpstream := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestReachedUpstream <- struct{}{}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"ready\"}\n\n"))
		_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_ready\"}}\n\n"))
	}))
	defer upstream.Close()

	relay := NewProviderRelayService(NewProviderService(), NewProviderPoolService(), nil, nil, nil, DefaultRelayBindAddr)
	pool := &ProviderPool{FirstTextRetryEnabled: true, FirstTextRetryTimeoutSeconds: 5}
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	request := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5","stream":true}`))
	request = request.WithContext(withProviderPoolContext(request.Context(), pool, "user-a"))
	context.Request = request
	requestLog := &ReqeustLog{startedAt: time.Now().Add(-6 * time.Second)}

	ok, err := relay.forwardRequestWithLog(
		context,
		"openai-responses",
		Provider{ID: 1, Name: "slow", APIURL: upstream.URL, APIKey: "test-key"},
		"/responses",
		nil,
		http.Header{},
		[]byte(`{"model":"gpt-5","stream":true}`),
		true,
		"gpt-5",
		requestLog,
	)
	if !ok || err != nil {
		t.Fatalf("forward result = (%v, %v), want successful fresh provider attempt", ok, err)
	}
	if requestLog.FirstTextSec <= 0 || requestLog.FirstTextSec >= 1 {
		t.Fatalf("fresh attempt first text = %.3fs, want attempt-relative timing below 1s", requestLog.FirstTextSec)
	}
	select {
	case <-requestReachedUpstream:
	default:
		t.Fatal("fresh provider attempt did not reach upstream")
	}
}

func TestPoolFirstTextTimeoutResetsForLowLevelHTTPRetry(t *testing.T) {
	var calls atomic.Int32
	secondAttemptStarted := make(chan time.Time, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		secondAttemptStarted <- time.Now()
		<-r.Context().Done()
	}))
	defer upstream.Close()

	relay := NewProviderRelayService(NewProviderService(), NewProviderPoolService(), nil, nil, nil, DefaultRelayBindAddr)
	pool := &ProviderPool{FirstTextRetryEnabled: true, FirstTextRetryTimeoutSeconds: 5}
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	request := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5","stream":true}`))
	request = request.WithContext(withProviderPoolContext(request.Context(), pool, "user-a"))
	context.Request = request

	ok, err := relay.forwardRequestWithLog(
		context,
		"openai-responses",
		Provider{ID: 1, Name: "retrying-provider", APIURL: upstream.URL, APIKey: "test-key"},
		"/responses",
		nil,
		http.Header{},
		[]byte(`{"model":"gpt-5","stream":true}`),
		true,
		"gpt-5",
		nil,
	)
	if ok || !errors.Is(err, errCodexFirstTextTimeout) {
		t.Fatalf("forward result = (%v, %v), want first-text timeout", ok, err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("HTTP attempts = %d, want 2", got)
	}
	select {
	case startedAt := <-secondAttemptStarted:
		if elapsed := time.Since(startedAt); elapsed < 4750*time.Millisecond || elapsed > 5500*time.Millisecond {
			t.Fatalf("second HTTP attempt timed out after %s, want its own five-second deadline", elapsed)
		}
	default:
		t.Fatal("second HTTP attempt never started")
	}
}

func TestFirstTextTimeoutAttemptPersistsBeforeLaterClientCancel(t *testing.T) {
	setupRelayTestEnv(t)
	db, err := xdb.DB("default")
	if err != nil {
		t.Fatalf("get db: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM request_log`); err != nil {
		t.Fatalf("clear request_log: %v", err)
	}

	previousQueue := GlobalDBQueueLogs
	testQueue := NewDBWriteQueue(db, 32, true)
	GlobalDBQueueLogs = testQueue
	t.Cleanup(func() {
		_ = testQueue.Shutdown(time.Second)
		GlobalDBQueueLogs = previousQueue
	})

	previousTracker := defaultActiveRequestTracker
	defaultActiveRequestTracker = newActiveRequestTracker()
	t.Cleanup(func() { defaultActiveRequestTracker = previousTracker })

	requestLog := &ReqeustLog{
		UserID:       "user-timeout-log",
		Platform:     "openai-responses",
		Provider:     "slow-key",
		Model:        "gpt-5",
		IsStream:     true,
		RelayKeyID:   "relay-a",
		HttpCode:     http.StatusGatewayTimeout,
		ErrorMessage: firstTextTimeoutErrorBody,
		startedAt:    time.Now().Add(-5 * time.Second),
	}
	requestLog.ActiveRequestID = defaultActiveRequestTracker.Start(requestLog, requestLog.startedAt)
	relay := &ProviderRelayService{}
	relay.persistFirstTextTimeoutAttempt(requestLog)

	// A later client cancellation belongs to the logical wrapper request. It
	// must not rewrite or duplicate the provider attempt that already timed out.
	requestLog.HttpCode = 499
	requestLog.ErrorMessage = "client cancelled"
	relay.finishActiveRequestLog(requestLog)

	var count, status int
	var body string
	if err := db.QueryRow(`
		SELECT COUNT(*), COALESCE(MAX(http_code), 0), COALESCE(MAX(error_message), '')
		FROM request_log WHERE user_id = ? AND provider = ?
	`, requestLog.UserID, "slow-key").Scan(&count, &status, &body); err != nil {
		t.Fatalf("query timeout log: %v", err)
	}
	if count != 1 || status != http.StatusGatewayTimeout || body != firstTextTimeoutErrorBody {
		t.Fatalf("persisted timeout = count %d status %d body %q, want one JSON 504", count, status, body)
	}
	if active := defaultActiveRequestTracker.List("", "", requestLog.UserID); len(active) != 0 {
		t.Fatalf("active logs after finish = %+v, want none", active)
	}
}

func TestProviderAttemptDeadlineDoesNotStartBeforeProxyPreparation(t *testing.T) {
	pool := &ProviderPool{
		ID: "proxy-pool",
		ProxyConfig: &AccountPoolProxyConfig{
			Enabled:     true,
			Selection:   AccountPoolProxySelectionNode,
			ProxyNodeID: "proxy-a",
		},
	}
	ctx := withProviderPoolContext(context.Background(), pool, "user-a")
	started := false
	relay := &ProviderRelayService{httpClient: http.DefaultClient}
	_, _, err := relay.doProviderRequestWithAttemptStart(
		ctx,
		"https://provider.example/v1/responses",
		make(http.Header),
		nil,
		nil,
		func(ctx context.Context) *providerRequestAttempt {
			started = true
			return &providerRequestAttempt{ctx: ctx}
		},
	)
	if err == nil {
		t.Fatal("proxy preparation without a proxy service unexpectedly succeeded")
	}
	if started {
		t.Fatal("provider/key deadline started before proxy preparation succeeded")
	}
}

func TestWriteCodexGuardedStreamingResponseDoesNotTimeoutAfterUsefulContent(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()

	resp := xrequest.NewResponse(&http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       pr,
	})

	done := make(chan error, 1)
	go func() {
		_, _, err := writeCodexGuardedStreamingResponseWithOptions(
			newStreamingRecorder(),
			resp,
			&ReqeustLog{startedAt: time.Now()},
			codexStreamGuardOptions{
				deferInitialKeepAlive:        true,
				disableKeepAliveUntilRelease: true,
				firstUsefulContentTimeout:    100 * time.Millisecond,
			},
		)
		done <- err
	}()

	if _, err := pw.Write([]byte("data: {\"type\":\"response.created\"}\n\n")); err != nil {
		t.Fatalf("write created event: %v", err)
	}
	if _, err := pw.Write([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hello\"}\n\n")); err != nil {
		t.Fatalf("write useful content: %v", err)
	}
	if _, err := pw.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_useful\"}}\n\n")); err != nil {
		t.Fatalf("write completed event: %v", err)
	}
	if err := pw.Close(); err != nil {
		t.Fatalf("close upstream stream: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("guard returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("guard did not finish after useful content")
	}
}

func TestCodexFirstTextTimeoutCountsTowardProviderBlacklist(t *testing.T) {
	relay := NewProviderRelayService(NewProviderService(), NewProviderPoolService(), nil, nil, nil, DefaultRelayBindAddr)
	pool := &ProviderPool{
		ID:                           "timeout-pool",
		Platform:                     "openai-responses",
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       2,
		AutoBlacklistDurationMinutes: 10,
	}
	provider := Provider{ID: 9, Name: "slow-provider", Enabled: true}

	if relay.recordCodexStreamPreflightFailureForUser("user-1", "openai-responses", pool.ID, pool, provider, errCodexFirstTextTimeout) {
		t.Fatal("first first-text timeout should not yet blacklist provider")
	}
	if relay.isProviderBlacklistedForUser("user-1", "openai-responses", pool.ID, provider.ID) {
		t.Fatal("provider blacklisted before threshold")
	}
	if !relay.recordCodexStreamPreflightFailureForUser("user-1", "openai-responses", pool.ID, pool, provider, errCodexFirstTextTimeout) {
		t.Fatal("second first-text timeout should blacklist provider")
	}

	statuses := relay.ListProviderBlacklistStatusForUser("user-1", "openai-responses", pool.ID)
	if len(statuses) != 1 || statuses[0].FailureCount != 2 || statuses[0].LastReason != "HTTP 504 (first text timeout)" {
		t.Fatalf("blacklist status = %+v, want one provider with two HTTP 504 timeout failures", statuses)
	}
}

func TestAutoProxyWithoutAvailableNodesDisablesPoolProxy(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	poolService := NewProviderPoolService()
	pool := &ProviderPool{
		ID:       "auto-proxy-pool",
		Platform: "openai-responses",
		Name:     "Auto Proxy Pool",
		PoolType: ProviderPoolTypeAccount,
		Mode:     ProviderPoolModeManaged,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            "https://upstream.example",
			ResponsesEndpoint: "/v1/responses",
			Keys:              []AccountPoolKey{{APIKey: "sk-test-key"}},
		},
		ProxyConfig: &AccountPoolProxyConfig{
			Enabled:                    true,
			Selection:                  AccountPoolProxySelectionAuto,
			AutoDisableWhenNoAvailable: true,
		},
	}
	if _, err := poolService.SavePoolForUser("user-1", pool); err != nil {
		t.Fatalf("save pool: %v", err)
	}

	relay := NewProviderRelayService(NewProviderService(), poolService, nil, nil, nil, DefaultRelayBindAddr)
	relay.disableAutoPoolProxy("user-1", pool)
	if pool.ProxyConfig.Enabled || pool.ProxyConfig.Selection != AccountPoolProxySelectionNone || pool.ProxyConfig.ProxyNodeID != "" {
		t.Fatalf("in-memory proxy config = %+v, want disabled", pool.ProxyConfig)
	}

	persisted, err := poolService.GetPoolForUser("user-1", pool.ID)
	if err != nil {
		t.Fatalf("load saved pool: %v", err)
	}
	if persisted == nil || persisted.ProxyConfig == nil || persisted.ProxyConfig.Enabled || persisted.ProxyConfig.Selection != AccountPoolProxySelectionNone || persisted.ProxyConfig.ProxyNodeID != "" {
		t.Fatalf("saved proxy config = %+v, want disabled", persisted)
	}
}

func TestAutoProxyUnavailableErrorDetection(t *testing.T) {
	if !isAutoProxyUnavailableError(errors.New("自动选择没有可用代理节点")) {
		t.Fatal("expected automatic proxy no-node error to be recognized")
	}
	if isAutoProxyUnavailableError(errors.New("固定代理节点不可用")) {
		t.Fatal("fixed-node error should not disable the pool proxy")
	}
}

func TestAutoProxyWithoutFallbackSettingStaysEnabled(t *testing.T) {
	pool := &ProviderPool{ProxyConfig: &AccountPoolProxyConfig{
		Enabled:   true,
		Selection: AccountPoolProxySelectionAuto,
	}}
	(&ProviderRelayService{}).disableAutoPoolProxy("user-1", pool)
	if !pool.ProxyConfig.Enabled || pool.ProxyConfig.Selection != AccountPoolProxySelectionAuto {
		t.Fatalf("proxy config = %+v, want automatic proxy to remain enabled without its fallback setting", pool.ProxyConfig)
	}
}

func TestPoolFirstTextTimeoutAlsoCancelsLocalRelayProvider(t *testing.T) {
	localRelay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		select {
		case <-r.Context().Done():
			return
		case <-time.After(6 * time.Second):
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"late\"}\n\n"))
		}
	}))
	defer localRelay.Close()

	// Match the target's listener exactly. Before the unified ownership rule,
	// this made the relay suppress the outer pool's first-text deadline.
	relay := NewProviderRelayService(NewProviderService(), NewProviderPoolService(), nil, nil, nil, localRelay.Listener.Addr().String())
	pool := &ProviderPool{FirstTextRetryEnabled: true, FirstTextRetryTimeoutSeconds: 5}
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	request := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5","stream":true}`))
	request = request.WithContext(withProviderPoolContext(request.Context(), pool, "user-a"))
	context.Request = request

	startedAt := time.Now()
	ok, err := relay.forwardRequestWithLog(
		context,
		"openai-responses",
		Provider{ID: 1, Name: "local-relay", APIURL: localRelay.URL, APIKey: "test-key"},
		"/responses",
		nil,
		http.Header{},
		[]byte(`{"model":"gpt-5","stream":true}`),
		true,
		"gpt-5",
		nil,
	)
	if ok || !errors.Is(err, errCodexFirstTextTimeout) {
		t.Fatalf("forward result = (%v, %v), want first-text timeout", ok, err)
	}
	if elapsed := time.Since(startedAt); elapsed < 4500*time.Millisecond || elapsed > 5500*time.Millisecond {
		t.Fatalf("local relay timed out after %s, want close to 5 seconds", elapsed)
	}
}

func TestNestedPoolOuterTimeoutDoesNotBlameInnerAccountKey(t *testing.T) {
	oldTracker := defaultActiveRequestTracker
	defaultActiveRequestTracker = newActiveRequestTracker()
	t.Cleanup(func() { defaultActiveRequestTracker = oldTracker })

	slowUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		<-r.Context().Done()
	}))
	defer slowUpstream.Close()

	innerPool := &ProviderPool{
		ID:                           "inner-account-pool",
		Platform:                     "openai-responses",
		PoolType:                     ProviderPoolTypeAccount,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       1,
		AutoBlacklistDurationMinutes: 5,
		FirstTextRetryEnabled:        true,
		FirstTextRetryTimeoutSeconds: 10,
	}
	innerProvider := Provider{
		ID:     -1,
		Name:   "inner-account-key",
		APIURL: slowUpstream.URL,
		APIKey: "inner-key",
	}
	innerRelay := NewProviderRelayService(NewProviderService(), NewProviderPoolService(), nil, nil, nil, DefaultRelayBindAddr)
	type innerResult struct {
		ok  bool
		err error
		log ReqeustLog
	}
	innerResults := make(chan innerResult, 1)
	localRelay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		context, _ := gin.CreateTestContext(w)
		request := r.WithContext(withProviderPoolContext(r.Context(), innerPool, "user-a"))
		context.Request = request
		requestLog := &ReqeustLog{startedAt: time.Now()}
		ok, err := innerRelay.forwardRequestWithLog(
			context,
			"openai-responses",
			innerProvider,
			"/responses",
			nil,
			http.Header{},
			[]byte(`{"model":"gpt-5","stream":true}`),
			true,
			"gpt-5",
			requestLog,
		)
		innerResults <- innerResult{ok: ok, err: err, log: *requestLog}
	}))
	defer localRelay.Close()

	rule := SpecialBlacklistRule{
		ID:                "outer-first-text-timeout",
		Name:              "Outer first-text timeout",
		HTTPStatus:        http.StatusGatewayTimeout,
		JSONPath:          "error.code",
		ExpectedJSONValue: `"first_text_timeout"`,
		Threshold:         1,
		DurationMinutes:   5,
	}
	outerPool := &ProviderPool{
		ID:                           "outer-normal-pool",
		Platform:                     "openai-responses",
		PoolType:                     ProviderPoolTypeNormal,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       10,
		AutoBlacklistDurationMinutes: 5,
		SpecialBlacklistRules:        []SpecialBlacklistRule{rule},
		FirstTextRetryEnabled:        true,
		FirstTextRetryTimeoutSeconds: 5,
	}
	outerProvider := Provider{ID: 1, Name: "local-relay", APIURL: localRelay.URL, APIKey: "relay-key"}
	// This is the exact address that the removed local-relay exception used to
	// recognize, so the outer timer must still own the direct relay attempt.
	outerRelay := NewProviderRelayService(NewProviderService(), NewProviderPoolService(), nil, nil, nil, localRelay.Listener.Addr().String())
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	request := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5","stream":true}`))
	request = request.WithContext(withProviderPoolContext(request.Context(), outerPool, "user-a"))
	context.Request = request
	outerLog := &ReqeustLog{startedAt: time.Now()}

	ok, err := outerRelay.forwardRequestWithLog(
		context,
		"openai-responses",
		outerProvider,
		"/responses",
		nil,
		http.Header{},
		[]byte(`{"model":"gpt-5","stream":true}`),
		true,
		"gpt-5",
		outerLog,
	)
	if ok || !errors.Is(err, errCodexFirstTextTimeout) {
		t.Fatalf("outer forward result = (%v, %v), want first-text timeout", ok, err)
	}
	if outerLog.HttpCode != http.StatusGatewayTimeout || outerLog.ErrorMessage != firstTextTimeoutErrorBody || !json.Valid([]byte(outerLog.ErrorMessage)) {
		t.Fatalf("outer log = %+v, want JSON 504 first-text timeout", outerLog)
	}

	// This is the same normal-pool failure accounting used after the direct
	// attempt above. It must assign the 504 to the outer relay provider only.
	matchedRule := specialBlacklistRuleForFailure(outerPool, outerLog.HttpCode, outerLog.ErrorMessage)
	if matchedRule == nil || matchedRule.ID != rule.ID {
		t.Fatalf("outer matched rule = %+v, want %q", matchedRule, rule.ID)
	}
	outerRelay.recordProviderFailureWithRuleForUser("user-a", "openai-responses", outerPool.ID, outerPool, outerProvider, "HTTP 504", matchedRule)
	outerStatuses := outerRelay.ListProviderBlacklistStatusForUser("user-a", "openai-responses", outerPool.ID)
	if len(outerStatuses) != 1 || outerStatuses[0].ProviderID != outerProvider.ID || outerStatuses[0].RuleFailureCounts[rule.ID] != 1 {
		t.Fatalf("outer blacklist statuses = %+v, want one local relay 504 rule failure", outerStatuses)
	}

	select {
	case result := <-innerResults:
		if result.ok || !errors.Is(result.err, errClientAbort) {
			t.Fatalf("inner forward result = (%v, %v), want client abort", result.ok, result.err)
		}
		if result.log.HttpCode != 499 || result.log.ErrorMessage != "client aborted" {
			t.Fatalf("inner log = %+v, want 499 client abort", result.log)
		}
	case <-time.After(time.Second):
		t.Fatal("inner account-key request did not observe the outer cancellation")
	}
	if statuses := innerRelay.ListProviderBlacklistStatusForUser("user-a", "openai-responses", innerPool.ID); len(statuses) != 0 {
		t.Fatalf("inner key blacklist statuses = %+v, want none after outer cancellation", statuses)
	}
}

func TestCodexProviderEnabledRequiredOnlyInManagedProxyMode(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	relay := NewProviderRelayService(NewProviderService(), nil, nil, nil, nil, DefaultRelayBindAddr)
	if relay.shouldRequireProviderEnabled("claude") != true {
		t.Fatalf("claude should always require provider enabled")
	}
	if relay.shouldRequireProviderEnabled("codex") != false {
		t.Fatalf("codex should ignore provider enabled when managed proxy is disabled")
	}
	if relay.shouldRequireProviderEnabled("openai-responses") != false {
		t.Fatalf("openai-responses should ignore provider enabled when managed proxy is disabled")
	}
	if relay.shouldRequireProviderEnabled("openai-chat") != false {
		t.Fatalf("openai-chat should ignore provider enabled when managed proxy is disabled")
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
	if relay.shouldRequireProviderEnabled("openai-responses") != true {
		t.Fatalf("openai-responses should require provider enabled when managed proxy is enabled")
	}
	if relay.shouldRequireProviderEnabled("openai-chat") != true {
		t.Fatalf("openai-chat should require provider enabled when managed proxy is enabled")
	}
}

func TestProviderBlacklistChangedEvents(t *testing.T) {
	hub := NewEventHub()
	events, cancel := hub.Subscribe(4)
	defer cancel()

	notificationService := NewNotificationService(nil)
	notificationService.SetEventEmitter(hub)
	relay := NewProviderRelayService(NewProviderService(), NewProviderPoolService(), nil, notificationService, nil, DefaultRelayBindAddr)
	pool := &ProviderPool{
		ID:                           "pool-1",
		Platform:                     "claude",
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       1,
		AutoBlacklistDurationMinutes: 10,
	}
	provider := Provider{ID: 7, Name: "provider-a", Enabled: true}

	if !relay.recordProviderFailureForUser("user-1", "claude", pool.ID, pool, provider, "upstream 500") {
		t.Fatal("expected provider to be blacklisted")
	}
	event := <-events
	if event.Name != "provider:blacklist:changed" {
		t.Fatalf("event name = %q, want provider:blacklist:changed", event.Name)
	}
	payload, ok := event.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("event payload type = %T, want map", event.Data)
	}
	if payload["action"] != "blacklisted" || payload["platform"] != "claude" || payload["poolID"] != pool.ID || payload["providerName"] != provider.Name {
		t.Fatalf("unexpected blacklist event payload: %#v", payload)
	}

	relay.clearProviderBlacklistForUser("user-1", "claude", pool.ID, provider.ID)
	event = <-events
	if event.Name != "provider:blacklist:changed" {
		t.Fatalf("event name = %q, want provider:blacklist:changed", event.Name)
	}
	payload, ok = event.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("event payload type = %T, want map", event.Data)
	}
	if payload["action"] != "cleared" || payload["platform"] != "claude" || payload["poolID"] != pool.ID {
		t.Fatalf("unexpected cleared event payload: %#v", payload)
	}
}

func TestClearAllProviderBlacklistsForUserOnlyClearsTargetPool(t *testing.T) {
	relay := NewProviderRelayService(NewProviderService(), NewProviderPoolService(), nil, nil, nil, DefaultRelayBindAddr)
	now := time.Now()
	blacklistedUntil := now.Add(10 * time.Minute)

	relay.poolPenalties[penaltyKey("user-1", "openai-responses", "account-pool", 101)] = &ProviderPoolProviderPenalty{
		UserID:           "user-1",
		Platform:         "openai-responses",
		PoolID:           "account-pool",
		ProviderID:       101,
		BlacklistedUntil: blacklistedUntil,
	}
	relay.poolPenalties[penaltyKey("user-1", "openai-responses", "account-pool", 102)] = &ProviderPoolProviderPenalty{
		UserID:           "user-1",
		Platform:         "openai-responses",
		PoolID:           "account-pool",
		ProviderID:       102,
		BlacklistedUntil: blacklistedUntil,
	}
	relay.poolPenalties[penaltyKey("user-2", "openai-responses", "account-pool", 101)] = &ProviderPoolProviderPenalty{
		UserID:           "user-2",
		Platform:         "openai-responses",
		PoolID:           "account-pool",
		ProviderID:       101,
		BlacklistedUntil: blacklistedUntil,
	}
	relay.poolPenalties[penaltyKey("user-1", "openai-responses", "other-pool", 101)] = &ProviderPoolProviderPenalty{
		UserID:           "user-1",
		Platform:         "openai-responses",
		PoolID:           "other-pool",
		ProviderID:       101,
		BlacklistedUntil: blacklistedUntil,
	}

	relay.ClearAllProviderBlacklistsForUser("user-1", "openai-responses", "account-pool")

	if _, ok := relay.poolPenalties[penaltyKey("user-1", "openai-responses", "account-pool", 101)]; ok {
		t.Fatal("first target blacklist was not cleared")
	}
	if _, ok := relay.poolPenalties[penaltyKey("user-1", "openai-responses", "account-pool", 102)]; ok {
		t.Fatal("second target blacklist was not cleared")
	}
	if _, ok := relay.poolPenalties[penaltyKey("user-2", "openai-responses", "account-pool", 101)]; !ok {
		t.Fatal("other user's blacklist was cleared")
	}
	if _, ok := relay.poolPenalties[penaltyKey("user-1", "openai-responses", "other-pool", 101)]; !ok {
		t.Fatal("other pool's blacklist was cleared")
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
	if err := os.WriteFile(filepath.Join(configDir, "openai-responses.json"), payload, 0o600); err != nil {
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

	relay := NewProviderRelayService(NewProviderService(), nil, nil, nil, nil, DefaultRelayBindAddr)
	id, required := relay.codexDirectAppliedProviderFilter("codex", false)
	if !required {
		t.Fatalf("manual mode should require direct applied provider")
	}
	if id == nil || *id != 2 {
		t.Fatalf("direct applied provider id = %v, want 2", id)
	}

	id, required = relay.codexDirectAppliedProviderFilter("openai-responses", false)
	if !required {
		t.Fatalf("openai-responses manual mode should require direct applied provider")
	}
	if id == nil || *id != 2 {
		t.Fatalf("openai-responses direct applied provider id = %v, want 2", id)
	}

	id, required = relay.codexDirectAppliedProviderFilter("codex", true)
	if required {
		t.Fatalf("managed mode should not require direct applied provider")
	}
	if id != nil {
		t.Fatalf("managed mode should not use direct applied provider id, got %v", *id)
	}

	id, required = relay.codexDirectAppliedProviderFilter("openai-responses", true)
	if required {
		t.Fatalf("openai-responses managed mode should not require direct applied provider")
	}
	if id != nil {
		t.Fatalf("openai-responses managed mode should not use direct applied provider id, got %v", *id)
	}
}

func TestCodexDirectAppliedProviderRequiredInManualMode(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	relay := NewProviderRelayService(NewProviderService(), nil, nil, nil, nil, DefaultRelayBindAddr)
	id, required := relay.codexDirectAppliedProviderFilter("codex", false)
	if !required {
		t.Fatalf("manual mode should require direct applied provider")
	}
	if id != nil {
		t.Fatalf("manual mode without direct apply should not select a provider, got %v", *id)
	}

	id, required = relay.codexDirectAppliedProviderFilter("openai-responses", false)
	if !required {
		t.Fatalf("openai-responses manual mode should require direct applied provider")
	}
	if id != nil {
		t.Fatalf("openai-responses manual mode without direct apply should not select a provider, got %v", *id)
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

func TestMarkFirstTextFromOpenAIResponsesDelta(t *testing.T) {
	requestLog := &ReqeustLog{startedAt: time.Now()}
	payload := `event: response.output_text.delta
data: {"type":"response.output_text.delta","delta":"你"}`

	markFirstTextFromSSEPayload(payload, requestLog)

	if requestLog.FirstTextSec <= 0 {
		t.Fatalf("expected FirstTextSec to be recorded")
	}
	if requestLog.FirstTokenDurationSec <= 0 {
		t.Fatalf("expected FirstTokenDurationSec to be recorded")
	}
}

func TestMarkFirstEventDoesNotSetFirstToken(t *testing.T) {
	requestLog := &ReqeustLog{startedAt: time.Now()}

	requestLog.markFirstEvent()

	if requestLog.FirstEventSec <= 0 {
		t.Fatalf("expected FirstEventSec to be recorded")
	}
	if requestLog.FirstTokenDurationSec != 0 {
		t.Fatalf("FirstTokenDurationSec = %f, want 0 before text", requestLog.FirstTokenDurationSec)
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
			"mistral/mistral-large":       true,
			"meta-llama/llama-3.1-405b":   true,
			"anthropic/claude-3.5-sonnet": true,
			"anthropic/claude-3.5-haiku":  true,
		},
		ModelMapping: map[string]string{
			"claude-*":  "anthropic/claude-*",
			"gpt-*":     "openai/gpt-*",
			"mistral-*": "mistral/mistral-*",
			"llama-*":   "meta-llama/llama-*",
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
		{"mistral-large", true, "mistral/mistral-large"},
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

func TestOpenAIChatParseTokenUsageFromResponse(t *testing.T) {
	var usage ReqeustLog

	OpenAIChatParseTokenUsageFromResponse(`{
		"usage": {
			"prompt_tokens": 7,
			"completion_tokens": 8,
			"total_tokens": 15,
			"prompt_tokens_details": {"cached_tokens": 3},
			"completion_tokens_details": {"reasoning_tokens": 4}
		}
	}`, &usage)

	if usage.InputTokens != 7 {
		t.Fatalf("InputTokens = %d, want 7", usage.InputTokens)
	}
	if usage.OutputTokens != 8 {
		t.Fatalf("OutputTokens = %d, want 8", usage.OutputTokens)
	}
	if usage.CacheReadTokens != 3 {
		t.Fatalf("CacheReadTokens = %d, want 3", usage.CacheReadTokens)
	}
	if usage.ReasoningTokens != 4 {
		t.Fatalf("ReasoningTokens = %d, want 4", usage.ReasoningTokens)
	}
}

func TestEnsureOpenAIChatStreamUsage(t *testing.T) {
	body := []byte(`{"model":"gpt-4","messages":[],"stream":true}`)

	updated := ensureOpenAIChatStreamUsage(body)

	if !gjson.GetBytes(updated, "stream_options.include_usage").Bool() {
		t.Fatalf("stream_options.include_usage was not injected: %s", string(updated))
	}
	if gjson.GetBytes(updated, "model").String() != "gpt-4" {
		t.Fatalf("model changed unexpectedly: %s", string(updated))
	}
}

func TestEnsureOpenAIChatStreamUsagePreservesExistingValue(t *testing.T) {
	body := []byte(`{"model":"gpt-4","stream_options":{"include_usage":true}}`)

	updated := ensureOpenAIChatStreamUsage(body)

	if string(updated) != string(body) {
		t.Fatalf("body changed unexpectedly: got %s want %s", string(updated), string(body))
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

// ==================== readResponseBody 测试 ====================

func TestReadResponseBodyClosesBody(t *testing.T) {
	// 使用自定义 ReadCloser 来验证 Close() 确实被调用
	tracker := &testReadCloser{Reader: strings.NewReader(`{"ok":true}`)}
	resp := &xrequest.Response{}
	resp.RawResponse = &http.Response{
		Body:       tracker,
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}

	data, err := readResponseBody(resp)
	if err != nil {
		t.Fatalf("readResponseBody failed: %v", err)
	}
	if string(data) != `{"ok":true}` {
		t.Fatalf("unexpected body: %s", data)
	}
	if !tracker.closed {
		t.Fatal("expected body to be closed after readResponseBody")
	}
}

// testReadCloser 是一个追踪 Close 调用的 io.ReadCloser
type testReadCloser struct {
	*strings.Reader
	closed bool
}

func (c *testReadCloser) Close() error {
	c.closed = true
	return nil
}

// ==================== parseNonStreamingTokens 测试 ====================

func TestParseNonStreamingTokensOpenAIChat(t *testing.T) {
	body := []byte(`{
		"id": "chatcmpl-123",
		"object": "chat.completion",
		"choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello!"}}],
		"usage": {
			"prompt_tokens": 10,
			"completion_tokens": 5,
			"total_tokens": 15
		}
	}`)

	log := &ReqeustLog{}
	OpenAIChatParseTokenUsageFromResponse(string(body), log)

	if log.InputTokens != 10 {
		t.Fatalf("expected InputTokens=10, got %d", log.InputTokens)
	}
	if log.OutputTokens != 5 {
		t.Fatalf("expected OutputTokens=5, got %d", log.OutputTokens)
	}
}

func TestParseNonStreamingTokensOpenAIChatNoUsage(t *testing.T) {
	body := []byte(`{
		"id": "chatcmpl-123",
		"object": "chat.completion",
		"choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello!"}}]
	}`)

	log := &ReqeustLog{}
	OpenAIChatParseTokenUsageFromResponse(string(body), log)

	// No usage field → tokens stay 0
	if log.InputTokens != 0 || log.OutputTokens != 0 {
		t.Fatalf("expected all tokens=0 without usage, got Input=%d Output=%d", log.InputTokens, log.OutputTokens)
	}
}

func TestParseNonStreamingTokensAnthropic(t *testing.T) {
	body := []byte(`{
		"id": "msg_123",
		"type": "message",
		"role": "assistant",
		"content": [{"type": "text", "text": "Hello!"}],
		"usage": {
			"input_tokens": 15,
			"output_tokens": 8
		}
	}`)

	log := &ReqeustLog{}
	parseNonStreamingTokens(body, "claude", log)

	if log.InputTokens != 15 {
		t.Fatalf("expected InputTokens=15, got %d", log.InputTokens)
	}
	if log.OutputTokens != 8 {
		t.Fatalf("expected OutputTokens=8, got %d", log.OutputTokens)
	}
}

// ==================== hasContentInResponse 测试 ====================

func TestHasContentInResponseOpenAIChatWithContent(t *testing.T) {
	body := []byte(`{
		"id": "chatcmpl-123",
		"choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello!"}}]
	}`)

	if !hasContentInResponse(body, "openai-chat") {
		t.Fatal("expected hasContent=true for OpenAI Chat with content")
	}
}

func TestHasContentInResponseOpenAIChatEmpty(t *testing.T) {
	body := []byte(`{
		"id": "chatcmpl-123",
		"choices": [{"index": 0, "message": {"role": "assistant", "content": ""}}]
	}`)

	if hasContentInResponse(body, "openai-chat") {
		t.Fatal("expected hasContent=false for OpenAI Chat with empty content")
	}
}

func TestHasContentInResponseOpenAIChatWithToolCalls(t *testing.T) {
	body := []byte(`{
		"id": "chatcmpl-123",
		"choices": [{"index": 0, "message": {"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "get_weather"}}]}}]
	}`)

	if !hasContentInResponse(body, "openai-chat") {
		t.Fatal("expected hasContent=true for OpenAI Chat with tool_calls")
	}
}

func TestHasContentInResponseOpenAIResponsesCodexOutputItems(t *testing.T) {
	for _, test := range []struct {
		name string
		item string
	}{
		{name: "image generation", item: `{"type":"image_generation_call","status":"completed","result":"Zm9v"}`},
		{name: "compaction", item: `{"type":"compaction","encrypted_content":"encrypted-summary"}`},
		{name: "compaction summary", item: `{"type":"compaction_summary","encrypted_content":"encrypted-summary"}`},
		{name: "reasoning encrypted", item: `{"type":"reasoning","summary":[],"encrypted_content":"encrypted-reasoning"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !hasContentInResponse([]byte(fmt.Sprintf(`{"output":[%s]}`, test.item)), "openai-responses") {
				t.Fatalf("expected valid Responses output item to contain useful content: %s", test.item)
			}
		})
	}

	if hasContentInResponse([]byte(`{"output":[{"type":"reasoning","summary":[]}]}`), "openai-responses") {
		t.Fatal("empty reasoning placeholder should not count as useful content")
	}
}

func TestHasContentInResponseAnthropicWithText(t *testing.T) {
	body := []byte(`{
		"id": "msg_123",
		"type": "message",
		"role": "assistant",
		"content": [{"type": "text", "text": "Hello!"}]
	}`)

	if !hasContentInResponse(body, "claude") {
		t.Fatal("expected hasContent=true for Anthropic with text")
	}
}

func TestHasContentInResponseAnthropicEmpty(t *testing.T) {
	body := []byte(`{
		"id": "msg_123",
		"type": "message",
		"role": "assistant",
		"content": []
	}`)

	if hasContentInResponse(body, "claude") {
		t.Fatal("expected hasContent=false for Anthropic with empty content")
	}
}

func TestHasContentInResponseAnthropicToolUse(t *testing.T) {
	body := []byte(`{
		"id": "msg_123",
		"type": "message",
		"role": "assistant",
		"content": [{"type": "tool_use", "id": "toolu_1", "name": "get_weather"}]
	}`)

	if !hasContentInResponse(body, "claude") {
		t.Fatal("expected hasContent=true for Anthropic with tool_use")
	}
}

// ==================== isEmptyShell 测试 ====================

func TestIsEmptyShellAllZero(t *testing.T) {
	log := &ReqeustLog{}
	if !log.isEmptyShell() {
		t.Fatal("expected isEmptyShell=true when all tokens are 0")
	}
}

func TestIsEmptyShellHasInput(t *testing.T) {
	log := &ReqeustLog{InputTokens: 10}
	if log.isEmptyShell() {
		t.Fatal("expected isEmptyShell=false when InputTokens > 0")
	}
}

func TestIsEmptyShellHasOutput(t *testing.T) {
	log := &ReqeustLog{OutputTokens: 5}
	if log.isEmptyShell() {
		t.Fatal("expected isEmptyShell=false when OutputTokens > 0")
	}
}

func TestIsEmptyShellHasCacheRead(t *testing.T) {
	log := &ReqeustLog{CacheReadTokens: 100}
	if log.isEmptyShell() {
		t.Fatal("expected isEmptyShell=false when CacheReadTokens > 0")
	}
}

func TestIsEmptyShellNil(t *testing.T) {
	var log *ReqeustLog
	if log.isEmptyShell() {
		t.Fatal("expected isEmptyShell=false for nil")
	}
}

// ==================== 空壳综合判定测试 ====================

func TestEmptyShellDetectionOpenAIChat(t *testing.T) {
	// 有内容但无 usage：不判空壳（模拟 forwardRequest 的判断条件）
	body := []byte(`{"choices":[{"message":{"content":"Hello!"}}]}`)
	log := &ReqeustLog{}
	OpenAIChatParseTokenUsageFromResponse(string(body), log)

	isShell := log.isEmptyShell() && !hasContentInResponse(body, "openai-chat")
	if isShell {
		t.Fatal("has content → should NOT be empty shell")
	}

	// 无内容且无 usage：判空壳
	body2 := []byte(`{"choices":[{"message":{"content":""}}]}`)
	log2 := &ReqeustLog{}
	OpenAIChatParseTokenUsageFromResponse(string(body2), log2)

	isShell2 := log2.isEmptyShell() && !hasContentInResponse(body2, "openai-chat")
	if !isShell2 {
		t.Fatal("no content and no usage → should be empty shell")
	}
}

func TestEmptyShellDetectionAnthropic(t *testing.T) {
	// 有内容：不判空壳
	body := []byte(`{"type":"message","content":[{"type":"text","text":"Hello!"}],"usage":{"input_tokens":0,"output_tokens":0}}`)
	log := &ReqeustLog{}
	parseNonStreamingTokens(body, "claude", log)

	isShell := log.isEmptyShell() && !hasContentInResponse(body, "claude")
	if isShell {
		t.Fatal("has text content → should NOT be empty shell")
	}

	// 无内容且 usage 全 0：判空壳
	body2 := []byte(`{"type":"message","content":[],"usage":{"input_tokens":0,"output_tokens":0}}`)
	log2 := &ReqeustLog{}
	parseNonStreamingTokens(body2, "claude", log2)

	isShell2 := log2.isEmptyShell() && !hasContentInResponse(body2, "claude")
	if !isShell2 {
		t.Fatal("no content and zero usage → should be empty shell")
	}
}

// ==================== errProviderEmptyShell 测试 ====================

func TestErrProviderEmptyShellIsDistinct(t *testing.T) {
	if errors.Is(errProviderEmptyShell, errClientAbort) {
		t.Fatal("errProviderEmptyShell should not be errClientAbort")
	}
	if errors.Is(errProviderEmptyShell, errCodexEmptyStream) {
		t.Fatal("errProviderEmptyShell should not be errCodexEmptyStream")
	}
}
