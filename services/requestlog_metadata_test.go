package services

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/daodao97/xgo/xdb"
	"github.com/gin-gonic/gin"
)

func TestCaptureResponseModelUsesProtocolMetadataOnly(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		parse func(string, *ReqeustLog)
		want  string
	}{
		{name: "anthropic message", body: `{"message":{"model":"claude-sonnet"}}`, parse: ClaudeCodeParseTokenUsageFromResponse, want: "claude-sonnet"},
		{name: "responses envelope", body: `{"response":{"model":"gpt-5"}}`, parse: CodexParseTokenUsageFromResponse, want: "gpt-5"},
		{name: "chat completion", body: `{"model":"gpt-4.1","choices":[{"delta":{"content":"hello"}}]}`, parse: OpenAIChatParseTokenUsageFromResponse, want: "gpt-4.1"},
		{name: "gemini version", body: `{"modelVersion":"gemini-2.5-pro"}`, parse: ClaudeCodeParseTokenUsageFromResponse, want: "gemini-2.5-pro"},
		{name: "content is ignored", body: `{"choices":[{"message":{"content":"model: fake","model":"fake"}}]}`, parse: OpenAIChatParseTokenUsageFromResponse, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry := &ReqeustLog{Model: "mapped-model", RequestedModel: "client-model"}
			tc.parse(tc.body, entry)
			if entry.ResponseModel != tc.want {
				t.Fatalf("response model = %q, want %q", entry.ResponseModel, tc.want)
			}
			if entry.Model != "mapped-model" || entry.RequestedModel != "client-model" {
				t.Fatalf("request identity changed: %+v", entry)
			}
		})
	}
}

func TestStartActiveRequestLogPreservesOriginalModelFromContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/v1/messages", nil)
	c.Set(requestedModelContextKey, "client-model")
	c.Set(relayKeyNameContextKey, "named-key")

	entry := (&ProviderRelayService{}).startActiveRequestLog(c, "claude", "mapped-model", false)
	if entry.RequestedModel != "client-model" {
		t.Fatalf("requested model = %q, want client-model", entry.RequestedModel)
	}
	if entry.Model != "mapped-model" || entry.RelayKeyName != "named-key" {
		t.Fatalf("unexpected request identity: %+v", entry)
	}
	defaultActiveRequestTracker.Finish(entry.ActiveRequestID)
}

func TestResponseModelObserverHandlesSplitEventsAndBoundsLargeLines(t *testing.T) {
	entry := &ReqeustLog{}
	observer := newResponseModelObserver(entry)
	observer.Write([]byte("data: {\"response\":{\"mod"))
	observer.Write([]byte("el\":\"split-model\"}}\n\n"))
	if entry.ResponseModel != "split-model" {
		t.Fatalf("response model = %q, want split-model", entry.ResponseModel)
	}

	entry.ResponseModel = ""
	observer.Write([]byte("data: {\"model\":\""))
	observer.Write(make([]byte, 8<<20))
	observer.Write([]byte("x\"}\n"))
	if entry.ResponseModel != "" {
		t.Fatalf("oversized line should not be parsed, got %q", entry.ResponseModel)
	}

	observer.Write([]byte("data:{\"model\":\"next-model\"}\n"))
	if entry.ResponseModel != "next-model" {
		t.Fatalf("response model = %q, want next-model", entry.ResponseModel)
	}
}

func TestForwardRequestPersistsRequestedAndResponseModels(t *testing.T) {
	setupCostServiceTestDB(t)
	if err := InitGlobalDBQueue(); err != nil {
		t.Fatal(err)
	}
	for _, stream := range []bool{false, true} {
		name := "metadata-json"
		body := `{"model":"upstream-returned","usage":{"input_tokens":3,"output_tokens":1},"content":[{"type":"text","text":"hello"}]}`
		contentType := "application/json"
		if stream {
			name = "metadata-sse"
			body = "data:{\"type\":\"message_start\",\"message\":{\"model\":\"upstream-returned\"}}\n\ndata: {\"type\":\"message_stop\"}\n\n"
			contentType = "text/event-stream"
		}
		t.Run(name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", contentType)
				_, _ = io.WriteString(w, body)
			}))
			defer upstream.Close()

			prs := &ProviderRelayService{httpClient: newRelayHTTPClient()}
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			requestBody := []byte(`{"model":"mapped-model","messages":[],"max_tokens":10}`)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(requestBody))
			c.Set(requestedModelContextKey, "client-model")
			c.Set(relayUserIDContextKey, "metadata-user")
			c.Set(relayKeyIDContextKey, "metadata-key")
			c.Set(relayKeyNameContextKey, "named key")
			ok, err := prs.forwardRequest(c, "claude", Provider{Name: name, APIURL: upstream.URL}, "/v1/messages", nil, http.Header{"Content-Type": {"application/json"}}, requestBody, stream, "mapped-model")
			if err != nil || !ok {
				t.Fatalf("forward request: ok=%t err=%v", ok, err)
			}
			if recorder.Body.String() != body {
				t.Fatal("response body changed")
			}
			db, err := xdb.DB("default")
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				var requested, mapped, response, keyName string
				err := db.QueryRow(`SELECT requested_model, model, response_model, relay_key_name FROM request_log WHERE user_id = ? AND provider = ? ORDER BY id DESC LIMIT 1`, "metadata-user", name).Scan(&requested, &mapped, &response, &keyName)
				if err == nil {
					if requested != "client-model" || mapped != "mapped-model" || response != "upstream-returned" || keyName != "named key" {
						t.Fatalf("persisted model metadata: requested=%q mapped=%q response=%q key=%q", requested, mapped, response, keyName)
					}
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("timed out waiting for persisted log: %v", err)
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}
