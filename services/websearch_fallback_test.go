package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

func TestDetectClaudeWebSearchFallbackRequest(t *testing.T) {
	body := []byte(`{
		"model": "claude-sonnet-4-6",
		"system": "You are an assistant for performing a web search tool use",
		"messages": [
			{
				"role": "user",
				"content": [
					{"type":"text","text":"Perform a web search for the query: Anthropic Claude Code documentation April 2026"}
				]
			}
		],
		"tools": [
			{
				"type":"web_search_20250305",
				"name":"web_search",
				"allowed_domains":["docs.anthropic.com","https://www.anthropic.com"],
				"blocked_domains":["status.anthropic.com"]
			}
		]
	}`)

	request, ok := detectClaudeWebSearchFallbackRequest(body)
	if !ok {
		t.Fatalf("expected fallback request to be detected")
	}
	if request.Query != "Anthropic Claude Code documentation April 2026" {
		t.Fatalf("query = %q", request.Query)
	}
	if request.ToolType != "web_search_20250305" {
		t.Fatalf("tool type = %q", request.ToolType)
	}
	if request.ToolName != "web_search" {
		t.Fatalf("tool name = %q", request.ToolName)
	}
	if !reflect.DeepEqual(request.AllowedDomains, []string{"docs.anthropic.com", "www.anthropic.com"}) {
		t.Fatalf("allowed domains = %#v", request.AllowedDomains)
	}
	if !reflect.DeepEqual(request.BlockedDomains, []string{"status.anthropic.com"}) {
		t.Fatalf("blocked domains = %#v", request.BlockedDomains)
	}
}

func TestDetectClaudeWebSearchFallbackRequestRejectsRegularPrompt(t *testing.T) {
	body := []byte(`{
		"messages": [
			{
				"role": "user",
				"content": [
					{"type":"text","text":"Search it for me"}
				]
			}
		],
		"tools": [
			{"type":"web_search_20250305","name":"web_search"}
		]
	}`)

	if _, ok := detectClaudeWebSearchFallbackRequest(body); ok {
		t.Fatalf("expected regular prompt not to trigger fallback")
	}
}

func TestParseBingSearchResultsHTML(t *testing.T) {
	html := `
<html><body>
<ul>
  <li class="b_algo">
    <h2><a href="https://www.bing.com/ck/a?!&&p=abc&u=a1aHR0cHM6Ly9kb2NzLmFudGhyb3BpYy5jb20vZW4vZG9jcy9jbGF1ZGUtY29kZQ&ntb=1">Claude Code overview - Anthropic</a></h2>
    <div class="b_caption"><p>Official Claude Code documentation.</p></div>
  </li>
  <li class="b_algo">
    <h2><a href="https://docs.anthropic.com/en/docs/claude-code/tutorials">Claude Code tutorials</a></h2>
    <div class="b_caption"><p>Getting started with Claude Code workflows.</p></div>
  </li>
</ul>
</body></html>`

	results, err := parseBingSearchResultsHTML(html, 5)
	if err != nil {
		t.Fatalf("parseBingSearchResultsHTML returned error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].URL != "https://docs.anthropic.com/en/docs/claude-code" {
		t.Fatalf("unexpected first url: %q", results[0].URL)
	}
	if !strings.Contains(results[0].Snippet, "Official Claude Code documentation") {
		t.Fatalf("unexpected first snippet: %q", results[0].Snippet)
	}
}

func TestNormalizeBingResultURL(t *testing.T) {
	rawURL := "https://www.bing.com/ck/a?!&&p=abc&u=a1aHR0cHM6Ly9kb2NzLmFudGhyb3BpYy5jb20vZW4vZG9jcy9jbGF1ZGUtY29kZQ&ntb=1"
	if got := normalizeBingResultURL(rawURL); got != "https://docs.anthropic.com/en/docs/claude-code" {
		t.Fatalf("normalizeBingResultURL() = %q", got)
	}
}

func TestParseBochaWebSearchResults(t *testing.T) {
	body := []byte(`{
		"code": 200,
		"msg": null,
		"data": {
			"webPages": {
				"value": [
					{
						"name": "Claude Code 概览 - Claude Code Docs",
						"url": "https://code.claude.com/docs/zh-CN/overview",
						"snippet": "了解 Claude Code。",
						"summary": "Claude Code 概览的详细介绍。"
					},
					{
						"name": "Claude Code 概览 - Claude Code Docs",
						"url": "https://code.claude.com/docs/zh-CN/overview",
						"snippet": "duplicate"
					},
					{
						"name": "Claude Code overview - Anthropic",
						"url": "https://docs.anthropic.com/en/docs/claude-code",
						"summary": "Official Claude Code documentation."
					}
				]
			}
		}
	}`)

	results, err := parseBochaWebSearchResults(body)
	if err != nil {
		t.Fatalf("parseBochaWebSearchResults returned error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].URL != "https://code.claude.com/docs/zh-CN/overview" {
		t.Fatalf("unexpected first url: %q", results[0].URL)
	}
	if results[0].Snippet != "了解 Claude Code。" {
		t.Fatalf("unexpected first snippet: %q", results[0].Snippet)
	}
	if results[1].Snippet != "Official Claude Code documentation." {
		t.Fatalf("unexpected second snippet: %q", results[1].Snippet)
	}
}

func TestFilterWebSearchResultsByDomains(t *testing.T) {
	results := []webSearchResult{
		{Title: "Docs", URL: "https://docs.anthropic.com/en/docs/claude-code"},
		{Title: "Status", URL: "https://status.anthropic.com/"},
		{Title: "Example", URL: "https://example.com/"},
	}

	filtered := filterWebSearchResultsByDomains(results, []string{"anthropic.com"}, []string{"status.anthropic.com"})
	if len(filtered) != 1 {
		t.Fatalf("expected 1 filtered result, got %d", len(filtered))
	}
	if filtered[0].URL != "https://docs.anthropic.com/en/docs/claude-code" {
		t.Fatalf("unexpected filtered result: %#v", filtered[0])
	}
}

func TestFilterWebSearchResultsByDomainsAppliesDefaultBlockedDomains(t *testing.T) {
	results := []webSearchResult{
		{Title: "CSDN", URL: "https://blog.csdn.net/example/article/details/1"},
		{Title: "Cnblogs", URL: "https://www.cnblogs.com/example/p/1.html"},
		{Title: "Docs", URL: "https://docs.anthropic.com/en/docs/claude-code"},
	}

	filtered := filterWebSearchResultsByDomains(results, nil, nil)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 filtered result, got %d", len(filtered))
	}
	if filtered[0].URL != "https://docs.anthropic.com/en/docs/claude-code" {
		t.Fatalf("unexpected filtered result: %#v", filtered[0])
	}
}

func TestBuildBackendWebSearchQuery(t *testing.T) {
	t.Run("no domains keeps original query", func(t *testing.T) {
		request := claudeWebSearchFallbackRequest{Query: "SQLite documentation"}
		if got := buildBackendWebSearchQuery(request); got != "SQLite documentation -site:csdn.net -site:cnblogs.com" {
			t.Fatalf("buildBackendWebSearchQuery() = %q", got)
		}
	})

	t.Run("single allowed domain uses site prefix", func(t *testing.T) {
		request := claudeWebSearchFallbackRequest{
			Query:          "SQLite documentation",
			AllowedDomains: []string{"sqlite.org"},
		}
		if got := buildBackendWebSearchQuery(request); got != "site:sqlite.org SQLite documentation -site:csdn.net -site:cnblogs.com" {
			t.Fatalf("buildBackendWebSearchQuery() = %q", got)
		}
	})

	t.Run("multiple allowed domains use bing or syntax", func(t *testing.T) {
		request := claudeWebSearchFallbackRequest{
			Query:          "Claude API overview",
			AllowedDomains: []string{"docs.anthropic.com", "code.claude.com"},
		}
		if got := buildBackendWebSearchQuery(request); got != "site:docs.anthropic.com OR site:code.claude.com Claude API overview -site:csdn.net -site:cnblogs.com" {
			t.Fatalf("buildBackendWebSearchQuery() = %q", got)
		}
	})

	t.Run("custom blocked domains merge with defaults", func(t *testing.T) {
		request := claudeWebSearchFallbackRequest{
			Query:          "Claude API overview",
			BlockedDomains: []string{"qq.com"},
		}
		if got := buildBackendWebSearchQuery(request); got != "Claude API overview -site:csdn.net -site:cnblogs.com -site:qq.com" {
			t.Fatalf("buildBackendWebSearchQuery() = %q", got)
		}
	})
}

func TestDeriveEffectiveClaudeWebSearchRequestExtractsSiteOperators(t *testing.T) {
	request := deriveEffectiveClaudeWebSearchRequest(claudeWebSearchFallbackRequest{
		Query:          "site:docs.kernel.org scheduler docs",
		AllowedDomains: []string{"kernel.org"},
	})

	if request.Query != "scheduler docs" {
		t.Fatalf("query = %q", request.Query)
	}
	if !reflect.DeepEqual(request.AllowedDomains, []string{"kernel.org", "docs.kernel.org"}) {
		t.Fatalf("allowed domains = %#v", request.AllowedDomains)
	}
}

func TestRunBingSearchQueriesPrefersHigherQualityVariant(t *testing.T) {
	originalBingWebSearch := executeBingWebSearch
	defer func() {
		executeBingWebSearch = originalBingWebSearch
	}()

	executeBingWebSearch = func(ctx context.Context, query string, maxResults int) ([]webSearchResult, error) {
		switch query {
		case "OpenAI API docs -site:csdn.net -site:cnblogs.com":
			return []webSearchResult{
				{
					Title:   "OpenAI solved NPC AI driving in video games half a decade ago",
					URL:     "https://forums.cdprojektred.com/threads/openai-solved",
					Snippet: "Forum thread mentioning OpenAI.",
				},
			}, nil
		case "OpenAI API documentation -site:csdn.net -site:cnblogs.com":
			return []webSearchResult{
				{
					Title:   "OpenAI Python API library - GitHub",
					URL:     "https://github.com/openai/openai-python",
					Snippet: "The official OpenAI API library for Python.",
				},
				{
					Title:   "Azure OpenAI Responses API",
					URL:     "https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/responses",
					Snippet: "Responses API documentation.",
				},
			}, nil
		default:
			return nil, nil
		}
	}

	results, err := runBingSearchQueries(context.Background(), []string{
		"OpenAI API docs -site:csdn.net -site:cnblogs.com",
		"OpenAI API documentation -site:csdn.net -site:cnblogs.com",
	}, claudeWebSearchFallbackRequest{
		Query: "OpenAI API docs",
	}, 5)
	if err != nil {
		t.Fatalf("runBingSearchQueries returned error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 merged results, got %d", len(results))
	}
	if results[0].URL != "https://github.com/openai/openai-python" {
		t.Fatalf("expected best-ranked result first, got %#v", results[0])
	}
	if results[len(results)-1].URL != "https://forums.cdprojektred.com/threads/openai-solved" {
		t.Fatalf("expected low-value forum result to rank last, got %#v", results[len(results)-1])
	}
}

func TestRunClaudeWebSearchUsesPerDomainBingQueriesForMultipleAllowedDomains(t *testing.T) {
	originalBingWebSearch := executeBingWebSearch
	defer func() {
		executeBingWebSearch = originalBingWebSearch
	}()

	var queries []string
	executeBingWebSearch = func(ctx context.Context, query string, maxResults int) ([]webSearchResult, error) {
		queries = append(queries, query)
		switch {
		case strings.HasPrefix(query, "site:docs.anthropic.com "):
			return []webSearchResult{
				{Title: "Docs", URL: "https://docs.anthropic.com/en/docs/intro-to-claude"},
			}, nil
		case strings.HasPrefix(query, "site:code.claude.com "):
			return []webSearchResult{
				{Title: "Claude Code", URL: "https://code.claude.com/docs/zh-CN/overview"},
			}, nil
		default:
			return nil, nil
		}
	}

	results, err := runClaudeWebSearch(context.Background(), claudeWebSearchFallbackRequest{
		Query:          "Claude API overview",
		AllowedDomains: []string{"docs.anthropic.com", "code.claude.com"},
	}, 5)
	if err != nil {
		t.Fatalf("runClaudeWebSearch returned error: %v", err)
	}
	if len(queries) != 4 {
		t.Fatalf("expected 4 bing queries, got %d: %#v", len(queries), queries)
	}
	if queries[0] != "site:docs.anthropic.com Claude API overview -site:csdn.net -site:cnblogs.com" {
		t.Fatalf("unexpected first query: %q", queries[0])
	}
	if queries[1] != "site:docs.anthropic.com -site:csdn.net -site:cnblogs.com" {
		t.Fatalf("unexpected second query: %q", queries[1])
	}
	if queries[2] != "site:code.claude.com Claude API overview -site:csdn.net -site:cnblogs.com" {
		t.Fatalf("unexpected third query: %q", queries[2])
	}
	if queries[3] != "site:code.claude.com -site:csdn.net -site:cnblogs.com" {
		t.Fatalf("unexpected fourth query: %q", queries[3])
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 merged results, got %d", len(results))
	}
}

func TestRunClaudeWebSearchFallsBackToDomainOnlyBingQuery(t *testing.T) {
	originalBingWebSearch := executeBingWebSearch
	defer func() {
		executeBingWebSearch = originalBingWebSearch
	}()

	var queries []string
	executeBingWebSearch = func(ctx context.Context, query string, maxResults int) ([]webSearchResult, error) {
		queries = append(queries, query)
		if query == "site:code.claude.com -site:csdn.net -site:cnblogs.com" {
			return []webSearchResult{
				{Title: "Claude Code 概览 - Claude Code Docs", URL: "https://code.claude.com/docs/zh-CN/overview"},
			}, nil
		}
		return nil, nil
	}

	results, err := runClaudeWebSearch(context.Background(), claudeWebSearchFallbackRequest{
		Query:          "Claude API overview",
		AllowedDomains: []string{"code.claude.com"},
	}, 5)
	if err != nil {
		t.Fatalf("runClaudeWebSearch returned error: %v", err)
	}
	if len(queries) != 2 {
		t.Fatalf("expected 2 bing queries, got %d: %#v", len(queries), queries)
	}
	if queries[0] != "site:code.claude.com Claude API overview -site:csdn.net -site:cnblogs.com" {
		t.Fatalf("unexpected first query: %q", queries[0])
	}
	if queries[1] != "site:code.claude.com -site:csdn.net -site:cnblogs.com" {
		t.Fatalf("unexpected fallback query: %q", queries[1])
	}
	if len(results) != 1 || results[0].URL != "https://code.claude.com/docs/zh-CN/overview" {
		t.Fatalf("unexpected results: %#v", results)
	}
}

func TestIsSupportedBingHost(t *testing.T) {
	if !isSupportedBingHost("www.bing.com") {
		t.Fatal("expected www.bing.com to be treated as supported bing host")
	}
	if !isSupportedBingHost("cn.bing.com") {
		t.Fatal("expected cn.bing.com to be treated as supported bing host")
	}
	if isSupportedBingHost("example.com") {
		t.Fatal("expected example.com not to be treated as supported bing host")
	}
}

func TestBingWebSearchPrimesSessionAndReusesCookies(t *testing.T) {
	var primeCount int32
	var searchCount int32
	var sawPrimeCookie int32
	var sawReferer int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/prime":
			atomic.AddInt32(&primeCount, 1)
			http.SetCookie(w, &http.Cookie{Name: "MUID", Value: "test-session", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "_HPVN", Value: "1", Path: "/"})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>primed</body></html>"))
		case "/search":
			atomic.AddInt32(&searchCount, 1)
			if cookie, err := r.Cookie("MUID"); err == nil && cookie.Value == "test-session" {
				atomic.StoreInt32(&sawPrimeCookie, 1)
			}
			if got := r.Header.Get("Referer"); got != "" {
				atomic.StoreInt32(&sawReferer, 1)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`
<html><body>
<ul>
  <li class="b_algo">
    <h2><a href="https://sqlite.org/docs.html">SQLite Documentation</a></h2>
    <div class="b_caption"><p>Official SQLite docs.</p></div>
  </li>
</ul>
</body></html>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	originalPrimeURL := bingPrimeURL
	originalSearchURL := bingSearchURL
	originalValidateHost := validateBingResponseHost
	bingSessionMu.Lock()
	originalClient := bingSessionClient
	originalPrimedAt := bingSessionPrimedAt
	bingSessionClient = nil
	bingSessionPrimedAt = time.Time{}
	bingSessionMu.Unlock()

	bingPrimeURL = server.URL + "/prime"
	bingSearchURL = server.URL + "/search"
	validateBingResponseHost = func(host string) bool { return true }

	defer func() {
		bingPrimeURL = originalPrimeURL
		bingSearchURL = originalSearchURL
		validateBingResponseHost = originalValidateHost
		bingSessionMu.Lock()
		bingSessionClient = originalClient
		bingSessionPrimedAt = originalPrimedAt
		bingSessionMu.Unlock()
	}()

	results, err := bingWebSearch(context.Background(), "SQLite official documentation", 3)
	if err != nil {
		t.Fatalf("bingWebSearch returned error: %v", err)
	}
	if atomic.LoadInt32(&primeCount) == 0 {
		t.Fatal("expected bing session to be primed before search")
	}
	if atomic.LoadInt32(&searchCount) == 0 {
		t.Fatal("expected search endpoint to be called")
	}
	if atomic.LoadInt32(&sawPrimeCookie) == 0 {
		t.Fatal("expected search request to reuse cookie from prime request")
	}
	if atomic.LoadInt32(&sawReferer) == 0 {
		t.Fatal("expected search request referer to be set")
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 search result, got %d", len(results))
	}
	if results[0].URL != "https://sqlite.org/docs.html" {
		t.Fatalf("unexpected result url: %q", results[0].URL)
	}
}

func TestBuildAllowedDomainFallbackResults(t *testing.T) {
	results := buildAllowedDomainFallbackResults([]string{"docs.anthropic.com", "code.claude.com", "docs.anthropic.com"})
	if len(results) != 2 {
		t.Fatalf("expected 2 fallback results, got %d", len(results))
	}
	if results[0].URL != "https://docs.anthropic.com/" {
		t.Fatalf("unexpected first fallback url: %q", results[0].URL)
	}
	if results[1].URL != "https://code.claude.com/" {
		t.Fatalf("unexpected second fallback url: %q", results[1].URL)
	}
}

func TestWriteClaudeWebSearchFallbackSSE(t *testing.T) {
	recorder := httptest.NewRecorder()
	requestLog := &ReqeustLog{}
	request := claudeWebSearchFallbackRequest{
		Query:          "Claude Code",
		AllowedDomains: []string{"docs.anthropic.com"},
		ToolType:       "web_search_20250305",
		ToolName:       "web_search",
	}
	results := []webSearchResult{
		{
			Title: "Docs",
			URL:   "https://docs.anthropic.com/en/docs/claude-code",
		},
	}

	err := writeClaudeWebSearchFallbackSSE(recorder, "gpt-5.4", request, results, requestLog)
	if err != nil {
		t.Fatalf("writeClaudeWebSearchFallbackSSE returned error: %v", err)
	}

	body := recorder.Body.String()
	for _, want := range []string{
		"event: message_start",
		"event: content_block_start",
		"event: content_block_delta",
		`"type":"server_tool_use"`,
		`"type":"input_json_delta"`,
		`"type":"web_search_tool_result"`,
		`"type":"search_result"`,
		`"tool_use_id":"srvtoolu_`,
		"https://docs.anthropic.com",
		"event: message_stop",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected SSE body to contain %q, got %s", want, body)
		}
	}
	if requestLog.HttpCode != 200 {
		t.Fatalf("requestLog.HttpCode = %d, want 200", requestLog.HttpCode)
	}
}

func TestIsUnsupportedWebSearchToolError(t *testing.T) {
	if !isUnsupportedWebSearchToolError(nil, assertableError("upstream status 400: {\"detail\":\"Unsupported tool type: web_search_preview\"}")) {
		t.Fatalf("expected unsupported tool type error to be detected")
	}
}

func TestClaudeWebSearchFallbackProxyHandlerJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	originalRunClaudeWebSearch := runClaudeWebSearch
	runClaudeWebSearch = func(ctx context.Context, request claudeWebSearchFallbackRequest, maxResults int) ([]webSearchResult, error) {
		return []webSearchResult{
			{
				Title:   "Claude Code overview - Anthropic",
				URL:     "https://docs.anthropic.com/en/docs/claude-code",
				Snippet: "Official Claude Code documentation.",
			},
		}, nil
	}
	defer func() {
		runClaudeWebSearch = originalRunClaudeWebSearch
	}()

	var upstreamCalled int32
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.StoreInt32(&upstreamCalled, 1)
		http.Error(w, `{"detail":"should not call upstream"}`, http.StatusBadGateway)
	}))
	defer upstreamServer.Close()

	providerService, relayService := newTestRelayService(t)
	err := providerService.SaveProviders("claude", []Provider{
		{
			ID:                   1,
			Name:                 "test-openai-responses",
			APIURL:               upstreamServer.URL,
			APIKey:               "test-upstream-key",
			Enabled:              true,
			APIEndpoint:          "/v1/responses",
			ModelMapping:         map[string]string{"claude-*": "gpt-5.4"},
			Level:                1,
			ConnectivityAuthType: "bearer",
			UpstreamProtocol:     "openai_chat",
			SupportsWebSearch:    true,
		},
	})
	if err != nil {
		t.Fatalf("SaveProviders failed: %v", err)
	}

	router := gin.New()
	relayService.registerRoutes(router)
	relayKey, err := relayService.codexRelayKeys.EnsureDefaultKey()
	if err != nil {
		t.Fatalf("EnsureDefaultKey failed: %v", err)
	}

	body := `{
		"model":"claude-sonnet-4-6",
		"max_tokens":256,
		"stream":false,
		"messages":[
			{
				"role":"user",
				"content":[
					{"type":"text","text":"Perform a web search for the query: Anthropic Claude Code documentation April 2026"}
				]
			}
		],
		"tools":[
			{"type":"web_search_20250305","name":"web_search"}
		]
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", relayKey.Key)
	req.Header.Set("anthropic-version", "2023-06-01")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(&upstreamCalled) != 0 {
		t.Fatalf("expected local fallback to bypass upstream")
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q", got)
	}
	bodyText := w.Body.String()
	if got := gjson.Get(bodyText, "content.0.type").String(); got != "server_tool_use" {
		t.Fatalf("content[0].type = %q, body = %s", got, bodyText)
	}
	toolUseID := gjson.Get(bodyText, "content.0.id").String()
	if !strings.HasPrefix(toolUseID, "srvtoolu_") {
		t.Fatalf("unexpected tool_use_id = %q, body = %s", toolUseID, bodyText)
	}
	if got := gjson.Get(bodyText, "content.1.type").String(); got != "web_search_tool_result" {
		t.Fatalf("content[1].type = %q, body = %s", got, bodyText)
	}
	if got := gjson.Get(bodyText, "content.1.tool_use_id").String(); got != toolUseID {
		t.Fatalf("content[1].tool_use_id = %q, want %q", got, toolUseID)
	}
	if got := gjson.Get(bodyText, "content.1.content.0.url").String(); got != "https://docs.anthropic.com/en/docs/claude-code" {
		t.Fatalf("content[1].content[0].url = %q, body = %s", got, bodyText)
	}
	if got := gjson.Get(bodyText, "usage.server_tool_use.web_search_requests").Int(); got != 1 {
		t.Fatalf("usage.server_tool_use.web_search_requests = %d, body = %s", got, bodyText)
	}
}

func TestClaudeWebSearchFallbackProxyHandlerSSE(t *testing.T) {
	gin.SetMode(gin.TestMode)

	originalRunClaudeWebSearch := runClaudeWebSearch
	runClaudeWebSearch = func(ctx context.Context, request claudeWebSearchFallbackRequest, maxResults int) ([]webSearchResult, error) {
		return []webSearchResult{
			{
				Title:   "Claude Code overview - Anthropic",
				URL:     "https://docs.anthropic.com/en/docs/claude-code",
				Snippet: "Official Claude Code documentation.",
			},
		}, nil
	}
	defer func() {
		runClaudeWebSearch = originalRunClaudeWebSearch
	}()

	var upstreamCalled int32
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.StoreInt32(&upstreamCalled, 1)
		http.Error(w, `{"detail":"should not call upstream"}`, http.StatusBadGateway)
	}))
	defer upstreamServer.Close()

	providerService, relayService := newTestRelayService(t)
	err := providerService.SaveProviders("claude", []Provider{
		{
			ID:                   1,
			Name:                 "test-openai-responses",
			APIURL:               upstreamServer.URL,
			APIKey:               "test-upstream-key",
			Enabled:              true,
			APIEndpoint:          "/v1/responses",
			ModelMapping:         map[string]string{"claude-*": "gpt-5.4"},
			Level:                1,
			ConnectivityAuthType: "bearer",
			UpstreamProtocol:     "openai_chat",
			SupportsWebSearch:    true,
		},
	})
	if err != nil {
		t.Fatalf("SaveProviders failed: %v", err)
	}

	router := gin.New()
	relayService.registerRoutes(router)
	relayKey, err := relayService.codexRelayKeys.EnsureDefaultKey()
	if err != nil {
		t.Fatalf("EnsureDefaultKey failed: %v", err)
	}

	body := `{
		"model":"claude-sonnet-4-6",
		"max_tokens":256,
		"stream":true,
		"messages":[
			{
				"role":"user",
				"content":[
					{"type":"text","text":"Perform a web search for the query: Anthropic Claude Code documentation April 2026"}
				]
			}
		],
		"tools":[
			{"type":"web_search_20250305","name":"web_search"}
		]
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", relayKey.Key)
	req.Header.Set("anthropic-version", "2023-06-01")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(&upstreamCalled) != 0 {
		t.Fatalf("expected local fallback to bypass upstream")
	}
	if got := w.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("content type = %q", got)
	}
	bodyText := w.Body.String()
	for _, want := range []string{
		"event: message_start",
		`"type":"server_tool_use"`,
		"event: content_block_delta",
		`"type":"input_json_delta"`,
		`"type":"web_search_tool_result"`,
		"https://docs.anthropic.com/en/docs/claude-code",
		"event: message_stop",
	} {
		if !strings.Contains(bodyText, want) {
			t.Fatalf("expected SSE body to contain %q, got %s", want, bodyText)
		}
	}
}

type assertableError string

func (e assertableError) Error() string {
	return string(e)
}
