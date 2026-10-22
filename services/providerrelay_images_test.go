package services

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// ==================== Images 协议端点解析 ====================

func TestProviderImagesEndpointResolution(t *testing.T) {
	provider := Provider{
		APIEndpoint:    "/legacy",
		ImagesEndpoint: "/custom/images",
	}

	for _, route := range []string{"/images/generations", "/images/edits"} {
		if got := provider.GetEffectiveEndpoint(route); got != "/custom/images" {
			t.Fatalf("GetEffectiveEndpoint(%q) = %q, want /custom/images", route, got)
		}
	}

	// 未配置 ImagesEndpoint 时，回落到平台默认端点而不是 APIEndpoint
	fallback := Provider{}
	if got := fallback.GetEffectiveEndpoint("/images/generations"); got != "/images/generations" {
		t.Fatalf("default images endpoint = %q, want /images/generations", got)
	}
}

func TestProviderFilePathForImagesPlatform(t *testing.T) {
	dir := t.TempDir()
	path, err := providerFilePathInDir(dir, "openai-images")
	if err != nil {
		t.Fatalf("providerFilePathInDir: %v", err)
	}
	if want := filepath.Join(dir, "openai-images.json"); path != want {
		t.Fatalf("images provider path = %q, want %q", path, want)
	}
	if got := providerPlatformForPool("OpenAI-Images"); got != "openai-images" {
		t.Fatalf("providerPlatformForPool = %q, want openai-images", got)
	}
}

// ==================== Images 响应判定与用量解析 ====================

func TestHasContentInResponseOpenAIImages(t *testing.T) {
	withBase64 := []byte(`{"created":1700000000,"data":[{"b64_json":"aW1hZ2U="}]}`)
	if !hasContentInResponse(withBase64, "openai-images") {
		t.Fatal("expected b64_json payload to count as content")
	}

	withURL := []byte(`{"data":[{"url":"https://example.com/a.png"}]}`)
	if !hasContentInResponse(withURL, "openai-images") {
		t.Fatal("expected url payload to count as content")
	}

	emptyData := []byte(`{"data":[]}`)
	if hasContentInResponse(emptyData, "openai-images") {
		t.Fatal("expected empty data array to count as empty shell")
	}

	noPayload := []byte(`{"data":[{"revised_prompt":"a cat"}]}`)
	if hasContentInResponse(noPayload, "openai-images") {
		t.Fatal("expected data item without image payload to count as empty shell")
	}
}

func TestParseNonStreamingTokensOpenAIImages(t *testing.T) {
	body := []byte(`{
		"created": 1700000000,
		"data": [{"b64_json": "aW1hZ2U="}],
		"usage": {"input_tokens": 12, "output_tokens": 343, "total_tokens": 355}
	}`)
	logEntry := &ReqeustLog{}
	parseNonStreamingTokens(body, "openai-images", logEntry)

	if logEntry.InputTokens != 12 || logEntry.OutputTokens != 343 {
		t.Fatalf("usage = (%d, %d), want (12, 343)", logEntry.InputTokens, logEntry.OutputTokens)
	}
}

// ==================== Images 端到端转发 ====================

func TestOpenAIImagesGenerationRelay(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody []byte

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"created":1700000000,"data":[{"b64_json":"aW1hZ2U="}],"usage":{"input_tokens":12,"output_tokens":343,"total_tokens":355}}`)
	}))
	defer upstream.Close()

	providerID := int64(7)
	providers := []Provider{{
		ID:              providerID,
		Name:            "image-upstream",
		Enabled:         true,
		APIURL:          upstream.URL,
		APIKey:          "sk-upstream",
		SupportedModels: map[string]bool{"gpt-image-2": true},
	}}
	pool := &ProviderPool{
		Platform: "openai-images",
		Name:     "Images",
		Mode:     ProviderPoolModeManaged,
		Members:  []ProviderPoolMember{{ProviderID: providerID, Enabled: true}},
	}

	_, router, relayKey, _ := setupProviderPoolHTTPTest(t, "openai-images", providers, pool)

	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations",
		strings.NewReader(`{"model":"gpt-image-2","prompt":"a ginger cat"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+relayKey)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	if gotPath != "/images/generations" {
		t.Fatalf("upstream path = %q, want /images/generations", gotPath)
	}
	if gotAuth != "Bearer sk-upstream" {
		t.Fatalf("upstream auth = %q, want Bearer sk-upstream", gotAuth)
	}
	if !strings.Contains(string(gotBody), `"a ginger cat"`) {
		t.Fatalf("upstream body did not carry prompt: %s", gotBody)
	}
	if !strings.Contains(w.Body.String(), "aW1hZ2U=") {
		t.Fatalf("client body lost b64_json payload: %s", w.Body.String())
	}
}

func TestOpenAIImagesRejectsStreamFlag(t *testing.T) {
	// 客户端误传 stream=true 时，协议仍应按一次性 JSON 处理，不得走 SSE 分支。
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":[{"b64_json":"aW1hZ2U="}],"usage":{"input_tokens":1,"output_tokens":343}}`)
	}))
	defer upstream.Close()

	providerID := int64(8)
	providers := []Provider{{
		ID: providerID, Name: "image-upstream", Enabled: true,
		APIURL: upstream.URL, APIKey: "sk-upstream",
		SupportedModels: map[string]bool{"gpt-image-2": true},
	}}
	pool := &ProviderPool{
		Platform: "openai-images",
		Name:     "Images",
		Mode:     ProviderPoolModeManaged,
		Members:  []ProviderPoolMember{{ProviderID: providerID, Enabled: true}},
	}

	_, router, relayKey, _ := setupProviderPoolHTTPTest(t, "openai-images", providers, pool)

	req := httptest.NewRequest(http.MethodPost, "/images/generations",
		strings.NewReader(`{"model":"gpt-image-2","prompt":"cat","stream":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+relayKey)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	if gotPath != "/images/generations" {
		t.Fatalf("upstream path = %q, want /images/generations", gotPath)
	}
	if strings.Contains(w.Body.String(), "data:") {
		t.Fatalf("images response must stay plain JSON, got SSE: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "aW1hZ2U=") {
		t.Fatalf("client body lost b64_json payload: %s", w.Body.String())
	}
}

func TestOpenAIImagesEditsRouteToImagesEndpoint(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":[{"b64_json":"ZWRpdGVk"}]}`)
	}))
	defer upstream.Close()

	providerID := int64(9)
	providers := []Provider{{
		ID: providerID, Name: "image-upstream", Enabled: true,
		APIURL: upstream.URL, APIKey: "sk-upstream",
		SupportedModels: map[string]bool{"gpt-image-2": true},
	}}
	pool := &ProviderPool{
		Platform: "openai-images",
		Name:     "Images",
		Mode:     ProviderPoolModeManaged,
		Members:  []ProviderPoolMember{{ProviderID: providerID, Enabled: true}},
	}

	_, router, relayKey, _ := setupProviderPoolHTTPTest(t, "openai-images", providers, pool)

	req := httptest.NewRequest(http.MethodPost, "/v1/images/edits",
		strings.NewReader(`{"model":"gpt-image-2","prompt":"repaint","images":[{"image_url":"data:image/png;base64,AAAA"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+relayKey)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	if gotPath != "/images/edits" {
		t.Fatalf("upstream path = %q, want /images/edits", gotPath)
	}
}
