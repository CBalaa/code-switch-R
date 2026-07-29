package services

import (
	"bufio"
	"context"
	"encoding/json"
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

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

func setupProviderPoolHTTPTest(t *testing.T, platform string, providers []Provider, pool *ProviderPool) (*ProviderRelayService, *gin.Engine, string, string) {
	t.Helper()

	testHome := t.TempDir()
	t.Setenv("HOME", testHome)
	configDir := filepath.Join(testHome, ".code-switch")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	providerPath, err := providerFilePath(platform)
	if err != nil {
		t.Fatalf("provider path: %v", err)
	}
	payload, _ := json.Marshal(providerEnvelope{Providers: providers})
	if err := os.WriteFile(providerPath, payload, 0o600); err != nil {
		t.Fatalf("write providers: %v", err)
	}

	providerService := NewProviderService()
	poolService := NewProviderPoolService()
	keyService := NewCodexRelayKeyService()
	poolService.SetBindingChecker(keyService)
	appSettings := NewAppSettingsService(nil)
	notificationService := NewNotificationService(appSettings)
	relay := NewProviderRelayService(
		providerService, poolService, keyService,
		notificationService, appSettings,
		DefaultRelayBindAddr,
	)

	if pool.Platform == "" {
		pool.Platform = platform
	}
	poolID, err := poolService.SavePool(pool)
	if err != nil {
		t.Fatalf("save pool: %v", err)
	}

	key, err := keyService.CreateKey("pool-test-key")
	if err != nil {
		t.Fatalf("create relay key: %v", err)
	}
	if err := keyService.SetPoolBinding(key.ID, platform, poolID); err != nil {
		t.Fatalf("bind relay key: %v", err)
	}
	keySecret, err := keyService.GetKeySecret(key.ID)
	if err != nil {
		t.Fatalf("key secret: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	relay.registerRoutes(router)
	return relay, router, keySecret, poolID
}

func serveChatRequest(router *gin.Engine, keySecret string, body string) (*httptest.ResponseRecorder, <-chan struct{}) {
	req := httptest.NewRequest(http.MethodPost, "/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+keySecret)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		router.ServeHTTP(w, req)
		close(done)
	}()
	return w, done
}

func waitForActiveLog(t *testing.T, platform string, predicate func(ReqeustLog) bool) ReqeustLog {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		logs := defaultActiveRequestTracker.List(platform, "", "")
		for _, logEntry := range logs {
			if predicate(logEntry) {
				return logEntry
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("active log matching predicate was not found")
	return ReqeustLog{}
}

// ========== HTTP 层 fail-closed 集成测试 ==========

// TestHTTPFailClosedNoBinding 有效 key 但无 binding → 403
func TestHTTPFailClosedNoBinding(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	configDir := filepath.Join(testHome, ".code-switch")
	_ = os.MkdirAll(configDir, 0o700)

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: "https://a.example.com", APIKey: "key-a"},
	}
	payload, _ := json.Marshal(providerEnvelope{Providers: providers})
	_ = os.WriteFile(filepath.Join(configDir, "openai-chat.json"), payload, 0o600)

	providerService := NewProviderService()
	poolService := NewProviderPoolService()
	keyService := NewCodexRelayKeyService()
	poolService.SetBindingChecker(keyService)
	appSettings := NewAppSettingsService(nil)
	notificationService := NewNotificationService(appSettings)

	relay := NewProviderRelayService(
		providerService, poolService, keyService,
		notificationService, appSettings,
		DefaultRelayBindAddr,
	)

	// 创建初始池子，但不给 key 绑定
	_, _ = poolService.EnsureDefaultPool("openai-chat", providers, DefaultPoolSeed{Mode: ProviderPoolModeManaged})

	key, _ := keyService.CreateKey("unbound-key")
	// 故意不绑定 pool

	gin.SetMode(gin.TestMode)
	router := gin.New()
	relay.registerRoutes(router)

	keySecret, _ := keyService.GetKeySecret(key.ID)

	req := httptest.NewRequest(http.MethodPost, "/chat/completions", strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+keySecret)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for key without pool binding, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "未绑定") {
		t.Fatalf("expected '未绑定' in error, got: %s", w.Body.String())
	}
}

// TestHTTPFailClosedBindingToNonexistentPool binding 指向不存在的 pool → 403
func TestHTTPFailClosedBindingToNonexistentPool(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	configDir := filepath.Join(testHome, ".code-switch")
	_ = os.MkdirAll(configDir, 0o700)

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: "https://a.example.com", APIKey: "key-a"},
	}
	payload, _ := json.Marshal(providerEnvelope{Providers: providers})
	_ = os.WriteFile(filepath.Join(configDir, "openai-chat.json"), payload, 0o600)

	providerService := NewProviderService()
	poolService := NewProviderPoolService()
	keyService := NewCodexRelayKeyService()
	poolService.SetBindingChecker(keyService)
	appSettings := NewAppSettingsService(nil)
	notificationService := NewNotificationService(appSettings)

	relay := NewProviderRelayService(
		providerService, poolService, keyService,
		notificationService, appSettings,
		DefaultRelayBindAddr,
	)

	key, _ := keyService.CreateKey("bad-binding-key")
	// 绑定到一个不存在的 pool
	_ = keyService.SetPoolBinding(key.ID, "openai-chat", "pool_nonexistent_xyz")

	gin.SetMode(gin.TestMode)
	router := gin.New()
	relay.registerRoutes(router)

	keySecret, _ := keyService.GetKeySecret(key.ID)

	req := httptest.NewRequest(http.MethodPost, "/chat/completions", strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+keySecret)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for binding to nonexistent pool, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "不存在") {
		t.Fatalf("expected '不存在' in error, got: %s", w.Body.String())
	}
}

// TestHTTPFailClosedPlatformMismatch binding 指向其他 platform 的 pool → 403
func TestHTTPFailClosedPlatformMismatch(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	configDir := filepath.Join(testHome, ".code-switch")
	_ = os.MkdirAll(configDir, 0o700)

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: "https://a.example.com", APIKey: "key-a"},
	}
	for _, platform := range []string{"openai-chat", "openai-responses"} {
		payload, _ := json.Marshal(providerEnvelope{Providers: providers})
		_ = os.WriteFile(filepath.Join(configDir, platform+".json"), payload, 0o600)
	}

	providerService := NewProviderService()
	poolService := NewProviderPoolService()
	keyService := NewCodexRelayKeyService()
	poolService.SetBindingChecker(keyService)
	appSettings := NewAppSettingsService(nil)
	notificationService := NewNotificationService(appSettings)

	relay := NewProviderRelayService(
		providerService, poolService, keyService,
		notificationService, appSettings,
		DefaultRelayBindAddr,
	)

	// 创建 openai-responses 的 pool
	_, _ = poolService.EnsureDefaultPool("openai-responses", providers, DefaultPoolSeed{Mode: ProviderPoolModeManaged})

	key, _ := keyService.CreateKey("mismatch-key")
	// 把 key 的 openai-chat 绑定到 openai-responses 的 pool
	_ = keyService.SetPoolBinding(key.ID, "openai-chat", "pool_openai-responses_default")

	gin.SetMode(gin.TestMode)
	router := gin.New()
	relay.registerRoutes(router)

	keySecret, _ := keyService.GetKeySecret(key.ID)

	req := httptest.NewRequest(http.MethodPost, "/chat/completions", strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+keySecret)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for platform mismatch, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "不匹配") {
		t.Fatalf("expected '不匹配' in error, got: %s", w.Body.String())
	}
}

// TestHTTPDifferentPoolsSelectDifferentProviders key1/key2 绑定不同 pool，选择不同 provider
func TestHTTPDifferentPoolsSelectDifferentProviders(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	configDir := filepath.Join(testHome, ".code-switch")
	_ = os.MkdirAll(configDir, 0o700)

	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("provider-a unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"provider":"provider-a","choices":[{"message":{"content":"from-a"}}]}`))
	}))
	defer upstreamA.Close()

	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("provider-b unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"provider":"provider-b","choices":[{"message":{"content":"from-b"}}]}`))
	}))
	defer upstreamB.Close()

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: upstreamA.URL, APIKey: "key-a"},
		{ID: 2, Name: "provider-b", Enabled: true, APIURL: upstreamB.URL, APIKey: "key-b"},
	}
	payload, _ := json.Marshal(providerEnvelope{Providers: providers})
	_ = os.WriteFile(filepath.Join(configDir, "openai-chat.json"), payload, 0o600)

	providerService := NewProviderService()
	poolService := NewProviderPoolService()
	keyService := NewCodexRelayKeyService()
	poolService.SetBindingChecker(keyService)
	appSettings := NewAppSettingsService(nil)
	notificationService := NewNotificationService(appSettings)

	relay := NewProviderRelayService(
		providerService, poolService, keyService,
		notificationService, appSettings,
		DefaultRelayBindAddr,
	)

	// Pool A 只有 provider-a
	poolA := &ProviderPool{
		Platform: "openai-chat",
		Name:     "Pool A",
		Mode:     ProviderPoolModeManaged,
		Members:  []ProviderPoolMember{{ProviderID: 1, Enabled: true}},
	}
	poolAID, _ := poolService.SavePool(poolA)

	// Pool B 只有 provider-b
	poolB := &ProviderPool{
		Platform: "openai-chat",
		Name:     "Pool B",
		Mode:     ProviderPoolModeManaged,
		Members:  []ProviderPoolMember{{ProviderID: 2, Enabled: true}},
	}
	poolBID, _ := poolService.SavePool(poolB)

	key1, _ := keyService.CreateKey("key-pool-a")
	_ = keyService.SetPoolBinding(key1.ID, "openai-chat", poolAID)

	key2, _ := keyService.CreateKey("key-pool-b")
	_ = keyService.SetPoolBinding(key2.ID, "openai-chat", poolBID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	relay.registerRoutes(router)

	key1Secret, _ := keyService.GetKeySecret(key1.ID)
	req1 := httptest.NewRequest(http.MethodPost, "/chat/completions", strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Authorization", "Bearer "+key1Secret)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("key1 expected 200, got %d: %s", w1.Code, w1.Body.String())
	}
	if !strings.Contains(w1.Body.String(), `"provider":"provider-a"`) {
		t.Fatalf("key1 should route to provider-a, got: %s", w1.Body.String())
	}

	key2Secret, _ := keyService.GetKeySecret(key2.ID)
	req2 := httptest.NewRequest(http.MethodPost, "/chat/completions", strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+key2Secret)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("key2 expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	if !strings.Contains(w2.Body.String(), `"provider":"provider-b"`) {
		t.Fatalf("key2 should route to provider-b, got: %s", w2.Body.String())
	}
}

func TestHTTPStickyPrimaryProviderUntilBlacklisted(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	configDir := filepath.Join(testHome, ".code-switch")
	_ = os.MkdirAll(configDir, 0o700)

	providerAHits := 0
	providerBHits := 0

	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerAHits++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"provider-a overloaded"}}`))
	}))
	defer upstreamA.Close()

	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerBHits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"provider":"provider-b","choices":[{"message":{"content":"from-b"}}]}`))
	}))
	defer upstreamB.Close()

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: upstreamA.URL, APIKey: "key-a"},
		{ID: 2, Name: "provider-b", Enabled: true, APIURL: upstreamB.URL, APIKey: "key-b"},
	}
	payload, _ := json.Marshal(providerEnvelope{Providers: providers})
	_ = os.WriteFile(filepath.Join(configDir, "openai-chat.json"), payload, 0o600)

	providerService := NewProviderService()
	poolService := NewProviderPoolService()
	keyService := NewCodexRelayKeyService()
	poolService.SetBindingChecker(keyService)
	appSettings := NewAppSettingsService(nil)
	notificationService := NewNotificationService(appSettings)

	relay := NewProviderRelayService(
		providerService, poolService, keyService,
		notificationService, appSettings,
		DefaultRelayBindAddr,
	)

	pool := &ProviderPool{
		Platform:                     "openai-chat",
		Name:                         "Sticky Pool",
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       2,
		AutoBlacklistDurationMinutes: 10,
		Members: []ProviderPoolMember{
			{ProviderID: 1, Enabled: true, Level: 1},
			{ProviderID: 2, Enabled: true, Level: 1},
		},
	}
	poolID, _ := poolService.SavePool(pool)

	key, _ := keyService.CreateKey("sticky-key")
	_ = keyService.SetPoolBinding(key.ID, "openai-chat", poolID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	relay.registerRoutes(router)

	keySecret, _ := keyService.GetKeySecret(key.ID)
	newRequest := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/chat/completions", strings.NewReader(`{"model":"gpt-4","messages":[]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+keySecret)
		return req
	}

	// 第一次失败：A 仍未拉黑，不能切到同级 B。
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, newRequest())
	if w1.Code != http.StatusBadGateway {
		t.Fatalf("first request expected 502, got %d: %s", w1.Code, w1.Body.String())
	}
	if providerAHits != 1 {
		t.Fatalf("after first request provider-a hits = %d, want 1", providerAHits)
	}
	if providerBHits != 0 {
		t.Fatalf("after first request provider-b hits = %d, want 0", providerBHits)
	}

	// 第二次失败达到阈值：A 被拉黑，当次请求切到 B 并成功。
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, newRequest())
	if w2.Code != http.StatusOK {
		t.Fatalf("second request expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	if providerAHits != 2 {
		t.Fatalf("after second request provider-a hits = %d, want 2", providerAHits)
	}
	if providerBHits != 1 {
		t.Fatalf("after second request provider-b hits = %d, want 1", providerBHits)
	}
	if !strings.Contains(w2.Body.String(), `"provider":"provider-b"`) {
		t.Fatalf("second request should route to provider-b after blacklist, got: %s", w2.Body.String())
	}

	// 第三次请求：A 仍在拉黑期，应直接走 B。
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, newRequest())
	if w3.Code != http.StatusOK {
		t.Fatalf("third request expected 200, got %d: %s", w3.Code, w3.Body.String())
	}
	if providerAHits != 2 {
		t.Fatalf("after third request provider-a hits = %d, want still 2", providerAHits)
	}
	if providerBHits != 2 {
		t.Fatalf("after third request provider-b hits = %d, want 2", providerBHits)
	}
	if !strings.Contains(w3.Body.String(), `"provider":"provider-b"`) {
		t.Fatalf("third request should route directly to provider-b, got: %s", w3.Body.String())
	}
}

func TestHTTPAccountPoolStickyKeysBearerEndpointAndStaleBlacklist(t *testing.T) {
	const (
		firstKey  = "sk-account-first-secret"
		secondKey = "sk-account-second-secret"
	)

	var firstHits, secondHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/custom/responses" {
			t.Errorf("account pool upstream path = %q, want /custom/responses", r.URL.Path)
		}
		switch r.Header.Get("Authorization") {
		case "Bearer " + firstKey:
			firstHits++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = fmt.Fprintf(w, `{"error":{"message":"authorization rejected: Bearer %s"}}`, firstKey)
		case "Bearer " + secondKey:
			secondHits++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"resp_test","object":"response","output":[{"type":"message","content":[{"type":"output_text","text":"from-second-key"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`))
		default:
			t.Errorf("unexpected account pool Authorization header %q", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer upstream.Close()

	pool := &ProviderPool{
		Platform:                     "openai-responses",
		Name:                         "Account Pool",
		PoolType:                     ProviderPoolTypeAccount,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       2,
		AutoBlacklistDurationMinutes: 10,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            upstream.URL + "/",
			ResponsesEndpoint: "custom/responses",
			Keys: []AccountPoolKey{
				{APIKey: firstKey},
				{APIKey: secondKey},
			},
		},
	}
	relay, router, relayKey, poolID := setupProviderPoolHTTPTest(t, "openai-responses", nil, pool)

	savedPool, err := relay.poolService.ResolvePoolByID(poolID)
	if err != nil || savedPool == nil {
		t.Fatalf("resolve account pool: pool=%v err=%v", savedPool, err)
	}
	selected, err := relay.selectProvidersForRequest("openai-responses", savedPool, "gpt-5")
	if err != nil {
		t.Fatalf("select account pool keys: %v", err)
	}
	if len(selected) != 2 {
		t.Fatalf("selected account keys = %d, want 2", len(selected))
	}
	if selected[0].APIKey != firstKey || selected[1].APIKey != secondKey {
		t.Fatalf("account key order changed: %#v", []string{selected[0].APIKey, selected[1].APIKey})
	}
	for _, provider := range selected {
		if provider.ID == 0 {
			t.Fatalf("account key %q has zero runtime provider ID", provider.Name)
		}
		if strings.Contains(provider.Name, firstKey) || strings.Contains(provider.Name, secondKey) {
			t.Fatalf("account provider name exposes a raw key: %q", provider.Name)
		}
	}

	hub := NewEventHub()
	events, cancelEvents := hub.Subscribe(8)
	defer cancelEvents()
	relay.notificationService.SetEventEmitter(hub)

	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5","input":"hello","stream":false}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+relayKey)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	assertNoRawKey := func(label, value string) {
		t.Helper()
		if strings.Contains(value, firstKey) || strings.Contains(value, secondKey) {
			t.Fatalf("%s exposes a raw account key: %q", label, value)
		}
	}

	// A stays selected through the threshold. Once it is blacklisted, B is
	// selected in the next round and its success remains internal to the pool.
	w1 := request()
	if w1.Code != http.StatusOK || !strings.Contains(w1.Body.String(), "from-second-key") {
		t.Fatalf("first account request status = %d, want fallback success: %s", w1.Code, w1.Body.String())
	}
	if firstHits != 2 || secondHits != 1 {
		t.Fatalf("first account request hits = (%d, %d), want (2, 1)", firstHits, secondHits)
	}
	assertNoRawKey("first fallback response", w1.Body.String())
	if statuses := relay.ListProviderBlacklistStatus("openai-responses", poolID); len(statuses) != 1 || statuses[0].ProviderID != selected[0].ID {
		t.Fatalf("first request should blacklist the selected key: %+v", statuses)
	}

	// While A is blacklisted, later requests start directly with B.
	w2 := request()
	if w2.Code != http.StatusOK || !strings.Contains(w2.Body.String(), "from-second-key") {
		t.Fatalf("second account request should use key B, got %d: %s", w2.Code, w2.Body.String())
	}
	if firstHits != 2 || secondHits != 2 {
		t.Fatalf("second account request hits = (%d, %d), want (2, 2)", firstHits, secondHits)
	}
	assertNoRawKey("successful response", w2.Body.String())

	statuses := relay.ListProviderBlacklistStatus("openai-responses", poolID)
	if len(statuses) != 1 || statuses[0].ProviderID != selected[0].ID {
		t.Fatalf("account blacklist status = %+v, want first key ID %d", statuses, selected[0].ID)
	}
	assertNoRawKey("account blacklist status", fmt.Sprint(statuses))
	select {
	case event := <-events:
		if event.Name != "provider:blacklist:changed" {
			t.Fatalf("first account event = %q, want provider:blacklist:changed", event.Name)
		}
		payload, ok := event.Data.(map[string]interface{})
		if !ok {
			t.Fatalf("account blacklist event payload type = %T", event.Data)
		}
		assertNoRawKey("blacklist event payload", fmt.Sprint(payload))
	case <-time.After(time.Second):
		t.Fatal("account blacklist event was not emitted")
	}

	// The blacklisted key remains excluded from subsequent requests.
	w3 := request()
	if w3.Code != http.StatusOK {
		t.Fatalf("third account request status = %d, want 200: %s", w3.Code, w3.Body.String())
	}
	if firstHits != 2 || secondHits != 3 {
		t.Fatalf("third account request hits = (%d, %d), want (2, 3)", firstHits, secondHits)
	}
	lastUsed := relay.GetLastUsedProviderByPool("openai-responses", poolID)
	if lastUsed == nil {
		t.Fatal("account pool last-used provider was not recorded")
	}
	assertNoRawKey("last-used provider name", lastUsed.ProviderName)

	// Manual clearing restores A. It is retried to the threshold before B is
	// eligible again, then can be removed while blacklisted.
	relay.ClearProviderBlacklist("openai-responses", poolID, selected[0].ID)
	w4 := request()
	if w4.Code != http.StatusOK || !strings.Contains(w4.Body.String(), "from-second-key") {
		t.Fatalf("request after unblacklist should silently fall back, got %d: %s", w4.Code, w4.Body.String())
	}
	if firstHits != 4 || secondHits != 4 {
		t.Fatalf("request after unblacklist hits = (%d, %d), want (4, 4)", firstHits, secondHits)
	}

	// The strict retries above have blacklisted A again; removing it must prune
	// that stale status from the persisted pool view.
	if statuses = relay.ListProviderBlacklistStatus("openai-responses", poolID); len(statuses) != 1 {
		t.Fatalf("first key should be blacklisted again, got %+v", statuses)
	}
	updatedPool, err := relay.poolService.ResolvePoolByID(poolID)
	if err != nil || updatedPool == nil {
		t.Fatalf("resolve account pool for key removal: pool=%v err=%v", updatedPool, err)
	}
	updatedPool.AccountPoolConfig.Keys = []AccountPoolKey{{ID: selected[1].ID, APIKey: secondKey}}
	if _, err := relay.poolService.SavePool(updatedPool); err != nil {
		t.Fatalf("remove blacklisted account key: %v", err)
	}
	if statuses = relay.ListProviderBlacklistStatus("openai-responses", poolID); len(statuses) != 0 {
		t.Fatalf("removed account key left stale blacklist status: %+v", statuses)
	}
}

func TestHTTPAccountPoolRetryUsesHighestPriorityKeyAfterReorder(t *testing.T) {
	oldTracker := defaultActiveRequestTracker
	defaultActiveRequestTracker = newActiveRequestTracker()
	t.Cleanup(func() {
		defaultActiveRequestTracker = oldTracker
	})

	const (
		firstKey  = "sk-retry-current-first"
		secondKey = "sk-retry-current-second"
	)
	firstEntered := make(chan struct{}, 1)
	var firstHits int32
	var secondHits int32
	var firstCancelled int32

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		switch r.Header.Get("Authorization") {
		case "Bearer " + firstKey:
			hit := atomic.AddInt32(&firstHits, 1)
			if hit == 1 {
				firstEntered <- struct{}{}
				select {
				case <-r.Context().Done():
					atomic.StoreInt32(&firstCancelled, 1)
				case <-time.After(2 * time.Second):
					w.WriteHeader(http.StatusGatewayTimeout)
				}
				return
			}
			_, _ = w.Write([]byte(`{"id":"resp_first","object":"response","output":[{"type":"message","content":[{"type":"output_text","text":"from-first-key"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`))
		case "Bearer " + secondKey:
			atomic.AddInt32(&secondHits, 1)
			_, _ = w.Write([]byte(`{"id":"resp_second","object":"response","output":[{"type":"message","content":[{"type":"output_text","text":"from-second-key"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`))
		default:
			t.Errorf("unexpected Authorization header %q", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer upstream.Close()

	pool := &ProviderPool{
		Platform:                     "openai-responses",
		Name:                         "Account Retry Pool",
		PoolType:                     ProviderPoolTypeAccount,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       1,
		AutoBlacklistDurationMinutes: 10,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            upstream.URL,
			ResponsesEndpoint: "/responses",
			Keys: []AccountPoolKey{
				{APIKey: firstKey},
				{APIKey: secondKey},
			},
		},
	}
	relay, router, relayKey, poolID := setupProviderPoolHTTPTest(t, "openai-responses", nil, pool)

	req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5","input":"hello","stream":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+relayKey)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		router.ServeHTTP(w, req)
		close(done)
	}()

	select {
	case <-firstEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("first account key request did not start")
	}

	savedPool, err := relay.poolService.ResolvePoolByID(poolID)
	if err != nil || savedPool == nil {
		t.Fatalf("resolve account retry pool: pool=%v err=%v", savedPool, err)
	}
	savedPool.AccountPoolConfig.Keys[0], savedPool.AccountPoolConfig.Keys[1] = savedPool.AccountPoolConfig.Keys[1], savedPool.AccountPoolConfig.Keys[0]
	if _, err := relay.poolService.SavePool(savedPool); err != nil {
		t.Fatalf("reorder account keys: %v", err)
	}

	processing := waitForActiveLog(t, "openai-responses", func(logEntry ReqeustLog) bool {
		return logEntry.Status == requestLogStatusProcessing && logEntry.Provider != ""
	})
	if result := defaultActiveRequestTracker.Retry(processing.ID, ""); result.Status != activeRequestRetryTriggered {
		t.Fatalf("account retry status = %q, want %q", result.Status, activeRequestRetryTriggered)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("account request did not finish after retry")
	}
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "from-second-key") {
		t.Fatalf("account retry should use the highest-priority key, got %d: %s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(&firstHits) != 1 || atomic.LoadInt32(&secondHits) != 1 {
		t.Fatalf("account retry hits = (%d, %d), want (1, 1)", firstHits, secondHits)
	}
	if atomic.LoadInt32(&firstCancelled) != 1 {
		t.Fatal("account retry did not cancel the original upstream request")
	}
	if statuses := relay.ListProviderBlacklistStatus("openai-responses", poolID); len(statuses) != 0 {
		t.Fatalf("user-triggered retry should not count as a key failure: %+v", statuses)
	}
}

func TestHTTPAccountPoolAllKeysBlacklistedReturnsServiceUnavailable(t *testing.T) {
	const (
		firstKey  = "sk-all-blacklisted-first"
		secondKey = "sk-all-blacklisted-second"
	)

	var firstHits, secondHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer " + firstKey:
			firstHits++
		case "Bearer " + secondKey:
			secondHits++
		default:
			t.Errorf("unexpected account pool Authorization header %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"rate limited"}}`))
	}))
	defer upstream.Close()

	pool := &ProviderPool{
		Platform:                     "openai-responses",
		Name:                         "Exhausted Account Pool",
		PoolType:                     ProviderPoolTypeAccount,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       1,
		AutoBlacklistDurationMinutes: 10,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            upstream.URL,
			ResponsesEndpoint: "/v1/responses",
			Keys: []AccountPoolKey{
				{APIKey: firstKey},
				{APIKey: secondKey},
			},
		},
	}
	relay, router, relayKey, poolID := setupProviderPoolHTTPTest(t, "openai-responses", nil, pool)

	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5","input":"hello","stream":false}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+relayKey)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	w1 := request()
	if w1.Code != http.StatusServiceUnavailable {
		t.Fatalf("first exhausted account request status = %d, want 503: %s", w1.Code, w1.Body.String())
	}
	if !strings.Contains(w1.Body.String(), "号池暂无可用账号") || strings.Contains(w1.Body.String(), "rate limited") {
		t.Fatalf("first exhausted account response must be generic, got %s", w1.Body.String())
	}
	if firstHits != 1 || secondHits != 1 {
		t.Fatalf("first exhausted account request hits = (%d, %d), want (1, 1)", firstHits, secondHits)
	}
	if statuses := relay.ListProviderBlacklistStatus("openai-responses", poolID); len(statuses) != 2 {
		t.Fatalf("all account keys should be blacklisted, got %+v", statuses)
	}

	w2 := request()
	if w2.Code != http.StatusServiceUnavailable {
		t.Fatalf("all-blacklisted account request status = %d, want 503: %s", w2.Code, w2.Body.String())
	}
	if firstHits != 1 || secondHits != 1 {
		t.Fatalf("503 request reached upstream: hits = (%d, %d)", firstHits, secondHits)
	}
	if strings.Contains(w2.Body.String(), firstKey) || strings.Contains(w2.Body.String(), secondKey) {
		t.Fatalf("all-blacklisted response exposes a raw key: %s", w2.Body.String())
	}
	if !strings.Contains(w2.Body.String(), "号池暂无可用账号") {
		t.Fatalf("all-blacklisted account response must be generic, got %s", w2.Body.String())
	}
}

func TestHTTPAccountPoolClient4xxDoesNotFailOverOrBlacklist(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnprocessableEntity} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			const (
				firstKey  = "sk-client-4xx-first"
				secondKey = "sk-client-4xx-second"
			)

			var firstHits, secondHits int
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read request body: %v", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				var provider string
				switch r.Header.Get("Authorization") {
				case "Bearer " + firstKey:
					firstHits++
					provider = "first"
				case "Bearer " + secondKey:
					secondHits++
					provider = "second"
				default:
					t.Errorf("unexpected account pool Authorization header %q", r.Header.Get("Authorization"))
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				if gjson.GetBytes(body, "input").String() == "invalid" {
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("X-Upstream-Debug", "account="+r.Header.Get("Authorization"))
					w.Header().Add("Set-Cookie", "provider_session=upstream-secret")
					w.WriteHeader(status)
					_, _ = w.Write([]byte(`{"error":{"message":"invalid request payload","type":"invalid_request_error"}}`))
					return
				}

				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"id":"resp_%s","object":"response","output":[{"type":"message","content":[{"type":"output_text","text":"from-%s"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`, provider, provider)
			}))
			defer upstream.Close()

			pool := &ProviderPool{
				Platform:                     "openai-responses",
				Name:                         "Client 4xx Account Pool",
				PoolType:                     ProviderPoolTypeAccount,
				Mode:                         ProviderPoolModeManaged,
				AutoBlacklistEnabled:         true,
				AutoBlacklistThreshold:       1,
				AutoBlacklistDurationMinutes: 10,
				AccountPoolConfig: &AccountPoolConfig{
					APIURL:            upstream.URL,
					ResponsesEndpoint: "/v1/responses",
					Keys:              []AccountPoolKey{{APIKey: firstKey}, {APIKey: secondKey}},
				},
			}
			relay, router, relayKey, poolID := setupProviderPoolHTTPTest(t, "openai-responses", nil, pool)

			request := func(input string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(fmt.Sprintf(`{"model":"gpt-5","input":%q,"conversation":"client-validation-session","stream":false}`, input)))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+relayKey)
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				return w
			}

			invalid := request("invalid")
			if invalid.Code != status {
				t.Fatalf("invalid request status = %d, want %d: %s", invalid.Code, status, invalid.Body.String())
			}
			if !strings.Contains(invalid.Body.String(), "invalid request payload") || strings.Contains(invalid.Body.String(), "号池中所有可用账号均请求失败") {
				t.Fatalf("invalid request did not return the upstream client error: %s", invalid.Body.String())
			}
			if invalid.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("invalid request content type = %q, want application/json", invalid.Header().Get("Content-Type"))
			}
			if strings.Contains(invalid.Body.String(), firstKey) || strings.Contains(invalid.Body.String(), secondKey) {
				t.Fatalf("invalid request leaked an account key: body=%q headers=%v", invalid.Body.String(), invalid.Header())
			}
			if debugHeader := invalid.Header().Get("X-Upstream-Debug"); debugHeader != "" {
				t.Fatalf("invalid request forwarded a sensitive upstream header: %q", debugHeader)
			}
			if cookies := invalid.Header().Values("Set-Cookie"); len(cookies) != 0 {
				t.Fatalf("invalid request forwarded upstream cookies: %v", cookies)
			}
			if firstHits+secondHits != 1 {
				t.Fatalf("invalid request upstream attempts = (%d, %d), want exactly one", firstHits, secondHits)
			}
			if statuses := relay.ListProviderBlacklistStatus("openai-responses", poolID); len(statuses) != 0 {
				t.Fatalf("client 4xx should not blacklist an account key: %+v", statuses)
			}

			valid := request("valid")
			if valid.Code != http.StatusOK {
				t.Fatalf("valid request after client 4xx status = %d, want 200: %s", valid.Code, valid.Body.String())
			}
			if firstHits+secondHits != 2 {
				t.Fatalf("valid request upstream attempts = (%d, %d), want two total attempts", firstHits, secondHits)
			}
			if !((firstHits == 2 && secondHits == 0) || (firstHits == 0 && secondHits == 2)) {
				t.Fatalf("client 4xx invalidated the sticky key binding: attempts = (%d, %d)", firstHits, secondHits)
			}
			if statuses := relay.ListProviderBlacklistStatus("openai-responses", poolID); len(statuses) != 0 {
				t.Fatalf("valid request after client 4xx found unexpected blacklist: %+v", statuses)
			}
		})
	}
}

func TestHTTPAccountPoolModelsUsesSiblingEndpointAndRedactsKey(t *testing.T) {
	const (
		firstKey  = "sk-models-first-secret"
		secondKey = "sk-models-second-secret"
	)

	var firstHits, secondHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("account models path = %q, want /v1/models", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Header.Get("Authorization") {
		case "Bearer " + firstKey:
			firstHits++
			w.Header().Set("X-Upstream-Debug", "rejected "+firstKey)
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = fmt.Fprintf(w, `{"error":"rejected key %s"}`, firstKey)
		case "Bearer " + secondKey:
			secondHits++
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"gpt-account-model"}]}`))
		default:
			t.Errorf("unexpected account models Authorization header %q", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer upstream.Close()

	pool := &ProviderPool{
		Platform:                     "openai-responses",
		Name:                         "Account Models Pool",
		PoolType:                     ProviderPoolTypeAccount,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       2,
		AutoBlacklistDurationMinutes: 10,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            upstream.URL + "/v1",
			ResponsesEndpoint: "/responses",
			Keys: []AccountPoolKey{
				{APIKey: firstKey},
				{APIKey: secondKey},
			},
		},
	}
	relay, router, relayKey, poolID := setupProviderPoolHTTPTest(t, "openai-responses", nil, pool)

	hub := NewEventHub()
	events, cancelEvents := hub.Subscribe(8)
	defer cancelEvents()
	relay.notificationService.SetEventEmitter(hub)

	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		req.Header.Set("Authorization", "Bearer "+relayKey)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	assertNoKey := func(label, value string) {
		t.Helper()
		if strings.Contains(value, firstKey) || strings.Contains(value, secondKey) {
			t.Fatalf("%s exposes an account key: %q", label, value)
		}
	}

	first := request()
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), "gpt-account-model") {
		t.Fatalf("first account models should silently fall back, got %d: %s", first.Code, first.Body.String())
	}
	assertNoKey("first account models body", first.Body.String())
	assertNoKey("first account models headers", fmt.Sprint(first.Header()))
	if firstHits != 2 || secondHits != 1 {
		t.Fatalf("first account models hits = (%d, %d), want (2, 1)", firstHits, secondHits)
	}
	if statuses := relay.ListProviderBlacklistStatus("openai-responses", poolID); len(statuses) != 1 {
		t.Fatalf("first key should be blacklisted after strict retries: %+v", statuses)
	}

	second := request()
	if second.Code != http.StatusOK || !strings.Contains(second.Body.String(), "gpt-account-model") {
		t.Fatalf("second account models request should switch keys, got %d: %s", second.Code, second.Body.String())
	}
	if firstHits != 2 || secondHits != 2 {
		t.Fatalf("second account models hits = (%d, %d), want (2, 2)", firstHits, secondHits)
	}
	statuses := relay.ListProviderBlacklistStatus("openai-responses", poolID)
	if len(statuses) != 1 {
		t.Fatalf("account models blacklist status = %+v, want one key", statuses)
	}
	assertNoKey("account models blacklist status", fmt.Sprint(statuses))

	select {
	case event := <-events:
		assertNoKey("account models event", fmt.Sprint(event.Data))
	case <-time.After(time.Second):
		t.Fatal("account models blacklist event was not emitted")
	}
}

func TestHTTPAccountPoolModelsMigratesWhenFailedKeyDeleted(t *testing.T) {
	const (
		firstKey  = "sk-models-delete-first"
		secondKey = "sk-models-delete-second"
	)

	var (
		relay    *ProviderRelayService
		poolID   string
		mu       sync.Mutex
		keyOrder []string
		removed  bool
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var keyName string
		switch r.Header.Get("Authorization") {
		case "Bearer " + firstKey:
			keyName = "first"
		case "Bearer " + secondKey:
			keyName = "second"
		default:
			t.Errorf("unexpected account models Authorization header %q", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		keyOrder = append(keyOrder, keyName)
		shouldRemove := keyName == "first" && !removed
		if shouldRemove {
			removed = true
		}
		mu.Unlock()

		if shouldRemove {
			updatedPool, err := relay.poolService.ResolvePoolByID(poolID)
			if err != nil || updatedPool == nil {
				t.Errorf("resolve pool for runtime key deletion: pool=%v err=%v", updatedPool, err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if len(updatedPool.AccountPoolConfig.Keys) != 2 {
				t.Errorf("pool key count before runtime deletion = %d, want 2", len(updatedPool.AccountPoolConfig.Keys))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			updatedPool.AccountPoolConfig.Keys = []AccountPoolKey{updatedPool.AccountPoolConfig.Keys[1]}
			if _, err := relay.poolService.SavePool(updatedPool); err != nil {
				t.Errorf("persist runtime key deletion: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if keyName == "first" {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"message":"first account is rate limited"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"gpt-from-second"}]}`))
	}))
	defer upstream.Close()

	pool := &ProviderPool{
		Platform:                     "openai-responses",
		Name:                         "Models Runtime Deletion Pool",
		PoolType:                     ProviderPoolTypeAccount,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       3,
		AutoBlacklistDurationMinutes: 10,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            upstream.URL,
			ResponsesEndpoint: "/responses",
			Keys:              []AccountPoolKey{{APIKey: firstKey}, {APIKey: secondKey}},
		},
	}
	relay, router, relayKey, poolID := setupProviderPoolHTTPTest(t, "openai-responses", nil, pool)

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+relayKey)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "gpt-from-second") {
		t.Fatalf("models request after runtime key deletion = %d: %s", w.Code, w.Body.String())
	}

	mu.Lock()
	defer mu.Unlock()
	if want := []string{"first", "second"}; fmt.Sprint(keyOrder) != fmt.Sprint(want) {
		t.Fatalf("models runtime deletion key order = %v, want %v", keyOrder, want)
	}
}

func TestHTTPAccountPoolModelsClient4xxDoesNotFailOverOrBlacklist(t *testing.T) {
	const (
		firstKey  = "sk-models-client-4xx-first"
		secondKey = "sk-models-client-4xx-second"
	)

	var firstHits, secondHits int
	returnClientError := true
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var provider string
		switch r.Header.Get("Authorization") {
		case "Bearer " + firstKey:
			firstHits++
			provider = "first"
		case "Bearer " + secondKey:
			secondHits++
			provider = "second"
		default:
			t.Errorf("unexpected account models Authorization header %q", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if returnClientError {
			w.Header().Set("X-Upstream-Debug", "account="+r.Header.Get("Authorization"))
			w.Header().Add("Set-Cookie", "provider_session=upstream-secret")
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"error":{"message":"invalid models request","type":"invalid_request_error"}}`))
			return
		}
		_, _ = fmt.Fprintf(w, `{"object":"list","data":[{"id":"gpt-from-%s"}]}`, provider)
	}))
	defer upstream.Close()

	pool := &ProviderPool{
		Platform:                     "openai-responses",
		Name:                         "Client 4xx Models Account Pool",
		PoolType:                     ProviderPoolTypeAccount,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       1,
		AutoBlacklistDurationMinutes: 10,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            upstream.URL,
			ResponsesEndpoint: "/v1/responses",
			Keys:              []AccountPoolKey{{APIKey: firstKey}, {APIKey: secondKey}},
		},
	}
	relay, router, relayKey, poolID := setupProviderPoolHTTPTest(t, "openai-responses", nil, pool)

	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		req.Header.Set("Authorization", "Bearer "+relayKey)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	invalid := request()
	if invalid.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid models status = %d, want 422: %s", invalid.Code, invalid.Body.String())
	}
	if !strings.Contains(invalid.Body.String(), "invalid models request") || strings.Contains(invalid.Body.String(), "号池中所有可用账号均请求失败") {
		t.Fatalf("invalid models request did not return the upstream client error: %s", invalid.Body.String())
	}
	if firstHits+secondHits != 1 {
		t.Fatalf("invalid models request upstream attempts = (%d, %d), want exactly one", firstHits, secondHits)
	}
	if statuses := relay.ListProviderBlacklistStatus("openai-responses", poolID); len(statuses) != 0 {
		t.Fatalf("models client 4xx should not blacklist an account key: %+v", statuses)
	}
	if debugHeader := invalid.Header().Get("X-Upstream-Debug"); debugHeader != "" {
		t.Fatalf("invalid models request forwarded a sensitive upstream header: %q", debugHeader)
	}
	if cookies := invalid.Header().Values("Set-Cookie"); len(cookies) != 0 {
		t.Fatalf("invalid models request forwarded upstream cookies: %v", cookies)
	}

	returnClientError = false
	valid := request()
	if valid.Code != http.StatusOK {
		t.Fatalf("valid models request after client 4xx status = %d, want 200: %s", valid.Code, valid.Body.String())
	}
	if firstHits+secondHits != 2 {
		t.Fatalf("valid models request upstream attempts = (%d, %d), want two total attempts", firstHits, secondHits)
	}
	if statuses := relay.ListProviderBlacklistStatus("openai-responses", poolID); len(statuses) != 0 {
		t.Fatalf("valid models request after client 4xx found unexpected blacklist: %+v", statuses)
	}
}

func TestHTTPAccountPoolModelsAllFailuresReturnGenericError(t *testing.T) {
	const (
		firstKey  = "sk-models-generic-first"
		secondKey = "sk-models-generic-second"
	)
	var firstHits, secondHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		switch r.Header.Get("Authorization") {
		case "Bearer " + firstKey:
			firstHits++
			_, _ = fmt.Fprintf(w, `{"error":"first key %s rejected"}`, firstKey)
		case "Bearer " + secondKey:
			secondHits++
			_, _ = fmt.Fprintf(w, `{"error":"second key %s rejected"}`, secondKey)
		default:
			t.Errorf("unexpected account pool Authorization header %q", r.Header.Get("Authorization"))
		}
	}))
	defer upstream.Close()

	pool := &ProviderPool{
		Platform:                     "openai-responses",
		Name:                         "Generic Models Account Pool",
		PoolType:                     ProviderPoolTypeAccount,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       3,
		AutoBlacklistDurationMinutes: 10,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            upstream.URL,
			ResponsesEndpoint: "/responses",
			Keys:              []AccountPoolKey{{APIKey: firstKey}, {APIKey: secondKey}},
		},
	}
	_, router, relayKey, _ := setupProviderPoolHTTPTest(t, "openai-responses", nil, pool)
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+relayKey)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("all-failed account models status = %d, want 502: %s", w.Code, w.Body.String())
	}
	if firstHits != 3 || secondHits != 3 {
		t.Fatalf("all-failed account models hits = (%d,%d), want (3,3)", firstHits, secondHits)
	}
	if !strings.Contains(w.Body.String(), "号池中所有可用账号均请求失败") || strings.Contains(w.Body.String(), firstKey) || strings.Contains(w.Body.String(), secondKey) || strings.Contains(w.Body.String(), "rejected") {
		t.Fatalf("all-failed account models response leaked details: %s", w.Body.String())
	}
}

func TestHTTPAccountPoolEmptyStreamBlacklistsAndSwitchesKey(t *testing.T) {
	const (
		firstKey  = "sk-empty-stream-first"
		secondKey = "sk-empty-stream-second"
	)

	var firstHits, secondHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/custom/codex" {
			t.Errorf("empty-stream account endpoint = %q, want /custom/codex", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		switch r.Header.Get("Authorization") {
		case "Bearer " + firstKey:
			firstHits++
			// A 200 response without useful SSE events is an upstream failure.
			return
		case "Bearer " + secondKey:
			secondHits++
			_, _ = w.Write([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"from-second-key\"}\n\n"))
			_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n"))
			_, _ = w.Write([]byte("data: [DONE]\n\n"))
		default:
			t.Errorf("unexpected account pool Authorization header %q", r.Header.Get("Authorization"))
		}
	}))
	defer upstream.Close()

	pool := &ProviderPool{
		Platform:                     "openai-responses",
		Name:                         "Empty Stream Account Pool",
		PoolType:                     ProviderPoolTypeAccount,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       1,
		AutoBlacklistDurationMinutes: 10,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            upstream.URL,
			ResponsesEndpoint: "/custom/codex",
			Keys: []AccountPoolKey{
				{APIKey: firstKey},
				{APIKey: secondKey},
			},
		},
	}
	relay, router, relayKey, poolID := setupProviderPoolHTTPTest(t, "openai-responses", nil, pool)

	req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5","input":"hello","stream":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+relayKey)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "from-second-key") {
		t.Fatalf("empty-stream account request should switch to key B, got %d: %s", w.Code, w.Body.String())
	}
	if firstHits != 1 || secondHits != 1 {
		t.Fatalf("empty-stream account request hits = (%d, %d), want (1, 1)", firstHits, secondHits)
	}
	statuses := relay.ListProviderBlacklistStatus("openai-responses", poolID)
	if len(statuses) != 1 {
		t.Fatalf("empty-stream account blacklist status = %+v, want one key", statuses)
	}
	if strings.Contains(w.Body.String(), firstKey) || strings.Contains(w.Body.String(), secondKey) {
		t.Fatalf("empty-stream response exposes a raw key: %s", w.Body.String())
	}
}

func TestHTTPAccountPoolEmptyStreamCountsOncePerLogicalRequest(t *testing.T) {
	const (
		firstKey  = "sk-empty-stream-logical-first"
		secondKey = "sk-empty-stream-logical-second"
	)

	var firstHits, secondHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		switch r.Header.Get("Authorization") {
		case "Bearer " + firstKey:
			firstHits++
			return
		case "Bearer " + secondKey:
			secondHits++
			_, _ = w.Write([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"from-second-key\"}\n\n"))
			_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-second\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n"))
			_, _ = w.Write([]byte("data: [DONE]\n\n"))
		default:
			t.Errorf("unexpected account pool Authorization header %q", r.Header.Get("Authorization"))
		}
	}))
	defer upstream.Close()

	pool := &ProviderPool{
		Platform:                     "openai-responses",
		Name:                         "Logical Empty Stream Account Pool",
		PoolType:                     ProviderPoolTypeAccount,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       3,
		AutoBlacklistDurationMinutes: 10,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            upstream.URL,
			ResponsesEndpoint: "/responses",
			Keys:              []AccountPoolKey{{APIKey: firstKey}, {APIKey: secondKey}},
		},
	}
	relay, router, relayKey, poolID := setupProviderPoolHTTPTest(t, "openai-responses", nil, pool)

	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5","conversation":"empty-stream-session","input":"hello","stream":true}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+relayKey)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	for attempt := 1; attempt <= 2; attempt++ {
		w := request()
		if w.Code != http.StatusBadGateway || gjson.Get(w.Body.String(), "error.code").String() != emptyStreamErrorCode {
			t.Fatalf("logical request %d = %d: %s, want standardized empty-stream 502", attempt, w.Code, w.Body.String())
		}
		if firstHits != attempt || secondHits != 0 {
			t.Fatalf("logical request %d hits = (%d,%d), want (%d,0)", attempt, firstHits, secondHits, attempt)
		}
		if statuses := relay.ListProviderBlacklistStatus("openai-responses", poolID); len(statuses) != 0 {
			t.Fatalf("logical request %d blacklisted the key too early: %+v", attempt, statuses)
		}
	}

	third := request()
	if third.Code != http.StatusOK || !strings.Contains(third.Body.String(), "from-second-key") {
		t.Fatalf("third logical request should blacklist first key and fall back, got %d: %s", third.Code, third.Body.String())
	}
	if firstHits != 3 || secondHits != 1 {
		t.Fatalf("three logical requests hits = (%d,%d), want (3,1)", firstHits, secondHits)
	}
	statuses := relay.ListProviderBlacklistStatus("openai-responses", poolID)
	if len(statuses) != 1 || statuses[0].FailureCount != 3 || statuses[0].LastReason != emptyStreamErrorCode {
		t.Fatalf("logical empty-stream blacklist status = %+v", statuses)
	}
}

func TestHTTPAccountPoolEmptyStreamMatchesSpecialBlacklistRule(t *testing.T) {
	const (
		firstKey  = "sk-empty-stream-rule-first"
		secondKey = "sk-empty-stream-rule-second"
	)

	var firstHits, secondHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		switch r.Header.Get("Authorization") {
		case "Bearer " + firstKey:
			firstHits++
			return
		case "Bearer " + secondKey:
			secondHits++
			_, _ = w.Write([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"from-second-key\"}\n\n"))
			_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-rule-second\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n"))
			_, _ = w.Write([]byte("data: [DONE]\n\n"))
		}
	}))
	defer upstream.Close()

	rule := SpecialBlacklistRule{
		ID:                "empty-stream-rule",
		Name:              "Empty stream",
		HTTPStatus:        http.StatusBadGateway,
		JSONPath:          "error.code",
		ExpectedJSONValue: `"empty_stream"`,
		Threshold:         1,
		DurationMinutes:   5,
	}
	pool := &ProviderPool{
		Platform:                     "openai-responses",
		Name:                         "Empty Stream Rule Account Pool",
		PoolType:                     ProviderPoolTypeAccount,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       10,
		AutoBlacklistDurationMinutes: 10,
		SpecialBlacklistRules:        []SpecialBlacklistRule{rule},
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            upstream.URL,
			ResponsesEndpoint: "/responses",
			Keys:              []AccountPoolKey{{APIKey: firstKey}, {APIKey: secondKey}},
		},
	}
	relay, router, relayKey, poolID := setupProviderPoolHTTPTest(t, "openai-responses", nil, pool)

	req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5","input":"hello","stream":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+relayKey)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "from-second-key") {
		t.Fatalf("special empty-stream rule should blacklist and switch, got %d: %s", w.Code, w.Body.String())
	}
	if firstHits != 1 || secondHits != 1 {
		t.Fatalf("special empty-stream rule hits = (%d,%d), want (1,1)", firstHits, secondHits)
	}
	statuses := relay.ListProviderBlacklistStatus("openai-responses", poolID)
	if len(statuses) != 1 || statuses[0].LastReason != rule.Name || statuses[0].RuleFailureCounts[rule.ID] != 1 {
		t.Fatalf("special empty-stream blacklist status = %+v", statuses)
	}
}

func TestHTTPAccountPoolFailedStreamFallsBackWhenNormalGuardDisabled(t *testing.T) {
	const (
		firstKey  = "sk-failed-stream-first"
		secondKey = "sk-failed-stream-second"
	)
	var firstHits, secondHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		switch r.Header.Get("Authorization") {
		case "Bearer " + firstKey:
			firstHits++
			_, _ = w.Write([]byte("data: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp-failed\"}}\n\ndata: [DONE]\n\n"))
		case "Bearer " + secondKey:
			secondHits++
			_, _ = w.Write([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"from-second-key\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-success\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\ndata: [DONE]\n\n"))
		default:
			t.Errorf("unexpected account pool Authorization header %q", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer upstream.Close()

	pool := &ProviderPool{
		Platform:                     "openai-responses",
		Name:                         "Failed Stream Account Pool",
		PoolType:                     ProviderPoolTypeAccount,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       2,
		AutoBlacklistDurationMinutes: 10,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            upstream.URL,
			ResponsesEndpoint: "/responses",
			Keys:              []AccountPoolKey{{APIKey: firstKey}, {APIKey: secondKey}},
		},
	}
	relay, router, relayKey, poolID := setupProviderPoolHTTPTest(t, "openai-responses", nil, pool)
	settings, err := relay.appSettings.GetAppSettings()
	if err != nil {
		t.Fatalf("get app settings: %v", err)
	}
	settings.EnableCodexStreamGuard = false
	if _, err := relay.appSettings.SaveAppSettings(settings); err != nil {
		t.Fatalf("disable normal Codex stream guard: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5","input":"hello","stream":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+relayKey)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "from-second-key") || strings.Contains(w.Body.String(), "response.failed") {
		t.Fatalf("failed stream should silently fall back, got %d: %s", w.Code, w.Body.String())
	}
	if firstHits != 2 || secondHits != 1 {
		t.Fatalf("failed stream hits = (%d,%d), want (2,1)", firstHits, secondHits)
	}
	if statuses := relay.ListProviderBlacklistStatus("openai-responses", poolID); len(statuses) != 1 {
		t.Fatalf("terminal stream failures should blacklist the selected key: %+v", statuses)
	}
}

func TestHTTPAccountPoolOversizedPreflightStreamFallsBackWithoutWriting(t *testing.T) {
	const (
		firstKey  = "sk-oversized-preflight-first"
		secondKey = "sk-oversized-preflight-second"
	)
	var firstHits, secondHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		switch r.Header.Get("Authorization") {
		case "Bearer " + firstKey:
			firstHits++
			line := []byte("data: {\"type\":\"response.created\"}\n")
			for written := 0; written < codexStreamGuardMaxInitialBufferBytes+len(line); written += len(line) {
				_, _ = w.Write(line)
			}
			_, _ = w.Write([]byte("data: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp-oversized-failed\"}}\n\n"))
		case "Bearer " + secondKey:
			secondHits++
			_, _ = w.Write([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"from-second-key\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-oversized-success\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\ndata: [DONE]\n\n"))
		default:
			t.Errorf("unexpected account pool Authorization header %q", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer upstream.Close()

	pool := &ProviderPool{
		Platform:                     "openai-responses",
		Name:                         "Oversized Preflight Account Pool",
		PoolType:                     ProviderPoolTypeAccount,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       2,
		AutoBlacklistDurationMinutes: 10,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            upstream.URL,
			ResponsesEndpoint: "/responses",
			Keys:              []AccountPoolKey{{APIKey: firstKey}, {APIKey: secondKey}},
		},
	}
	_, router, relayKey, _ := setupProviderPoolHTTPTest(t, "openai-responses", nil, pool)
	req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5","input":"hello","stream":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+relayKey)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "from-second-key") || strings.Contains(w.Body.String(), "response.created") || strings.Contains(w.Body.String(), "resp-oversized-failed") {
		t.Fatalf("oversized preflight should be hidden before fallback, got %d: %s", w.Code, w.Body.String())
	}
	if firstHits != 2 || secondHits != 1 {
		t.Fatalf("oversized preflight hits = (%d,%d), want (2,1)", firstHits, secondHits)
	}
}

func TestHTTPAccountPoolStrictStickinessRetriesBoundKeyUntilBlacklist(t *testing.T) {
	const (
		firstKey  = "sk-strict-sticky-first"
		secondKey = "sk-strict-sticky-second"
	)

	var mu sync.Mutex
	var keyOrder []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var keyName string
		switch r.Header.Get("Authorization") {
		case "Bearer " + firstKey:
			keyName = "first"
		case "Bearer " + secondKey:
			keyName = "second"
		default:
			t.Errorf("unexpected account pool Authorization header %q", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		keyOrder = append(keyOrder, keyName)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if keyName == "first" {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"message":"first account is rate limited"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"resp-after-migration","object":"response","output":[{"type":"message","content":[{"type":"output_text","text":"from-second-key"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`))
	}))
	defer upstream.Close()

	pool := &ProviderPool{
		Platform:                     "openai-responses",
		Name:                         "Strict Sticky Account Pool",
		PoolType:                     ProviderPoolTypeAccount,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       2,
		AutoBlacklistDurationMinutes: 10,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            upstream.URL,
			ResponsesEndpoint: "/responses",
			Keys:              []AccountPoolKey{{APIKey: firstKey}, {APIKey: secondKey}},
		},
	}
	relay, router, relayKey, poolID := setupProviderPoolHTTPTest(t, "openai-responses", nil, pool)

	request := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+relayKey)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	// A durable conversation binding starts on the first key. It must retry A
	// until that key is blacklisted; B is eligible only after invalidation.
	initial := request(`{"model":"gpt-5","conversation":"strict-session","input":"hello"}`)
	if initial.Code != http.StatusOK || !strings.Contains(initial.Body.String(), "from-second-key") {
		t.Fatalf("initial strict sticky request = %d: %s", initial.Code, initial.Body.String())
	}
	mu.Lock()
	gotInitialOrder := append([]string(nil), keyOrder...)
	mu.Unlock()
	if want := []string{"first", "first", "second"}; fmt.Sprint(gotInitialOrder) != fmt.Sprint(want) {
		t.Fatalf("strict retry key order = %v, want %v", gotInitialOrder, want)
	}
	if statuses := relay.ListProviderBlacklistStatus("openai-responses", poolID); len(statuses) != 1 {
		t.Fatalf("first key should be blacklisted after two failures, got %+v", statuses)
	}

	// The successful fallback response is now a B-bound continuation. It must
	// not resurrect A or distribute to another key.
	continuation := request(`{"model":"gpt-5","previous_response_id":"resp-after-migration","input":"continue"}`)
	if continuation.Code != http.StatusOK || !strings.Contains(continuation.Body.String(), "from-second-key") {
		t.Fatalf("post-migration continuation = %d: %s", continuation.Code, continuation.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"first", "first", "second", "second"}; fmt.Sprint(keyOrder) != fmt.Sprint(want) {
		t.Fatalf("post-migration response-id key order = %v, want %v", keyOrder, want)
	}
}

func TestHTTPAccountPoolAnonymousFirstRequestRetriesSelectedKeyUntilBlacklist(t *testing.T) {
	const (
		firstKey  = "sk-anonymous-strict-first"
		secondKey = "sk-anonymous-strict-second"
	)

	var mu sync.Mutex
	var keyOrder []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var keyName string
		switch r.Header.Get("Authorization") {
		case "Bearer " + firstKey:
			keyName = "first"
		case "Bearer " + secondKey:
			keyName = "second"
		default:
			t.Errorf("unexpected account pool Authorization header %q", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		keyOrder = append(keyOrder, keyName)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if keyName == "first" {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"message":"first account is rate limited"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"resp-anonymous-success","object":"response","output":[{"type":"message","content":[{"type":"output_text","text":"from-second-key"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`))
	}))
	defer upstream.Close()

	pool := &ProviderPool{
		Platform:                     "openai-responses",
		Name:                         "Anonymous Strict Account Pool",
		PoolType:                     ProviderPoolTypeAccount,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       2,
		AutoBlacklistDurationMinutes: 10,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            upstream.URL,
			ResponsesEndpoint: "/responses",
			Keys:              []AccountPoolKey{{APIKey: firstKey}, {APIKey: secondKey}},
		},
	}
	relay, router, relayKey, poolID := setupProviderPoolHTTPTest(t, "openai-responses", nil, pool)

	// Deliberately omit conversation and previous_response_id: the initial
	// request still must stay on A until A becomes unavailable.
	req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5","input":"hello"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+relayKey)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "from-second-key") {
		t.Fatalf("anonymous strict request = %d: %s", w.Code, w.Body.String())
	}

	mu.Lock()
	defer mu.Unlock()
	if want := []string{"first", "first", "second"}; fmt.Sprint(keyOrder) != fmt.Sprint(want) {
		t.Fatalf("anonymous strict key order = %v, want %v", keyOrder, want)
	}
	if statuses := relay.ListProviderBlacklistStatus("openai-responses", poolID); len(statuses) != 1 {
		t.Fatalf("first key should be blacklisted after two anonymous retries: %+v", statuses)
	}
}

func TestHTTPAccountPoolFirstTextTimeoutOnlyBlacklistsTimedOutKey(t *testing.T) {
	const (
		firstKey  = "sk-first-text-timeout-first"
		secondKey = "sk-first-text-timeout-second"
	)

	var mu sync.Mutex
	var keyOrder []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer " + firstKey:
			mu.Lock()
			keyOrder = append(keyOrder, "first")
			mu.Unlock()
			time.Sleep(6 * time.Second)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"too-late"}`))
		case "Bearer " + secondKey:
			mu.Lock()
			keyOrder = append(keyOrder, "second")
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"resp-after-timeout","object":"response","output":[{"type":"message","content":[{"type":"output_text","text":"fresh-second-key"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`))
		default:
			t.Errorf("unexpected account pool Authorization header %q", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer upstream.Close()

	rule := SpecialBlacklistRule{
		ID:                "first-text-timeout",
		Name:              "First text timeout",
		HTTPStatus:        http.StatusGatewayTimeout,
		JSONPath:          "error.code",
		ExpectedJSONValue: `"first_text_timeout"`,
		Threshold:         1,
		DurationMinutes:   5,
	}
	pool := &ProviderPool{
		Platform:                     "openai-responses",
		Name:                         "First Text Timeout Account Pool",
		PoolType:                     ProviderPoolTypeAccount,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       10,
		AutoBlacklistDurationMinutes: 10,
		SpecialBlacklistRules:        []SpecialBlacklistRule{rule},
		FirstTextRetryEnabled:        true,
		FirstTextRetryTimeoutSeconds: 5,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            upstream.URL,
			ResponsesEndpoint: "/responses",
			Keys:              []AccountPoolKey{{APIKey: firstKey}, {APIKey: secondKey}},
		},
	}
	relay, router, relayKey, poolID := setupProviderPoolHTTPTest(t, "openai-responses", nil, pool)

	request := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5","conversation":"timeout-session","input":"hello"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+relayKey)
	response := httptest.NewRecorder()
	startedAt := time.Now()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "fresh-second-key") {
		t.Fatalf("fallback response = %d: %s", response.Code, response.Body.String())
	}
	if elapsed := time.Since(startedAt); elapsed < 5*time.Second || elapsed > 7*time.Second {
		t.Fatalf("two-key request duration = %s, want one five-second timeout plus prompt fallback", elapsed)
	}
	mu.Lock()
	gotOrder := append([]string(nil), keyOrder...)
	mu.Unlock()
	if want := []string{"first", "second"}; fmt.Sprint(gotOrder) != fmt.Sprint(want) {
		t.Fatalf("key attempts = %v, want %v", gotOrder, want)
	}

	statuses := relay.ListProviderBlacklistStatus("openai-responses", poolID)
	if len(statuses) != 1 || statuses[0].RuleFailureCounts[rule.ID] != 1 || statuses[0].LastReason != rule.Name {
		t.Fatalf("blacklist statuses = %+v, want only the timed-out key with one matched 504", statuses)
	}
}

func TestHTTPAccountPoolStrictStickinessMigratesWhenBoundKeyDeleted(t *testing.T) {
	const (
		firstKey  = "sk-strict-delete-first"
		secondKey = "sk-strict-delete-second"
	)

	var mu sync.Mutex
	var keyOrder []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyName := ""
		switch r.Header.Get("Authorization") {
		case "Bearer " + firstKey:
			keyName = "first"
		case "Bearer " + secondKey:
			keyName = "second"
		default:
			t.Errorf("unexpected account pool Authorization header %q", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		keyOrder = append(keyOrder, keyName)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":"resp-from-%s","object":"response","output":[{"type":"message","content":[{"type":"output_text","text":"from-%s-key"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`, keyName, keyName)
	}))
	defer upstream.Close()

	pool := &ProviderPool{
		Platform:                     "openai-responses",
		Name:                         "Strict Sticky Deletion Pool",
		PoolType:                     ProviderPoolTypeAccount,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       3,
		AutoBlacklistDurationMinutes: 10,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            upstream.URL,
			ResponsesEndpoint: "/responses",
			Keys:              []AccountPoolKey{{APIKey: firstKey}, {APIKey: secondKey}},
		},
	}
	relay, router, relayKey, poolID := setupProviderPoolHTTPTest(t, "openai-responses", nil, pool)
	request := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+relayKey)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	initial := request(`{"model":"gpt-5","conversation":"delete-session","input":"hello"}`)
	if initial.Code != http.StatusOK || !strings.Contains(initial.Body.String(), "from-first-key") {
		t.Fatalf("initial strict sticky request = %d: %s", initial.Code, initial.Body.String())
	}
	updatedPool, err := relay.poolService.ResolvePoolByID(poolID)
	if err != nil || updatedPool == nil {
		t.Fatalf("resolve account pool for key deletion: pool=%v err=%v", updatedPool, err)
	}
	if len(updatedPool.AccountPoolConfig.Keys) != 2 {
		t.Fatalf("saved key count = %d, want 2", len(updatedPool.AccountPoolConfig.Keys))
	}
	updatedPool.AccountPoolConfig.Keys = []AccountPoolKey{updatedPool.AccountPoolConfig.Keys[1]}
	if _, err := relay.poolService.SavePool(updatedPool); err != nil {
		t.Fatalf("delete bound account key: %v", err)
	}

	continuation := request(`{"model":"gpt-5","previous_response_id":"resp-from-first","input":"continue"}`)
	if continuation.Code != http.StatusOK || !strings.Contains(continuation.Body.String(), "from-second-key") {
		t.Fatalf("continuation after bound key deletion = %d: %s", continuation.Code, continuation.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"first", "second"}; fmt.Sprint(keyOrder) != fmt.Sprint(want) {
		t.Fatalf("key deletion migration order = %v, want %v", keyOrder, want)
	}
}

func TestHTTPAccountPoolConversationStickinessLinksResponseIDs(t *testing.T) {
	const (
		firstKey  = "sk-sticky-conversation-first"
		secondKey = "sk-sticky-conversation-second"
	)

	var mu sync.Mutex
	var keyOrder []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		keyName := ""
		switch r.Header.Get("Authorization") {
		case "Bearer " + firstKey:
			keyName = "first"
		case "Bearer " + secondKey:
			keyName = "second"
		default:
			t.Errorf("unexpected account pool Authorization header %q", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		keyOrder = append(keyOrder, keyName)
		mu.Unlock()

		requestBody := string(body)
		if strings.Contains(requestBody, `"stream":true`) {
			responseID := "resp-stream-a"
			if strings.Contains(requestBody, "resp-stream-a") {
				responseID = "resp-stream-b"
			}
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprintf(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"stream\"}\n\n")
			_, _ = fmt.Fprintf(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":%q,\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n", responseID)
			_, _ = w.Write([]byte("data: [DONE]\n\n"))
			return
		}

		responseID := "resp-nonstream-a"
		if strings.Contains(requestBody, "resp-nonstream-a") {
			responseID = "resp-nonstream-b"
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":%q,"object":"response","output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`, responseID)
	}))
	defer upstream.Close()

	pool := &ProviderPool{
		Platform:                     "openai-responses",
		Name:                         "Sticky Conversation Pool",
		PoolType:                     ProviderPoolTypeAccount,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       3,
		AutoBlacklistDurationMinutes: 10,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            upstream.URL,
			ResponsesEndpoint: "/responses",
			Keys: []AccountPoolKey{
				{APIKey: firstKey},
				{APIKey: secondKey},
			},
		},
	}
	_, router, relayKey, _ := setupProviderPoolHTTPTest(t, "openai-responses", nil, pool)

	request := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+relayKey)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	for _, body := range []string{
		`{"model":"gpt-5","conversation":"conversation-nonstream","input":"hello"}`,
		`{"model":"gpt-5","previous_response_id":"resp-nonstream-a","input":"continue"}`,
		`{"model":"gpt-5","previous_response_id":"resp-nonstream-b","input":"continue"}`,
		`{"model":"gpt-5","conversation":{"id":"conversation-stream"},"input":"hello","stream":true}`,
		`{"model":"gpt-5","previous_response_id":"resp-stream-a","input":"continue","stream":true}`,
		`{"model":"gpt-5","prompt_cache_key":"pi-session-1","input":"hello"}`,
		`{"model":"gpt-5","prompt_cache_key":"pi-session-1","input":"continue"}`,
	} {
		response := request(body)
		if response.Code != http.StatusOK {
			t.Fatalf("sticky response status = %d, body=%s", response.Code, response.Body.String())
		}
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"first", "first", "first", "second", "second", "first", "first"}
	if fmt.Sprint(keyOrder) != fmt.Sprint(want) {
		t.Fatalf("sticky key order = %v, want %v", keyOrder, want)
	}
}

func TestHTTPAccountPoolStreamCompletionAliasIsAvailableBeforeEOF(t *testing.T) {
	const (
		firstKey  = "sk-stream-alias-first"
		secondKey = "sk-stream-alias-second"
	)
	var mu sync.Mutex
	var firstKeyHits, secondKeyHits int
	releaseFirstStream := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseFirstStream) })
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		stream := strings.Contains(string(body), `"stream":true`)
		writeContinuation := func(label string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"id":"resp_continuation","object":"response","output":[{"type":"message","content":[{"type":"output_text","text":%q}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`, label)
		}

		switch r.Header.Get("Authorization") {
		case "Bearer " + firstKey:
			mu.Lock()
			firstKeyHits++
			mu.Unlock()
			if !stream {
				writeContinuation("from-first-key")
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"first\"}\n\n"))
			_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_stream_a\"}}\n\n"))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			select {
			case <-releaseFirstStream:
				_, _ = w.Write([]byte("data: [DONE]\n\n"))
			case <-r.Context().Done():
			}
		case "Bearer " + secondKey:
			mu.Lock()
			secondKeyHits++
			mu.Unlock()
			writeContinuation("from-second-key")
		default:
			t.Errorf("unexpected account pool Authorization header %q", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer upstream.Close()

	pool := &ProviderPool{
		Platform:                     "openai-responses",
		Name:                         "Open Stream Alias Pool",
		PoolType:                     ProviderPoolTypeAccount,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       3,
		AutoBlacklistDurationMinutes: 10,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            upstream.URL,
			ResponsesEndpoint: "/responses",
			Keys:              []AccountPoolKey{{APIKey: firstKey}, {APIKey: secondKey}},
		},
	}
	_, router, relayKey, _ := setupProviderPoolHTTPTest(t, "openai-responses", nil, pool)
	relayServer := httptest.NewServer(router)
	defer relayServer.Close()
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	firstRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, relayServer.URL+"/responses", strings.NewReader(`{"model":"gpt-5","input":"first","stream":true}`))
	if err != nil {
		t.Fatalf("create first request: %v", err)
	}
	firstRequest.Header.Set("Content-Type", "application/json")
	firstRequest.Header.Set("Authorization", "Bearer "+relayKey)
	firstResponse, err := http.DefaultClient.Do(firstRequest)
	if err != nil {
		t.Fatalf("start first stream: %v", err)
	}
	defer firstResponse.Body.Close()
	if firstResponse.StatusCode != http.StatusOK {
		t.Fatalf("first stream status = %d", firstResponse.StatusCode)
	}

	reader := bufio.NewReader(firstResponse.Body)
	for {
		line, readErr := reader.ReadString('\n')
		if strings.Contains(line, `"type":"response.completed"`) {
			break
		}
		if readErr != nil {
			t.Fatalf("first stream ended before completed event: %v", readErr)
		}
	}

	continuationRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, relayServer.URL+"/responses", strings.NewReader(`{"model":"gpt-5","previous_response_id":"resp_stream_a","input":"continue"}`))
	if err != nil {
		t.Fatalf("create continuation request: %v", err)
	}
	continuationRequest.Header.Set("Content-Type", "application/json")
	continuationRequest.Header.Set("Authorization", "Bearer "+relayKey)
	continuationResponse, err := http.DefaultClient.Do(continuationRequest)
	if err != nil {
		t.Fatalf("send continuation before EOF: %v", err)
	}
	continuationBody, _ := io.ReadAll(continuationResponse.Body)
	_ = continuationResponse.Body.Close()
	if continuationResponse.StatusCode != http.StatusOK || !strings.Contains(string(continuationBody), "from-first-key") {
		t.Fatalf("continuation before EOF did not keep key A: %d %s", continuationResponse.StatusCode, continuationBody)
	}

	mu.Lock()
	first, second := firstKeyHits, secondKeyHits
	mu.Unlock()
	if first != 2 || second != 0 {
		t.Fatalf("continuation key hits = (%d,%d), want (2,0)", first, second)
	}
	release()
	_, _ = io.Copy(io.Discard, reader)
}

func TestHTTPModelsSkipsBlacklistedProvider(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	configDir := filepath.Join(testHome, ".code-switch")
	_ = os.MkdirAll(configDir, 0o700)

	providerAHits := 0
	providerBHits := 0

	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerAHits++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"provider-a forbidden"}`))
	}))
	defer upstreamA.Close()

	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerBHits++
		if r.URL.Path != "/v1/models" {
			t.Errorf("expected /v1/models, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"model-b"}]}`))
	}))
	defer upstreamB.Close()

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: upstreamA.URL, APIKey: "key-a"},
		{ID: 2, Name: "provider-b", Enabled: true, APIURL: upstreamB.URL, APIKey: "key-b"},
	}
	payload, _ := json.Marshal(providerEnvelope{Providers: providers})
	_ = os.WriteFile(filepath.Join(configDir, "openai-chat.json"), payload, 0o600)

	providerService := NewProviderService()
	poolService := NewProviderPoolService()
	keyService := NewCodexRelayKeyService()
	poolService.SetBindingChecker(keyService)
	appSettings := NewAppSettingsService(nil)
	notificationService := NewNotificationService(appSettings)

	relay := NewProviderRelayService(
		providerService, poolService, keyService,
		notificationService, appSettings,
		DefaultRelayBindAddr,
	)

	pool := &ProviderPool{
		Platform:                     "openai-chat",
		Name:                         "Models Pool",
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       1,
		AutoBlacklistDurationMinutes: 10,
		Members: []ProviderPoolMember{
			{ProviderID: 1, Enabled: true, Level: 1},
			{ProviderID: 2, Enabled: true, Level: 2},
		},
	}
	poolID, _ := poolService.SavePool(pool)

	key, _ := keyService.CreateKey("models-key")
	_ = keyService.SetPoolBinding(key.ID, "openai-chat", poolID)

	if !relay.recordProviderFailure("openai-chat", poolID, pool, providers[0], "previous upstream 403") {
		t.Fatal("expected provider-a to be blacklisted")
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	relay.registerRoutes(router)

	keySecret, _ := keyService.GetKeySecret(key.ID)
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+keySecret)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("models request expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if providerAHits != 0 {
		t.Fatalf("blacklisted provider-a should not be hit, got %d hits", providerAHits)
	}
	if providerBHits != 1 {
		t.Fatalf("provider-b hits = %d, want 1", providerBHits)
	}
	if !strings.Contains(w.Body.String(), "model-b") {
		t.Fatalf("models response should come from provider-b, got: %s", w.Body.String())
	}
}

func TestHTTPProviderConcurrencyManagedFallbackQueueAndCancel(t *testing.T) {
	oldTracker := defaultActiveRequestTracker
	defaultActiveRequestTracker = newActiveRequestTracker()
	t.Cleanup(func() {
		defaultActiveRequestTracker = oldTracker
	})

	aRelease := make(chan struct{})
	bRelease := make(chan struct{})
	var providerAHits int32
	var providerBHits int32
	var providerCHits int32

	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&providerAHits, 1)
		<-aRelease
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"provider":"provider-a","choices":[{"message":{"content":"from-a"}}]}`))
	}))
	defer upstreamA.Close()

	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&providerBHits, 1)
		<-bRelease
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"provider":"provider-b","choices":[{"message":{"content":"from-b"}}]}`))
	}))
	defer upstreamB.Close()

	upstreamC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&providerCHits, 1)
		w.WriteHeader(http.StatusTeapot)
	}))
	defer upstreamC.Close()

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: upstreamA.URL, APIKey: "key-a", MaxConcurrency: 1},
		{ID: 2, Name: "provider-b", Enabled: true, APIURL: upstreamB.URL, APIKey: "key-b", MaxConcurrency: 1},
		{ID: 3, Name: "provider-c", Enabled: true, APIURL: upstreamC.URL, APIKey: "key-c", MaxConcurrency: 1},
	}
	pool := &ProviderPool{
		Platform: "openai-chat",
		Name:     "Concurrency Pool",
		Mode:     ProviderPoolModeManaged,
		Members: []ProviderPoolMember{
			{ProviderID: 1, Enabled: true, Level: 1},
			{ProviderID: 2, Enabled: true, Level: 2},
			{ProviderID: 3, Enabled: false, Level: 3},
		},
	}
	relay, router, keySecret, poolID := setupProviderPoolHTTPTest(t, "openai-chat", providers, pool)

	w1, done1 := serveChatRequest(router, keySecret, `{"model":"gpt-4","messages":[{"role":"user","content":"first"}]}`)
	for atomic.LoadInt32(&providerAHits) < 1 {
		time.Sleep(10 * time.Millisecond)
	}

	w2, done2 := serveChatRequest(router, keySecret, `{"model":"gpt-4","messages":[{"role":"user","content":"second"}]}`)
	for atomic.LoadInt32(&providerBHits) < 1 {
		time.Sleep(10 * time.Millisecond)
	}

	w3, done3 := serveChatRequest(router, keySecret, `{"model":"gpt-4","messages":[{"role":"user","content":"third"}]}`)
	queued := waitForActiveLog(t, "openai-chat", func(logEntry ReqeustLog) bool {
		return logEntry.Status == requestLogStatusQueued && logEntry.QueuePosition == 1
	})
	if queued.ErrorMessage != "排队中" {
		t.Fatalf("queued error message = %q, want 排队中", queued.ErrorMessage)
	}
	if result := defaultActiveRequestTracker.Retry(queued.ID, ""); result.Status != activeRequestRetryIgnoredQueued {
		t.Fatalf("queued retry status = %q, want %q", result.Status, activeRequestRetryIgnoredQueued)
	}

	ctx, cancelQueued := context.WithCancel(context.Background())
	req4 := httptest.NewRequest(http.MethodPost, "/chat/completions", strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"cancel"}]}`)).WithContext(ctx)
	req4.Header.Set("Content-Type", "application/json")
	req4.Header.Set("Authorization", "Bearer "+keySecret)
	w4 := httptest.NewRecorder()
	done4 := make(chan struct{})
	go func() {
		router.ServeHTTP(w4, req4)
		close(done4)
	}()
	waitForActiveLog(t, "openai-chat", func(logEntry ReqeustLog) bool {
		return logEntry.Status == requestLogStatusQueued && logEntry.QueuePosition == 2
	})
	cancelQueued()
	select {
	case <-done4:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled queued request did not return")
	}
	waitForActiveLog(t, "openai-chat", func(logEntry ReqeustLog) bool {
		return logEntry.ID == queued.ID && logEntry.Status == requestLogStatusQueued && logEntry.QueuePosition == 1
	})

	if statuses := relay.ListProviderBlacklistStatus("openai-chat", poolID); len(statuses) != 0 {
		t.Fatalf("concurrency full should not blacklist providers, got %+v", statuses)
	}

	close(aRelease)
	select {
	case <-done3:
	case <-time.After(2 * time.Second):
		t.Fatal("queued request did not finish after provider-a released")
	}
	close(bRelease)
	select {
	case <-done1:
	case <-time.After(2 * time.Second):
		t.Fatal("first request did not finish")
	}
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("second request did not finish")
	}

	if w1.Code != http.StatusOK || w2.Code != http.StatusOK || w3.Code != http.StatusOK {
		t.Fatalf("codes = first %d second %d third %d, want all 200; third body=%s", w1.Code, w2.Code, w3.Code, w3.Body.String())
	}
	if atomic.LoadInt32(&providerAHits) != 2 {
		t.Fatalf("provider-a hits = %d, want 2", providerAHits)
	}
	if atomic.LoadInt32(&providerBHits) != 1 {
		t.Fatalf("provider-b hits = %d, want 1", providerBHits)
	}
	if atomic.LoadInt32(&providerCHits) != 0 {
		t.Fatalf("disabled provider-c should not be hit, got %d hits", providerCHits)
	}
}

func TestHTTPProviderConcurrencyQueuesAfterFailedProviderWhenRemainingProviderFull(t *testing.T) {
	oldTracker := defaultActiveRequestTracker
	defaultActiveRequestTracker = newActiveRequestTracker()
	t.Cleanup(func() {
		defaultActiveRequestTracker = oldTracker
	})

	testHome := t.TempDir()
	t.Setenv("HOME", testHome)
	configDir := filepath.Join(testHome, ".code-switch")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}

	var providerAHits int32
	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&providerAHits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"provider-a forbidden"}`))
	}))
	defer upstreamA.Close()

	bRelease := make(chan struct{})
	var providerBHits int32
	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit := atomic.AddInt32(&providerBHits, 1)
		if hit == 1 {
			<-bRelease
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"provider":"provider-b","choices":[{"message":{"content":"from-b"}}]}`))
	}))
	defer upstreamB.Close()

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: upstreamA.URL, APIKey: "key-a", MaxConcurrency: 1},
		{ID: 2, Name: "provider-b", Enabled: true, APIURL: upstreamB.URL, APIKey: "key-b", MaxConcurrency: 1},
	}
	payload, _ := json.Marshal(providerEnvelope{Providers: providers})
	if err := os.WriteFile(filepath.Join(configDir, "openai-chat.json"), payload, 0o600); err != nil {
		t.Fatalf("write providers: %v", err)
	}

	providerService := NewProviderService()
	poolService := NewProviderPoolService()
	keyService := NewCodexRelayKeyService()
	poolService.SetBindingChecker(keyService)
	appSettings := NewAppSettingsService(nil)
	relay := NewProviderRelayService(providerService, poolService, keyService, NewNotificationService(appSettings), appSettings, DefaultRelayBindAddr)

	blockerPoolID, err := poolService.SavePool(&ProviderPool{
		Platform: "openai-chat",
		Name:     "Blocker Pool",
		Mode:     ProviderPoolModeManaged,
		Members:  []ProviderPoolMember{{ProviderID: 2, Enabled: true, Level: 1}},
	})
	if err != nil {
		t.Fatalf("save blocker pool: %v", err)
	}
	targetPool := &ProviderPool{
		Platform:                     "openai-chat",
		Name:                         "Fallback Queue Pool",
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       1,
		AutoBlacklistDurationMinutes: 10,
		Members: []ProviderPoolMember{
			{ProviderID: 1, Enabled: true, Level: 1},
			{ProviderID: 2, Enabled: true, Level: 2},
		},
	}
	targetPoolID, err := poolService.SavePool(targetPool)
	if err != nil {
		t.Fatalf("save target pool: %v", err)
	}

	blockerKey, err := keyService.CreateKey("blocker-key")
	if err != nil {
		t.Fatalf("create blocker key: %v", err)
	}
	if err := keyService.SetPoolBinding(blockerKey.ID, "openai-chat", blockerPoolID); err != nil {
		t.Fatalf("bind blocker key: %v", err)
	}
	targetKey, err := keyService.CreateKey("target-key")
	if err != nil {
		t.Fatalf("create target key: %v", err)
	}
	if err := keyService.SetPoolBinding(targetKey.ID, "openai-chat", targetPoolID); err != nil {
		t.Fatalf("bind target key: %v", err)
	}
	blockerSecret, _ := keyService.GetKeySecret(blockerKey.ID)
	targetSecret, _ := keyService.GetKeySecret(targetKey.ID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	relay.registerRoutes(router)

	wBlocker, doneBlocker := serveChatRequest(router, blockerSecret, `{"model":"gpt-4","messages":[{"role":"user","content":"block b"}]}`)
	for atomic.LoadInt32(&providerBHits) < 1 {
		time.Sleep(10 * time.Millisecond)
	}

	wTarget, doneTarget := serveChatRequest(router, targetSecret, `{"model":"gpt-4","messages":[{"role":"user","content":"queue after a fails"}]}`)
	waitForActiveLog(t, "openai-chat", func(logEntry ReqeustLog) bool {
		return logEntry.Status == requestLogStatusQueued && logEntry.QueuePosition == 1
	})

	if atomic.LoadInt32(&providerAHits) != 1 {
		t.Fatalf("provider-a hits = %d, want 1", providerAHits)
	}
	if atomic.LoadInt32(&providerBHits) != 1 {
		t.Fatalf("target request should queue before hitting full provider-b, hits=%d", providerBHits)
	}

	close(bRelease)
	select {
	case <-doneBlocker:
	case <-time.After(2 * time.Second):
		t.Fatal("blocker request did not finish")
	}
	select {
	case <-doneTarget:
	case <-time.After(2 * time.Second):
		t.Fatal("target request did not finish after provider-b released")
	}

	if wBlocker.Code != http.StatusOK || wTarget.Code != http.StatusOK {
		t.Fatalf("codes = blocker %d target %d, want both 200; target body=%s", wBlocker.Code, wTarget.Code, wTarget.Body.String())
	}
	if atomic.LoadInt32(&providerBHits) != 2 {
		t.Fatalf("provider-b hits = %d, want 2", providerBHits)
	}
	if statuses := relay.ListProviderBlacklistStatus("openai-chat", targetPoolID); len(statuses) != 1 {
		t.Fatalf("provider-a should be blacklisted in target pool, got %+v", statuses)
	}
}

func TestHTTPProviderConcurrencyClearsStaleReservationAfterProviderBlacklisted(t *testing.T) {
	oldTracker := defaultActiveRequestTracker
	defaultActiveRequestTracker = newActiveRequestTracker()
	t.Cleanup(func() {
		defaultActiveRequestTracker = oldTracker
	})

	testHome := t.TempDir()
	t.Setenv("HOME", testHome)
	configDir := filepath.Join(testHome, ".code-switch")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}

	aRelease := make(chan struct{})
	bRelease := make(chan struct{})
	var closeA sync.Once
	var closeB sync.Once
	t.Cleanup(func() {
		closeA.Do(func() { close(aRelease) })
		closeB.Do(func() { close(bRelease) })
	})

	var providerAHits int32
	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit := atomic.AddInt32(&providerAHits, 1)
		if hit == 1 {
			<-aRelease
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"provider-a forbidden"}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"provider-a should stay blacklisted"}`))
	}))
	defer upstreamA.Close()

	var providerBHits int32
	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit := atomic.AddInt32(&providerBHits, 1)
		if hit == 1 {
			<-bRelease
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"provider":"provider-b","choices":[{"message":{"content":"from-b"}}]}`))
	}))
	defer upstreamB.Close()

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: upstreamA.URL, APIKey: "key-a", MaxConcurrency: 1},
		{ID: 2, Name: "provider-b", Enabled: true, APIURL: upstreamB.URL, APIKey: "key-b", MaxConcurrency: 1},
	}
	payload, _ := json.Marshal(providerEnvelope{Providers: providers})
	if err := os.WriteFile(filepath.Join(configDir, "openai-chat.json"), payload, 0o600); err != nil {
		t.Fatalf("write providers: %v", err)
	}

	providerService := NewProviderService()
	poolService := NewProviderPoolService()
	keyService := NewCodexRelayKeyService()
	poolService.SetBindingChecker(keyService)
	appSettings := NewAppSettingsService(nil)
	relay := NewProviderRelayService(providerService, poolService, keyService, NewNotificationService(appSettings), appSettings, DefaultRelayBindAddr)

	blockerPoolID, err := poolService.SavePool(&ProviderPool{
		Platform: "openai-chat",
		Name:     "Stale Reservation Blocker Pool",
		Mode:     ProviderPoolModeManaged,
		Members:  []ProviderPoolMember{{ProviderID: 2, Enabled: true, Level: 1}},
	})
	if err != nil {
		t.Fatalf("save blocker pool: %v", err)
	}
	targetPoolID, err := poolService.SavePool(&ProviderPool{
		Platform:                     "openai-chat",
		Name:                         "Stale Reservation Target Pool",
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       1,
		AutoBlacklistDurationMinutes: 10,
		Members: []ProviderPoolMember{
			{ProviderID: 1, Enabled: true, Level: 1},
			{ProviderID: 2, Enabled: true, Level: 2},
		},
	})
	if err != nil {
		t.Fatalf("save target pool: %v", err)
	}

	blockerKey, _ := keyService.CreateKey("stale-reservation-blocker")
	targetKey, _ := keyService.CreateKey("stale-reservation-target")
	_ = keyService.SetPoolBinding(blockerKey.ID, "openai-chat", blockerPoolID)
	_ = keyService.SetPoolBinding(targetKey.ID, "openai-chat", targetPoolID)
	blockerSecret, _ := keyService.GetKeySecret(blockerKey.ID)
	targetSecret, _ := keyService.GetKeySecret(targetKey.ID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	relay.registerRoutes(router)

	wBlocker, doneBlocker := serveChatRequest(router, blockerSecret, `{"model":"gpt-4","messages":[{"role":"user","content":"block b"}]}`)
	for atomic.LoadInt32(&providerBHits) < 1 {
		time.Sleep(10 * time.Millisecond)
	}

	wFirst, doneFirst := serveChatRequest(router, targetSecret, `{"model":"gpt-4","messages":[{"role":"user","content":"first hits a"}]}`)
	for atomic.LoadInt32(&providerAHits) < 1 {
		time.Sleep(10 * time.Millisecond)
	}

	wQueued, doneQueued := serveChatRequest(router, targetSecret, `{"model":"gpt-4","messages":[{"role":"user","content":"queued should use b"}]}`)
	waitForActiveLog(t, "openai-chat", func(logEntry ReqeustLog) bool {
		return logEntry.Status == requestLogStatusQueued && logEntry.QueuePosition == 1
	})

	closeA.Do(func() { close(aRelease) })
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if statuses := relay.ListProviderBlacklistStatus("openai-chat", targetPoolID); len(statuses) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if statuses := relay.ListProviderBlacklistStatus("openai-chat", targetPoolID); len(statuses) != 1 {
		t.Fatalf("provider-a should be blacklisted before provider-b releases, got %+v", statuses)
	}

	closeB.Do(func() { close(bRelease) })
	for name, done := range map[string]<-chan struct{}{
		"blocker": doneBlocker,
		"first":   doneFirst,
		"queued":  doneQueued,
	} {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s request did not finish", name)
		}
	}

	if wBlocker.Code != http.StatusOK || wFirst.Code != http.StatusOK || wQueued.Code != http.StatusOK {
		t.Fatalf("codes = blocker %d first %d queued %d, want all 200; queued body=%s", wBlocker.Code, wFirst.Code, wQueued.Code, wQueued.Body.String())
	}
	if atomic.LoadInt32(&providerAHits) != 1 {
		t.Fatalf("provider-a hits = %d, want 1", providerAHits)
	}
	if atomic.LoadInt32(&providerBHits) != 3 {
		t.Fatalf("provider-b hits = %d, want 3", providerBHits)
	}
	if !strings.Contains(wQueued.Body.String(), `"provider":"provider-b"`) {
		t.Fatalf("queued request should route to provider-b after stale reservation clears, got: %s", wQueued.Body.String())
	}
}

func TestHTTPProviderConcurrencyManualModeQueuesWithoutFallback(t *testing.T) {
	oldTracker := defaultActiveRequestTracker
	defaultActiveRequestTracker = newActiveRequestTracker()
	t.Cleanup(func() {
		defaultActiveRequestTracker = oldTracker
	})

	aRelease := make(chan struct{})
	var providerAHits int32
	var providerBHits int32

	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&providerAHits, 1)
		<-aRelease
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"provider":"provider-a","choices":[{"message":{"content":"from-a"}}]}`))
	}))
	defer upstreamA.Close()

	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&providerBHits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"provider":"provider-b","choices":[{"message":{"content":"from-b"}}]}`))
	}))
	defer upstreamB.Close()

	manualProviderID := int64(1)
	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: upstreamA.URL, APIKey: "key-a", MaxConcurrency: 1},
		{ID: 2, Name: "provider-b", Enabled: true, APIURL: upstreamB.URL, APIKey: "key-b", MaxConcurrency: 1},
	}
	pool := &ProviderPool{
		Platform:         "openai-chat",
		Name:             "Manual Concurrency Pool",
		Mode:             ProviderPoolModeManual,
		ManualProviderID: &manualProviderID,
		Members: []ProviderPoolMember{
			{ProviderID: 1, Enabled: true},
			{ProviderID: 2, Enabled: true},
		},
	}
	_, router, keySecret, _ := setupProviderPoolHTTPTest(t, "openai-chat", providers, pool)

	w1, done1 := serveChatRequest(router, keySecret, `{"model":"gpt-4","messages":[{"role":"user","content":"first"}]}`)
	for atomic.LoadInt32(&providerAHits) < 1 {
		time.Sleep(10 * time.Millisecond)
	}

	w2, done2 := serveChatRequest(router, keySecret, `{"model":"gpt-4","messages":[{"role":"user","content":"second"}]}`)
	waitForActiveLog(t, "openai-chat", func(logEntry ReqeustLog) bool {
		return logEntry.Status == requestLogStatusQueued && logEntry.QueuePosition == 1
	})
	if atomic.LoadInt32(&providerBHits) != 0 {
		t.Fatalf("manual mode should not fallback to provider-b, hits=%d", providerBHits)
	}

	close(aRelease)
	select {
	case <-done1:
	case <-time.After(2 * time.Second):
		t.Fatal("first manual request did not finish")
	}
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("queued manual request did not finish")
	}
	if w1.Code != http.StatusOK || w2.Code != http.StatusOK {
		t.Fatalf("manual codes = first %d second %d, want 200", w1.Code, w2.Code)
	}
	if atomic.LoadInt32(&providerAHits) != 2 {
		t.Fatalf("provider-a hits = %d, want 2", providerAHits)
	}
	if atomic.LoadInt32(&providerBHits) != 0 {
		t.Fatalf("provider-b hits = %d, want 0", providerBHits)
	}
}

func TestHTTPProviderConcurrencyStreamingRequestHoldsSlotUntilFinished(t *testing.T) {
	oldTracker := defaultActiveRequestTracker
	defaultActiveRequestTracker = newActiveRequestTracker()
	t.Cleanup(func() {
		defaultActiveRequestTracker = oldTracker
	})

	streamRelease := make(chan struct{})
	streamStarted := make(chan struct{}, 2)
	var hits int32

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n"))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		streamStarted <- struct{}{}
		<-streamRelease
		_, _ = w.Write([]byte("data: {\"choices\":[{\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer upstream.Close()

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: upstream.URL, APIKey: "key-a", MaxConcurrency: 1},
	}
	pool := &ProviderPool{
		Platform: "openai-chat",
		Name:     "Streaming Concurrency Pool",
		Mode:     ProviderPoolModeManaged,
		Members:  []ProviderPoolMember{{ProviderID: 1, Enabled: true, Level: 1}},
	}
	_, router, keySecret, _ := setupProviderPoolHTTPTest(t, "openai-chat", providers, pool)

	body := `{"model":"gpt-4","stream":true,"messages":[{"role":"user","content":"stream"}]}`
	w1, done1 := serveChatRequest(router, keySecret, body)
	select {
	case <-streamStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("first stream did not start")
	}

	w2, done2 := serveChatRequest(router, keySecret, body)
	waitForActiveLog(t, "openai-chat", func(logEntry ReqeustLog) bool {
		return logEntry.Status == requestLogStatusQueued && logEntry.QueuePosition == 1
	})
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("second stream should be queued before first stream finishes, hits=%d", hits)
	}

	close(streamRelease)
	select {
	case <-done1:
	case <-time.After(2 * time.Second):
		t.Fatal("first stream did not finish")
	}
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("queued stream did not finish")
	}
	if w1.Code != http.StatusOK || w2.Code != http.StatusOK {
		t.Fatalf("stream codes = first %d second %d, want both 200", w1.Code, w2.Code)
	}
	if atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("upstream stream hits = %d, want 2", hits)
	}
}

func TestHTTPProviderConcurrencySharedProviderWakesQueuedDifferentPool(t *testing.T) {
	oldTracker := defaultActiveRequestTracker
	defaultActiveRequestTracker = newActiveRequestTracker()
	t.Cleanup(func() {
		defaultActiveRequestTracker = oldTracker
	})

	testHome := t.TempDir()
	t.Setenv("HOME", testHome)
	configDir := filepath.Join(testHome, ".code-switch")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}

	release := make(chan struct{})
	var hits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"provider":"provider-a","choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer upstream.Close()

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: upstream.URL, APIKey: "key-a", MaxConcurrency: 1},
	}
	payload, _ := json.Marshal(providerEnvelope{Providers: providers})
	if err := os.WriteFile(filepath.Join(configDir, "openai-chat.json"), payload, 0o600); err != nil {
		t.Fatalf("write providers: %v", err)
	}

	providerService := NewProviderService()
	poolService := NewProviderPoolService()
	keyService := NewCodexRelayKeyService()
	poolService.SetBindingChecker(keyService)
	appSettings := NewAppSettingsService(nil)
	relay := NewProviderRelayService(providerService, poolService, keyService, NewNotificationService(appSettings), appSettings, DefaultRelayBindAddr)

	poolA := &ProviderPool{
		Platform: "openai-chat",
		Name:     "Pool A",
		Mode:     ProviderPoolModeManaged,
		Members:  []ProviderPoolMember{{ProviderID: 1, Enabled: true, Level: 1}},
	}
	poolAID, err := poolService.SavePool(poolA)
	if err != nil {
		t.Fatalf("save pool A: %v", err)
	}
	poolB := &ProviderPool{
		Platform: "openai-chat",
		Name:     "Pool B",
		Mode:     ProviderPoolModeManaged,
		Members:  []ProviderPoolMember{{ProviderID: 1, Enabled: true, Level: 1}},
	}
	poolBID, err := poolService.SavePool(poolB)
	if err != nil {
		t.Fatalf("save pool B: %v", err)
	}
	keyA, _ := keyService.CreateKey("key-a")
	keyB, _ := keyService.CreateKey("key-b")
	_ = keyService.SetPoolBinding(keyA.ID, "openai-chat", poolAID)
	_ = keyService.SetPoolBinding(keyB.ID, "openai-chat", poolBID)
	secretA, _ := keyService.GetKeySecret(keyA.ID)
	secretB, _ := keyService.GetKeySecret(keyB.ID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	relay.registerRoutes(router)

	w1, done1 := serveChatRequest(router, secretA, `{"model":"gpt-4","messages":[{"role":"user","content":"pool-a"}]}`)
	for atomic.LoadInt32(&hits) < 1 {
		time.Sleep(10 * time.Millisecond)
	}

	w2, done2 := serveChatRequest(router, secretB, `{"model":"gpt-4","messages":[{"role":"user","content":"pool-b"}]}`)
	waitForActiveLog(t, "openai-chat", func(logEntry ReqeustLog) bool {
		return logEntry.Status == requestLogStatusQueued && logEntry.QueuePosition == 1
	})
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("pool B request should be queued while shared provider is occupied, hits=%d", hits)
	}

	close(release)
	select {
	case <-done1:
	case <-time.After(2 * time.Second):
		t.Fatal("pool A request did not finish")
	}
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("pool B queued request did not wake after shared provider release")
	}
	if w1.Code != http.StatusOK || w2.Code != http.StatusOK {
		t.Fatalf("shared provider codes = poolA %d poolB %d, want both 200", w1.Code, w2.Code)
	}
	if atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("shared provider hits = %d, want 2", hits)
	}
}

func TestHTTPClientCancelBeforeUpstreamHeadersDoesNotBlacklistProvider(t *testing.T) {
	oldTracker := defaultActiveRequestTracker
	defaultActiveRequestTracker = newActiveRequestTracker()
	t.Cleanup(func() {
		defaultActiveRequestTracker = oldTracker
	})

	started := make(chan struct{}, 1)
	unblock := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-unblock
	}))
	defer upstream.Close()

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: upstream.URL, APIKey: "key-a", MaxConcurrency: 1},
	}
	pool := &ProviderPool{
		Platform:                     "openai-chat",
		Name:                         "Cancel Pool",
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       1,
		AutoBlacklistDurationMinutes: 10,
		Members:                      []ProviderPoolMember{{ProviderID: 1, Enabled: true, Level: 1}},
	}
	relay, router, keySecret, poolID := setupProviderPoolHTTPTest(t, "openai-chat", providers, pool)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/chat/completions", strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"cancel"}]}`)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+keySecret)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		router.ServeHTTP(w, req)
		close(done)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream request did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(unblock)
		t.Fatal("cancelled in-flight request did not return")
	}
	close(unblock)
	if statuses := relay.ListProviderBlacklistStatus("openai-chat", poolID); len(statuses) != 0 {
		t.Fatalf("client cancellation should not blacklist provider, got %+v", statuses)
	}
}

func TestHTTPClientCancelDuringNonStreamingBodyDoesNotBlacklistProvider(t *testing.T) {
	oldTracker := defaultActiveRequestTracker
	defaultActiveRequestTracker = newActiveRequestTracker()
	t.Cleanup(func() {
		defaultActiveRequestTracker = oldTracker
	})

	headersSent := make(chan struct{}, 1)
	unblock := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		headersSent <- struct{}{}
		<-unblock
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer upstream.Close()

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: upstream.URL, APIKey: "key-a", MaxConcurrency: 1},
	}
	pool := &ProviderPool{
		Platform:                     "openai-chat",
		Name:                         "Cancel Body Pool",
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       1,
		AutoBlacklistDurationMinutes: 10,
		Members:                      []ProviderPoolMember{{ProviderID: 1, Enabled: true, Level: 1}},
	}
	relay, router, keySecret, poolID := setupProviderPoolHTTPTest(t, "openai-chat", providers, pool)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/chat/completions", strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"cancel body"}]}`)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+keySecret)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		router.ServeHTTP(w, req)
		close(done)
	}()

	select {
	case <-headersSent:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream headers were not sent")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(unblock)
		t.Fatal("cancelled body read did not return")
	}
	close(unblock)
	if statuses := relay.ListProviderBlacklistStatus("openai-chat", poolID); len(statuses) != 0 {
		t.Fatalf("client cancellation during body read should not blacklist provider, got %+v", statuses)
	}
}

func TestHTTPModelsClientCancelDoesNotBlacklistProvider(t *testing.T) {
	oldTracker := defaultActiveRequestTracker
	defaultActiveRequestTracker = newActiveRequestTracker()
	t.Cleanup(func() {
		defaultActiveRequestTracker = oldTracker
	})

	started := make(chan struct{}, 1)
	unblock := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-unblock
	}))
	defer upstream.Close()

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: upstream.URL, APIKey: "key-a", MaxConcurrency: 1},
	}
	pool := &ProviderPool{
		Platform:                     "openai-chat",
		Name:                         "Models Cancel Pool",
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       1,
		AutoBlacklistDurationMinutes: 10,
		Members:                      []ProviderPoolMember{{ProviderID: 1, Enabled: true, Level: 1}},
	}
	relay, router, keySecret, poolID := setupProviderPoolHTTPTest(t, "openai-chat", providers, pool)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+keySecret)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		router.ServeHTTP(w, req)
		close(done)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream models request did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(unblock)
		t.Fatal("cancelled models request did not return")
	}
	close(unblock)
	if statuses := relay.ListProviderBlacklistStatus("openai-chat", poolID); len(statuses) != 0 {
		t.Fatalf("models client cancellation should not blacklist provider, got %+v", statuses)
	}
}

func TestHTTPProcessingRetryEnqueuesBehindExistingQueue(t *testing.T) {
	oldTracker := defaultActiveRequestTracker
	defaultActiveRequestTracker = newActiveRequestTracker()
	t.Cleanup(func() {
		defaultActiveRequestTracker = oldTracker
	})

	firstEntered := make(chan struct{}, 1)
	order := make(chan string, 2)
	var hits int32
	var firstCancelled int32

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		hit := atomic.AddInt32(&hits, 1)
		if hit == 1 {
			firstEntered <- struct{}{}
			select {
			case <-r.Context().Done():
				atomic.StoreInt32(&firstCancelled, 1)
			case <-time.After(2 * time.Second):
				w.WriteHeader(http.StatusGatewayTimeout)
			}
			return
		}
		order <- string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"provider":"provider-a","choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer upstream.Close()

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: upstream.URL, APIKey: "key-a", MaxConcurrency: 1},
	}
	pool := &ProviderPool{
		Platform: "openai-chat",
		Name:     "Retry FIFO Pool",
		Mode:     ProviderPoolModeManaged,
		Members:  []ProviderPoolMember{{ProviderID: 1, Enabled: true, Level: 1}},
	}
	_, router, keySecret, _ := setupProviderPoolHTTPTest(t, "openai-chat", providers, pool)

	firstBody := `{"model":"gpt-4","messages":[{"role":"user","content":"first"}]}`
	secondBody := `{"model":"gpt-4","messages":[{"role":"user","content":"second"}]}`
	w1, done1 := serveChatRequest(router, keySecret, firstBody)
	select {
	case <-firstEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("first upstream request did not start")
	}

	w2, done2 := serveChatRequest(router, keySecret, secondBody)
	waitForActiveLog(t, "openai-chat", func(logEntry ReqeustLog) bool {
		return logEntry.Status == requestLogStatusQueued && logEntry.QueuePosition == 1
	})
	processing := waitForActiveLog(t, "openai-chat", func(logEntry ReqeustLog) bool {
		return logEntry.Status == requestLogStatusProcessing && logEntry.Provider == "provider-a"
	})
	if result := defaultActiveRequestTracker.Retry(processing.ID, ""); result.Status != activeRequestRetryTriggered {
		t.Fatalf("processing retry status = %q, want %q", result.Status, activeRequestRetryTriggered)
	}

	var firstAfterRetry string
	var secondAfterRetry string
	select {
	case firstAfterRetry = <-order:
	case <-time.After(2 * time.Second):
		t.Fatal("first queued turn did not reach upstream")
	}
	select {
	case secondAfterRetry = <-order:
	case <-time.After(2 * time.Second):
		t.Fatal("retried request did not reach upstream after queued request")
	}

	if !strings.Contains(firstAfterRetry, "second") {
		t.Fatalf("first request after retry should be existing queued request, got %s", firstAfterRetry)
	}
	if !strings.Contains(secondAfterRetry, "first") {
		t.Fatalf("retried request should run after existing queue, got %s", secondAfterRetry)
	}

	select {
	case <-done1:
	case <-time.After(2 * time.Second):
		t.Fatal("retried first request did not finish")
	}
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("queued second request did not finish")
	}
	if w1.Code != http.StatusOK || w2.Code != http.StatusOK {
		t.Fatalf("retry FIFO codes = first %d second %d, want both 200", w1.Code, w2.Code)
	}
	if atomic.LoadInt32(&firstCancelled) != 1 {
		t.Fatal("FIFO retry did not cancel the original upstream request")
	}
}

func TestHTTPRetryUsesHighestPriorityProviderAfterPriorityChange(t *testing.T) {
	oldTracker := defaultActiveRequestTracker
	defaultActiveRequestTracker = newActiveRequestTracker()
	t.Cleanup(func() {
		defaultActiveRequestTracker = oldTracker
	})

	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	configDir := filepath.Join(testHome, ".code-switch")
	_ = os.MkdirAll(configDir, 0o700)

	providerAEntered := make(chan struct{}, 1)
	var providerAHits int32
	var providerBHits int32
	var providerACancelled int32

	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		hit := atomic.AddInt32(&providerAHits, 1)
		if hit == 1 {
			providerAEntered <- struct{}{}
			select {
			case <-r.Context().Done():
				atomic.StoreInt32(&providerACancelled, 1)
			case <-time.After(2 * time.Second):
				w.WriteHeader(http.StatusGatewayTimeout)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"provider":"provider-a","choices":[{"message":{"content":"from-a"}}]}`))
	}))
	defer upstreamA.Close()

	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&providerBHits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"provider":"provider-b","choices":[{"message":{"content":"from-b"}}]}`))
	}))
	defer upstreamB.Close()

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: upstreamA.URL, APIKey: "key-a"},
		{ID: 2, Name: "provider-b", Enabled: true, APIURL: upstreamB.URL, APIKey: "key-b"},
	}
	payload, _ := json.Marshal(providerEnvelope{Providers: providers})
	_ = os.WriteFile(filepath.Join(configDir, "openai-chat.json"), payload, 0o600)

	providerService := NewProviderService()
	poolService := NewProviderPoolService()
	keyService := NewCodexRelayKeyService()
	poolService.SetBindingChecker(keyService)
	appSettings := NewAppSettingsService(nil)
	notificationService := NewNotificationService(appSettings)

	relay := NewProviderRelayService(
		providerService, poolService, keyService,
		notificationService, appSettings,
		DefaultRelayBindAddr,
	)

	pool := &ProviderPool{
		Platform: "openai-chat",
		Name:     "Retry Pool",
		Mode:     ProviderPoolModeManaged,
		Members: []ProviderPoolMember{
			{ProviderID: 1, Enabled: true, Level: 1},
			{ProviderID: 2, Enabled: true, Level: 2},
		},
	}
	poolID, _ := poolService.SavePool(pool)

	key, _ := keyService.CreateKey("retry-key")
	_ = keyService.SetPoolBinding(key.ID, "openai-chat", poolID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	relay.registerRoutes(router)

	keySecret, _ := keyService.GetKeySecret(key.ID)
	req := httptest.NewRequest(http.MethodPost, "/chat/completions", strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+keySecret)

	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		router.ServeHTTP(w, req)
		close(done)
	}()

	select {
	case <-providerAEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("provider-a was not called")
	}

	pool.Members = []ProviderPoolMember{
		{ProviderID: 2, Enabled: true, Level: 1},
		{ProviderID: 1, Enabled: true, Level: 2},
	}
	if _, err := poolService.SavePool(pool); err != nil {
		t.Fatalf("update pool priority: %v", err)
	}

	var retryResult ActiveRequestRetryResult
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		active := defaultActiveRequestTracker.List("openai-chat", "", "")
		if len(active) > 0 {
			retryResult = defaultActiveRequestTracker.Retry(active[0].ID, "")
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if retryResult.Status != activeRequestRetryTriggered {
		t.Fatalf("retry status = %q, want %q", retryResult.Status, activeRequestRetryTriggered)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not finish after retry")
	}

	if w.Code != http.StatusOK {
		t.Fatalf("retry request expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(&providerAHits) != 1 {
		t.Fatalf("provider-a hits = %d, want 1", providerAHits)
	}
	if atomic.LoadInt32(&providerBHits) != 1 {
		t.Fatalf("provider-b hits = %d, want 1", providerBHits)
	}
	if atomic.LoadInt32(&providerACancelled) != 1 {
		t.Fatal("retry did not cancel the original provider-a request")
	}
	if !strings.Contains(w.Body.String(), `"provider":"provider-b"`) {
		t.Fatalf("retry should use highest-priority provider-b, got: %s", w.Body.String())
	}
}

func TestHTTPRetryUsesCurrentManualPoolProvider(t *testing.T) {
	oldTracker := defaultActiveRequestTracker
	defaultActiveRequestTracker = newActiveRequestTracker()
	t.Cleanup(func() {
		defaultActiveRequestTracker = oldTracker
	})

	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	configDir := filepath.Join(testHome, ".code-switch")
	_ = os.MkdirAll(configDir, 0o700)

	providerAEntered := make(chan struct{}, 1)
	var providerAHits int32
	var providerBHits int32
	var providerACancelled int32

	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		atomic.AddInt32(&providerAHits, 1)
		providerAEntered <- struct{}{}
		select {
		case <-r.Context().Done():
			atomic.StoreInt32(&providerACancelled, 1)
			return
		case <-time.After(2 * time.Second):
			w.WriteHeader(http.StatusGatewayTimeout)
			_, _ = w.Write([]byte(`{"error":"provider-a was not retried"}`))
		}
	}))
	defer upstreamA.Close()

	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&providerBHits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"provider":"provider-b","choices":[{"message":{"content":"from-b"}}]}`))
	}))
	defer upstreamB.Close()

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: upstreamA.URL, APIKey: "key-a"},
		{ID: 2, Name: "provider-b", Enabled: true, APIURL: upstreamB.URL, APIKey: "key-b"},
	}
	payload, _ := json.Marshal(providerEnvelope{Providers: providers})
	_ = os.WriteFile(filepath.Join(configDir, "openai-chat.json"), payload, 0o600)

	providerService := NewProviderService()
	poolService := NewProviderPoolService()
	keyService := NewCodexRelayKeyService()
	poolService.SetBindingChecker(keyService)
	appSettings := NewAppSettingsService(nil)
	notificationService := NewNotificationService(appSettings)

	relay := NewProviderRelayService(
		providerService, poolService, keyService,
		notificationService, appSettings,
		DefaultRelayBindAddr,
	)

	manualA := int64(1)
	manualB := int64(2)
	pool := &ProviderPool{
		Platform:         "openai-chat",
		Name:             "Manual Retry Pool",
		Mode:             ProviderPoolModeManual,
		ManualProviderID: &manualA,
		Members: []ProviderPoolMember{
			{ProviderID: 1, Enabled: true},
			{ProviderID: 2, Enabled: false},
		},
	}
	poolID, _ := poolService.SavePool(pool)

	key, _ := keyService.CreateKey("manual-retry-key")
	_ = keyService.SetPoolBinding(key.ID, "openai-chat", poolID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	relay.registerRoutes(router)

	keySecret, _ := keyService.GetKeySecret(key.ID)
	req := httptest.NewRequest(http.MethodPost, "/chat/completions", strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+keySecret)

	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		router.ServeHTTP(w, req)
		close(done)
	}()

	select {
	case <-providerAEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("provider-a was not called")
	}

	pool.ManualProviderID = &manualB
	if _, err := poolService.SavePool(pool); err != nil {
		t.Fatalf("update manual provider: %v", err)
	}

	var retryResult ActiveRequestRetryResult
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		active := defaultActiveRequestTracker.List("openai-chat", "", "")
		if len(active) > 0 {
			retryResult = defaultActiveRequestTracker.Retry(active[0].ID, "")
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if retryResult.Status != activeRequestRetryTriggered {
		t.Fatalf("retry status = %q, want %q", retryResult.Status, activeRequestRetryTriggered)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not finish after retry")
	}

	if w.Code != http.StatusOK {
		t.Fatalf("manual retry request expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(&providerAHits) != 1 {
		t.Fatalf("provider-a hits = %d, want 1", providerAHits)
	}
	if atomic.LoadInt32(&providerBHits) != 1 {
		t.Fatalf("provider-b hits = %d, want 1", providerBHits)
	}
	if atomic.LoadInt32(&providerACancelled) != 1 {
		t.Fatal("manual retry did not cancel the original provider-a request")
	}
	if !strings.Contains(w.Body.String(), `"provider":"provider-b"`) {
		t.Fatalf("manual retry should use current pool provider-b, got: %s", w.Body.String())
	}
}

func TestHTTPResponsesPreflightFailuresRemainGuardedWhenLegacyGuardDisabled(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		payload     string
		wantCode    string
	}{
		{
			name:     "empty EOF",
			wantCode: emptyStreamErrorCode,
		},
		{
			name: "completed without output",
			payload: "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_empty\",\"output\":[],\"usage\":{\"input_tokens\":3,\"output_tokens\":0}}}\n\n" +
				"data: [DONE]\n\n",
			wantCode: emptyStreamErrorCode,
		},
		{
			name:     "terminal failure",
			payload:  "data: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp_failed\"}}\n\n",
			wantCode: terminalStreamFailureErrorCode,
		},
		{
			name:        "HTML instead of SSE",
			contentType: "text/html; charset=utf-8",
			payload:     "<!doctype html><html><head><title>upstream error</title></head></html>",
			wantCode:    invalidStreamContentTypeCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var hits int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&hits, 1)
				contentType := test.contentType
				if contentType == "" {
					contentType = "text/event-stream"
				}
				w.Header().Set("Content-Type", contentType)
				_, _ = io.WriteString(w, test.payload)
			}))
			defer upstream.Close()

			providers := []Provider{{ID: 1, Name: "guarded-provider", Enabled: true, APIURL: upstream.URL, APIKey: "provider-key"}}
			rule := SpecialBlacklistRule{
				ID:                "preflight-" + strings.ReplaceAll(test.wantCode, "_", "-"),
				Name:              "Preflight " + test.wantCode,
				HTTPStatus:        http.StatusBadGateway,
				JSONPath:          "error.code",
				ExpectedJSONValue: fmt.Sprintf("%q", test.wantCode),
				Threshold:         1,
				DurationMinutes:   5,
			}
			pool := &ProviderPool{
				Platform:                     "openai-responses",
				Name:                         "Guard Invariant Pool",
				Mode:                         ProviderPoolModeManaged,
				AutoBlacklistEnabled:         true,
				AutoBlacklistThreshold:       10,
				AutoBlacklistDurationMinutes: 10,
				SpecialBlacklistRules:        []SpecialBlacklistRule{rule},
				Members:                      []ProviderPoolMember{{ProviderID: 1, Enabled: true, Level: 1}},
			}
			relay, router, relayKey, poolID := setupProviderPoolHTTPTest(t, "openai-responses", providers, pool)
			settings, err := relay.appSettings.GetAppSettings()
			if err != nil {
				t.Fatalf("get app settings: %v", err)
			}
			settings.EnableCodexStreamGuard = false
			if _, err := relay.appSettings.SaveAppSettings(settings); err != nil {
				t.Fatalf("disable legacy guard setting: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5","input":"hello","stream":true}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+relayKey)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502: %s", w.Code, w.Body.String())
			}
			if got := gjson.Get(w.Body.String(), "error.code").String(); got != test.wantCode {
				t.Fatalf("error.code = %q, want %q: %s", got, test.wantCode, w.Body.String())
			}
			if got := atomic.LoadInt32(&hits); got != 1 {
				t.Fatalf("upstream hits = %d, want 1", got)
			}
			statuses := relay.ListProviderBlacklistStatus("openai-responses", poolID)
			if len(statuses) != 1 || statuses[0].LastReason != rule.Name || statuses[0].RuleFailureCounts[rule.ID] != 1 {
				t.Fatalf("preflight protocol error did not match advanced blacklist rule: %+v", statuses)
			}
		})
	}
}

func TestHTTPEmptyStreamReturns502UntilBlacklistThenFailsOver(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	configDir := filepath.Join(testHome, ".code-switch")
	_ = os.MkdirAll(configDir, 0o700)

	var providerAHits int32
	var providerBHits int32

	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		atomic.AddInt32(&providerAHits, 1)
		w.Header().Set("Content-Type", "text/event-stream")
	}))
	defer upstreamA.Close()

	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&providerBHits, 1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"from-b\"}\n\n"))
		_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer upstreamB.Close()

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: upstreamA.URL, APIKey: "key-a"},
		{ID: 2, Name: "provider-b", Enabled: true, APIURL: upstreamB.URL, APIKey: "key-b"},
	}
	payload, _ := json.Marshal(providerEnvelope{Providers: providers})
	_ = os.WriteFile(filepath.Join(configDir, "openai-responses.json"), payload, 0o600)

	providerService := NewProviderService()
	poolService := NewProviderPoolService()
	keyService := NewCodexRelayKeyService()
	poolService.SetBindingChecker(keyService)
	appSettings := NewAppSettingsService(nil)
	notificationService := NewNotificationService(appSettings)

	relay := NewProviderRelayService(
		providerService, poolService, keyService,
		notificationService, appSettings,
		DefaultRelayBindAddr,
	)

	pool := &ProviderPool{
		Platform:                     "openai-responses",
		Name:                         "Responses Retry Pool",
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       2,
		AutoBlacklistDurationMinutes: 10,
		Members: []ProviderPoolMember{
			{ProviderID: 1, Enabled: true, Level: 1},
			{ProviderID: 2, Enabled: true, Level: 2},
		},
	}
	poolID, _ := poolService.SavePool(pool)

	key, _ := keyService.CreateKey("responses-retry-key")
	_ = keyService.SetPoolBinding(key.ID, "openai-responses", poolID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	relay.registerRoutes(router)

	keySecret, _ := keyService.GetKeySecret(key.ID)
	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5.5","input":"hello","stream":true}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+keySecret)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	first := request()
	if first.Code != http.StatusBadGateway {
		t.Fatalf("first empty stream status = %d, want 502: %s", first.Code, first.Body.String())
	}
	if got := gjson.Get(first.Body.String(), "error.code").String(); got != emptyStreamErrorCode {
		t.Fatalf("first empty stream code = %q, want %q: %s", got, emptyStreamErrorCode, first.Body.String())
	}
	if got := gjson.Get(first.Body.String(), "error.upstream_status").Int(); got != http.StatusOK {
		t.Fatalf("first empty stream upstream status = %d, want 200: %s", got, first.Body.String())
	}
	if atomic.LoadInt32(&providerAHits) != 1 || atomic.LoadInt32(&providerBHits) != 0 {
		t.Fatalf("first request hits = (%d,%d), want (1,0)", providerAHits, providerBHits)
	}
	if blacklisted := relay.ListProviderBlacklistStatus("openai-responses", poolID); len(blacklisted) != 0 {
		t.Fatalf("first logical request should not blacklist provider-a: %+v", blacklisted)
	}

	second := request()
	if second.Code != http.StatusOK || !strings.Contains(second.Body.String(), "from-b") {
		t.Fatalf("second logical request should blacklist A and fail over to B, got %d: %s", second.Code, second.Body.String())
	}
	if atomic.LoadInt32(&providerAHits) != 2 {
		t.Fatalf("provider-a hits = %d, want 2", providerAHits)
	}
	if atomic.LoadInt32(&providerBHits) != 1 {
		t.Fatalf("provider-b hits = %d, want 1", providerBHits)
	}
	blacklisted := relay.ListProviderBlacklistStatus("openai-responses", poolID)
	if len(blacklisted) != 1 || blacklisted[0].ProviderID != 1 || blacklisted[0].FailureCount != 2 || blacklisted[0].LastReason != emptyStreamErrorCode {
		t.Fatalf("empty-stream blacklist status = %+v, want provider-a at 2 failures with reason %q", blacklisted, emptyStreamErrorCode)
	}
}

func TestHTTPMissingCompletionDoesNotAppendFallbackAfterStreamStarts(t *testing.T) {
	var providerAHits int32
	var providerBHits int32

	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&providerAHits, 1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial-a\"}\n\n")
	}))
	defer upstreamA.Close()

	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&providerBHits, 1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"from-b\"}\n\n")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_b\"}}\n\n")
	}))
	defer upstreamB.Close()

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: upstreamA.URL, APIKey: "key-a"},
		{ID: 2, Name: "provider-b", Enabled: true, APIURL: upstreamB.URL, APIKey: "key-b"},
	}
	pool := &ProviderPool{
		Platform:                     "openai-responses",
		Name:                         "Missing Completion Pool",
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       1,
		AutoBlacklistDurationMinutes: 10,
		Members: []ProviderPoolMember{
			{ProviderID: 1, Enabled: true, Level: 1},
			{ProviderID: 2, Enabled: true, Level: 2},
		},
	}
	relay, router, keySecret, poolID := setupProviderPoolHTTPTest(t, "openai-responses", providers, pool)

	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5","input":"hello","stream":true}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+keySecret)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	first := request()
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), "partial-a") {
		t.Fatalf("first stream = %d %q, want partial provider-a stream", first.Code, first.Body.String())
	}
	if strings.Contains(first.Body.String(), "from-b") {
		t.Fatalf("fallback data was appended after the client stream started: %q", first.Body.String())
	}
	if atomic.LoadInt32(&providerAHits) != 1 || atomic.LoadInt32(&providerBHits) != 0 {
		t.Fatalf("first request hits = (%d,%d), want (1,0)", providerAHits, providerBHits)
	}
	if blacklisted := relay.ListProviderBlacklistStatus("openai-responses", poolID); len(blacklisted) != 1 || blacklisted[0].ProviderID != 1 || blacklisted[0].LastReason != missingCompletionErrorCode {
		t.Fatalf("missing-completion stream was not recorded as a provider failure: %+v", blacklisted)
	}

	second := request()
	if second.Code != http.StatusOK || !strings.Contains(second.Body.String(), "from-b") {
		t.Fatalf("second stream = %d %q, want provider-b response", second.Code, second.Body.String())
	}
	if atomic.LoadInt32(&providerAHits) != 1 || atomic.LoadInt32(&providerBHits) != 1 {
		t.Fatalf("second request hits = (%d,%d), want (1,1)", providerAHits, providerBHits)
	}
}
