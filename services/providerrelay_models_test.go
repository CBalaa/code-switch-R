package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
)

var (
	testRelayEnvOnce sync.Once
	testRelayEnvErr  error
)

func setupRelayTestEnv(t *testing.T) {
	t.Helper()

	testRelayEnvOnce.Do(func() {
		testHome, err := os.MkdirTemp("", "codeswitch-services-test-*")
		if err != nil {
			testRelayEnvErr = err
			return
		}

		if err := os.Setenv("HOME", testHome); err != nil {
			testRelayEnvErr = err
			return
		}

		testRelayEnvErr = InitDatabase()
	})

	if testRelayEnvErr != nil {
		t.Fatalf("初始化测试环境失败: %v", testRelayEnvErr)
	}
}

func newTestRelayService(t *testing.T) (*ProviderService, *ProviderRelayService) {
	t.Helper()
	setupRelayTestEnv(t)

	homeDir, err := getUserHomeDir()
	if err != nil {
		t.Fatalf("获取测试 home 目录失败: %v", err)
	}
	_ = os.Remove(filepath.Join(homeDir, ".code-switch", "claude-code.json"))
	_ = os.Remove(filepath.Join(homeDir, ".code-switch", "codex.json"))
	_ = os.Remove(filepath.Join(homeDir, ".code-switch", codexRelayKeysFile))
	_ = os.RemoveAll(filepath.Join(homeDir, ".code-switch", "providers"))
	_ = os.Remove(filepath.Join(homeDir, ".codex", "config.toml"))
	_ = os.Remove(filepath.Join(homeDir, ".codex", "auth.json"))

	providerService := NewProviderService()
	settingsService := NewSettingsService()
	appSettings := NewAppSettingsService(nil)
	codexRelayKeys := NewCodexRelayKeyService()
	notificationService := NewNotificationService(appSettings)
	blacklistService := NewBlacklistService(settingsService, notificationService)
	geminiService := NewGeminiService("127.0.0.1:18100")

	relayService := NewProviderRelayService(
		providerService,
		geminiService,
		codexRelayKeys,
		blacklistService,
		notificationService,
		appSettings,
		"",
	)

	return providerService, relayService
}

// TestModelsHandler 测试 /v1/models 端点处理器
func TestModelsHandler(t *testing.T) {
	// 设置测试环境
	gin.SetMode(gin.TestMode)

	// 创建模拟的上游服务器
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 验证请求方法
		if r.Method != "GET" {
			t.Errorf("期望 GET 请求，收到 %s", r.Method)
		}

		// 验证路径
		if r.URL.Path != "/v1/models" {
			t.Errorf("期望路径 /v1/models，收到 %s", r.URL.Path)
		}

		// 验证 Authorization 头
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			t.Error("缺少 Authorization 头")
		}
		if authHeader != "Bearer test-api-key" {
			t.Errorf("Authorization 头不正确，期望 'Bearer test-api-key'，收到 '%s'", authHeader)
		}

		// 返回模拟的模型列表
		response := map[string]interface{}{
			"object": "list",
			"data": []map[string]interface{}{
				{
					"id":       "claude-sonnet-4",
					"object":   "model",
					"created":  1234567890,
					"owned_by": "anthropic",
				},
				{
					"id":       "claude-opus-4",
					"object":   "model",
					"created":  1234567890,
					"owned_by": "anthropic",
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer upstreamServer.Close()

	// 创建测试用的 ProviderService
	providerService, relayService := newTestRelayService(t)

	// 创建测试用的 provider（使用模拟服务器的 URL）
	testProvider := Provider{
		ID:      1,
		Name:    "TestProvider",
		APIURL:  upstreamServer.URL,
		APIKey:  "test-api-key",
		Enabled: true,
		Level:   1,
	}

	// 保存 provider 配置
	err := providerService.SaveProviders("claude", []Provider{testProvider})
	if err != nil {
		t.Fatalf("保存 provider 配置失败: %v", err)
	}

	// 创建测试路由
	router := gin.New()
	relayService.registerRoutes(router)

	relayKey, err := relayService.codexRelayKeys.EnsureDefaultKey()
	if err != nil {
		t.Fatalf("创建 relay key 失败: %v", err)
	}

	// 创建测试请求
	req := httptest.NewRequest("GET", "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+relayKey.Key)
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应状态码
	if w.Code != http.StatusOK {
		t.Errorf("期望状态码 %d，收到 %d", http.StatusOK, w.Code)
		t.Logf("响应体: %s", w.Body.String())
	}

	// 验证响应内容类型
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("期望 Content-Type 为 'application/json'，收到 '%s'", contentType)
	}

	// 验证响应体可以解析为 JSON
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Errorf("响应体不是有效的 JSON: %v", err)
		t.Logf("响应体: %s", w.Body.String())
	}

	// 验证响应包含 data 字段
	if _, ok := response["data"]; !ok {
		t.Error("响应缺少 'data' 字段")
	}
}

// TestCustomModelsHandler 测试自定义 CLI 工具的 /v1/models 端点
func TestCustomModelsHandler(t *testing.T) {
	// 设置测试环境
	gin.SetMode(gin.TestMode)

	// 创建模拟的上游服务器
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 验证请求方法
		if r.Method != "GET" {
			t.Errorf("期望 GET 请求，收到 %s", r.Method)
		}

		// 验证路径
		if r.URL.Path != "/v1/models" {
			t.Errorf("期望路径 /v1/models，收到 %s", r.URL.Path)
		}

		// 验证 Authorization 头
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer custom-api-key" {
			t.Errorf("Authorization 头不正确，期望 'Bearer custom-api-key'，收到 '%s'", authHeader)
		}

		// 返回模拟的模型列表
		response := map[string]interface{}{
			"object": "list",
			"data": []map[string]interface{}{
				{
					"id":      "custom-model-1",
					"object":  "model",
					"created": 1234567890,
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer upstreamServer.Close()

	// 创建测试用的 ProviderService
	providerService, relayService := newTestRelayService(t)

	// 创建测试用的 provider（使用模拟服务器的 URL）
	testProvider := Provider{
		ID:      1,
		Name:    "CustomTestProvider",
		APIURL:  upstreamServer.URL,
		APIKey:  "custom-api-key",
		Enabled: true,
		Level:   1,
	}

	// 保存 provider 配置（使用自定义 CLI 工具的 kind）
	toolId := "mytool"
	kind := "custom:" + toolId
	err := providerService.SaveProviders(kind, []Provider{testProvider})
	if err != nil {
		t.Fatalf("保存 provider 配置失败: %v", err)
	}

	// 创建测试路由
	router := gin.New()
	relayService.registerRoutes(router)

	// 创建测试请求
	req := httptest.NewRequest("GET", "/custom/mytool/v1/models", nil)
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应状态码
	if w.Code != http.StatusOK {
		t.Errorf("期望状态码 %d，收到 %d", http.StatusOK, w.Code)
		t.Logf("响应体: %s", w.Body.String())
	}

	// 验证响应内容类型
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("期望 Content-Type 为 'application/json'，收到 '%s'", contentType)
	}

	// 验证响应体可以解析为 JSON
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Errorf("响应体不是有效的 JSON: %v", err)
		t.Logf("响应体: %s", w.Body.String())
	}

	// 验证响应包含 data 字段
	if _, ok := response["data"]; !ok {
		t.Error("响应缺少 'data' 字段")
	}
}

func TestCodexResponsesRequireManagedKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	upstreamHits := 0
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++

		if r.Method != http.MethodPost {
			t.Errorf("期望 POST 请求，收到 %s", r.Method)
		}
		if r.URL.Path != "/responses" {
			t.Errorf("期望路径 /responses，收到 %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer provider-api-key" {
			t.Errorf("上游 Authorization 头不正确，期望 'Bearer provider-api-key'，收到 %q", got)
		}
		if got := r.Header.Get(codexRelayKeyHeader); got != "" {
			t.Errorf("relay key 不应继续转发到上游，收到 %q", got)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"resp_1","object":"response","status":"completed"}`))
	}))
	defer upstreamServer.Close()

	providerService, relayService := newTestRelayService(t)
	err := providerService.SaveProviders("codex", []Provider{
		{
			ID:      1,
			Name:    "CodexProvider",
			APIURL:  upstreamServer.URL,
			APIKey:  "provider-api-key",
			Enabled: true,
			Level:   1,
		},
	})
	if err != nil {
		t.Fatalf("保存 codex provider 失败: %v", err)
	}

	relayKey, err := relayService.codexRelayKeys.EnsureDefaultKey()
	if err != nil {
		t.Fatalf("创建 Codex relay key 失败: %v", err)
	}

	router := gin.New()
	relayService.registerRoutes(router)

	makeRequest := func(authHeader string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5-codex","input":"hello"}`))
		req.Header.Set("Content-Type", "application/json")
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	if w := makeRequest(""); w.Code != http.StatusUnauthorized {
		t.Fatalf("缺少 key 时应返回 401，实际为 %d，响应体: %s", w.Code, w.Body.String())
	}

	if w := makeRequest("Bearer wrong-key"); w.Code != http.StatusUnauthorized {
		t.Fatalf("错误 key 时应返回 401，实际为 %d，响应体: %s", w.Code, w.Body.String())
	}

	w := makeRequest("Bearer " + relayKey.Key)
	if w.Code != http.StatusOK {
		t.Fatalf("正确 key 时应返回 200，实际为 %d，响应体: %s", w.Code, w.Body.String())
	}

	if upstreamHits != 1 {
		t.Fatalf("只有合法请求才应命中上游，实际命中 %d 次", upstreamHits)
	}
}

func TestCodexEnableProxyWritesManagedRelayKey(t *testing.T) {
	setupRelayTestEnv(t)

	homeDir, err := getUserHomeDir()
	if err != nil {
		t.Fatalf("获取测试 home 目录失败: %v", err)
	}
	_ = os.Remove(filepath.Join(homeDir, ".code-switch", codexRelayKeysFile))
	_ = os.Remove(filepath.Join(homeDir, ".codex", "config.toml"))
	_ = os.Remove(filepath.Join(homeDir, ".codex", "auth.json"))

	relayKeys := NewCodexRelayKeyService()
	settings := NewCodexSettingsService("127.0.0.1:18100", relayKeys)
	if err := settings.EnableProxy(); err != nil {
		t.Fatalf("启用 Codex 代理失败: %v", err)
	}

	managedKey, err := relayKeys.EnsureDefaultKey()
	if err != nil {
		t.Fatalf("获取 relay key 失败: %v", err)
	}

	authPath := filepath.Join(homeDir, ".codex", "auth.json")
	authData, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatalf("读取 auth.json 失败: %v", err)
	}

	var payload map[string]string
	if err := json.Unmarshal(authData, &payload); err != nil {
		t.Fatalf("解析 auth.json 失败: %v", err)
	}

	if payload[codexEnvKey] != managedKey.Key {
		t.Fatalf("auth.json 中的 OPENAI_API_KEY = %q，期望 %q", payload[codexEnvKey], managedKey.Key)
	}
}

// TestModelsHandler_NoProviders 测试没有可用 provider 的情况
func TestModelsHandler_NoProviders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// 创建空的 ProviderService
	providerService, relayService := newTestRelayService(t)
	if err := providerService.SaveProviders("claude", []Provider{}); err != nil {
		t.Fatalf("清空 claude provider 配置失败: %v", err)
	}

	// 创建测试路由
	router := gin.New()
	relayService.registerRoutes(router)

	relayKey, err := relayService.codexRelayKeys.EnsureDefaultKey()
	if err != nil {
		t.Fatalf("创建 relay key 失败: %v", err)
	}

	// 创建测试请求
	req := httptest.NewRequest("GET", "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+relayKey.Key)
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应状态码应该是 404（没有可用的 provider）
	if w.Code != http.StatusNotFound {
		t.Errorf("期望状态码 %d，收到 %d", http.StatusNotFound, w.Code)
	}

	// 验证响应包含错误信息
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Errorf("响应体不是有效的 JSON: %v", err)
	}

	if _, ok := response["error"]; !ok {
		t.Error("响应缺少 'error' 字段")
	}
}
