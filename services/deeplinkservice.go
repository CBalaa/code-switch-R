package services

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DeepLinkImportRequest 深度链接导入请求模型
type DeepLinkImportRequest struct {
	Version      string  `json:"version"`              // 协议版本 (e.g., "v1")
	Resource     string  `json:"resource"`             // 资源类型 (e.g., "provider")
	App          string  `json:"app"`                  // 目标应用 (claude/codex/gemini)
	Name         string  `json:"name"`                 // 供应商名称
	Homepage     string  `json:"homepage"`             // 供应商主页
	Endpoint     string  `json:"endpoint"`             // API 端点
	APIKey       string  `json:"apiKey"`               // API 密钥
	Model        *string `json:"model,omitempty"`      // 可选模型名称
	Notes        *string `json:"notes,omitempty"`      // 可选备注
	HaikuModel   *string `json:"haikuModel,omitempty"` // Claude Haiku 模型
	SonnetModel  *string `json:"sonnetModel,omitempty"`  // Claude Sonnet 模型
	OpusModel    *string `json:"opusModel,omitempty"`  // Claude Opus 模型
	Config       *string `json:"config,omitempty"`     // Base64 编码的配置
	ConfigFormat *string `json:"configFormat,omitempty"` // 配置格式 (json/toml)
	ConfigURL    *string `json:"configUrl,omitempty"`  // 远程配置 URL
}

// DeepLinkService 深度链接服务
type DeepLinkService struct {
	providerService *ProviderService
}

// NewDeepLinkService 创建深度链接服务
func NewDeepLinkService(providerService *ProviderService) *DeepLinkService {
	return &DeepLinkService{
		providerService: providerService,
	}
}

// Start Wails生命周期方法
func (s *DeepLinkService) Start() error {
	return nil
}

// Stop Wails生命周期方法
func (s *DeepLinkService) Stop() error {
	return nil
}

// ParseDeepLinkURL 解析 ccswitch:// URL
// 预期格式: ccswitch://v1/import?resource=provider&app=claude&name=...&homepage=...&endpoint=...&apiKey=...
func (s *DeepLinkService) ParseDeepLinkURL(urlStr string) (*DeepLinkImportRequest, error) {
	// 解析 URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("无效的深度链接 URL: %w", err)
	}

	// 验证 scheme
	if parsedURL.Scheme != "ccswitch" {
		return nil, fmt.Errorf("无效的 scheme: 期望 'ccswitch', 得到 '%s'", parsedURL.Scheme)
	}

	// 提取版本（从 host）
	version := parsedURL.Host
	if version != "v1" {
		return nil, fmt.Errorf("不支持的协议版本: %s", version)
	}

	// 验证路径
	if parsedURL.Path != "/import" {
		return nil, fmt.Errorf("无效的路径: 期望 '/import', 得到 '%s'", parsedURL.Path)
	}

	// 解析查询参数
	params := parsedURL.Query()

	// 提取并验证资源类型
	resource := params.Get("resource")
	if resource == "" {
		return nil, fmt.Errorf("缺少 'resource' 参数")
	}
	if resource != "provider" {
		return nil, fmt.Errorf("不支持的资源类型: %s", resource)
	}

	// 提取必需字段
	app := params.Get("app")
	if app == "" {
		return nil, fmt.Errorf("缺少 'app' 参数")
	}
	if app != "claude" && app != "codex" && app != "openai-responses" && app != "openai-chat" && app != "gemini" {
		return nil, fmt.Errorf("无效的 app 类型: 必须是 'claude', 'openai-responses', 'openai-chat', 或 'gemini', 得到 '%s'", app)
	}

	name := params.Get("name")
	if name == "" {
		return nil, fmt.Errorf("缺少 'name' 参数")
	}

	// 这些字段在 v3.8+ 中可选（支持配置文件自动填充）
	homepage := params.Get("homepage")
	endpoint := params.Get("endpoint")
	apiKey := params.Get("apiKey")

	// 验证 URL（如果提供）
	if homepage != "" {
		if err := validateHTTPURL(homepage, "homepage"); err != nil {
			return nil, err
		}
	}
	if endpoint != "" {
		if err := validateHTTPURL(endpoint, "endpoint"); err != nil {
			return nil, err
		}
	}

	// 提取可选字段
	var model, notes, haikuModel, sonnetModel, opusModel, config, configFormat, configURL *string
	if v := params.Get("model"); v != "" {
		model = &v
	}
	if v := params.Get("notes"); v != "" {
		notes = &v
	}
	if v := params.Get("haikuModel"); v != "" {
		haikuModel = &v
	}
	if v := params.Get("sonnetModel"); v != "" {
		sonnetModel = &v
	}
	if v := params.Get("opusModel"); v != "" {
		opusModel = &v
	}
	if v := params.Get("config"); v != "" {
		config = &v
	}
	if v := params.Get("configFormat"); v != "" {
		configFormat = &v
	}
	if v := params.Get("configUrl"); v != "" {
		configURL = &v
	}

	return &DeepLinkImportRequest{
		Version:      version,
		Resource:     resource,
		App:          app,
		Name:         name,
		Homepage:     homepage,
		Endpoint:     endpoint,
		APIKey:       apiKey,
		Model:        model,
		Notes:        notes,
		HaikuModel:   haikuModel,
		SonnetModel:  sonnetModel,
		OpusModel:    opusModel,
		Config:       config,
		ConfigFormat: configFormat,
		ConfigURL:    configURL,
	}, nil
}

// ImportProviderFromDeepLink 从深度链接导入供应商
func (s *DeepLinkService) ImportProviderFromDeepLink(request *DeepLinkImportRequest) (string, error) {
	// 1. 合并配置文件（如果提供）
	merged, err := s.parseAndMergeConfig(request)
	if err != nil {
		return "", err
	}

	// 2. 验证必需字段（合并后）
	if merged.APIKey == "" {
		return "", fmt.Errorf("API key 是必需的（在 URL 或配置文件中）")
	}
	if merged.Endpoint == "" {
		return "", fmt.Errorf("Endpoint 是必需的（在 URL 或配置文件中）")
	}
	if merged.Homepage == "" {
		return "", fmt.Errorf("Homepage 是必需的（在 URL 或配置文件中）")
	}

	// 3. 根据 app 类型构建 Provider
	provider, err := s.buildProviderFromRequest(merged)
	if err != nil {
		return "", err
	}

	// 4. 添加到对应的平台
	var kind string
	switch merged.App {
	case "claude":
		kind = "claude"
	case "codex", "openai-responses":
		kind = "openai-responses"
	case "openai-chat":
		kind = "openai-chat"
	case "gemini":
		// Gemini 暂不支持通过 ProviderService 添加，返回友好提示
		return "", fmt.Errorf("Gemini 供应商导入暂不支持，请使用 Gemini 页面手动添加")
	default:
		return "", fmt.Errorf("不支持的 app 类型: %s", merged.App)
	}

	// 加载现有供应商列表
	providers, err := s.providerService.LoadProviders(kind)
	if err != nil {
		return "", fmt.Errorf("加载供应商列表失败: %w", err)
	}

	// 添加新供应商到列表
	providers = append(providers, *provider)

	// 保存更新后的列表
	if err := s.providerService.SaveProviders(kind, providers); err != nil {
		return "", fmt.Errorf("保存供应商失败: %w", err)
	}

	return strconv.FormatInt(provider.ID, 10), nil
}

// buildProviderFromRequest 从深度链接请求构建 Provider
func (s *DeepLinkService) buildProviderFromRequest(request *DeepLinkImportRequest) (*Provider, error) {
	// 生成唯一 ID（使用时间戳）
	id := time.Now().UnixNano()

	provider := &Provider{
		ID:      id,
		Name:    request.Name,
		APIURL:  request.Endpoint,
		APIKey:  request.APIKey,
		Site:    request.Homepage,
		Enabled: false, // 默认禁用，用户需手动启用
		Level:   1,     // 默认最高优先级
	}

	// 如果提供了模型信息，可以设置到 SupportedModels
	if request.Model != nil && *request.Model != "" {
		provider.SupportedModels = map[string]bool{
			*request.Model: true,
		}
	}

	return provider, nil
}

// parseAndMergeConfig 解析并合并配置
// 优先级: URL 参数 > 内联配置 > 远程配置
func (s *DeepLinkService) parseAndMergeConfig(request *DeepLinkImportRequest) (*DeepLinkImportRequest, error) {
	// 如果没有配置，直接返回原始请求
	if request.Config == nil && request.ConfigURL == nil {
		return request, nil
	}

	// 获取配置内容
	var configContent string
	if request.Config != nil {
		// 解码 Base64 内联配置
		decoded, err := base64.StdEncoding.DecodeString(*request.Config)
		if err != nil {
			return nil, fmt.Errorf("无效的 Base64 编码: %w", err)
		}
		configContent = string(decoded)
	} else if request.ConfigURL != nil {
		// 远程配置（TODO: 下一阶段实现）
		return nil, fmt.Errorf("远程配置 URL 暂不支持，请使用内联配置")
	} else {
		return request, nil
	}

	// 解析配置（基于格式）
	format := "json"
	if request.ConfigFormat != nil {
		format = *request.ConfigFormat
	}

	var configData map[string]interface{}
	switch format {
	case "json":
		if err := json.Unmarshal([]byte(configContent), &configData); err != nil {
			return nil, fmt.Errorf("无效的 JSON 配置: %w", err)
		}
	case "toml":
		// TOML 解析（暂不实现，后续添加）
		return nil, fmt.Errorf("TOML 配置格式暂不支持")
	default:
		return nil, fmt.Errorf("不支持的配置格式: %s", format)
	}

	// 合并配置（基于 app 类型）
	merged := *request // 复制请求
	switch request.App {
	case "claude":
		s.mergeClaudeConfig(&merged, configData)
	case "codex", "openai-responses":
		s.mergeCodexConfig(&merged, configData)
	case "openai-chat":
		s.mergeCodexConfig(&merged, configData)
	case "gemini":
		s.mergeGeminiConfig(&merged, configData)
	}

	return &merged, nil
}

// mergeClaudeConfig 合并 Claude 配置
func (s *DeepLinkService) mergeClaudeConfig(request *DeepLinkImportRequest, config map[string]interface{}) {
	env, ok := config["env"].(map[string]interface{})
	if !ok {
		return
	}

	// 自动填充 API key
	if request.APIKey == "" {
		if token, ok := env["ANTHROPIC_AUTH_TOKEN"].(string); ok {
			request.APIKey = token
		}
	}

	// 自动填充 endpoint
	if request.Endpoint == "" {
		if baseURL, ok := env["ANTHROPIC_BASE_URL"].(string); ok {
			request.Endpoint = baseURL
		}
	}

	// 自动填充 homepage（从 endpoint 推断）
	if request.Homepage == "" && request.Endpoint != "" {
		request.Homepage = inferHomepage(request.Endpoint, "https://anthropic.com")
	}

	// 自动填充模型字段
	if request.Model == nil {
		if model, ok := env["ANTHROPIC_MODEL"].(string); ok {
			request.Model = &model
		}
	}
	if request.HaikuModel == nil {
		if model, ok := env["ANTHROPIC_DEFAULT_HAIKU_MODEL"].(string); ok {
			request.HaikuModel = &model
		}
	}
	if request.SonnetModel == nil {
		if model, ok := env["ANTHROPIC_DEFAULT_SONNET_MODEL"].(string); ok {
			request.SonnetModel = &model
		}
	}
	if request.OpusModel == nil {
		if model, ok := env["ANTHROPIC_DEFAULT_OPUS_MODEL"].(string); ok {
			request.OpusModel = &model
		}
	}
}

// mergeCodexConfig 合并 Codex 配置
func (s *DeepLinkService) mergeCodexConfig(request *DeepLinkImportRequest, config map[string]interface{}) {
	// 自动填充 API key
	if request.APIKey == "" {
		if auth, ok := config["auth"].(map[string]interface{}); ok {
			if apiKey, ok := auth["OPENAI_API_KEY"].(string); ok {
				request.APIKey = apiKey
			}
		}
	}

	// 自动填充 endpoint 和 model（从 config string）
	if configStr, ok := config["config"].(string); ok {
		// 简单解析 TOML（使用正则表达式）
		if request.Endpoint == "" {
			baseURLRegex := regexp.MustCompile(`base_url\s*=\s*"([^"]+)"`)
			if matches := baseURLRegex.FindStringSubmatch(configStr); len(matches) > 1 {
				request.Endpoint = matches[1]
			}
		}
		if request.Model == nil {
			modelRegex := regexp.MustCompile(`^model\s*=\s*"([^"]+)"`)
			for _, line := range strings.Split(configStr, "\n") {
				if matches := modelRegex.FindStringSubmatch(strings.TrimSpace(line)); len(matches) > 1 {
					model := matches[1]
					request.Model = &model
					break
				}
			}
		}
	}

	// 自动填充 homepage
	if request.Homepage == "" && request.Endpoint != "" {
		request.Homepage = inferHomepage(request.Endpoint, "https://openai.com")
	}
}

// mergeGeminiConfig 合并 Gemini 配置
func (s *DeepLinkService) mergeGeminiConfig(request *DeepLinkImportRequest, config map[string]interface{}) {
	// Gemini 使用扁平化的 env 结构
	if request.APIKey == "" {
		if apiKey, ok := config["GEMINI_API_KEY"].(string); ok {
			request.APIKey = apiKey
		}
	}

	if request.Endpoint == "" {
		if baseURL, ok := config["GEMINI_BASE_URL"].(string); ok {
			request.Endpoint = baseURL
		}
	}

	if request.Model == nil {
		if model, ok := config["GEMINI_MODEL"].(string); ok {
			request.Model = &model
		}
	}

	// 自动填充 homepage
	if request.Homepage == "" && request.Endpoint != "" {
		request.Homepage = inferHomepage(request.Endpoint, "https://ai.google.dev")
	}
}

// validateHTTPURL 验证 HTTP(S) URL
func validateHTTPURL(urlStr, fieldName string) error {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("'%s' 的 URL 无效: %w", fieldName, err)
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("'%s' 的 URL scheme 无效: 必须是 http 或 https, 得到 '%s'", fieldName, parsedURL.Scheme)
	}

	return nil
}

// inferHomepage 从端点推断主页
func inferHomepage(endpoint, fallback string) string {
	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return fallback
	}

	host := parsedURL.Host
	// 移除常见的 API 前缀
	if strings.HasPrefix(host, "api.") {
		host = strings.TrimPrefix(host, "api.")
	} else if strings.HasPrefix(host, "api-") {
		parts := strings.SplitN(host, ".", 2)
		if len(parts) > 1 {
			host = parts[1]
		}
	}

	return "https://" + host
}
