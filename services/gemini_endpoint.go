package services

import (
	"strings"
)

// resolveGeminiEndpoint 将 Gemini 端点（前缀或残缺路径）补全为完整的 generateContent 端点
func resolveGeminiEndpoint(endpoint string, model string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		endpoint = "/v1beta"
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}
	endpoint = strings.TrimSuffix(endpoint, "/")

	// 如果已经包含了具体的动作（如 :generateContent 或 :streamGenerateContent），直接返回
	if strings.Contains(endpoint, ":generateContent") || strings.Contains(endpoint, ":streamGenerateContent") {
		return endpoint
	}

	model = strings.TrimSpace(model)
	if model == "" {
		model = "gemini-2.5-flash"
	}

	// 如果端点已经包含 /models/ 路径（如 /v1beta/models/xxx），补全 :generateContent
	if strings.Contains(endpoint, "/models/") {
		return endpoint + ":generateContent"
	}
	if strings.HasSuffix(endpoint, "/models") {
		return endpoint + "/" + model + ":generateContent"
	}

	// 否则作为前缀路径补全（例如 /v1beta -> /v1beta/models/{model}:generateContent）
	return endpoint + "/models/" + model + ":generateContent"
}
