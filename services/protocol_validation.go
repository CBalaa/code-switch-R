package services

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
)

func validateProviderResponseProtocol(platform string, endpoint string, body []byte) error {
	body = []byte(strings.TrimSpace(string(body)))
	if len(body) == 0 {
		return fmt.Errorf("响应体为空")
	}
	if !json.Valid(body) {
		return fmt.Errorf("响应不是有效 JSON")
	}

	endpoint = strings.ToLower(strings.TrimSpace(endpoint))
	switch {
	case strings.EqualFold(platform, "claude") || strings.Contains(endpoint, "/messages"):
		return validateClaudeMessageResponse(body)
	case strings.Contains(endpoint, "/responses"):
		return validateOpenAIResponsesResponse(body)
	default:
		return validateOpenAIChatResponse(body)
	}
}

func validateClaudeMessageResponse(body []byte) error {
	result := gjson.ParseBytes(body)
	if result.Get("error").Exists() {
		return fmt.Errorf("上游返回错误: %s", compactResponseForError(body))
	}
	if result.Get("type").String() != "message" {
		return fmt.Errorf("Claude 响应缺少 type=message")
	}
	if strings.TrimSpace(result.Get("role").String()) != "assistant" {
		return fmt.Errorf("Claude 响应缺少 role=assistant")
	}
	content := result.Get("content")
	if !content.IsArray() {
		return fmt.Errorf("Claude 响应缺少 content 数组")
	}
	usage := result.Get("usage")
	if !usage.IsObject() {
		return fmt.Errorf("Claude 响应缺少 usage 对象")
	}
	if !usage.Get("input_tokens").Exists() || !usage.Get("output_tokens").Exists() {
		return fmt.Errorf("Claude usage 缺少 input_tokens/output_tokens")
	}
	return nil
}

func validateOpenAIChatResponse(body []byte) error {
	result := gjson.ParseBytes(body)
	if result.Get("error").Exists() {
		return fmt.Errorf("上游返回错误: %s", compactResponseForError(body))
	}
	choices := result.Get("choices")
	if !choices.IsArray() || len(choices.Array()) == 0 {
		return fmt.Errorf("OpenAI Chat 响应缺少 choices 数组")
	}
	first := choices.Array()[0]
	if !first.Get("message").Exists() && !first.Get("delta").Exists() {
		return fmt.Errorf("OpenAI Chat choice 缺少 message/delta")
	}
	return nil
}

func validateOpenAIResponsesResponse(body []byte) error {
	result := gjson.ParseBytes(body)
	if result.Get("error").Exists() {
		return fmt.Errorf("上游返回错误: %s", compactResponseForError(body))
	}
	if !result.Get("id").Exists() {
		return fmt.Errorf("Responses 响应缺少 id")
	}
	if object := result.Get("object").String(); object != "" && !strings.Contains(object, "response") {
		return fmt.Errorf("Responses object 字段异常: %s", object)
	}
	if status := result.Get("status").String(); status != "" {
		return nil
	}
	if output := result.Get("output"); output.Exists() {
		return nil
	}
	return fmt.Errorf("Responses 响应缺少 status 或 output")
}

func compactResponseForError(body []byte) string {
	text := strings.Join(strings.Fields(string(body)), " ")
	if len(text) > 240 {
		return text[:240] + "..."
	}
	return text
}
