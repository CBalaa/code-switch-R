package services

import "testing"

func TestValidateProviderResponseProtocolRejectsHTML(t *testing.T) {
	body := []byte(`<!doctype html><html><head><title>New API</title></head></html>`)
	if err := validateProviderResponseProtocol("claude", "/messages", body); err == nil {
		t.Fatal("expected HTML response to fail protocol validation")
	}
}

func TestValidateProviderResponseProtocolClaudeMessage(t *testing.T) {
	body := []byte(`{
		"type": "message",
		"role": "assistant",
		"content": [{"type":"text","text":"ok"}],
		"usage": {"input_tokens": 1, "output_tokens": 1}
	}`)
	if err := validateProviderResponseProtocol("claude", "/v1/messages", body); err != nil {
		t.Fatalf("expected Claude message response to pass, got %v", err)
	}
}

func TestValidateProviderResponseProtocolOpenAIChat(t *testing.T) {
	body := []byte(`{
		"id": "chatcmpl_1",
		"object": "chat.completion",
		"choices": [{"message":{"role":"assistant","content":"ok"}}]
	}`)
	if err := validateProviderResponseProtocol("openai-chat", "/chat/completions", body); err != nil {
		t.Fatalf("expected OpenAI chat response to pass, got %v", err)
	}
}

func TestValidateProviderResponseProtocolResponses(t *testing.T) {
	body := []byte(`{
		"id": "resp_1",
		"object": "response",
		"status": "completed",
		"output": []
	}`)
	if err := validateProviderResponseProtocol("openai-responses", "/responses", body); err != nil {
		t.Fatalf("expected Responses response to pass, got %v", err)
	}
}
