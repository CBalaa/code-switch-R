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

func TestValidateProviderResponseProtocolOpenAIImages(t *testing.T) {
	ok := []byte(`{"created":1700000000,"data":[{"b64_json":"aW1hZ2U="}]}`)
	if err := validateProviderResponseProtocol("openai-images", "/images/generations", ok); err != nil {
		t.Fatalf("expected Images response to pass, got %v", err)
	}

	withURL := []byte(`{"data":[{"url":"https://example.com/a.png"}]}`)
	if err := validateProviderResponseProtocol("openai-images", "/images/edits", withURL); err != nil {
		t.Fatalf("expected Images url response to pass, got %v", err)
	}

	empty := []byte(`{"data":[]}`)
	if err := validateProviderResponseProtocol("openai-images", "/images/generations", empty); err == nil {
		t.Fatal("expected empty data array to fail Images protocol validation")
	}

	noPayload := []byte(`{"data":[{"revised_prompt":"a cat"}]}`)
	if err := validateProviderResponseProtocol("openai-images", "/images/generations", noPayload); err == nil {
		t.Fatal("expected data item without image payload to fail validation")
	}

	upstreamErr := []byte(`{"error":{"message":"model not found"}}`)
	if err := validateProviderResponseProtocol("openai-images", "/images/generations", upstreamErr); err == nil {
		t.Fatal("expected upstream error body to fail validation")
	}
}
