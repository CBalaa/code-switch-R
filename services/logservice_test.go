package services

import "testing"

func TestRelayKeyDisplayName(t *testing.T) {
	names := map[string]string{
		"key-1": "main key",
	}

	if got := relayKeyDisplayName("key-1", names); got != "main key" {
		t.Fatalf("expected key name, got %q", got)
	}
	if got := relayKeyDisplayName("deleted-key", names); got != "deleted-key" {
		t.Fatalf("expected id fallback, got %q", got)
	}
	if got := relayKeyDisplayName("", names); got != "" {
		t.Fatalf("expected empty display name, got %q", got)
	}
}
