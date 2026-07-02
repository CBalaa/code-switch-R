package services

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/daodao97/xgo/xdb"
)

func TestClientIPFromRequest(t *testing.T) {
	t.Setenv(relayTrustedProxiesEnv, "")

	req := httptest.NewRequest("POST", "/v1/messages", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	if got := clientIPFromRequest(req); got != "127.0.0.1" {
		t.Fatalf("clientIPFromRequest = %q, want 127.0.0.1", got)
	}

	req.RemoteAddr = "[::1]:12345"
	if got := clientIPFromRequest(req); got != "::1" {
		t.Fatalf("clientIPFromRequest IPv6 = %q, want ::1", got)
	}

	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.25, 10.0.0.2")
	if got := clientIPFromRequest(req); got != "203.0.113.25" {
		t.Fatalf("clientIPFromRequest trusted X-Forwarded-For = %q, want 203.0.113.25", got)
	}

	req.Header.Del("X-Forwarded-For")
	req.Header.Set("X-Real-IP", "198.51.100.7")
	if got := clientIPFromRequest(req); got != "198.51.100.7" {
		t.Fatalf("clientIPFromRequest trusted X-Real-IP = %q, want 198.51.100.7", got)
	}

	req.RemoteAddr = "198.51.100.10:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	if got := clientIPFromRequest(req); got != "198.51.100.10" {
		t.Fatalf("clientIPFromRequest untrusted proxy = %q, want 198.51.100.10", got)
	}
}

func TestClientIPFromRequestUsesConfiguredTrustedProxy(t *testing.T) {
	t.Setenv(relayTrustedProxiesEnv, "10.0.0.0/8")

	req := httptest.NewRequest("POST", "/v1/messages", nil)
	req.RemoteAddr = "10.1.2.3:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.30")

	if got := clientIPFromRequest(req); got != "203.0.113.30" {
		t.Fatalf("clientIPFromRequest configured trusted proxy = %q, want 203.0.113.30", got)
	}
}

func TestActiveRequestTrackerListFiltersAndFinishes(t *testing.T) {
	tracker := newActiveRequestTracker()
	now := time.Now()

	oldID := tracker.Start(&ReqeustLog{
		UserID:     "user-a",
		Platform:   "claude",
		Provider:   "provider-a",
		Model:      "claude-sonnet",
		IsStream:   true,
		ClientIP:   "127.0.0.1",
		RelayKeyID: "key-a",
	}, now.Add(-3*time.Second))
	newID := tracker.Start(&ReqeustLog{
		UserID:   "user-b",
		Platform: "openai-responses",
		Provider: "provider-b",
		Model:    "gpt-5",
	}, now.Add(-time.Second))

	logs := tracker.List("", "", "")
	if len(logs) != 2 {
		t.Fatalf("active logs count = %d, want 2", len(logs))
	}
	if logs[0].Provider != "provider-b" || logs[1].Provider != "provider-a" {
		t.Fatalf("active logs order = [%s, %s], want newest first", logs[0].Provider, logs[1].Provider)
	}
	if logs[0].ID >= 0 || logs[0].Status != requestLogStatusProcessing {
		t.Fatalf("active log metadata = id %d status %q, want negative processing", logs[0].ID, logs[0].Status)
	}
	if logs[1].DurationSec <= 0 {
		t.Fatalf("active duration = %f, want positive", logs[1].DurationSec)
	}

	tracker.Update(oldID, &ReqeustLog{
		UserID:   "user-a",
		Platform: "claude",
		Provider: "provider-c",
		Model:    "claude-opus",
	})
	filtered := tracker.List("claude", "provider-c", "user-a")
	if len(filtered) != 1 || filtered[0].Model != "claude-opus" {
		t.Fatalf("filtered active logs = %#v, want updated claude provider-c", filtered)
	}

	tracker.Finish(oldID)
	tracker.Finish(newID)
	if remaining := tracker.List("", "", ""); len(remaining) != 0 {
		t.Fatalf("remaining active logs = %d, want 0", len(remaining))
	}
}

func TestListRequestLogsPrependsActiveRequests(t *testing.T) {
	setupRelayTestEnv(t)

	previousTracker := defaultActiveRequestTracker
	defaultActiveRequestTracker = newActiveRequestTracker()
	t.Cleanup(func() {
		defaultActiveRequestTracker = previousTracker
	})

	db, err := xdb.DB("default")
	if err != nil {
		t.Fatalf("get db: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM request_log`); err != nil {
		t.Fatalf("clear request_log: %v", err)
	}
	key, err := NewCodexRelayKeyService().CreateKeyForUser("user-a", "My named relay key")
	if err != nil {
		t.Fatalf("create relay key: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO request_log (
			user_id, platform, model, provider, relay_key_id, http_code,
			input_tokens, output_tokens, cache_create_tokens, cache_read_tokens,
			reasoning_tokens, is_stream, duration_sec, first_token_duration_sec, first_text_sec, client_ip
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "user-a", "claude", "claude-sonnet", "completed-provider", key.ID, 200, 10, 20, 0, 0, 0, 1, 2.5, 0, 0.4, "127.0.0.1"); err != nil {
		t.Fatalf("insert request_log: %v", err)
	}

	activeID := defaultActiveRequestTracker.Start(&ReqeustLog{
		UserID:     "user-a",
		Platform:   "claude",
		Provider:   "active-provider",
		Model:      "claude-opus",
		IsStream:   true,
		ClientIP:   "127.0.0.2",
		RelayKeyID: key.ID,
	}, time.Now().Add(-time.Second))
	defer defaultActiveRequestTracker.Finish(activeID)

	logs, err := NewLogService().ListRequestLogsForUser("user-a", "claude", "", 10)
	if err != nil {
		t.Fatalf("ListRequestLogsForUser: %v", err)
	}
	if len(logs) < 2 {
		t.Fatalf("logs count = %d, want at least 2", len(logs))
	}
	if logs[0].Status != requestLogStatusProcessing || logs[0].Provider != "active-provider" {
		t.Fatalf("first log = status %q provider %q, want processing active-provider", logs[0].Status, logs[0].Provider)
	}
	if logs[0].ClientIP != "127.0.0.2" {
		t.Fatalf("active client_ip = %q, want 127.0.0.2", logs[0].ClientIP)
	}
	if logs[0].RelayKeyName != "My named relay key" {
		t.Fatalf("active relay key name = %q, want My named relay key", logs[0].RelayKeyName)
	}
	if logs[1].Status != requestLogStatusCompleted || logs[1].Provider != "completed-provider" {
		t.Fatalf("second log = status %q provider %q, want completed completed-provider", logs[1].Status, logs[1].Provider)
	}
	if logs[1].ClientIP != "127.0.0.1" || logs[1].FirstTokenDurationSec != 0.4 {
		t.Fatalf("completed fields = client_ip %q first_token %f, want 127.0.0.1 and 0.4", logs[1].ClientIP, logs[1].FirstTokenDurationSec)
	}
}
