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

func TestParseLogTimestampTreatsSQLiteTimestampAsUTCAndReturnsBeijingTime(t *testing.T) {
	createdAt, hasTime := parseLogTimestamp("2026-06-08 07:33:59")
	if !hasTime {
		t.Fatalf("expected timestamp to include time")
	}
	if got := createdAt.Format(timeLayout); got != "2026-06-08 15:33:59" {
		t.Fatalf("createdAt = %q, want Beijing time %q", got, "2026-06-08 15:33:59")
	}
	if got := dayFromTimestamp("2026-06-07 16:00:00"); got != "2026-06-08" {
		t.Fatalf("dayFromTimestamp = %q, want Beijing day %q", got, "2026-06-08")
	}
}
