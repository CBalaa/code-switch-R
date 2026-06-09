package services

import (
	"testing"
	"time"
)

func TestCodexRelayKeyServiceCreateCopyAndDelete(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	service := NewCodexRelayKeyService()

	firstKey, err := service.CreateKey("local-dev")
	if err != nil {
		t.Fatalf("CreateKey(first) failed: %v", err)
	}
	if firstKey.Key == "" {
		t.Fatal("expected first key secret to be returned")
	}

	list, err := service.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys() failed: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 key after first create, got %d", len(list))
	}
	if list[0].MaskedKey == "" || list[0].MaskedKey == firstKey.Key {
		t.Fatalf("expected masked key in list output, got %q", list[0].MaskedKey)
	}

	secret, err := service.GetKeySecret(firstKey.ID)
	if err != nil {
		t.Fatalf("GetKeySecret() failed: %v", err)
	}
	if secret != firstKey.Key {
		t.Fatalf("expected copied secret to match created key")
	}

	if err := service.DeleteKey(firstKey.ID); err == nil {
		t.Fatal("expected deleting the last enabled key to fail")
	}

	secondKey, err := service.CreateKey("ci")
	if err != nil {
		t.Fatalf("CreateKey(second) failed: %v", err)
	}

	if err := service.DeleteKey(firstKey.ID); err != nil {
		t.Fatalf("DeleteKey(first) after creating second key failed: %v", err)
	}

	list, err = service.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys() after delete failed: %v", err)
	}
	if len(list) != 1 || list[0].ID != secondKey.ID {
		t.Fatalf("expected remaining key %q, got %+v", secondKey.ID, list)
	}
}

func TestResolveRelayKeyUsageWindowCustomRange(t *testing.T) {
	start := "2026-06-09T00:00:00+08:00"
	end := "2026-06-09T03:30:00+08:00"

	rangeKey, startAt, endAt, step, err := resolveRelayKeyUsageWindow("custom", start, end)
	if err != nil {
		t.Fatalf("resolveRelayKeyUsageWindow returned error: %v", err)
	}
	if rangeKey != "custom" {
		t.Fatalf("rangeKey = %q, want custom", rangeKey)
	}
	if step != 15*time.Minute {
		t.Fatalf("step = %v, want 15m", step)
	}
	if !startAt.Equal(time.Date(2026, 6, 8, 16, 0, 0, 0, time.UTC)) {
		t.Fatalf("startAt = %s", startAt.Format(time.RFC3339))
	}
	if !endAt.Equal(time.Date(2026, 6, 8, 19, 30, 0, 0, time.UTC)) {
		t.Fatalf("endAt = %s", endAt.Format(time.RFC3339))
	}
}

func TestResolveRelayKeyUsageWindowRejectsInvalidCustomRange(t *testing.T) {
	_, _, _, _, err := resolveRelayKeyUsageWindow("custom", "2026-06-09T03:30:00+08:00", "2026-06-09T00:00:00+08:00")
	if err == nil {
		t.Fatal("expected invalid custom range to fail")
	}
}
