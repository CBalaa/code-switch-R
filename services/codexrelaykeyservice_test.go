package services

import "testing"

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
