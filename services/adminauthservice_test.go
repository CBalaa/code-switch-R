package services

import "testing"

func TestAdminAuthServiceLifecycle(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	appSettings := NewAppSettingsService(nil)
	service := NewAdminAuthService(appSettings)

	status, err := service.GetStatus("")
	if err != nil {
		t.Fatalf("GetStatus() failed: %v", err)
	}
	if status.Initialized || status.Authenticated {
		t.Fatalf("expected uninitialized status, got %+v", status)
	}

	initialToken, status, err := service.InitializeAdmin("admin", "password123")
	if err != nil {
		t.Fatalf("InitializeAdmin() failed: %v", err)
	}
	if initialToken == "" {
		t.Fatal("expected initialize to return a session token")
	}
	if !status.Initialized || !status.Authenticated || status.Username != "admin" {
		t.Fatalf("unexpected initialize status: %+v", status)
	}

	username, ok, err := service.ValidateSession(initialToken)
	if err != nil {
		t.Fatalf("ValidateSession(initialToken) failed: %v", err)
	}
	if !ok || username != "admin" {
		t.Fatalf("expected initial session to validate, got ok=%v username=%q", ok, username)
	}

	loginToken, status, err := service.Login("admin", "password123")
	if err != nil {
		t.Fatalf("Login() failed: %v", err)
	}
	if loginToken == "" {
		t.Fatal("expected login to return a session token")
	}
	if !status.Authenticated || status.Username != "admin" {
		t.Fatalf("unexpected login status: %+v", status)
	}

	if _, _, err := service.Login("admin", "wrong-password"); err == nil {
		t.Fatal("expected login with wrong password to fail")
	}

	rotatedToken, status, err := service.UpdateCredentials("password123", "root", "newpassword456")
	if err != nil {
		t.Fatalf("UpdateCredentials() failed: %v", err)
	}
	if rotatedToken == "" {
		t.Fatal("expected credential update to return a new session token")
	}
	if status.Username != "root" {
		t.Fatalf("expected updated username root, got %+v", status)
	}

	if _, ok, err := service.ValidateSession(initialToken); err != nil {
		t.Fatalf("ValidateSession(old token) failed: %v", err)
	} else if ok {
		t.Fatal("expected old session token to be invalid after credential rotation")
	}

	username, ok, err = service.ValidateSession(rotatedToken)
	if err != nil {
		t.Fatalf("ValidateSession(rotatedToken) failed: %v", err)
	}
	if !ok || username != "root" {
		t.Fatalf("expected rotated session token to validate, got ok=%v username=%q", ok, username)
	}

	status, err = service.GetStatus(rotatedToken)
	if err != nil {
		t.Fatalf("GetStatus(rotatedToken) failed: %v", err)
	}
	if !status.Initialized || !status.Authenticated || status.Username != "root" {
		t.Fatalf("unexpected status for rotated token: %+v", status)
	}

	if _, _, err := service.InitializeAdmin("another", "password789"); err == nil {
		t.Fatal("expected second initialization attempt to fail")
	}
}
