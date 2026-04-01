package main

import (
	"bytes"
	"codeswitch/services"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestWebRuntime(t *testing.T) *appRuntime {
	t.Helper()

	t.Setenv("HOME", t.TempDir())

	appSettings := services.NewAppSettingsService(nil)

	return &appRuntime{
		adminAddr:      "127.0.0.1:0",
		staticDir:      t.TempDir(),
		eventHub:       services.NewEventHub(),
		appService:     &AppService{},
		appSettings:    appSettings,
		adminAuth:      services.NewAdminAuthService(appSettings),
		codexRelayKeys: services.NewCodexRelayKeyService(),
	}
}

func performRequest(t *testing.T, handler http.Handler, method, path string, body any, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()

	var requestBody *bytes.Reader
	if body == nil {
		requestBody = bytes.NewReader(nil)
	} else {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("failed to encode request body: %v", err)
		}
		requestBody = bytes.NewReader(payload)
	}

	req := httptest.NewRequest(method, path, requestBody)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func decodeJSON[T any](t *testing.T, recorder *httptest.ResponseRecorder) T {
	t.Helper()

	var value T
	if err := json.Unmarshal(recorder.Body.Bytes(), &value); err != nil {
		t.Fatalf("failed to decode response body %q: %v", recorder.Body.String(), err)
	}
	return value
}

func TestAdminServerProtectsRoutes(t *testing.T) {
	rt := newTestWebRuntime(t)
	server := newAdminServer(rt)

	health := performRequest(t, server.Handler, http.MethodGet, "/healthz", nil)
	if health.Code != http.StatusOK {
		t.Fatalf("expected /healthz 200, got %d", health.Code)
	}

	ready := performRequest(t, server.Handler, http.MethodGet, "/readyz", nil)
	if ready.Code != http.StatusOK {
		t.Fatalf("expected /readyz 200, got %d", ready.Code)
	}

	status := performRequest(t, server.Handler, http.MethodGet, "/api/admin/status", nil)
	if status.Code != http.StatusOK {
		t.Fatalf("expected /api/admin/status 200, got %d", status.Code)
	}
	var authStatus services.AdminAuthStatus
	authStatus = decodeJSON[services.AdminAuthStatus](t, status)
	if authStatus.Initialized || authStatus.Authenticated {
		t.Fatalf("expected initial admin status to be unauthenticated, got %+v", authStatus)
	}

	call := performRequest(t, server.Handler, http.MethodPost, "/api/wails/call", map[string]any{
		"name": "codeswitch/services.AppSettingsService.GetAppSettings",
		"args": []any{},
	})
	if call.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated /api/wails/call to return 401, got %d", call.Code)
	}

	events := performRequest(t, server.Handler, http.MethodGet, "/api/wails/events", nil)
	if events.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated /api/wails/events to return 401, got %d", events.Code)
	}
}

func TestAdminServerInitializeAndManageCodexKeys(t *testing.T) {
	rt := newTestWebRuntime(t)
	server := newAdminServer(rt)

	initialize := performRequest(t, server.Handler, http.MethodPost, "/api/admin/initialize", map[string]string{
		"username": "admin",
		"password": "password123",
	})
	if initialize.Code != http.StatusOK {
		t.Fatalf("expected initialize 200, got %d: %s", initialize.Code, initialize.Body.String())
	}

	cookies := initialize.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected initialize response to set an admin session cookie")
	}
	adminCookie := cookies[0]

	wailsCall := performRequest(t, server.Handler, http.MethodPost, "/api/wails/call", map[string]any{
		"name": "codeswitch/services.AppSettingsService.GetAppSettings",
		"args": []any{},
	}, adminCookie)
	if wailsCall.Code != http.StatusOK {
		t.Fatalf("expected authenticated /api/wails/call 200, got %d: %s", wailsCall.Code, wailsCall.Body.String())
	}

	protectedKeys := performRequest(t, server.Handler, http.MethodGet, "/api/admin/codex-keys", nil)
	if protectedKeys.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated codex key list 401, got %d", protectedKeys.Code)
	}

	createFirst := performRequest(t, server.Handler, http.MethodPost, "/api/admin/codex-keys", map[string]string{
		"name": "local-dev",
	}, adminCookie)
	if createFirst.Code != http.StatusOK {
		t.Fatalf("expected create first key 200, got %d: %s", createFirst.Code, createFirst.Body.String())
	}
	firstKey := decodeJSON[services.CodexRelayKeyCreateResult](t, createFirst)
	if firstKey.Key == "" {
		t.Fatal("expected create first key response to include secret")
	}

	secret := performRequest(t, server.Handler, http.MethodGet, "/api/admin/codex-keys/"+firstKey.ID+"/secret", nil, adminCookie)
	if secret.Code != http.StatusOK {
		t.Fatalf("expected get key secret 200, got %d: %s", secret.Code, secret.Body.String())
	}
	secretPayload := decodeJSON[map[string]string](t, secret)
	if secretPayload["key"] != firstKey.Key {
		t.Fatalf("expected returned secret to match created key")
	}

	deleteLast := performRequest(t, server.Handler, http.MethodDelete, "/api/admin/codex-keys/"+firstKey.ID, nil, adminCookie)
	if deleteLast.Code != http.StatusBadRequest {
		t.Fatalf("expected deleting last key to fail with 400, got %d: %s", deleteLast.Code, deleteLast.Body.String())
	}

	createSecond := performRequest(t, server.Handler, http.MethodPost, "/api/admin/codex-keys", map[string]string{
		"name": "ci",
	}, adminCookie)
	if createSecond.Code != http.StatusOK {
		t.Fatalf("expected create second key 200, got %d: %s", createSecond.Code, createSecond.Body.String())
	}

	deleteFirst := performRequest(t, server.Handler, http.MethodDelete, "/api/admin/codex-keys/"+firstKey.ID, nil, adminCookie)
	if deleteFirst.Code != http.StatusNoContent {
		t.Fatalf("expected deleting first key to succeed, got %d: %s", deleteFirst.Code, deleteFirst.Body.String())
	}

	listKeys := performRequest(t, server.Handler, http.MethodGet, "/api/admin/codex-keys", nil, adminCookie)
	if listKeys.Code != http.StatusOK {
		t.Fatalf("expected authenticated codex key list 200, got %d: %s", listKeys.Code, listKeys.Body.String())
	}
	var listPayload struct {
		Keys []services.CodexRelayKeyListItem `json:"keys"`
	}
	listPayload = decodeJSON[struct {
		Keys []services.CodexRelayKeyListItem `json:"keys"`
	}](t, listKeys)
	if len(listPayload.Keys) != 1 {
		t.Fatalf("expected one remaining key, got %+v", listPayload.Keys)
	}
	if listPayload.Keys[0].ID == firstKey.ID {
		t.Fatalf("expected deleted key %q to be absent from list", firstKey.ID)
	}
}
