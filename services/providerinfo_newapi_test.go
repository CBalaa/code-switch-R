package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestQueryNewAPIPricingRetriesWithAccountToken(t *testing.T) {
	var mu sync.Mutex
	var pricingAuth []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/pricing":
			mu.Lock()
			pricingAuth = append(pricingAuth, r.Header.Get("Authorization"))
			mu.Unlock()
			if r.Header.Get("Authorization") != "Bearer account-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"success":true,"data":[{"model_name":"Claude-Fable-5","quota_type":0,"model_ratio":5,"completion_ratio":1,"enable_groups":["all"]}],"group_ratio":{"default":1}}`))
		case "/api/status":
			_, _ = w.Write([]byte(`{"success":true,"data":{"quota_per_unit":500000}}`))
		case "/api/usage/token/":
			_, _ = w.Write([]byte(`{"code":true,"data":{"object":"token_usage","total_granted":100,"total_used":10,"total_available":90}}`))
		case "/api/user/self":
			_, _ = w.Write([]byte(`{"success":true,"data":{"quota":319426214}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	service := NewProviderInfoService(nil)
	result := service.queryNewAPI("pricing-fallback", server.URL, "api-key", true, &UpstreamInfoConfig{AccountToken: "account-token"})
	if result.PricingState.Status != "ready" {
		t.Fatalf("pricing status = %q, want ready", result.PricingState.Status)
	}
	if result.Pricing == nil || len(result.Pricing.Rows) != 1 || result.Pricing.Rows[0].Model != "Claude-Fable-5" {
		t.Fatalf("pricing = %#v, want one decoded row", result.Pricing)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(pricingAuth) != 2 || pricingAuth[0] != "" || pricingAuth[1] != "Bearer account-token" {
		t.Fatalf("pricing authorization sequence = %#v, want anonymous then account token", pricingAuth)
	}
}

func TestQueryNewAPIPricingWithoutTokenReportsAuthRequired(t *testing.T) {
	var pricingRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/pricing" {
			pricingRequests++
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Path == "/api/status" {
			_, _ = w.Write([]byte(`{"success":true,"data":{"quota_per_unit":500000}}`))
			return
		}
		if r.URL.Path == "/api/usage/token/" {
			_, _ = w.Write([]byte(`{"code":true,"data":{"object":"token_usage","total_available":90}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	service := NewProviderInfoService(nil)
	result := service.queryNewAPI("pricing-auth-required", server.URL, "api-key", true, &UpstreamInfoConfig{})
	if result.PricingState.Status != "auth_required" {
		t.Fatalf("pricing status = %q, want auth_required", result.PricingState.Status)
	}
	if pricingRequests != 1 {
		t.Fatalf("pricing requests = %d, want one anonymous request", pricingRequests)
	}
}

func TestQueryNewAPIPricingTokenFailureReportsAuth(t *testing.T) {
	var pricingAuth []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/pricing" {
			pricingAuth = append(pricingAuth, r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/status" {
			_, _ = w.Write([]byte(`{"success":true,"data":{"quota_per_unit":500000}}`))
			return
		}
		if r.URL.Path == "/api/usage/token/" {
			_, _ = w.Write([]byte(`{"code":true,"data":{"object":"token_usage","total_available":90}}`))
			return
		}
		if r.URL.Path == "/api/user/self" {
			_, _ = w.Write([]byte(`{"success":true,"data":{"quota":1}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	service := NewProviderInfoService(nil)
	result := service.queryNewAPI("pricing-auth-failure", server.URL, "api-key", true, &UpstreamInfoConfig{AccountToken: "wrong-token"})
	if result.PricingState.Status != "auth" {
		t.Fatalf("pricing status = %q, want auth", result.PricingState.Status)
	}
	if len(pricingAuth) != 2 || pricingAuth[0] != "" || pricingAuth[1] != "Bearer wrong-token" {
		t.Fatalf("pricing authorization sequence = %#v, want anonymous then configured token", pricingAuth)
	}
}

func TestDecodeNewAPIPricingResponseRemainsAllowlisted(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"success": true,
		"data":    []map[string]any{{"model_name": "model", "quota_type": 0, "model_ratio": 1}},
	})
	data, status := decodeNewAPI(body, "newapi_pricing")
	if status != "ready" || len(data) == 0 {
		t.Fatalf("decode status = %q, data length = %d, want ready data", status, len(data))
	}
}
