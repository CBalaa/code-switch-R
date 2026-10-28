package main

import (
	"codeswitch/services"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPoolScheduleStatusRPCIsAuthenticatedAndUserScoped(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	poolService := services.NewProviderPoolService()
	for _, userID := range []string{"user-a", "user-b"} {
		pool := &services.ProviderPool{
			ID:       "same-pool-id",
			Platform: "openai-chat",
			Name:     userID + " pool",
			PoolType: services.ProviderPoolTypeAccount,
			Mode:     services.ProviderPoolModeManaged,
			AccountPoolConfig: &services.AccountPoolConfig{
				APIURL:       "https://upstream.example.com",
				ChatEndpoint: "/v1/chat/completions",
				Keys:         []services.AccountPoolKey{{APIKey: "sk-private-" + userID}},
				Schedule: &services.AccountPoolSchedule{
					Enabled: userID == "user-a",
					Windows: []services.AccountPoolScheduleWindow{{Weekday: 1, StartTime: "18:00", EndTime: "23:59"}},
				},
			},
		}
		if _, err := poolService.SavePoolForUser(userID, pool); err != nil {
			t.Fatal(err)
		}
	}
	scoped := &userScopedProviderPoolService{base: poolService}
	registry := newRPCRegistry()
	registry.Register("codeswitch/services.ProviderPoolService", scoped)
	method := "codeswitch/services.ProviderPoolService.GetAccountPoolScheduleStatuses"
	args := []json.RawMessage{json.RawMessage(`"openai-chat"`)}
	if _, err := registry.Call(context.Background(), method, args); err == nil {
		t.Fatal("unauthenticated status query was accepted")
	}
	for _, userID := range []string{"user-a", "user-b"} {
		ctx := contextWithAuthenticatedUser(context.Background(), &services.AuthenticatedUser{ID: userID})
		result, err := registry.Call(ctx, method, args)
		if err != nil {
			t.Fatal(err)
		}
		batch, ok := result.(*services.AccountPoolScheduleStatuses)
		if !ok || len(batch.Statuses) != 1 {
			t.Fatalf("unexpected status result: %#v", result)
		}
		if _, err := time.Parse(time.RFC3339, batch.ServerNow); err != nil {
			t.Fatalf("invalid server time: %v", err)
		}
		status := batch.Statuses[0]
		if status.PoolID != "same-pool-id" || status.Enabled != (userID == "user-a") {
			t.Fatalf("status leaked another user's schedule: %#v", status)
		}
		if userID == "user-b" && (!status.IsOpen || status.NextChangeAt != "") {
			t.Fatalf("disabled schedule is not always open: %#v", status)
		}
		payload, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(payload), "sk-private-") || strings.Contains(string(payload), "upstream.example.com") {
			t.Fatalf("status response exposed upstream configuration: %s", payload)
		}
		result, err = registry.Call(ctx, method, []json.RawMessage{json.RawMessage(`"openai-responses"`)})
		if err != nil || len(result.(*services.AccountPoolScheduleStatuses).Statuses) != 0 {
			t.Fatalf("platform filter failed: %#v, %v", result, err)
		}
	}
}
