package services

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestEmitProgressReachesSubscriber 验证进度事件经 EventHub 到达订阅者（SSE 同路径）
func TestEmitProgressReachesSubscriber(t *testing.T) {
	hub := NewEventHub()
	events, cancel := hub.Subscribe(32)
	defer cancel()

	svc := NewModelTraceService(nil)
	svc.SetEventEmitter(hub)

	run := &modelTraceRun{
		UserID:        "user-a",
		SessionID:     "mt-1-abc",
		ProviderID:    42,
		ExpectedModel: "gpt-5.4",
		Start:         time.Now(),
	}
	svc.emitProgress(run, "sending", 1, "测试进度")

	select {
	case event := <-events:
		if event.Name != "modeltrace:progress" {
			t.Fatalf("event name = %s", event.Name)
		}
		data, err := json.Marshal(event.Data)
		if err != nil {
			t.Fatal(err)
		}
		var payload ModelTraceProgressEvent
		if err := json.Unmarshal(data, &payload); err != nil {
			t.Fatalf("payload 解析失败: %v", err)
		}
		if payload.SessionID != "mt-1-abc" || payload.ProviderID != 42 ||
			payload.ExpectedModel != "gpt-5.4" || payload.Stage != "sending" ||
			payload.Attempt != 1 || payload.MaxAttempts != maxVerifyAttempts {
			t.Fatalf("payload 不符: %+v", payload)
		}
		t.Logf("payload OK: %+v", payload)
	case <-time.After(time.Second):
		t.Fatal("1 秒内未收到进度事件")
	}
}

// TestProgressEventIsUserScoped 事件必须声明归属用户（SSE 层据此隔离），
// 同时 userID 不能下发给前端。
func TestProgressEventIsUserScoped(t *testing.T) {
	hub := NewEventHub()
	events, cancel := hub.Subscribe(32)
	defer cancel()

	svc := NewModelTraceService(nil)
	svc.SetEventEmitter(hub)
	svc.emitProgress(&modelTraceRun{
		UserID:        "user-a",
		SessionID:     "mt-1-abc",
		ProviderID:    42,
		ExpectedModel: "gpt-5.4",
		Start:         time.Now(),
	}, "sending", 1, "测试进度")

	event := <-events
	scoped, ok := event.Data.(UserScopedEvent)
	if !ok {
		t.Fatalf("事件载荷未实现 UserScopedEvent: %T", event.Data)
	}
	if scoped.EventUserID() != "user-a" {
		t.Fatalf("EventUserID = %q, 期望 user-a", scoped.EventUserID())
	}
	data, err := json.Marshal(event.Data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "user-a") {
		t.Fatalf("userID 不应序列化给前端: %s", data)
	}

	// 流式片段同样要带归属
	svc2 := NewModelTraceService(nil)
	svc2.SetEventEmitter(hub)
	chunker := newStreamChunker(&modelTraceRun{UserID: "user-b", SessionID: "mt-2-xyz", ProviderID: 7}, hub)
	chunker.Add("123, 456, 789, 012, 345, 678, 901")
	chunker.Flush()
	streamEvent := <-events
	if streamEvent.Name != "modeltrace:stream" {
		t.Fatalf("event name = %s", streamEvent.Name)
	}
	streamScoped, ok := streamEvent.Data.(UserScopedEvent)
	if !ok {
		t.Fatalf("流式事件载荷未实现 UserScopedEvent: %T", streamEvent.Data)
	}
	if streamScoped.EventUserID() != "user-b" {
		t.Fatalf("流式事件 EventUserID = %q, 期望 user-b", streamScoped.EventUserID())
	}
}

// TestEmitterNilSafe emitter 未注入时 emitProgress 不应 panic
func TestEmitterNilSafe(t *testing.T) {
	svc := NewModelTraceService(nil)
	svc.emitProgress(&modelTraceRun{SessionID: "mt", ProviderID: 1, ExpectedModel: "gpt-5.4", Start: time.Now()}, "sending", 1, "x")
	svc.emitProgress(nil, "sending", 1, "x")
}
